# Quipu syntax — Encrypted broadcast (`0x0e XX`)

> **STATUS, mixed.** The single-signer (P2PKH) pattern documented here is
> implemented in `colegio_tools.py` and used by the existing on-chain
> encrypted-image quipus (`d68175...`, `d0209a...`) and their key drops
> (`89b51b...`, `f278e4...`). The multisig variant (combined-signer
> pubkey, Section "Multisig broadcast") is **DRAFT** — the design is
> chosen but not yet implemented in `colegio_tools.py`.

The encrypted-broadcast pattern lets one inscriber seal content to N
recipients simultaneously, each of whom can decrypt independently using
only their own private key plus information already on chain. The
existing on-chain instances are encrypted-image quipus (`0x0e 03`); the
same pattern generalizes to encrypted-text broadcast (`0x0e 00`) and
any other inner content type.

---

## The encryption scheme — static ECDH with sender pubkey

Encryption uses **static ECDH between the sender and each recipient**,
not ephemeral ECIES. This is a deliberate choice: it lets the sender's
on-chain pubkey serve as half of every shared secret, so recipients can
identify "messages for me" without needing per-message ephemeral pubkey
overhead.

### Sender side (one signer, the implemented case)

```
1. Sender has identity keypair (sender_priv, sender_pub).
2. For each recipient i in 1..M:
     shared_secret_i = HKDF(ECDH(sender_priv, recipient_i_pub), 32 bytes, SHA256)
3. Generate one random session key (32-byte AES key).
4. Encrypt the body with the session key (AES).
5. For each recipient i:
     session_key_copy_i = AES_encrypt(shared_secret_i, session_key)
6. Build payload:
     [type-specific header][M (number of recipients, 1B)][optional title]
     [M × 64-byte session_key_copies]
     [AES-encrypted body]
7. Inscribe the payload via a normal Cadena spending the sender's funds.
   The sender's pubkey appears in the input scriptSig of the broadcast tx.
```

### Recipient side

```
1. Recipient sees an encrypted broadcast at txid X. Knows their own privkey.
2. Look up the sender's pubkey by reading X's input scriptSig (the last
   token of the scriptSig for P2PKH inputs).
3. Compute shared_secret = HKDF(ECDH(my_priv, sender_pub), 32 bytes, SHA256).
4. Try to decrypt each session_key_copy_i:
     try: session = AES_decrypt(shared_secret, session_key_copy_i)
   The slot that decrypts successfully gives the session key.
5. Decrypt the body with the session key.
```

In the current `colegio_tools.py:array_dec_from_txn`, the recipient
provides their `index_key` directly — they're told their position in
the recipient list out-of-band. A future version may iterate slots and
return the first that decrypts.

### Implementation reference

`colegio_tools.py`:

- `shared_key(prvKey, pubKey)` (line 793) — HKDF(ECDH(prv, pub), 32 bytes, SHA256)
- `get_txn_pub_from_node(txn_ident)` (line 799) — extracts sender pubkey from a tx's input scriptSig
- `array_dec_from_txn(txn_ident, prvKey_input, index_key, df_outputs)` (line 807) — full decryption flow

---

## Multisig broadcast — DRAFT

The single-signer pattern above breaks for multisig senders because
`get_txn_pub_from_node` assumes a P2PKH input (one pubkey at the tail
of the scriptSig). A multisig input's scriptSig contains N signatures
followed by the redeemscript, not a single pubkey — so the recipient
can't derive a unique shared secret from it.

The chosen fix: **combined-signer-pubkey ECDH (Option 2).**

### Why this option

The same curve-point-addition trick already used in
`quipu_crypto.py:combine_pubkeys` (the multi-keyholder ECIES seal
mechanism for the five-seal La Verna structure) extends naturally to
ECDH. A multisig with N signers has a uniquely-defined combined pubkey
that anyone can derive from the redeemscript, and a uniquely-defined
combined privkey that only the N signers together can produce.

| | Encryption side | Decryption side |
|---|---|---|
| Single-signer (P2PKH) | `shared = ECDH(sender_priv, recipient_pub)` | `shared = ECDH(my_priv, sender_pub)` |
| **Multisig (combined-signer)** | `shared = ECDH(combined_signer_priv, recipient_pub)` | `shared = ECDH(my_priv, combined_signer_pub)` |

For the multisig case:
- `combined_signer_priv = sum of signer privkeys (mod n)` — requires all N signers to convene with their privkeys
- `combined_signer_pub = sum of signer pubkeys (curve point addition)` — derivable by anyone from the multisig redeemscript

This **mirrors the multisig spending semantics in the encryption layer**:
the same group required to spend from the address is required to encrypt
from it. Same ceremony, same authority.

### Byte format extension — one flag byte added

The encrypted-broadcast header gains a `Combined` flag byte
distinguishing the two cases:

```
[type-specific header bytes]
[Combined]    1B   00 = single-signer ECDH (current behavior, P2PKH sender)
                   01 = combined-signer ECDH (multisig sender)
[M]           1B   number of recipients
[optional title text]
[M × 64-byte session_key_copies]
[AES-encrypted body]
```

For backward compatibility, all existing encrypted broadcasts have
`Combined = 0` implicitly (the field didn't exist when they were
inscribed; readers should default to 0 for legacy inscriptions or
detect by checking whether the input is multisig).

### Sender procedure (multisig, all N signers convene)

```
1. The N signers physically/cryptographically convene with their privkeys.
2. Compute combined_signer_priv = sum of signer privkeys mod n.
3. For each recipient i:
     shared_secret_i = HKDF(ECDH(combined_signer_priv, recipient_i_pub),
                            32 bytes, SHA256)
4. Generate session key, encrypt body, encrypt session-key copies — same
   as single-signer flow.
5. Build payload with Combined = 0x01.
6. Sign the inscription tx with the N multisig signatures (per the existing
   CadenaMulti / CadenaMultiAtom flow).
7. Discard combined_signer_priv. (Each signer's individual privkey is
   retained; the combined value should not be persisted.)
```

The combined privkey exists only momentarily during the encryption
ceremony. None of the N signers ever holds it alone, before or after.

### Recipient procedure

```
1. Receive an encrypted broadcast at txid X.
2. Read X's input. If multisig, parse the redeemscript to get all N
   signer pubkeys.
3. Compute combined_signer_pub = sum of signer pubkeys (curve point
   addition).
4. Compute shared_secret = HKDF(ECDH(my_priv, combined_signer_pub),
                                 32 bytes, SHA256).
5. Try to decrypt each session_key_copy with this single shared secret.
6. Use the recovered session key to decrypt the body.
```

The recipient never needs to know which individual signers' privkeys
are being used — the combined pubkey acts as a unified sender identity
for the multisig.

### Implementation TODO

`colegio_tools.py` updates required to support multisig broadcasts:

1. **`get_txn_pub_from_node`** — detect multisig inputs and extract the
   N signer pubkeys from the redeemscript instead of returning a single
   pubkey.
2. **New helper** `combined_signer_pub_from_redeemscript(asm)` — parse the
   redeemscript, extract the N pubkeys, compute curve sum via
   `coincurve.PublicKey.combine_keys` (already used by
   `quipu_crypto.combine_pubkeys`).
3. **`array_dec_from_txn`** — branch on `Combined` flag (or detect via
   input type), use combined_signer_pub for shared secret derivation
   when multisig.
4. **New encoder** `mk_encrypted_broadcast_multisig(...)` — analogous to
   the single-signer broadcast encoder, but takes the combined privkey
   as input and sets `Combined = 0x01` in the payload.

These changes are mechanical extensions of the existing single-signer
code; the cryptographic primitives (`combine_pubkeys`, `combine_privkeys`,
`shared_key`) all already exist.

---

## Why static ECDH and not ephemeral ECIES

A common alternative scheme — ephemeral ECIES (what the `eciespy` library's
`ecies.encrypt` does) — generates a fresh ephemeral keypair for each
encryption, includes the ephemeral pubkey in the ciphertext, and lets
the recipient derive the shared secret from their own privkey plus the
ephemeral pubkey. The sender's identity isn't used.

Tradeoff:

|  | Static ECDH (this protocol's choice) | Ephemeral ECIES |
|---|---|---|
| Sender pubkey enters encryption? | Yes (via ECDH) | No |
| Per-message overhead | None beyond session-key copies | +33 bytes ephemeral pubkey per slot |
| Requires sender's pubkey to decrypt? | Yes (must know sender) | No |
| Authorship binding | Sender pubkey is half of every shared secret — implicit attribution | None |
| Stealth-style addressing | Recipients can identify messages from a specific sender | No sender notion |

Static ECDH was chosen because the chain *already* provides the sender's
pubkey for free (it's in the input scriptSig of every spending tx).
Including ephemeral pubkeys would be redundant overhead, and losing the
implicit sender attribution would be a regression.

The ephemeral-ECIES scheme is also available via `quipu_crypto.py`'s
`encrypt_ecies` / `decrypt_ecies` for the **five-seal mechanisms** in
the La Verna bordado. Those use ECIES to a combined recipient pubkey
(Pattern B from the seal mechanism design) — a different use case from
broadcast.

---

## Open questions

1. **Recipient index discovery.** Currently `array_dec_from_txn` requires
   the recipient to provide `index_key` (their position in the recipient
   list). A try-each-slot approach would be more user-friendly but costs
   M decryption attempts per broadcast. Probably switch to try-each-slot
   in the next iteration.

2. **Mixed input types.** What if a transaction has both P2PKH and
   multisig inputs? Probably define: the broadcast's "sender" is the
   first input, and only that input's type determines the
   single-vs-combined encryption mode. Edge case; address when it
   actually happens.

3. **Combined privkey discipline.** The combined privkey must not be
   stored — it's a momentary value during the encryption ceremony.
   Future tooling for multisig broadcasts should encode this as a
   single `compute_and_discard()` interface that the N signers
   collaboratively call without any persistent state.

4. **Verification of combined-signer integrity.** Anyone observing a
   multisig broadcast can verify it was signed by the multisig
   (chain-level signature verification), but proving that the
   combined_signer_priv used for encryption corresponds to the same
   N signers requires either trust or a zero-knowledge proof. For v1,
   assume the multisig signatures and the encryption are produced by
   the same ceremony — chain attestation suffices.
