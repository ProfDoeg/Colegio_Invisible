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

## Strand termination — recipient knots (DRAFT)

After an inscription's OP_RETURN data is fully written, the strand(s)
can be **terminated** with dust outputs to recipient addresses. These
dust outputs serve as **knots** — structurally analogous to the knots
that bind the strands of a physical Andean quipu — and as a
notification/discovery mechanism: each recipient's wallet sees an
incoming dust output and can walk back through the spend chain to
find the encrypted broadcast that addresses them.

This is a convention applied to inscriptions that want addressing.
Strands left with vout 0 dangling (unspent) means the quipu is
**unterminated** and has no recipient list. Termination is opt-in.

### The boundary marker

The transition from data-bearing strand to termination is marked
**structurally**: the first transaction in the spend chain that does
**not** carry an OP_RETURN at vout 1 is the start of termination. No
length prefix, no count, no special header byte — the absence of
OP_RETURN is the signal.

### Single-strand termination (simple case)

A single-strand quipu (header strand only, no body strands — typical
for an apocrypha-signed inscription on the single-key address) can be
terminated with a single tx whose outputs carry the dust:

```
Header strand:
  Tx_h_1: vout 0 (continuation) | vout 1 (OP_RETURN: c1dd 0001 ...)
  Tx_h_2: vout 0 (continuation) | vout 1 (OP_RETURN: more body)
  ...
  Tx_h_N: vout 0 (continuation) | vout 1 (OP_RETURN: last bytes)

Termination tx (no OP_RETURN — boundary marker):
  inputs:  Tx_h_N.vout0
  outputs:
    vout 0 → change back to sender's address (funds reclaimed)
    vout 1 → 1 DOGE dust to recipient R1
    vout 2 → 1 DOGE dust to recipient R2
    ...
    vout M → 1 DOGE dust to recipient RM
```

vout 0 of the termination tx serves two roles simultaneously:
- Funds reclamation (most of the strand-funding amount returns to the
  sender)
- Self-as-recipient-0 if the sender is also a recipient (the sender's
  wallet sees the change output and can re-find their own broadcast
  later)

### Multi-strand joining (the binding knot)

A multi-strand quipu (header + N body strands — typical for a bordado
inscription on the 3-of-3 multisig address) is terminated by a single
**joining transaction** that pulls *all* strand ends together as
inputs and addresses recipients via its outputs:

```
Quipu root tx:
  vout 0 → starts header strand (cabeza)
  vout 1 → starts body strand 2
  vout 2 → starts body strand 3
  ...

Each strand chains independently through its OP_RETURN-bearing txs:
  Header strand:    Tx_h_1 → ... → Tx_h_N1   (last OP_RETURN)
  Body strand 2:    Tx_2_1 → ... → Tx_2_N2   (last OP_RETURN)
  Body strand 3:    Tx_3_1 → ... → Tx_3_N3   (last OP_RETURN)
  ...

Joining tx (the binding knot — no OP_RETURN, multi-input):
  inputs:
    Tx_h_N1.vout0,         ← header strand end (input 0, by convention)
    Tx_2_N2.vout0,         ← body strand 2 end
    Tx_3_N3.vout0,         ← body strand 3 end
    ...                    ← in original strand order from root tx
  outputs:
    vout 0 → change back to sender's address (or to multi-sig, etc.)
    vout 1 → dust to R1
    vout 2 → dust to R2
    ...
    vout M → dust to RM
```

Two structural signals identify the joining tx as termination:
1. **No OP_RETURN at vout 1** (same boundary marker as single-strand)
2. **Multiple inputs converging from strand ends** (the joining property)

The joining tx makes the quipu a **closed cultural object**. All
strands are bound together; the recipient list addresses the *whole*
quipu (not individual strands). The quipu can be referred to by the
joining tx's txid as well as by its root.

### Many recipients — continuation

If the recipient count exceeds what fits in a single tx (Dogecoin's
practical max ~hundreds of dust outputs per tx given size limits),
the joining tx's vout 0 can spend into a continuation termination tx:

```
Joining tx 1:
  inputs:  all strand ends
  outputs:
    vout 0 → continuation to Joining tx 2
    vout 1..K → first batch of dust to R1..RK

Joining tx 2:
  inputs:  Joining tx 1's vout 0
  outputs:
    vout 0 → continuation to Joining tx 3 (or change-to-self if last)
    vout 1..K → next batch of dust to R(K+1)..R(2K)
  ...

Final joining tx P:
  inputs:  Joining tx (P-1)'s vout 0
  outputs:
    vout 0 → change back to sender (funds reclaim, strand truly ends here)
    vout 1..J → last batch of dust to recipients
```

Only the *first* joining tx has the multi-strand-input property.
Subsequent termination txs in the chain are single-input continuations
of the first. The reader knows it's still in the termination region
because it's walking forward from the joining tx via vout 0 with no
intervening OP_RETURNs.

### Recipient ordering

Across single-strand, multi-strand, and continuation termination, the
recipient ordering convention is:

- **Recipient 0 = self** (the change-to-self output at vout 0 of the
  first joining tx). Used when the sender is also a recipient (e.g.,
  for the AI-memory pattern of broadcasting to oneself).
- **Recipients 1..M** map to dust outputs in tx-order then vout-order:
  vout 1, vout 2, ..., vout K of the first joining tx, then vout 1,
  vout 2, ..., vout K of the second joining tx, etc.
- The encrypted body's session-key copies map 1-to-1 with this
  ordering: session-key copy 0 is for self, copy 1 is for R1, etc.

### Reader algorithm

```
identify_termination(quipu_root_txid):
  root = fetch(quipu_root_txid)

  # 1. Each output of the root that's spent into an OP_RETURN-bearing
  #    tx is a strand head. Walk each strand to its end.
  strand_ends = []
  for n in range(len(root.vout)):
    head_txout = (quipu_root_txid, n)
    if not has_strand(head_txout):
      continue   # vout n didn't become a strand
    cur = head_txout
    while spending_tx(cur).vout[1] is OP_RETURN:
      cur = (spending_tx(cur).txid, 0)   # follow vout 0
    strand_ends.append(spending_tx(cur))   # last tx with OP_RETURN

  # 2. Find the joining tx — the tx that spends *all* strand ends as
  #    inputs (or for single-strand quipus, just the strand's terminator).
  candidates = [next_tx_via_vout0(end) for end in strand_ends]
  if len(set(c.txid for c in candidates)) != 1:
    return None   # strands didn't converge — quipu is unterminated
  joining_tx = candidates[0]

  # 3. Collect knots from joining tx and any continuation termination txs.
  knots = []
  cur = joining_tx
  while cur is not None:
    for i in range(1, len(cur.vout)):
      knots.append(cur.vout[i].address)
    if cur.vout[0] is spent and not_op_return(spending_tx_of(cur.vout[0])):
      cur = spending_tx_of(cur.vout[0])
    else:
      cur = None

  return joining_tx.txid, knots
```

The single-strand case falls out of the same algorithm: `strand_ends`
has one entry, all candidates trivially share one tx (the
single-strand's terminator), and that tx's outputs are the knots.

### Conventions worth pinning

- **Joining tx input order**: header strand first (input 0), then body
  strands in their root-vout order. Per-strand input order is
  deterministic from the root, which makes the joining tx
  reconstructible.
- **Joining tx output order**: vout 0 = change/continuation/self,
  vout 1+ = recipient knots in recipient-list order matching the
  encrypted body's session-key copy order.
- **Dust amount**: 1 DOGE per recipient by default. Could carry semantic
  meaning in future variants (e.g., 108 satoshis for a Mochuelos issue
  notification) but v1 picks a uniform amount.
- **Knot privacy tradeoff**: the dust outputs publicly link the sender
  to the recipient addresses. Anyone watching the chain sees the
  conversation graph (who's talking to whom), even though the content
  remains encrypted. For genuinely anonymous recipients, future work
  could derive per-broadcast dust addresses from each recipient's
  identity quipu (BIP32-style). v1 sends dust directly to the
  recipient's known address.

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
