# Quipu type `0x0e` — Encrypted family

> **STATUS: CANONICAL v1** (May 2026). Implemented in
> [`canonical/encrypted.py`](../../canonical/encrypted.py). Three sub-families
> under one type byte. Four pre-canonical inscriptions exist on chain at
> apocrypha; they used different layouts and are abandoned (see § Abandoned
> legacy forms).

The `0x0e` family wraps any plaintext quipu in either a symmetric (AES) or
asymmetric (ECIES) envelope, plus a key-management operation (keydrop) for
releasing keys to readers after the fact. All three sub-families share one
8-byte structural header; the byte at offset 6 selects which sub-family,
and the byte at offset 7 selects a variant within that sub-family.

The encrypted layer is fully **type-agnostic about what it wraps**: any
inner quipu — text, image, cert, celestial, identity, binding, even another
encrypted quipu — can be sealed. After decryption, the inner bytes start
with the standard `c1dd0001` magic and dispatch through the normal type
parser.

---

## Design principle: same byte = same role

The header obeys the project's uniform convention:

- **Byte 4** is always the type byte. Here: `0e`.
- **Byte 5** is always the tone byte. `00` ordinary, `01` affection,
  `0d` demonic, `ff` reverence. **Defaults to `0x00`** for encrypted quipus so the wrapper
  doesn't leak metadata about the sealed content. Opt-in disclosure: an
  author can set `0xff` reverence on a sealed posthumous letter if they
  want that hint visible to readers without a key.
- **Bytes 6 and 7** are structural fields that vary per type. For `0x0e`,
  they are the sub-family byte and the variant byte.

No bit-packing within bytes. Each byte carries exactly one meaning.

---

## Byte layout

### Header — 8 structural bytes

```
offset  bytes        meaning
0..3    c1 dd 00 01  magic + protocol version 0.1
4       0e           type byte = encrypted family
5       <tone>       00 ordinary (default), 01 affection, 0d demonic, ff reverence
6       <sub_family> ae AES wrapper
                     ec ECIES per-recipient wrapper
                     0d key drop (operation, not a wrapper)
7       <variant>    sub-family-specific qualifier (see per-sub sections)
8..     [body]       sub-family-specific
```

### Sub-family at offset 6

| value | sub-family | mnemonic |
|---|---|---|
| `ae` | AES wrapper | reads as "AE" — short for AES |
| `ec` | ECIES wrapper | reads as "EC" — Elliptic Curve |
| `0d` | key drop | reads as "0D" — Drop |

All other byte values at offset 6 are reserved for future amendments
(e.g., Shamir share sub-family for M-of-N recipient quorums — see
§ Future amendments).

---

## Sub-family `0e ae` — AES wrapper

Symmetric encryption of an inner quipu under a 32-byte AES key. The key
can be raw bytes or derived from a passphrase.

### Variant byte (offset 7)

| value | name | how the key is supplied |
|---|---|---|
| `0x00` | AES-raw | a raw 32-byte key, supplied directly (typically released later via a keydrop) |
| `0x01` | AES-password | the key is derived via `SHA256(passphrase_utf8)` |

### Body

```
[|TITLE|]          optional outer public-facing label (no inner-content leak)
<ciphertext>       AES-CBC(key, framed_inner)
```

Where `framed_inner` is the length-prefixed inner quipu (see § Inner
framing below).

### Worked AES-password example

```
c1dd 0001  0e  00  ae  01  | Para una conocida |  <AES-CBC ciphertext>
            ^   ^   ^   ^
            |   |   |   01 = password-derived
            |   |   ae = AES sub-family
            |   00 = ordinary tone
            type = encrypted
```

### Notes on key derivation

- **No salt, no iteration count.** Per the project's minimal-cryptography
  convention, `aes_key = SHA256(passphrase_utf8)` is deterministic and
  unsalted. This is a deliberate choice. Passphrases must be strong
  enough on their own (the threat model assumes users pick non-trivial
  passphrases; not a defense against dictionary attacks on weak ones).
- **Raw key vs password is structural**, not just a hint. Readers
  dispatch on the variant byte: `0x00` expects a 32-byte argument,
  `0x01` expects a passphrase string.

---

## Sub-family `0e ec` — ECIES broadcast wrapper

Hybrid scheme: a fresh 32-byte session key encrypts the body via AES-CBC,
and the session key itself is wrapped per-recipient using ECDH-derived
keys.

### Variant byte (offset 7)

| value | name |
|---|---|
| `0x00` | broadcast — per-recipient envelopes wrap a shared session key |

(Other variants are reserved — e.g., ephemeral-pubkey ECIES, threshold
broadcast.)

### Body

```
[|TITLE|]                optional outer public label
<Nrec:1>                 number of recipient envelopes (max 255)
N × <envelope:64>        each envelope is 16 B IV + 48 B AES-CBC ciphertext
                         of the 32-byte session key
<ciphertext>             AES-CBC(session_key, framed_inner)
```

### Crypto, step by step

**1. Session key generation.** A fresh random 256-bit AES key is generated
per inscription:
```
session_key = random_256_bits()
```

**2. Per-recipient envelopes.** For each recipient pubkey, the sender
computes a Diffie-Hellman shared point on secp256k1:
```
shared_point = sender_priv × recipient_pub        [scalar × point]
```
By ECDH symmetry, the recipient computes the same point as
`recipient_priv × sender_pub`. The shared point is HKDF-SHA256'd to a
32-byte envelope key:
```
envelope_key = HKDF-SHA256(shared_point.serialized, 32 bytes)
```
The session key is wrapped under the envelope key with AES-CBC:
```
envelope = AES-CBC(envelope_key, session_key)
         = 16 B IV + 48 B AES-CBC-PKCS7(32 B session)  = 64 B total
```

**3. Body encryption.** The framed inner quipu is encrypted with the
session key (NOT the envelope key):
```
ciphertext = AES-CBC(session_key, framed_inner)
```

**4. Author pubkey recovery.** The sender's pubkey is NOT stored in the
outer header. It's recovered from the cabeza transaction's input
scriptSig:
- For P2PKH inputs: scriptSig has the form `<signature> <pubkey>`; the
  trailing token is the author's compressed-or-uncompressed pubkey.
- For P2SH multisig inputs: the redeem script (last asm token) contains
  all N component pubkeys; the reader sums them via point addition to
  derive the aggregate sender pubkey.

Helper: `colegio_tools.get_txn_pub_from_node(txid)` and
`colegio_tools.get_address_pubkeys(address)`.

### Multisig sender — aggregate-key ECDH

For an **N-of-N multisig sender** (the only multisig topology used in
this project), the sender identity is the **aggregate** of the N
component keys:

```
aggregate_pubkey  = sum of N component pubkeys                [point addition]
aggregate_privkey = (sum of N component privkeys) mod n       [scalar addition mod curve order]
```

Algebraic identity: `aggregate_privkey · G == aggregate_pubkey`. The
reader derives the aggregate pubkey from the redeem script (which is
public on chain in any P2SH spend). The sender side requires all N
component privkey holders to cooperate to perform the ECDH, since the
aggregate privkey is the modular sum of all N component privkeys.

**Why N-of-N (not M-of-N)?** For aggregate-key ECDH decryption, you need
the full aggregate privkey, which requires all N component privkeys.
In an M-of-N threshold, M < N cosigners can sign a transaction but
cannot reconstruct the aggregate privkey — the (N − M) absent privkeys
are missing summands. So aggregate-key ECIES only works cleanly for
N-of-N multisigs. The project's multisigs are all N-of-N, which makes
this convention self-reinforcing.

### Multisig recipient

Two equivalent ways to encrypt to a multisig recipient:

| pattern | how it works |
|---|---|
| **per-component envelopes** | include each of the N component pubkeys as a separate recipient in the envelope list. Any one cosigner can decrypt independently with their own privkey. |
| **aggregate envelope** | include the aggregate pubkey as a single recipient. To decrypt, all N cosigners must reconstruct the aggregate privkey (same math as for senders). |

The first pattern (per-component envelopes) is the project's default for
"any cosigner can read" semantics. The second pattern (aggregate
envelope) gives "the multisig as a whole reads" semantics — useful when
you want decryption to require the same quorum as signing.

### Recipient identities don't need on-chain addresses

A recipient pubkey can be:
- A single person's pubkey (P2PKH context)
- The aggregate of an N-of-N multisig that EXISTS on chain (e.g.,
  the `multiman` 2-of-2 of mi+key1)
- The aggregate of an ad-hoc set of pubkeys that DOES NOT correspond to
  any inscribed multisig address — just a pubkey computed locally by
  point addition.

The encryption layer cares only about the pubkey/privkey math, not
about whether any Dogecoin address derives from the pubkey.

---

## Sub-family `0e 0d` — Key drop

A plaintext inscription that **releases one or more AES keys** for
previously-sealed targets. Not an encryption — a key-management
operation. The body is unencrypted; the whole point is to make the
keys publicly readable. Each released key is named so it can be
addressed individually via the `<<txid>><<name>>` citation convention.

### Variant byte (offset 7)

| value | name |
|---|---|
| `0x00` | release — drops one or more named keys for sealed targets |

Future operations (rotation, revocation, expiry) get higher variant
values via Estandarte amendment.

### Body

```
<count:2 uint16 BE>             number of drops (1..65,535)
for each drop:
    <namelen:1>                 length of this drop's name (0..255 UTF-8 bytes)
    <name:namelen>              UTF-8 name (may be empty = anonymous drop)
    <ref_txid:32>               target encrypted quipu txid (raw bytes)
    <key:32>                    the 32-byte AES (or ECIES session) key
[|TITLE|]                       optional outer batch label
```

A single-drop keydrop is just `count = 1`. There is no separate "single"
vs "multi" variant — every keydrop body has this uniform shape. Naming
each drop is optional (a 0-byte name = anonymous), but anonymous drops
cannot be cited by name via `<<txid>><<name>>`.

Per-drop record size: `1 + namelen + 64` bytes. A 5-drop batch with
20-character names is `5 × (1 + 20 + 64) + 2 + title ≈ 440 bytes`,
easily fits in a single-strand inscription.

### What the dropped key unlocks

| target sub-family + variant | the 32 bytes are... | how the reader uses them |
|---|---|---|
| `0e ae 00` (AES raw) | the raw AES key | `AES-CBC-Decrypt(key, target_body)` |
| `0e ae 01` (AES password) | the SHA256 of the original passphrase (the derived key) | same `AES-CBC-Decrypt(key, target_body)` |
| `0e ec 00` (ECIES broadcast) | the **session key** — the 32 bytes that any envelope would have decrypted to | skip the envelope-unwrap step; `AES-CBC-Decrypt(session, target_body)` directly |

**Crucial property for ECIES targets**: a keydrop lets a NON-envelope-recipient
decrypt. The original ECIES recipients still have access via their envelopes,
but the readable audience expands to anyone who finds the keydrop. This is
the mechanism for delayed-broadcast: seal to a small initial audience, release
widely later.

### Citation by drop name

Each named drop within a keydrop is addressable through the standard
quipu citation convention:

```
<<keydrop_txid>>                       — refers to the whole keydrop (all drops)
<<keydrop_txid>><<drop name>>          — refers to a specific named drop
```

The citation resolver returns the single drop's `(ref_txid, key)` pair,
which a reader can then use to walk to the sealed target and decrypt.
This makes essays expressive about which release they're invoking:

> "The author's birth letter is unlocked by `<<keydrop_xyz>><<birth>>`."

Resolution behavior: the resolver scans the drops list in order and
returns the FIRST match by name. Anonymous drops (empty name) are not
addressable by name — they're released as part of the batch but require
the reader to walk the whole keydrop to find them. Names SHOULD be
unique within a single keydrop; duplicates are permitted but only the
first is reachable via citation.

### One-shot helper: `resolve_and_decrypt`

The canonical convenience function

```
resolve_and_decrypt(keydrop_txid, drop_name, fetcher)
    → {'inner_header', 'inner_body', 'magic_ok', ...}
```

composes the two steps (resolve the drop → fetch the target → decrypt
with the released key) into a single call, auto-dispatching on the
target's sub-family byte:

- target sub-family `0xae` (AES) → the 32 bytes are used as the AES key
- target sub-family `0xec` (ECIES) → the 32 bytes are used as the
  *session key*, bypassing envelope unwrap entirely

The reader's `read_encrypted_quipu` accepts a `session_key=` kwarg
specifically for this bypass path. A keydrop-recipient is therefore
not required to be an ECIES envelope-recipient — possession of the
released session key alone is sufficient to read the body.

### Tone semantics

A keydrop's tone byte (offset 5) carries semantic weight independent of
the target's tone. A keydrop of love letters released after the author's
death can carry `tone = 0xff` reverence to flag the posthumous context,
even if the original sealed inscriptions carried other tones. This is a
structural way to encode "the act of releasing this key happens for a
specific reason" alongside the bare technical fact of the release.

---

## Inner framing — the length prefix

For both wrapper sub-families (`ae` and `ec`), the inner quipu's bytes
are framed with an explicit length prefix before encryption:

```
framed_inner = <header_len:2 BE> <inner_header> <inner_body>
```

Where:
- `header_len` is a 16-bit big-endian unsigned integer — the byte count
  of the inner header. Max 65,535 (any real quipu header fits well within
  this).
- `inner_header` starts with the standard `c1dd 0001` magic. Its layout
  depends on the inner type byte (`inner_header[4]`).
- `inner_body` is the inner quipu's body bytes, length implicit (it
  fills the rest of the decrypted stream).

### Why the prefix is needed

Outside encryption, the **strand boundary in the diamond pattern** is
the natural separator between header and body — the cabeza strand
contains the header, the cuerpo strands contain the body, and
`read_quipu()` returns them as separate `(header_hex, body_hex)`.

Inside encryption, the whole quipu is concatenated into one ciphertext
blob. The strand framing is gone. The 2-byte length prefix replaces it,
giving the reader a uniform way to split header from body after
decryption without needing to know the inner type's specific layout.

### After decryption

```
decrypted = decrypt(outer_body, key)         # AES-CBC for ae, AES-CBC after envelope unwrap for ec
header_len = decrypted[:2]                   # uint16 BE
inner_header = decrypted[2 : 2 + header_len] # starts with c1dd0001
inner_body   = decrypted[2 + header_len :]   # rest of stream
# Now dispatch to the standard type parser
inner_type_byte = inner_header[4]
parsed = read_quipu_by_type(inner_type_byte, inner_header, inner_body)
```

The dispatcher receives a `(header_bytes, body_bytes)` tuple identical
in shape to what the strand walker produces. The type-specific reader
doesn't need to know it's looking at decrypted bytes; its interface is
unchanged.

---

## Magic-prefix tamper / wrong-key detection

After decryption, the reader checks `inner_header[:4] == c1dd 0001`.

AES-CBC produces a deterministic byte stream from any key, valid or
not — wrong-key decryption yields gibberish without raising an error.
But the magic byte sequence is unforgeable from random output (1 in
~4 billion by coincidence), so:

- **`inner_header[:4] == c1dd 0001`** → the key was correct and the
  ciphertext wasn't corrupted.
- **`inner_header[:4] != c1dd 0001`** → wrong key OR corrupted
  ciphertext. The canonical reader raises in this case.

This gives a free integrity check without needing an explicit MAC.

---

## Composability — nested encryption

The encryption layer is content-agnostic. If the inner type byte is
`0x0e`, the inner is itself an encrypted quipu, and decryption peels
one layer:

```
Layer 1 (outermost):  AES-password
Layer 2:              ECIES broadcast
Layer 3 (innermost):  text quipu (the actual plaintext)
```

Each layer's decryption yields a length-prefixed inner that itself
starts with `c1dd 0001` plus a type byte. The standard dispatcher
recurses into the inner layer until reaching a non-encrypted type.

This composability enables patterns like:
- **Key escrow with quorum**: seal a piece of content with AES-raw,
  then seal the AES key inside an ECIES envelope addressed to N
  trustees. Decrypting requires unwrapping the ECIES envelope first
  (with any one trustee's privkey) to obtain the AES key, then using
  that key on the inner-most AES blob.
- **Layered disclosure**: a public outer layer (text quipu describing
  the inscription), with a sealed inner layer that's only revealed via
  a future keydrop.

---

## Worked example — AES-password seal of a text quipu

Inner quipu (a small text quipu, ordinary tone, title "Un secreto"):
```
inner_header = c1dd 0001  00  00  | Un secreto |     (16 bytes)
inner_body   = "Te encuentro en las estrellas; te pierdo en el amanecer."  (56 bytes)
```

Framed for encryption:
```
framed = 00 10            <header_len = 16, uint16 BE>
       + c1dd 0001 00 00 | Un secreto |
       + "Te encuentro..."
```

Total framed: 2 + 16 + 56 = 74 bytes.

Encrypted under `aes_key = SHA256("el rio de la noche")`:
```
ciphertext = AES-CBC(aes_key, framed)
           = 16 B IV + 80 B AES-CBC-PKCS7(74 B framed)  = 96 B
```

Outer inscription:
```
header:  c1dd 0001  0e  00  ae  01  | Para una conocida |     (~25 bytes)
body:    <96-byte AES ciphertext>
```

Total inscription: ~121 bytes. Fits in 2 OP_RETURN transactions per
strand.

---

## Abandoned legacy forms

Four pre-canonical `0x0e` inscriptions exist on chain at apocrypha
under earlier layouts that the v1 canonical reader does NOT parse:

| txid | what | legacy layout |
|---|---|---|
| `d68175766b70f716…` | encrypted image (grayscale) | `0e 03 <color> <L> <W> <B> <Nrec> \|TITLE\|` — broadcast variant where byte 5 doubled as both sub-family marker AND inner type byte |
| `d0209a0f85872d68…` | encrypted image (RGB) | same |
| `89b51b4852b0e80f…` | key drop | `0e 0e 0d \|TITLE\|` — doubled-marker form where the encryption family byte appeared twice before the drop marker |
| `f278e466012fb784…` | key drop | same |

These inscriptions remain on chain forever as historical artifacts. The
canonical reader simply doesn't attempt to parse them — they're
documented as out-of-spec rather than supported by a back-compat shim.

A reader walking the canonical corpus (via the Estandarte and the
`0xab` binding to canonical examples) will never reach these txids.

---

## Future amendments

Reserved sub-families at byte 6 that may be specified in future
Estandarte amendments:

| candidate value | name | purpose |
|---|---|---|
| `ss` | Shamir share | one fragment of a key split via Shamir's Secret Sharing. Readers collect K of N shares to reconstruct the key for a target. Enables M-of-N (threshold) RECIPIENT quorums, distinct from per-recipient ECIES envelopes. The natural way to do "any K of these N trustees can release the key together." |
| (others) | reserved | post-quantum sealed, threshold-decrypted, ephemeral-pubkey ECIES, etc. |

Future variants for the existing sub-families:
- `0e ae 02..ff` — new AES key-derivation modes (argon2, scrypt, hardware-token, etc.)
- `0e ec 01..ff` — new ECIES modes (ephemeral pubkey, threshold, post-quantum hybrids)
- `0e 0d 01..ff` — new key-management operations (rotation, revocation, expiry attestations)

All amendments must be inscribed as Estandarte updates citing v1 as
the parent, so the lineage chain documents the protocol's evolution.

---

## Reference parser

See [`canonical/encrypted.py`](../../canonical/encrypted.py) for the
authoritative builder + reader. Eight self-tests pass:

- AES raw key — round-trip + wrong-key rejection
- AES password — round-trip + wrong-passphrase rejection
- ECIES single recipient — round-trip + outsider rejection
- ECIES 3-recipient broadcast
- ECIES multisig sender (3-of-3 aggregate-key ECDH) — mathematical
  identity verified
- Key drop round-trip
- Nested AES-in-AES composability
- 6 validation error cases (invalid tone, title with pipe, non-32-byte
  key, non-magic inner header, bad keydrop txid length, bad keydrop
  key length)

End-to-end on-chain test suite lives in
[`notebooks/50_aes_password.ipynb`](../../notebooks/50_aes_password.ipynb)
through `54_keydrops.ipynb`.

---

## Why `0x0e`

The byte was chosen for two reasons:

- **Mnemonic**: `0e` reads as "encrypted" (the first letters of
  *Elliptic-Curve* / *Encrypted*).
- **Compositional sense**: starts with `0` like the other low-numbered
  basic types (`00` text, `03` image, `07` audio) — encryption is a
  primitive wrapper, not a structured content type, and the low byte
  signals that.

No collision with the other established type bytes (`00` text,
`03` image, `07` audio, `1d` identity, `ab` binding, `cc` certificate,
`ce` celestial, `ee` Estandarte).
