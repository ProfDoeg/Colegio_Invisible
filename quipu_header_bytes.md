# Quipu Header Bytes — Observed Examples

This document compiles every quipu header byte string found in the
codebase, with interpretive notes about what each byte appears to mean.

**This is a transcription, not a specification.** Each entry is sourced
to a specific notebook and code line. Where bytes are documented in the
notebook itself, that documentation is quoted. Where they are not, the
interpretation is marked as such.

---

## All observed header strings

| # | Source | Header bytes (hex) | Notes |
|---|---|---|---|
| 1 | `12_cuaderno.ipynb`, cell ~13 | `c1dd0001 03ff 0000 4000 4005` | Image quipu (early generalization) |
| 2 | `13_cuaderno.ipynb`, cell ~13 | `c1dd0001 03ff 0100 4000 4005` | Image quipu (multi-strand iteration) |
| 3 | `14_cuaderno.ipynb`, cell ~13 | `c1dd0001 03ff 0100 4000 4005` | Same as 13 |
| 4 | `15_cuaderno.ipynb`, cell 14 | `c1dd0001 0300 00 + L + W + B` | Image, no tone, single-channel |
| 5 | `16_cuaderno.ipynb`, cell 14 | `c1dd0001 03ff 01 + L + W + B` | Image, color, with tone |
| 6 | `17_cuaderno.ipynb`, cell 23 | `c1dd0001 0e03 01 + L + W + B + Nrecip` | **Encrypted color image, broadcast** |
| 7 | `17_cuaderno.ipynb`, cell 23 (commented) | `c1dd0001 0e0e 00 + Nrecip` | "Opaque encoding with internal/encryption header" |
| 8 | `18_cuaderno.ipynb`, MD cell 8 | `c1dd0001 0e03 01 + L + W + B + Nrecip + text` | Same as 17 (documented) |
| 9 | `18_cuaderno.ipynb`, MD cell 12 | `c1dd0001 0e0e 0d + text` | **Key-drop quipu** |
| 10 | `20_cuaderno.ipynb`, MD cell 25 | `c1dd0001 1d 00 00` | **Identity quipu** (`1d` = identity, per documentation) |
| 11 | `quipu3.ipynb` cell 66 (Verna) | `c1dd0001 03ff 0101 2c00 f006` | La Verna image quipu |
| 12 | `colegio_tools.py` build_aes_sealed_quipu | `c1dd0001 0eae <inner_full_header_from_byte_4>` | **AES-sealed wrapper** (any inner type) |

---

## Byte-by-byte structure

Every header begins with the same 4 bytes: `c1 dd 00 01`.

```
bytes 0..1 : c1 dd        magic — quipu protocol signature
bytes 2..3 : 00 01        version — protocol v1
bytes 4..  : type-specific
```

After the 4-byte preamble, the structure varies by what's being inscribed.

---

## What we observe at byte 4

Byte 4 takes the values: **`03`, `0e`, `1d`**.

### `0x03` — Image (plaintext)

Confirmed in notebook 17 comment: "*This would be color image*". Confirmed
by the existing `read_image_data` parser, which reads the bytes following
the preamble as image dimensions and bit-depth.

When byte 4 is `0x03`, the layout that follows is:
```
byte 4  : 03            content type = image
byte 5  : tone          ff = reverence, 00 = (undocumented; absent)
byte 6  : color flag    00 = greyscale, 01 = color
bytes 7..8   : L (length, big-endian uint16)
bytes 9..10  : W (width, big-endian uint16)
byte 11      : bit depth
[ optional title / caption text ]
```

Used in: notebooks 12, 13, 14, 15, 16, La Verna.

### `0x0e` — Encrypted (broadcast or opaque)

Byte 4 = `0x0e` indicates encrypted content. Two sub-forms appear:

**Encrypted-image broadcast** (byte 5 = `0x03`):
```
byte 4  : 0e            encrypted
byte 5  : 03            inner content type = image
byte 6  : color flag    01 = color
bytes 7..8   : L
bytes 9..10  : W
byte 11      : bit depth
byte 12      : N_recip (number of recipient session-key copies)
[ optional title text ]
```

Body layout for this type: `[N_recip × 64-byte session-key copies][AES-encrypted image bytes]`.

Used in: notebook 17, notebook 18 (`d0209a...`).

**Encrypted-opaque** (byte 5 = `0x0e`, byte 6 = `0x00`) — *commented-out
example only, not used in any inscription I can find*:
```
byte 4  : 0e            encrypted
byte 5  : 0e            (undocumented)
byte 6  : 00            (undocumented)
byte 7+ : N_recip + body
```

This appears in notebook 17 as a commented-out alternative. Possibly an
intended future type for "encrypted content of unspecified format" but
not implemented.

### `0x0e 0x0e 0x0d` — Key drop

```
byte 4  : 0e
byte 5  : 0e
byte 6  : 0d
[ text ]
body: enc_txid_bytes (32) + aes_key_bytes (32)
```

Documented in notebook 18: "*For key drop header is...*"

Used to release the AES session key for a previously-broadcast encrypted
quipu, by referencing its txid + the key. Works equally for a `0x0e 0xae`
AES-sealed target — the reader detects the target's sub-family byte and
either skips per-recipient envelopes (broadcast) or decrypts directly
(AES-sealed). The txid in the body is stored display-endian (per nb18's
`bytes.fromhex(displayed_txid)` — *not* reversed).

### `0x0e 0xae` — AES-sealed (independent sub-family)

A general-purpose AES-only wrapper around any plaintext inner type. No
per-recipient envelopes — the body is AES-encrypted with a key derived
from a passphrase (`SHA-256(password)`) or supplied directly as 32 bytes.
The wrap is structural: `0e ae` is inserted between `c1dd0001` and the
inner type byte, with everything else (title, inner structural fields)
preserved in place.

```
byte 4  : 0e            family = encrypted
byte 5  : ae            sub-family = AES-sealed
byte 6  : <inner_type>  03 image, 04 essay, 00 text, …
bytes 7+ : <inner-type-specific header fields, including |TITLE|>
body     : aes_encrypt(key, <plaintext inner body>)
```

Reader simply prepends `c1dd0001` to outer-header bytes 6+ to recover the
plaintext inner header, then AES-decrypts the body. The recovered
`(inner_header, inner_body)` is exactly the shape an unencrypted inner
quipu would have, so all existing per-type readers handle it unchanged.

Receives a key drop on equal footing with `0x0e 0x03` — the apply path
in `colegio_tools.apply_keydrop` dispatches on the sub-family byte and
skips the envelope-skip step for `0xae`.

Implemented in `colegio_tools.py`:
`build_aes_sealed_quipu`, `read_aes_sealed_quipu`. Console writer exposes
this as "AES password (0x0e 0xae)" in the Plan tab.

### `0x1d` — Identity

Documented explicitly in notebook 20: "*`1d` is the byte for Identity inscriptions*".

```
byte 4  : 1d            content type = identity
byte 5  : 00            (undocumented)
byte 6  : 00            (undocumented)
[ JSON-encoded identity dictionary ]
```

The body is a JSON dictionary of the inscriber's identity — names,
public keys, social handles, references to other identity quipus.

---

## What we observe at byte 5 (tone byte, when content type is image)

When byte 4 = `0x03` (image), byte 5 takes the values:

- `0xff` — *"reverence, marker to indicate reverence and seriousness because it talks about the dead"* (per user, in our conversation)
- `0x00` — appears in notebook 15 ("Dr. Doeg en Buenos Aires") — a non-reverent, presumably ordinary tone

Other tone values are not yet defined.

---

## Open questions / undocumented bytes

These are bytes whose meaning isn't documented in the notebooks I can read.
They might be documented in essays or notes I haven't seen.

1. **Byte 5 in identity quipu (`1d 00 00`)** — what does `00` after the type byte signify?
2. **Byte 6 in identity quipu** — same question.
3. **The relationship between `0x0e` (encryption) and the inner content type** — is `0e 03` a stable "encrypted image" pattern, or could `0e 1d` mean "encrypted identity"?
4. **What is `0e 0e 0d`?** The pattern of two `0e`s followed by `0d` is unusual. Is `0e 0e` a special "key drop" composite, or is `0e` here doing different work than in `0e 03`?
5. **The "sub-type" or "sequence" bytes in image headers** — bytes 5 and 6 carry tone and color flag respectively in plaintext images, but the encrypted-image variant has a different layout (byte 5 = inner type, byte 6 = color).

---

## Provisional table for new types you might want next

For the certificate of La Verna and the 5 encrypted quipus we've been
discussing, we'd need types not yet in the table. **These are
unallocated suggestions for discussion, not used anywhere yet.**

| Proposed | Meaning | Notes |
|---|---|---|
| `0x04` | Text essay (plaintext) | Body is UTF-8. Could carry the 108 essays' content. |
| `0x05` | Certificate | A specific kind of "essay-like" document that references other quipus by txid. |
| `0x0e 0x04` | Encrypted text essay | Encrypted variant of `0x04`, parallel to `0x0e 0x03`. |
| ~~`0x0e 0x0a`~~ | ~~Password-sealed payload~~ | **Superseded** — now allocated as `0x0e 0xae` (see above). |
| `0x0e 0x0b` | Time-released (random AES key, future key drop) | Your Quipu 2 mechanism. |
| `0xce` | Celestial figure | Constellation, earth path, vigil, or any named set of named coordinate points connected by lines. **DRAFT spec at [docs/quipu-types/celestial.md](docs/quipu-types/celestial.md)** |
| `0xab` | Bindings (abecedario) | Flat list of `NAME → txid` assignments. Imported by essays for stable, project-wide aliases. **DRAFT spec at [docs/quipu-types/bindings.md](docs/quipu-types/bindings.md)** |

---

## Documented body conventions

### Pipe-delimited title field — the `|TITLE|` convention

After the type-specific structured bytes (or directly after type/tone
for unstructured types like `0x00` text), inscriptions carry one or
more **pipe-bracketed fields**:

```
... |FIELD_1|FIELD_2|...|FIELD_N| [body content]
```

Each `|` is the literal byte `0x7C`. Fields share boundary `|`
characters when consecutive. The body begins after the closing `|`
of the last field.

For most quipus the first field is the title. For some types (cert,
multi-field), additional fields carry hash algorithms, hash values,
or other structured metadata.

This is **observed across the corpus**:

| Quipu | Type | Header bytes after type/tone |
|---|---|---|
| Mi Perrito | `0x00` text | `\|Mi Perrito\|` |
| Mi Caballo | `0x00` text | `\|Mi Caballo\|` |
| Maier 3-key declaration | `0xcc` cert | `00 01 \|SHA256\|33709...` |
| Domremy bordado | `0xcc` cert | `00 02 \|Domrémy Bordado Certificate\|` |
| Sun Face | `0x03` image | `[L,W,B] \|Sun Face\|` |
| Domremy image | `0x03` image | `[L,W,B] \| Domremy: Campo de Bourlemont \|` |
| Encrypted image #8 | `0x0e` enc | `[L,W,B,N_recip] \|Here is an encrypted image...\|` |
| Identity DrDoeg | `0x1d` id | `00 \|Declaration of Identity\|` |

The essay convention (`docs/quipu-syntax/essay.md`) formalizes this
for `0x00` text quipus and extends it with optional author, date,
and other fields.

Whether any of these are right depends on choices you haven't made yet.
They're just placeholder slots so the conversation has something to point at.
