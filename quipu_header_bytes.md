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
quipu, by referencing its txid + the key.

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
| `0x0e 0x0a` | Password-sealed payload | New mechanism (your Quipu 1 in the 5-seal structure). |
| `0x0e 0x0b` | Time-released (random AES key, future key drop) | Your Quipu 2 mechanism. |

Whether any of these are right depends on choices you haven't made yet.
They're just placeholder slots so the conversation has something to point at.
