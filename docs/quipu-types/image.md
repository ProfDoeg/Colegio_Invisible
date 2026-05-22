# Quipu type `0x03` — Image

> **STATUS: CANONICAL v1.** Implemented in
> [`canonical/image.py`](../../canonical/image.py). Many existing
> on-chain inscriptions use this type (Domremy bordado image,
> Sun Face, Monte Veritá, Sabina, La Verna, …).

An *image quipu* is a bit-packed raster image: pixel values written
left-to-right, top-to-bottom, channels interleaved per pixel,
MSB-first within each byte. The header carries width, height, color
mode, and bit-depth as separate byte fields followed by a
pipe-bracketed title.

---

## Byte layout

### Header — 12 + (title) bytes

```
offset  bytes        meaning
0..3    c1 dd 00 01  magic + protocol version 0.1
4       03           type byte = image
5       <tone>       00 ordinary, 01 affection, 0d demonic, ff reverence
6       <color>      00 grayscale (1ch), 01 RGB (3ch),
                     02 grayscale+alpha (2ch), 03 RGBA (4ch)
7..8    <W_hi W_lo>  width  in pixels, uint16 big-endian
9..10   <H_hi H_lo>  height in pixels, uint16 big-endian
11      <bit_depth>  bits per channel per pixel (1..8)
12..    | TITLE |    UTF-8 between pipe sentinels (optional)
```

### Body — bit-packed pixels

```
Total bits  = width * height * channels * bit_depth
Total bytes = ceil(total_bits / 8)
```

Bits are packed **MSB-first** within each byte, written in **row-major**
order (top-left first, scanning each row left-to-right, then the next
row), with channels **interleaved per pixel** (e.g. R, G, B for RGB).

The final byte is zero-padded on the right if the total bit count is
not a multiple of 8.

---

## Dimension convention

The header writes **width first, then height** — `<W_hi W_lo>` then
`<H_hi H_lo>`. The pixel array in memory is **row-major (H, W)**, so
a reader that wants a NumPy-style shape tuple uses `(height, width)`,
not `(width, height)`.

A single historical inscription (Sabina) transposed this and stored
height before width in the header bytes. That's a documented one-off,
not the convention — the canonical builder writes width first and the
canonical reader expects width first.

---

## Title region

The bytes between the 12-byte structural header and the start of the
body comprise the **title region**. The body's start offset is computed
from the declared dimensions:

```
body_offset  = total_bytes - (W × H × channels × bit_depth + 7) // 8
title_region = bytes[12 : body_offset]
```

Three v1-canonical forms of title region are accepted (May 2026
relaxation):

| Form | Example bytes | Title resolves to |
|---|---|---|
| pipe-bracketed | `\|Title\|` | `"Title"` |
| pipe-bracketed with cabeza padding | `\|Title\|<arbitrary bytes>` | `"Title"` (first non-empty pipe field) |
| double-pipe wrap | `\| \|Title\| \|` | `"Title"` (whitespace-only fields between pipes collapse) |
| bare title, no pipes | `Title bytes` | `"Title bytes"` (whole region, decoded UTF-8) |
| empty | (zero-length region) | `""` |

**Reader rule (canonical):**
- If any `\|` is present: split the title region on `\|`, strip each
  field of surrounding whitespace, and take the first non-empty field
  as the title.
- Else: decode the whole region as UTF-8 with `errors='replace'`,
  truncate at the first replacement char (which marks the start of
  non-text cabeza padding bytes), and strip whitespace.

**Builder rule (canonical):**
- Write `\|TITLE\|` form. The reader accepts other historical forms
  but the builder produces the cleanest one.

This relaxation made the 8 historical images (La Verna, Monte Veritá,
Dr. Doeg en Buenos Aires, Peter Bea, Peter on her blanket, Sparkle
🐈‍⬛, ha image, ca image) canonical_v1 — their structural headers
(magic, type, tone, color, W, H, bit_depth) are all valid; only the
title region differs from the strict `\|TITLE\|` form.

The same rule extends to the text quipu (0x00) title region in the
header — both types share the convention.

---

## Tone vocabulary

Same as text quipus:

| `<tone>` | name | when to use |
|---|---|---|
| `0x00` | ordinary  | the default; descriptive or neutral imagery |
| `0x01` | affection | paired / intimate / addressed-to-a-specific-other imagery |
| `0x0d` | demonic   | imagery that documents harm: portraits of dictators, founding documents of state terror, surveillance instruments |
| `0xff` | reverence | the dead, ancestors, formal commemorative imagery |

---

## Color modes

| `<color>` | name | channels | values per pixel |
|---|---|---|---|
| `0x00` | grayscale | 1 | one intensity value |
| `0x01` | RGB | 3 | red, green, blue |
| `0x02` | grayscale + alpha | 2 | gray, alpha (interleaved per pixel) |
| `0x03` | RGBA | 4 | red, green, blue, alpha (interleaved per pixel) |

`bit_depth` applies uniformly to all channels including alpha. So
4-bit RGBA gives 16 levels per channel: 16 reds × 16 greens × 16 blues
× 16 alpha levels, 16 bits per pixel total. 1-bit alpha (full
transparency / full opacity) is achievable by mixing per-pixel channel
bit-depths only via separate inscriptions — the protocol does not yet
support per-channel bit-depth specification.

The alpha modes (0x02, 0x03) were added 2026-05-22 to support sprite
sheets and matte-channeled images (dancers, characters, cutouts).
RGBA is the dominant choice for these; gray+alpha is useful for
silhouette / line-art with transparency.

Any byte value other than `0x00`..`0x03` is rejected by the canonical
builder. Future amendments may allocate additional color modes (CMYK,
indexed-palette, HDR, depth-augmented, etc.).

---

## Bit depth

`bit_depth` is in the range `[1, 8]` and applies per channel per
pixel. Common values:

| bit_depth | values per channel | typical use |
|---|---|---|
| 1 | 2 (B&W) | bitmap text, line art |
| 4 | 16 | restrained palettes |
| 5 | 32 | the project default — fits 3 channels in 15 bits/pixel, ~3 bytes per pixel-and-a-half |
| 8 | 256 | full-byte channels |

5-bit RGB is the prevailing on-chain choice (Domremy, Sabina, La Verna,
Monte Veritá): a 160×240 RGB image at 5 bpc fits in 72 KB. Acceptable
inscription cost; visibly compressed but recognisable.

---

## Worked example — Domremy bordado image

On chain at root [`b92bbbf974ad7d1b…`](https://blockchair.com/dogecoin/transaction/b92bbbf974ad7d1ba035d03b34ee455dadf4e85c365d841beb4443e55da0b66c)
(bordado address).

Header (44 bytes):

```
c1 dd 00 01                          magic + version
03                                   type = image
ff                                   tone = reverence
01                                   color = RGB (3 channels)
00 a0                                width  = 160 px
00 f0                                height = 240 px
05                                   bit_depth = 5 bits/channel
7c 20 44 6f 6d 72 65 6d 79 3a 20    "| Domremy: Campo de Bourlemont |"
43 61 6d 70 6f 20 64 65 20 42 6f
75 72 6c 65 6d 6f 6e 74 20 7c
```

Body: `160 * 240 * 3 * 5 / 8 = 72000` bytes of bit-packed pixel data.

Total inscription: 44 + 72000 = 72044 bytes; ~900 OP_RETURNs across the
diamond's strands.

---

## Reference parser

See [`canonical/image.py`](../../canonical/image.py) for the
authoritative builder + reader + pack/unpack helpers. Round-trip
self-tests cover:

- 4×3 RGB 8-bit header round-trip with pixel values 0..35
- 5-bit pack/unpack round-trip (project-default depth)
- Domremy on-chain header parse (verifies the byte layout against real bytes)
- 6 validation cases (body-length mismatch, bit-depth out of range,
  invalid color, zero width, title-with-pipe, pixel-value-overflow)

---

## Why `0x03`

Inherited from the earliest quipu inscriptions in the corpus (`12_cuaderno.ipynb`
through `17_cuaderno.ipynb`). The byte itself has no Latin-letter
mnemonic, but the position — early, low-numbered — reflects that
images were one of the first types implemented after plain text.
