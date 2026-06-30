# Quipu type `0x07` — Sound

> **STATUS: CANONICAL v1.** Container in
> [`canonical/sound.py`](../../canonical/sound.py) (keyless, pure-stdlib);
> the `0x20` music codec in [`canonical/music.py`](../../canonical/music.py)
> (keyless, pure-stdlib). The numpy DSP for the vocoders lives in
> [`voice_codec.py`](../../voice_codec.py); the music mixer in the prototype
> `working/music/music_codec.py`. The **`0x07` sound type is the umbrella for
> all audio** — the codec byte is the subtype discriminator, selecting one of
> three worlds: **voice** (vocoders `0x00`–`0x02`), **audio** (opaque standard
> formats `0x10`–`0x13`), or **music** (a composed recipe, `0x20`).

A *sound quipu* wraps an opaque body of encoded audio in a small,
self-describing header. The header carries a **codec byte**, a
**sample rate**, a **channel count**, a **duration**, a small
**codec-specific metadata blob** (`codec_meta`), and an optional
**title**. The container is *codec-agnostic*: it never decodes the body.
What the body bytes mean is defined entirely per codec.

This canonicalizes the old `0x07` slot. The earlier "voice" sketch was
never inscribed, so its wire format was redesigned freely into this
container. Speech vocoders and opaque standard formats now share one type
byte; the codec enum disambiguates.

The reader is **keyless** and the container parse is **pure stdlib**
(`struct` only — **no numpy**, no third-party imports). The vocoder DSP in
`voice_codec.py` imports numpy *lazily*, so the container builds and reads
on a machine with no numpy at all.

---

## Byte layout

### Header — `15 + cmlen + titlelen` bytes

```
offset  field                bytes  meaning
0..3    c1 dd 00 01          4B  magic + protocol version 0.1
4       07                   1B  type byte = sound
5       <tone>               1B  tone byte — see tone.md
6       <codec>              1B  codec / format byte (enum below)
7..8    <sample_rate:u16>    2B  Hz, big-endian; 0 = unknown / in-bitstream
9       <channels>           1B  channel count; 0 = unknown
10..13  <duration_ms:u32>    4B  total duration in ms, big-endian; 0 = unknown
14      <cmlen>              1B  codec-meta length, 0..255
15..    <codec_meta:cmlen>   ..  codec-specific bytes, opaque to the container
.       <titlelen>           1B  length of title, 0..255
.       <title:titlelen>     ..  UTF-8 human title; may be length 0
```

All multi-byte integers are **big-endian** (`struct '>H'`, `'>I'`,
`'>f'`). The fixed structural prefix is **15 bytes** (offsets 0..14),
with the codec-meta length byte at offset 14. The `codec_meta` region
begins at offset 15; the title-length byte sits at offset `15 + cmlen`,
and the title at `16 + cmlen`. Both length-prefixed regions are
**self-delimiting**, so the header length is recoverable from the header
bytes alone — a reader never needs the total blob length to split header
from body:

```
header_len = 15 + cmlen + titlelen
           = 16 + cmlen + titlelen   (including the title-length byte)
```

(`canonical/sound.py` exposes `sound_header_len(header_bytes)` returning
exactly this, for blob-splitting helpers.)

### Body — encoded audio bytes

The body is opaque. The container neither parses nor transforms it. The
reader reports `size = len(body)` and returns the bytes verbatim.

---

## Codec enum

| byte | name | kind | `codec_meta` |
|------|------|------|--------------|
| `0x00` | `stft`   | quipu STFT-magnitude vocoder (speech)       | `n_frames:u16 + g_min:f32 + g_max:f32` (10 B, `'>Hff'`) |
| `0x01` | `lpc`    | quipu LPC-10 vocoder (speech)               | `n_frames:u16` (2 B, `'>H'`) |
| `0x02` | `codec2` | Codec2-700C (speech, needs libcodec2)       | `n_frames:u16` (2 B, `'>H'`) |
| `0x10` | `opus`   | opaque ogg/opus bytes                       | `b''` |
| `0x11` | `mp3`    | opaque                                      | `b''` |
| `0x12` | `wav`    | opaque WAV / PCM                            | `b''` |
| `0x13` | `flac`   | opaque                                      | `b''` |
| `0x20` | `music`  | composed-music **recipe** — the `QM` module (synth + sampled + sliced instruments on a note timeline) | `b''` (the module is the body) |

The split is deliberate:

- **Vocoder codecs `0x00`–`0x02`** carry quipu-native bodies produced and
  consumed by the numpy DSP in `voice_codec.py`. A browser cannot play
  them; they must be decoded by the sound DSP first. They are *lean* —
  designed for the OP_RETURN economics of the protocol (see below).
- **Opaque codecs `0x10`–`0x13`** carry a real container/bitstream that an
  audio library or browser decodes directly. Their `codec_meta` is empty;
  the metadata they need is in the bitstream itself.

Any codec byte parses fine. An **unknown** byte surfaces via
`codec_name()` as `'unknown_0xNN'`, and the builder accepts **any** byte
in `[0, 255]` — both for forward compatibility. The 10-byte STFT
`codec_meta` is the largest defined, comfortably under the 255-byte cap.

---

## API

```python
build_sound_quipu(codec, body, *, sample_rate=0, channels=0,
                  duration_ms=0, codec_meta=b'', title='',
                  tone=TONE_ORDINARY) -> (header_bytes, body_bytes)
```

Validation: `validate_tone(tone)`; `0 <= codec <= 255`;
`0 <= sample_rate <= 65535`; `0 <= channels <= 255`;
`0 <= duration_ms <= 0xFFFFFFFF`; `len(codec_meta) <= 255`;
`len(title.encode('utf-8')) <= 255`. The body is returned **unchanged**.

```python
read_sound_quipu(header_bytes, body_bytes) -> dict
```

Returns:

```python
{
  'type':        'sound',
  'tone':        int,
  'codec':       int,
  'codec_name':  str,    # 'stft' / ... / 'unknown_0xNN'
  'sample_rate': int,    # Hz; 0 = unknown
  'channels':    int,    # 0 = unknown
  'duration_ms': int,    # 0 = unknown
  'codec_meta':  bytes,  # opaque codec-specific blob
  'title':       str,
  'body':        bytes,
  'size':        int,    # len(body)
}
```

Validates magic == `c1dd0001` and `header_bytes[4] == 0x07`. **Keyless** —
no key material is consulted.

**Reader calling convention.** `decode.py` invokes every reader as
`reader(hdr, body)` — the header strand and body strand arrive as two
separate `bytes` arguments, so the signature is
`read_sound_quipu(header_bytes, body_bytes)`.

### `codec_meta` (un)packers

For the vocoder codecs, `canonical/sound.py` provides pure-stdlib
helpers so the container can assemble/parse `codec_meta` without numpy:

```python
pack_stft_meta(n_frames, g_min, g_max) -> bytes   # '>Hff', 10 bytes
unpack_stft_meta(codec_meta) -> (n_frames, g_min, g_max)

pack_frames_meta(n_frames) -> bytes               # '>H', 2 bytes
unpack_frames_meta(codec_meta) -> n_frames        # LPC / Codec2
```

Name maps: `CODEC_NAMES` (byte → name), `CODEC_BY_NAME` (name → byte),
`CODEC_MIME` (opaque codec → MIME, for renderers emitting `<audio>`), and
`VOCODER_CODECS` (the frozenset `{0x00, 0x01, 0x02}` of codecs whose
bodies need the DSP).

---

## Vocoder DSP integration (`voice_codec.py`)

`canonical/sound.py` is the *format*; `voice_codec.py` is the *DSP*. The
DSP keeps numpy **lazy** (imported only when an encode/decode actually
runs), so importing it — and the container — works on a numpy-free box.

```python
encode_sound_stft(audio, title='', tone=0)   -> (header, body)  # codec 0x00
encode_sound_lpc(audio, title='', tone=0)    -> (header, body)  # codec 0x01
encode_sound_codec2(audio, title='', tone=0) -> (header, body)  # codec 0x02
decode_sound(header, body) -> (audio, meta)  # reads container, routes to DSP
```

Each encoder runs its DSP to compute `body` + the vocoder parameters,
then calls `sound.build_sound_quipu(...)` with the appropriate
`codec_meta`. `decode_sound` reads the container (keyless) and dispatches
on the codec byte to the matching DSP; for an **opaque** codec it raises,
pointing the caller at `sound.read_sound_quipu` (the body is a real
bitstream for a browser / audio library, not something the vocoder DSP
decodes). The legacy names `encode_voice` / `encode_voice_lpc` /
`encode_voice_c2` remain as aliases of the `encode_sound_*` adapters.

### STFT codec (`0x00`) detail

Sample rate 8 kHz; 256-sample (32 ms) Hann window; 128-sample hop (50 %
overlap → constant-OLA, 62.5 frames/sec); 32 of 129 magnitude bins kept
(0–1 kHz, where vowel formants and voiced excitation concentrate); 8-bit
log-magnitude quantized per-utterance via a global min/max (the `g_min`
/ `g_max` in `codec_meta`); Griffin–Lim phase recovery on decode. Body is
`n_frames × 32` bytes ≈ **2000 bytes/sec**. Quality is "whispered"
(random-phase Griffin–Lim is the known weakness for speech). LPC (`0x01`)
is robotic/buzzy but intelligible at ~480 B/sec; Codec2 700C (`0x02`) is
the leanest at ~88 B/sec but needs `libcodec2` + `pycodec2`.

---

## Music codec (`0x20`)

Music is the one codec that is a **recipe, not a recording**. The vocoders and
standard formats are *waveforms* — decode bytes to samples. A music body is a
**score**: instruments plus a note timeline, which a numpy mixer *renders* to a
waveform. (Same shape as MIDI living under `audio/*`: the output is sound, the
encoding is symbolic — so music belongs *under* `0x07`, as a codec, not as a
separate type.) The body is the **`QM` module**; the format is
[`canonical/music.py`](../../canonical/music.py) — keyless and pure-stdlib, with
pcm carried as raw bytes; the rendering mixer is the DSP layer.

### Five instrument kinds — the ways music is made

| kind | name | what it is |
|------|------|------------|
| `0` | `synth`      | oscillators (square / triangle / saw / sine / noise) + ADSR — *generated* |
| `1` | `sample`     | a whole recording, pitched across the keyboard, looped for sustain |
| `2` | `sliced`     | one long recording + a slice table — chop it, re-sequence the pieces |
| `3` | `sample_ref` | a `sample` whose audio is **resolved from another sound quipu** — no embedded PCM |
| `4` | `sliced_ref` | a `sliced` whose clip is **resolved from another sound quipu** |

A 1-byte `kind` on each instrument (the per-element discriminator again, cf. the
celestial kind byte). One track may mix all of them on a single note timeline — a
synth sub, a sampled pad, chopped vocal hits, and a choir **referenced** from a
recording already on the chain (see [Build by reference](#build-by-reference)).

### Per-instrument bit depth (`bits`)

`sample` and `sliced` instruments each carry a **`bits`** byte: `8` (dusty /
lean, ~−48 dB floor, SP-1200 character) or `16` (clean / hi-fi, ~−96 dB). Each
instrument chooses independently, so a dusty 8-bit drum chop and a clean 16-bit
lead can share one track. (Reference kinds 3/4 store no PCM, so they carry no
`bits` — the resolver decodes the referenced audio to float and the render
quantizes internally.)

### Build by reference

`sample_ref` (kind 3) and `sliced_ref` (kind 4) store **no PCM** — only a 32-byte
**`ref_txid`** (the root txid of another sound quipu, the same reference primitive
as [`book.py`](../../canonical/book.py)) plus an extraction spec: `src_start_ms`,
`src_len_ms`, a target `srate`, a `flags` byte (bit 0 `REF_NORMALIZE` =
peak-normalize the extracted region), and either a loop (kind 3) or a slice table
(kind 4, indexing the *resolved* samples).

A renderer **resolves** each reference: fetch the named quipu
(`colegio_tools.fetch_quipu_bytes`), decode its audio (opus / wav / codec2 / …),
take `[src_start_ms, +src_len_ms]`, resample to `srate`, optionally normalize —
and from there it plays exactly like an embedded `sample` / `sliced`. The DSP
layer's `render_music(body, rate, resolver)` takes a
`resolver(ref_txid) -> (pcm, source_rate)`; the keyless container only stores and
reads the reference.

This is what makes a **sound library** possible: inscribe a recording once, and
any number of future compositions reference it — a referenced instrument is
~95 bytes versus the tens of KB of embedded PCM. Because a consolidated diamond
signs every root deterministically before broadcast and **backfills** placeholder
txids with the real sibling roots, a song can even reference sources inscribed *in
the same batch* (only a cross-batch *child* — a quipu that spends from this one —
cannot be referenced). One quipu may **mix both**: embed some samples, reference
others.

### `QM` module wire format (the `0x20` body)

All multi-byte ints **big-endian**:

```
'QM' · version:u8=2 · tempo_bpm:u16 · rows_per_beat:u8 · num_channels:u8 ·
num_instruments:u8 · num_patterns:u8 · order_len:u8 · master_volume:u8
  (version 1 carried num_rows & event.row as u8; version 2 widens both to u16
   for long, finely-subdivided patterns. The reader accepts both.)
INSTRUMENTS (num_instruments):
  kind:u8 · namelen:u8 · name · volume:u8 ·
  attack_ms:u16 · decay_ms:u16 · sustain_level:u8 · release_ms:u16
  kind 0 synth:  waveform:u8 · duty:u8           (for noise, duty = lowpass tone)
  kind 1 sample: srate:u16 · base_note:u8 · bits:u8 · loop_start:u16 ·
                 loop_end:u16 · pcm_len:u32(SAMPLES) · pcm (int8 | int16-BE)
  kind 2 sliced: srate:u16 · base_note:u8 · bits:u8 · num_slices:u16 ·
                 num_slices×(start:u32,length:u32) [SAMPLES] ·
                 pcm_len:u32(SAMPLES) · pcm (int8 | int16-BE)
  kind 3 sample_ref: ref_txid:32 · srate:u16 · base_note:u8 · flags:u8 ·
                 src_start_ms:u32 · src_len_ms:u32 · loop_start:u32 · loop_end:u32
  kind 4 sliced_ref: ref_txid:32 · srate:u16 · base_note:u8 · flags:u8 ·
                 src_start_ms:u32 · src_len_ms:u32 · num_slices:u16 ·
                 num_slices×(start:u32,length:u32) [resolved SAMPLES]
    flags bit 0 = REF_NORMALIZE (peak-normalize the extracted region)
PATTERNS (num_patterns):
  num_rows:u16 · num_events:u16 ·
  events × [row:u16, channel:u8, note:u8, instrument:u8, volume:u8]
    note 0 = key-off; for a SLICED / SLICED_REF instrument note = slice_index + 1
ORDER: order_len × pattern_index:u8
```

### Data density

The **score** — every note, every chop, the whole arrangement — is **~1 KB**.
You pay bytes only for the *audio you embed*:

- **Synthesis is nearly free** — a full chiptune piece is ~1 KB total (≈ a
  single OP_RETURN strand).
- **Slicing is a multiplier** — one recording becomes a whole arrangement, and a
  take typically triggers only a handful of slices, so a real inscription keeps
  only the used slices (the full source clip can dominate size otherwise).

### Rendering

A `QM` body must be *rendered* (the mixer walks order → patterns → events on a
clock at `samples_per_row = rate·60/(tempo·rows_per_beat)`, synthesizes or
resamples each voice, applies ADSR/velocity, sums, soft-limits, peak-normalizes)
to produce a waveform — which a viewer then plays. Unlike the opaque codecs, a
browser cannot play a `QM` body directly; it is rendered to a WAV at build time.
Example pieces (in `working/music/`): `chiptune` (synth only), `jam_boombap` (a
hummed melody chopped into a sliced instrument over synth drums), `calm`,
`wutang`.

---

## On-chain economics

The vocoder codecs exist because audio is large and OP_RETURN is small.
At **80 bytes/tx** and a **25-tx-per-strand** mempool-ancestor cap, a
quipu is assembled from a cabeza strand (the header) plus one or more
cuerpo strands (the body):

| codec | body rate | 5 s clip | 60 s clip | cuerpo strands (60 s) |
|-------|-----------|----------|-----------|------------------------|
| `0x00` stft   | ~2000 B/s | ~10 KB | ~120 KB | ~6 |
| `0x01` lpc    | ~480 B/s  | ~2.4 KB | ~29 KB | ~2 |
| `0x02` codec2 | ~88 B/s   | ~0.5 KB | ~5.3 KB | ~1 |

So a one-minute Ephemeris utterance is a single diamond quipu of a few
cuerpo strands — affordable at the standard tip. The opaque codecs
(`0x10`–`0x13`) are for cases where the audio already exists as a small,
real bitstream worth inscribing verbatim (a short opus/mp3/wav/flac
clip); they carry no DSP cost but no extra leanness either.

---

## Renderer notes

A renderer keys off `codec`:

- **Opaque codecs `0x10`–`0x13`** map to a MIME type (`CODEC_MIME`) and can
  be emitted as an HTML5 `<audio controls>` with the body as a base64
  data-URI — but only when the body is small enough to inline (a renderer
  caps the raw body length, e.g. a few MB, before base64's ~33 % inflation,
  and otherwise falls back to a download link / metadata card).
- **Vocoder codecs `0x00`–`0x02`** can **never** be emitted as `<audio>` —
  the browser cannot decode them. A renderer always shows a metadata card
  noting "quipu vocoder — needs the sound DSP to decode", regardless of
  size.

Show `title`, `codec_name`, `duration_ms`, `sample_rate`, `channels`, and
`size` on the card either way.

---

## Reference parser

See [`canonical/sound.py`](../../canonical/sound.py) for the authoritative
builder + reader, and [`voice_codec.py`](../../voice_codec.py) for the
vocoder DSP. Round-trip self-tests cover:

- an **opaque** `0x12 wav` with synthetic bytes — full metadata + body
  round-trip, byte-identical;
- the **`0x00 stft`** vocoder `codec_meta` (`pack`/`unpack_stft_meta`) and a
  synthetic-body round-trip (no numpy needed for the container path);
- the **`0x01 lpc` / `0x02 codec2`** 2-byte `codec_meta`
  (`pack`/`unpack_frames_meta`);
- an **unknown** codec byte surfacing as `'unknown_0xNN'`, empty title,
  and the name maps;
- validation cases (bad tone, out-of-range sample rate / channels /
  duration, over-long `codec_meta` / title, codec out of range, wrong type
  byte);
- container **purity** (`numpy` not imported after `import sound`);
- DSP **integration** in `voice_codec.py`: `encode_sound_*` emits a valid
  container the **keyless** reader parses, `decode_sound` routes it back to
  audio, and `import voice_codec` succeeds with numpy unavailable (lazy
  import), while the container build/read path stays numpy-free.
```