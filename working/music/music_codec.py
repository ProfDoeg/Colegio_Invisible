"""
music_codec.py — quipu MUSIC codec (prototype) for the 0x07 SOUND container.

A piece of music is a *recipe*, not rendered audio: a set of instruments plus a
note timeline (patterns + an order list), rendered to PCM by a deterministic
numpy mixer. ONE module format holds BOTH synthesized (chiptune) instruments and
sampled instruments — each instrument carries a 1-byte KIND tag (0=synth,
1=sample). This is the per-element-discriminator pattern already used elsewhere
in the codebase (cf. the celestial 0xce kind map).

Layering
--------
  * The MUSIC MODULE is the *body* of a 0x07 sound quipu, under codec byte 0x20.
    Its (un)packers — build_music_body / read_music_body — are pure stdlib
    (struct only), so the module wire format builds and reads on a machine
    with no numpy.
  * render_music() is the numpy DSP that turns a module into a float32 mono
    waveform. It imports numpy at module top because it is the synth/mixer.
  * The container (sound.py, build_sound_quipu / read_sound_quipu) is reused
    verbatim — we only choose codec 0x20 and supply this module as the body.

Wire format (the 0x07 body, codec 0x20). All multi-byte ints BIG-ENDIAN:

  'QM'                      2B  magic (0x51 0x4D)
  version:u8 = 2            v1: u8 num_rows & event.row; v2: u16 each (long,
                           finely-subdivided patterns). Reader accepts both.
  tempo_bpm:u16
  rows_per_beat:u8          rows per quarter-note (e.g. 4 = 16th-note grid)
  num_channels:u8           polyphony channels (a chord = several channels/row)
  num_instruments:u8
  num_patterns:u8
  order_len:u8
  master_volume:u8          0..255
  INSTRUMENTS (num_instruments of):
    kind:u8                 0 synth, 1 sample
    namelen:u8, name        UTF-8 label
    volume:u8               0..255 instrument gain
    attack_ms:u16  decay_ms:u16  sustain_level:u8(0..255)  release_ms:u16
    if synth:  waveform:u8 (0 square,1 triangle,2 saw,3 sine,4 noise)
               duty:u8 (square duty, 128=50%)
    if sample: srate:u16  base_note:u8  bits:u8(8 or 16)  loop_start:u16 loop_end:u16(0,0=one-shot)
               pcm_len:u32 (SAMPLE count)  pcm: pcm_len samples, int8(bits=8) or int16-BE(bits=16)
    if sliced: srate:u16  base_note:u8  bits:u8(8 or 16)  num_slices:u16
               num_slices x (start:u32, length:u32)  (slice regions, in SAMPLES)
               pcm_len:u32 (SAMPLE count)  pcm: pcm_len samples, int8(bits=8) or int16-BE(bits=16)
  PATTERNS (num_patterns of):
    num_rows:u16             (v1: u8)
    num_events:u16
    EVENTS (num_events of): row:u16 channel:u8 note:u8 instrument:u8 volume:u8
        row is u16 in v2 (u8 in v1)
        note: 0 = key-off, 1..127 = MIDI note number
  ORDER:  order_len x pattern_index:u8
"""

from __future__ import annotations

import struct

import numpy as np


# ---------------------------------------------------------------------------
# Format constants
# ---------------------------------------------------------------------------

MUSIC_MAGIC   = b"QM"          # 0x51 0x4D
MUSIC_VERSION = 2              # v2: u16 num_rows & event.row (v1 = u8; reader accepts both)

CODEC_MUSIC = 0x20             # the 0x07 sound container's codec byte for music

# Instrument kinds (the per-element discriminator).
KIND_SYNTH      = 0
KIND_SAMPLE     = 1
KIND_SLICED     = 2      # one long PCM + a slice table; event.note = slice_index + 1
KIND_SAMPLE_REF = 3      # like SAMPLE, but PCM RESOLVED from a referenced quipu
KIND_SLICED_REF = 4      # like SLICED, but the clip RESOLVED from a referenced quipu

# A reference instrument names another sound quipu by its 32-byte ROOT txid (the
# book.py convention) and stores NO PCM. At render time a `resolver(ref_txid)`
# fetches+decodes that quipu; the region [src_start_ms, +src_len_ms] is taken,
# resampled to `srate`, optionally peak-normalized, and used as the sample/clip.
REF_NORMALIZE = 0x01     # flags bit: peak-normalize the extracted region

# Synth waveforms.
WAVE_SQUARE   = 0
WAVE_TRIANGLE = 1
WAVE_SAW      = 2
WAVE_SINE     = 3
WAVE_NOISE    = 4

WAVE_NAMES = {
    WAVE_SQUARE:   "square",
    WAVE_TRIANGLE: "triangle",
    WAVE_SAW:      "saw",
    WAVE_SINE:     "sine",
    WAVE_NOISE:    "noise",
}

# Deterministic noise seed — render_music must never depend on global RNG state.
NOISE_SEED = 0x5150  # 'QP'


# ---------------------------------------------------------------------------
# Helpers to build instrument / event / pattern dicts
# ---------------------------------------------------------------------------

def synth_instrument(name, waveform=WAVE_SQUARE, *, duty=128, volume=255,
                     attack_ms=2, decay_ms=40, sustain_level=200,
                     release_ms=60):
    """Build a synth instrument dict (kind 0).

    waveform: one of WAVE_*; duty is the square duty (128 = 50%). ADSR times in
    ms, sustain_level in 0..255.
    """
    return {
        "kind":          KIND_SYNTH,
        "name":          str(name),
        "volume":        int(volume),
        "attack_ms":     int(attack_ms),
        "decay_ms":      int(decay_ms),
        "sustain_level": int(sustain_level),
        "release_ms":    int(release_ms),
        "waveform":      int(waveform),
        "duty":          int(duty),
    }


# --- Sample bit-depth (per-instrument): 8-bit (dusty/lean) or 16-bit (clean). ---
def _quantize_pcm(pcm, bits):
    """Round/clip PCM to int8 (bits=8) or int16 (bits=16). `pcm` may be any
    numeric array already scaled to the target range."""
    a = np.round(np.asarray(pcm, dtype=np.float64))
    if bits == 8:
        return np.clip(a, -128, 127).astype(np.int8)
    if bits == 16:
        return np.clip(a, -32768, 32767).astype(np.int16)
    raise ValueError(f"bits must be 8 or 16; got {bits}")


def _pcm_to_bytes(pcm, bits):
    """Serialize PCM samples -> bytes: int8 (8-bit) or int16 BIG-ENDIAN (16-bit)."""
    return pcm.astype(np.int8).tobytes() if bits == 8 else pcm.astype(">i2").tobytes()


def _pcm_from_bytes(buf, bits):
    """Parse PCM bytes back to a native int array (int8 or int16)."""
    if bits == 8:
        return np.frombuffer(buf, dtype=np.int8).copy()
    return np.frombuffer(buf, dtype=">i2").astype(np.int16)


def _pcm_scale(bits):
    """Float divisor to bring stored PCM into [-1, 1]."""
    return 128.0 if bits == 8 else 32768.0


def sample_instrument(name, pcm, *, srate=22050, base_note=60, bits=8,
                      loop_start=0, loop_end=0, volume=255,
                      attack_ms=0, decay_ms=0, sustain_level=255,
                      release_ms=20):
    """Build a sample instrument dict (kind 1) from a PCM one-shot.

    pcm: a 1-D array-like of signed PCM already scaled to `bits` (int8 for
    bits=8, int16 for bits=16). base_note is the MIDI note at which it plays at
    its native rate. loop_start/loop_end frame a sustain loop; (0,0) = one-shot.
    bits selects the per-instrument depth: 8 (dusty/lean) or 16 (clean/hi-fi).
    """
    return {
        "kind":          KIND_SAMPLE,
        "name":          str(name),
        "volume":        int(volume),
        "attack_ms":     int(attack_ms),
        "decay_ms":      int(decay_ms),
        "sustain_level": int(sustain_level),
        "release_ms":    int(release_ms),
        "srate":         int(srate),
        "base_note":     int(base_note),
        "bits":          int(bits),
        "loop_start":    int(loop_start),
        "loop_end":      int(loop_end),
        "pcm":           _quantize_pcm(pcm, int(bits)),
    }


def sliced_instrument(name, pcm, slices, *, srate=22050, base_note=60, bits=8,
                      volume=255, attack_ms=1, decay_ms=0, sustain_level=255,
                      release_ms=8):
    """Build a SLICED-sample instrument (kind 2): ONE long PCM clip plus a slice
    table. `slices` is a list of (start, length) frame regions into the clip. An
    event triggers a slice via note = slice_index + 1 (note 0 stays the universal
    key-off). The slice plays at native pitch as a one-shot (cut by the next event
    on its channel). This is the sampler/chop model — reference a clip, and a
    section of it. bits = 8 (dusty/lean) or 16 (clean/hi-fi) per instrument."""
    sl = [(int(s), int(l)) for (s, l) in slices]
    return {
        "kind":          KIND_SLICED,
        "name":          str(name),
        "volume":        int(volume),
        "attack_ms":     int(attack_ms),
        "decay_ms":      int(decay_ms),
        "sustain_level": int(sustain_level),
        "release_ms":    int(release_ms),
        "srate":         int(srate),
        "base_note":     int(base_note),
        "bits":          int(bits),
        "slices":        sl,
        "pcm":           _quantize_pcm(pcm, int(bits)),
    }


def _coerce_txid(ref):
    """Raw 32 bytes or 64-hex -> raw 32 bytes. None/'' -> 32 zero bytes (the
    book.py placeholder sentinel for an unresolved reference)."""
    if ref is None or ref == "":
        return b"\x00" * 32
    if isinstance(ref, (bytes, bytearray)):
        if len(ref) != 32:
            raise ValueError(f"ref_txid raw must be 32 bytes (got {len(ref)})")
        return bytes(ref)
    if isinstance(ref, str):
        s = ref.strip()
        if len(s) != 64 or any(c not in "0123456789abcdefABCDEF" for c in s):
            raise ValueError("ref_txid hex must be exactly 64 hex chars")
        return bytes.fromhex(s)
    raise ValueError(f"ref_txid must be bytes(32) or hex(64); got {type(ref).__name__}")


def sample_ref_instrument(name, ref_txid, *, src_start_ms, src_len_ms,
                          srate=22050, base_note=60, normalize=True,
                          loop_start=0, loop_end=0, volume=255, attack_ms=0,
                          decay_ms=0, sustain_level=255, release_ms=20):
    """A whole-sample instrument (kind 3) whose audio is RESOLVED from another
    sound quipu (ref_txid). Stores no PCM — only the reference + extraction spec."""
    return {
        "kind": KIND_SAMPLE_REF, "name": str(name), "volume": int(volume),
        "attack_ms": int(attack_ms), "decay_ms": int(decay_ms),
        "sustain_level": int(sustain_level), "release_ms": int(release_ms),
        "ref_txid": _coerce_txid(ref_txid), "srate": int(srate),
        "base_note": int(base_note), "flags": (REF_NORMALIZE if normalize else 0),
        "src_start_ms": int(src_start_ms), "src_len_ms": int(src_len_ms),
        "loop_start": int(loop_start), "loop_end": int(loop_end),
    }


def sliced_ref_instrument(name, ref_txid, slices, *, src_start_ms, src_len_ms,
                          srate=22050, base_note=60, normalize=True,
                          volume=255, attack_ms=1, decay_ms=0,
                          sustain_level=255, release_ms=8):
    """A sliced instrument (kind 4) whose clip is RESOLVED from another sound
    quipu. `slices` are (start,length) in the RESOLVED samples (post-resample)."""
    return {
        "kind": KIND_SLICED_REF, "name": str(name), "volume": int(volume),
        "attack_ms": int(attack_ms), "decay_ms": int(decay_ms),
        "sustain_level": int(sustain_level), "release_ms": int(release_ms),
        "ref_txid": _coerce_txid(ref_txid), "srate": int(srate),
        "base_note": int(base_note), "flags": (REF_NORMALIZE if normalize else 0),
        "src_start_ms": int(src_start_ms), "src_len_ms": int(src_len_ms),
        "slices": [(int(s), int(l)) for (s, l) in slices],
    }


def event(row, channel, note, instrument, volume=255):
    """Build a note event dict. note 0 = key-off; 1..127 = MIDI note."""
    return {
        "row":        int(row),
        "channel":    int(channel),
        "note":       int(note),
        "instrument": int(instrument),
        "volume":     int(volume),
    }


def pattern(num_rows, events):
    """Build a pattern dict from a row count and a list of event dicts."""
    return {"num_rows": int(num_rows), "events": list(events)}


# ---------------------------------------------------------------------------
# Module (un)packers — pure stdlib (struct), the 0x07 body
# ---------------------------------------------------------------------------

def _u8(v, field):
    v = int(v)
    if not (0 <= v <= 0xFF):
        raise ValueError(f"{field} must fit in u8 [0,255]; got {v}")
    return v


def _u16(v, field):
    v = int(v)
    if not (0 <= v <= 0xFFFF):
        raise ValueError(f"{field} must fit in u16 [0,65535]; got {v}")
    return v


def _u32(v, field):
    v = int(v)
    if not (0 <= v <= 0xFFFFFFFF):
        raise ValueError(f"{field} must fit in u32 [0,2^32); got {v}")
    return v


def build_music_body(*, tempo_bpm, rows_per_beat, num_channels, instruments,
                     patterns, order, master_volume=255):
    """Pack a music module into the 0x07 body bytes (codec 0x20).

    instruments: list of dicts from synth_instrument / sample_instrument.
    patterns:    list of dicts from pattern().
    order:       list of pattern indices (u8 each).
    Returns the body bytes.
    """
    instruments = list(instruments)
    patterns = list(patterns)
    order = list(order)

    out = bytearray()
    out += MUSIC_MAGIC
    out += bytes([
        _u8(MUSIC_VERSION, "version"),
    ])
    out += struct.pack(">H", _u16(tempo_bpm, "tempo_bpm"))
    out += bytes([
        _u8(rows_per_beat, "rows_per_beat"),
        _u8(num_channels, "num_channels"),
        _u8(len(instruments), "num_instruments"),
        _u8(len(patterns), "num_patterns"),
        _u8(len(order), "order_len"),
        _u8(master_volume, "master_volume"),
    ])

    # Instruments
    for idx, ins in enumerate(instruments):
        kind = _u8(ins["kind"], f"instrument[{idx}].kind")
        name_raw = str(ins["name"]).encode("utf-8")
        if len(name_raw) > 255:
            raise ValueError(f"instrument[{idx}] name too long (>255 utf-8 B)")
        out += bytes([kind, len(name_raw)])
        out += name_raw
        out += bytes([_u8(ins["volume"], f"instrument[{idx}].volume")])
        out += struct.pack(">H", _u16(ins["attack_ms"], "attack_ms"))
        out += struct.pack(">H", _u16(ins["decay_ms"], "decay_ms"))
        out += bytes([_u8(ins["sustain_level"], "sustain_level")])
        out += struct.pack(">H", _u16(ins["release_ms"], "release_ms"))

        if kind == KIND_SYNTH:
            out += bytes([
                _u8(ins["waveform"], "waveform"),
                _u8(ins["duty"], "duty"),
            ])
        elif kind == KIND_SAMPLE:
            bits = int(ins.get("bits", 8))
            pcm = _quantize_pcm(ins["pcm"], bits)             # pcm_len = SAMPLE count
            out += struct.pack(">H", _u16(ins["srate"], "srate"))
            out += bytes([_u8(ins["base_note"], "base_note"), _u8(bits, "bits")])
            out += struct.pack(">H", _u16(ins["loop_start"], "loop_start"))
            out += struct.pack(">H", _u16(ins["loop_end"], "loop_end"))
            out += struct.pack(">I", _u32(len(pcm), "pcm_len"))
            out += _pcm_to_bytes(pcm, bits)
        elif kind == KIND_SLICED:
            bits = int(ins.get("bits", 8))
            pcm = _quantize_pcm(ins["pcm"], bits)
            slices = list(ins["slices"])
            out += struct.pack(">H", _u16(ins["srate"], "srate"))
            out += bytes([_u8(ins.get("base_note", 60), "base_note"), _u8(bits, "bits")])
            out += struct.pack(">H", _u16(len(slices), "num_slices"))
            for (s, l) in slices:
                out += struct.pack(">II", _u32(s, "slice.start"),
                                   _u32(l, "slice.length"))
            out += struct.pack(">I", _u32(len(pcm), "pcm_len"))
            out += _pcm_to_bytes(pcm, bits)
        elif kind == KIND_SAMPLE_REF:
            out += _coerce_txid(ins["ref_txid"])
            out += struct.pack(">H", _u16(ins["srate"], "srate"))
            out += bytes([_u8(ins["base_note"], "base_note"),
                          _u8(ins.get("flags", 0), "flags")])
            out += struct.pack(">II", _u32(ins["src_start_ms"], "src_start_ms"),
                               _u32(ins["src_len_ms"], "src_len_ms"))
            out += struct.pack(">II", _u32(ins.get("loop_start", 0), "loop_start"),
                               _u32(ins.get("loop_end", 0), "loop_end"))
        elif kind == KIND_SLICED_REF:
            out += _coerce_txid(ins["ref_txid"])
            out += struct.pack(">H", _u16(ins["srate"], "srate"))
            out += bytes([_u8(ins["base_note"], "base_note"),
                          _u8(ins.get("flags", 0), "flags")])
            out += struct.pack(">II", _u32(ins["src_start_ms"], "src_start_ms"),
                               _u32(ins["src_len_ms"], "src_len_ms"))
            slices = list(ins["slices"])
            out += struct.pack(">H", _u16(len(slices), "num_slices"))
            for (s, l) in slices:
                out += struct.pack(">II", _u32(s, "slice.start"), _u32(l, "slice.length"))
        else:
            raise ValueError(f"instrument[{idx}] unknown kind {kind}")

    # Patterns
    for pidx, pat in enumerate(patterns):
        events = list(pat["events"])
        out += struct.pack(">H", _u16(pat["num_rows"], f"pattern[{pidx}].num_rows"))
        out += struct.pack(">H", _u16(len(events), f"pattern[{pidx}].num_events"))
        for ev in events:
            out += struct.pack(">H", _u16(ev["row"], "event.row"))
            out += bytes([
                _u8(ev["channel"], "event.channel"),
                _u8(ev["note"], "event.note"),
                _u8(ev["instrument"], "event.instrument"),
                _u8(ev["volume"], "event.volume"),
            ])

    # Order
    for o in order:
        out += bytes([_u8(o, "order")])

    return bytes(out)


def read_music_body(body):
    """Parse a music module body (codec 0x20) into a dict. Pure stdlib.

    Returns:
      {
        'version', 'tempo_bpm', 'rows_per_beat', 'num_channels',
        'master_volume',
        'instruments': [ {kind, name, volume, adsr..., + kind-specific} ],
        'patterns':    [ {num_rows, events:[{row,channel,note,instrument,volume}]} ],
        'order':       [pattern_index, ...],
      }
    """
    body = bytes(body)
    if body[:2] != MUSIC_MAGIC:
        raise ValueError("not a music module ('QM' magic missing)")
    p = 2

    def need(n):
        if p + n > len(body):
            raise ValueError(f"music body truncated at offset {p} (need {n})")

    need(1)
    version = body[p]; p += 1
    if version not in (1, 2):
        raise ValueError(f"unsupported music version {version}")
    row_wide = version >= 2            # v2 carries num_rows & event.row as u16

    need(2)
    tempo_bpm = struct.unpack(">H", body[p:p + 2])[0]; p += 2
    need(6)
    rows_per_beat   = body[p]; p += 1
    num_channels    = body[p]; p += 1
    num_instruments = body[p]; p += 1
    num_patterns    = body[p]; p += 1
    order_len       = body[p]; p += 1
    master_volume   = body[p]; p += 1

    instruments = []
    for _ in range(num_instruments):
        need(2)
        kind = body[p]; p += 1
        namelen = body[p]; p += 1
        need(namelen)
        name = body[p:p + namelen].decode("utf-8", errors="replace"); p += namelen
        need(1)
        volume = body[p]; p += 1
        need(2); attack_ms = struct.unpack(">H", body[p:p + 2])[0]; p += 2
        need(2); decay_ms = struct.unpack(">H", body[p:p + 2])[0]; p += 2
        need(1); sustain_level = body[p]; p += 1
        need(2); release_ms = struct.unpack(">H", body[p:p + 2])[0]; p += 2

        ins = {
            "kind":          kind,
            "name":          name,
            "volume":        volume,
            "attack_ms":     attack_ms,
            "decay_ms":      decay_ms,
            "sustain_level": sustain_level,
            "release_ms":    release_ms,
        }

        if kind == KIND_SYNTH:
            need(2)
            ins["waveform"] = body[p]; p += 1
            ins["duty"] = body[p]; p += 1
        elif kind == KIND_SAMPLE:
            need(2); srate = struct.unpack(">H", body[p:p + 2])[0]; p += 2
            need(1); base_note = body[p]; p += 1
            need(1); bits = body[p]; p += 1
            need(2); loop_start = struct.unpack(">H", body[p:p + 2])[0]; p += 2
            need(2); loop_end = struct.unpack(">H", body[p:p + 2])[0]; p += 2
            need(4); pcm_len = struct.unpack(">I", body[p:p + 4])[0]; p += 4
            nbytes = pcm_len * (bits // 8)
            need(nbytes)
            pcm = _pcm_from_bytes(body[p:p + nbytes], bits); p += nbytes
            ins["srate"] = srate
            ins["base_note"] = base_note
            ins["bits"] = bits
            ins["loop_start"] = loop_start
            ins["loop_end"] = loop_end
            ins["pcm"] = pcm
        elif kind == KIND_SLICED:
            need(2); srate = struct.unpack(">H", body[p:p + 2])[0]; p += 2
            need(1); base_note = body[p]; p += 1
            need(1); bits = body[p]; p += 1
            need(2); num_slices = struct.unpack(">H", body[p:p + 2])[0]; p += 2
            slices = []
            for _ in range(num_slices):
                need(8); s, l = struct.unpack(">II", body[p:p + 8]); p += 8
                slices.append((s, l))
            need(4); pcm_len = struct.unpack(">I", body[p:p + 4])[0]; p += 4
            nbytes = pcm_len * (bits // 8)
            need(nbytes)
            pcm = _pcm_from_bytes(body[p:p + nbytes], bits); p += nbytes
            ins["srate"] = srate
            ins["base_note"] = base_note
            ins["bits"] = bits
            ins["slices"] = slices
            ins["pcm"] = pcm
        elif kind == KIND_SAMPLE_REF:
            need(32); ins["ref_txid"] = body[p:p + 32]; p += 32
            need(2); ins["srate"] = struct.unpack(">H", body[p:p + 2])[0]; p += 2
            need(2); ins["base_note"] = body[p]; ins["flags"] = body[p + 1]; p += 2
            need(8); ins["src_start_ms"], ins["src_len_ms"] = struct.unpack(">II", body[p:p + 8]); p += 8
            need(8); ins["loop_start"], ins["loop_end"] = struct.unpack(">II", body[p:p + 8]); p += 8
        elif kind == KIND_SLICED_REF:
            need(32); ins["ref_txid"] = body[p:p + 32]; p += 32
            need(2); ins["srate"] = struct.unpack(">H", body[p:p + 2])[0]; p += 2
            need(2); ins["base_note"] = body[p]; ins["flags"] = body[p + 1]; p += 2
            need(8); ins["src_start_ms"], ins["src_len_ms"] = struct.unpack(">II", body[p:p + 8]); p += 8
            need(2); num_slices = struct.unpack(">H", body[p:p + 2])[0]; p += 2
            slices = []
            for _ in range(num_slices):
                need(8); s, l = struct.unpack(">II", body[p:p + 8]); p += 8
                slices.append((s, l))
            ins["slices"] = slices
        else:
            raise ValueError(f"unknown instrument kind {kind}")

        instruments.append(ins)

    patterns = []
    for _ in range(num_patterns):
        if row_wide:
            need(2); num_rows = struct.unpack(">H", body[p:p + 2])[0]; p += 2
        else:
            need(1); num_rows = body[p]; p += 1
        need(2)
        num_events = struct.unpack(">H", body[p:p + 2])[0]; p += 2
        events = []
        for _ in range(num_events):
            if row_wide:
                need(6)
                row = struct.unpack(">H", body[p:p + 2])[0]
                channel, note, instrument, volume = body[p + 2:p + 6]
                p += 6
            else:
                need(5)
                row, channel, note, instrument, volume = body[p:p + 5]
                p += 5
            events.append({
                "row":        row,
                "channel":    channel,
                "note":       note,
                "instrument": instrument,
                "volume":     volume,
            })
        patterns.append({"num_rows": num_rows, "events": events})

    need(order_len)
    order = list(body[p:p + order_len]); p += order_len

    return {
        "version":       version,
        "tempo_bpm":     tempo_bpm,
        "rows_per_beat": rows_per_beat,
        "num_channels":  num_channels,
        "master_volume": master_volume,
        "instruments":   instruments,
        "patterns":      patterns,
        "order":         order,
    }


# ---------------------------------------------------------------------------
# Duration helper
# ---------------------------------------------------------------------------

def module_num_rows(module):
    """Total rows across the order (sum of each ordered pattern's num_rows)."""
    pats = module["patterns"]
    return sum(pats[o]["num_rows"] for o in module["order"])


def module_duration_ms(module, out_rate=22050):
    """Compute the rendered duration in ms (rows x samples_per_row / rate)."""
    spr = out_rate * 60.0 / (module["tempo_bpm"] * module["rows_per_beat"])
    total_samples = module_num_rows(module) * spr
    return int(round(total_samples * 1000.0 / out_rate))


# ---------------------------------------------------------------------------
# ADSR envelope
# ---------------------------------------------------------------------------

def _adsr_envelope(n_held, n_release, attack_ms, decay_ms, sustain_level,
                   release_ms, rate):
    """Build an ADSR amplitude envelope over (held span + release tail).

    n_held: samples the key is held. n_release: samples of release tail.
    Returns a float32 array of length n_held + n_release in [0,1].
    """
    total = n_held + n_release
    if total <= 0:
        return np.zeros(0, dtype=np.float32)

    env = np.zeros(total, dtype=np.float32)
    sus = float(sustain_level) / 255.0

    a = max(0, int(round(attack_ms * rate / 1000.0)))
    d = max(0, int(round(decay_ms * rate / 1000.0)))

    # Attack: 0 -> 1 over the held span (clamped to held length).
    a = min(a, n_held)
    if a > 0:
        env[:a] = np.linspace(0.0, 1.0, a, endpoint=False, dtype=np.float32)
    pos = a

    # Decay: 1 -> sustain over the held span.
    d = min(d, max(0, n_held - pos))
    if d > 0:
        env[pos:pos + d] = np.linspace(1.0, sus, d, endpoint=False,
                                       dtype=np.float32)
    pos += d

    # Sustain: hold at sustain level for the rest of the held span.
    if pos < n_held:
        env[pos:n_held] = sus

    # Level reached at key-off — release ramps from here to 0.
    level_at_off = env[n_held - 1] if n_held > 0 else sus

    # Release: from level_at_off -> 0 over the release tail.
    if n_release > 0:
        env[n_held:total] = np.linspace(level_at_off, 0.0, n_release,
                                        endpoint=True, dtype=np.float32)

    return env


# ---------------------------------------------------------------------------
# Voice synthesis
# ---------------------------------------------------------------------------

def _midi_to_freq(note):
    return 440.0 * (2.0 ** ((note - 69) / 12.0))


def _render_synth_voice(ins, note, n_samples, rate, rng):
    """Generate a synth waveform (no envelope/velocity) of n_samples."""
    if n_samples <= 0:
        return np.zeros(0, dtype=np.float32)
    freq = _midi_to_freq(note)
    waveform = ins.get("waveform", WAVE_SQUARE)

    if waveform == WAVE_NOISE:
        # Deterministic white noise from the seeded rng, tone-shaped by `duty`:
        # duty is a lowpass cutoff (255 = full bandwidth/bright, lower = darker/
        # warmer) so noise reads as a drum, not broadband static.
        nz = (rng.random(n_samples, dtype=np.float32) * 2.0 - 1.0)
        duty = int(ins.get("duty", 128))
        if duty < 252 and n_samples >= 16:
            F = np.fft.rfft(nz)
            k = np.fft.rfftfreq(n_samples)              # 0..0.5 cycles/sample
            cut = max(0.01, duty / 255.0) * 0.5         # cutoff
            mask = 1.0 / (1.0 + (k / cut) ** 6)         # smooth ~6th-order rolloff
            nz = np.fft.irfft(F * mask, n=n_samples).astype(np.float32)
            mx = float(np.max(np.abs(nz))) or 1.0
            nz = (nz / mx).astype(np.float32)           # keep level after filtering
        return nz

    t = np.arange(n_samples, dtype=np.float64)
    phase = (freq * t / rate) % 1.0  # 0..1 within each cycle

    if waveform == WAVE_SQUARE:
        duty = float(ins.get("duty", 128)) / 256.0
        duty = min(max(duty, 0.01), 0.99)
        wave = np.where(phase < duty, 1.0, -1.0)
    elif waveform == WAVE_TRIANGLE:
        # 0..1..0..-... triangle in [-1,1]
        wave = 2.0 * np.abs(2.0 * phase - 1.0) - 1.0
    elif waveform == WAVE_SAW:
        wave = 2.0 * phase - 1.0
    elif waveform == WAVE_SINE:
        wave = np.sin(2.0 * np.pi * phase)
    else:
        wave = np.where(phase < 0.5, 1.0, -1.0)  # default square

    return wave.astype(np.float32)


def _render_sample_voice(ins, note, n_samples, rate):
    """Resample an int8 PCM one-shot/loop to n_samples at the output rate.

    Pitch step combines the note transpose and the sample-rate conversion:
      out frame i  ->  source position advances by
        step = 2**((note-base_note)/12) * (srate / out_rate)
    Linear interpolation. If a loop (loop_start<loop_end) is set, the read
    position wraps within [loop_start, loop_end) once it passes loop_start;
    otherwise it is a one-shot that goes silent past the end.
    """
    if n_samples <= 0:
        return np.zeros(0, dtype=np.float32)
    pcm = np.asarray(ins["pcm"], dtype=np.float32) / _pcm_scale(ins.get("bits", 8))
    L = len(pcm)
    if L == 0:
        return np.zeros(n_samples, dtype=np.float32)

    srate = ins.get("srate", rate)
    base_note = ins.get("base_note", 60)
    loop_start = ins.get("loop_start", 0)
    loop_end = ins.get("loop_end", 0)
    has_loop = (loop_end > loop_start) and (loop_end <= L) and (loop_start >= 0)

    step = (2.0 ** ((note - base_note) / 12.0)) * (float(srate) / float(rate))

    # Source read positions.
    pos = np.arange(n_samples, dtype=np.float64) * step

    if has_loop:
        loop_len = loop_end - loop_start
        # Before reaching loop_start, read linearly; after, wrap in the loop.
        wrapped = pos.copy()
        past = pos >= loop_start
        wrapped[past] = loop_start + np.mod(pos[past] - loop_start, loop_len)
        pos = wrapped
        valid = np.ones(n_samples, dtype=bool)
    else:
        valid = pos < (L - 1)

    out = np.zeros(n_samples, dtype=np.float32)
    if not np.any(valid):
        return out
    pv = pos[valid]
    i0 = np.floor(pv).astype(np.int64)
    frac = (pv - i0).astype(np.float32)
    i0 = np.clip(i0, 0, L - 1)
    i1 = np.clip(i0 + 1, 0, L - 1)
    out[valid] = pcm[i0] * (1.0 - frac) + pcm[i1] * frac
    return out


def _render_sliced_voice(ins, note, n_samples, rate):
    """Play slice (note-1) of a sliced instrument's clip, at native pitch, as a
    one-shot. The slice = a (start, length) region of the one long stored PCM."""
    if n_samples <= 0:
        return np.zeros(0, dtype=np.float32)
    pcm = np.asarray(ins["pcm"], dtype=np.float32) / _pcm_scale(ins.get("bits", 8))
    slices = ins["slices"]
    si = note - 1                       # event.note = slice_index + 1
    if si < 0 or si >= len(slices):
        return np.zeros(n_samples, dtype=np.float32)
    start, length = slices[si]
    seg = pcm[start:start + length]
    if len(seg) < 2:
        return np.zeros(n_samples, dtype=np.float32)
    step = float(ins.get("srate", rate)) / float(rate)   # native pitch (rate conv only)
    pos = np.arange(n_samples, dtype=np.float64) * step
    valid = pos < (len(seg) - 1)
    out = np.zeros(n_samples, dtype=np.float32)
    if not np.any(valid):
        return out
    pv = pos[valid]
    i0 = np.floor(pv).astype(np.int64)
    frac = (pv - i0).astype(np.float32)
    i0 = np.clip(i0, 0, len(seg) - 1)
    i1 = np.clip(i0 + 1, 0, len(seg) - 1)
    out[valid] = seg[i0] * (1.0 - frac) + seg[i1] * frac
    return out


# ---------------------------------------------------------------------------
# Reference resolution — turn a referenced quipu into an embed-equivalent voice
# ---------------------------------------------------------------------------

def _resolve_ref_instrument(ins, resolver):
    """Turn a reference instrument (kind 3/4) into an embed-equivalent (kind 1/2):
    fetch+decode the referenced quipu, take [src_start_ms, +src_len_ms], resample
    to the instrument's `srate`, optionally peak-normalize, quantize to 16-bit.
    resolver(ref_txid_bytes) -> (float_mono_pcm in [-1,1], source_rate)."""
    import scipy.signal as _sig
    src_pcm, src_rate = resolver(bytes(ins["ref_txid"]))
    src = np.asarray(src_pcm, dtype=np.float64)
    a = max(0, int(round(ins["src_start_ms"] * src_rate / 1000.0)))
    b = min(len(src), a + int(round(ins["src_len_ms"] * src_rate / 1000.0)))
    seg = np.array(src[a:b], dtype=np.float64)
    tgt = int(ins["srate"])
    if int(src_rate) != tgt and len(seg) > 1:
        seg = _sig.resample(seg, max(1, int(round(len(seg) * tgt / src_rate))))
    if ins.get("flags", 0) & REF_NORMALIZE:
        mx = float(np.max(np.abs(seg))) or 1.0
        seg = seg / mx
    pcm16 = np.clip(np.round(seg * 30000.0), -32768, 32767).astype(np.int16)
    out = {"name": ins["name"], "volume": ins["volume"], "attack_ms": ins["attack_ms"],
           "decay_ms": ins["decay_ms"], "sustain_level": ins["sustain_level"],
           "release_ms": ins["release_ms"], "srate": tgt,
           "base_note": ins["base_note"], "bits": 16, "pcm": pcm16}
    if ins["kind"] == KIND_SAMPLE_REF:
        out["kind"] = KIND_SAMPLE
        out["loop_start"] = ins.get("loop_start", 0)
        out["loop_end"] = ins.get("loop_end", 0)
    else:
        out["kind"] = KIND_SLICED
        out["slices"] = ins["slices"]
    return out


# ---------------------------------------------------------------------------
# render_music — the deterministic numpy mixer
# ---------------------------------------------------------------------------

def render_music(module_bytes, out_rate=22050, resolver=None):
    """Render a music module (the 0x07 body, codec 0x20) to float32 mono [-1,1].

    Deterministic: any noise comes from a fixed-seed numpy Generator, so the
    output is bit-identical across runs. If the module carries reference
    instruments (kind 3/4), `resolver(ref_txid)->(pcm,rate)` must be supplied;
    each is resolved to an embed-equivalent voice before rendering.
    """
    if isinstance(module_bytes, dict):
        module = module_bytes
    else:
        module = read_music_body(module_bytes)

    tempo_bpm     = module["tempo_bpm"]
    rows_per_beat = module["rows_per_beat"]
    master_volume = module["master_volume"]
    instruments   = module["instruments"]
    patterns      = module["patterns"]
    order         = module["order"]

    # Resolve reference instruments (kind 3/4) -> embed-equivalent (kind 1/2).
    if any(i["kind"] in (KIND_SAMPLE_REF, KIND_SLICED_REF) for i in instruments):
        if resolver is None:
            raise ValueError("module has reference instruments but no resolver supplied")
        instruments = [_resolve_ref_instrument(i, resolver)
                       if i["kind"] in (KIND_SAMPLE_REF, KIND_SLICED_REF) else i
                       for i in instruments]

    samples_per_row = out_rate * 60.0 / (tempo_bpm * rows_per_beat)

    total_rows = module_num_rows(module)
    total_samples = int(round(total_rows * samples_per_row))

    # Generous tail so release ramps don't get clipped off the end of the buffer.
    max_release_ms = max([i["release_ms"] for i in instruments], default=0)
    tail = int(round(max_release_ms * out_rate / 1000.0)) + 2
    buf = np.zeros(total_samples + tail, dtype=np.float32)

    rng = np.random.default_rng(NOISE_SEED)

    # Flatten the order into an absolute (row -> sample offset) timeline and
    # gather all events with absolute row numbers.
    # Per channel, accumulate (start_abs_row, note, instrument, velocity).
    num_channels = max(module["num_channels"], 1)
    # voices_by_channel[ch] = list of (start_row, end_row_or_None, note, inst, vel)
    # We build per-channel event streams, then realize voices.

    # 1) Collect absolute events.
    abs_events = []  # (abs_row, channel, note, instrument, volume)
    row_cursor = 0
    for pat_idx in order:
        pat = patterns[pat_idx]
        for ev in pat["events"]:
            if ev["row"] >= pat["num_rows"]:
                continue
            abs_events.append((
                row_cursor + ev["row"],
                ev["channel"], ev["note"], ev["instrument"], ev["volume"],
            ))
        row_cursor += pat["num_rows"]

    # Stable sort by (channel, row) so we can pair each note with the next
    # event on the same channel as its key-off boundary.
    abs_events.sort(key=lambda e: (e[1], e[0]))

    # 2) Group by channel.
    from itertools import groupby
    for ch, group in groupby(abs_events, key=lambda e: e[1]):
        chan_events = list(group)
        for i, (arow, _ch, note, inst, vol) in enumerate(chan_events):
            if note == 0:
                continue  # key-off marker; handled as a boundary below
            if inst >= len(instruments):
                continue
            # End row = the next event on this channel (note or key-off),
            # else the song end.
            if i + 1 < len(chan_events):
                end_row = chan_events[i + 1][0]
            else:
                end_row = total_rows
            if end_row <= arow:
                end_row = arow + 1  # at least one row held

            start_s = int(round(arow * samples_per_row))
            end_s = int(round(end_row * samples_per_row))
            n_held = max(1, end_s - start_s)

            ins = instruments[inst]
            n_release = int(round(ins["release_ms"] * out_rate / 1000.0))
            n_total = n_held + n_release

            if ins["kind"] == KIND_SYNTH:
                raw = _render_synth_voice(ins, note, n_total, out_rate, rng)
            elif ins["kind"] == KIND_SLICED:
                raw = _render_sliced_voice(ins, note, n_total, out_rate)
            else:
                raw = _render_sample_voice(ins, note, n_total, out_rate)

            env = _adsr_envelope(
                n_held, n_release,
                ins["attack_ms"], ins["decay_ms"], ins["sustain_level"],
                ins["release_ms"], out_rate,
            )
            # Match lengths defensively.
            m = min(len(raw), len(env))
            velocity = float(vol) / 255.0
            inst_gain = float(ins["volume"]) / 255.0
            voice = raw[:m] * env[:m] * velocity * inst_gain

            dst0 = start_s
            dst1 = start_s + m
            if dst1 > len(buf):
                dst1 = len(buf)
                voice = voice[:dst1 - dst0]
            if dst0 < len(buf) and dst1 > dst0:
                buf[dst0:dst1] += voice

    # Master volume.
    buf *= float(master_volume) / 255.0

    # Soft-limit (tanh) then peak-normalize to ~0.9 so it never clips.
    buf = np.tanh(buf).astype(np.float32)
    peak = float(np.max(np.abs(buf))) if buf.size else 0.0
    if peak > 1e-9:
        buf *= (0.9 / peak)

    # Trim the tail back to exactly the song length so duration is predictable.
    buf = buf[:total_samples]
    return buf.astype(np.float32)


# ---------------------------------------------------------------------------
# WAV writer — 16-bit PCM mono, standard RIFF
# ---------------------------------------------------------------------------

def write_wav(path, audio, rate=22050):
    """Write a float32 mono array in [-1,1] to a 16-bit PCM mono WAV file."""
    import wave

    audio = np.asarray(audio, dtype=np.float32)
    audio = np.clip(audio, -1.0, 1.0)
    pcm16 = np.round(audio * 32767.0).astype("<i2")

    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(int(rate))
        w.writeframes(pcm16.tobytes())
    return str(path)


# ---------------------------------------------------------------------------
# Container glue — wrap a music module in the 0x07 sound container
# ---------------------------------------------------------------------------

def build_music_quipu(module_bytes, *, out_rate=22050, title="", tone=None):
    """Wrap a music module body in a 0x07 sound quipu (codec 0x20).

    sample_rate = the output render rate; channels = polyphony channel count;
    duration_ms = the computed rendered duration. Returns (header, body).
    """
    import sound

    module = read_music_body(module_bytes)
    duration_ms = module_duration_ms(module, out_rate=out_rate)
    channels = min(max(module["num_channels"], 0), 255)

    if tone is None:
        tone = sound.TONE_ORDINARY

    return sound.build_sound_quipu(
        CODEC_MUSIC, module_bytes,
        sample_rate=out_rate, channels=channels, duration_ms=duration_ms,
        codec_meta=b"", title=title, tone=tone,
    )


def read_music_quipu(header_bytes, body_bytes):
    """Read a 0x07 sound quipu and, if codec 0x20, parse its music module.

    Returns the sound-container dict (from read_sound_quipu) with an extra
    'module' key holding the parsed music module.
    """
    import sound

    rec = sound.read_sound_quipu(header_bytes, body_bytes)
    if rec["codec"] == CODEC_MUSIC:
        rec["module"] = read_music_body(rec["body"])
    return rec


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _selftest():
    import os
    import sound

    out_rate = 22050

    # --- A tiny generated one-shot sample: a short plucked "blip". ---
    # Deterministic: decaying sine burst, quantized to int8.
    rng = np.random.default_rng(0xABCD)
    n = 1500
    t = np.arange(n, dtype=np.float64)
    blip = np.sin(2 * np.pi * 220.0 * t / out_rate) * np.exp(-t / 300.0)
    blip += 0.15 * (rng.random(n) * 2 - 1) * np.exp(-t / 80.0)  # a little noise attack
    blip = blip / np.max(np.abs(blip))
    pcm_int8 = np.clip(np.round(blip * 120.0), -128, 127).astype(np.int8)

    # --- Instruments: one synth (square lead), one sample (the blip). ---
    lead = synth_instrument(
        "square lead", WAVE_SQUARE, duty=96, volume=200,
        attack_ms=2, decay_ms=30, sustain_level=180, release_ms=60,
    )
    pluck = sample_instrument(
        "blip", pcm_int8, srate=out_rate, base_note=57,  # A3
        loop_start=0, loop_end=0, volume=230,
        attack_ms=0, decay_ms=0, sustain_level=255, release_ms=40,
    )
    instruments = [lead, pluck]

    # --- One bar, 16th-note grid: tempo 120, 4 rows/beat, 16 rows. ---
    # Channel 0 = lead melody; channel 1 = sample on the beat.
    evts = [
        # lead melody (channel 0): C4 E4 G4 C5 ... with a key-off at the end
        event(0,  0, 60, 0, 230),
        event(4,  0, 64, 0, 230),
        event(8,  0, 67, 0, 230),
        event(12, 0, 72, 0, 230),
        event(15, 0, 0,  0, 0),     # key-off lead
        # sample hits (channel 1) on beats 1 and 3
        event(0,  1, 57, 1, 255),   # A3 native
        event(8,  1, 60, 1, 255),   # up a minor third
    ]
    pat = pattern(16, evts)
    patterns = [pat]
    order = [0]

    # --- Build the module body (pure stdlib path). ---
    body = build_music_body(
        tempo_bpm=120, rows_per_beat=4, num_channels=2,
        instruments=instruments, patterns=patterns, order=order,
        master_volume=220,
    )

    # --- Wrap in the 0x07 sound container (codec 0x20). ---
    header, cbody = build_music_quipu(
        body, out_rate=out_rate, title="| QM selftest |",
        tone=sound.TONE_AI,
    )
    container_size = len(header) + len(cbody)

    # --- Read the container back, verify codec + round-trip. ---
    rec = read_music_quipu(header, cbody)
    assert rec["type"] == "sound"
    assert rec["codec"] == CODEC_MUSIC, rec["codec"]
    assert rec["codec_name"] == "unknown_0x20"  # 0x20 not in sound.py's enum
    assert rec["sample_rate"] == out_rate
    assert rec["channels"] == 2
    assert rec["body"] == body, "container body must be the module bytes verbatim"

    mod = rec["module"]
    assert mod["tempo_bpm"] == 120
    assert mod["rows_per_beat"] == 4
    assert mod["num_channels"] == 2
    assert len(mod["instruments"]) == 2
    assert mod["instruments"][0]["kind"] == KIND_SYNTH
    assert mod["instruments"][1]["kind"] == KIND_SAMPLE
    assert mod["instruments"][1]["pcm"].dtype == np.int8
    assert len(mod["instruments"][1]["pcm"]) == n
    assert mod["instruments"][1]["base_note"] == 57
    assert len(mod["patterns"]) == 1
    assert len(mod["patterns"][0]["events"]) == len(evts)
    assert mod["order"] == [0]

    # --- Render to audio (deterministic). ---
    audio = render_music(rec["body"], out_rate=out_rate)

    samples_per_row = out_rate * 60.0 / (120 * 4)
    expected_len = int(round(16 * samples_per_row))

    # Determinism: render twice, must be bit-identical.
    audio2 = render_music(rec["body"], out_rate=out_rate)
    assert np.array_equal(audio, audio2), "render_music must be deterministic"

    # Assertions: finite, non-silent, right length, not clipped.
    assert np.all(np.isfinite(audio)), "audio must be finite"
    rms = float(np.sqrt(np.mean(audio.astype(np.float64) ** 2)))
    assert rms > 0.0, f"audio must be non-silent (rms={rms})"
    assert audio.dtype == np.float32
    assert len(audio) == expected_len, (len(audio), expected_len)
    peak = float(np.max(np.abs(audio)))
    assert peak <= 1.0, f"audio must not clip (peak={peak})"

    # --- Write the WAV. ---
    out_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "_selftest.wav"
    )
    write_wav(out_path, audio, out_rate)
    wav_size = os.path.getsize(out_path)

    dur_ms = module_duration_ms(mod, out_rate=out_rate)

    print("=== quipu MUSIC codec self-test ===")
    print(f"  module body         : {len(body)} B")
    print(f"  container (hdr+body): {container_size} B "
          f"(header {len(header)} B + body {len(cbody)} B)")
    print(f"  codec byte          : 0x{rec['codec']:02x} "
          f"({rec['codec_name']})")
    print(f"  sample_rate         : {rec['sample_rate']} Hz")
    print(f"  channels (polyphony): {rec['channels']}")
    print(f"  duration_ms (hdr)   : {rec['duration_ms']} ms  "
          f"(computed {dur_ms} ms)")
    print(f"  instruments         : "
          f"{[ (i['name'], 'synth' if i['kind']==0 else 'sample') for i in mod['instruments'] ]}")
    print(f"  samples_per_row     : {samples_per_row:.3f}")
    print(f"  rendered samples    : {len(audio)} (expected {expected_len})")
    print(f"  rms                 : {rms:.5f}  (non-silent)")
    print(f"  peak                : {peak:.5f}  (<= 1.0, no clip)")
    print(f"  finite              : {bool(np.all(np.isfinite(audio)))}")
    print(f"  deterministic       : {bool(np.array_equal(audio, audio2))}")
    print(f"  WAV written         : {out_path} ({wav_size} B)")
    print("  ALL ASSERTIONS PASSED")


if __name__ == "__main__":
    _selftest()
