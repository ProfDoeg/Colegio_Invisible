"""
compose_calm.py — a CALM, SAMPLED demo for the quipu MUSIC codec.

"Organic / sequenced small samples": mellow, NOT drum & bass. Every instrument
is a SAMPLE instrument (kind=1) — gentle one-shot PCM generated with numpy and
stored as int8 in the module. Four-chord loop in D major, ~74 BPM, sparse and
quiet.

  marimba   soft sine + a few decaying harmonics, fast-ish decay (one-shot)
  pad       a couple of detuned saws through a one-pole lowpass, slow attack,
            LOOPED so a held chord sustains
  kick      sine with a downward pitch glide + quick decay (one-shot)
  shaker    short filtered-noise burst (one-shot, seeded -> deterministic)

Run:  /Users/anthony/Documents/taller/Colegio_Invisible/.venv/bin/python \
        Colegio_Invisible/working/music/compose_calm.py
(cwd /Users/anthony/Documents/taller)
"""

from __future__ import annotations

import os
import sys

import numpy as np

# Resolve paths relative to this file so cwd only needs to be the repo root.
HERE = os.path.dirname(os.path.abspath(__file__))
CANONICAL = os.path.normpath(os.path.join(HERE, "..", "..", "canonical"))
sys.path.insert(0, CANONICAL)   # so 'import sound' / 'import tone' resolve
sys.path.insert(0, HERE)        # so 'import music_codec' resolves

import sound
import music_codec as mc

OUT_RATE = 22050
SR_BIN = os.path.join(HERE, "calm.sound.bin")
WAV    = os.path.join(HERE, "calm.wav")

# Deterministic sample synthesis — fixed seed for the shaker's noise.
SAMPLE_SEED = 0x1A11E  # 'taller'


# ---------------------------------------------------------------------------
# Sample one-shot generators (numpy -> int8 PCM, <= ~0.5 s each)
# ---------------------------------------------------------------------------

def _to_int8(x, peak=120.0):
    """Normalize a float array to [-1,1] and quantize to int8 at `peak`."""
    x = np.asarray(x, dtype=np.float64)
    m = np.max(np.abs(x))
    if m > 1e-12:
        x = x / m
    return np.clip(np.round(x * peak), -128, 127).astype(np.int8)


def make_marimba(rate=OUT_RATE, base_hz=261.63, dur=0.45):
    """Soft marimba/bell: fundamental sine + a few decaying harmonics, fast
    decay. base_hz = the pitch the PCM is recorded at (C4 here)."""
    n = int(rate * dur)
    t = np.arange(n) / rate
    # Marimba-ish partials: strong fundamental, soft 4th & 10th (bar modes),
    # each with its own faster-decaying envelope.
    partials = [
        (1.0,  1.00, 9.0),    # (amp, freq_mult, decay_rate)
        (0.45, 4.00, 14.0),
        (0.18, 10.0, 22.0),
    ]
    wave = np.zeros(n)
    for amp, mult, dec in partials:
        wave += amp * np.sin(2 * np.pi * base_hz * mult * t) * np.exp(-dec * t)
    # Tiny soft attack shaping (a couple of ms) to avoid a click.
    atk = int(rate * 0.003)
    if atk > 0:
        wave[:atk] *= np.linspace(0.0, 1.0, atk)
    return _to_int8(wave, peak=118.0)


def make_pad(rate=OUT_RATE, base_hz=261.63, dur=0.5):
    """Warm pad: two detuned saws through a one-pole lowpass, slow attack.
    LOOPED while held — we return PCM + a loop window over the steady middle."""
    n = int(rate * dur)
    t = np.arange(n) / rate
    # Two slightly detuned saws (band-limited enough for int8 at this rate via
    # the lowpass below). Saw via 2*frac - 1.
    def saw(f):
        ph = (f * t) % 1.0
        return 2.0 * ph - 1.0
    detune = 1.005
    raw = 0.5 * saw(base_hz) + 0.5 * saw(base_hz * detune)
    # One-pole lowpass (warm, removes the harsh saw edge).
    a = 0.18  # cutoff coefficient (lower = darker)
    y = np.zeros(n)
    acc = 0.0
    for i in range(n):
        acc += a * (raw[i] - acc)
        y[i] = acc
    # Slow attack baked lightly into the sample; the ADSR adds more.
    atk = int(rate * 0.05)
    if atk > 0:
        y[:atk] *= np.linspace(0.0, 1.0, atk)
    pcm = _to_int8(y, peak=95.0)
    # Loop window over the steady middle third (a whole number of base cycles
    # so the wrap is reasonably smooth).
    period = rate / base_hz
    loop_start = int(rate * 0.18)
    cycles = int(((n - loop_start) * 0.6) / period)
    loop_len = max(1, int(round(cycles * period)))
    loop_end = min(n, loop_start + loop_len)
    return pcm, loop_start, loop_end


def make_kick(rate=OUT_RATE, dur=0.22):
    """Soft kick: sine with a downward pitch glide + quick amplitude decay."""
    n = int(rate * dur)
    t = np.arange(n) / rate
    # Pitch glide 95 Hz -> 45 Hz over a short time constant.
    f0, f1, tau = 95.0, 45.0, 0.04
    inst_f = f1 + (f0 - f1) * np.exp(-t / tau)
    phase = 2 * np.pi * np.cumsum(inst_f) / rate
    amp = np.exp(-t / 0.07)
    wave = np.sin(phase) * amp
    atk = int(rate * 0.002)
    if atk > 0:
        wave[:atk] *= np.linspace(0.0, 1.0, atk)
    return _to_int8(wave, peak=110.0)


def make_shaker(rate=OUT_RATE, dur=0.12, seed=SAMPLE_SEED):
    """Soft shaker/brush: short filtered-noise burst. Seeded -> deterministic."""
    n = int(rate * dur)
    rng = np.random.default_rng(seed)
    noise = rng.standard_normal(n)
    # Bandpass-ish: highpass via first difference (brighten), then a touch of
    # one-pole lowpass to soften the very top -> a "brushed" hiss.
    hp = np.diff(noise, prepend=noise[0])
    a = 0.5
    y = np.zeros(n)
    acc = 0.0
    for i in range(n):
        acc += a * (hp[i] - acc)
        y[i] = acc
    # Percussive envelope: fast attack, short decay.
    env = np.exp(-np.arange(n) / (rate * 0.025))
    env[: int(rate * 0.001)] *= np.linspace(0.0, 1.0, int(rate * 0.001))
    return _to_int8(y * env, peak=70.0)


# ---------------------------------------------------------------------------
# Build the four sample instruments
# ---------------------------------------------------------------------------

def build_instruments():
    marimba_pcm = make_marimba(base_hz=261.63)   # recorded at C4 = MIDI 60
    pad_pcm, p_ls, p_le = make_pad(base_hz=261.63)  # C4 = MIDI 60
    kick_pcm = make_kick()                        # tuned by ear; base C2 = 36
    shaker_pcm = make_shaker()                    # noise; base C5 = 72

    marimba = mc.sample_instrument(
        "marimba", marimba_pcm, srate=OUT_RATE, base_note=60,
        loop_start=0, loop_end=0,           # one-shot
        volume=150,
        attack_ms=1, decay_ms=0, sustain_level=255, release_ms=120,
    )
    pad = mc.sample_instrument(
        "warm pad", pad_pcm, srate=OUT_RATE, base_note=60,
        loop_start=p_ls, loop_end=p_le,     # LOOPED -> sustains while held
        volume=78,
        attack_ms=320, decay_ms=200, sustain_level=210, release_ms=600,
    )
    kick = mc.sample_instrument(
        "soft kick", kick_pcm, srate=OUT_RATE, base_note=36,
        loop_start=0, loop_end=0,           # one-shot
        volume=120,
        attack_ms=0, decay_ms=0, sustain_level=255, release_ms=40,
    )
    shaker = mc.sample_instrument(
        "shaker", shaker_pcm, srate=OUT_RATE, base_note=72,
        loop_start=0, loop_end=0,           # one-shot
        volume=46,
        attack_ms=0, decay_ms=0, sustain_level=255, release_ms=20,
    )
    return [marimba, pad, kick, shaker], (p_ls, p_le)


# Instrument indices.
I_MARIMBA = 0
I_PAD     = 1
I_KICK    = 2
I_SHAKER  = 3

# Channel layout (polyphony). Pad needs 4 (chord) + 1 bass root = 5.
# Marimba arpeggiates on 1 channel. Kick + shaker 1 channel each.
CH_PAD0, CH_PAD1, CH_PAD2, CH_PAD3 = 0, 1, 2, 3   # pad chord voices (mid)
CH_PAD_BASS = 4                                   # pad root low (D2-ish)
CH_MARIMBA  = 5                                   # arpeggio
CH_KICK     = 6
CH_SHAKER   = 7
NUM_CHANNELS = 8


# ---------------------------------------------------------------------------
# The score — D major, 74 BPM, rows_per_beat=4. Four chords, 2 bars each.
# ---------------------------------------------------------------------------
# MIDI: D4=62 F#4=66 A4=69 C#5=73 ; B3=59 D4=62 F#4=66 A4=69 ;
#       G3=55 B3=59 D4=62 F#4=66 ; A3=57 C#4=61 E4=64 G4=67
#
# Pad holds chord tones in ~C3-C4 region (we use the mid octave around the
# given chord-tone set). Marimba arpeggiates root/3rd/5th/7th one octave up
# (~C4-C5). Bass-ish pad root is the chord root down near D2-D3.
#
# Chord tones as named in the brief (D-F#-A-C# etc.); we voice the PAD with
# these in octave 3-4 and the MARIMBA an octave higher.

# Pad chord voicings (4 notes), placed ~C3..C4 (MIDI 48..60-ish region).
# Dmaj7: D F# A C# ; Bm7: B D F# A ; Gmaj7: G B D F# ; A7: A C# E G
PAD_CHORDS = [
    [50, 54, 57, 61],   # Dmaj7  : D3 F#3 A3 C#4
    [47, 50, 54, 57],   # Bm7    : B2 D3 F#3 A3
    [43, 47, 50, 54],   # Gmaj7  : G2 B2 D3 F#3
    [45, 49, 52, 55],   # A7     : A2 C#3 E3 G3
]
# Bass-ish pad root, ~D2..D3.
PAD_BASS = [38, 35, 31, 33]   # D2, B1->use B... keep low: D2 B1? choose D2,B2,G2,A2
# Re-voice bass to sit in D2..D3 cleanly: roots one octave below the chord root.
PAD_BASS = [38, 47 - 12, 43 - 12, 45 - 12]  # D2=38, B2=35, G2=31, A2=33

# Marimba arpeggio notes (root,3rd,5th,7th) ~C4..C5 — chord tones up an octave
# from the pad chord roots.
MARIMBA_ARP = [
    [62, 66, 69, 73],   # Dmaj7  : D4 F#4 A4 C#5
    [59, 62, 66, 69],   # Bm7    : B3 D4 F#4 A4
    [55, 59, 62, 66],   # Gmaj7  : G3 B3 D4 F#4
    [57, 61, 64, 67],   # A7     : A3 C#4 E4 G4
]

ROWS_PER_BEAT = 4
BEATS_PER_BAR = 4
BARS_PER_CHORD = 2
ROWS_PER_BAR = ROWS_PER_BEAT * BEATS_PER_BAR        # 16
ROWS_PER_CHORD = ROWS_PER_BAR * BARS_PER_CHORD       # 32


def build_chord_pattern(chord_idx):
    """One 2-bar pattern (32 rows) for a single chord: pad sustains the chord,
    marimba arpeggiates gentle 8th notes, soft kick on beats 1 & 3 of each bar,
    shaker on the offbeat 8ths. Sparse and quiet."""
    evts = []
    chord = PAD_CHORDS[chord_idx]
    bass = PAD_BASS[chord_idx]
    arp = MARIMBA_ARP[chord_idx]

    # --- Pad: strike the 4 chord voices + bass root at row 0, hold to end. ---
    pad_chs = [CH_PAD0, CH_PAD1, CH_PAD2, CH_PAD3]
    for ch, note in zip(pad_chs, chord):
        evts.append(mc.event(0, ch, note, I_PAD, volume=60))      # low velocity
    evts.append(mc.event(0, CH_PAD_BASS, bass, I_PAD, volume=72))
    # Key-off the pad just before the pattern ends so the release tail breathes
    # into the next chord (kept long via release_ms).
    last = ROWS_PER_CHORD - 1
    for ch in pad_chs + [CH_PAD_BASS]:
        evts.append(mc.event(last, ch, 0, I_PAD, 0))

    # --- Marimba: gentle 8th-note arpeggio (every 2 rows = 8th note). ---
    # Pattern over the 4 arp notes, ascending then gently weaving, soft.
    # 32 rows / 2 = 16 eighth-notes across the 2 bars.
    arp_order = [0, 1, 2, 3, 2, 1, 0, 1]   # an 8-step gentle contour
    soft_vel = [110, 86, 96, 80, 92, 78, 104, 82]  # quiet, lightly varying
    eighth = 0
    for row in range(0, ROWS_PER_CHORD, 2):   # rows 0,2,4,...,30 -> 16 eighths
        step = eighth % len(arp_order)
        note = arp[arp_order[step]]
        # Lift octave occasionally on the very top note for sparkle, but keep
        # it within ~C4..C5.
        vel = soft_vel[step]
        evts.append(mc.event(row, CH_MARIMBA, note, I_MARIMBA, volume=vel))
        eighth += 1

    # --- Soft kick on beats 1 and 3 of each of the 2 bars. ---
    # Beat 1 = row 0/16; beat 3 = row 8/24 (relative to each bar).
    for bar in range(BARS_PER_CHORD):
        b0 = bar * ROWS_PER_BAR
        evts.append(mc.event(b0 + 0, CH_KICK, 36, I_KICK, volume=150))  # beat 1
        evts.append(mc.event(b0 + 8, CH_KICK, 36, I_KICK, volume=120))  # beat 3

    # --- Shaker lightly on the offbeat 8ths, low velocity. ---
    # Offbeat 8ths = rows 2,6,10,14,... (the "and" of each beat). rows %4 == 2.
    for row in range(2, ROWS_PER_CHORD, 4):
        evts.append(mc.event(row, CH_SHAKER, 72, I_SHAKER, volume=60))

    return mc.pattern(ROWS_PER_CHORD, evts)


def main():
    instruments, (p_ls, p_le) = build_instruments()

    # One pattern per chord (2 bars each = 32 rows). At 74 BPM a bar is ~3.24 s,
    # so 2 bars/chord x 4 chords = 8 bars ~= 26 s — the 25-35 s target is the
    # binding constraint, so the 4-chord progression plays once (8 bars). Add a
    # short tail repeat of the first chord so the loop resolves home (Dmaj7).
    patterns = [build_chord_pattern(i) for i in range(4)]
    order = [0, 1, 2, 3]   # Dmaj7 Bm7 Gmaj7 A7 -> 8 bars, ~26 s

    body = mc.build_music_body(
        tempo_bpm=74, rows_per_beat=ROWS_PER_BEAT, num_channels=NUM_CHANNELS,
        instruments=instruments, patterns=patterns, order=order,
        master_volume=200,
    )

    # Wrap in the 0x07 sound container (codec 0x20, music).
    header, cbody = mc.build_music_quipu(
        body, out_rate=OUT_RATE, title="| Colegio Invisible — calm |",
        tone=sound.TONE_AFFECTION,
    )
    container = header + cbody

    # Save the container bytes.
    with open(SR_BIN, "wb") as f:
        f.write(container)

    # Read back + verify it parses as a music quipu using SAMPLE instruments.
    rec = mc.read_music_quipu(header, cbody)
    mod = rec["module"]
    assert rec["codec"] == mc.CODEC_MUSIC
    assert rec["body"] == body
    kinds = [ins["kind"] for ins in mod["instruments"]]
    assert all(k == mc.KIND_SAMPLE for k in kinds), kinds  # ALL samples

    # Render to audio (deterministic) and write the WAV.
    audio = mc.render_music(rec["body"], out_rate=OUT_RATE)
    audio2 = mc.render_music(rec["body"], out_rate=OUT_RATE)
    deterministic = bool(np.array_equal(audio, audio2))

    mc.write_wav(WAV, audio, OUT_RATE)

    # Stats.
    dur_ms = mc.module_duration_ms(mod, out_rate=OUT_RATE)
    duration_s = len(audio) / OUT_RATE
    peak = float(np.max(np.abs(audio)))
    rms = float(np.sqrt(np.mean(audio.astype(np.float64) ** 2)))
    wav_size = os.path.getsize(WAV)

    inst_summary = [
        (ins["name"], "sample", len(ins["pcm"]),
         "loop" if ins["loop_end"] > ins["loop_start"] else "one-shot")
        for ins in mod["instruments"]
    ]

    print("=== Colegio Invisible — CALM / SAMPLED demo ===")
    print(f"  container size      : {len(container)} B "
          f"(header {len(header)} B + body {len(cbody)} B)")
    print(f"  module body         : {len(body)} B")
    print(f"  codec byte          : 0x{rec['codec']:02x} ({rec['codec_name']})")
    print(f"  tone                : 0x{rec['tone']:02x} (affection)")
    print(f"  sample_rate         : {rec['sample_rate']} Hz")
    print(f"  channels (polyphony): {rec['channels']}")
    print(f"  duration            : {duration_s:.2f} s  "
          f"(hdr {rec['duration_ms']} ms / computed {dur_ms} ms)")
    print(f"  instruments (ALL kind=1 SAMPLE):")
    for name, kind, plen, loop in inst_summary:
        print(f"      - {name:9s}  {kind}  pcm={plen:5d} int8  {loop}")
    print(f"  all SAMPLE          : {all(k == mc.KIND_SAMPLE for k in kinds)}")
    print(f"  peak                : {peak:.4f}  (<= 1.0, no clip)")
    print(f"  rms                 : {rms:.4f}  (quiet/calm)")
    print(f"  deterministic       : {deterministic}")
    print(f"  WAV written         : {WAV} ({wav_size} B)")
    print(f"  container written   : {SR_BIN}")
    n_bars = mc.module_num_rows(mod) // ROWS_PER_BAR
    print(f"  score               : D major | 74 BPM | rows/beat=4 | "
          f"Dmaj7-Bm7-Gmaj7-A7 (2 bars ea) = {n_bars} bars")


if __name__ == "__main__":
    main()
