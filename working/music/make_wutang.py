"""
make_wutang.py — a Wu-Tang Clan / RZA "36 Chambers"-era boom-bap instrumental,
composed entirely through the existing quipu MUSIC codec (music_codec.py).

The Wu duality: a beautiful melancholic minor SOUL loop over HARD grimy drums.
EVERY instrument is a SAMPLE one-shot (kind=1): generated as numpy int8 PCM and
stored in the module. The 8-bit storage is the FEATURE — SP-1200-style dust. We
lean into lo-fi: lowpass, slight bit-crush, slight detune.

Run:  /Users/anthony/Documents/taller/Colegio_Invisible/.venv/bin/python \
        Colegio_Invisible/working/music/make_wutang.py
(cwd /Users/anthony/Documents/taller)
"""

from __future__ import annotations

import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
CANON = os.path.abspath(os.path.join(HERE, "..", "..", "canonical"))
sys.path.insert(0, HERE)    # music_codec.py
sys.path.insert(0, CANON)   # sound.py

import sound  # noqa: E402
from music_codec import (  # noqa: E402
    sample_instrument, event, pattern,
    build_music_body, read_music_body, build_music_quipu, read_music_quipu,
    render_music, write_wav, module_duration_ms, KIND_SAMPLE,
)

OUT_RATE = 22050
SR        = OUT_RATE

# Deterministic: ALL noise comes from this seeded generator.
rng = np.random.default_rng(0x3643)  # '36' chambers


# ---------------------------------------------------------------------------
# Lo-fi DSP helpers (operate on float [-1,1], return float)
# ---------------------------------------------------------------------------

def lowpass(x, cutoff_hz, sr=SR):
    """One-pole lowpass — warmth, removes hiss/fizz (dusty)."""
    x = np.asarray(x, dtype=np.float64)
    if cutoff_hz >= sr / 2:
        return x
    dt = 1.0 / sr
    rc = 1.0 / (2.0 * np.pi * cutoff_hz)
    a = dt / (rc + dt)
    y = np.empty_like(x)
    acc = 0.0
    for i in range(x.size):
        acc += a * (x[i] - acc)
        y[i] = acc
    return y


def bitcrush(x, bits):
    """Quantize to fewer bits — extra crunch on top of the 8-bit storage."""
    x = np.asarray(x, dtype=np.float64)
    levels = 2 ** bits
    return np.round(x * (levels / 2)) / (levels / 2)


def soft_sat(x, drive=1.5):
    """Soft saturation (tanh) — analog-ish warmth / glue on the kick."""
    return np.tanh(np.asarray(x, dtype=np.float64) * drive) / np.tanh(drive)


def normf(x):
    x = np.asarray(x, dtype=np.float64)
    m = np.max(np.abs(x))
    return x / m if m > 1e-12 else x


def to_int8(x, peak=120.0):
    """Float [-1,1] -> int8 one-shot. peak<127 leaves a hair of headroom."""
    return np.clip(np.round(normf(x) * peak), -128, 127).astype(np.int8)


def env_exp(n, tau):
    """Exponential decay envelope, length n, time-constant tau (samples)."""
    t = np.arange(n, dtype=np.float64)
    return np.exp(-t / tau)


# ---------------------------------------------------------------------------
# Instrument 0 — THE SOUL LOOP (warm Rhodes/piano-ish, lowpassed, detuned)
# ---------------------------------------------------------------------------
# A single struck Rhodes-ish tone one-shot, played as a melodic instrument by
# the sequencer (transposed per note). Sine fundamental + a few decaying
# harmonics, soft attack, medium decay, lowpassed for warmth, slightly detuned
# for the dusty "off" feel.

def make_rhodes(base_hz, dur_s=1.6):
    n = int(dur_s * SR)
    t = np.arange(n, dtype=np.float64)
    detune = 1.0 + 0.004  # slightly sharp -> dusty beating
    # Partials: fundamental + soft harmonics, each its own decay (Rhodes bell).
    partials = [
        (1.00, 1.00, 0.55),  # (freq mult, amp, decay scale)
        (2.00, 0.42, 0.42),
        (3.01, 0.18, 0.30),
        (4.00, 0.09, 0.22),
        (6.02, 0.05, 0.16),  # faint bell shimmer
    ]
    sig = np.zeros(n)
    for mult, amp, dscale in partials:
        f = base_hz * mult * detune
        tau = dscale * 0.5 * SR  # medium decay
        sig += amp * np.sin(2 * np.pi * f * t / SR) * np.exp(-t / tau)
    # Soft attack (a few ms) so it isn't a click — Rhodes "give".
    atk = int(0.012 * SR)
    sig[:atk] *= np.linspace(0.0, 1.0, atk)
    sig = normf(sig)
    sig = lowpass(sig, 2600.0)   # warmth — roll off the highs
    sig = bitcrush(sig, 7)       # slight crush
    return to_int8(sig, peak=118.0)


# C natural minor. The Rhodes one-shot is sampled at C4 (MIDI 60).
C4_HZ = 261.6256
rhodes_pcm = make_rhodes(C4_HZ, dur_s=1.7)


# ---------------------------------------------------------------------------
# Instrument 1 — KICK (deep, punchy, dusty; pitch-glide sine + saturation)
# ---------------------------------------------------------------------------

def make_kick():
    dur_s = 0.34
    n = int(dur_s * SR)
    t = np.arange(n, dtype=np.float64)
    # Downward pitch glide: ~120 Hz -> ~48 Hz, fast.
    f0, f1 = 118.0, 46.0
    k = 22.0
    fsweep = f1 + (f0 - f1) * np.exp(-t / SR * k)
    phase = 2 * np.pi * np.cumsum(fsweep) / SR
    body = np.sin(phase) * env_exp(n, 0.085 * SR)
    # Tiny click transient for attack definition.
    click = np.sin(2 * np.pi * 1800.0 * t / SR) * env_exp(n, 0.0016 * SR) * 0.25
    sig = body + click
    sig = soft_sat(sig, drive=1.8)   # punch / glue
    sig = normf(sig)
    sig = lowpass(sig, 1100.0)       # dusty — kill fizz
    return to_int8(sig, peak=122.0)


kick_pcm = make_kick()


# ---------------------------------------------------------------------------
# Instrument 2 — SNARE (HARD, cracking, dry; noise burst + short tonal body)
# ---------------------------------------------------------------------------

def make_snare():
    dur_s = 0.26
    n = int(dur_s * SR)
    t = np.arange(n, dtype=np.float64)
    # Noise crack (the Wu signature) — short, dry.
    noise = (rng.standard_normal(n))
    noise *= env_exp(n, 0.035 * SR)
    # Two tonal bodies (drum shell) for a bit of "thwack".
    tone = (np.sin(2 * np.pi * 188.0 * t / SR) +
            0.6 * np.sin(2 * np.pi * 268.0 * t / SR))
    tone *= env_exp(n, 0.045 * SR)
    sig = 0.85 * noise + 0.5 * tone
    sig = normf(sig)
    sig = lowpass(sig, 6800.0)   # lowpass a touch but KEEP the crack
    sig = bitcrush(sig, 7)
    return to_int8(sig, peak=124.0)


snare_pcm = make_snare()


# ---------------------------------------------------------------------------
# Instrument 3 — HI-HAT (dusty closed hat; very short filtered-noise burst)
# ---------------------------------------------------------------------------

def make_hat(open_hat=False):
    dur_s = 0.16 if open_hat else 0.05
    n = int(dur_s * SR)
    t = np.arange(n, dtype=np.float64)
    noise = rng.standard_normal(n)
    tau = (0.060 if open_hat else 0.014) * SR
    noise *= env_exp(n, tau)
    sig = normf(noise)
    # Bandish: high-pass-ish by subtracting a lowpassed copy, then lowpass the top.
    lp = lowpass(sig, 1200.0)
    sig = sig - 0.9 * lp          # remove lows -> hat sits up top
    sig = lowpass(sig, 8500.0)    # dusty — not too bright
    sig = bitcrush(sig, 6)        # grit
    return to_int8(sig, peak=96.0)  # hats sit lower


hat_pcm  = make_hat(open_hat=False)
ohat_pcm = make_hat(open_hat=True)


# ---------------------------------------------------------------------------
# Instrument 5 — SUB BASS (deep round low sine one-shot, clean under the dust)
# ---------------------------------------------------------------------------

def make_sub(base_hz):
    dur_s = 1.1
    n = int(dur_s * SR)
    t = np.arange(n, dtype=np.float64)
    sig = np.sin(2 * np.pi * base_hz * t / SR)
    sig += 0.12 * np.sin(2 * np.pi * 2 * base_hz * t / SR)  # faint 2nd harm
    # Slow attack so it's round, medium-long body.
    atk = int(0.010 * SR)
    sig[:atk] *= np.linspace(0.0, 1.0, atk)
    sig *= env_exp(n, 0.55 * SR)
    sig = normf(sig)
    sig = lowpass(sig, 320.0)   # keep it LOW and clean
    return to_int8(sig, peak=120.0)


# Sub sampled at C2 (MIDI 36).
C2_HZ = 65.40639
sub_pcm = make_sub(C2_HZ)


# ---------------------------------------------------------------------------
# Build the SAMPLE instruments (ALL kind=1).
# ---------------------------------------------------------------------------

I_RHODES, I_KICK, I_SNARE, I_HAT, I_OHAT, I_SUB = range(6)

instruments = [
    sample_instrument("soul rhodes (lo-fi)", rhodes_pcm, srate=SR, base_note=60,
                      volume=190, attack_ms=8, decay_ms=0, sustain_level=255,
                      release_ms=180),                       # C4
    sample_instrument("dusty kick", kick_pcm, srate=SR, base_note=36,
                      volume=255, attack_ms=0, decay_ms=0, sustain_level=255,
                      release_ms=20),
    sample_instrument("cracking snare", snare_pcm, srate=SR, base_note=60,
                      volume=240, attack_ms=0, decay_ms=0, sustain_level=255,
                      release_ms=18),
    sample_instrument("dusty hat", hat_pcm, srate=SR, base_note=60,
                      volume=150, attack_ms=0, decay_ms=0, sustain_level=255,
                      release_ms=8),
    sample_instrument("open hat", ohat_pcm, srate=SR, base_note=60,
                      volume=140, attack_ms=0, decay_ms=0, sustain_level=255,
                      release_ms=12),
    sample_instrument("sub bass", sub_pcm, srate=SR, base_note=36,
                      volume=235, attack_ms=4, decay_ms=0, sustain_level=255,
                      release_ms=60),                        # C2
]

assert all(i["kind"] == KIND_SAMPLE for i in instruments), "ALL must be sample"


# ---------------------------------------------------------------------------
# THE SCORE — C natural minor, ~90 BPM, 16th grid w/ light swing.
# ---------------------------------------------------------------------------
# rows_per_beat = 4 -> 16 rows per bar. We pair patterns into 2-bar phrases so
# the soul loop and drum variations breathe. Channels:
#   ch0,ch1,ch2 = soul rhodes polyphony (sparse chords/notes)
#   ch3 = kick   ch4 = snare   ch5 = hats   ch6 = sub bass
TEMPO = 90
RPB   = 4
ROWS  = 16  # per bar

# C natural minor MIDI: C=60 D=62 Eb=63 F=65 G=67 Ab=68 Bb=70
N_C4, N_D4, N_EB4, N_F4, N_G4, N_AB4, N_BB4 = 60, 62, 63, 65, 67, 68, 70
N_C5, N_EB5, N_G5 = 72, 75, 79
N_G3, N_AB3, N_BB3 = 55, 56, 58
# Sub roots (low):
N_C2, N_AB1, N_F1, N_G1 = 36, 32, 29, 31  # Ab1=32, F1=29, G1=31

CH_R0, CH_R1, CH_R2 = 0, 1, 2
CH_KICK, CH_SNARE, CH_HAT, CH_SUB = 3, 4, 5, 6
NUM_CH = 7

HAT_V  = 86    # low velocity hats
HAT_V2 = 60    # ghost hats even quieter


def hats_bar(swing=True, opens=()):
    """8th-note closed hats across one bar with light swing; some opens."""
    evs = []
    for step in range(8):              # 8th notes -> rows 0,2,4,...,14
        row = step * 2
        inst = I_HAT
        vel = HAT_V if step % 2 == 0 else HAT_V2  # offbeats softer
        if swing and step % 2 == 1:
            row += 1                   # push offbeat hat one 16th late = shuffle
        if step in opens:
            inst = I_OHAT
            vel = HAT_V
        evs.append(event(row, CH_HAT, N_C5, inst, vel))
    return evs


def snare_bar():
    """Backbeat: HARD snare on beats 2 and 4 (rows 4 and 12)."""
    return [event(4,  CH_SNARE, N_C4, I_SNARE, 240),
            event(12, CH_SNARE, N_C4, I_SNARE, 240)]


def kick_bar(variant=0):
    """Boom-bap kick: beat 1, then the syncopated '& of 2 / start of 3' pocket.
    'boom .. b-boom'. Vary slightly across bars."""
    if variant == 0:
        rows = [(0, 255), (7, 220), (8, 235)]          # 1 , &2 , 3
    elif variant == 1:
        rows = [(0, 255), (6, 200), (10, 220)]         # 1 , (a)2 , &3
    elif variant == 2:
        rows = [(0, 255), (3, 190), (8, 235), (11, 200)]  # 1, e1, 3, &3 (busier)
    else:
        rows = [(0, 255), (8, 235), (14, 205)]         # 1 , 3 , &4 pickup
    return [event(r, CH_KICK, N_C2, I_KICK, v) for r, v in rows]


# --- The SOUL LOOP: 2-bar haunting descending minor motif, SPARSE. ---
# Bar A: a held Cm color high, descending.  Bar B: resolves down, leaves air.
# We keep it to a few notes with long releases so it rings into the space.
# Voicing region C4-Eb4-G4 with a held resolution, one tasteful "Eastern" b2
# color (Db over the Cm -> Phrygian tinge) used once.
N_DB4 = 61  # b2 — RZA "Eastern" flavor, tasteful, used once in bar B

def soul_barA():
    R, RV = I_RHODES, 200
    return [
        # Cm triad stab (sparse), let ring
        event(0, CH_R0, N_G4,  R, RV),
        event(0, CH_R1, N_EB4, R, 180),
        event(0, CH_R2, N_C4,  R, 170),
        # descending melodic answer, leaving space
        event(8, CH_R0, N_F4,  R, 190),
        event(12, CH_R0, N_EB4, R, 185),
    ]

def soul_barB():
    R = I_RHODES
    return [
        # held resolution, lower — the "give it air" bar
        event(0, CH_R0, N_EB4, R, 195),
        event(0, CH_R1, N_C4,  R, 175),
        event(0, CH_R2, N_G3,  R, 160),
        # one Eastern b2 grace, then settle to the root, ringing out
        event(10, CH_R0, N_DB4, R, 150),  # tasteful Phrygian color
        event(12, CH_R0, N_C4,  R, 185),
    ]


def sub_barA():
    """Sub locks with kick on the root motion. C minor root."""
    return [event(0, CH_SUB, N_C2, I_SUB, 235),
            event(8, CH_SUB, N_C2, I_SUB, 215)]

def sub_barB():
    """Root motion to Ab then back — sparse."""
    return [event(0, CH_SUB, N_AB1, I_SUB, 230),
            event(8, CH_SUB, N_C2,  I_SUB, 215)]


# Assemble four distinct 1-bar patterns; order them into 16 bars.
#   pat0 = soul A + drums(var0) + hats(opens at 6) + subA
#   pat1 = soul B + drums(var1) + hats(opens at 7) + subB
#   pat2 = soul A + drums(var2, busier) + hats + subA  (mid-tune lift)
#   pat3 = soul B + drums(var3) + hats(open at 7) + subB (turnaround)

def build_bar(soul_fn, kick_var, sub_fn, hat_opens, swing=True):
    evs = []
    evs += soul_fn()
    evs += kick_bar(kick_var)
    evs += snare_bar()
    evs += hats_bar(swing=swing, opens=hat_opens)
    evs += sub_fn()
    return pattern(ROWS, evs)


pat0 = build_bar(soul_barA, 0, sub_barA, hat_opens=(6,))
pat1 = build_bar(soul_barB, 1, sub_barB, hat_opens=(7,))
pat2 = build_bar(soul_barA, 2, sub_barA, hat_opens=(2, 6))
pat3 = build_bar(soul_barB, 3, sub_barB, hat_opens=(7,))

# Intro bar: drums only, no soul loop (let the beat establish) — sparse/dark.
def build_intro():
    evs = []
    evs += kick_bar(0)
    evs += snare_bar()
    evs += hats_bar(swing=True, opens=())
    evs += sub_barA()
    return pattern(ROWS, evs)

pat_intro = build_bar.__self__ if False else build_intro()  # plain call

patterns = [pat0, pat1, pat2, pat3, pat_intro]
P0, P1, P2, P3, PIN = range(5)

# 16-bar arrangement: 1 intro bar, then 2-bar soul phrases, with the busier
# pat2 lifting the middle. Hypnotic, head-nod, leaves space. Lands ~37s.
order = [
    PIN,                 # 1 bar: drum pocket establishes
    P0, P1, P0, P1,      # 4 bars: soul loop enters
    P2, P3, P2, P3,      # 4 bars: lift (busier kick / extra open hat)
    P0, P1,              # 2 bars: back to the core loop
    P2, P3,              # 2 bars: turnaround out
]
assert len(order) == 13


# ---------------------------------------------------------------------------
# Build module -> container -> render -> write
# ---------------------------------------------------------------------------

body = build_music_body(
    tempo_bpm=TEMPO, rows_per_beat=RPB, num_channels=NUM_CH,
    instruments=instruments, patterns=patterns, order=order,
    master_volume=205,
)

header, cbody = build_music_quipu(
    body, out_rate=OUT_RATE, title="| 36 quipu chambers |",
    tone=sound.TONE_DEMONIC,   # dark/grimy tone tag
)
container_size = len(header) + len(cbody)

# Read back + verify codec / round-trip / all-sample.
rec = read_music_quipu(header, cbody)
assert rec["type"] == "sound"
assert rec["codec"] == 0x20, rec["codec"]
assert rec["body"] == body
mod = rec["module"]
all_sample = all(i["kind"] == KIND_SAMPLE for i in mod["instruments"])
assert all_sample, "ALL instruments must be kind=sample"

# Render (deterministic) + measure.
audio = render_music(rec["body"], out_rate=OUT_RATE)
audio2 = render_music(rec["body"], out_rate=OUT_RATE)
deterministic = bool(np.array_equal(audio, audio2))

peak = float(np.max(np.abs(audio)))
rms  = float(np.sqrt(np.mean(audio.astype(np.float64) ** 2)))
dur_ms = module_duration_ms(mod, out_rate=OUT_RATE)
dur_s = dur_ms / 1000.0

assert peak <= 0.9 + 1e-6, f"peak must stay <= 0.9 (got {peak})"
assert np.all(np.isfinite(audio))

# Write the container .bin (header + body) and the WAV.
bin_path = os.path.join(HERE, "wutang.sound.bin")
wav_path = os.path.join(HERE, "wutang.wav")
with open(bin_path, "wb") as f:
    f.write(header)
    f.write(cbody)
write_wav(wav_path, audio, OUT_RATE)

bin_size = os.path.getsize(bin_path)
wav_size = os.path.getsize(wav_path)

print("=== Wu-Tang / RZA boom-bap — quipu MUSIC codec ===")
print(f"  container (.bin)    : {bin_path}")
print(f"  container byte size : {container_size} B  (file on disk {bin_size} B)")
print(f"     header {len(header)} B + body {len(cbody)} B")
print(f"  codec byte          : 0x{rec['codec']:02x} ({rec['codec_name']})")
print(f"  WAV                  : {wav_path} ({wav_size} B)")
print(f"  duration             : {dur_s:.2f} s ({dur_ms} ms)")
print(f"  peak                 : {peak:.5f}   (<= 0.9, no clip)")
print(f"  rms                  : {rms:.5f}")
print(f"  deterministic        : {deterministic}")
print(f"  num instruments      : {len(mod['instruments'])}")
for i in mod["instruments"]:
    kind = "sample" if i["kind"] == KIND_SAMPLE else "SYNTH"
    print(f"     - kind={kind:6s} '{i['name']}'  "
          f"(base_note={i['base_note']}, pcm={len(i['pcm'])} B int8)")
print(f"  ALL instruments kind=sample : {all_sample}")
print("  SCORE: C natural minor | 90 BPM, 16th grid (rows_per_beat=4, light "
      "swing) | 16 bars, 5 patterns, 2-bar soul loop (Cm: G-Eb-C stab -> "
      "F/Eb descent -> Eb/C/G resolve w/ one Db Phrygian grace) | drums: "
      "kick on 1 + &2/3 pocket (varied), HARD snare on 2 & 4, swung 8th hats "
      "+ open-hat flavor, sub locking C2->Ab1 roots")
