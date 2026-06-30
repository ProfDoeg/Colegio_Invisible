#!/usr/bin/env python
"""Compose a BOOM-BAP / Wu-Tang head-nod JAM (~88 BPM) from the user's
chopped hum (hum173_chop.npz). Dark, sparse, dusty.

Drums + bass = synth instruments. The melodic hook = short G#3/A3 slices of the
hum, re-sequenced on a 16th-note grid and looped.
"""
import os
import sys

import numpy as np

HERE = "/Users/anthony/Documents/taller/Colegio_Invisible/working/music"
sys.path.insert(0, "/Users/anthony/Documents/taller/Colegio_Invisible/canonical")
sys.path.insert(0, HERE)

import music_codec as M
import sound

OUT_BIN = os.path.join(HERE, "jam_boombap.sound.bin")
OUT_WAV = os.path.join(HERE, "jam_boombap.wav")

# ---------------------------------------------------------------------------
# Load the chopped hum
# ---------------------------------------------------------------------------
z = np.load(os.path.join(HERE, "hum173_chop.npz"))
pcm = z["pcm"]
slices = [tuple(int(v) for v in s) for s in z["slices"]]
rate = int(z["rate"])

# ---------------------------------------------------------------------------
# Instruments
# ---------------------------------------------------------------------------
# Hum, chopped — short attack/release so stabs are tight & dusty.
hum = M.sliced_instrument(
    "hum", pcm, slices, srate=rate,
    volume=235, attack_ms=2, release_ms=22,
)
HUM = 0

# Hard dusty kick: sine, low, short punchy body with a fast decay.
kick = M.synth_instrument(
    "kick", M.WAVE_SINE, volume=255,
    attack_ms=1, decay_ms=110, sustain_level=0, release_ms=40,
)
KICK = 1

# Cracking snare: ONE-SHOT noise burst — sustain_level=0 so it decays to silence
# (no sustained noise bed = no static), duty band-limits the crack.
snare = M.synth_instrument(
    "snare", M.WAVE_NOISE, volume=200, duty=150,
    attack_ms=1, decay_ms=55, sustain_level=0, release_ms=22,
)
SNARE = 2

# Snare body (tonal thwack under the noise) — short triangle.
snarebody = M.synth_instrument(
    "snarebody", M.WAVE_TRIANGLE, volume=120,
    attack_ms=1, decay_ms=45, sustain_level=0, release_ms=20,
)
SNAREB = 3

# Dusty hat: very short, quiet, band-limited noise tick (tight one-shot).
hat = M.synth_instrument(
    "hat", M.WAVE_NOISE, volume=60, duty=205,
    attack_ms=0, decay_ms=13, sustain_level=0, release_ms=5,
)
HAT = 4

# Sub bass: sine on the low roots (A1 ~ MIDI 33, E1 ~ MIDI 28).
sub = M.synth_instrument(
    "sub", M.WAVE_SINE, volume=255,
    attack_ms=3, decay_ms=40, sustain_level=210, release_ms=70,
)
SUB = 5

instruments = [hum, kick, snare, snarebody, hat, sub]

# ---------------------------------------------------------------------------
# Channels
# ---------------------------------------------------------------------------
CH_KICK, CH_SNARE, CH_SNB, CH_HAT, CH_SUB = 0, 1, 2, 3, 4
CH_HUM_A, CH_HUM_B = 5, 6
NUM_CH = 8

# ---------------------------------------------------------------------------
# Grid: 88 BPM, 4 rows/beat = 16th grid. Bar = 16 rows. Pattern = 2 bars = 32.
# Row indices within a 16-row bar:
#   0=1   2=1&  4=2   6=2&  8=3  10=3& 12=4  14=4&
# ---------------------------------------------------------------------------
TEMPO = 88
ROWS_PER_BEAT = 4
BAR = 16
PAT_ROWS = 32  # two bars

# Hum hook (note = slice_index + 1). Short G#3/A3 stabs, re-sequenced.
# slice 28=G#3, 20=G#3, 7=G#3, 32=A3, 17=G#3, 33=F#3, 4=G#3
GS_A, GS_B, GS_C = 28, 20, 7       # G#3 stabs (punchy)
A3_1 = 32                          # A3
GS_D = 17                          # G#3
FS = 33                            # F#3 (color)
SUS = 6                            # A3 sustained (longer slice for a held tail)


def hum_ev(row, ch, slice_idx, vel=235):
    return M.event(row, ch, slice_idx + 1, HUM, vel)


def hum_off(row, ch):
    return M.event(row, ch, 0, HUM, 0)


def build_pattern():
    ev = []

    # -- DRUMS over the two bars --
    for bar in range(2):
        b = bar * BAR
        # Kick: boom-bap pocket -> on 1 (row 0) and the '&' of 2 (row 6).
        ev.append(M.event(b + 0, CH_KICK, 36, KICK, 255))
        ev.append(M.event(b + 6, CH_KICK, 36, KICK, 240))
        # An extra ghost kick on the '&' of 3 in bar 2 for a little swing pull.
        if bar == 1:
            ev.append(M.event(b + 11, CH_KICK, 36, KICK, 200))

        # Snare on 2 & 4 (rows 4 and 12). Noise crack + tonal body.
        for sr in (4, 12):
            ev.append(M.event(b + sr, CH_SNARE, 64, SNARE, 220))
            ev.append(M.event(b + sr, CH_SNB, 52, SNAREB, 150))

        # Hats on every 8th note (rows 0,2,4,...,14). Accent the offbeats.
        for hr in range(0, BAR, 2):
            vel = 95 if (hr % 4 == 2) else 65  # offbeats a touch louder
            ev.append(M.event(b + hr, CH_HAT, 70, HAT, vel))

        # Sub bass: low roots, head-nod movement. A1(33) -> E1(28).
        # 1: A1 land on the kick; move to E1 in the second half.
        ev.append(M.event(b + 0, CH_SUB, 33, SUB, 255))      # A1 on the 1
        ev.append(M.event(b + 6, CH_SUB, 33, SUB, 235))      # A1 reinforce w/ kick
        ev.append(M.event(b + 8, CH_SUB, 28, SUB, 245))      # E1 on the 3
        ev.append(M.event(b + 14, CH_SUB, 28, SUB, 220))     # E1 pickup into next bar
        ev.append(M.event(b + 15, CH_SUB, 0, SUB, 0))        # key-off before downbeat

    # -- HUM HOOK (the melodic chops) --
    # A short, dark 4-8 slice phrase on a 16th grid, answered across the 2 bars.
    # Bar 1: stab phrase. Bar 2: variation + a held A3 tail.
    # Channel A = the lead stabs (cut tight by the next stab).
    # Bar 1
    hook_a = [
        (2,  GS_A),   # G#3 on the '&' of 1
        (5,  GS_B),   # G#3 (syncopated)
        (8,  A3_1),   # A3 on the 3
        (11, GS_C),   # G#3
        (14, FS),     # F#3 color into the turn
    ]
    for r, sl in hook_a:
        ev.append(hum_ev(r, CH_HUM_A, sl))
    ev.append(hum_off(15, CH_HUM_A))

    # Bar 2 (rows offset by 16): variation, sparser, ends on a sustained A3.
    hook_b = [
        (16 + 2,  GS_D),  # G#3
        (16 + 5,  GS_A),  # G#3
        (16 + 8,  GS_B),  # G#3 on the 3
    ]
    for r, sl in hook_b:
        ev.append(hum_ev(r, CH_HUM_A, sl))
    ev.append(hum_off(16 + 9, CH_HUM_A))
    # A held A3 tail on channel B (longer slice 6) ringing into the loop seam.
    ev.append(hum_ev(16 + 11, CH_HUM_B, SUS, 200))
    ev.append(hum_off(16 + 15, CH_HUM_B))

    return M.pattern(PAT_ROWS, ev)


pat = build_pattern()
patterns = [pat]
# Loop the 2-bar pattern 4x  ->  ~21.8 s (matches the hum's own length).
LOOPS = 4
order = [0] * LOOPS

body = M.build_music_body(
    tempo_bpm=TEMPO, rows_per_beat=ROWS_PER_BEAT, num_channels=NUM_CH,
    instruments=instruments, patterns=patterns, order=order,
    master_volume=205,
)

header, cbody = M.build_music_quipu(
    body, out_rate=rate,
    title="| boom-bap hum jam |",
    tone=sound.TONE_AI,
)

with open(OUT_BIN, "wb") as f:
    f.write(header + cbody)

audio = M.render_music(body, rate)
M.write_wav(OUT_WAV, audio, rate)

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
container_size = len(header) + len(cbody)
dur_s = len(audio) / rate
peak = float(np.max(np.abs(audio)))
rms = float(np.sqrt(np.mean(audio.astype(np.float64) ** 2)))

print("RESULT")
print(f"  container_bytes : {container_size}")
print(f"  module_body     : {len(body)} B")
print(f"  duration_s      : {dur_s:.2f}")
print(f"  samples         : {len(audio)}")
print(f"  rate            : {rate}")
print(f"  peak            : {peak:.4f}")
print(f"  rms             : {rms:.4f}")
_fr = 1024
_rf = np.array([np.sqrt(np.mean(audio[i:i+_fr]**2)) for i in range(0, len(audio)-_fr, _fr)])
print(f"  tempo_bpm       : {TEMPO}  rows/beat {ROWS_PER_BEAT}  loops {LOOPS}")
print(f"  quiet_floor_dB  : {20*np.log10(np.percentile(_rf,10)+1e-12):.0f}  (was -8 dB; lower = less static)")
print(f"  bin             : {OUT_BIN} ({os.path.getsize(OUT_BIN)} B)")
print(f"  wav             : {OUT_WAV} ({os.path.getsize(OUT_WAV)} B)")
