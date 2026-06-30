"""
compose_jam_calm.py — a CALM lo-fi jam built from the user's own hummed melody.

~74 BPM, sparse and warm. Soft kick on 1 & 3, gentle shaker/hat, soft sub.
The hum slices (G#3/A3/F#3/B3) are sequenced into a slow pretty phrase with
space; one low E2 slice is a soft bass pulse. The voice is the centerpiece.
"""

import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "/Users/anthony/Documents/taller/Colegio_Invisible/canonical")
sys.path.insert(0, HERE)

import music_codec as M
import sound

OUT_BIN = os.path.join(HERE, "jam_calm.sound.bin")
OUT_WAV = os.path.join(HERE, "jam_calm.wav")

# ---------------------------------------------------------------------------
# Load the chopped hum.
# ---------------------------------------------------------------------------
z = np.load(os.path.join(HERE, "hum173_chop.npz"))
pcm    = z["pcm"]                                       # int8 @ 22050
slices = [tuple(int(v) for v in s) for s in z["slices"]]
rate   = int(z["rate"])

# The sliced vocal instrument. Gentle attack/release so chops don't click.
hum = M.sliced_instrument(
    "hum", pcm, slices, srate=rate,
    attack_ms=4, release_ms=40, volume=255,
)

# Slice picks (index -> pitch), from the supplied contour + measured loudness:
#   melodic hook (pretty, sustained):  G#3=3, A3=13, F#3=12, B3=14, G#3=10
#   bass pulse (low, warm):            E2=27 (0.58s solid), D2=34
HUM = 0  # instrument index

# ---------------------------------------------------------------------------
# Drums + sub — soft synths.
# ---------------------------------------------------------------------------
# Kick: low sine, short, soft. Triggered at a low MIDI note for a round thud.
kick = M.synth_instrument(
    "kick", M.WAVE_SINE, volume=150,
    attack_ms=1, decay_ms=130, sustain_level=0, release_ms=40,
)
# Hat / shaker: a very short noise tick, quiet.
hat = M.synth_instrument(
    "hat", M.WAVE_NOISE, volume=42,
    attack_ms=0, decay_ms=28, sustain_level=0, release_ms=14,
)
# Sub bass: warm triangle, low and soft, long-ish for a pillow under the hum.
sub = M.synth_instrument(
    "sub", M.WAVE_TRIANGLE, volume=120,
    attack_ms=8, decay_ms=120, sustain_level=150, release_ms=120,
)

instruments = [hum, kick, hat, sub]
I_HUM, I_KICK, I_HAT, I_SUB = 0, 1, 2, 3

# ---------------------------------------------------------------------------
# Grid. 74 BPM, 4 rows/beat (16th grid). 16 rows = 1 bar. Pattern = 2 bars = 32 rows.
# At 74 BPM a 16th is ~0.203 s, a bar ~3.24 s. Two-bar phrase ~6.5 s.
# ---------------------------------------------------------------------------
TEMPO = 74
RPB   = 4
BAR   = 16
ROWS  = BAR * 2   # 32-row, two-bar phrase

# Channels:
#   0 = hum melody (lead vocal phrase)
#   1 = hum bass pulse (low E2/D2 slice)
#   2 = kick
#   3 = hat / shaker
#   4 = sub bass
CH_MEL, CH_BAS, CH_KICK, CH_HAT, CH_SUB = 0, 1, 2, 3, 4
NUM_CH = 6

# MIDI notes for synths.
KICK_N = 36   # C2-ish thud
SUB_A  = 33   # A1   (root, A major)
SUB_E  = 28   # E1   (the fifth below)

def slc(i):
    """note value to trigger slice index i."""
    return i + 1

# --- Pattern A: melody states the phrase; soft drums; sub on A. ---
ev = []

# Drums (both bars identical): soft kick on beat 1 & 3 of each bar.
for bar0 in (0, BAR):
    ev += [
        M.event(bar0 + 0,  CH_KICK, KICK_N, I_KICK, 180),
        M.event(bar0 + 8,  CH_KICK, KICK_N, I_KICK, 150),
    ]
    # Gentle shaker: offbeat 8th-note ticks, soft, with a touch of swing-feel
    # by accenting the back half.
    for r, v in [(2, 28), (6, 40), (10, 28), (14, 44)]:
        ev.append(M.event(bar0 + r, CH_HAT, 60, I_HAT, v))

# Sub bass: a slow pulse. A under bar 1, drop to E under bar 2 -> gentle motion.
ev += [
    M.event(0,   CH_SUB, SUB_A, I_SUB, 150),
    M.event(8,   CH_SUB, SUB_A, I_SUB, 120),
    M.event(BAR, CH_SUB, SUB_E, I_SUB, 150),
    M.event(BAR + 8, CH_SUB, SUB_E, I_SUB, 120),
]

# Melody phrase (channel 0). Slow, spacious. Each note rings then is cut by the
# next event. Leave gaps (rests) so the hum breathes. A major / F#-minor feel.
#   row : slice (pitch)
mel = [
    (0,  3),    # G#3  — long, warm opening (lets it ring ~ a beat)
    (6,  13),   # A3   — answer, up
    (12, 12),   # F#3  — settle down
    (16, 10),   # G#3  — restate at bar 2
    (22, 14),   # B3   — a bright reach (short slice)
    (24, 13),   # A3   — resolve back toward A
    (30, 0),    # key-off — let the last note decay into space at phrase end
]
for r, s in mel:
    if s == 0:
        ev.append(M.event(r, CH_MEL, 0, I_HUM, 0))   # key-off
    else:
        ev.append(M.event(r, CH_MEL, slc(s), I_HUM, 235))

# Bass pulse from the hum's own low voice (channel 1): one soft E2 hit at the
# top of each bar, doubling the sub but with the user's timbre.
ev += [
    M.event(0,   CH_BAS, slc(27), I_HUM, 150),   # E2
    M.event(BAR, CH_BAS, slc(34), I_HUM, 140),   # D2  (motion under bar 2)
]

patA = M.pattern(ROWS, ev)

# --- Pattern B: a variation — sparser melody, more space, same groove. ---
ev2 = []
for bar0 in (0, BAR):
    ev2 += [
        M.event(bar0 + 0,  CH_KICK, KICK_N, I_KICK, 180),
        M.event(bar0 + 8,  CH_KICK, KICK_N, I_KICK, 150),
    ]
    for r, v in [(2, 26), (6, 38), (10, 26), (14, 42)]:
        ev2.append(M.event(bar0 + r, CH_HAT, 60, I_HAT, v))
ev2 += [
    M.event(0,   CH_SUB, SUB_A, I_SUB, 150),
    M.event(8,   CH_SUB, SUB_A, I_SUB, 120),
    M.event(BAR, CH_SUB, SUB_E, I_SUB, 150),
    M.event(BAR + 8, CH_SUB, SUB_E, I_SUB, 120),
]
# Sparser, more pensive melodic restatement with longer rings + a rest bar feel.
mel2 = [
    (0,  10),   # G#3
    (8,  13),   # A3
    (16, 12),   # F#3  — held long across most of bar 2
    (26, 3),    # G#3  — a single late warm tail
    (31, 0),    # key-off
]
for r, s in mel2:
    if s == 0:
        ev2.append(M.event(r, CH_MEL, 0, I_HUM, 0))
    else:
        ev2.append(M.event(r, CH_MEL, slc(s), I_HUM, 225))
ev2 += [
    M.event(0,   CH_BAS, slc(27), I_HUM, 145),   # E2
    M.event(BAR, CH_BAS, slc(27), I_HUM, 130),   # E2 again, steadier
]
patB = M.pattern(ROWS, ev2)

patterns = [patA, patB]
# A -> A -> B -> A : 4 phrases, ~26 s of a breathing loop.
order = [0, 0, 1, 0]

# ---------------------------------------------------------------------------
# Encode + render.
# ---------------------------------------------------------------------------
body = M.build_music_body(
    tempo_bpm=TEMPO, rows_per_beat=RPB, num_channels=NUM_CH,
    instruments=instruments, patterns=patterns, order=order,
    master_volume=200,
)

header, cbody = M.build_music_quipu(
    body, out_rate=rate, title="| calm hum jam |", tone=sound.TONE_AI,
)

with open(OUT_BIN, "wb") as f:
    f.write(header + cbody)

audio = M.render_music(body, rate)
M.write_wav(OUT_WAV, audio, rate)

# ---------------------------------------------------------------------------
# Report.
# ---------------------------------------------------------------------------
container_size = len(header) + len(cbody)
dur_ms = M.module_duration_ms(M.read_music_body(body), out_rate=rate)
peak = float(np.max(np.abs(audio)))
rms  = float(np.sqrt(np.mean(audio.astype(np.float64) ** 2)))

print(f"container : {container_size} B  (header {len(header)} + body {len(cbody)})")
print(f"wav       : {os.path.getsize(OUT_WAV)} B")
print(f"duration  : {dur_ms/1000.0:.2f} s")
print(f"peak      : {peak:.4f}")
print(f"rms       : {rms:.4f}")
print(f"tempo     : {TEMPO} BPM, {RPB} rows/beat, {NUM_CH} ch, order {order}")
print("SCORE: 74 BPM lo-fi; soft sine kick on 1&3, quiet noise shaker offbeats, "
      "warm triangle sub (A->E); hummed G#3/A3/F#3/B3 sliced into a slow breathing "
      "phrase over an E2/D2 vocal bass pulse — the user's voice front and center.")
