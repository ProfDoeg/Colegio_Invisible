"""
JAM: UPTEMPO BOUNCE ~124 BPM from the user's chopped hum.

Energetic, playful, danceable. Four-on-the-floor kick with a bouncy syncopated
ghost, clap on 2 & 4, busy 16th hats, a triangle-sub bassline rooted on the
E2/D2 low hum slices' pitch (re-built as synth so it's tight and punchy), and the
hum chopped into a catchy stutter riff (a couple of slices repeated for a hook).
"""

import os
import sys

sys.path.insert(0, "/Users/anthony/Documents/taller/Colegio_Invisible/canonical")

import numpy as np

import music_codec as M
import sound

HERE = "/Users/anthony/Documents/taller/Colegio_Invisible/working/music"
OUT_BIN = os.path.join(HERE, "jam_bounce.sound.bin")
OUT_WAV = os.path.join(HERE, "jam_bounce.wav")

# ---------------------------------------------------------------------------
# Source: the chopped hum
# ---------------------------------------------------------------------------
z = np.load(os.path.join(HERE, "hum173_chop.npz"))
pcm = z["pcm"]
slices = [tuple(int(v) for v in s) for s in z["slices"]]
rate = int(z["rate"])

# Sliced vocal instrument. Short attack to keep chops snappy; quick release so a
# cut chop doesn't smear into the next 16th.
hum = M.sliced_instrument(
    "hum", pcm, slices, srate=rate,
    attack_ms=3, release_ms=18, volume=255,
)
HUM = 0  # instrument index

# ---------------------------------------------------------------------------
# Drum + bass synths
# ---------------------------------------------------------------------------
# Kick: sine, fast decay, no sustain — pitch from a low MIDI note (36 = C2).
kick = M.synth_instrument(
    "kick", M.WAVE_SINE, volume=255,
    attack_ms=0, decay_ms=85, sustain_level=0, release_ms=30,
)
KICK = 1

# Snare/clap: noise burst, snappy.
clap = M.synth_instrument(
    "clap", M.WAVE_NOISE, volume=190,
    attack_ms=0, decay_ms=70, sustain_level=0, release_ms=40,
)
CLAP = 2

# Hat: very short noise tick.
hat = M.synth_instrument(
    "hat", M.WAVE_NOISE, volume=95,
    attack_ms=0, decay_ms=18, sustain_level=0, release_ms=8,
)
HAT = 3

# Sub bass: triangle, low, with a hair of sustain so it bounces.
sub = M.synth_instrument(
    "sub", M.WAVE_TRIANGLE, volume=235,
    attack_ms=2, decay_ms=60, sustain_level=140, release_ms=40,
)
SUB = 4

instruments = [hum, kick, clap, hat, sub]

# ---------------------------------------------------------------------------
# Grid: 124 BPM, 4 rows/beat -> 16th grid. 16 rows = 1 bar.
# Channels: 0 hum-lead, 1 hum-hook/stutter, 2 kick, 3 clap, 4 hat, 5 sub, 6 sub2
# ---------------------------------------------------------------------------
TEMPO = 124
RPB = 4
NUM_CH = 8
ROWS = 16  # one bar per pattern

CH_HUM_A = 0
CH_HUM_B = 1
CH_KICK = 2
CH_CLAP = 3
CH_HAT = 4
CH_SUB = 5

# F#-minor / A-major bassline root choices (MIDI): F#1=30, A1=33, E2=40,
# D2=38, B1=35, C#2=37. Keep it low + bouncy.

def drum_bed(bass_notes):
    """Common groove: four-on-floor kick, clap 2&4, busy hats, bouncy sub.
    bass_notes: list of (row, midi_note) for the sub bassline this bar."""
    ev = []
    # Kick: four on the floor (rows 0,4,8,12) + a bouncy syncopated ghost on the
    # 'and' of beat 3 (row 11) for the bounce.
    for r in (0, 4, 8, 12):
        ev.append(M.event(r, CH_KICK, 36, KICK, 255))
    ev.append(M.event(11, CH_KICK, 36, KICK, 170))
    # Clap on 2 & 4 (rows 4, 12).
    ev.append(M.event(4, CH_CLAP, 60, CLAP, 230))
    ev.append(M.event(12, CH_CLAP, 60, CLAP, 230))
    # Hats: every 16th, accenting the off-beats (the 'e' and 'a').
    for r in range(16):
        vel = 130 if (r % 2 == 1) else 80   # push off-beats for swing-ish bounce
        ev.append(M.event(r, CH_HAT, 72, HAT, vel))
    # Sub bassline.
    for (r, note) in bass_notes:
        ev.append(M.event(r, CH_SUB, note, SUB, 240))
    return ev


# Hum hook slices (consonant in A-maj / F#-min):
#   A3 = 1, 6, 13 ; G#3 = 9, 10, 11 (and short 7,17) ; G3 = 16 ; B3 = 14 ; F#3 = 12,33
# Short stutter slices: 9(G#3,104), 14(B3,104), 17(G#3,104), 7(G#3,116)
A3a, A3b = 1, 13
GS3 = 10
GS3s = 9      # short G#3 for stutter
B3s = 14      # short B3
G3 = 16
FS3 = 12

# Bassline notes (low, bouncy): root walk in F# minor.
#  FS1=30, A1=33, B1=35, CS2=37, D2=38, E2=40
BASS_A = [(0, 30), (3, 30), (6, 33), (8, 38), (11, 38), (14, 37)]  # F# .. A .. D .. C#
BASS_B = [(0, 30), (3, 30), (6, 35), (8, 40), (11, 40), (14, 38)]  # F# .. B .. E .. D


# --- Pattern 0: intro / main groove A — hook melody chopped on grid ---
# Hum lead on CH_HUM_A: phrase F#3 -> A3 -> G#3 -> A3, chopped to length by the
# next event. A short rest then a stutter on CH_HUM_B at the bar tail.
hum_A = [
    M.event(0,  CH_HUM_A, FS3 + 1, HUM, 235),   # F#3
    M.event(4,  CH_HUM_A, A3a + 1, HUM, 245),   # A3
    M.event(8,  CH_HUM_A, GS3 + 1, HUM, 240),   # G#3
    M.event(12, CH_HUM_A, A3b + 1, HUM, 245),   # A3
    M.event(15, CH_HUM_A, 0, HUM, 0),           # cut tight
]
# Stutter hook on CH_HUM_B: rapid repeat of a short slice = the catchy hook.
hum_hookA = [
    M.event(6,  CH_HUM_B, GS3s + 1, HUM, 210),
    M.event(7,  CH_HUM_B, GS3s + 1, HUM, 210),
    M.event(14, CH_HUM_B, B3s + 1, HUM, 215),
    M.event(15, CH_HUM_B, B3s + 1, HUM, 220),
]
pat0 = M.pattern(ROWS, hum_A + hum_hookA + drum_bed(BASS_A))

# --- Pattern 1: groove B — answer phrase + busier stutter ---
hum_B = [
    M.event(0,  CH_HUM_A, A3a + 1, HUM, 245),
    M.event(4,  CH_HUM_A, G3 + 1,  HUM, 235),   # G3
    M.event(8,  CH_HUM_A, GS3 + 1, HUM, 240),
    M.event(10, CH_HUM_A, FS3 + 1, HUM, 235),
    M.event(13, CH_HUM_A, 0, HUM, 0),
]
hum_hookB = [
    # Triple stutter for the hook turnaround.
    M.event(12, CH_HUM_B, GS3s + 1, HUM, 215),
    M.event(13, CH_HUM_B, GS3s + 1, HUM, 215),
    M.event(14, CH_HUM_B, GS3s + 1, HUM, 220),
    M.event(15, CH_HUM_B, B3s + 1,  HUM, 225),
]
pat1 = M.pattern(ROWS, hum_B + hum_hookB + drum_bed(BASS_B))

# --- Pattern 2: drop / breakdown — drums + sub only, hum stutter teaser ---
hum_teaser = [
    M.event(0,  CH_HUM_B, A3a + 1, HUM, 230),
    M.event(2,  CH_HUM_B, A3a + 1, HUM, 200),
    M.event(8,  CH_HUM_B, GS3s + 1, HUM, 215),
    M.event(10, CH_HUM_B, GS3s + 1, HUM, 210),
    M.event(12, CH_HUM_B, GS3s + 1, HUM, 220),
    M.event(14, CH_HUM_B, B3s + 1,  HUM, 225),
]
pat2 = M.pattern(ROWS, hum_teaser + drum_bed(BASS_A))

patterns = [pat0, pat1, pat2]

# Arrangement: A A B  | A A B  | drop(2) | A B  -> grooving, repetitive, danceable
# ~16 bars total. Each bar = 16 rows.
order = [0, 0, 1, 0, 0, 1, 2, 1, 0, 0, 1, 2, 0, 1]

body = M.build_music_body(
    tempo_bpm=TEMPO, rows_per_beat=RPB, num_channels=NUM_CH,
    instruments=instruments, patterns=patterns, order=order,
    master_volume=205,
)

header, cbody = M.build_music_quipu(
    body, out_rate=rate, title="| hum bounce jam ~124bpm |", tone=sound.TONE_AI,
)

with open(OUT_BIN, "wb") as f:
    f.write(header + cbody)

audio = M.render_music(body, rate)
M.write_wav(OUT_WAV, audio, rate)

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
mod = M.read_music_body(body)
container_size = len(header) + len(cbody)
dur_ms = M.module_duration_ms(mod, out_rate=rate)
peak = float(np.max(np.abs(audio)))
rms = float(np.sqrt(np.mean(audio.astype(np.float64) ** 2)))
n_events = sum(len(p["events"]) for p in patterns)

print("=== JAM: hum bounce ~124 BPM ===")
print(f"container : {container_size} B  (header {len(header)} + body {len(cbody)})")
print(f"wav       : {os.path.getsize(OUT_WAV)} B")
print(f"duration  : {dur_ms/1000:.2f} s  ({dur_ms} ms)")
print(f"tempo     : {TEMPO} BPM, {RPB} rows/beat, {NUM_CH} ch, {len(order)} bars")
print(f"peak      : {peak:.4f}")
print(f"rms       : {rms:.4f}")
print(f"events    : {n_events} across {len(patterns)} patterns")
print("SCORE: 124-BPM four-on-floor bounce; kick+ghost, clap on 2&4, busy 16th "
      "hats, triangle-sub F#-minor bassline; hum chopped to a F#3-A3-G#3-A3 hook "
      "with G#3/B3 stutter repeats; A-A-B form + a drop. Danceable.")
