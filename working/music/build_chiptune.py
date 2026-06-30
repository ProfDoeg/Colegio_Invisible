"""
build_chiptune.py — compose an 8-bit chiptune piece with the quipu MUSIC codec.

Key A minor, ~136 BPM, rows_per_beat=4 (16th-note grid). Upbeat and playful.
Chord loop, 1 bar each:  Am - F - C - G  (the classic i-VI-III-VII), x4 = 16 bars.

Voices (all SYNTH, kind=0):
  ch0  PULSE LEAD   square, duty 64 (25% thin/bright), snappy ADSR — the melody
  ch1  TRIANGLE BASS triangle — chord roots in 8th notes (A2 F2 C3 G2)
  ch2  square ARP    square, duty 128 — root-3rd-5th, 16th notes (the shimmer)
  ch3  NOISE perc    waveform 4 — a hat on every 8th (quiet) + snare on beats 2 & 4

Encodes a 0x07 sound container (codec 0x20), renders to WAV, prints a report.
Run:  /Users/anthony/Documents/taller/Colegio_Invisible/.venv/bin/python \
        Colegio_Invisible/working/music/build_chiptune.py
(cwd /Users/anthony/Documents/taller)
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CANON = os.path.abspath(os.path.join(HERE, "..", "..", "canonical"))
sys.path.insert(0, CANON)   # so `import sound` resolves
sys.path.insert(0, HERE)    # so `import music_codec` resolves

import numpy as np

import sound
import music_codec as mc

OUT_RATE = 22050
TEMPO    = 136
RPB      = 4          # rows per beat -> 16 rows per 4/4 bar
ROWS_BAR = RPB * 4    # 16

# ---------------------------------------------------------------------------
# MIDI note helpers (A minor; A4 = 69)
# ---------------------------------------------------------------------------
A2, F2, C3, G2 = 45, 41, 48, 43          # triangle bass roots
# Chord tones (MIDI) for each bar — root, 3rd, 5th in a mid octave for the arp.
#   Am = A C E   F = F A C   C = C E G   G = G B D
CHORDS = [
    ("Am", [57, 60, 64]),   # A3 C4 E4
    ("F",  [53, 57, 60]),   # F3 A3 C4
    ("C",  [48, 52, 55]),   # C3 E3 G3
    ("G",  [55, 59, 62]),   # G3 B3 D4
]
BASS_ROOT = [A2, F2, C3, G2]

# Velocities
V_LEAD  = 235
V_BASS  = 215
V_ARP   = 150
V_HAT   = 55
V_SNARE = 200

# Channels
CH_LEAD, CH_BASS, CH_ARP, CH_PERC = 0, 1, 2, 3
NUM_CH = 4

# Instrument indices (order matters: kind tags shown in report)
I_LEAD, I_BASS, I_ARP, I_PERC = 0, 1, 2, 3


def build_instruments():
    lead = mc.synth_instrument(
        "pulse lead", mc.WAVE_SQUARE, duty=64,          # ~25% thin bright pulse
        volume=215, attack_ms=1, decay_ms=35,
        sustain_level=170, release_ms=55,
    )
    bass = mc.synth_instrument(
        "triangle bass", mc.WAVE_TRIANGLE,
        volume=235, attack_ms=1, decay_ms=60,
        sustain_level=210, release_ms=45,
    )
    arp = mc.synth_instrument(
        "square arp", mc.WAVE_SQUARE, duty=128,         # 50% — classic shimmer
        volume=120, attack_ms=1, decay_ms=22,
        sustain_level=120, release_ms=25,
    )
    perc = mc.synth_instrument(
        "noise perc", mc.WAVE_NOISE,
        volume=200, attack_ms=0, decay_ms=18,
        sustain_level=0, release_ms=30,                 # short snappy noise burst
    )
    return [lead, bass, arp, perc]


# ---------------------------------------------------------------------------
# Lead melody — one phrase per bar, A minor, mostly stepwise, landing on
# chord tones. 4 bars (Am F C G), then loop x4. The first beat of each bar
# lands on a chord tone; the line is mostly conjunct with a couple of leaps.
# Rows are within a 16-row bar. (row, midi) pairs; held until the next lead note.
# ---------------------------------------------------------------------------
LEAD_PHRASES = [
    # Bar 1 — Am: land on E4(64), step down A-minor, leap up to A4
    [(0, 64), (2, 62), (4, 60), (6, 64), (8, 69), (11, 67), (14, 64)],
    # Bar 2 — F : land on A3(57)/C4, neighbor tones, leap to F4
    [(0, 65), (2, 64), (4, 60), (6, 62), (8, 60), (10, 57), (12, 65), (14, 64)],
    # Bar 3 — C : land on E4(64), bright stepwise climb to G4
    [(0, 64), (2, 65), (4, 67), (6, 64), (8, 60), (10, 62), (12, 64), (14, 67)],
    # Bar 4 — G : land on D4(62)/B3, descend, leave on the leading tone B3(59)
    [(0, 67), (2, 65), (4, 62), (6, 64), (8, 62), (10, 59), (12, 62), (14, 59)],
]


# Each bar is ONE pattern of ROWS_BAR (16) rows, with row numbers LOCAL to the
# bar (0..15) — so row and num_rows both fit in a u8. The 4 chord bars become
# 4 patterns; the ORDER list sequences them Am-F-C-G x4 = 16 bars. Voices
# SUSTAIN across a pattern boundary (the renderer flattens the order into one
# absolute timeline and pairs each note with the next event on its channel),
# so the bass/lead/arp ring through bar lines naturally.

def lead_events(bar):
    """Lead melody events for one bar (local rows 0..15)."""
    evs = []
    phrase = LEAD_PHRASES[bar % 4]
    for row, note in phrase:
        evs.append(mc.event(row, CH_LEAD, note, I_LEAD, V_LEAD))
    return evs


def bass_events(bar):
    """Triangle bass — chord root in straight 8th notes (every 2 rows)."""
    root = BASS_ROOT[bar % 4]
    evs = []
    for k in range(8):                       # 8 eighth-notes per bar
        evs.append(mc.event(k * 2, CH_BASS, root, I_BASS, V_BASS))
    return evs


def arp_events(bar):
    """Square arpeggio — root-3rd-5th repeating in 16th notes (every row).
    16 rows -> the 3-note cycle wraps; gives the rolling chiptune shimmer."""
    _, tones = CHORDS[bar % 4]
    evs = []
    for r in range(ROWS_BAR):
        note = tones[r % 3]
        evs.append(mc.event(r, CH_ARP, note, I_ARP, V_ARP))
    return evs


def perc_events(bar):
    """Noise percussion. Hat on every 8th (every 2 rows, quiet). Snare (loud
    noise burst) on beats 2 and 4 (rows 4 and 12). Pitch barely matters for
    white noise, but keep hat/snare distinct. Snare replaces the hat on its
    rows."""
    evs = []
    for k in range(8):                       # hats on every 8th
        row = k * 2
        if k in (2, 6):                      # rows 4 and 12 = beats 2 & 4 -> snare
            evs.append(mc.event(row, CH_PERC, 50, I_PERC, V_SNARE))
        else:
            evs.append(mc.event(row, CH_PERC, 72, I_PERC, V_HAT))
    return evs


def build_song():
    instruments = build_instruments()

    n_loops = 4                              # 4 chords x 4 = 16 bars
    # One pattern per chord (4 patterns).
    patterns = []
    for bar in range(4):
        evs = []
        evs += lead_events(bar)
        evs += bass_events(bar)
        evs += arp_events(bar)
        evs += perc_events(bar)
        patterns.append(mc.pattern(ROWS_BAR, evs))

    # Add clean key-offs on the LAST row of a final copy of the G pattern so
    # the trailing voices release cleanly at song end. We make a 5th pattern =
    # the G bar plus key-offs on its last row, and put it at the very end.
    last_evs = []
    last_evs += lead_events(3)
    last_evs += bass_events(3)
    last_evs += arp_events(3)
    last_evs += perc_events(3)
    last_row = ROWS_BAR - 1
    last_evs.append(mc.event(last_row, CH_LEAD, 0, I_LEAD, 0))
    last_evs.append(mc.event(last_row, CH_BASS, 0, I_BASS, 0))
    last_evs.append(mc.event(last_row, CH_ARP,  0, I_ARP,  0))
    patterns.append(mc.pattern(ROWS_BAR, last_evs))   # pattern index 4
    PAT_G_FINAL = 4

    # ORDER: Am F C G  three times, then Am F C G_final = 16 bars.
    order = []
    for loop in range(n_loops):
        if loop == n_loops - 1:
            order += [0, 1, 2, PAT_G_FINAL]
        else:
            order += [0, 1, 2, 3]

    body = mc.build_music_body(
        tempo_bpm=TEMPO, rows_per_beat=RPB, num_channels=NUM_CH,
        instruments=instruments, patterns=patterns, order=order,
        master_volume=225,
    )
    return body


def main():
    body = build_song()

    header, cbody = mc.build_music_quipu(
        body, out_rate=OUT_RATE,
        title="| Colegio Invisible — Chiptune (Am i-VI-III-VII) |",
        tone=sound.TONE_AI,
    )
    container_bytes = header + cbody
    container_size = len(container_bytes)

    # Persist the container bytes.
    bin_path = os.path.join(HERE, "chiptune.sound.bin")
    with open(bin_path, "wb") as f:
        f.write(container_bytes)

    # Read back to confirm the container + module round-trip, then render.
    rec = mc.read_music_quipu(header, cbody)
    assert rec["type"] == "sound"
    assert rec["codec"] == mc.CODEC_MUSIC
    assert rec["body"] == body
    mod = rec["module"]

    audio = render = mc.render_music(rec["body"], out_rate=OUT_RATE)

    # Determinism check.
    audio2 = mc.render_music(rec["body"], out_rate=OUT_RATE)
    deterministic = bool(np.array_equal(audio, audio2))

    wav_path = os.path.join(HERE, "chiptune.wav")
    mc.write_wav(wav_path, audio, OUT_RATE)

    # Metrics.
    duration_s = len(audio) / OUT_RATE
    peak = float(np.max(np.abs(audio))) if audio.size else 0.0
    rms = float(np.sqrt(np.mean(audio.astype(np.float64) ** 2)))

    kinds = [("synth" if i["kind"] == mc.KIND_SYNTH else "sample")
             for i in mod["instruments"]]
    all_synth = all(i["kind"] == mc.KIND_SYNTH for i in mod["instruments"])

    print("=== Colegio Invisible — CHIPTUNE (0x07 sound, codec 0x20 music) ===")
    print(f"  module body bytes   : {len(body)}")
    print(f"  container size bytes : {container_size}"
          f"  (header {len(header)} + body {len(cbody)})")
    print(f"  codec               : 0x{rec['codec']:02x} ({rec['codec_name']})")
    print(f"  sample_rate         : {rec['sample_rate']} Hz")
    print(f"  channels (polyphony): {rec['channels']}")
    print(f"  tempo / rows_per_beat: {mod['tempo_bpm']} BPM / {mod['rows_per_beat']}")
    print(f"  duration_s          : {duration_s:.3f} s "
          f"(hdr {rec['duration_ms']} ms)")
    n_events = sum(len(p["events"]) for p in mod["patterns"])
    print(f"  patterns / order_len: {len(mod['patterns'])} / {len(mod['order'])}")
    print(f"  events (all patterns): {n_events}")
    print(f"  instruments         : "
          f"{[(i['name'], k) for i, k in zip(mod['instruments'], kinds)]}")
    print(f"  uses SYNTH only     : {all_synth} (kind=0 for all voices)")
    print(f"  peak                : {peak:.5f}")
    print(f"  rms                 : {rms:.5f}")
    print(f"  deterministic       : {deterministic}")
    print(f"  container written   : {bin_path}")
    print(f"  WAV written         : {wav_path} ({os.path.getsize(wav_path)} B)")
    print()
    print("  SCORE: A-minor chiptune, 136 BPM, i-VI-III-VII (Am-F-C-G) x4 over "
          "16 bars — thin 25% pulse lead, triangle 8th-note bass, square "
          "16th-note root-3rd-5th arpeggio shimmer, noise hats every 8th with "
          "snare on 2 & 4.")


if __name__ == "__main__":
    main()
