#!/usr/bin/env python
"""claustro — an ambient showcase for the quipu music codec (0x07 / codec 0x20).

The OTHER face of these codecs from the boom-bap amen_song: slow, consonant,
"easier on the nervous system" — yet harmonically rich and compositionally
developed. No drums, no bells. It exercises all three instrument KINDS together:

  synth  (0): a bass drone, a warm triangle pad chord, a high sine shimmer, a lead.
  sample (1): a LOOPED 16-bit vowel from the Mass choir -> an endless vocal pad
              (one held syllable, sustain-looped, pitched to a low fifth pedal).
  sliced (2): soft 8-bit fountain-water grains -> a gentle babbling texture bed.

plus per-instrument BIT DEPTH (16-bit warm choir beside 8-bit lean water), a
sustain LOOP, long ADSR swells, polyphonic extended-jazz harmony, and a 5-section
arc where layers enter and recede. Key D major, 60 BPM.

  INTRO (drone + water)            ->
  A     (pad chords: D Bm G A)     ->
  B     (+ lead motif, + choir pedal; D F#m G A) ->
  C     (fullest; D Bm Em A)       ->
  OUTRO (resolve to D, fade)
"""
import os
import sys

import numpy as np
import scipy.io.wavfile as wavio
import scipy.signal as sig

HERE = "/Users/anthony/Documents/taller/Colegio_Invisible/working/music"
sys.path.insert(0, "/Users/anthony/Documents/taller/Colegio_Invisible/canonical")
sys.path.insert(0, HERE)

import music_codec as M
import sound

SAMP = os.path.join(HERE, "samples")
MASS = "--mass" in sys.argv          # add a Mass choral bloom under C
REFS = "--refs" in sys.argv          # BUILD-BY-REFERENCE: choir/voice2/water resolve
if REFS:                             #   from their own sound quipus (Mass stays embedded)
    MASS = True
_stem = "claustro_refs" if REFS else ("claustro_mass" if MASS else "claustro")
OUT_BIN = os.path.join(HERE, _stem + ".sound.bin")
OUT_WAV = os.path.join(HERE, _stem + ".wav")
RATE = 22050

# 32-byte placeholders for the referenced source quipus; the consolidated-diamond
# build backfills these (size-preservingly) with the real sibling root txids.
def _placeholder(pid):
    return (b"QREF:" + pid.encode()).ljust(32, b"\x00")[:32]
AMEN_PH  = _placeholder("amen")
AMEN2_PH = _placeholder("amen2")
FAIRY_PH = _placeholder("fairy_spring")


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
def load_mono(fname, *, start_s=0.0, dur_s=None):
    sr, x = wavio.read(os.path.join(SAMP, fname))
    x = x.astype(np.float64)
    if x.ndim > 1:
        x = x.mean(axis=1)
    a = int(start_s * sr)
    b = len(x) if dur_s is None else min(len(x), a + int(dur_s * sr))
    x = x[a:b]
    if sr != RATE:
        x = sig.resample(x, int(round(len(x) * RATE / sr)))
    mx = np.max(np.abs(x)) or 1.0
    return (x / mx).astype(np.float32)


def nearest_zero_up(x, i):
    """Nearest rising zero-crossing to index i (clean loop point -> no click)."""
    i = int(np.clip(i, 1, len(x) - 2))
    for d in range(2200):
        for j in (i - d, i + d):
            if 1 <= j < len(x) and x[j - 1] <= 0.0 < x[j]:
                return j
    return i


def detect_midi(x, fmin=70, fmax=500):
    """Rough pitch (autocorrelation) -> nearest MIDI note, to tune the loop."""
    x = x - x.mean()
    if len(x) < 256:
        return 52
    c = np.correlate(x, x, mode="full")[len(x) - 1:]
    lo, hi = int(RATE / fmax), int(RATE / fmin)
    seg = c[lo:hi]
    if len(seg) == 0:
        return 52
    lag = lo + int(np.argmax(seg))
    return int(round(69 + 12 * np.log2((RATE / lag) / 440.0)))


# --- Choir vocal pad: a sustained vowel from the Mass "amen", sustain-looped. ---
amen = load_mono("Amen.wav")
seg_a = int(0.8 * RATE)
seg_b = int(min(len(amen), seg_a + int(1.8 * RATE)))
choir_seg = np.array(amen[seg_a:seg_b], dtype=np.float32)
LOOP_S = nearest_zero_up(choir_seg, int(0.45 * RATE))   # loop in the steady middle
LOOP_E = nearest_zero_up(choir_seg, int(1.35 * RATE))
CHOIR_BASE = detect_midi(choir_seg[LOOP_S:LOOP_E])
choir_pcm16 = np.clip(np.round(choir_seg * 30000.0), -32768, 32767).astype(np.int16)

# --- Water grains: soft, 8-bit, long & gently faded (a wash, not a chop). ---
water = load_mono("fairy_fountain.wav", start_s=10.0, dur_s=50.0)


def grain_kit(x, *, n=12, glen_ms=190, fade_ms=34, gain=110.0):
    glen = int(glen_ms * RATE / 1000)
    fade = int(fade_ms * RATE / 1000)
    starts = np.linspace(0, max(1, len(x) - glen - 1), n).astype(int)
    win = np.ones(glen, dtype=np.float32)
    win[:fade] = np.linspace(0, 1, fade)
    win[-fade:] = np.linspace(1, 0, fade)
    pcm, sl, cur = [], [], 0
    for s in starts:
        g = np.array(x[s:s + glen], dtype=np.float32)
        if len(g) < glen:
            g = np.pad(g, (0, glen - len(g)))
        q = np.clip(np.round(g * win * gain), -128, 127).astype(np.int8)
        sl.append((cur, len(q)))
        pcm.append(q)
        cur += len(q)
    return np.concatenate(pcm), sl


water_pcm, water_sl = grain_kit(water)
NW = len(water_sl)

# --- "amen" INVOCATIONS: pitched one-shot vocal phrases for human harmony. ---
# Amen2 is a second choir colour — the literal "a-men" word, pitched to chord
# tones so the choir intones the harmony beneath/around the lead melody. (Amen's
# vowel, already loaded as the looped pad, is the first colour.)
amen2 = load_mono("Amen2.wav")
V2A = int(0.25 * RATE)
V2B = min(len(amen2), V2A + int(2.4 * RATE))     # the "a-men" articulation
voice2_seg = np.array(amen2[V2A:V2B], dtype=np.float32)
VOICE2_BASE = 53                                  # ~F3 (autocorr's 87 Hz = octave down)
voice2_pcm16 = np.clip(np.round(voice2_seg * 30000.0), -32768, 32767).astype(np.int16)


# ---------------------------------------------------------------------------
# Instruments — synth (0) x4, sample-looped (1), sliced (2)
# ---------------------------------------------------------------------------
bass = M.synth_instrument("bass", M.WAVE_SINE, volume=150,
                          attack_ms=140, decay_ms=300, sustain_level=205, release_ms=900)
pad = M.synth_instrument("pad", M.WAVE_TRIANGLE, volume=92,
                         attack_ms=700, decay_ms=420, sustain_level=190, release_ms=1500)
air = M.synth_instrument("air", M.WAVE_SINE, volume=40,
                         attack_ms=180, decay_ms=320, sustain_level=120, release_ms=720)
lead = M.synth_instrument("lead", M.WAVE_TRIANGLE, volume=84,
                          attack_ms=110, decay_ms=240, sustain_level=175, release_ms=620)
choir = M.sample_instrument("choir", choir_pcm16, srate=RATE, base_note=CHOIR_BASE,
                            bits=16, loop_start=int(LOOP_S), loop_end=int(LOOP_E),
                            volume=120, attack_ms=1500, decay_ms=240,
                            sustain_level=235, release_ms=2000)
water_i = M.sliced_instrument("water", water_pcm, water_sl, srate=RATE, base_note=60,
                              bits=8, volume=72, attack_ms=45, decay_ms=0,
                              sustain_level=255, release_ms=220)
# The second choir colour: a 16-bit one-shot "amen", pitched per chord, blooming
# (long attack) then receding — an invocation, not a drone.
voice2 = M.sample_instrument("voice2", voice2_pcm16, srate=RATE, base_note=VOICE2_BASE,
                             bits=16, loop_start=0, loop_end=0, volume=118,
                             attack_ms=650, decay_ms=320, sustain_level=235, release_ms=950)

instruments = [bass, pad, air, lead, choir, water_i, voice2]
BASS, PAD, AIR, LEAD, CHOIR, WATER, VOICE2 = range(7)

# Second version only: a Mass choral bloom — a sustained chord from the Mass
# recording (its loud ~9-11.5s swell), sustain-looped, pitched to the tonic, with
# a very long attack so it blooms in under the C climax.
MASSI = None
if MASS:
    mass_seg = load_mono("Mass.wav", start_s=8.9, dur_s=2.6)
    MLS = nearest_zero_up(mass_seg, int(0.5 * RATE))
    MLE = nearest_zero_up(mass_seg, int(1.8 * RATE))
    mass_pcm16 = np.clip(np.round(mass_seg * 28000.0), -32768, 32767).astype(np.int16)
    mass = M.sample_instrument("mass", mass_pcm16, srate=RATE, base_note=52, bits=16,
                               loop_start=int(MLS), loop_end=int(MLE), volume=180,
                               attack_ms=3600, decay_ms=700, sustain_level=205,
                               release_ms=2800)
    instruments.append(mass)
    MASSI = 7

# BUILD-BY-REFERENCE: swap choir / voice2 / water for instruments that RESOLVE
# their audio from the amen / amen2 / fairy-spring quipus (no embedded PCM). The
# Mass stays embedded above — both ways demonstrated in one quipu. Same regions,
# loop points, slice geometry, and ADSR/volume as the embedded originals.
if REFS:
    instruments[CHOIR] = M.sample_ref_instrument(
        "choir", AMEN_PH, src_start_ms=800, src_len_ms=1800, srate=RATE,
        base_note=CHOIR_BASE, normalize=True, loop_start=int(LOOP_S), loop_end=int(LOOP_E),
        volume=120, attack_ms=1500, decay_ms=240, sustain_level=235, release_ms=2000)
    instruments[VOICE2] = M.sample_ref_instrument(
        "voice2", AMEN2_PH, src_start_ms=250, src_len_ms=2400, srate=RATE,
        base_note=VOICE2_BASE, normalize=True, volume=118, attack_ms=650,
        decay_ms=320, sustain_level=235, release_ms=950)
    _glen = int(0.190 * RATE)                       # grains into the resolved 40 s spring
    _starts = np.linspace(0, int(40.0 * RATE) - _glen - 1, NW).astype(int)
    instruments[WATER] = M.sliced_ref_instrument(
        "water", FAIRY_PH, [(int(s), _glen) for s in _starts],
        src_start_ms=0, src_len_ms=40000, srate=RATE, base_note=60, normalize=True,
        volume=72, attack_ms=45, decay_ms=0, sustain_level=255, release_ms=220)

# Channels: bass / 4-note pad / 2 shimmer / lead / 2 choir / 2 water.
CH_BASS = 0
CH_PAD = [1, 2, 3, 4]
CH_AIR = [5, 6]
CH_LEAD = 7
CH_CHOIR = [8, 9]
CH_WATER = [10, 11]
CH_VOX = [12, 13]            # pitched "amen" invocations (2 voices for harmony)
CH_MASS = 14                 # Mass choral bloom (second version only)
NUM_CH = 15 if MASS else 14

TEMPO = 60
RPB = 4
BAR = 16            # 16 rows / bar = 4 s/bar at 60 BPM

# Extended-harmony voicings (4 upper notes + bass root). Smooth voice-leading:
# D and Bm share the same upper voicing (only the bass moves).
CH = {
    "D":   ([62, 66, 69, 73], 38),   # Dmaj7    D4 F#4 A4 C#5 / D2
    "Bm":  ([62, 66, 69, 73], 47),   # Bm9      (same top) / B2
    "G":   ([62, 66, 71, 74], 43),   # Gmaj7    D4 F#4 B4 D5 / G2
    "A":   ([64, 66, 69, 73], 45),   # A6/9     E4 F#4 A4 C#5 / A2
    "F#m": ([66, 69, 73, 76], 42),   # F#m7     F#4 A4 C#5 E5 / F#2
    "Em":  ([64, 67, 71, 74], 40),   # Em7      E4 G4 B4 D5 / E2
}
CHOIR_PEDAL = [50, 57]               # D3 + A3 — a low open-fifth vocal pedal


# ---------------------------------------------------------------------------
# Placement helpers
# ---------------------------------------------------------------------------
def place_chord(ev, r0, nbars, name, *, pad_vel=92, with_bass=True, shimmer=True):
    notes, root = CH[name]
    span = nbars * BAR
    for ch, n in zip(CH_PAD, notes):
        ev.append(M.event(r0, ch, n, PAD, pad_vel))
        ev.append(M.event(r0 + span - 1, ch, 0, PAD, 0))
    if with_bass:
        ev.append(M.event(r0, CH_BASS, root, BASS, 150))
        ev.append(M.event(r0 + span - 1, CH_BASS, 0, BASS, 0))
    if shimmer:
        tones = [notes[1] + 12, notes[2] + 12, notes[3] + 12]   # top tones, +1 octave
        k = 0
        for rr in range(r0, r0 + span, 2):                       # 8th-note, 3-against-4
            ev.append(M.event(rr, CH_AIR[k % 2], tones[k % 3], AIR, 46))
            k += 1
        for c in CH_AIR:
            ev.append(M.event(r0 + span - 1, c, 0, AIR, 0))


def place_water(ev, r0, span, *, density=12, vel=60):
    pos = np.linspace(r0 + 1, r0 + span - 2, density).astype(int)
    for i, rr in enumerate(pos):
        ev.append(M.event(int(rr), CH_WATER[i % 2], ((i * 3 + 1) % NW) + 1, WATER, vel))


def choir_pedal(ev, r0, span, vel=(95, 80)):
    for ci, n, v in zip(CH_CHOIR, CHOIR_PEDAL, vel):
        ev.append(M.event(r0, ci, n, CHOIR, v))
        ev.append(M.event(r0 + span - 1, ci, 0, CHOIR, 0))


def lead_note(ev, r, note, dur, vel=95):
    ev.append(M.event(r, CH_LEAD, note, LEAD, vel))
    ev.append(M.event(r + dur, CH_LEAD, 0, LEAD, 0))


def invoke(ev, r0, note, *, vel=92, ch=0, hold=11):
    """A pitched 'amen' bloom on a chord tone (voice2) — a sung invocation."""
    ev.append(M.event(r0, CH_VOX[ch], note, VOICE2, vel))
    ev.append(M.event(r0 + hold, CH_VOX[ch], 0, VOICE2, 0))


# ---------------------------------------------------------------------------
# Lead motifs (contemplative; every note a chord tone of the bar beneath it)
# ---------------------------------------------------------------------------
def melody_B(ev, r0):
    # chords by bar-pair: D(0) F#m(32) G(64) A(96)
    seq = [(2, 69, 11), (15, 66, 9),            # D : A4 -> F#4
           (34, 73, 9), (45, 69, 9),            # F#m: C#5 -> A4
           (66, 71, 11), (79, 74, 7),           # G : B4 -> D5
           (98, 73, 9), (109, 69, 7), (117, 66, 9)]  # A : C#5 A4 F#4
    for r, n, d in seq:
        lead_note(ev, r0 + r, n, d, vel=96)


def melody_C(ev, r0):
    # chords by bar-pair: D(0) Bm(32) Em(64) A(96)
    seq = [(2, 74, 9), (13, 73, 8), (23, 69, 8),    # D : D5 C#5 A4
           (34, 71, 11), (47, 69, 7),               # Bm: B4 A4
           (66, 67, 9), (77, 71, 8), (87, 74, 7),   # Em: G4 B4 D5
           (98, 73, 11), (111, 76, 6), (119, 73, 7)]  # A : C#5 E5 C#5
    for r, n, d in seq:
        lead_note(ev, r0 + r, n, d, vel=100)


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------
def pat_intro():                                   # 4 bars — drone + water wash
    ev = []
    ev.append(M.event(0, CH_BASS, 38, BASS, 105))
    ev.append(M.event(63, CH_BASS, 0, BASS, 0))
    place_water(ev, 0, 64, density=10, vel=52)
    for k, rr in enumerate(range(8, 64, 8)):       # faint air on D/A/F#
        ev.append(M.event(rr, CH_AIR[k % 2], [74, 69, 78][k % 3], AIR, 34))
    return M.pattern(64, ev)


def pat_A():                                       # 8 bars — pad chords enter
    ev = []
    for i, name in enumerate(["D", "Bm", "G", "A"]):
        place_chord(ev, i * 32, 2, name, pad_vel=88)
    place_water(ev, 0, 128, density=14, vel=58)
    return M.pattern(128, ev)


def pat_B():                                       # 8 bars — lead + choir pedal
    ev = []
    for i, name in enumerate(["D", "F#m", "G", "A"]):
        place_chord(ev, i * 32, 2, name, pad_vel=84)
    choir_pedal(ev, 0, 128, vel=(92, 78))
    melody_B(ev, 0)
    # A single sung "amen" per chord, on the chord's 3rd — the choir answers.
    for i, n in enumerate([54, 57, 59, 57]):       # F#3 A3 B3 A3
        invoke(ev, i * 32 + 2, n, vel=86)
    place_water(ev, 0, 128, density=12, vel=54)
    return M.pattern(128, ev)


def pat_C():                                       # 8 bars — fullest
    ev = []
    for i, name in enumerate(["D", "Bm", "Em", "A"]):
        place_chord(ev, i * 32, 2, name, pad_vel=92)
    choir_pedal(ev, 0, 128, vel=(104, 90))
    melody_C(ev, 0)
    # The human peak: a TWO-part sung invocation per chord (a high 5th/3rd, then
    # a lower answer a beat later) — call-and-response with the lead.
    hi = [57, 54, 59, 57]      # A3 F#3 B3 A3
    lo = [54, 50, 55, 52]      # F#3 D3 G3 E3
    for i in range(4):
        invoke(ev, i * 32 + 2, hi[i], vel=92, ch=0)
        invoke(ev, i * 32 + 12, lo[i], vel=82, ch=1)
    if MASS:                                   # a tonic Mass choral bloom under it all
        ev.append(M.event(0, CH_MASS, 50, MASSI, 90))    # D3, swells in (3.6s attack)
        ev.append(M.event(122, CH_MASS, 0, MASSI, 0))    # release rings into the outro
    place_water(ev, 0, 128, density=16, vel=60)
    return M.pattern(128, ev)


def pat_outro():                                   # 4 bars — resolve to D, fade
    ev = []
    place_chord(ev, 0, 4, "D", pad_vel=80)
    choir_pedal(ev, 0, 64, vel=(88, 74))
    invoke(ev, 2, 54, vel=84, ch=0)        # a closing "amen": F#3 (3rd) ...
    invoke(ev, 30, 50, vel=76, ch=1)       # ... resolving to D3 (root)
    place_water(ev, 0, 64, density=8, vel=44)
    return M.pattern(64, ev)


patterns = [pat_intro(), pat_A(), pat_B(), pat_C(), pat_outro()]
PAT_NAMES = ["INTRO", "A", "B", "C", "OUTRO"]
order = [0, 1, 2, 3, 4]

body = M.build_music_body(
    tempo_bpm=TEMPO, rows_per_beat=RPB, num_channels=NUM_CH,
    instruments=instruments, patterns=patterns, order=order, master_volume=180,
)
SONG_TONE = sound.TONE_PLAY if REFS else sound.TONE_AFFECTION
header, cbody = M.build_music_quipu(
    body, out_rate=RATE, title="| claustro · misa |" if MASS else "| claustro |",
    tone=SONG_TONE,
)
with open(OUT_BIN, "wb") as f:
    f.write(header + cbody)


def _make_resolver(mapping):
    """resolver(placeholder_txid) -> (float mono PCM, source_rate) by decoding the
    referenced sound quipu's opus body. On-chain this is colegio_tools.fetch_quipu
    + opus-decode; here we decode the local .sound.bin for each placeholder."""
    import subprocess, tempfile, wave
    cache = {}
    def resolve(txid):
        if txid in cache:
            return cache[txid]
        blob = open(mapping[bytes(txid)], "rb").read()
        hl = sound.sound_header_len(blob)
        obody = sound.read_sound_quipu(blob[:hl], blob[hl:])["body"]
        op = tempfile.mktemp(suffix=".opus"); wv = op[:-5] + ".wav"
        open(op, "wb").write(obody)
        subprocess.run(["opusdec", "--quiet", op, wv], check=True)
        w = wave.open(wv); n, ch, sr = w.getnframes(), w.getnchannels(), w.getframerate()
        pcm = np.frombuffer(w.readframes(n), dtype="<i2").astype(np.float64) / 32768.0
        if ch > 1:
            pcm = pcm.reshape(-1, ch).mean(1)
        w.close(); os.unlink(op); os.unlink(wv)
        cache[txid] = (pcm, sr); return cache[txid]
    return resolve


RESOLVER = _make_resolver({AMEN_PH: "amen.sound.bin", AMEN2_PH: "amen2.sound.bin",
                           FAIRY_PH: "fairy_spring.sound.bin"}) if REFS else None
audio = M.render_music(body, RATE, resolver=RESOLVER)
M.write_wav(OUT_WAV, audio, RATE)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
csize = len(header) + len(cbody)
# Quipu layout (matches quipu_diamond): a KNOT = one OP_RETURN tx, <=80 B payload;
# a STRAND = a chain of up to STRAND_CAP=24 knots (< the 25-ancestor mempool limit).
# A quipu is a diamond: the header strand (strand 0) + N body strands.
body_knots = -(-len(cbody) // 80)
knots = (-(-len(header) // 80) or 1) + body_knots
strands = 1 + -(-body_knots // 24)
dur = len(audio) / RATE
peak = float(np.max(np.abs(audio)))
rms = float(np.sqrt(np.mean(audio.astype(np.float64) ** 2)))
kinds = {0: "synth", 1: "sample", 2: "sliced", 3: "sample_ref", 4: "sliced_ref"}
import tone as _tonemod
print("=" * 60)
print("  claustro%s   (D major, %d BPM, ambient)" % (" · misa [by reference]" if REFS else "", TEMPO))
print("=" * 60)
print(f"  duration_s      : {dur:.2f} s   ({len(audio)} samples @ {RATE} Hz)")
print(f"  peak            : {peak:.4f}   rms : {rms:.4f}   crest : {peak/max(rms,1e-9):.2f}")
print(f"  container       : {csize} B  ->  {knots} knots / {strands} strands")
print(f"  tone            : 0x{SONG_TONE:02x} ({_tonemod.name(SONG_TONE)})")
if REFS:
    print(f"  references      : choir->amen, voice2->amen2, water->fairy_spring "
          f"(placeholders backfilled at inscription); Mass EMBEDDED")
print(f"  choir base_note : {CHOIR_BASE}  loop [{LOOP_S},{LOOP_E}] "
      f"({(LOOP_E-LOOP_S)/RATE:.2f}s) bits 16")
print(f"  voice2 (amen2)  : base_note {VOICE2_BASE}  seg {len(voice2_seg)/RATE:.2f}s "
      f"bits 16  (pitched invocations, B/C/outro)")
print(f"  water grains    : {NW}  bits 8")
if MASS:
    print(f"  mass bloom      : base 52 -> D3, loop [{MLS},{MLE}], bits 16 (sustained under C)")
print(f"  instruments     : " +
      ", ".join(f"{i['name']}({kinds[i['kind']]})" for i in instruments))
print(f"  sections        : {' -> '.join(PAT_NAMES[i] for i in order)}")
print(f"  bin : {OUT_BIN}")
print(f"  wav : {OUT_WAV}")
