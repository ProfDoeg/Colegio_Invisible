#!/usr/bin/env python
"""amen_song — a mass, rebuilt.

A multi-section boom-bap song built from two CHOIR "Amen" recordings (from a
Mass). Both whole Amens play through (intro / drop / outro); chopped grooves
drive the A / B / A' sections. Key = E minor, ~88 BPM.

Material:
  Amen.wav   ~4.3s, choir sings F#3 -> E3 (descending A-men cadence)
  Amen2.wav  ~4.9s, choir sings around F3 (a semitone above) -> nudged DOWN
             one semitone so both center on E.

Four instruments from the amens + synth drums:
  amen1_WHOLE / amen2_WHOLE  : SAMPLE instruments (kind 1) -> whole recording.
  amen1_SLICED / amen2_SLICED: SLICED instruments (kind 2) -> onset chops.
  drums: kick / snare / hat / sub  (kind 0), de-static settings.
  pad  : a soft synth for the switch-up.

SONG FORM (order list, not one loop):
  INTRO  -> A GROOVE -> B SWITCH-UP -> DROP -> A' -> OUTRO
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
OUT_BIN = os.path.join(HERE, "amen_song.sound.bin")
OUT_WAV = os.path.join(HERE, "amen_song.wav")

RATE = 22050


# ---------------------------------------------------------------------------
# 1) Load + condition the two Amens
# ---------------------------------------------------------------------------
def load_amen(fname, *, semitone_down=False):
    """Load a WAV, mono, resample to RATE, normalize to [-1,1]. Optionally
    pitch DOWN one semitone (lengthen the array by 2**(1/12))."""
    sr, x = wavio.read(os.path.join(SAMP, fname))
    x = x.astype(np.float64)
    if x.ndim > 1:                          # to mono
        x = x.mean(axis=1)
    if sr != RATE:                          # resample to 22050
        x = sig.resample(x, int(round(len(x) * RATE / sr)))
    if semitone_down:                       # nudge DOWN a semitone (stretch)
        x = sig.resample(x, int(len(x) * 2 ** (1 / 12)))
    mx = np.max(np.abs(x)) or 1.0
    x = x / mx
    return x.astype(np.float32)


amen1 = load_amen("Amen.wav")                       # F#3 -> E3
amen2 = load_amen("Amen2.wav", semitone_down=True)  # ~F3 -> nudged to ~E

# int8 PCM for the WHOLE-sample instruments (dusty 8-bit).
amen1_pcm = np.clip(np.round(amen1 * 120.0), -128, 127).astype(np.int8)
amen2_pcm = np.clip(np.round(amen2 * 120.0), -128, 127).astype(np.int8)


# ---------------------------------------------------------------------------
# 2) Onset-chop each amen (spectral-flux peaks, min slice ~0.10 s)
# ---------------------------------------------------------------------------
def onset_slices(x, *, rate=RATE, min_slice_s=0.10, win=1024, hop=256):
    """Spectral-flux onset detection -> list of (start, length) slice regions
    covering the whole clip. Always returns at least one slice."""
    n = len(x)
    min_len = int(min_slice_s * rate)
    # STFT magnitude.
    nfr = max(1, 1 + (n - win) // hop)
    mags = np.empty((nfr, win // 2 + 1), dtype=np.float64)
    w = np.hanning(win).astype(np.float64)
    for i in range(nfr):
        seg = x[i * hop:i * hop + win]
        if len(seg) < win:
            seg = np.pad(seg, (0, win - len(seg)))
        mags[i] = np.abs(np.fft.rfft(seg * w))
    # Positive spectral flux.
    flux = np.zeros(nfr)
    diff = np.diff(mags, axis=0)
    flux[1:] = np.sum(np.maximum(diff, 0.0), axis=1)
    if flux.max() > 0:
        flux = flux / flux.max()
    # Peak-pick: above adaptive threshold + local max.
    thr = np.median(flux) + 0.5 * np.std(flux)
    onsets = [0]
    for i in range(1, nfr - 1):
        if flux[i] > thr and flux[i] >= flux[i - 1] and flux[i] > flux[i + 1]:
            s = i * hop
            if s - onsets[-1] >= min_len:
                onsets.append(s)
    # Build (start, length) covering to clip end; drop a too-short final tail.
    bounds = onsets + [n]
    slices = []
    for a, b in zip(bounds[:-1], bounds[1:]):
        if b - a >= min_len // 2:
            slices.append((int(a), int(b - a)))
    if not slices:
        slices = [(0, n)]
    return slices


sl1 = onset_slices(amen1)
sl2 = onset_slices(amen2)


# ---------------------------------------------------------------------------
# 2b) New sources for the glitch: church bells (173) + fountain water.
#     Built as TIGHT chop KITS — short fragments, each trimmed to start AT its
#     transient — which (a) kills the "sampling late" feel and (b) keeps the
#     stored PCM tiny (only the fragments we actually chop, not whole clips).
# ---------------------------------------------------------------------------
def load_src(fname, *, start_s=0.0, dur_s=None):
    """Load a WAV, mono, segment [start_s, start_s+dur_s], resample to RATE,
    normalize to [-1,1]."""
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


def _flux_onsets(x, *, win=1024, hop=256):
    """Spectral-flux onset positions (samples) with their flux strength,
    strongest first."""
    n = len(x)
    nfr = max(1, 1 + (n - win) // hop)
    w = np.hanning(win).astype(np.float64)
    mags = np.empty((nfr, win // 2 + 1))
    for i in range(nfr):
        seg = x[i * hop:i * hop + win]
        if len(seg) < win:
            seg = np.pad(seg, (0, win - len(seg)))
        mags[i] = np.abs(np.fft.rfft(seg * w))
    flux = np.zeros(nfr)
    flux[1:] = np.sum(np.maximum(np.diff(mags, axis=0), 0.0), axis=1)
    if flux.max() > 0:
        flux /= flux.max()
    thr = np.median(flux) + 0.6 * np.std(flux)
    peaks = []
    for i in range(1, nfr - 1):
        if flux[i] > thr and flux[i] >= flux[i - 1] and flux[i] > flux[i + 1]:
            peaks.append((i * hop, float(flux[i])))
    if not peaks:
        peaks = [(0, 1.0)]
    peaks.sort(key=lambda t: -t[1])
    return peaks


def _tighten(seg, *, trim_thresh=0.14, fade_in_ms=1.2, fade_out_frac=0.30):
    """Trim leading low-energy so the fragment starts AT its punch, then fade."""
    ae = np.abs(seg)
    if ae.max() <= 0:
        return seg
    k = int(np.argmax(ae > trim_thresh * ae.max()))   # first sample above thresh
    seg = seg[k:]
    if len(seg) < 4:
        return seg
    fi = min(len(seg), int(fade_in_ms * RATE / 1000.0))
    if fi > 1:
        seg[:fi] *= np.linspace(0.0, 1.0, fi, dtype=np.float32)
    fo = max(1, int(len(seg) * fade_out_frac))
    seg[-fo:] *= np.linspace(1.0, 0.0, fo, dtype=np.float32)
    return seg


def onset_kit(x, *, n_frags=10, frag_ms=170, pre_ms=5, gain=120.0,
              trim_thresh=0.14):
    """A TIGHT transient kit: take the strongest onsets, cut a short fragment at
    each (starting a hair early, then trimmed to the transient), fade, quantize
    to int8, concatenate. Returns (pcm_int8, slices[(start,len)...])."""
    frag = int(frag_ms * RATE / 1000.0)
    pre = int(pre_ms * RATE / 1000.0)
    onsets = _flux_onsets(x)[:n_frags]
    onsets.sort(key=lambda t: t[0])            # back to time order
    pcm = []
    slices = []
    cur = 0
    for pos, _str in onsets:
        a = max(0, pos - pre)
        seg = np.array(x[a:a + frag], dtype=np.float32)
        if len(seg) < 8:
            continue
        seg = _tighten(seg, trim_thresh=trim_thresh)
        q = np.clip(np.round(seg * gain), -128, 127).astype(np.int8)
        slices.append((cur, len(q)))
        pcm.append(q)
        cur += len(q)
    if not pcm:
        pcm = [np.zeros(frag, dtype=np.int8)]
        slices = [(0, frag)]
    return np.concatenate(pcm), slices


def grain_kit(x, *, n_grains=14, grain_ms=110, fade_ms=7, gain=120.0,
              span_s=None):
    """A granular kit for a textural source (water): evenly sample short grains
    across the clip, fade both ends (no transient to align), quantize, concat.
    Fast-chopping these = a babbling computerized wash."""
    glen = int(grain_ms * RATE / 1000.0)
    span = len(x) if span_s is None else min(len(x), int(span_s * RATE))
    starts = np.linspace(0, max(1, span - glen - 1), n_grains).astype(int)
    fade = max(1, int(fade_ms * RATE / 1000.0))
    win = np.ones(glen, dtype=np.float32)
    win[:fade] = np.linspace(0.0, 1.0, fade)
    win[-fade:] = np.linspace(1.0, 0.0, fade)
    pcm = []
    slices = []
    cur = 0
    for s in starts:
        seg = np.array(x[s:s + glen], dtype=np.float32)
        if len(seg) < glen:
            seg = np.pad(seg, (0, glen - len(seg)))
        seg = seg * win
        q = np.clip(np.round(seg * gain), -128, 127).astype(np.int8)
        slices.append((cur, len(q)))
        pcm.append(q)
        cur += len(q)
    return np.concatenate(pcm), slices


# Build the kits. Bells: 12 sharp strikes from the first ~12 s of 173. Water: 16
# grains spread across a babbly minute of the fountain.
bells_src = load_src("173.wav", start_s=0.0, dur_s=12.0)
water_src = load_src("fairy_fountain.wav", start_s=6.0, dur_s=60.0)

amen1_kit_pcm, amen1_kit_sl = onset_kit(amen1, n_frags=10, frag_ms=175, trim_thresh=0.10)
amen2_kit_pcm, amen2_kit_sl = onset_kit(amen2, n_frags=10, frag_ms=175, trim_thresh=0.10)
bell_kit_pcm,  bell_kit_sl  = onset_kit(bells_src, n_frags=12, frag_ms=160, trim_thresh=0.18)
water_kit_pcm, water_kit_sl = grain_kit(water_src, n_grains=16, grain_ms=105, span_s=54.0)

NB, NA1, NA2, NW = len(bell_kit_sl), len(amen1_kit_sl), len(amen2_kit_sl), len(water_kit_sl)


# ---------------------------------------------------------------------------
# 3) Instruments
# ---------------------------------------------------------------------------
# WHOLE samples: triggering a note plays the ENTIRE recording (base_note=60).
amen1_whole = M.sample_instrument(
    "amen1_WHOLE", amen1_pcm, srate=RATE, base_note=60, bits=8,
    volume=235, attack_ms=4, decay_ms=0, sustain_level=255, release_ms=120,
)
amen2_whole = M.sample_instrument(
    "amen2_WHOLE", amen2_pcm, srate=RATE, base_note=60, bits=8,
    volume=235, attack_ms=4, decay_ms=0, sustain_level=255, release_ms=120,
)
# SLICED choppers: event note = slice_index + 1, native pitch one-shots.
amen1_sliced = M.sliced_instrument(
    "amen1_SLICED", amen1_pcm, sl1, srate=RATE, base_note=60, bits=8,
    volume=230, attack_ms=2, release_ms=20,
)
amen2_sliced = M.sliced_instrument(
    "amen2_SLICED", amen2_pcm, sl2, srate=RATE, base_note=60, bits=8,
    volume=230, attack_ms=2, release_ms=20,
)

# Drums — EXACT de-static settings.
kick = M.synth_instrument("kick", M.WAVE_SINE, volume=255,
                          attack_ms=1, decay_ms=110, sustain_level=0, release_ms=40)
snare = M.synth_instrument("snare", M.WAVE_NOISE, volume=200, duty=150,
                           attack_ms=1, decay_ms=55, sustain_level=0, release_ms=22)
hat = M.synth_instrument("hat", M.WAVE_NOISE, volume=58, duty=205,
                         attack_ms=0, decay_ms=13, sustain_level=0, release_ms=5)
sub = M.synth_instrument("sub", M.WAVE_SINE, volume=255,
                         attack_ms=3, decay_ms=40, sustain_level=205, release_ms=70)

# Pad for melodic color in the switch-up (warm triangle, E-minor chord tones).
pad = M.synth_instrument("pad", M.WAVE_TRIANGLE, volume=95,
                         attack_ms=40, decay_ms=120, sustain_level=150, release_ms=260)

# TIGHT chop kits for the glitch sections — hard 0 ms attack (snaps on the grid,
# no "late"), short release. amen1/amen2 = the choir identity; bells = the sharp
# metallic transient that anchors the grid; water = granular wash.
amen1_tight = M.sliced_instrument(
    "amen1_tight", amen1_kit_pcm, amen1_kit_sl, srate=RATE, base_note=60, bits=8,
    volume=235, attack_ms=0, decay_ms=0, sustain_level=255, release_ms=8)
amen2_tight = M.sliced_instrument(
    "amen2_tight", amen2_kit_pcm, amen2_kit_sl, srate=RATE, base_note=60, bits=8,
    volume=235, attack_ms=0, decay_ms=0, sustain_level=255, release_ms=8)
bells = M.sliced_instrument(
    "bells", bell_kit_pcm, bell_kit_sl, srate=RATE, base_note=60, bits=8,
    volume=42, attack_ms=0, decay_ms=0, sustain_level=255, release_ms=16)
water = M.sliced_instrument(
    "water", water_kit_pcm, water_kit_sl, srate=RATE, base_note=60, bits=8,
    volume=150, attack_ms=0, decay_ms=0, sustain_level=255, release_ms=10)

instruments = [
    amen1_whole, amen2_whole, amen1_sliced, amen2_sliced,
    kick, snare, hat, sub, pad,
    amen1_tight, amen2_tight, bells, water,
]
(A1W, A2W, A1S, A2S, KICK, SNARE, HAT, SUB, PAD,
 A1T, A2T, BELL, WATER) = range(13)


# ---------------------------------------------------------------------------
# 4) Channels & grid
# ---------------------------------------------------------------------------
# Keep whole-samples / chops / drums on separate channels so they never collide.
CH_KICK, CH_SNARE, CH_HAT, CH_SUB = 0, 1, 2, 3
CH_CHOP_A, CH_CHOP_B = 4, 5          # sliced chops (two voices for overlap)
CH_WHOLE = 6                          # whole-amen voice (rings full length)
CH_PAD1, CH_PAD2, CH_PAD3 = 7, 8, 9   # pad chord (3 notes)
# Extra voices used ONLY by the dense glitch sections (the rest of the song
# never touches these, so it renders identically).
CH_BELL1, CH_BELL2 = 10, 11           # church-bell transients
CH_WATER1, CH_WATER2 = 12, 13         # fountain granular wash
CH_CHOP_C, CH_CHOP_D = 14, 15         # extra chop voices for ratchet overlap
NUM_CH = 16

TEMPO = 88
RPB = 4             # COARSE authoring grid: 4 rows/beat = 16th notes
BAR = 16            # 16th grid -> 16 rows / bar
# Row map in a bar: 0=1  2=1&  4=2  6=2&  8=3  10=3&  12=4  14=4&

# --- Fine grid for the GLITCH subdivision ---------------------------------
# Everything is AUTHORED on the coarse 16th grid above, then rescaled x SCALE
# onto a finer grid so the glitch fills can stutter far faster than a 16th note.
# SCALE=12 -> rows_per_beat 48: 16th=12 rows, 32nd=6, 64th=3, and a 1-row ratchet
# = a 192nd note (~14 ms, ~70 hits/sec). The rescale is exactly audio-preserving
# (samples_per_row_fine = samples_per_row_coarse / SCALE, so row*SCALE lands on
# the identical sample). This needs the v2 (u16-row) module format: the 4-bar
# patterns are 64*12 = 768 rows, well past the old u8 limit.
SCALE = 12
RPB_FINE = RPB * SCALE          # = 48

# E-minor sub roots (low octave): E1=28, B0=23, C1=24.
E1, B0, C1 = 28, 24, 23  # (B0=23 per direction; C1=24)
# Pad chord tones (E minor triad up an octave): E3=52, G3=55, B3=59.
PAD_E, PAD_G, PAD_B = 52, 55, 59


def drum_basic(ev, b, *, ghost=False, busy_hats=False, hat_vel=(65, 95)):
    """Standard boom-bap drum bar starting at absolute row b."""
    # Kick on 1 (row 0) and the '&' of 2 (row 6).
    ev.append(M.event(b + 0, CH_KICK, 36, KICK, 255))
    ev.append(M.event(b + 6, CH_KICK, 36, KICK, 235))
    if ghost:
        ev.append(M.event(b + 11, CH_KICK, 36, KICK, 195))
    # Snare on 2 & 4 (rows 4, 12).
    for sr in (4, 12):
        ev.append(M.event(b + sr, CH_SNARE, 64, SNARE, 220))
    # Hats: 8ths normally, 16ths when busy.
    step = 1 if busy_hats else 2
    for hr in range(0, BAR, step):
        off, on = hat_vel
        vel = on if (hr % 4 == 2) else off
        if busy_hats and (hr % 2 == 1):
            vel = max(40, off - 18)        # quieter in-between 16th
        ev.append(M.event(b + hr, CH_HAT, 70, HAT, vel))


def sub_bar(ev, b, roots):
    """roots = list of (row, midi). Adds key-off before the next downbeat."""
    for r, m in roots:
        ev.append(M.event(b + r, CH_SUB, m, SUB, 240))
    ev.append(M.event(b + 15, CH_SUB, 0, SUB, 0))


def chop_ev(row, ch, slice_idx, inst, vel=230):
    return M.event(row, ch, slice_idx + 1, inst, vel)


def chop_off(row, ch, inst):
    return M.event(row, ch, 0, inst, 0)


# ---------------------------------------------------------------------------
# 5) PATTERNS
# ---------------------------------------------------------------------------
# Each pattern = 2 bars = 32 rows, except whole-sample sections sized to ring.

n1_sl = len(sl1)
n2_sl = len(sl2)


def clamp1(i):
    return max(0, min(i, n1_sl - 1))


def clamp2(i):
    return max(0, min(i, n2_sl - 1))


# ---- INTRO (4 bars = 64 rows): whole Amen1 rings; soft sub + pad only. ----
def pat_intro():
    ev = []
    # Trigger the WHOLE Amen1 at row 0 of channel 6; let it ring (no re-trigger).
    ev.append(M.event(0, CH_WHOLE, 60, A1W, 235))   # base_note=60 -> native pitch
    # Soft sustained sub root (E1) under it, moving to B0 halfway.
    ev.append(M.event(0, CH_SUB, E1, SUB, 150))
    ev.append(M.event(32, CH_SUB, B0, SUB, 140))
    ev.append(M.event(63, CH_SUB, 0, SUB, 0))
    # A gentle pad swell, E-minor, entering on bar 3.
    ev.append(M.event(32, CH_PAD1, PAD_E, PAD, 70))
    ev.append(M.event(32, CH_PAD2, PAD_G, PAD, 60))
    ev.append(M.event(32, CH_PAD3, PAD_B, PAD, 55))
    ev.append(M.event(63, CH_PAD1, 0, PAD, 0))
    ev.append(M.event(63, CH_PAD2, 0, PAD, 0))
    ev.append(M.event(63, CH_PAD3, 0, PAD, 0))
    return M.pattern(64, ev)


# ---- A GROOVE (2-bar pattern, played x4 = 8 bars): full boom-bap + Amen1 chops.
def pat_A():
    ev = []
    for bar in range(2):
        b = bar * BAR
        drum_basic(ev, b, ghost=(bar == 1))
        sub_bar(ev, b, [(0, E1), (6, E1), (8, B0), (14, B0)])
    # Amen1 chop hook (the head-nod). Sequence a few onset slices.
    hook = [
        (2,  clamp1(1)),
        (5,  clamp1(2)),
        (8,  clamp1(3)),
        (11, clamp1(2)),
        (14, clamp1(4)),
        (18, clamp1(1)),
        (21, clamp1(3)),
        (24, clamp1(5)),
        (27, clamp1(2)),
    ]
    for r, sl in hook:
        ev.append(chop_ev(r, CH_CHOP_A, sl, A1S))
    ev.append(chop_off(31, CH_CHOP_A, A1S))
    return M.pattern(32, ev)


# ---- B SWITCH-UP (2-bar pattern, x4 = 8 bars): busier 16th hats, Amen2 chops,
#       pad chord, sub moved. Clearly differs from A. ----
def pat_B():
    ev = []
    for bar in range(2):
        b = bar * BAR
        drum_basic(ev, b, busy_hats=True, ghost=(bar == 0),
                   hat_vel=(55, 90))
        # Sub MOVED: land on C1/B0 motion, syncopated push on the '&'s.
        sub_bar(ev, b, [(0, E1), (3, E1), (8, C1), (10, C1), (12, B0)])
    # Amen2 chops — a DIFFERENT, more syncopated pattern.
    hook = [
        (0,  clamp2(0)),
        (3,  clamp2(2)),
        (6,  clamp2(1)),
        (10, clamp2(3)),
        (13, clamp2(2)),
        (16, clamp2(4)),
        (19, clamp2(1)),
        (22, clamp2(3)),
        (25, clamp2(0)),
        (29, clamp2(2)),
    ]
    for r, sl in hook:
        ev.append(chop_ev(r, CH_CHOP_B, sl, A2S, 225))
    ev.append(chop_off(31, CH_CHOP_B, A2S))
    # Pad chord stabs (E minor) on the downbeats for melodic color.
    for db in (0, 16):
        ev.append(M.event(db, CH_PAD1, PAD_E, PAD, 80))
        ev.append(M.event(db, CH_PAD2, PAD_G, PAD, 70))
        ev.append(M.event(db, CH_PAD3, PAD_B, PAD, 65))
        ev.append(M.event(db + 14, CH_PAD1, 0, PAD, 0))
        ev.append(M.event(db + 14, CH_PAD2, 0, PAD, 0))
        ev.append(M.event(db + 14, CH_PAD3, 0, PAD, 0))
    return M.pattern(32, ev)


# ---- DROP (4 bars = 64 rows): whole Amen2 plays through over a stripped beat.
#       Drums drop out for the first bar, then SLAM back. The climax. ----
def pat_drop():
    ev = []
    # Whole Amen2 rings from the top of the drop.
    ev.append(M.event(0, CH_WHOLE, 60, A2W, 240))
    # Bar 1: drums drop — just a single sub hit (the breath before the slam).
    ev.append(M.event(0, CH_SUB, E1, SUB, 200))
    ev.append(M.event(15, CH_SUB, 0, SUB, 0))
    # Bars 2-4: big stripped beat slams back. Heavy kick+snare, sparse hats.
    for bar in range(1, 4):
        b = bar * BAR
        ev.append(M.event(b + 0, CH_KICK, 36, KICK, 255))
        ev.append(M.event(b + 6, CH_KICK, 36, KICK, 245))
        ev.append(M.event(b + 10, CH_KICK, 36, KICK, 210))
        for sr in (4, 12):
            ev.append(M.event(b + sr, CH_SNARE, 64, SNARE, 235))
        for hr in range(0, BAR, 4):                # sparse quarter hats
            ev.append(M.event(b + hr, CH_HAT, 70, HAT, 70))
        sub_bar(ev, b, [(0, E1), (8, B0)])
    return M.pattern(64, ev)


# ---- A' (2-bar pattern, x4 = 8 bars): return to the groove, FULLER.
#       Adds a second chop voice + ghost-kick swing. ----
def pat_Aprime():
    ev = []
    for bar in range(2):
        b = bar * BAR
        drum_basic(ev, b, ghost=True, hat_vel=(70, 100))
        sub_bar(ev, b, [(0, E1), (6, E1), (8, B0), (11, C1), (14, B0)])
    # Lead Amen1 chops (as in A) ...
    hook = [
        (2,  clamp1(1)), (5,  clamp1(2)), (8,  clamp1(3)),
        (11, clamp1(2)), (14, clamp1(4)),
        (18, clamp1(1)), (21, clamp1(3)), (24, clamp1(5)), (27, clamp1(2)),
    ]
    for r, sl in hook:
        ev.append(chop_ev(r, CH_CHOP_A, sl, A1S))
    ev.append(chop_off(31, CH_CHOP_A, A1S))
    # ... PLUS an answering Amen2 chop voice (fuller than A).
    answer = [(4, clamp2(2)), (12, clamp2(1)), (20, clamp2(3)), (28, clamp2(0))]
    for r, sl in answer:
        ev.append(chop_ev(r, CH_CHOP_B, sl, A2S, 200))
    ev.append(chop_off(31, CH_CHOP_B, A2S))
    return M.pattern(32, ev)


# ---- OUTRO (4 bars = 64 rows): whole Amen1 again, drums thin out, resolve. ----
def pat_outro():
    ev = []
    ev.append(M.event(0, CH_WHOLE, 60, A1W, 230))     # whole Amen1 rings out
    # Bars 1-2: thinning beat (kick on 1, soft snare on 3, light hats).
    for bar in range(2):
        b = bar * BAR
        ev.append(M.event(b + 0, CH_KICK, 36, KICK, 230))
        ev.append(M.event(b + 12, CH_SNARE, 64, SNARE, 170))
        for hr in range(0, BAR, 4):
            ev.append(M.event(b + hr, CH_HAT, 70, HAT, 50))
    # Bars 3-4: drums gone; only the sub + pad resolve to E.
    ev.append(M.event(0, CH_SUB, E1, SUB, 170))
    ev.append(M.event(32, CH_SUB, E1, SUB, 150))
    ev.append(M.event(63, CH_SUB, 0, SUB, 0))
    ev.append(M.event(32, CH_PAD1, PAD_E, PAD, 70))
    ev.append(M.event(32, CH_PAD2, PAD_G, PAD, 55))
    ev.append(M.event(32, CH_PAD3, PAD_B, PAD, 50))
    ev.append(M.event(63, CH_PAD1, 0, PAD, 0))
    ev.append(M.event(63, CH_PAD2, 0, PAD, 0))
    ev.append(M.event(63, CH_PAD3, 0, PAD, 0))
    return M.pattern(64, ev)


# ---------------------------------------------------------------------------
# 5b) GLITCH — rescale to the fine grid + a dense multi-source slap-chop
# ---------------------------------------------------------------------------
# At TWO moments — the A-groove around ~22 s and the FINAL groove near the end —
# the chop hook is replaced with a TOTALLY slap-chopped collage: church bells
# (sharp, immediate — they kill the "late" feel and anchor the grid), the amen
# choir chopped tight, and fountain water as a granular wash. Method: rescale
# every authored (coarse) pattern x SCALE onto the rows_per_beat=48 grid, then
# build the two glitch patterns at 32nd/64th speed collapsing into 1-row ratchet
# walls. (The rest of the song is the untouched, rescaled original.)

def scale_ev(e, f):
    return M.event(e["row"] * f, e["channel"], e["note"], e["instrument"],
                   e["volume"])


def scale_pattern(pat, f):
    return M.pattern(pat["num_rows"] * f, [scale_ev(e, f) for e in pat["events"]])


def beat_only(pat):
    """Drums+sub events only (drop the chop voices) — the beat to glitch over."""
    return [e for e in pat["events"]
            if e["channel"] not in (CH_CHOP_A, CH_CHOP_B)]


def glitch_run(ev, ch, inst, n_slices, start, end, step, *,
               sweep0=0, sweepstep=1, gate=(235, 120), pingpong_ch=None):
    """Fill fine-rows [start, end) with chops every `step` rows. The slice index
    SWEEPS (data-scrub timbre), the velocity cycles through `gate` (robotic
    gating), and hits optionally PING-PONG between two channels so fast
    retriggers overlap instead of only cutting each other."""
    k = 0
    r = start
    while r < end:
        si = (sweep0 + k * sweepstep) % max(1, n_slices)
        vel = gate[k % len(gate)]
        cch = ch if (pingpong_ch is None or k % 2 == 0) else pingpong_ch
        ev.append(chop_ev(r, cch, si, inst, vel))
        r += step
        k += 1


# Fine-grid geometry at RPB_FINE=48: 1 bar = 192 fine rows, a 2-bar groove = 384.
# 16th=12 rows, 32nd=6, 64th=3, a 1-row ratchet = a ~192nd note (~14 ms).
FBAR = RPB_FINE * 4              # 192 fine rows / bar
F2 = FBAR * 2                    # 384 fine rows for a 2-bar groove
S16, S32, S64, RAT = 12, 6, 3, 1


def koff(ev, chans):
    for ch, inst in chans:
        ev.append(chop_off(F2 - 1, ch, inst))


def glitch_chops_A(nb, na1, nw):
    """~22 s slap-chop. BELLS lay a tight, immediate grid (the snap that kills the
    'late' feel); AMEN1 chops are the choir identity, ping-ponging; WATER grains
    wash the gaps. Everything tightens 16th -> 32nd -> 64th -> a ratchet wall."""
    ev = []
    # NO BELLS here — just the WATER (below) for texture under the amen chops.
    # AMEN1 tight — the choir, ping-pong A/C, sweeping syllables.
    glitch_run(ev, CH_CHOP_A, A1T, na1,   0,  96, S16, sweep0=1, sweepstep=2, gate=(235, 160), pingpong_ch=CH_CHOP_C)
    glitch_run(ev, CH_CHOP_A, A1T, na1,  96, 192, S32, sweep0=2, sweepstep=3, gate=(230, 150, 195), pingpong_ch=CH_CHOP_C)
    glitch_run(ev, CH_CHOP_A, A1T, na1, 192, 336, S32, sweep0=0, sweepstep=2, gate=(235, 160), pingpong_ch=CH_CHOP_C)
    glitch_run(ev, CH_CHOP_A, A1T, na1, 336, 384, S64, sweep0=3, sweepstep=1, gate=(240, 185))
    # WATER — granular wash, low, ratchets under the wall.
    glitch_run(ev, CH_WATER1, WATER, nw,   0, 192, S32, sweep0=0, sweepstep=3, gate=(150, 110))
    glitch_run(ev, CH_WATER1, WATER, nw, 192, 360, S32, sweep0=2, sweepstep=2, gate=(160, 120, 140))
    glitch_run(ev, CH_WATER2, WATER, nw, 360, 384, RAT, sweep0=1, sweepstep=2, gate=(150, 120))
    koff(ev, [(CH_CHOP_A, A1T), (CH_CHOP_C, A1T),
              (CH_WATER1, WATER), (CH_WATER2, WATER)])
    return ev


def glitch_chops_Aprime(nb, na1, na2, nw):
    """The end — TOTALLY slap-chopped. Both amens machine-gun, bells double-time,
    water everywhere, all collapsing into a full ratchet WALL (bells + amen1 +
    amen2 + water at 1-row) before the outro resolves."""
    ev = []
    # BELLS — quiet, bitty, COMPLEX two-voice interplay throughout, then a brief
    # SMASH at the final wall (louder only relative to the now-quiet filigree).
    glitch_run(ev, CH_BELL1, BELL, nb,   0, 192, S32, sweep0=0, sweepstep=2, gate=(94, 68, 110))
    glitch_run(ev, CH_BELL2, BELL, nb,   5, 192, S64, sweep0=4, sweepstep=3, gate=(78, 58, 100, 70))
    glitch_run(ev, CH_BELL1, BELL, nb, 192, 336, S32, sweep0=1, sweepstep=2, gate=(100, 74, 116, 86))
    glitch_run(ev, CH_BELL2, BELL, nb, 240, 336, S64, sweep0=2, sweepstep=3, gate=(88, 66, 104))
    glitch_run(ev, CH_BELL1, BELL, nb, 336, 384, RAT, sweep0=0, sweepstep=1, gate=(188, 208, 168))  # SMASH
    # AMEN1 + AMEN2 machine-guns, interleaved.
    glitch_run(ev, CH_CHOP_A, A1T, na1,   0, 192, S32, sweep0=1, sweepstep=2, gate=(235, 160), pingpong_ch=CH_CHOP_C)
    glitch_run(ev, CH_CHOP_B, A2T, na2,   3, 192, S32, sweep0=0, sweepstep=2, gate=(220, 150), pingpong_ch=CH_CHOP_D)
    glitch_run(ev, CH_CHOP_A, A1T, na1, 192, 336, S64, sweep0=2, sweepstep=3, gate=(235, 165))
    glitch_run(ev, CH_CHOP_B, A2T, na2, 195, 336, S64, sweep0=1, sweepstep=2, gate=(220, 150))
    glitch_run(ev, CH_CHOP_A, A1T, na1, 336, 384, RAT, sweep0=2, sweepstep=1, gate=(240, 200))
    glitch_run(ev, CH_CHOP_B, A2T, na2, 337, 384, RAT, sweep0=1, sweepstep=2, gate=(225, 185))
    # WATER everywhere, ratchet wall at the very end.
    glitch_run(ev, CH_WATER1, WATER, nw,   0, 192, S32, sweep0=0, sweepstep=3, gate=(155, 115, 135))
    glitch_run(ev, CH_WATER2, WATER, nw, 192, 360, S32, sweep0=2, sweepstep=2, gate=(155, 120))
    glitch_run(ev, CH_WATER1, WATER, nw, 360, 384, RAT, sweep0=1, sweepstep=2, gate=(150, 120))
    koff(ev, [(CH_BELL1, BELL), (CH_BELL2, BELL), (CH_CHOP_A, A1T), (CH_CHOP_C, A1T),
              (CH_CHOP_B, A2T), (CH_CHOP_D, A2T), (CH_WATER1, WATER), (CH_WATER2, WATER)])
    return ev


# Glitch groove patterns: the rescaled beat (drums+sub) + the dense chop collage.
pat_A_glitch = M.pattern(
    F2, [scale_ev(e, SCALE) for e in beat_only(pat_A())]
        + glitch_chops_A(NB, NA1, NW))
pat_Aprime_glitch = M.pattern(
    F2, [scale_ev(e, SCALE) for e in beat_only(pat_Aprime())]
        + glitch_chops_Aprime(NB, NA1, NA2, NW))


patterns = [
    scale_pattern(pat_intro(),  SCALE),   # 0 INTRO
    scale_pattern(pat_A(),      SCALE),   # 1 A_GROOVE (clean)
    scale_pattern(pat_B(),      SCALE),   # 2 B_SWITCHUP
    scale_pattern(pat_drop(),   SCALE),   # 3 DROP
    scale_pattern(pat_Aprime(), SCALE),   # 4 A_PRIME (clean)
    scale_pattern(pat_outro(),  SCALE),   # 5 OUTRO
    pat_A_glitch,                          # 6 A_GROOVE (GLITCH ~22 s)
    pat_Aprime_glitch,                     # 7 A_PRIME (GLITCH, final groove)
]
PAT_NAMES = ["INTRO", "A_GROOVE", "B_SWITCHUP", "DROP", "A_PRIME", "OUTRO",
             "A_GLITCH", "A'_GLITCH"]

# ORDER: the same arrangement, but the A-groove instance at ~22 s and the FINAL
# A' groove now use the GLITCH variants (the computerized slap-chop).
#   INTRO  A  A  A-GLITCH  A   B B B B   DROP   A' A' A'  A'-GLITCH   OUTRO
order = [0, 1, 1, 6, 1, 2, 2, 2, 2, 3, 4, 4, 4, 7, 5]

body = M.build_music_body(
    tempo_bpm=TEMPO, rows_per_beat=RPB_FINE, num_channels=NUM_CH,
    instruments=instruments, patterns=patterns, order=order,
    master_volume=200,
)

header, cbody = M.build_music_quipu(
    body, out_rate=RATE, title="| amen — a mass, rebuilt |", tone=0xff,
)

with open(OUT_BIN, "wb") as f:
    f.write(header + cbody)

audio = M.render_music(body, RATE)
M.write_wav(OUT_WAV, audio, RATE)


# ---------------------------------------------------------------------------
# 6) Report
# ---------------------------------------------------------------------------
container_size = len(header) + len(cbody)
knots_80 = -(-container_size // 80)            # ceil: <=80-B OP_RETURN knots
strands = -(-knots_80 // 25)                   # ceil: 25 knots / strand (cord)
dur_s = len(audio) / RATE
peak = float(np.max(np.abs(audio)))
rms = float(np.sqrt(np.mean(audio.astype(np.float64) ** 2)))

# Verify both whole-samples are triggered (scan all ordered events).
trig_a1w = trig_a2w = 0
for pidx in order:
    for e in patterns[pidx]["events"]:
        if e["note"] != 0 and e["instrument"] == A1W:
            trig_a1w += 1
        if e["note"] != 0 and e["instrument"] == A2W:
            trig_a2w += 1

print("=" * 60)
print("  amen — a mass, rebuilt   (E minor, %d BPM)" % TEMPO)
print("=" * 60)
print(f"  duration_s        : {dur_s:.2f} s")
print(f"  samples           : {len(audio)} @ {RATE} Hz")
print(f"  peak              : {peak:.4f}   rms : {rms:.4f}")
print(f"  master_volume     : 200  (codec soft-limits to 0.9)")
print(f"  module_body       : {len(body)} B")
print(f"  container (hdr+body): {container_size} B "
      f"(header {len(header)} + body {len(cbody)})")
print(f"  on-chain          : {knots_80} knots / {strands} strands "
      f"(<=80-B OP_RETURN/knot, 25 knots/strand)")
print(f"  channels          : {NUM_CH}")
print(f"  instruments       : {[i['name'] for i in instruments]}")
print(f"  Amen1 onset slices: {n1_sl}   Amen2 onset slices: {n2_sl}")
print(f"  patterns(rows)    : "
      f"{[(PAT_NAMES[i], patterns[i]['num_rows']) for i in range(len(patterns))]}")
print(f"  order (indices)   : {order}")
print(f"  section sequence  : {' -> '.join(PAT_NAMES[i] for i in order)}")
print(f"  amen1_WHOLE triggers: {trig_a1w}   amen2_WHOLE triggers: {trig_a2w}")
both = trig_a1w >= 1 and trig_a2w >= 1
print(f"  BOTH whole samples play through: {both}  "
      f"(Amen1 in INTRO+OUTRO, Amen2 in DROP)")
print(f"  bin : {OUT_BIN} ({os.path.getsize(OUT_BIN)} B)")
print(f"  wav : {OUT_WAV} ({os.path.getsize(OUT_WAV)} B)")
