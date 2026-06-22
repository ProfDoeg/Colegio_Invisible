"""
voice_codec.py — the numpy DSP behind the 0x07 SOUND type's speech vocoders.

This file is the *DSP layer*. The on-the-wire format is the canonical
audio container defined in `canonical/sound.py` (type 0x07): a keyless,
pure-stdlib envelope carrying a codec byte, sample rate, channels,
duration, a small codec-specific metadata blob (codec_meta), a title,
and an opaque body. This file's job is to PRODUCE and CONSUME that
container's body + codec_meta for the three quipu-native speech codecs:

    codec 0x00  stft    band-limited 8-bit STFT-magnitude vocoder
    codec 0x01  lpc     LPC-10-style vocoder
    codec 0x02  codec2  Codec2-700C (needs libcodec2 + pycodec2)

The opaque standard codecs (0x10 opus / 0x11 mp3 / 0x12 wav / 0x13 flac)
need no DSP here — their bodies are real bitstreams a browser or audio
library decodes directly.

Numpy is LAZY. `import voice_codec` (and, through it, the pure-stdlib
container `sound`) must succeed on a machine with no numpy; the numpy
import happens only when a DSP encode/decode actually runs. So the
container build/read path is always available; only the vocoder math
needs numpy.

Public adapters
---------------
    encode_sound_stft(audio, title='', tone=0)   -> (header, body)  [codec 0x00]
    encode_sound_lpc(audio, title='', tone=0)    -> (header, body)  [codec 0x01]
    encode_sound_codec2(audio, title='', tone=0) -> (header, body)  [codec 0x02]
    decode_sound(header, body) -> (audio, meta)   # reads container, routes
                                                  # to the matching DSP

    (encode_voice / encode_voice_lpc / encode_voice_c2 remain as aliases,
     and decode_voice / decode_voice_lpc / decode_voice_c2 decode a single
     codec each. All produce/consume the canonical sound container.)

STFT codec (0x00) detail
------------------------
Sample rate 8 kHz; 256-sample (32 ms) Hann window; 128-sample hop (50%
overlap → constant-OLA); 32 of 129 magnitude bins kept (0–1 kHz, where
vowel formants and voiced excitation concentrate); 8-bit log-magnitude
quantized per-utterance via global min/max; Griffin–Lim phase recovery
on decode (random phase init, 32 iterations). ~2000 bytes/sec of body.

codec_meta layouts (packed by canonical/sound.py)
-------------------------------------------------
    0x00 stft    n_frames:u16 + g_min:f32 + g_max:f32   (10 bytes, '>Hff')
    0x01 lpc     n_frames:u16                            (2 bytes,  '>H')
    0x02 codec2  n_frames:u16                            (2 bytes,  '>H')

Body layouts
------------
    0x00 stft    n_frames × 32 bytes (one byte per kept bin, row-major)
    0x01 lpc     n_frames × 12 bytes (10 reflection + gain + pitch)
    0x02 codec2  n_frames × 4 bytes  (Codec2 700C packed frames)

Quality character: STFT is "whispered" (random-phase Griffin–Lim is the
known weakness for speech); LPC is robotic/buzzy but intelligible;
Codec2 700C is the leanest. See docs/quipu-types/sound.md.
"""

import os
import sys
import wave

# Reach the canonical container module. voice_codec.py lives one directory
# above canonical/; add it to sys.path so `import sound` resolves to
# canonical/sound.py (the keyless, pure-stdlib audio container). This import
# is numpy-free: it must succeed on a machine with no numpy.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "canonical"))
import sound
from sound import (
    CODEC_STFT, CODEC_LPC, CODEC_CODEC2,
    CODEC_OPUS, CODEC_MP3, CODEC_WAV, CODEC_FLAC,
)


# ---------------------------------------------------------------------------
# Lazy numpy
# ---------------------------------------------------------------------------
# The DSP below needs numpy, but it must stay a LAZY import: merely importing
# voice_codec (and, through it, the pure-stdlib container `sound`) must not
# pull numpy in. We expose the familiar module-global name `np` as a thin
# proxy that imports the real numpy on first attribute access. Every existing
# `np.<attr>` call site therefore triggers the import only when DSP actually
# runs — `import voice_codec` on a numpy-free box still succeeds, and so does
# the container build/read path.

_NUMPY = None


def _np():
    """Lazily import numpy and cache it. DSP functions call this at their top
    (`np = _np()`) so the import only happens when DSP actually runs — never
    at module import time. Keeps `import voice_codec` (and the pure-stdlib
    container `sound`) working on a machine with no numpy."""
    global _NUMPY
    if _NUMPY is None:
        import numpy as _numpy  # local, lazy
        _NUMPY = _numpy
    return _NUMPY


class _LazyNumpy:
    """Proxy exposing the familiar module-global name `np` for the handful of
    DSP call sites that still reference it directly. Resolves to the real
    numpy on first attribute access via _np(), so the import stays lazy."""
    __slots__ = ()

    def __getattr__(self, name):
        return getattr(_np(), name)


np = _LazyNumpy()


# ---------------------------------------------------------------------------
# Codec constants
# ---------------------------------------------------------------------------

SR = 8000          # Hz
FRAME = 256        # samples per analysis window (32 ms at 8 kHz)
HOP = FRAME // 2   # 128 samples (16 ms, 50% overlap for constant-OLA)
K_BINS = 32        # number of low-frequency magnitude bins kept (0 - 1 kHz)
N_BINS_FULL = FRAME // 2 + 1   # 129
GRIFFIN_LIM_ITERS = 32


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hann(n):
    return 0.5 * (1 - np.cos(2 * np.pi * np.arange(n) / n))


def _frame_signal(x, frame=FRAME, hop=HOP):
    """Split x into overlapping frames. Returns (n_frames, frame)."""
    n_samples = len(x)
    if n_samples < frame:
        x = np.pad(x, (0, frame - n_samples))
        n_samples = frame
    n_frames = 1 + (n_samples - frame) // hop
    frames = np.zeros((n_frames, frame), dtype=np.float32)
    for i in range(n_frames):
        s = i * hop
        frames[i] = x[s:s + frame]
    return frames


def _overlap_add(frames, hop=HOP):
    """Reconstruct signal from analysis frames via overlap-add."""
    n_frames, frame = frames.shape
    out_len = (n_frames - 1) * hop + frame
    out = np.zeros(out_len, dtype=np.float32)
    norm = np.zeros(out_len, dtype=np.float32)
    w = _hann(frame).astype(np.float32)
    for i in range(n_frames):
        s = i * hop
        out[s:s + frame] += frames[i]
        norm[s:s + frame] += w * w   # accounting for analysis + synth window
    norm = np.maximum(norm, 1e-6)
    return out / norm


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------

def _stft_encode_body(audio_samples):
    """Run the STFT-magnitude DSP and return (body_bytes, n_frames, g_min,
    g_max, duration_ms). Pure DSP — numpy is used here (lazily). The caller
    wraps the result in the canonical sound container."""
    np = _np()
    x = np.asarray(audio_samples, dtype=np.float32)
    if x.ndim != 1:
        raise ValueError("audio must be mono (1-D)")

    # Peak normalize so quantization range is well-used
    peak = float(np.max(np.abs(x)))
    if peak > 0:
        x = x / peak

    # Analysis: window + STFT
    frames = _frame_signal(x)
    w = _hann(FRAME).astype(np.float32)
    windowed = frames * w
    spectrum = np.fft.rfft(windowed, axis=1)             # (n_frames, 129)
    magnitude = np.abs(spectrum).astype(np.float32)
    mag_kept = magnitude[:, :K_BINS]                      # (n_frames, 32)

    # Log-domain, normalize to [0, 1] per utterance, quantize to uint8
    log_mag = np.log(mag_kept + 1e-6)
    g_min = float(log_mag.min())
    g_max = float(log_mag.max())
    span = g_max - g_min if g_max > g_min else 1.0
    norm = (log_mag - g_min) / span
    quant = np.clip(np.round(norm * 255.0), 0, 255).astype(np.uint8)

    n_frames = int(quant.shape[0])
    if n_frames > 65535:
        raise ValueError("utterance too long: n_frames must fit in uint16")

    body = quant.tobytes()  # n_frames × 32 bytes, row-major
    duration_ms = int(round(len(x) / SR * 1000))
    return body, n_frames, g_min, g_max, duration_ms


def encode_sound_stft(audio_samples, title="", tone=sound.TONE_ORDINARY):
    """Encode mono 8 kHz float audio into a canonical SOUND container
    (type 0x07, codec 0x00 = STFT-magnitude vocoder).

    Args:
        audio_samples: 1-D numpy array, float in [-1, 1], sampled at 8 kHz.
                       Input outside [-1, 1] will be peak-normalized.
        title:         UTF-8 string, max 255 bytes when encoded.
        tone:          any valid tone byte (see canonical/tone.py).

    Returns:
        (header_bytes, body_bytes) — the SOUND container produced by
        sound.build_sound_quipu. codec_meta carries n_frames + g_min + g_max.
    """
    body, n_frames, g_min, g_max, duration_ms = _stft_encode_body(audio_samples)
    return sound.build_sound_quipu(
        CODEC_STFT, body,
        sample_rate=SR, channels=1, duration_ms=duration_ms,
        codec_meta=sound.pack_stft_meta(n_frames, g_min, g_max),
        title=title, tone=tone,
    )


# Backward-compatible alias: the old name now emits the container.
encode_voice = encode_sound_stft


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

def decode_voice(header_bytes, body_bytes, gl_iters=GRIFFIN_LIM_ITERS):
    """Decode a SOUND container (type 0x07, codec 0x00 = STFT) back to audio.

    Reads the canonical container, pulls n_frames + g_min + g_max from its
    codec_meta, and runs Griffin-Lim phase recovery on the body.

    Returns:
        (audio_samples, meta_dict)
        audio_samples: 1-D float32 numpy array at SR=8 kHz, peak ~ ±1.
        meta_dict:     {'title', 'tone', 'codec', 'n_frames',
                        'duration_s', 'sample_rate', 'k_bins'}.
    """
    np = _np()
    rec = sound.read_sound_quipu(header_bytes, body_bytes)
    if rec["codec"] != CODEC_STFT:
        raise ValueError(
            f"not the STFT codec (codec = {rec['codec']:#04x}, expected 0x00)"
        )
    tone = rec["tone"]
    title = rec["title"]
    n_frames, g_min, g_max = sound.unpack_stft_meta(rec["codec_meta"])
    body_bytes = rec["body"]

    expected = n_frames * K_BINS
    if len(body_bytes) < expected:
        raise ValueError(f"body too short: {len(body_bytes)} < {expected}")
    quant = np.frombuffer(body_bytes[:expected], dtype=np.uint8)
    quant = quant.reshape((n_frames, K_BINS))

    # Un-quantize back to log-magnitude, then to linear magnitude
    span = g_max - g_min if g_max > g_min else 1.0
    log_mag = (quant.astype(np.float32) / 255.0) * span + g_min
    mag_kept = np.maximum(np.exp(log_mag) - 1e-6, 0.0)

    # Zero-pad up to full STFT bin count (drop high band → muted highs)
    mag = np.zeros((n_frames, N_BINS_FULL), dtype=np.float32)
    mag[:, :K_BINS] = mag_kept

    # Griffin-Lim phase recovery: random init, iterate
    rng = np.random.default_rng(0)
    phase = 2 * np.pi * rng.random((n_frames, N_BINS_FULL)).astype(np.float32)
    spectrum = mag * np.exp(1j * phase)
    w = _hann(FRAME).astype(np.float32)

    for _ in range(gl_iters):
        frames = np.fft.irfft(spectrum, n=FRAME, axis=1).astype(np.float32) * w
        audio = _overlap_add(frames)
        re_frames = _frame_signal(audio)[:n_frames] * w
        re_spectrum = np.fft.rfft(re_frames, axis=1)
        spectrum = mag * np.exp(1j * np.angle(re_spectrum))

    frames = np.fft.irfft(spectrum, n=FRAME, axis=1).astype(np.float32) * w
    audio = _overlap_add(frames)

    # Peak normalize output (Griffin-Lim doesn't preserve scale)
    peak = float(np.max(np.abs(audio)))
    if peak > 0:
        audio = audio / peak * 0.95

    return audio, {
        "title": title,
        "tone": tone,
        "codec": CODEC_STFT,
        "n_frames": n_frames,
        "duration_s": n_frames * HOP / SR,
        "sample_rate": SR,
        "k_bins": K_BINS,
    }


# ---------------------------------------------------------------------------
# WAV helpers (for local audition; not part of the on-chain codec)
# ---------------------------------------------------------------------------

def save_wav(path, audio_samples, sample_rate=SR):
    """Save a float audio array as a 16-bit mono WAV file at `path`."""
    x = np.asarray(audio_samples, dtype=np.float32)
    x16 = (np.clip(x, -1.0, 1.0) * 32767.0).astype(np.int16)
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sample_rate)
        w.writeframes(x16.tobytes())


def load_wav(path):
    """Load a mono 16-bit WAV file. Returns (audio_float, sample_rate)."""
    with wave.open(path, "rb") as w:
        if w.getnchannels() != 1:
            raise ValueError("only mono WAVs supported in this sketch")
        if w.getsampwidth() != 2:
            raise ValueError("only 16-bit WAVs supported in this sketch")
        sr = w.getframerate()
        nframes = w.getnframes()
        raw = w.readframes(nframes)
    x = np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0
    return x, sr


# ---------------------------------------------------------------------------
# Synthetic test signal (no external audio needed)
# ---------------------------------------------------------------------------

def _synthesize_test_voice(duration_s=5.0):
    """Synthesize a 5-second 'voice-like' test signal: a sustained vowel
    with formant structure, modulated by a slow vibrato + a brief pause
    + a chirp. Demonstrates that the codec preserves something musical."""
    sr = SR
    t = np.arange(int(duration_s * sr)) / sr
    out = np.zeros_like(t)

    # Section 1: vowel "ah"  (~F1=730, F2=1090, F3≈2440)
    # We synthesize as a sum of harmonics of a 130 Hz fundamental modulated
    # by formant resonance approximations.
    s1 = (t >= 0) & (t < 2.0)
    fund = 130.0 + 4.0 * np.sin(2 * np.pi * 5.0 * t)  # vibrato
    phase = np.cumsum(2 * np.pi * fund / sr)
    vowel = np.zeros_like(t)
    for n, amp in [(1, 1.0), (2, 0.7), (3, 0.4), (4, 0.35),
                   (5, 0.3), (6, 0.2), (7, 0.18), (8, 0.12)]:
        vowel += amp * np.sin(n * phase)
    # Crude formant emphasis: amplitude shape per partial via filter would
    # be cleaner; for a sketch the harmonic sum sounds vowel-like enough.
    out[s1] = vowel[s1] * 0.5

    # Section 2: silence (0.5 s)
    # already zero

    # Section 3: chirp 200 -> 1500 Hz from t=2.5 to t=4.0
    s3 = (t >= 2.5) & (t < 4.0)
    t_c = t[s3] - 2.5
    f0, f1 = 200.0, 1500.0
    # linear frequency sweep
    inst_f = f0 + (f1 - f0) * (t_c / (4.0 - 2.5))
    ch_phase = 2 * np.pi * (f0 * t_c + (f1 - f0) * (t_c ** 2) / (2 * (4.0 - 2.5)))
    out[s3] = 0.6 * np.sin(ch_phase)

    # Section 4: vowel "ee"-ish at t=4.0 to end (higher fundamental + harmonics)
    s4 = (t >= 4.0)
    fund2 = 220.0
    phase2 = 2 * np.pi * fund2 * (t - 4.0)
    ee = np.zeros_like(t)
    for n, amp in [(1, 0.9), (2, 0.4), (3, 0.25), (4, 0.2), (5, 0.15)]:
        ee += amp * np.sin(n * phase2)
    out[s4] = ee[s4] * 0.5

    # Soft envelope to avoid clicks at section transitions
    env = np.ones_like(t)
    fade = int(0.02 * sr)
    env[:fade] = np.linspace(0, 1, fade)
    env[-fade:] = np.linspace(1, 0, fade)
    out *= env

    return out.astype(np.float32)


# ---------------------------------------------------------------------------
# Self-test: round-trip a synthetic utterance + report sizes
# ---------------------------------------------------------------------------

def _selftest():
    print("=" * 70)
    print("voice_codec.py self-test  —  0x07 0x00 STFT-magnitude voice codec")
    print("=" * 70)

    # 1) synthesize
    duration = 5.0
    audio_in = _synthesize_test_voice(duration_s=duration)
    save_wav("/tmp/voice_in.wav", audio_in)
    print(f"\nInput:  {len(audio_in)} samples @ {SR} Hz "
          f"= {duration:.1f}s  →  /tmp/voice_in.wav")

    # 2) encode
    header, body = encode_voice(
        audio_in,
        title="codec sketch — vowel + chirp + vowel",
        tone=0x00,
    )
    print(f"\nEncoded:")
    print(f"  header:  {len(header):4d} B")
    print(f"  body:    {len(body):4d} B")
    total = len(header) + len(body)
    print(f"  total:   {total:4d} B  "
          f"({total / duration:.0f} B/sec = "
          f"{total * 8 / duration:.0f} bits/sec)")

    # OP_RETURN economics
    bytes_per_op = 80
    n_op_total = (total + bytes_per_op - 1) // bytes_per_op
    n_op_cabeza = (len(header) + bytes_per_op - 1) // bytes_per_op
    n_op_cuerpo = (len(body) + bytes_per_op - 1) // bytes_per_op
    n_strands_for_body = (n_op_cuerpo + 24) // 25  # 25 = mempool ancestor cap

    print(f"\nOP_RETURN economics (80 B / tx, 25 txs / strand):")
    print(f"  cabeza strand:  {n_op_cabeza} tx")
    print(f"  cuerpo strands: {n_op_cuerpo} tx  → {n_strands_for_body} strand(s)")
    print(f"  total quipu shape: 1 cabeza + {n_strands_for_body} cuerpo "
          f"= {1 + n_strands_for_body} strands")
    fee_per_tx = 0.05  # DOGE
    n_tx_quipu = 1 + n_op_cabeza + n_op_cuerpo + 1  # root + cabeza + cuerpo + join
    cost = n_tx_quipu * fee_per_tx
    print(f"  estimated cost: ~{cost:.2f} DOGE  "
          f"({n_tx_quipu} txs × {fee_per_tx} DOGE/tip)")

    # 3) decode
    audio_out, meta = decode_voice(header, body)
    save_wav("/tmp/voice_out.wav", audio_out)
    print(f"\nDecoded:")
    print(f"  title:        {meta['title']!r}")
    print(f"  tone:         {meta['tone']:#04x}")
    print(f"  codec:        0x07 0x{meta['codec']:02x}")
    print(f"  n_frames:     {meta['n_frames']}")
    print(f"  duration:     {meta['duration_s']:.2f}s @ {meta['sample_rate']} Hz")
    print(f"  samples out:  {len(audio_out)}  →  /tmp/voice_out.wav")

    # 4) quality metric: log-spectral distance between input and output
    # (Griffin-Lim won't reproduce phase, but magnitude should be close.)
    f_in = _frame_signal(audio_in / max(np.max(np.abs(audio_in)), 1e-6))
    f_out = _frame_signal(audio_out / max(np.max(np.abs(audio_out)), 1e-6))
    n = min(f_in.shape[0], f_out.shape[0])
    w = _hann(FRAME).astype(np.float32)
    m_in = np.abs(np.fft.rfft(f_in[:n] * w, axis=1))[:, :K_BINS]
    m_out = np.abs(np.fft.rfft(f_out[:n] * w, axis=1))[:, :K_BINS]
    lsd = np.sqrt(np.mean((np.log(m_in + 1e-6) - np.log(m_out + 1e-6)) ** 2))
    print(f"\nQuality:")
    print(f"  log-spectral distance (in vs out, kept band): {lsd:.3f}")
    print(f"  (lower is better; ≤ 1.0 is intelligible reconstruction)")

    print("\nListen:  open /tmp/voice_in.wav  /tmp/voice_out.wav")
    print("=" * 70)


# ===========================================================================
# Codec variant 0x07 0x01 — LPC-10-style vocoder
# ===========================================================================
#
# A linear-predictive-coding vocoder modelled on the classic LPC-10 (US DOD
# STANAG, 2.4 kbps). At each frame, the vocal tract is parameterized by
# a 10th-order LPC filter; the excitation is either an impulse train (voiced)
# or white noise (unvoiced). Synthesis drives the LPC filter with the
# reconstructed excitation.
#
# Frame:                 200 samples (25 ms at 8 kHz), no overlap → 40 fps
# Per-frame parameters:  10 reflection coefficients (1 B each)
#                        + 1 byte log-gain
#                        + 1 byte pitch period in samples (0 = unvoiced)
#                        = 12 bytes per frame
# Bytes per second:      480 B/sec  (≈ 4× leaner than 0x07 0x00)
# 5-sec clip:            ~2.4 KB  →  ~30 strand txs (2 cuerpo strands)
# 30-sec clip:           ~14 KB
# 60-sec clip:           ~29 KB
#
# Quality character: robotic, intelligible, "Stephen Hawking" timbre.
# Voiced content keeps pitch contour and formant character; unvoiced
# segments sound like whispered hiss. Trade-off well-known from the
# LPC-10 lineage and acceptable for a 5×-leaner codec slot.
#
# Header layout (codec variant 0x01):
#     c1dd 0001        4B   magic + version
#     07               1B   type = audio
#     TT               1B   tone
#     01               1B   codec variant
#     NN NN            2B   n_frames, uint16 BE
#     LL               1B   title length
#     TITLE            L B  UTF-8 title
#     Total header:    10 + L bytes  (no global gain min/max — gain is
#                                     quantized per-frame)
#
# Body: n_frames × 12 bytes (10 reflection + 1 gain + 1 pitch)
# ---------------------------------------------------------------------------

LPC_FRAME = 200          # samples at 8 kHz = 25 ms
LPC_HOP = LPC_FRAME      # no overlap
LPC_ORDER = 10           # filter order — classic LPC-10
LPC_BYTES_PER_FRAME = LPC_ORDER + 2  # refl coefs + gain + pitch = 12
PRE_EMPHASIS = 0.97      # high-pass coefficient — flattens spectrum for LPC


def _autocorr(x, order):
    """Compute autocorrelation R[0..order] of a 1-D signal."""
    R = np.zeros(order + 1, dtype=np.float64)
    for k in range(order + 1):
        if k == 0:
            R[k] = np.dot(x, x)
        else:
            R[k] = np.dot(x[:-k], x[k:])
    return R


def _levinson_durbin(R, order):
    """Solve the symmetric Toeplitz system for LPC analysis. Returns
    (a, k) where:
      a[0..order] = LPC coefficients (a[0] = 1)
      k[0..order-1] = reflection (PARCOR) coefficients
    A nearly-silent frame returns k = zeros."""
    a = np.zeros(order + 1, dtype=np.float64)
    a[0] = 1.0
    k = np.zeros(order, dtype=np.float64)
    E = R[0]
    if E <= 1e-12:
        return a, k

    for i in range(order):
        if abs(E) < 1e-12:
            break
        # Compute reflection coefficient k[i]
        s = R[i + 1]
        for j in range(i):
            s += a[j + 1] * R[i - j]
        k[i] = -s / E
        # Update a[1..i+1] in place using two passes
        a_new = a.copy()
        a_new[i + 1] = k[i]
        for j in range(i):
            a_new[j + 1] = a[j + 1] + k[i] * a[i - j]
        a = a_new
        E = E * (1.0 - k[i] ** 2)

    return a, k


def _refl_to_lpc(k_vec):
    """Convert reflection coefficients back to LPC filter coefficients."""
    order = len(k_vec)
    a = np.zeros(order + 1, dtype=np.float64)
    a[0] = 1.0
    for i in range(order):
        a_new = a.copy()
        a_new[i + 1] = k_vec[i]
        for j in range(i):
            a_new[j + 1] = a[j + 1] + k_vec[i] * a[i - j]
        a = a_new
    return a


def _estimate_pitch(frame, sr=SR, min_hz=70.0, max_hz=400.0):
    """Center-clipped autocorrelation pitch detector. Returns pitch period
    in samples (0 if frame is judged unvoiced)."""
    n = len(frame)
    if n < 64:
        return 0
    # Center-clip to suppress formant carry-through (classic Sondhi)
    thresh = 0.3 * np.max(np.abs(frame))
    if thresh < 1e-6:
        return 0  # near-silence
    clipped = np.where(np.abs(frame) > thresh,
                       np.sign(frame) * (np.abs(frame) - thresh),
                       0.0).astype(np.float32)
    # Autocorrelation by full numpy correlate (small array, fast enough)
    R = np.correlate(clipped, clipped, mode="full")[n - 1:]
    min_lag = max(int(sr / max_hz), 1)
    max_lag = min(int(sr / min_hz), n - 1)
    if max_lag <= min_lag:
        return 0
    peak_lag = int(np.argmax(R[min_lag:max_lag + 1])) + min_lag
    # Voiced/unvoiced decision: R[peak]/R[0] threshold
    if R[0] <= 0:
        return 0
    if R[peak_lag] / R[0] < 0.30:
        return 0
    if peak_lag > 255:
        return 0  # can't fit in a byte → degrade to unvoiced
    return peak_lag


def encode_sound_lpc(audio_samples, title="", tone=sound.TONE_ORDINARY):
    """Encode mono 8 kHz audio with the LPC vocoder into a canonical SOUND
    container (type 0x07, codec 0x01 = LPC-10). About 4x leaner than the
    STFT codec. Output sounds robotic/buzzy but intelligible for speech.

    Returns (header_bytes, body_bytes) from sound.build_sound_quipu;
    codec_meta carries n_frames (u16).
    """
    np = _np()
    x = np.asarray(audio_samples, dtype=np.float32)
    if x.ndim != 1:
        raise ValueError("audio must be mono (1-D)")
    peak = float(np.max(np.abs(x)))
    if peak > 0:
        x = x / peak

    # Pre-emphasis flattens the spectrum, which makes LPC analysis crisper
    x_pre = np.empty_like(x)
    x_pre[0] = x[0]
    x_pre[1:] = x[1:] - PRE_EMPHASIS * x[:-1]

    # Pad to whole frames
    n_frames = max(1, (len(x_pre) + LPC_FRAME - 1) // LPC_FRAME)
    padded = np.zeros(n_frames * LPC_FRAME, dtype=np.float32)
    padded[:len(x_pre)] = x_pre
    if n_frames > 65535:
        raise ValueError("utterance too long: n_frames must fit uint16")

    w = _hann(LPC_FRAME).astype(np.float32)
    quant = np.zeros((n_frames, LPC_BYTES_PER_FRAME), dtype=np.uint8)

    for i in range(n_frames):
        frame_raw = padded[i * LPC_FRAME:(i + 1) * LPC_FRAME]
        frame_w = frame_raw * w
        R = _autocorr(frame_w, LPC_ORDER)
        a, refl = _levinson_durbin(R, LPC_ORDER)
        # Residual energy: R[0] · ∏(1 − k²)
        e_res = R[0] * float(np.prod(1.0 - refl ** 2))
        e_res = max(e_res, 1e-12)
        gain = float(np.sqrt(e_res / LPC_FRAME))  # RMS-equiv
        pitch = _estimate_pitch(frame_raw)

        # Quantize reflection coefs (range [-1, 1]) to 8-bit
        refl_q = np.clip(np.round((refl + 1.0) * 127.5), 0, 255).astype(np.uint8)
        # Quantize gain: log domain, range [-60, 0] dB → [0, 255]
        gain_db = 20.0 * np.log10(max(gain, 1e-6))
        gain_q = int(np.clip(np.round((gain_db + 60.0) * (255.0 / 60.0)), 0, 255))

        quant[i, :LPC_ORDER] = refl_q
        quant[i, LPC_ORDER] = gain_q
        quant[i, LPC_ORDER + 1] = pitch  # 0 = unvoiced

    body = quant.tobytes()
    duration_ms = int(round(len(x) / SR * 1000))
    return sound.build_sound_quipu(
        CODEC_LPC, body,
        sample_rate=SR, channels=1, duration_ms=duration_ms,
        codec_meta=sound.pack_frames_meta(n_frames),
        title=title, tone=tone,
    )


# Backward-compatible alias: the old name now emits the container.
encode_voice_lpc = encode_sound_lpc


def decode_voice_lpc(header_bytes, body_bytes):
    """Decode a SOUND container (type 0x07, codec 0x01 = LPC) back to audio.
    Returns (audio_float32, meta_dict)."""
    np = _np()
    rec = sound.read_sound_quipu(header_bytes, body_bytes)
    if rec["codec"] != CODEC_LPC:
        raise ValueError(
            f"not the LPC codec (codec = {rec['codec']:#04x}, expected 0x01)"
        )
    tone = rec["tone"]
    title = rec["title"]
    n_frames = sound.unpack_frames_meta(rec["codec_meta"])
    body_bytes = rec["body"]

    expected = n_frames * LPC_BYTES_PER_FRAME
    if len(body_bytes) < expected:
        raise ValueError(f"body too short: {len(body_bytes)} < {expected}")
    quant = np.frombuffer(body_bytes[:expected], dtype=np.uint8)
    quant = quant.reshape((n_frames, LPC_BYTES_PER_FRAME))

    rng = np.random.default_rng(0)
    audio = np.zeros(n_frames * LPC_FRAME, dtype=np.float32)
    filter_state = np.zeros(LPC_ORDER, dtype=np.float64)
    pitch_phase = 0  # carry across voiced frames for continuity

    for i in range(n_frames):
        refl_q = quant[i, :LPC_ORDER]
        gain_q = int(quant[i, LPC_ORDER])
        pitch = int(quant[i, LPC_ORDER + 1])

        refl = (refl_q.astype(np.float64) - 127.5) / 127.5
        refl = np.clip(refl, -0.99, 0.99)  # keep filter strictly stable
        gain_db = (gain_q / 255.0) * 60.0 - 60.0
        gain = 10.0 ** (gain_db / 20.0)
        a = _refl_to_lpc(refl)

        # Excitation
        excitation = np.zeros(LPC_FRAME, dtype=np.float64)
        if pitch >= 20:  # voiced (≥ 50 ms period would be sub-audible)
            j = pitch_phase
            while j < LPC_FRAME:
                # √pitch scaling keeps perceived loudness independent of period
                excitation[j] = np.sqrt(pitch)
                j += pitch
            pitch_phase = j - LPC_FRAME
        else:  # unvoiced
            excitation = rng.standard_normal(LPC_FRAME) * 0.3
            pitch_phase = 0

        excitation *= gain

        # All-pole synthesis filter: y[n] = e[n] - Σ a[k] · y[n-k]
        y = np.zeros(LPC_FRAME, dtype=np.float64)
        state = filter_state.copy()
        for n in range(LPC_FRAME):
            v = excitation[n]
            for k_idx in range(LPC_ORDER):
                v -= a[k_idx + 1] * state[k_idx]
            y[n] = v
            # Shift state right
            state[1:] = state[:-1]
            state[0] = v
        filter_state = state

        audio[i * LPC_FRAME:(i + 1) * LPC_FRAME] = y.astype(np.float32)

    # Defend against the occasional filter blow-up: replace nan/inf with 0
    audio = np.nan_to_num(audio, nan=0.0, posinf=0.0, neginf=0.0)
    # Soft-clip pathological excursions before de-emphasis to keep the
    # leaky integrator below from amplifying any one frame's transient
    audio = np.tanh(audio / 4.0) * 4.0

    # De-emphasis (inverse of pre-emphasis IIR)
    de = np.empty_like(audio)
    de[0] = audio[0]
    for n in range(1, len(audio)):
        de[n] = audio[n] + PRE_EMPHASIS * de[n - 1]
    de = np.nan_to_num(de, nan=0.0, posinf=0.0, neginf=0.0)

    peak = float(np.max(np.abs(de)))
    if peak > 0:
        de = de / peak * 0.95

    return de, {
        "title": title,
        "tone": tone,
        "codec": 0x01,
        "n_frames": n_frames,
        "duration_s": n_frames * LPC_FRAME / SR,
        "sample_rate": SR,
        "lpc_order": LPC_ORDER,
    }


def _selftest_lpc():
    print()
    print("=" * 70)
    print("voice_codec.py self-test  —  0x07 0x01 LPC-10 vocoder")
    print("=" * 70)

    duration = 5.0
    audio_in = _synthesize_test_voice(duration_s=duration)
    save_wav("/tmp/voice_in_lpc.wav", audio_in)
    print(f"\nInput:  {len(audio_in)} samples @ {SR} Hz "
          f"= {duration:.1f}s  →  /tmp/voice_in_lpc.wav")

    header, body = encode_voice_lpc(
        audio_in,
        title="LPC sketch — vowel + chirp + vowel",
    )
    print(f"\nEncoded:")
    print(f"  header:  {len(header):4d} B")
    print(f"  body:    {len(body):4d} B  ({body.__len__() // LPC_BYTES_PER_FRAME}"
          f" frames × {LPC_BYTES_PER_FRAME} B)")
    total = len(header) + len(body)
    print(f"  total:   {total:4d} B  "
          f"({total / duration:.0f} B/sec = "
          f"{total * 8 / duration:.0f} bits/sec)")

    bytes_per_op = 80
    n_op_cabeza = (len(header) + bytes_per_op - 1) // bytes_per_op
    n_op_cuerpo = (len(body) + bytes_per_op - 1) // bytes_per_op
    n_strands_for_body = (n_op_cuerpo + 24) // 25
    n_tx_quipu = 1 + n_op_cabeza + n_op_cuerpo + 1
    cost = n_tx_quipu * 0.05
    print(f"\nOP_RETURN economics (80 B / tx, 25 txs / strand):")
    print(f"  cabeza strand:  {n_op_cabeza} tx")
    print(f"  cuerpo strands: {n_op_cuerpo} tx  → {n_strands_for_body} strand(s)")
    print(f"  total tx count: {n_tx_quipu}")
    print(f"  estimated cost: ~{cost:.2f} DOGE")

    audio_out, meta = decode_voice_lpc(header, body)
    save_wav("/tmp/voice_out_lpc.wav", audio_out)
    print(f"\nDecoded:")
    print(f"  title:        {meta['title']!r}")
    print(f"  codec:        0x07 0x{meta['codec']:02x}  (LPC order {meta['lpc_order']})")
    print(f"  n_frames:     {meta['n_frames']}")
    print(f"  duration:     {meta['duration_s']:.2f}s @ {meta['sample_rate']} Hz")
    print(f"  samples out:  {len(audio_out)}  →  /tmp/voice_out_lpc.wav")

    # Voiced/unvoiced summary
    quant = np.frombuffer(body, dtype=np.uint8).reshape((-1, LPC_BYTES_PER_FRAME))
    n_voiced = int(np.sum(quant[:, -1] > 0))
    print(f"  frames voiced: {n_voiced}/{meta['n_frames']} "
          f"({100*n_voiced/meta['n_frames']:.0f}%)")

    # Spectral-distance metric
    f_in = _frame_signal(audio_in / max(np.max(np.abs(audio_in)), 1e-6))
    f_out = _frame_signal(audio_out / max(np.max(np.abs(audio_out)), 1e-6))
    n = min(f_in.shape[0], f_out.shape[0])
    w = _hann(FRAME).astype(np.float32)
    m_in = np.abs(np.fft.rfft(f_in[:n] * w, axis=1))[:, :K_BINS]
    m_out = np.abs(np.fft.rfft(f_out[:n] * w, axis=1))[:, :K_BINS]
    lsd = float(np.sqrt(np.mean(
        (np.log(m_in + 1e-6) - np.log(m_out + 1e-6)) ** 2
    )))
    print(f"\nQuality:")
    print(f"  log-spectral distance (in vs out, kept band): {lsd:.3f}")

    print("\nListen:  open /tmp/voice_in_lpc.wav  /tmp/voice_out_lpc.wav")
    print("=" * 70)


# ===========================================================================
# Codec variant 0x07 0x02 — Codec2 700C (libcodec2 wrapper)
# ===========================================================================
#
# The leanest practical voice codec: David Rowe's Codec2 at 700 bps. Uses
# a sinusoidal speech model with mel-LSP quantization at 700 bits/second.
# Reference for the protocol: requires libcodec2 (Homebrew: `brew install
# codec2`) and the pycodec2 binding (`pip install pycodec2`).
#
# Mode 700C:
#   samples per frame: 320 (40 ms at 8 kHz)
#   bytes per frame:   4   (28 bits packed into 4 bytes, last 4 bits unused)
#   bitrate:           700 bps  →  87.5 bytes/sec
#
# A 100-second utterance fits in ~8.75 KB = ~110 OP_RETURNs = ~5 cuerpo
# strands. Costs ~6 DOGE at the standard tip — roughly 21× leaner than
# 0x07 0x00 STFT, ~4× leaner than 0x07 0x01 LPC.
#
# Header (10 + L bytes):
#     c1dd 0001         4B
#     07                1B  type = audio
#     TT                1B  tone
#     02                1B  codec variant = Codec2 700C
#     NN NN             2B  n_frames, uint16 BE
#     LL                1B  title length
#     TITLE             L B UTF-8
# Body: n_frames × 4 bytes
# ---------------------------------------------------------------------------

C2_FRAME = 320      # samples per Codec2 700C frame (40 ms @ 8 kHz)
C2_BPF = 4          # bytes per frame
C2_MODE = 700       # pycodec2 mode integer for 700C


def _get_c2():
    """Lazy-import the Codec2 binding so voice_codec.py still loads (and the
    0x00 and 0x01 codecs still work) on machines without libcodec2."""
    import pycodec2
    return pycodec2.Codec2(C2_MODE)


def encode_sound_codec2(audio_samples, title="", tone=sound.TONE_ORDINARY):
    """Encode mono 8 kHz audio with Codec2 700C into a canonical SOUND
    container (type 0x07, codec 0x02). The leanest variant in the type;
    needs libcodec2 + pycodec2. Returns (header_bytes, body_bytes);
    codec_meta carries n_frames (u16)."""
    np = _np()
    x = np.asarray(audio_samples, dtype=np.float32)
    if x.ndim != 1:
        raise ValueError("audio must be mono")

    # Convert float [-1, 1] to int16
    peak = float(np.max(np.abs(x)))
    if peak > 0:
        x = x / peak
    x_i16 = (np.clip(x, -1.0, 1.0) * 32767.0).astype(np.int16)

    # Pad to whole frames
    n_frames = max(1, (len(x_i16) + C2_FRAME - 1) // C2_FRAME)
    padded = np.zeros(n_frames * C2_FRAME, dtype=np.int16)
    padded[:len(x_i16)] = x_i16
    if n_frames > 65535:
        raise ValueError("utterance too long: n_frames must fit uint16")

    c2 = _get_c2()
    chunks = bytearray()
    for i in range(n_frames):
        frame = padded[i * C2_FRAME:(i + 1) * C2_FRAME]
        chunks.extend(c2.encode(frame))

    duration_ms = int(round(len(x_i16) / SR * 1000))
    return sound.build_sound_quipu(
        CODEC_CODEC2, bytes(chunks),
        sample_rate=SR, channels=1, duration_ms=duration_ms,
        codec_meta=sound.pack_frames_meta(n_frames),
        title=title, tone=tone,
    )


# Backward-compatible alias: the old name now emits the container.
encode_voice_c2 = encode_sound_codec2


def decode_voice_c2(header_bytes, body_bytes):
    """Decode a SOUND container (type 0x07, codec 0x02 = Codec2 700C)."""
    np = _np()
    rec = sound.read_sound_quipu(header_bytes, body_bytes)
    if rec["codec"] != CODEC_CODEC2:
        raise ValueError(
            f"not the Codec2 codec (codec = {rec['codec']:#04x}, "
            f"expected 0x02)"
        )
    tone = rec["tone"]
    title = rec["title"]
    n_frames = sound.unpack_frames_meta(rec["codec_meta"])
    body_bytes = rec["body"]

    expected = n_frames * C2_BPF
    if len(body_bytes) < expected:
        raise ValueError(f"body too short: {len(body_bytes)} < {expected}")

    c2 = _get_c2()
    audio_i16 = np.zeros(n_frames * C2_FRAME, dtype=np.int16)
    for i in range(n_frames):
        chunk = body_bytes[i * C2_BPF:(i + 1) * C2_BPF]
        audio_i16[i * C2_FRAME:(i + 1) * C2_FRAME] = c2.decode(chunk)

    audio_f = audio_i16.astype(np.float32) / 32768.0
    return audio_f, {
        "title": title,
        "tone": tone,
        "codec": 0x02,
        "n_frames": n_frames,
        "duration_s": n_frames * C2_FRAME / SR,
        "sample_rate": SR,
        "bitrate_bps": 700,
    }


# ---------------------------------------------------------------------------
# Unified container decode dispatcher
# ---------------------------------------------------------------------------

# Maps each vocoder codec byte to the DSP decoder that reconstructs audio.
_DECODE_DISPATCH = {
    CODEC_STFT:   decode_voice,
    CODEC_LPC:    decode_voice_lpc,
    CODEC_CODEC2: decode_voice_c2,
}


def decode_sound(header_bytes, body_bytes):
    """Decode a canonical SOUND container (type 0x07) to audio samples.

    Reads the container (keyless, pure-stdlib via sound.read_sound_quipu),
    then routes to the matching numpy DSP for the vocoder codecs
    (0x00 STFT / 0x01 LPC / 0x02 Codec2). Opaque standard codecs
    (0x10 opus / 0x11 mp3 / 0x12 wav / 0x13 flac) are NOT decoded here —
    their bodies are real bitstreams for a browser/audio library, so this
    raises ValueError pointing the caller at the container record (use
    sound.read_sound_quipu to get the opaque body + codec_name).

    Returns:
        (audio_samples, meta_dict) — same shape the per-codec decoders return.
    """
    rec = sound.read_sound_quipu(header_bytes, body_bytes)
    codec = rec["codec"]
    fn = _DECODE_DISPATCH.get(codec)
    if fn is None:
        raise ValueError(
            f"codec 0x{codec:02x} ({rec['codec_name']}) is not a quipu "
            f"vocoder; its body is an opaque {rec['codec_name']} bitstream. "
            f"Use sound.read_sound_quipu() and decode it with an audio "
            f"library / browser instead."
        )
    return fn(header_bytes, body_bytes)


def _selftest_c2():
    print()
    print("=" * 70)
    print("voice_codec.py self-test  —  0x07 0x02 Codec2 700C")
    print("=" * 70)

    duration = 5.0
    audio_in = _synthesize_test_voice(duration_s=duration)
    save_wav("/tmp/voice_in_c2.wav", audio_in)
    print(f"\nInput:  {len(audio_in)} samples @ {SR} Hz = {duration:.1f}s")

    header, body = encode_voice_c2(audio_in, title="Codec2 sketch")
    total = len(header) + len(body)
    print(f"\nEncoded:")
    print(f"  header:  {len(header):4d} B")
    print(f"  body:    {len(body):4d} B  ({len(body)//C2_BPF} frames × {C2_BPF} B)")
    print(f"  total:   {total:4d} B  ({total/duration:.0f} B/sec, "
          f"{total*8/duration:.0f} bits/sec)")

    bytes_per_op = 80
    n_op_cabeza = (len(header) + bytes_per_op - 1) // bytes_per_op
    n_op_cuerpo = (len(body) + bytes_per_op - 1) // bytes_per_op
    n_strands = (n_op_cuerpo + 24) // 25
    n_tx = 1 + n_op_cabeza + n_op_cuerpo + 1
    print(f"\nOP_RETURN economics:")
    print(f"  total tx count: {n_tx} (cabeza {n_op_cabeza} + cuerpo {n_op_cuerpo} + root + join)")
    print(f"  cuerpo strands needed: {n_strands}")
    print(f"  estimated cost: ~{n_tx*0.05:.2f} DOGE")

    audio_out, meta = decode_voice_c2(header, body)
    save_wav("/tmp/voice_out_c2.wav", audio_out)
    print(f"\nDecoded: {len(audio_out)} samples → /tmp/voice_out_c2.wav")

    print("\nListen:  open /tmp/voice_in_c2.wav  /tmp/voice_out_c2.wav")
    print("=" * 70)


def _selftest_container_integration():
    """Assert the DSP encoders emit a valid canonical SOUND container that the
    KEYLESS reader (sound.read_sound_quipu) parses, and that decode_sound
    routes back to audio. Covers the STFT and LPC vocoders (both pure-numpy);
    Codec2 needs libcodec2 so it's exercised separately."""
    print()
    print("=" * 70)
    print("voice_codec.py self-test  —  canonical SOUND container integration")
    print("=" * 70)
    audio_in = _synthesize_test_voice(duration_s=2.0)

    for label, codec, enc in (
        ("stft", CODEC_STFT, encode_sound_stft),
        ("lpc",  CODEC_LPC,  encode_sound_lpc),
    ):
        header, body = enc(audio_in, title=f"{label} container test",
                           tone=sound.TONE_REVERENCE)
        # The KEYLESS container reader must parse the DSP's output.
        rec = sound.read_sound_quipu(header, body)
        assert rec["type"] == "sound"
        assert rec["codec"] == codec
        assert rec["codec_name"] == label
        assert rec["sample_rate"] == SR
        assert rec["channels"] == 1
        assert rec["duration_ms"] > 0
        assert rec["tone"] == sound.TONE_REVERENCE
        assert rec["title"] == f"{label} container test"
        assert rec["body"] == body
        # Header is a well-formed quipu prefix.
        assert header[:4] == b"\xc1\xdd\x00\x01"
        assert header[4] == 0x07
        # The unified dispatcher routes container -> DSP -> audio.
        audio_out, meta = decode_sound(header, body)
        assert meta["codec"] == codec
        assert len(audio_out) > 0
        print(f"  {label:6s} codec 0x{codec:02x}: header {len(header)} B, "
              f"body {len(body)} B, dur {rec['duration_ms']} ms -> "
              f"{len(audio_out)} samples decoded  OK")

    # decode_sound on an opaque codec must refuse (no DSP for it).
    h_op, b_op = sound.build_sound_quipu(CODEC_WAV, b"RIFF....fake",
                                         sample_rate=8000, channels=1)
    try:
        decode_sound(h_op, b_op)
    except ValueError as e:
        print(f"  opaque 0x12 wav: decode_sound refused as expected ({e})"[:90])
    else:
        print("  opaque 0x12 wav: decode_sound DID NOT REFUSE (bug)")
    print("=" * 70)


if __name__ == "__main__":
    _selftest()
    _selftest_lpc()
    _selftest_container_integration()
    try:
        _selftest_c2()
    except ImportError as e:
        print(f"\n[skipped 0x07 0x02 Codec2 self-test: {e}]")
        print("Install with:  brew install codec2 && pip install pycodec2")
