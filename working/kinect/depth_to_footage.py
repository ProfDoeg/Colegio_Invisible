#!/usr/bin/env python3
"""Kinect depth stack -> 0xda dancer footage.

The depth sensor is a better capture source for the dancer format than RGB
video: the footage block stores only the opaque silhouette (a 1-bpp mask +
palette indices, delta-coded), and the hard part of making that from video
is segmentation — cutting the body from the background. Depth makes the cut
a threshold: keep pixels in a distance band, and the silhouette falls out,
lighting-independent.

Pipeline per frame:
  1. valid mask        : 0 < raw < 2047  (2047 = no return)
  2. band select       : near_raw <= raw <= far_raw  (the dancer's depth slab)
  3. downscale         : block-OR to the notional frame (any opaque cell wins)
  4. clean             : morphological open->close + largest connected blob
  5. hysteresis        : a cell must disagree for HYST frames before it flips
  6. quantise (opt)    : N depth bands within the body -> palette indices
                         (nearer = brighter); pal_n==1 -> pure silhouette

Output is the footage dict consumed by canonical/dancer.py _emit_footage:
  {palette, frames:[{x,y,w,h,cx,cy,facing,mask,idx}], nw, nh, fps, keyint}
"""
import numpy as np

RAW_NODATA = 2047


def raw_to_mm(raw):
    """libfreenect 11-bit raw -> millimetres (the standard tan fit)."""
    return 1000.0 * 0.1236 * np.tan(raw / 2842.5 + 1.1863)


def mm_to_raw(mm):
    return 2842.5 * (np.arctan(mm / 123.6) - 1.1863)


def _downscale_or(opaque, nw, nh):
    """Block-reduce a (H,W) bool to (nh,nw) by OR — any opaque source cell
    makes the target cell opaque. Keeps thin limbs that averaging would erase."""
    H, W = opaque.shape
    ys = (np.arange(H) * nh // H)
    xs = (np.arange(W) * nw // W)
    out = np.zeros((nh, nw), bool)
    np.logical_or.at(out, (ys[:, None], xs[None, :]), opaque)
    return out


def _largest_blob(mask):
    """Keep only the largest 4-connected component (drops speckle/second body)."""
    from scipy import ndimage
    lbl, n = ndimage.label(mask)
    if n <= 1:
        return mask
    sizes = ndimage.sum(mask, lbl, range(1, n + 1))
    return lbl == (1 + int(np.argmax(sizes)))


def _clean(mask):
    from scipy import ndimage
    m = ndimage.binary_opening(mask, iterations=1)
    m = ndimage.binary_closing(m, iterations=1)
    return _largest_blob(m)


def depth_stack_to_footage(stack, *, near_mm=1500, far_mm=2600, nw=160, nh=120,
                           fps=15, keyint=30, palette_bands=1, hyst=2,
                           facing=0, stride=2, registered=None):
    """stack: (N,H,W) uint16 depth. Returns a footage dict + a coverage report.
    `registered`: True if the stack is already in MILLIMETRES (libfreenect
    REGISTERED mode, as the Linux studio streams); False for raw 11-bit
    (the macOS libfreenect_sync default). None = autodetect from the value
    range (raw 11-bit tops out at 2047; mm reaches ~4500+).
    `stride` decimates frames; `palette_bands`: 1 = silhouette, >1 = shaded."""
    try:
        import scipy.ndimage  # noqa: F401
        have_scipy = True
    except ImportError:
        have_scipy = False

    if registered is None:
        registered = int(stack.max()) > 2047          # mm exceeds the 11-bit cap

    if registered:                                    # stack values ARE mm
        lo, hi = float(near_mm), float(far_mm)
    else:                                             # raw 11-bit: convert bounds
        near_raw, far_raw = mm_to_raw(near_mm), mm_to_raw(far_mm)
        lo, hi = min(near_raw, far_raw), max(near_raw, far_raw)

    sel = stack[::stride]
    palette = _band_palette(palette_bands)
    frames, covs = [], []
    prev_obs = None        # last raw observation (this frame's clean mask)
    committed = None       # debounced output mask actually emitted

    for raw in sel:
        valid = (raw > 0) if registered else ((raw > 0) & (raw < RAW_NODATA))
        band = valid & (raw >= lo) & (raw <= hi)
        obs = _downscale_or(band, nw, nh)
        if have_scipy and obs.any():
            obs = _clean(obs)
        # debounce: a cell adopts its new state only when the last TWO
        # observations agree on it; otherwise hold the committed value.
        # Kills single-frame IR edge flicker the delta codec prices as motion.
        if committed is not None and prev_obs is not None and hyst > 1:
            agree = obs == prev_obs
            committed = np.where(agree, obs, committed)
        else:
            committed = obs
        prev_obs = obs
        covs.append(committed.mean())

        frames.append(_sprite_from_mask(committed, raw, band, nw, nh,
                                        palette_bands, lo, hi, facing))

    return ({"palette": palette, "frames": frames, "nw": nw, "nh": nh,
             "fps": fps, "keyint": keyint},
            {"frames": len(frames), "mean_coverage": float(np.mean(covs)) if covs else 0.0,
             "scipy": have_scipy})


def _band_palette(n):
    if n <= 1:
        return [(255, 255, 255)]
    return [(int(255 * (i + 1) / n),) * 3 for i in range(n)]   # near=bright grey ramp


def _sprite_from_mask(small, raw, band, nw, nh, bands, lo, hi, facing):
    ys, xs = np.where(small)
    if len(xs) == 0:
        return {"x": 0, "y": 0, "w": 0, "h": 0, "cx": 0.0, "cy": 0.0,
                "facing": facing, "mask": [], "idx": []}
    x0, x1 = xs.min(), xs.max()
    y0, y1 = ys.min(), ys.max()
    w, h = int(x1 - x0 + 1), int(y1 - y0 + 1)
    sub = small[y0:y1 + 1, x0:x1 + 1]
    mask = sub.astype(np.uint8).flatten().tolist()

    if bands <= 1:
        idx = [0] * int(sub.sum())
    else:
        # per-opaque-cell depth band: downscale the raw to the notional grid
        # by nearest, map nearer->higher index (brighter)
        H, W = raw.shape
        ry = (np.arange(H) * nh // H)
        rx = (np.arange(W) * nw // W)
        # init to +inf, NOT NaN — np.minimum propagates NaN, which would leave
        # every voted cell NaN and flatten all depth bands to the brightest index
        grid = np.full((nh, nw), np.inf)
        bv = raw[band].astype(np.float32)
        np.minimum.at(grid, (ry[np.where(band)[0]], rx[np.where(band)[1]]), bv)
        g = grid[y0:y1 + 1, x0:x1 + 1]
        span = max(hi - lo, 1)
        idx = []
        for j in range(h):
            for i in range(w):
                if sub[j, i]:
                    val = g[j, i]
                    if not np.isfinite(val):
                        idx.append(bands - 1)
                    else:
                        t = 1.0 - (val - lo) / span        # near -> 1
                        idx.append(int(np.clip(t, 0, 1) * (bands - 1) + 0.5))

    return {"x": int(x0), "y": int(y0), "w": w, "h": h,
            "cx": float((x0 + x1) / 2 / nw), "cy": float((y0 + y1) / 2 / nh),
            "facing": facing, "mask": mask, "idx": idx}


if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "canonical"))
    npy = sys.argv[1] if len(sys.argv) > 1 else "/tmp/kinect_depth.npy"
    stack = np.load(npy)
    foot, rep = depth_stack_to_footage(stack, near_mm=1300, far_mm=2300,
                                       palette_bands=4, stride=2)
    print("segmentation:", rep)
    import dancer
    hdr, body = dancer.build_footage("Kinect test", foot)
    pf = dancer.read_dancer(hdr, body)["footage"]
    total = len(hdr) + len(body)
    print(f"encoded {total} bytes (~{total/80:.0f} knots) -> {len(pf['frames'])} frames, "
          f"pal {len(pf['palette'])}, {pf['nw']}x{pf['nh']} @ {pf['fps']}fps")
    # exact mask round-trip on a mid frame with real coverage
    i = next((k for k, f in enumerate(foot["frames"]) if f["w"]), 0)
    ok = (pf["frames"][i]["mask"] == foot["frames"][i]["mask"]
          and pf["frames"][i]["idx"] == foot["frames"][i]["idx"])
    print(f"round-trip frames OK: {len(pf['frames']) == len(foot['frames'])} | "
          f"frame {i} pixels exact: {ok}")
