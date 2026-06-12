# Kinect → dancer (`0xda`)

Capture motion-sprite **footage** for the dancer type from an Xbox 360
Kinect's depth stream. Depth is a better source than RGB video for this
format: the footage block stores only the opaque silhouette (1-bpp mask +
palette indices, delta-coded), and depth makes segmentation a threshold —
keep the pixels in a distance band and the body falls out, lighting-
independent. No chroma key, no matting, works in a dark room.

## Proven 2026-06-11

- **Sensor**: Xbox Kinect model **1473**, streams depth on this Mac at
  **30 fps**, 640×480, 11-bit, via Homebrew `libfreenect 0.7.5`.
- **Path**: camera subdevice only (`freenect_select_subdevices(…, 2)`),
  async C API via ctypes. The motor/`fakenect-record` path **wedges**
  this model — avoid it; if a tool half-claims the interface, replug.
- A 12 s room capture → 180 frames @ 160×120, 4 depth bands →
  **13,962 bytes (~175 knots)**, round-trips bit-exact through
  `canonical/dancer.read_dancer`.

## Use

```sh
# 1. capture (replug Kinect first if a prior run errored)
.venv/bin/python working/kinect/capture_depth.py /tmp/kinect_depth.npy 12

# 2. segment + encode to 0xda footage (round-trip self-test in __main__)
.venv/bin/python working/kinect/depth_to_footage.py /tmp/kinect_depth.npy
```

`depth_to_footage.depth_stack_to_footage(stack, …)` returns the footage
dict that `canonical/dancer.build_footage` / `build_performance` consume.

### Tuning knobs

| knob | meaning |
|---|---|
| `near_mm` / `far_mm` | the depth slab the dancer stands in — set to the body's distance ± ~0.5 m to drop floor and back wall |
| `nw` / `nh` | notional frame; 160×120 is a good silhouette resolution |
| `fps` / `stride` | `stride` decimates the 30 fps capture; `fps` is the playback rate written to the footage |
| `palette_bands` | 1 = pure silhouette (cheapest); >1 = depth-shaded bas-relief (nearer = brighter) |
| `hyst` | a cell must disagree for N frames before it flips — kills IR edge flicker the delta codec would otherwise price as motion |
| `facing` | 0 front / 1 back / 2 profile_R / 3 profile_L — set per take |

## Capture notes (the IR gotchas)

All-`2047` depth = no IR return. Causes, in order: something covering the
two front IR windows (projector far-left, camera centre); aimed at a
window / sunlit surface (daylight washes out the pattern); or everything
out of the ~0.5–4.5 m range. A phone camera sees the projector's faint
purple dot-grid — use it to confirm the laser is lit. Stand the dancer
**1.5–2.5 m** from the sensor against open space or a far wall.

## Next

- `capture_depth.py` writes a raw `.npy` stack; a longer take + a clean
  silhouette (`palette_bands=1`) against open space is the first real
  dancer recording candidate.
- Footage → graph → controller are separate `0xda` variants; this tool
  makes the **footage** (the body). Choreography (graph) and intention
  (controller) are authored on top, per `docs/quipu-types/dancer.md`.
