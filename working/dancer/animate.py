"""Stitch the action frames into animated GIFs.

Produces:
  per-action loops:
    anim_idle_breathe.gif      — palindromic idle breath
    anim_step_right.gif        — walk-cycle (admittedly weak in this run)
    anim_wave.gif              — wave gesture, looping
    anim_bow.gif               — bow down then rise (forward + reverse)
    anim_spin_half_cw.gif      — half rotation
    anim_point_right.gif       — point and retract (forward + reverse)
    anim_reach_up.gif          — arms up and down (forward + reverse)
    anim_lift_skirt.gif        — lift and release (forward + reverse)

  composability demos:
    demo_mirror_trick.gif      — wave_right + wave_left side-by-side
    demo_reverse_trick.gif     — bow_down + rise_from_bow side-by-side
    demo_sequence.gif          — idle → wave → idle → bow → idle → spin → idle
"""
import json
from pathlib import Path
from PIL import Image, ImageOps

THIS_DIR  = Path(__file__).parent
ACTIONS   = THIS_DIR / "actions"
PROCESSED = THIS_DIR / "processed"
OUT_DIR   = THIS_DIR / "animations"
OUT_DIR.mkdir(exist_ok=True)

# Use the source 1024×1536 frames, but downscale to viewable size
VIEW_W, VIEW_H = 256, 384

# Composition white background so the GIFs are readable (GIF has 1-bit alpha,
# not great for showing the dancer against arbitrary scene backgrounds, but
# fine for demoing the motion)
BG = (250, 245, 235)

ACTION_FRAMES = {
    "idle_breathe":       3,
    "step_right":         5,
    "wave":               5,
    "bow":                5,
    "spin_half_cw":       5,
    "point_right":        4,
    "reach_up_bilateral": 4,
    "lift_skirt":         4,
}

# Per-action playback timing — fps roughly tuned to the action's natural pace
TIMINGS_MS = {
    "idle_breathe":        250,
    "step_right":          180,
    "wave":                160,
    "bow":                 200,
    "spin_half_cw":        140,
    "point_right":         140,
    "reach_up_bilateral":  150,
    "lift_skirt":          180,
}


def load_frame(action, idx):
    """Open a source frame, composite over white BG (so GIF is legible),
    and resize to viewable dimensions."""
    src = Image.open(ACTIONS / f"{action}_{idx:02d}.png").convert("RGBA")
    # composite over white BG
    bg = Image.new("RGBA", src.size, BG + (255,))
    composed = Image.alpha_composite(bg, src).convert("RGB")
    # crop to figure bbox (with margin), then resize
    return composed.resize((VIEW_W, VIEW_H), Image.LANCZOS)


def save_gif(frames, path, ms_per_frame, loop=0):
    if not frames:
        return
    frames[0].save(
        path,
        save_all=True,
        append_images=frames[1:],
        duration=ms_per_frame,
        loop=loop,        # 0 = infinite loop
        optimize=True,
        disposal=2,
    )
    print(f"  ✓ {path.name}  {len(frames)} frames @ {ms_per_frame}ms  "
          f"({path.stat().st_size//1024} KB)")


print(f"Loading and rendering frames at {VIEW_W}×{VIEW_H}...")
loaded = {}  # (action, idx) -> Image
for action, n in ACTION_FRAMES.items():
    for i in range(n):
        loaded[(action, i)] = load_frame(action, i)
print(f"  loaded {len(loaded)} frames")
print()

# -----------------------------------------------------------------------------
# Per-action loops (forward play)
# -----------------------------------------------------------------------------
print("Per-action loops:")
for action, n in ACTION_FRAMES.items():
    frames = [loaded[(action, i)] for i in range(n)]
    # For non-palindromic actions, also append the reverse so the loop is
    # smooth (otherwise the last→first transition is a hard cut)
    if action not in ("idle_breathe",):  # idle is already palindromic
        frames = frames + list(reversed(frames))[1:-1]  # drop the duplicate ends
    save_gif(frames, OUT_DIR / f"anim_{action}.gif", TIMINGS_MS[action])

print()

# -----------------------------------------------------------------------------
# Composability demos
# -----------------------------------------------------------------------------
print("Composability demos:")

# Demo 1: mirror trick — wave with right arm, then wave with left arm (flipped)
wave_right = [loaded[("wave", i)] for i in range(ACTION_FRAMES["wave"])]
wave_left  = [ImageOps.mirror(f) for f in wave_right]
mirror_demo = wave_right + wave_right[-2:0:-1] + wave_left + wave_left[-2:0:-1]
save_gif(mirror_demo, OUT_DIR / "demo_mirror_trick.gif", 140)

# Demo 2: reverse trick — bow down, then bow up (same frames, reversed)
bow_down = [loaded[("bow", i)] for i in range(ACTION_FRAMES["bow"])]
bow_up   = list(reversed(bow_down))
reverse_demo = bow_down + bow_up
save_gif(reverse_demo, OUT_DIR / "demo_reverse_trick.gif", 200)

# Demo 3: a small choreographed sequence stringing actions together
def cyc(name):
    n = ACTION_FRAMES[name]
    f = [loaded[(name, i)] for i in range(n)]
    if name not in ("idle_breathe",):
        f = f + list(reversed(f))[1:-1]
    return f

sequence = (
    cyc("idle_breathe") +
    cyc("idle_breathe") +
    cyc("wave") +
    cyc("idle_breathe") +
    cyc("bow") +
    cyc("idle_breathe") +
    cyc("spin_half_cw") +
    cyc("idle_breathe") +
    cyc("lift_skirt") +
    cyc("idle_breathe")
)
save_gif(sequence, OUT_DIR / "demo_sequence.gif", 170)

# Demo 4: mirror + reverse showing 4× expansion from one clip
#   wave_right_out  → wave_right_in (reverse)
#   wave_left_out   → wave_left_in  (mirror+reverse)
wro = wave_right
wri = list(reversed(wave_right))
wlo = wave_left
wli = list(reversed(wave_left))
expansion_demo = wro + wri[1:] + wlo[1:] + wli[1:]
save_gif(expansion_demo, OUT_DIR / "demo_4x_expansion.gif", 140)

print()
print("All animations in", OUT_DIR)
