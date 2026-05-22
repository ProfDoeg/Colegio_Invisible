"""Assemble the 35 action frames into a unified sprite sheet.

For each frame:
  1. Open the 1024×1536 RGBA source PNG.
  2. Find the alpha-bounding-box of the dancer (where alpha > threshold).
Across all frames:
  3. Compute the UNION bounding box — the bbox that contains the dancer
     in every frame. This guarantees the dancer never gets clipped, and
     all frames share the same crop dimensions so motion looks anchored.
Per frame:
  4. Crop to the union bbox.
  5. Resize to (sprite_w, sprite_h) preserving aspect ratio with alpha-
     aware LANCZOS resampling.
Layout:
  6. Arrange the 35 frames into a grid, in canonical order:
       row 0: idle_breathe          (3 frames, right-padded)
       row 1: step_right            (5 frames)
       row 2: wave                  (5 frames)
       row 3: bow                   (5 frames)
       row 4: spin_half_cw          (5 frames)
       row 5: point_right           (4 frames, right-padded)
       row 6: reach_up_bilateral    (4 frames, right-padded)
       row 7: lift_skirt            (4 frames, right-padded)
  7. Save a preview PNG (full color depth) AND a quantized variant
     (4-bit RGBA preview, what the inscribed body would look like).
"""
import json
from pathlib import Path
from PIL import Image
import numpy as np

THIS_DIR    = Path(__file__).parent
ACTIONS_DIR = THIS_DIR / "actions"
OUT_DIR     = THIS_DIR / "processed"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Sprite size — each frame in the assembled sheet
SPRITE_W, SPRITE_H = 128, 192

# Canonical row order — this is the order frames will be laid out in the
# sheet, and (after assembly) the order the 0xda motion-sprite type will
# reference them by frame index.
ROWS = [
    ("idle_breathe",       3),
    ("step_right",         5),
    ("wave",               5),
    ("bow",                5),
    ("spin_half_cw",       5),
    ("point_right",        4),
    ("reach_up_bilateral", 4),
    ("lift_skirt",         4),
]
MAX_COLS = max(n for _, n in ROWS)
N_FRAMES = sum(n for _, n in ROWS)

ALPHA_THRESHOLD = 16  # alpha values above this count as "figure"


def find_alpha_bbox(img):
    """Return (left, top, right, bottom) bounding box of the figure
    (where alpha > threshold). Returns None if image has no figure."""
    arr = np.array(img)
    alpha = arr[..., 3]
    mask = alpha > ALPHA_THRESHOLD
    if not mask.any():
        return None
    rows = np.where(mask.any(axis=1))[0]
    cols = np.where(mask.any(axis=0))[0]
    return (int(cols.min()), int(rows.min()),
            int(cols.max()) + 1, int(rows.max()) + 1)


def union_bbox(bboxes):
    """Smallest bbox containing all input bboxes."""
    lefts   = [b[0] for b in bboxes if b]
    tops    = [b[1] for b in bboxes if b]
    rights  = [b[2] for b in bboxes if b]
    bottoms = [b[3] for b in bboxes if b]
    return (min(lefts), min(tops), max(rights), max(bottoms))


def main():
    # ---- Pass 1: open every source, find each frame's bbox ----------------
    print(f"Pass 1: scanning {N_FRAMES} frames for bounding boxes...")
    sources = {}  # name -> (PIL.Image, bbox)
    for action, n_frames in ROWS:
        for i in range(n_frames):
            name = f"{action}_{i:02d}"
            path = ACTIONS_DIR / f"{name}.png"
            if not path.exists():
                raise FileNotFoundError(f"missing {path}")
            img = Image.open(path).convert("RGBA")
            bbox = find_alpha_bbox(img)
            sources[name] = (img, bbox)

    all_bboxes = [b for _, b in sources.values() if b]
    union = union_bbox(all_bboxes)
    union_w = union[2] - union[0]
    union_h = union[3] - union[1]
    print(f"  union bounding box: {union}  ({union_w}×{union_h} px)")
    print()

    # ---- Pass 2: crop each frame to union bbox, resize to sprite size -----
    print(f"Pass 2: cropping + resizing to {SPRITE_W}×{SPRITE_H} sprites...")
    sprites = {}
    for name, (img, _) in sources.items():
        cropped = img.crop(union)
        # alpha-aware lanczos resize
        sprite = cropped.resize((SPRITE_W, SPRITE_H), Image.LANCZOS)
        sprites[name] = sprite

    # ---- Pass 3: lay out into grid ----------------------------------------
    sheet_w = MAX_COLS * SPRITE_W
    sheet_h = len(ROWS)  * SPRITE_H
    sheet = Image.new("RGBA", (sheet_w, sheet_h), (0, 0, 0, 0))

    layout = []  # for the JSON metadata
    for row_idx, (action, n_frames) in enumerate(ROWS):
        for col_idx in range(n_frames):
            name = f"{action}_{col_idx:02d}"
            sprite = sprites[name]
            x = col_idx * SPRITE_W
            y = row_idx * SPRITE_H
            sheet.paste(sprite, (x, y), sprite)
            frame_global_idx = sum(n for _, n in ROWS[:row_idx]) + col_idx
            layout.append({
                "frame_index":     frame_global_idx,
                "action":          action,
                "action_frame":    col_idx,
                "sprite_name":     name,
                "grid_row":        row_idx,
                "grid_col":        col_idx,
                "sheet_x":         x,
                "sheet_y":         y,
            })

    out_path = OUT_DIR / "sprite_sheet_rgba.png"
    sheet.save(out_path)
    print(f"  ✓ sprite sheet saved: {out_path}  ({sheet.size}, "
          f"{out_path.stat().st_size//1024} KB)")

    # ---- Pass 4: also produce a 4-bit-RGBA quantized preview --------------
    print()
    print(f"Pass 4: 4-bit RGBA quantization preview...")
    arr = np.array(sheet)            # H × W × 4 uint8
    # Quantize each channel from 0-255 to 0-15, then back to 0-255 representation
    arr4 = (arr >> 4) << 4          # equivalent to quantize-to-16-levels
    preview = Image.fromarray(arr4, mode="RGBA")
    preview_path = OUT_DIR / "sprite_sheet_4bit_preview.png"
    preview.save(preview_path)
    print(f"  ✓ 4-bit preview saved: {preview_path}  "
          f"({preview_path.stat().st_size//1024} KB)")

    # ---- Layout metadata for the eventual 0xda motion-sprite quipu --------
    print()
    layout_meta = {
        "sprite_w":          SPRITE_W,
        "sprite_h":          SPRITE_H,
        "n_frames":          N_FRAMES,
        "grid_columns":      MAX_COLS,
        "grid_rows":         len(ROWS),
        "sheet_w":           sheet_w,
        "sheet_h":           sheet_h,
        "actions":           [{"name": a, "frame_count": n} for a, n in ROWS],
        "frames":            layout,
        "source_union_bbox": union,
        "source_size":       sources[layout[0]["sprite_name"]][0].size,
    }
    meta_path = OUT_DIR / "sprite_sheet_layout.json"
    meta_path.write_text(json.dumps(layout_meta, indent=2, ensure_ascii=False))
    print(f"  ✓ layout metadata: {meta_path}")

    # ---- Inscription cost estimate ----------------------------------------
    print()
    print("Inscription cost estimate (for the 4-bit RGBA sheet):")
    body_pixels = sheet_w * sheet_h
    for bit_depth in (4, 5, 8):
        bytes_per_pixel = bit_depth * 4 / 8
        body_bytes = int(body_pixels * bytes_per_pixel)
        knots      = (body_bytes + 79) // 80
        doge       = knots * 0.05
        print(f"  RGBA {bit_depth}-bit:  body={body_bytes:>9} B  "
              f"knots={knots:>5}  DOGE={doge:>7.2f}")


if __name__ == "__main__":
    main()
