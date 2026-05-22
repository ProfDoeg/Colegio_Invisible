"""Generate character-reference images of the dancer via gpt-image-1.

Outputs 4 reference images to working/dancer/refs/.

Uses OpenAI's gpt-image-1 model with background="transparent" so the
images come back with a native alpha channel — no chroma-keying or
post-matting needed.

Persona is intentionally specific (Argentine criolla folkloric dancer
in the Bordado-universe aesthetic) so future action-pose generations
have a stable character to anchor against. Bilateral idle pose,
moment-of-balance composition — sets up the palindromic / reversible
clip strategy.
"""
import os, sys, json, time, base64
from pathlib import Path

import openai

THIS_DIR = Path(__file__).parent
OUT_DIR  = THIS_DIR / "refs"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# -------- the character --------------------------------------------------
# This description is intentionally detailed so action-pose generations
# can be conditioned identically. Lock once, reuse across all clips.

CHARACTER = """\
A young woman dancer in Argentine pampa folkloric attire (china criolla
style): a flowing knee-length dark blue skirt with embroidered red and
white botanical motifs along the hem, a simple white blouse with puffed
short sleeves, a red sash at the waist, soft leather flat shoes. Her
long dark hair is in a single braid down her back, tied with a red
ribbon. Mid-twenties, brown skin, calm focused expression, looking
straight ahead.\
"""

# -------- the four reference poses ---------------------------------------
# All bilateral, weight-balanced, full-body, centered. These set the
# character; later we'll generate action clips that ANIMATE between
# variations of these.

POSES = [
    {
        "name":   "ref_01_idle_front",
        "prompt": (
            f"{CHARACTER} "
            "Standing in a calm idle pose, feet shoulder-width apart, "
            "weight distributed evenly between left and right, "
            "both arms relaxed at her sides, palms facing inward. "
            "Bilateral symmetric posture — the figure could be doing the "
            "same thing on either side. Facing directly forward, full body "
            "visible from head to feet, centered composition. "
            "Hand-drawn folk-art illustration style reminiscent of South "
            "American textile embroidery and Argentine pampa folklore. "
            "Simple flat shapes, clear silhouette, soft warm colors, "
            "no shading gradients. NOT photorealistic. "
            "Plain white-paper background that will be made transparent."
        ),
    },
    {
        "name":   "ref_02_idle_threequarter",
        "prompt": (
            f"{CHARACTER} "
            "Same idle pose, but body turned slightly to her right so the "
            "viewer sees her at a three-quarter angle. Weight still even, "
            "arms still relaxed and symmetric at her sides. "
            "Full body visible, centered composition. "
            "Same hand-drawn folk-art illustration style as the other "
            "reference images — flat shapes, soft warm colors, clear "
            "silhouette. NOT photorealistic. "
            "Plain white-paper background that will be made transparent."
        ),
    },
    {
        "name":   "ref_03_arms_extended",
        "prompt": (
            f"{CHARACTER} "
            "Standing in a bilateral arms-extended pose: both arms raised "
            "to shoulder height, palms facing forward, in mirror-image "
            "symmetry. Feet still shoulder-width apart, weight balanced. "
            "Facing forward, full body visible, centered composition. "
            "Same hand-drawn folk-art illustration style — flat shapes, "
            "soft warm colors, clear silhouette. NOT photorealistic. "
            "Plain white-paper background that will be made transparent."
        ),
    },
    {
        "name":   "ref_04_step_right_midstride",
        "prompt": (
            f"{CHARACTER} "
            "Mid-stride stepping to her right: right foot extended outward, "
            "weight shifting onto the right leg, left foot still on the "
            "ground behind. Right arm slightly forward for balance, left "
            "arm slightly back. Skirt flowing slightly with motion. "
            "Facing forward, full body visible, centered composition. "
            "Same hand-drawn folk-art illustration style — flat shapes, "
            "soft warm colors, clear silhouette. NOT photorealistic. "
            "Plain white-paper background that will be made transparent."
        ),
    },
]


def generate(client, name, prompt):
    out_path = OUT_DIR / f"{name}.png"
    meta_path = OUT_DIR / f"{name}.json"

    if out_path.exists():
        print(f"  ↺ {name}  already exists, skipping")
        return out_path

    print(f"  → {name}  generating (~10-30s)...")
    t0 = time.time()
    resp = client.images.generate(
        model="gpt-image-1",
        prompt=prompt,
        size="1024x1536",       # portrait, fits full-body figure
        quality="high",
        background="transparent",
        output_format="png",
        n=1,
    )
    elapsed = time.time() - t0

    img_b64 = resp.data[0].b64_json
    img_bytes = base64.b64decode(img_b64)
    out_path.write_bytes(img_bytes)

    meta = {
        "name":      name,
        "prompt":    prompt,
        "model":     "gpt-image-1",
        "size":      "1024x1536",
        "quality":   "high",
        "background":"transparent",
        "elapsed_s": elapsed,
        "bytes":     len(img_bytes),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False))

    print(f"  ✓ {name}  {len(img_bytes)//1024} KB, {elapsed:.1f}s")
    return out_path


def verify_transparency(path):
    """Confirm the generated PNG has alpha and the corners are transparent."""
    from PIL import Image
    img = Image.open(path)
    if img.mode != "RGBA":
        print(f"  ⚠ {path.name}  not RGBA mode ({img.mode})")
        return False
    # Sample the four corners
    w, h = img.size
    corners = [(0, 0), (w-1, 0), (0, h-1), (w-1, h-1)]
    alpha_values = [img.getpixel(c)[3] for c in corners]
    transparent = all(a < 16 for a in alpha_values)
    print(f"  {'✓' if transparent else '⚠'} {path.name}  mode={img.mode} size={w}×{h} "
          f"corner-alpha={alpha_values}")
    return transparent


def main():
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("ERROR: OPENAI_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    client = openai.OpenAI(api_key=api_key)

    print(f"Generating {len(POSES)} dancer reference images")
    print(f"  → output: {OUT_DIR}")
    print()

    paths = []
    for pose in POSES:
        path = generate(client, pose["name"], pose["prompt"])
        paths.append(path)

    print()
    print("Verifying transparency...")
    for path in paths:
        verify_transparency(path)

    print()
    print("Done. Inspect images at:")
    for path in paths:
        print(f"  {path}")


if __name__ == "__main__":
    main()
