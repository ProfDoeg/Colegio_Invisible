"""Generate action-pose frame sequences for the dancer.

Eight named base actions, ~35 frames total. Each frame is a single
gpt-image-1 generation with a pose-specific prompt. The CHARACTER and
FRAMING blocks are locked across all calls so the persona stays
consistent and the alpha matting stays clean.

Effective vocabulary via mirror + reverse:
    idle_breathe        ×1   bilateral palindrome
    step_right          ×4   mirror→step_left, reverse→step_back
    wave                ×4   mirror→wave_left, reverse→wave_in
    bow                 ×2   reverse→rise_from_bow
    spin_half_cw        ×4   mirror→ccw, reverse→spin_back
    point_right         ×4   mirror→point_left, reverse→retract
    reach_up_bilateral  ×2   reverse→arms_down
    lift_skirt          ×2   reverse→release_skirt
                       ────
                        23 effective named transitions

Runs generations in parallel via ThreadPoolExecutor (8 workers). Skips
any frame whose output PNG already exists. Each frame's prompt and
metadata are saved alongside as JSON for reproducibility.
"""
import os, sys, json, time, base64
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import openai

THIS_DIR = Path(__file__).parent
OUT_DIR  = THIS_DIR / "actions"
OUT_DIR.mkdir(parents=True, exist_ok=True)


# ----------------------------------------------------------------------------
# Locked character description (identical to generate_refs.py — must match
# for consistent persona across reference + action generations)
# ----------------------------------------------------------------------------

CHARACTER = """\
A young woman dancer in Argentine pampa folkloric attire (china criolla
style): a flowing knee-length dark blue skirt with embroidered red and
white botanical motifs along the hem, a simple white blouse with puffed
short sleeves, a red sash at the waist, soft leather flat shoes. Her
long dark hair is in a single braid down her back, tied with a red
ribbon. Mid-twenties, brown skin, calm focused expression.\
"""

# Framing instructions — added to every prompt to enforce consistent
# composition, no shadow, transparent background.
FRAMING = """\
Full body visible from head to feet, centered composition.
Hand-drawn folk-art illustration style reminiscent of South American
textile embroidery and Argentine pampa folklore — flat shapes, soft
warm colors, clear silhouette, no shading gradients. NOT photorealistic.
NO ground shadow, NO cast shadow, NO ground plane, NO surface beneath
the figure. The figure floats completely separate from any background.
Plain white-paper background that will be made transparent.\
"""


# ----------------------------------------------------------------------------
# The action vocabulary — each action is a list of pose-specific prompts,
# one per frame. Frames are ordered from start to end of the action arc.
# ----------------------------------------------------------------------------

ACTIONS = {
    # palindromic breath cycle: F0 → F1 → F0
    "idle_breathe": [
        "Standing calm idle pose, feet shoulder-width apart, weight evenly "
        "balanced, both arms relaxed at her sides palms facing inward. "
        "Shoulders relaxed at neutral height. Bilateral symmetric posture. "
        "Facing directly forward.",
        "Same standing idle pose, but in mid-inhalation: shoulders raised "
        "slightly, chest expanded slightly, head tilted very slightly upward. "
        "Arms still relaxed at sides. Bilateral symmetric. Facing forward.",
        "Standing calm idle pose, feet shoulder-width apart, weight evenly "
        "balanced, both arms relaxed at her sides palms facing inward. "
        "Shoulders relaxed at neutral height. Bilateral symmetric posture. "
        "Facing directly forward.",  # same as F0 — palindromic close
    ],

    # 5-frame walk cycle to the right (mirror for left)
    "step_right": [
        "Standing in neutral pose, feet together, facing forward, arms "
        "relaxed at sides.",
        "Beginning to step to her right: right foot lifting off the ground, "
        "weight shifting onto left leg, right arm starting to swing slightly "
        "forward for balance, left arm slightly back. Facing forward.",
        "Mid-stride to the right: right foot extended outward and forward, "
        "weight transferring onto the right leg, left foot still planted "
        "behind. Right arm swung forward at hip level, left arm swung back. "
        "Skirt flowing slightly with motion. Facing forward.",
        "Right foot now planted on the ground to the right, weight fully "
        "shifted right, left foot beginning to lift to follow. Arms in "
        "transition back toward neutral. Facing forward.",
        "Both feet planted again, slightly wider stance than the starting "
        "position (one step to the right). Weight balanced. Arms returning "
        "to neutral at sides. Facing forward.",
    ],

    # 5-frame wave with right arm (mirror for left, reverse for wave-in)
    "wave": [
        "Standing in neutral pose, facing forward, both arms relaxed at "
        "sides.",
        "Right arm beginning to lift, elbow bending slightly, hand at hip "
        "level moving outward. Left arm relaxed at side. Body facing forward.",
        "Right arm raised to chest level, elbow bent at right angle, palm "
        "facing forward. Left arm relaxed at side. Body facing forward.",
        "Right arm fully raised to shoulder height, fully extended outward "
        "and slightly forward, palm open facing forward in a wave gesture. "
        "Left arm relaxed at side. Body facing forward.",
        "Right arm at shoulder height extended, hand now tilted slightly to "
        "the left as part of a waving motion. Left arm relaxed at side. "
        "Body facing forward.",
    ],

    # 5-frame bow (reverse plays as rise from bow)
    "bow": [
        "Standing in neutral pose, facing forward, both arms relaxed at "
        "sides, head upright.",
        "Beginning to bow: head tilting downward slightly, upper body "
        "starting to bend forward at the waist, hands beginning to lift "
        "outward from the sides to grasp the skirt edges.",
        "Halfway through the bow: upper body bent forward at about 30 "
        "degrees, head tilted down, hands now grasping the outer edges of "
        "the skirt and lifting it outward into a small fan.",
        "Deep bow: upper body bent forward at about 60 degrees, head down, "
        "skirt held out in a wide fan shape by hands gripping the edges. "
        "Knees slightly bent.",
        "Fullest bow: upper body bent forward at about 80 degrees, head "
        "nearly horizontal, skirt fanned out wide, knees bent in a curtsy "
        "position. Held pose at the bottom of the bow.",
    ],

    # 5-frame half-rotation clockwise (front → side → back)
    # Mirror → counter-clockwise; reverse → spin back
    "spin_half_cw": [
        "Standing in neutral pose, facing directly forward, arms slightly "
        "out from sides as if mid-rotation, skirt flowing slightly to the "
        "left from rotational motion.",
        "Body rotated 45 degrees clockwise (now showing three-quarter view "
        "from her left side). Arms still slightly out from sides for "
        "balance. Skirt flowing outward with rotation.",
        "Body rotated 90 degrees clockwise — full side profile view, "
        "showing her right side. Arms still slightly out from sides. "
        "Skirt flowing outward with rotation, fanning behind her.",
        "Body rotated 135 degrees clockwise (three-quarter back view from "
        "her right side). Arms still slightly out for balance. Skirt "
        "flowing behind with rotation.",
        "Body rotated 180 degrees — full back view. Braid visible down "
        "her back. Arms slightly out from sides. Skirt flowing.",
    ],

    # 4-frame point to the right (mirror→left, reverse→retract)
    "point_right": [
        "Standing in neutral pose, facing forward, both arms relaxed at "
        "sides.",
        "Right arm beginning to rise outward to the right, elbow slightly "
        "bent. Left arm relaxed at side. Body facing forward.",
        "Right arm raised diagonally outward to the right, hand at "
        "shoulder height, index finger extending. Left arm relaxed at "
        "side. Body facing forward.",
        "Right arm fully extended outward to the right at shoulder height, "
        "index finger fully extended pointing to her right. Left arm "
        "relaxed at side. Body facing forward, but eyes / head turned "
        "slightly to follow the point direction.",
    ],

    # 4-frame bilateral arms-up (reverse plays as arms-down)
    "reach_up_bilateral": [
        "Standing in neutral pose, facing forward, both arms relaxed at "
        "sides.",
        "Both arms beginning to lift outward from sides in bilateral mirror "
        "motion: elbows slightly bent, hands at hip level moving outward "
        "and upward. Bilateral symmetric.",
        "Both arms raised to shoulder height in bilateral mirror, fully "
        "extended outward in a T-shape. Palms facing forward. Bilateral "
        "symmetric. Facing forward.",
        "Both arms raised fully overhead in bilateral mirror, hands almost "
        "touching above her head, palms facing inward. Bilateral symmetric. "
        "Facing forward. Skirt unchanged.",
    ],

    # 4-frame skirt lift (bilateral, reverse plays as release)
    "lift_skirt": [
        "Standing in neutral pose, facing forward, both arms relaxed at "
        "sides.",
        "Both hands moving outward and downward toward the outer edges of "
        "her skirt in bilateral mirror motion. Body facing forward.",
        "Both hands now grasping the outer edges of the skirt at hip "
        "level, beginning to lift outward. Bilateral symmetric.",
        "Both hands lifting the skirt edges fully outward into a wide fan "
        "shape, arms extended outward and slightly upward. Bilateral "
        "symmetric. Facing forward.",
    ],
}


# ----------------------------------------------------------------------------
# Generation
# ----------------------------------------------------------------------------

def build_prompt(pose_specific):
    return f"{CHARACTER}\n\n{pose_specific}\n\n{FRAMING}"


def generate_one(client, action_name, frame_idx, pose_specific):
    name = f"{action_name}_{frame_idx:02d}"
    out_path  = OUT_DIR / f"{name}.png"
    meta_path = OUT_DIR / f"{name}.json"

    if out_path.exists():
        return name, "skipped (exists)", 0.0, out_path.stat().st_size

    prompt = build_prompt(pose_specific)
    t0 = time.time()
    try:
        resp = client.images.generate(
            model="gpt-image-1",
            prompt=prompt,
            size="1024x1536",
            quality="high",
            background="transparent",
            output_format="png",
            n=1,
        )
    except Exception as e:
        return name, f"ERROR: {e}", time.time() - t0, 0
    elapsed = time.time() - t0

    img_bytes = base64.b64decode(resp.data[0].b64_json)
    out_path.write_bytes(img_bytes)

    meta = {
        "name":      name,
        "action":    action_name,
        "frame_idx": frame_idx,
        "prompt":    prompt,
        "model":     "gpt-image-1",
        "size":      "1024x1536",
        "quality":   "high",
        "elapsed_s": elapsed,
        "bytes":     len(img_bytes),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False))

    return name, "ok", elapsed, len(img_bytes)


def main():
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("ERROR: OPENAI_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    client = openai.OpenAI(api_key=api_key)

    # Flatten action list into (action_name, frame_idx, prompt) tuples
    jobs = []
    for action_name, frames in ACTIONS.items():
        for i, pose in enumerate(frames):
            jobs.append((action_name, i, pose))

    total_frames = len(jobs)
    print(f"Generating {total_frames} action-frame images across {len(ACTIONS)} actions")
    print(f"  → output: {OUT_DIR}")
    print(f"  → parallelism: 8 concurrent calls")
    print(f"  → est cost: ${total_frames * 0.16:.2f}")
    print()

    t_start = time.time()
    completed = 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {
            pool.submit(generate_one, client, a, i, p): (a, i)
            for a, i, p in jobs
        }
        for fut in as_completed(futures):
            name, status, elapsed, size = fut.result()
            completed += 1
            kb = size // 1024 if size else 0
            print(f"  [{completed:>2}/{total_frames}] {name:<28} {status:<20} "
                  f"{elapsed:>5.1f}s  {kb:>5} KB")

    wall = time.time() - t_start
    print()
    print(f"Done in {wall:.1f}s ({wall/60:.1f} min).")
    print(f"Files in {OUT_DIR}:")
    for p in sorted(OUT_DIR.glob("*.png")):
        print(f"  {p.name}  {p.stat().st_size//1024} KB")


if __name__ == "__main__":
    main()
