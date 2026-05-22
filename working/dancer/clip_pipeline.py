"""Chained Sora-2 clip pipeline: short focused clips, each conditioned on
the last frame of the previous one.

Pattern:
    clip_1   no reference        e.g. "walk far-left to far-right, turn around"
    clip_2   ref = last(clip_1)  e.g. "walk back to middle"
    clip_3   ref = last(clip_2)  e.g. "point left, drop arm"
    clip_4   ref = last(clip_3)  e.g. "jumping jacks"
    clip_5   ref = last(clip_4)  e.g. "jump right, stand neutral"

The image reference gives Sora a visual anchor — same character, same pose,
same frame position — so successive clips stitch together visually.

Usage:
    # generate clip_1
    python clip_pipeline.py make clip_1

    # generate clip_2 referencing the last frame of clip_1
    python clip_pipeline.py make clip_2

    # also expose helpers:
    python clip_pipeline.py extract <mp4>     # save last frame as PNG
    python clip_pipeline.py status            # list known clips
"""
import os, sys, json, time, subprocess
from pathlib import Path

import openai

THIS_DIR  = Path(__file__).parent
SORA_DIR  = THIS_DIR / "sora"
FRAMES_DIR = THIS_DIR / "sora" / "frames"
SORA_DIR.mkdir(parents=True, exist_ok=True)
FRAMES_DIR.mkdir(parents=True, exist_ok=True)


# ----------------------------------------------------------------------------
# Locked-character + locked-framing blocks (reused in every clip prompt)
# ----------------------------------------------------------------------------

CHARACTER = """\
A contemporary dancer, woman in her late twenties, in plain dance-studio
attire: long-sleeved white leotard with no pattern, matching white footless
leggings, bare feet. Dark hair pulled back into a sleek low bun. Calm focused
expression. The SAME person throughout the video — no identity changes.
"""

FRAMING = """\
WIDE SHOT, telephoto / long-lens cinematography. The dancer occupies about
40% of the vertical frame height — not too small, not too tall. CRITICAL
margin requirements:
  - her FEET are clearly visible, with at least 15% of the frame height
    of empty green BELOW her feet (between her feet and the bottom edge
    of the frame)
  - her HEAD is clearly visible, with at least 15% of the frame height
    of empty green ABOVE her head (between her head and the top edge of
    the frame)
  - her body is NOT clipped at the top OR bottom of the frame
  - she has plenty of empty green to her left and right for walking

THE CAMERA IS A FIXED TRIPOD-MOUNTED CCTV-STYLE STATIC CAMERA. The
camera does not move. The camera does not pan. The camera does not tilt.
The camera does not zoom. The camera does not dolly. The camera does
NOT follow or track the subject. The 1280x720 frame is a FIXED WINDOW
looking at a fixed scene; the subject moves through this window. If the
subject walks to the edge of the frame, she goes out of the frame —
the camera DOES NOT move to keep her in view.

Think of this as: a single locked-off security-camera shot, or a stage
proscenium view from a fixed seat in the audience, or a Wes-Anderson-style
perfectly symmetric tableau where the camera never moves throughout the
entire take.

Background: solid bright chroma-green screen, hex #00B140 / RGB (0,177,64),
filling the entire 1280x720 frame edge to edge. The green stays IN THE
EXACT SAME POSITION every frame — the green never shifts, never reframes,
never moves within the frame. No patterns, no texture, no variation. Soft
even lighting, no harsh shadows on the green. The figure stays clearly
separated from the green at all times.
"""

NEGATIVES = """\
ABSOLUTELY NO CAMERA TRACKING. NO subject tracking. NO subject centering.
The camera DOES NOT FOLLOW the dancer. NO camera movement of any kind.
NO pan. NO tilt. NO zoom. NO shake. NO dolly. NO reframing. NO recomposition.
The framing at second 1 of the video is identical to the framing at second
8. NO walking-in-place. NO shuffling. NO motion blur. NO ground shadow.
NO extra figures. NO objects. NO text overlays. NO logos. NO identity
drift. NO crop or letterboxing. NO digital zoom. NO virtual camera.
NO clipping of the dancer's feet. NO clipping of the dancer's head.
NO clipping of any part of her body. She is ALWAYS fully in frame with
generous margin above and below her.
"""


# ----------------------------------------------------------------------------
# The clips — each is a short focused action
# ----------------------------------------------------------------------------

CLIPS = {
    "clip_1_walk_left_to_right": {
        "seconds": "8",
        "model":   "sora-2",
        "ref_clip": None,             # first clip, no reference
        "action": """\
SINGLE ACTION across 8 seconds:

Seconds 0-1: The dancer stands STILL at the FAR LEFT of the frame, in
the leftmost ~15% of the frame width, with her FULL BODY VISIBLE inside
the frame (feet visible at the bottom, head visible at the top, margins
on all sides). She faces to her right (camera's right). No movement.

Seconds 1-6: She walks at a calm steady pace from the FAR LEFT to the
FAR RIGHT of the frame. About 4 steps. Arms swing naturally in
counter-rhythm. She faces her direction of travel (camera's right)
throughout — she does NOT turn around.

Seconds 6-8: She stops walking and stands STILL at the FAR RIGHT of
the frame. Her ENDING POSITION: her body is in the rightmost ~15% of
the frame width, with her FULL BODY STILL VISIBLE INSIDE THE FRAME —
she does NOT exit the right edge of the frame, she does NOT walk off
screen. She stops with margin between her body and the right edge.
She is still facing right (no turn).

The fixed camera does not follow her — the frame composition (the
amount of green, the position of the floor line, the height of the
frame) is identical at second 0 and at second 8. Only the dancer has
moved within the fixed frame.
""",
    },

    "clip_2_turn_around_at_right": {
        "seconds": "4",
        "model":   "sora-2",
        "ref_clip": "clip_1_walk_left_to_right",
        "action": """\
SINGLE ACTION across 4 seconds:

Seconds 0-1: The dancer (standing at the FAR RIGHT of the frame facing
right, from the reference image) stands still in her starting pose.

Seconds 1-3: She turns around 180 degrees in place — a smooth pivot.
She stays in the SAME horizontal position throughout — she does not
walk, she does not translate, she only rotates her body. Her feet stay
in the same spot.

Seconds 3-4: She has finished the rotation and stands still, now
facing the opposite direction (camera's LEFT), still at the far right
of the frame.

The fixed camera does not move. The frame composition (amount of green
on each side, position of the floor line) is identical at second 0 and
second 4 — only the dancer's facing direction has changed.
""",
    },

    "clip_3_walk_right_to_left": {
        "seconds": "8",
        "model":   "sora-2",
        "ref_clip": "clip_2_turn_around_at_right",
        "action": """\
SINGLE ACTION across 8 seconds:

Seconds 0-1: The dancer (standing at the FAR RIGHT of the frame facing
LEFT, from the reference image) stands still in her starting pose.

Seconds 1-6: She walks at a calm steady pace from the FAR RIGHT all the
way to the FAR LEFT of the frame. About 4 steps. Arms swing naturally in
counter-rhythm. She faces her direction of travel (camera's left)
throughout — she does NOT turn around.

Seconds 6-8: She stops walking and stands STILL at the FAR LEFT of the
frame. Her ENDING POSITION: her body is in the leftmost ~15% of the frame
width, with her FULL BODY STILL VISIBLE INSIDE THE FRAME — she does NOT
exit the left edge, she does NOT walk off screen. She stops with margin
between her body and the left edge. Still facing left.

The fixed camera does not follow her — the frame composition is identical
at second 0 and second 8. Only the dancer has moved within the fixed
frame.
""",
    },

    "clip_4_face_camera_and_point_left": {
        "seconds": "4",
        "model":   "sora-2",
        "ref_clip": "clip_3_walk_right_to_left",
        "action": """\
SINGLE ACTION: The dancer (standing in the middle of the frame, facing
left, from the reference image) first turns to face the camera (forward),
then raises her LEFT arm and points to the left side of the frame — arm
fully extended horizontally at shoulder height. Holds for 2 seconds. Then
lowers arm back to her side. She stays in the dead-center of the frame
horizontally throughout. No walking, no horizontal translation.
""",
    },

    "clip_5_jumping_jacks": {
        "seconds": "4",
        "model":   "sora-2",
        "ref_clip": "clip_4_face_camera_and_point_left",
        "action": """\
SINGLE ACTION: The dancer (standing in the middle of the frame facing
forward, from the reference image) performs JUMPING JACKS in place.
Three full repetitions. Each rep: jump while arms swing up overhead and
legs spread wide apart, then jump again to bring arms down to sides and
feet together. Rhythmic, athletic. She stays in the EXACT CENTER of the
frame horizontally — no walking, no translation. Only vertical jump
motion and arm/leg spreads.
""",
    },

    "clip_6_jump_right": {
        "seconds": "4",
        "model":   "sora-2",
        "ref_clip": "clip_5_jumping_jacks",
        "action": """\
SINGLE ACTION: The dancer (standing in the middle of the frame, facing
forward, from the reference image) performs a small lateral JUMP to her
right (camera's right). Both feet leave the ground and land about half a
body-width to her right. Arms slightly extended for balance. After
landing, she stands in calm neutral idle pose, facing forward.
""",
    },
}


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def extract_last_frame(mp4_path, out_png):
    """Use ffmpeg to extract the very last frame of an mp4 as a PNG."""
    if not mp4_path.exists():
        raise FileNotFoundError(mp4_path)
    # -sseof -1 seeks to 1s before end; then -vframes 1 grabs one frame
    cmd = ["ffmpeg", "-y", "-sseof", "-0.1", "-i", str(mp4_path),
           "-vframes", "1", "-update", "1", str(out_png)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"ffmpeg failed:\n{r.stderr}")
    if not out_png.exists() or out_png.stat().st_size == 0:
        raise RuntimeError(f"ffmpeg ran but no output at {out_png}")
    return out_png


def build_prompt(action_text):
    return "\n\n".join([CHARACTER, FRAMING, action_text, NEGATIVES]).strip()


def clip_path(name):    return SORA_DIR  / f"{name}.mp4"
def meta_path(name):    return SORA_DIR  / f"{name}.json"
def lastframe_path(name): return FRAMES_DIR / f"{name}_lastframe.png"


def make_clip(name):
    if name not in CLIPS:
        print(f"unknown clip: {name}")
        print(f"available: {list(CLIPS.keys())}")
        sys.exit(1)

    cfg = CLIPS[name]
    out_mp4 = clip_path(name)

    if out_mp4.exists():
        print(f"  ↺ {out_mp4.name} already exists, skipping")
        print(f"     delete it to regenerate")
        return

    # Resolve reference image
    ref_kwarg = {}
    if cfg["ref_clip"]:
        ref_png = lastframe_path(cfg["ref_clip"])
        if not ref_png.exists():
            # try to extract it from the predecessor's mp4
            prev_mp4 = clip_path(cfg["ref_clip"])
            if prev_mp4.exists():
                print(f"  extracting last frame of {cfg['ref_clip']} for reference...")
                extract_last_frame(prev_mp4, ref_png)
            else:
                print(f"ERROR: ref_clip {cfg['ref_clip']} has no mp4 — generate it first")
                sys.exit(1)
        # Open as a binary file handle for Sora's input_reference
        ref_kwarg["input_reference"] = open(ref_png, "rb")
        print(f"  using reference: {ref_png.name}")

    prompt = build_prompt(cfg["action"])
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("ERROR: OPENAI_API_KEY not set", file=sys.stderr); sys.exit(1)
    client = openai.OpenAI(api_key=api_key)

    print(f"Submitting Sora job: {name}")
    print(f"  model:    {cfg['model']}")
    print(f"  seconds:  {cfg['seconds']}")
    print(f"  ref_clip: {cfg['ref_clip']}")
    print(f"  prompt:   {prompt[:140]}...")
    t0 = time.time()
    video = client.videos.create_and_poll(
        model=cfg["model"],
        prompt=prompt,
        size="1280x720",
        seconds=cfg["seconds"],
        **ref_kwarg,
    )
    elapsed = time.time() - t0
    print(f"  status:   {video.status}  (after {elapsed:.0f}s)")

    if video.status != "completed":
        print(f"ERROR: status={video.status}")
        print(video.model_dump_json(indent=2))
        sys.exit(1)

    content = client.videos.download_content(video.id, variant="video")
    content.write_to_file(str(out_mp4))
    print(f"  ✓ saved: {out_mp4}  ({out_mp4.stat().st_size//1024} KB)")

    meta = {
        "video_id":  video.id,
        "name":      name,
        "model":     cfg["model"],
        "seconds":   cfg["seconds"],
        "ref_clip":  cfg["ref_clip"],
        "prompt":    prompt,
        "elapsed_s": elapsed,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    meta_path(name).write_text(json.dumps(meta, indent=2, ensure_ascii=False))

    # Extract the last frame so the next clip in the chain can reference it
    out_frame = lastframe_path(name)
    extract_last_frame(out_mp4, out_frame)
    print(f"  ✓ last frame extracted: {out_frame.name}")


def status():
    print(f"{'clip':<32} {'mp4':<6} {'last-frame':<12}")
    print("-" * 56)
    for name, cfg in CLIPS.items():
        has_mp4 = clip_path(name).exists()
        has_frame = lastframe_path(name).exists()
        print(f"{name:<32} "
              f"{'✓' if has_mp4 else '·':<6} "
              f"{'✓' if has_frame else '·':<12}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: clip_pipeline.py {make CLIP|extract MP4|status}")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "make":
        if len(sys.argv) < 3:
            print("usage: clip_pipeline.py make CLIP_NAME")
            sys.exit(1)
        make_clip(sys.argv[2])
    elif cmd == "extract":
        if len(sys.argv) < 3:
            print("usage: clip_pipeline.py extract path/to.mp4")
            sys.exit(1)
        src = Path(sys.argv[2])
        out = src.with_suffix(".lastframe.png")
        extract_last_frame(src, out)
        print(f"  ✓ {out}")
    elif cmd == "status":
        status()
    else:
        print(f"unknown command: {cmd}")
        sys.exit(1)
