"""Generate a 12-second Sora-2 choreography clip.

Choreography:
  0.0-1.0s   stand neutral at far LEFT of frame
  1.0-4.0s   walk from left to RIGHT, smooth pace (~3 steps)
  4.0-5.0s   turn around (180° rotation in place) at far right
  5.0-7.0s   walk back from right to MIDDLE of frame
  7.0-7.5s   stand neutral
  7.5-8.5s   point LEFT with left arm extended, hold for 1 beat
  8.5-9.0s   arm down, return to neutral
  9.0-11.0s  jumping jacks — 3 to 4 reps
  11.0-11.5s small lateral JUMP to the RIGHT
  11.5-12.0s stand neutral

Each segment becomes a labeled transition in the eventual motion-sprite
quipu (extracted via frame timestamps in post-processing).

Same character + framing + chroma-green-screen constraints as the
walking_right test pass.
"""
import os, sys, json, time
from pathlib import Path

import openai

THIS_DIR = Path(__file__).parent
OUT_DIR  = THIS_DIR / "sora"
OUT_DIR.mkdir(parents=True, exist_ok=True)

CHARACTER = """\
A contemporary dancer, woman in her late twenties, in plain dance-studio attire:
long-sleeved white leotard with no pattern, matching white footless leggings,
bare feet. Dark hair pulled back into a sleek low bun at the nape of her neck,
no braid, no ribbon, no loose strands. Athletic build, calm focused expression.
Skin tone: medium / warm. THE SAME PERSON throughout the entire video — same
face, same outfit, same hair — no identity changes.
"""

FRAMING = """\
Medium-wide shot. The dancer occupies 50-60% of the vertical frame height
— large enough that her feet and steps are clearly visible. The camera is
locked off COMPLETELY — no pan, no tilt, no zoom, no shake, no dolly, no
movement of any kind. Camera angle: eye-level, perfectly horizontal. The
dancer's full body visible from head to feet throughout the entire video.

Background: a solid bright chroma-green screen, hex #00B140 / RGB (0,177,64),
filling the entire frame edge-to-edge, no patterns, no texture, no variation,
no shadow on the green. Lighting: soft, even, flat, no harsh cast shadows
under the figure. The figure stays clearly separated from the green at all
times.

Her apparent size remains constant — no perspective scaling, no foreshortening.
Treat the scene as a near-orthographic side view.
"""

CHOREOGRAPHY = """\
THE DANCER PHYSICALLY TRANSLATES ACROSS THE FRAME — this is the most
important requirement of the entire video. Her body LITERALLY MOVES from
one side of the green screen to the other. She does not walk in place.
Her feet step forward and her position shifts horizontally each step.
You should see her starting position is different from her ending position
in every walking segment.

12-second choreography, ten beats:

  Beat 1 (0.0 - 1.0s): STANDS still at the FAR LEFT edge of the frame,
    facing the camera. Arms relaxed at sides. Her body is positioned in
    the leftmost ~15% of the frame width. No movement at all.

  Beat 2 (1.0 - 4.0s): WALKS HORIZONTALLY across the green screen, from
    the far LEFT to the far RIGHT. About 4 steps. Her body physically
    translates rightward — her position at second 4 is in the rightmost
    ~15% of the frame, completely separated from her position at second 1.
    Arms swing naturally in counter-rhythm with steps. She faces to her
    right (camera's right) as she walks.

  Beat 3 (4.0 - 5.0s): TURNS AROUND 180° in place at the far right.
    Smooth rotation, ends facing to her left (camera's left).

  Beat 4 (5.0 - 7.0s): WALKS HORIZONTALLY back from the far right toward
    the CENTER of the frame. About 3 steps. She physically translates
    leftward — her ending position at second 7 is in the dead-center of
    the frame width.

  Beat 5 (7.0 - 7.5s): Stops in the middle. Turns to face the camera.
    Neutral idle pose, arms at sides.

  Beat 6 (7.5 - 8.5s): Raises her LEFT arm and POINTS toward the left
    side of the frame — arm fully extended horizontally at shoulder
    height. Holds.

  Beat 7 (8.5 - 9.0s): Lowers arm. Neutral idle.

  Beat 8 (9.0 - 11.0s): JUMPING JACKS in place — 3 to 4 full reps. Arms
    swing up overhead while legs spread wide; then arms back to sides
    while feet come together. Rhythmic.

  Beat 9 (11.0 - 11.5s): Small lateral JUMP to her RIGHT — both feet
    leave the ground and land about half a body-width to her right.

  Beat 10 (11.5 - 12.0s): Lands and stands neutral, facing camera.

Critical: the walking beats (2 and 4) MUST show real horizontal
translation. Her position at the END of each walking beat must be at
least 40-50% of the frame width away from her position at the START of
that beat. Walking in place is FORBIDDEN.
"""

NEGATIVES = """\
NO walking-in-place. NO shuffling. NO camera movement of any kind. NO zoom.
NO pan. NO tilt. NO motion blur. NO ground shadow under her feet. NO
additional figures. NO extra objects. NO text overlays. NO logos,
watermarks, captions, or labels. NO change in her apparent size as she
moves around the frame. NO identity drift — same face, hair, outfit
throughout. NO crop or letterboxing — fill the entire 1280x720 frame
with the scene from edge to edge.
"""

PROMPT = "\n\n".join([CHARACTER, FRAMING, CHOREOGRAPHY, NEGATIVES]).strip()


def main():
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("ERROR: OPENAI_API_KEY not set", file=sys.stderr); sys.exit(1)

    client = openai.OpenAI(api_key=api_key)

    out_path = OUT_DIR / "choreo_12s_v2.mp4"
    meta_path = OUT_DIR / "choreo_12s_v2.json"

    if out_path.exists():
        print(f"  ↺ {out_path.name} already exists, skipping generation")
        print(f"     delete it to regenerate")
        return

    print("PROMPT (excerpt):")
    print("-" * 72)
    for line in PROMPT.split("\n")[:12]:
        print(line)
    print(f"... ({len(PROMPT)} chars total)")
    print("-" * 72)
    print()

    print(f"Submitting Sora-2 video job (12s choreography)...")
    print(f"  model:    sora-2-pro")
    print(f"  size:     1280x720")
    print(f"  seconds:  12")
    t0 = time.time()

    video = client.videos.create_and_poll(
        model="sora-2-pro",
        prompt=PROMPT,
        size="1280x720",
        seconds="12",
    )
    elapsed = time.time() - t0
    print(f"  status:   {video.status}  (after {elapsed:.0f}s)")

    if video.status != "completed":
        print(f"ERROR: video status = {video.status}", file=sys.stderr)
        print(f"  full: {video.model_dump_json(indent=2)}")
        sys.exit(1)

    print(f"  downloading...")
    content = client.videos.download_content(video.id, variant="video")
    content.write_to_file(str(out_path))
    print(f"  ✓ saved: {out_path}  ({out_path.stat().st_size//1024} KB)")

    meta = {
        "video_id":     video.id,
        "model":        "sora-2-pro",
        "size":         "1280x720",
        "seconds":      "12",
        "prompt":       PROMPT,
        "elapsed_s":    elapsed,
        "status":       video.status,
        "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        # Pre-baked segment timestamps for later cutting + labeling
        "segments": [
            {"t0": 0.0,  "t1": 1.0,  "label": "neutral_left"},
            {"t0": 1.0,  "t1": 4.0,  "label": "walk_right"},
            {"t0": 4.0,  "t1": 5.0,  "label": "turn_around"},
            {"t0": 5.0,  "t1": 7.0,  "label": "walk_to_middle"},
            {"t0": 7.0,  "t1": 7.5,  "label": "neutral_middle"},
            {"t0": 7.5,  "t1": 8.5,  "label": "point_left"},
            {"t0": 8.5,  "t1": 9.0,  "label": "neutral_middle"},
            {"t0": 9.0,  "t1": 11.0, "label": "jumping_jacks"},
            {"t0": 11.0, "t1": 11.5, "label": "jump_right"},
            {"t0": 11.5, "t1": 12.0, "label": "neutral_after_jump"},
        ],
    }
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False))
    print(f"  ✓ metadata: {meta_path}")


if __name__ == "__main__":
    main()
