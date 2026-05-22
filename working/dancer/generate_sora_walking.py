"""Generate a Sora-2 video of the dancer walking across the frame.

Specifications:
  - wide shot, telephoto-compressed perspective
  - static locked-off camera, no movement
  - dancer occupies ~30-40% of vertical frame height (far from camera)
  - solid bright green-screen background for chroma-key matting
  - walking RIGHT — the mirror trick gives walking LEFT for free
  - 1280×720 landscape, 8 seconds, sora-2 (not pro for first test)

Output: working/dancer/sora/walking_right.mp4 + metadata JSON
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
no braid, no ribbon, no loose strands. Athletic build, calm focused expression,
looking forward in the direction of travel. Skin tone: medium / warm.
"""

FRAMING = """\
Wide-shot, telephoto / long-lens cinematography compressing the perspective.
The dancer is far from the camera and occupies only the central 30-35% of the
vertical frame height. The camera is locked off completely — no pan, no tilt,
no zoom, no shake, no dolly. Camera ANGLE: eye-level, perfectly horizontal,
the dancer's full body visible from head to feet throughout.

Background: a solid bright chroma-green screen, hex #00B140 / RGB (0,177,64),
filling the entire frame edge-to-edge, no patterns, no texture, no variation,
no shadow on the green. Lighting is soft, even, flat — no harsh cast shadows
under the figure. The figure stays clearly separated from the green at all
times.

The dancer's apparent SIZE remains constant across the frame as she walks —
no perspective scaling, no foreshortening change. Treat the scene as a
near-orthographic side view.
"""

ACTION = """\
She walks calmly and steadily from the LEFT side of the frame toward the
RIGHT side, in a natural relaxed walking pace. Approximately one step per
second. Her arms swing naturally and gently in counter-rhythm with her legs.
Her gaze stays forward in the direction of travel. The walk is smooth and
even — no hesitation, no looking around, no gesture changes. Just walking.

She enters the frame from the left edge at the start of the video and exits
through the right edge at the end. Her vertical position in the frame
remains constant.
"""

NEGATIVES = """\
NO camera movement. NO zoom. NO pan. NO tilt. NO motion blur. NO ground
shadow under her feet. NO extra figures. NO additional objects. NO text
overlays. NO logos or watermarks. NO change in her apparent size as she
moves. NO crop or letterboxing — fill the entire frame with the scene.
"""

PROMPT = "\n\n".join([CHARACTER, FRAMING, ACTION, NEGATIVES]).strip()


def main():
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("ERROR: OPENAI_API_KEY not set", file=sys.stderr); sys.exit(1)

    client = openai.OpenAI(api_key=api_key)

    out_path = OUT_DIR / "walking_right.mp4"
    meta_path = OUT_DIR / "walking_right.json"

    if out_path.exists():
        print(f"  ↺ {out_path.name} already exists, skipping generation")
        print(f"     delete it to regenerate")
        return

    print("PROMPT:")
    print("-" * 72)
    print(PROMPT)
    print("-" * 72)
    print()

    print(f"Submitting Sora-2 video job...")
    print(f"  model:    sora-2")
    print(f"  size:     1280x720")
    print(f"  seconds:  8")
    t0 = time.time()

    # create_and_poll handles the async job pattern automatically:
    # create video job → poll status → return when 'completed' or 'failed'
    video = client.videos.create_and_poll(
        model="sora-2",
        prompt=PROMPT,
        size="1280x720",
        seconds="8",
    )
    elapsed = time.time() - t0
    print(f"  status:   {video.status}  (after {elapsed:.0f}s)")

    if video.status != "completed":
        print(f"ERROR: video status = {video.status}", file=sys.stderr)
        print(f"  full: {video.model_dump_json(indent=2)}")
        sys.exit(1)

    # Download the video binary
    print(f"  downloading...")
    content = client.videos.download_content(video.id, variant="video")
    content.write_to_file(str(out_path))
    print(f"  ✓ saved: {out_path}  ({out_path.stat().st_size//1024} KB)")

    # Save metadata
    meta = {
        "video_id":  video.id,
        "model":     "sora-2",
        "size":      "1280x720",
        "seconds":   "8",
        "prompt":    PROMPT,
        "elapsed_s": elapsed,
        "status":    video.status,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False))
    print(f"  ✓ metadata: {meta_path}")


if __name__ == "__main__":
    main()
