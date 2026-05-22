# dancer/ — motion-sprite exploratory pipeline

Exploratory work toward the future `0xda` motion-sprite type
(see `docs/quipu-types/` once it lands, and
`memory/dancer_pipeline_status.md` for the design status).

This directory's **scripts** are committed; the **generated artifacts**
(reference images, action frames, sprite sheets, Sora videos) are
gitignored — they are large and regenerable from the scripts.

## What's here

| file | purpose |
|---|---|
| `generate_refs.py` | gpt-image-1 calls for 4 character reference images (full body, transparent BG via `background: "transparent"`). Establishes character persona. |
| `generate_actions.py` | gpt-image-1 calls for 8 named actions × 3-5 frames = 35 frames total. Same character description as the references; pose-specific per frame. Parallel via ThreadPoolExecutor. |
| `assemble_sprite_sheet.py` | crop / resize / quantize the 35 action frames into a unified sprite sheet at multiple sizes (128×192, 64×96, 48×72, 32×48) with cost estimates per inscription size + bit depth. |
| `animate.py` | stitches the 35 frames into per-action looping GIFs + composability demos (mirror trick, reverse trick, choreographed sequence). |
| `generate_sora_walking.py` | early Sora-2 single-clip test (walking-right reference). Established the working framing pattern (30-35% vertical, locked camera, chroma-green background). |
| `generate_sora_choreo.py` | attempt at a 12-second multi-beat choreography clip. Demonstrated that Sora-2 collapses complex temporal sequences — better to chain short clips. |
| `clip_pipeline.py` | chained-clip workflow: short focused 4-8s Sora-2 clips, each conditioned on the last frame of the previous via `input_reference`. The pattern that actually works. |

## Status of the dancer track

**Deferred to ~late May 2026 / early June 2026** until Anthony has
his own dancer datasets to inscribe against — see
`memory/dancer_pipeline_status.md` for the full design summary, the
data model we converged on (frames + per-frame centroid + per-frame
displacement + named-transition graph), and the lessons learned (what
worked in Sora-2 prompting, what to avoid).

The `0x03` image-type extension for RGBA / gray+alpha shipped in
commit `3e0df82` — the on-chain prerequisite for any future dancer
inscription is already in place. The `0xda` type spec itself is
deferred until real assets arrive.

## Reproducing the artifacts

```bash
# from the repo root
export OPENAI_API_KEY=...

.venv/bin/python working/dancer/generate_refs.py          # 4 reference PNGs
.venv/bin/python working/dancer/generate_actions.py       # 35 action frames
.venv/bin/python working/dancer/assemble_sprite_sheet.py  # sprite sheets + previews
.venv/bin/python working/dancer/animate.py                # GIFs for inspection

# Sora-2 chained-clip pipeline
.venv/bin/python working/dancer/clip_pipeline.py make clip_1_walk_left_to_right
.venv/bin/python working/dancer/clip_pipeline.py make clip_2_turn_around_at_right
# ... etc, each clip references the previous via its last extracted frame
```

Each script is idempotent — generated artifacts are skipped on re-run.
Delete a specific output file to force regeneration.
