# Quipu type `0x3d` — Scene

> **STATUS: DRAFT, version 1.** Not yet implemented in `canonical/scene.py`.
> No inscriptions of this type exist on chain. Designed to make the
> chain walkable — to give quipus spatial positions, rotations, and
> animations, so a viewer can stand inside a corpus and look around.

A **scene quipu** describes a 3D world: a list of objects, each with a
transform (position, rotation, scale) and a reference to other content
on chain (an image quipu becomes a wall plane; an audio quipu becomes
a positional sound; another scene quipu becomes an embedded sub-scene
or a portal). Optional animations slerp quaternion rotations and lerp
positions between keyframes.

The scene type is **declarative and architectural**. It describes what
IS in the world — not how a user navigates through it. Locomotion,
controls, collision, field of view, and "feel" live in the renderer.
The same scene quipu can be experienced as a VR walkthrough, a
desktop first-person tour, a mobile orbit-and-zoom, or a static
illustration; the bytes describe the world, the renderer chooses the
inhabitation.

---

## Why this type exists

The chain is already a graph of references — essays cite images, books
list essays, certs sign books. A scene quipu adds **a place** to that
graph. Each essay can have a location. Each book can have a room. The
library has a vestibule, a corridor, a skydome.

Architectural goals:

- **Walkable corpus.** Visitors don't read the chain as a list; they
  walk into a gallery, see the bordado on a wall, push open a door
  into the next chapel.
- **Spatial interaction.** Walk up to a password-protected quipu and
  the keydrop unlocks. Approach a soundscape and it begins to play.
- **Composability.** Scenes drop into other scenes. The library is
  built from rooms; each room is its own inscribed scene; reuse a
  column scene twelve times by referencing it twelve times with twelve
  different transforms.
- **Time.** Quaternion rotations slerp between keyframes. A plane can
  pulse, a galaxy can turn, a doorway can open.

The format leans on **glTF 2.0** — the Khronos standard JSON
description of 3D scenes — because every WebGL renderer already
consumes it, the animation model already does SLERP correctly on
quaternion rotation channels, and the schema is well-thought-out for
extension via the `extras` mechanism.

---

## Type byte choice

`0x3d` reads as "3d." Unused in the existing type table; not reserved
for anything else.

---

## Byte layout

### Header — 6 + (header tail) bytes

```
offset  bytes        meaning
0..3    c1 dd 00 01  magic + protocol version 0.1
4       3d           type byte = scene
5       <tone>       00 ordinary, 01 affection, ff reverence
6..     | header tail |    pipe-delimited title + optional key=value fields
```

The header tail is identical to `0x00 text` — same multi-field
pipe-delimited grammar, same reserved field formats. See
[`text.md`](./text.md) for the authoritative header spec.

Scene-specific conventional fields (all optional, all advisory):

| field          | example       | meaning |
|----------------|---------------|---------|
| `scene_kind`   | `gallery`     | broad hint to renderers — `gallery`, `room`, `sky`, `walk`, `corridor`, `portal`, `library` |
| `unit_scale`   | `meter`       | unit interpretation for transforms (`meter` default; `cm`, `inch`, others allowed) |
| `up_axis`      | `y`           | up-axis convention (`y` default per glTF; `z` for some pipelines) |
| `default_camera_node` | `5`     | index into `nodes[]` of the suggested starting viewpoint |
| `series`       | `Bordado`     | series this scene belongs to |
| `volume`       | `I`           | volume identifier when associated with a book |

### Body — JSON document (UTF-8)

The body is a JSON document. The shape follows **glTF 2.0** as closely
as practical:

```
{
  "asset":      { "version": "2.0", "generator": "quipu-3d/v1" },
  "scene":      0,
  "scenes":     [ { "name": "main", "nodes": [0, 1, 2, ...] } ],
  "nodes":      [ ... per-node TRS + extras ... ],
  "animations": [ ... optional animation channels ... ],
  "cameras":    [ ... optional named viewpoints ... ]
}
```

- `asset.version` MUST be `"2.0"`. The `generator` field is informational.
- Exactly one top-level scene is rendered, indicated by the `scene`
  index into the `scenes` array. (glTF allows multiple scene roots; we
  permit it but require a `scene` selector.)
- `nodes[]` lists every object in the world.
- `animations[]` and `cameras[]` are optional.

The body MAY contain additional standard glTF fields (`meshes`,
`materials`, `accessors`, `buffers`, `bufferViews`, `samplers`,
`images`) — they pass through to glTF-compatible renderers. For most
quipu scenes, geometry will come from referenced quipus (an image plane
is just a `quipu_ref`), so the heavy glTF tables are usually empty.

### Per-node structure

Each entry in `nodes[]`:

```json
{
  "name":        "the bordado",
  "translation": [0, 1.5, -3],
  "rotation":    [0, 0, 0, 1],
  "scale":       [2, 2, 1],
  "children":    [],
  "extras": {
    "object_kind":  "plane",
    "quipu_ref":    "94f700ad…"
  }
}
```

- `translation` — `[x, y, z]`, floats. Default `[0,0,0]` if omitted.
- `rotation` — quaternion `[x, y, z, w]`, floats. Default `[0,0,0,1]`
  (identity) if omitted. **MUST be a unit quaternion** (sum of squares
  ≈ 1.0).
- `scale` — `[x, y, z]`, floats. Default `[1,1,1]` if omitted.
- `children` — array of node indices that are positioned relative to
  this node. Standard glTF hierarchy. Cycles forbidden.
- `extras` — the protocol's dialect. See below.

### Per-node `extras` — the quipu dialect

```
object_kind        STRING       discriminator. Required for any quipu-aware behavior.
                                values: plane, sphere, cube, model, light, camera,
                                        subscene, audio, text, marker

quipu_ref          STRING       64-char hex txid of the content this node renders.
                                Interpretation depends on object_kind:
                                  plane    → texture from a 0x03 image quipu
                                  sphere   → texture from a 0x03 image quipu
                                  cube     → texture(s) from 0x03 image quipus
                                  model    → mesh from a future 3D-model quipu type
                                  subscene → another 0x3d scene quipu
                                  audio    → a future 0x07 audio quipu
                                  text     → a 0x01 essay or 0x00 text quipu

portal_mode        STRING       only when object_kind = subscene:
                                  "embed"  — render the sub-scene in place,
                                             stacked under this node's transform
                                  "portal" — interactive doorway; renderer
                                             switches to the sub-scene on traversal

lock_ref           STRING       64-char hex txid of an 0x0e 0x0d keydrop quipu
                                that guards this node. Renderer must obtain the
                                key (prompt the user, or check pre-supplied keys)
                                before rendering / activating the node.

sound_ref          STRING       64-char hex txid of an audio quipu (future 0x07)
                                playing as positional audio at this node.

proximity_trigger  NUMBER       distance (in unit_scale units) at which renderers
                                MAY fire this node's interactions (sound play,
                                lock prompt, portal traversal).

label              STRING       optional UI label shown when the node is hovered
                                or examined.

caption_quipu_ref  STRING       optional txid of a text or essay quipu that
                                renders as a floating description near this node.
```

Additional extras may be added freely. Renderers MUST ignore unknown
`extras` keys without erroring. This is the extension mechanism.

### Animations and SLERP

Animation channels are standard glTF. The keyframes are inscribed; the
renderer interpolates between them per the channel's `interpolation`
setting.

```json
{
  "animations": [{
    "name": "the bordado breathes",
    "channels": [
      { "target": { "node": 3, "path": "rotation"    }, "sampler": 0 },
      { "target": { "node": 3, "path": "scale"       }, "sampler": 1 },
      { "target": { "node": 3, "path": "translation" }, "sampler": 2 }
    ],
    "samplers": [
      {
        "input":         [0.0, 2.0, 4.0],
        "output":        [ [0,0,0,1], [0,0.38,0,0.92], [0,0,0,1] ],
        "interpolation": "LINEAR"
      },
      {
        "input":         [0.0, 2.0, 4.0],
        "output":        [ [1,1,1], [1.05,1.05,1], [1,1,1] ],
        "interpolation": "LINEAR"
      },
      {
        "input":         [0.0, 4.0],
        "output":        [ [0,1.5,-3], [0,1.6,-3] ],
        "interpolation": "LINEAR"
      }
    ]
  }]
}
```

- **LINEAR interpolation on a `rotation` channel performs SLERP** (per
  glTF 2.0 §3.7.2.3) — spherical linear interpolation along the
  shortest great-circle arc between unit quaternions. We get slerp for
  free; we just inscribe the keyframes.
- LINEAR on `translation` / `scale` performs normal vector lerp.
- `STEP` performs hard cuts (no interpolation).
- `CUBICSPLINE` performs cubic-spline interpolation with author-supplied
  tangents (output array tripled: in-tangent, value, out-tangent per
  keyframe).

`sampler.input` values are seconds from animation start. `sampler.output`
contains the keyframe values. Number of input keyframes must equal
number of output keyframes (or output/3 for CUBICSPLINE).

### Cameras

Optional. Defined per glTF:

```json
{
  "cameras": [
    {
      "name": "entry",
      "type": "perspective",
      "perspective": { "yfov": 0.785, "znear": 0.1, "zfar": 100, "aspectRatio": 1.777 }
    }
  ]
}
```

A node references a camera by setting its `camera` index (alongside
its TRS). The scene's `default_camera_node` header field (or
`scenes[0].extras.suggested_view`) points at the node the renderer
should use as initial viewpoint. Renderers are free to override.

---

## What scenes do NOT specify

Crisp separation of concerns:

```
   Protocol describes:                    Renderer decides:
   ──────────────────────                 ──────────────────────
   where things are                       how the user moves
   what things are                        camera control schemes
   how things change over time            collision detection
   where interactions can fire            mouse/keyboard/touch/VR mapping
   suggested viewpoints                   physics simulation
                                          render quality, FOV, lighting model
                                          portal traversal feel (fade, cut, walk)
                                          unit interpretation when given a hint
```

A scene quipu MUST NOT carry control bindings, viewport dimensions,
"WASD enabled" flags, gravity values, frame rate targets, or any other
renderer-policy choice. If you want to suggest a starting viewpoint,
use `default_camera_node`; if you want to suggest scale, use
`unit_scale`. Anything stronger violates the architectural-not-locomotive
principle.

---

## Hybrid composition — scenes inside scenes

A node with `extras.object_kind = "subscene"` and a `quipu_ref` pointing
at another scene quipu **embeds the referenced scene at this node's
transform**.

```
   outer scene:                              embedded scene "chapel":
   ┌─────────────────────────────┐           ┌──────────────┐
   │  node #5  "side_chapel"     │           │ wall, floor,  │
   │  translation: (12, 0, 0)    │  ──────►  │ altar, candle │
   │  rotation:    yaw 90°       │           │  1, candle 2  │
   │  scale:       0.5           │           └──────────────┘
   │  quipu_ref:   <chapel>      │
   │  portal_mode: embed         │
   └─────────────────────────────┘

   composition:
     entire chapel placed at (12, 0, 0), rotated yaw 90°, scaled 0.5,
     INSIDE the outer scene's world. The chapel's own animations
     continue running; the outer scene's animation of the embedding
     node moves the chapel as a unit.
```

Two `portal_mode` values:

- **`embed`** — the referenced scene's contents are rendered in place,
  stacked under the embedding node's transform. The world is continuous;
  the user sees the embedded scene without switching context.
- **`portal`** — the embedding node is a clickable / walk-into-able
  trigger. When the renderer's "user is here" predicate fires, it
  switches to rendering the referenced scene as the new top-level scene.
  State (player position, accumulated triggers, etc.) is per-renderer.

Recursive embedding is allowed. A scene may embed a scene that embeds
a scene. Readers walk the embedding tree depth-first with cycle
detection and a depth limit (default 8, same convention as bindings and
books).

Instancing — the **same** `quipu_ref` used at multiple nodes — is the
natural way to repeat content. Twelve nodes pointing at the same column
scene with twelve different translations is twelve column instances at
the cost of one inscribed column.

---

## Worked example — a small gallery

A two-object scene: a Goethe practice page on one wall, a Hayagriva
bordado on another wall, both slowly slerping their rotations.

Header:

```
c1dd 0001 3d 00 |Goethe & Hayagriva|author=El Ermitaño|date=2026-06-01|lang=es|scene_kind=gallery|unit_scale=meter|
```

Body (JSON):

```json
{
  "asset": { "version": "2.0", "generator": "quipu-3d/v1" },
  "scene": 0,
  "scenes": [{ "name": "main", "nodes": [0, 1, 2] }],
  "nodes": [
    {
      "name":        "goethe_plane",
      "translation": [0, 1.5, -3],
      "rotation":    [0, 0, 0, 1],
      "scale":       [1.2, 0.78, 1],
      "extras": {
        "object_kind":       "plane",
        "quipu_ref":         "94f700ad614d481f58a90fb5f5576d70b50c49a119cc6d1a2bb33c7620b18641",
        "label":             "Página de Práctica Hebrea de Goethe, c. 1760",
        "proximity_trigger": 2.0
      }
    },
    {
      "name":        "hayagriva_plane",
      "translation": [3, 1.5, 0],
      "rotation":    [0, -0.707, 0, 0.707],
      "scale":       [1.5, 1, 1],
      "extras": {
        "object_kind": "plane",
        "quipu_ref":   "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1",
        "label":       "Hayagriva (Maier)"
      }
    },
    {
      "name":        "entry_camera",
      "translation": [0, 1.6, 2],
      "rotation":    [0, 0, 0, 1],
      "camera":      0
    }
  ],
  "animations": [{
    "name": "slow_breath",
    "channels": [
      { "target": { "node": 0, "path": "rotation" }, "sampler": 0 },
      { "target": { "node": 1, "path": "rotation" }, "sampler": 1 }
    ],
    "samplers": [
      {
        "input":  [0.0, 4.0, 8.0],
        "output": [[0,0,0,1], [0,0.087,0,0.996], [0,0,0,1]],
        "interpolation": "LINEAR"
      },
      {
        "input":  [0.0, 4.0, 8.0],
        "output": [[0,-0.707,0,0.707], [0,-0.643,0,0.766], [0,-0.707,0,0.707]],
        "interpolation": "LINEAR"
      }
    ]
  }],
  "cameras": [{
    "name": "entry",
    "type": "perspective",
    "perspective": { "yfov": 0.785, "znear": 0.1, "zfar": 100, "aspectRatio": 1.777 }
  }]
}
```

The scene has two image planes (each referencing an existing image
quipu by `quipu_ref`), one camera marker, and a single animation with
two rotation channels that slerp both planes through a slow oscillation.
A glTF-compliant renderer fetches the two referenced image quipus
(via the protocol fetcher), uses their decoded pixel data as plane
textures, and runs the animation.

---

## Reader API

```python
from scene import read_scene_quipu, build_scene_quipu

parsed = read_scene_quipu(header_bytes, body_bytes)
# parsed = {
#   'title':   str,
#   'tone':    int,
#   'fields':  dict[str, str],           # scene_kind, unit_scale, up_axis, etc.
#   'gltf':    dict,                      # the parsed JSON body verbatim
#   'nodes':   list,                      # gltf['nodes'] for convenience
#   'animations': list,                   # gltf.get('animations', [])
#   'cameras':    list,                   # gltf.get('cameras', [])
# }
```

### Convenience accessors

```python
def scene_nodes_by_kind(parsed, kind):
    """Iterate nodes whose extras.object_kind equals `kind`."""

def scene_subscene_refs(parsed):
    """List (node_index, quipu_ref, portal_mode) for every subscene node."""

def scene_locked_refs(parsed):
    """List (node_index, lock_ref) for every node with a lock guard."""

def walk_scene_tree(parsed, fetcher, max_depth=8, visited=None):
    """Recursively descend embedded sub-scenes. Same contract as
    walk_book_tree (cycle detection, depth limit, error capture)."""
```

---

## Builder

```python
def build_scene_quipu(title, gltf_body, tone=TONE_ORDINARY, fields=None):
    """Build a 0x3d scene quipu's (header_bytes, body_bytes) pair.

    Args:
        title:    str. The scene title.
        gltf_body: dict — the parsed JSON scene structure. Validated
                  against the minimum schema (asset.version=='2.0',
                  scene index valid, nodes list well-formed,
                  quaternions unit-length).
        tone:     TONE_ORDINARY (default), TONE_AFFECTION, TONE_REVERENCE.
        fields:   optional dict[str, str] of header metadata.

    Returns:
        (header_bytes, body_bytes)  — body_bytes is the UTF-8 encoded
        JSON serialization of gltf_body, with consistent formatting
        (sorted keys, no trailing whitespace) for inscription
        reproducibility.
    """
```

Validation rules:

- `asset.version == "2.0"` REQUIRED
- `scene` is a valid index into `scenes[]`
- Every node's `rotation`, if present, is a 4-vector with sum-of-squares
  within `[0.999, 1.001]` (unit quaternion tolerance)
- Every `quipu_ref` is a valid 64-char hex string
- `extras.object_kind`, if present, is a known kind OR an unknown
  string (warning, not error) so future kinds can be authored before
  the type spec catches up

---

## Tone vocabulary

Inherited from `0x00 text`:

| `<tone>` | when to use |
|---|---|
| `0x00` ordinary  | the default — gallery scenes, library rooms, technical walkthroughs |
| `0x01` affection | personal scenes, gift walkthroughs, dedicated installations |
| `0xff` reverence | memorial scenes, sanctuaries, commemorative spaces |

---

## Relationship to other types

| ref kind | object_kind | what it gives the scene |
|----------|-------------|-------------------------|
| `0x03 image`   | `plane`, `sphere`, `cube` | texture(s) on geometry |
| `0x01 essay`   | `text` (or label) | text rendered in 3D space |
| `0x00 text`    | `text` (or label) | literal text panels |
| `0x07 audio` (TBD) | `audio`     | positional sound |
| `0x0e 0x0d keydrop` | (via `lock_ref`) | spatial password gates |
| `0xce celestial` | `sphere` with `subscene` semantics | skydome with constellations |
| `0x09 book`     | (via subscene to a book's "scene" entry) | walk into a book |
| `0x3d scene`    | `subscene` | embedded sub-scenes, portals, recursion |

The 0x3d type compose-walks the rest of the chain. Any quipu can be
placed somewhere.

---

## Open questions / future extensions

1. **Geometry quipus.** Right now planes and spheres carry image
   textures, but actual mesh geometry comes only from glTF's `meshes`
   table. A future `0x?? model` type holding .glb bytes (or
   draco-compressed mesh data) would let nodes reference complex
   geometry the same way they reference textures.

2. **PBR materials and lighting.** glTF supports physically-based
   rendering via `materials`. We currently leave this to the renderer
   (default unlit shading on referenced image textures). Authors
   wanting PBR can inscribe full `materials` tables; spec doesn't
   yet enforce.

3. **Compression.** A complex scene with many keyframes could grow.
   Investigate `KHR_draco_mesh_compression` and `EXT_meshopt_compression`
   for future versions. Not v1.

4. **Inline assets vs referenced quipus.** glTF allows inline base64
   data URIs in `images`/`buffers`. Our convention is to reference
   image quipus via `extras.quipu_ref` rather than embedding bytes
   inline — keeps scene quipus small and lets the chain be the asset
   store. v1 SHOULD discourage inline data URIs (warn but allow).

5. **Multi-scene quipus.** glTF allows multiple scene roots in one
   document. Our v1 requires exactly one active scene via the `scene`
   index, but the body MAY contain additional scenes used as
   sub-graphs. Convention TBD.

6. **Interaction wiring.** The `extras` mechanism standardizes refs
   and triggers, but the full vocabulary of "what an interaction can
   do" — fire animation, switch scene, unlock, play sound, branch on
   condition — needs more design. v1 covers `lock_ref` (unlock-gate),
   `sound_ref` (proximity audio), `portal_mode` (scene switch), and
   `proximity_trigger` (distance threshold). More extras coming.

7. **Authoring tools.** glTF has rich Blender / Maya / Three.js
   editors. A "quipu scene from Blender" exporter would set the
   `extras.quipu_ref` fields automatically based on Blender custom
   properties. Out of v1 scope but easy follow-on.

---

## Cross-references

- [`docs/quipu-types/text.md`](./text.md) — header grammar inherited by scenes
- [`docs/quipu-types/image.md`](./image.md) — image type referenced as textures
- [`docs/quipu-types/essay.md`](./essay.md) — essays referenced as text panels
- [`docs/quipu-types/book.md`](./book.md) — books as the bibliographic dual of scenes
- [`docs/quipu-types/celestial.md`](./celestial.md) — celestial scenes (skydomes)
- [Khronos glTF 2.0 specification](https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html) — external reference for the body format
