# The avatar player (Max/MSP, 2009) — how it actually works

Reconstructed by tracing `avatar_trueplayer.maxpat` (patch cords, not just object
names). This documents the *real* runtime so it can be replicated faithfully.

## What it is

A **controllable avatar driven from one recorded video**. The dancer was filmed
on a plain background and matted to alpha (the `*png.mov` files: PNG codec, RGBA).
Playback is **continuous frame-by-frame scrubbing of that video**, re-sequenced on
the fly by a **motion graph** whose nodes are hand-tagged pose frames. Because the
pixels that play are the real recording, **all movement — including crossing the
stage — lives in the footage. Nothing is synthesised.** The graph only chooses,
at tagged frames, whether to keep playing or cut/reverse to another frame.

This is the crucial point I got wrong the first time: it is **not** pose-to-pose
limited animation, and locomotion is **not** a billboard moved by displacement.

## The data (per dancer)

- **video** — `caity1png.mov` etc. RGBA, 720×279, 30 fps, ~3000 frames. One take.
- **crumbs / pcrumbs** — the graph **nodes**. `id, label variant frame;`
  e.g. `7, low_a 1 836;` = a pose named `low_a` tagged at frame 836.
- **map** — the graph **edges**, one row per source frame, five parallel arrays:
  `frame, control … frames … time … space … weight …;`
  - `frames`  destination frame of each edge
  - `time`   1 = play forward, 2 = play **reverse** (negative time)
  - `space`  1 = normal, 2 = **mirror** (horizontal flip)
  - `weight` edge weight; **0 = disabled**, larger = preferred
  - `control` which command/mode exposes this edge (1 = ambient, 2/3 = curated)
  Destinations come in forward/reverse **pairs** (each frame appears with time 1
  and time 2). The map's source frames are exactly the crumb-tagged frames.

The map nodes form **pose-class cliques**: every `push_a` frame connects to every
other `push_a` frame, etc. The cliques are mostly disconnected, **by design** —
you don't need global connectivity, because linear playback carries the dancer
between regions; a clique just lists the interchangeable cut points for one pose.

## Runtime architecture (subpatchers)

| patcher | role |
|---|---|
| root | the playhead loop + GL context (`jit.gl.render danceshow`, `jit.window`) |
| `map_reader` | look up current frame in `coll map`, pick an edge |
| `dancer1` | the dancer's movie + videoplane placement (position, rotate, mirror) |
| `fixme` (small) | `move_frame` play/pause toggle from `at_frame`/`to_frame` |
| `fixme` (big) | facing-from-motion (`cartopol` of the centroid delta) + contact shadow |
| `stage` | floor.jpg + curtain.jpg backdrops as videoplanes |
| `navigator` → `key_input` → pitch/height/turn/move/side | **keyboard camera** |
| `layering` → `dist` | depth-sort multiple dancers by centroid distance |

## The core loop (one `qmetro 20` tick ≈ 50 Hz)

```
qmetro 20 ──► t b erase b b
                ├─ out3 ─► s movie ─► r movie ─► [play/pause gate] ─► gate 2
                │                                   gate 2 routes the bang by t_dir
                │                                   ├─ forward ─► (1) ─┐
                │                                   └─ reverse ─► (-1) ─┤
                │                                                       ▼
                │                                              + 0  (frame accumulator)
                │                                                       │  N = current frame
                │                                                       ▼
                │                                              p map_reader ─► coll map[N]
                │                                                 • miss  → pass N through
                │                                                 • hit   → weighted-random
                │                                                   pick among N's edges
                │                                                   eligible for the active
                │                                                   `control`; emit to_frame,
                │                                                   set t_dir, set flip_state
                │                                                       │
                │                                                       ▼
                │                                                   [number] N'
                │                          ┌──────────────┬───────────┼─────────────┐
                │                          ▼              ▼           ▼             ▼
                │                      set + 0        s frame   p dancer1 ─► frame $1 ─► jit.qt.movie
                │                    (accumulator)              (sets the displayed frame)
                ├─ out2 ─► s movie1 ─► r movie1 ─► bang jit.qt.movie ─► matrix ─► jit.brcosa ─► videoplane
                └─ out0/out1 ─► erase + render danceshow
```

In words, every tick:
1. The **accumulator** adds ±1 to the current frame (sign = `t_dir`). Continuous
   playback.
2. The new frame `N` queries **`coll map`**. If `N` is not a tagged node, it passes
   straight through — the recording just keeps playing. If `N` **is** a node,
   `map_reader` does a **weighted-random** choice among the edges whose `control`
   matches the active command (`table tucci` + entropy normalise of the weights),
   yielding a destination `to_frame`, a `time` direction, and a `space` flip.
3. `N` (passed-through or jumped) is pushed to `jit.qt.movie` via `frame $1`. The
   movie is **slaved** to this counter — random-access every frame, never free-run.
4. `dancer1` textures that frame onto the `danceshow` videoplane and places it
   (position/rotate; `space`→mirror via scale.x). `cv.jit.centroids` tracks the
   figure; the big `fixme` derives facing from the centroid's motion vector and
   drives the contact shadow.
5. The GL scene (floor + curtain + dancer[s]) is erased and rendered.

A play/pause `gate` can freeze the playhead. `r reset` (`t 1 1 b`) seeds a start
frame.

## The three layers, as the patch realises them

- **Recorded movement** — the video; movement and displacement are in its pixels.
- **Motion graph** — `coll map`: at each tagged pose, the set of frames you may cut
  to (with forward/reverse and mirror). Pure possibility; computed/authored from
  the footage; disconnected pose-cliques are fine.
- **Control layer** — `control` selects which edges are live (steering / mode),
  `weight` biases the random choice. Swappable intention over the same graph.

## Replication plan

To replicate faithfully the renderer must **play the real frames** and only cut at
nodes — never tween poses, never move a billboard by hand.

1. **Engine, proven offline first.** In Python, implement the exact loop:
   accumulator ±1, `coll map` lookup, weighted-random edge pick filtered by
   `control`, `time`→direction, cut to `to_frame`; read the actual movie frames;
   composite on the floor+curtain stage; write an MP4. This proves the algorithm
   on real footage before any UI.
2. **Interactive version.** Stream the frames into a WebGL/`<video>` stage with the
   same loop; add the `navigator` keyboard camera and a control selector. Reverse
   playback and per-frame access are the two things to get right for the web.
