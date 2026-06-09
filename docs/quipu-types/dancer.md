# Quipu type `0xda` — Dancer

> **STATUS: CANONICAL v1.** Implemented in
> [`canonical/dancer.py`](../../canonical/dancer.py). First on chain as
> the **Jeremy** performance (root `6de4688a945fb03f41f9b1139c83f5099dd309378348398d4b52ce1c1d12a489`,
> block 6,230,020, apocrypha address).

A *dancer quipu* is a **controllable motion-sprite**: a creature that
moves, not a picture that sits. It is its own format — **tight sprites +
delta differencing**, a motion graph over those sprites, and a controller
that decides how the graph is walked. The only thing it borrows from the
image type is the low-level bit-packer (`pack_pixels` / `unpack_pixels`,
MSB-first); the *encoding* is sprite-and-delta, not raster.

The dancer is built in **three layers**, each independently inscribable,
so an expensive recording can be cited once and re-skinned cheaply:

| layer | what it is | the metaphor |
|---|---|---|
| **footage** | the pixels — a delta-coded sprite recording | the body |
| **graph** | a cut topology over footage frames (nodes + edges) | the skeleton of motion |
| **controller** | methods + preferences + live bindings | the intention |

---

## Variants

The header's variant byte selects which layers a given inscription
carries:

| `<variant>` | name | body |
|---|---|---|
| `0x01` | **performance** | graph (inline footage table) + controllers — self-contained |
| `0x02` | **footage** | a single footage block (the reusable, expensive asset) |
| `0x03` | **graph** | footage table (inline and/or ref) + the cut topology |
| `0x04` | **controller** | a 32-byte graph txid + one or more controllers |

### Portability models

Because every layer is a citable quipu, a dancer can be assembled from
pieces already on chain:

- **Model A** — the whole stack inline (a `performance`, or
  `controller → graph → footage` by reference).
- **Model B** — a new `controller` citing an existing `graph` txid (a
  re-choreography of the same body).
- **Model C** — a new `graph` citing an existing `footage` txid (a new
  cut of the same recording).

The footage table inside a graph holds **one or many** footages, each
either inline or a 32-byte reference, so a single dancer can blend
multiple recordings or recordings spread across several quipu.

---

## Byte layout

### Header — 8 + (title) bytes, every variant

```
offset  bytes        meaning
0..3    c1 dd 00 01  magic + protocol version 0.1
4       da           type byte = dancer
5       <tone>       tone byte — see tone.md for the canonical vocabulary
6       <variant>    01 performance | 02 footage | 03 graph | 04 controller
7       <T>          title length in UTF-8 bytes (uint8)
8..8+T  <title>      title, UTF-8
```

> **Title is length-prefixed**, not pipe-bracketed. This differs from the
> image (`0x03`) and text (`0x00`) types, which wrap the title in `|…|`.
> The dancer header is fixed-width up to the title, so the body starts at
> a known offset (`8 + T`) with no sentinel scan.

### Footage block — delta(c) storage

The footage is a shared palette plus `N` frames. Each frame stores its
anchor and facing, then **either** a keyframe (a full tight sprite)
**or** a diff against the previous frame. Size tracks *total motion*,
not frame count.

```
pal_n   u8            palette size, 1..255
N       u16           frame count, big-endian
ib      u8            index bits = ceil(log2(pal_n)); 1 when pal_n==1
palette pal_n×(r g b) shared palette, one RGB triple per entry, u8 each
nw      u16           notional frame width   (the coordinate space)
nh      u16           notional frame height
fps     u8            playback rate
keyint  u16           K — force a keyframe every K frames (0 = never force)

N × frame:
    cx  f32           centroid x, fraction of the notional frame (anchor)
    cy  f32           centroid y, fraction of the notional frame
    facing u8         0 front | 1 back | 2 profile_R | 3 profile_L
    flag   u8         0 = keyframe, 1 = diff

    if flag == 0  (KEYFRAME — a full tight sprite):
        x y w h  u16×4        sprite bbox within the notional frame
        mask     w·h bits     1 = opaque   (1-bpp, MSB-first)
        idx      nopq × ib    one palette index per opaque pixel,
                              row-major over the opaque pixels
                              (nopq = popcount(mask))

    if flag == 1  (DIFF — changed pixels vs the previous frame):
        cbx cby cbw cbh  u16×4   changed-region bbox, notional coords
        cmask    cbw·cbh bits     1 = this cell changed
        abits    nch bits         per changed cell: 1 = now opaque,
                                  0 = now transparent  (nch = popcount(cmask))
        nidx     nopq × ib        palette index for each now-opaque
                                  changed cell  (nopq = popcount(abits))
        # an identical frame is a diff with bbox (0,0,0,0): cbw·cbh == 0,
        # so cmask/abits/nidx are empty.
```

**Keyframe vs diff is chosen by cost.** The encoder forces a keyframe at
frame 0 and at every `i % K == 0`; otherwise it emits whichever of
{keyframe, diff} packs to fewer bytes. Decoding is exact (lossless): a
keyframe rebuilds the notional-frame index map from scratch; a diff
applies changed cells onto the previous map, then the tight sprite is
re-extracted from the map. Transparent pixels are never stored — only
the opaque silhouette and its palette indices.

### Footage table

Used wherever a graph references footage (inside `0x03` and `0x01`).

```
Nfoot  u8                 number of footage entries
Nfoot × entry:
    kind u8   00 inline →  <footage block>   (above)
              01 ref    →  txid (32 bytes)    (a 0x02 footage quipu)
```

### Graph body

```
<footage table>
nmode   u8                number of control modes
Llab    u8                pose-label vocabulary size
Llab × (len u8 + utf8)    label names
start   u16               start node index
Nn      u16               node count

Nn × node head:
    foot   u8             which footage in the table
    ord    u16            frame ordinal / cut point in that footage
    label  u8             index into the label vocabulary
    sym    u8             symmetry class: 0 same | 1 reflected | 2 symmetric
    narc   u8             number of outgoing edges

then, per node in order, narc × edge:
    dst    u16            destination node index
    flags  u8             bit0 time (0 fwd | 1 rev), bit1 space (0 same | 1 mirror)
    ctrl   u8             control mode this edge belongs to (0xFF = all modes)
```

Each edge encodes one member of the **Klein-four** transition group:
`time ∈ {forward, reverse}` × `space ∈ {same, mirror}`. A mirror edge
swaps `profile_R ↔ profile_L` on its footage; a reverse edge plays the
clip backward. The node `sym` marks how a node sits under reflection
(its own mirror orbit), which is what lets a reflected walk reuse the
same footage.

### Controller list

For variant `0x04` the body is a 32-byte graph txid **then** the
controller list; for `0x01` it is the inline graph **then** the list.

```
Nctrl         u8          number of controllers
default_ctrl  u8          index of the controller used by default

Nctrl × controller:
    start          u16     start node for this controller
    mode0          u8      initial control mode
    Nmethod        u8
    default_method u8
    Nmethod × method:
        id    u8           method id (table below)
        plen  u8           parameter length
        params[plen]       method parameters (table below)
    Npref          u8      preference-set count
    Npref × pref:
        namelen u8 + name(utf8)
        Nw      u16        weight count
        Nw × (node u16 · eidx u8 · weight u8)   per-edge weights
    Nbind          u8      live-binding count
    Nbind × binding:
        source u8 · port u8 · scale f32
```

A **preference set** is a named bag of per-edge weights (which transition
to favour at which node). A **method** is a rule for turning the
available edges at the current node into a choice. A **binding** wires a
live input source to a control port (e.g. an attractor's x-position to
the target port), with a scalar gain.

#### Methods

| `id` | name | params (`plen`) | meaning |
|---|---|---|---|
| `0x00` | uniform | — (0) | pick uniformly among available edges |
| `0x01` | weighted | `pref` u8 (1) | follow a named preference set |
| `0x02` | boltzmann | `beta` f32 · `gain_t` f32 · `axis` u8 · `pref` u8 (10) | softmax chase toward a target; signed `beta` = attract/repel |
| `0x03` | quantum | `generator` u8 · `measure_per_step` f32 · `measure_handedness` u8 · `well_depth` f32 (10) | unitary evolution + measurement over the footage-derived operator |
| `0x10` | keyboard | `map` u8 (1) | direct key control |

An unknown method id is preserved opaquely: its `params[plen]` pass
through the reader untouched, so a future method survives a round-trip
through an older parser.

#### Quantum generators

The quantum method's operator is **derived from the footage**, never
stored. `generator` selects which operator:

| `generator` | name | operator |
|---|---|---|
| `0` | similarity | `S` — the frame-similarity Gram matrix (Hermitian → unitary evolution) |
| `1` | symnorm | `D^{-1/2} S D^{-1/2}` — symmetric-normalized |
| `2` | full | the full transition matrix |
| `3` | sa | `S + A` — symmetric + antisymmetric; chiral, carries a time-arrow |

#### Ports and sources

Ports (binding targets) and sources (live inputs) are named small
integers — opaque to the codec, meaningful to a renderer:

| port | | source | |
|---|---|---|---|
| `0` target | `2` gain | `0` attractor_x | `3` key_ud |
| `1` method_select | `3` mode | `1` attractor_z | `4` key_btn |
| `4` measure_rate | | `2` key_lr | `5` clock |

Multiple bindings to the same port sum — that's how multiple attractors
(several dancers drawn to a fire, repelled from each other) compose.

---

## The motion model

A controller walks the graph by repeatedly choosing an outgoing edge.
The continuous form of that walk is the matrix-exponential excursion
`v_next = e^{M} v`, where **M is the transition matrix between edges** —
a propagator in a motive field, not a reflector. `e^{M}` is then the
graph's *communicability* (Estrada): walks of every length summed with
factorial weights.

In the relational form, with `M` the (symmetric) similarity operator and
`R` a handedness reflection (`R² = I`):

```
e^{M ⊗ R} = cosh(M) ⊗ I + sinh(M) ⊗ R
```

even-length walks preserve handedness; odd-length walks flip it — the
dance and its mirror carve lines on the same manifold, and self-symmetry
is what lets a walk cross into the mirror world. Operator symmetry is
needed only for a clean spectrum and unitary quantum evolution; the
`⊗R` split needs only `R² = I`. This is developed in full in the **The
Moving Quipu** volume (`working/moving/`).

---

## Worked example — Jeremy

A `0x01` performance, the first dancer on chain.

- **Footage:** 16-colour shared palette (`ib = 4`), 128 px tall notional
  frame, 30 fps, `keyint = 30`, delta-coded — 2,374 frames of the 2009
  avatar recording.
- **Graph:** footage inline; cut topology from the original motion
  player (named pose labels, Klein-four edges).
- **Controller:** seven methods — uniform, boltzmann (the default
  chase), all four quantum generators (similarity / symnorm / full / sa),
  and keyboard — with `attractor_x → target` and `key_btn →
  method_select` bindings, so the same inscription is a self-running
  boltzmann wanderer *or* a key-driven, generator-switchable instrument.
- **Body:** 1,790,082 bytes.
- **On chain:** 255 strands · 22,377 knots; root
  `6de4688a945fb03f41f9b1139c83f5099dd309378348398d4b52ce1c1d12a489`,
  join `e1be6faa4eb5750cbd4d96f5328d0d007a7b6288162e3667f82f6dd565080439`
  (block 6,230,020). Tone: ordinary. Funded from apocrypha at 0.02
  DOGE/knot. See [`../guides/broadcasting.md`](../guides/broadcasting.md)
  for how it was woven.

---

## Reference parser

See [`canonical/dancer.py`](../../canonical/dancer.py) for the
authoritative builders (`build_footage` / `build_graph` /
`build_controller` / `build_performance`) and reader (`read_dancer`).
The self-test (`python canonical/dancer.py`) round-trips, losslessly:

- **footage** — palette + tight sprites + delta frames.
- **graph** — a footage table mixing one inline footage and one 32-byte
  reference, with Klein-four edges and node symmetry classes.
- **controller** — two whole controllers carrying boltzmann + keyboard +
  quantum methods, a named preference set, and live bindings.
- **performance** — the self-contained footage + graph + controllers
  bundle.

The real-data Jeremy build round-tripped bit-exact before inscription.

---

## Tone vocabulary

See [tone.md](tone.md). A dancer takes the same four transverse tone
values as every other type, applied to the figure (reverence for a
memorial dancer, demonic for a tyrant's effigy, etc.).

---

## Why `0xda`

`da` reads as **dancer** — a rare two-letter Latin mnemonic in the type
table. The high byte also keeps the motion types clustered above the
static-media types (`0x03` image), leaving room below for the still
forms and above for the moving and walkable ones (`0x3d` scene).
