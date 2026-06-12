# Kinect → dancer (`0xda`) — capture, label, compose

A local pipeline that turns a moving body into `0xda` dancer footage and a
motion graph: **capture** depth+RGB, **label** key poses, **mask** the body
out of the room, **compose** a random walk on the motion graph. One honest
step from a dancer on chain that is a real person, not generated.

Depth beats RGB as the capture source because the footage block stores only
the opaque silhouette (1-bpp mask + palette indices, delta-coded), and depth
makes segmentation a threshold — lighting-independent, no chroma key.

---

## Where everything runs (READ FIRST on a new machine)

Capture moved off the MacBooks (no USB-A; the Kinect drops its isochronous
stream through a USB-C dongle) onto **nodus** — a headless Geekom mini-PC,
also a dogecoin node.

| what | where |
|---|---|
| **nodus** | `192.168.1.231`, user `drdoeg`, Ubuntu 24.10 (EOL → apt points at `old-releases.ubuntu.com`) |
| Kinect | plugged into nodus's **direct USB-A** (steady 30 fps, no drops) |
| tooling | `~/kinect/` on nodus (this dir, scp'd over) |
| takes | `~/kinect/takes/take_<stamp>/` on nodus — **never committed** (see `.gitignore`) |

**Live servers on nodus** (open from any browser on the LAN):

| server | port | what |
|---|---|---|
| studio | `:8787` | live 4-panel view + record |
| lab | `:8786` | scrub / filter / label / background plate |
| playback | `:8788` | loop a take for review |

**Driving nodus from another computer:**
- The HTTP servers are reachable from any LAN browser — no auth.
- SSH is keyed to the **original Mac** only. A new machine needs its own
  public key appended to `drdoeg@nodus:~/.ssh/authorized_keys` (or the
  password). `drdoeg` has passwordless sudo (`/etc/sudoers.d/drdoeg-nopasswd`).
- nodus has **no `curl`** — use `wget`. udev rule
  `/etc/udev/rules.d/51-kinect.rules` gives plugdev access to the sensor.

**Launching a server on nodus (the reliable incantation):**
```sh
ssh drdoeg@192.168.1.231 'cd ~/kinect && nohup python3 kinect_studio.py </dev/null >/tmp/studio.log 2>&1 &'
```
The `</dev/null` matters — without it the process dies when SSH closes.
Verify it came up by hitting the **HTTP port**, not the SSH exit code
(combined `pkill; launch` in one SSH call often reports failure while the
remote command actually ran). On Linux the lib path is
`libfreenect.so.0.5` and servers bind `0.0.0.0` (the committed files use
the macOS dylib path + `127.0.0.1`; re-patch with `sed` after scp, or keep
nodus's already-patched copies).

---

## The tools

### `capture_depth.py` — depth-only quick capture (macOS, libfreenect 0.7.5)
Async **camera subdevice only** (`freenect_select_subdevices(ctx, 2)`) via
ctypes. The motor / `fakenect-record` path **wedges** the 1473 — if a tool
half-claims the interface, physically replug. Writes a raw `.npy` stack.

### `kinect_studio.py` — recording studio (`:8787`)
Live 4-panel view (rgb · depth · mask · masked-colour), near/far band as a
**preview aid only** (never touches saved bytes), delayed-start record with
a countdown, **stop & save** + a live `m:ss` counter. Records **both
streams raw** and refuses to start unless depth AND rgb are live (so a
depth-only take can't happen silently). Takes → `~/kinect/takes/`.

### `kinect_lab.py` — editing lab (`:8786`)
The workstation. Open one take with random access:
- **scrub / play**, live **filter chain** (near/far → open → close/fill →
  largest-blob), view modes: masked-colour · overlay · rgb · depth · mask ·
  depth-shaded.
- **Breadcrumb labeler** — matches the 2009 `avatar_maker` format:
  `idx, label sym frame;`. `sym` 1/2/3 = **normal / flipped / symmetric**
  (= 0xda node `sym` 0/1/2). Clusters key on the **exact label string** —
  `crouch` ≠ `crouch1` ≠ `crouch2`, `praise1..4` are four distinct poses.
  Keys: type label + Enter to drop, ←/→ step, 1/2/3 set sym, space play.
  Reusable label vocabulary; **reset all** + overwrite guard.
  Saves `breadcrumbs.json` + `precrumb.txt` on **save**.
- **Onion-skin envelope** — as you type a label, the accumulated mask
  density of every same-label crumb is painted cyan behind the live frame
  (warm-red where the figure spills outside it). Align the new pose into
  the envelope so a pose cluster stays cut-consistent.
- **Background plate** — select an empty-room frame range (subject OUT of
  frame; can be at the start, end, anywhere) → **build plate**. Builds a
  **depth plate** (per-pixel median = static surface; removes furniture a
  depth band can't) AND an **RGB plate**. The mask = `(in band) AND
  (closer than depth plate)`, then **hair/IR-scatter recovery**: RGB only
  votes inside a ~22 px collar around the depth body, only to ADD — so
  hair (which scatters IR and drops from depth) fills back in with its real
  shape, while shadows/couch stay out because they're nowhere near the
  collar. Knobs in-file: `BG_MARGIN=300`, `RGB_THRESH=38`, `HAIR_COLLAR=22`.

### `depth_to_footage.py` — depth stack → `0xda` footage
Segment → tight sprite + delta → the footage dict that
`canonical/dancer.build_footage` / `build_performance` consume. Registered-mm
aware (`registered=` / autodetected). Round-trips bit-exact through
`read_dancer`. Knobs: `near_mm`/`far_mm`, `nw`/`nh`, `fps`/`stride`,
`palette_bands` (1 = silhouette, >1 = depth-shaded), `hyst`, `facing`.

### `walk_render.py` (lives in each take dir on nodus)
Builds the **bounded motion graph** from `breadcrumbs.json` and runs a
**uniform random walk** (`M_UNIFORM`), playing footage spans forward/reverse
and cutting between same-label nodes, **never outside `[first ord, last
ord]`**, rendered to a masked-colour MP4 via ffmpeg.

---

## Motion graph ↔ 2009 `avatar_maker` mapping

A **breadcrumb is a 0xda graph NODE**: `label`→vocab index, `frame`→`ord`,
`sym`→`sym`. The **map = edges**. Reconstructed from `avatar_maker8.maxpat`
+ the precrumb/map files (in `~/Documents/avatar_complete/`), the auto-map
rule (`p auto_map_making`, comment: `control=f(crumbz) space=g(crumbz)
weight=!=max,!=min`):

- **clusters = exact label**; within a cluster, **all-to-all** edges.
- **`time` 1/2** → each target twice = Klein-four time bit (fwd/rev).
- **`space`** → per-target = mirror bit, from the crumb's `sym`.
- **`weight`** → 1 except **0 at the cluster's min/max frame** → the walk
  can't escape the labeled span (bounded).
- **`control`** → the per-node mode gating (0xda edge `ctrl`).

Full 0xda graph/controller byte layout: `docs/quipu-types/dancer.md`;
emit/read code: `canonical/dancer.py`.

---

## The corpus (the bigger picture)

This isn't one dancer. There's a 2009 troupe — the source of Jeremy & Caity:

- **footage** (`.mov`, per-frame PNG sprite sequences): `~/Documents/avatari/`
  — caity1png, jeremy2png, deedee2png, michael1png, patrick2png, peggy2png;
  `~/Desktop/cavin_clean_png.mov`.
- **labels/maps** (precrumb + map/supermap per dancer):
  `~/Documents/avatar_complete/`.
- **on chain (0xda):** Jeremy, Caity.
- **ready, NOT on chain** (footage + 2009 labels already done): **DeeDee,
  Michael, Patrick, Peggy, Cavin** — the slow human part is finished.
- **new, born from depth:** the Kinect take(s) in `~/kinect/takes/`.

---

## Next steps (highest leverage first)

1. **Build the auto-map converter**: `precrumb`/`supermap` (and lab
   `breadcrumbs.json`) → a `0xda` **graph** dict, per the mapping above.
   Validate against the **known-good Jeremy/Caity** maps, then it serves
   both the old corpus and every new Kinect capture.
2. **Encode the 4–5 ready 2009 dancers** to `0xda` from their existing
   labels (DeeDee, Michael, Patrick, Peggy, Cavin).
3. **Persist one mask recipe per take** (`filter.json` + `bg_plate.npy` +
   `bg_rgb.npy`) that the lab, walk renderer, and encoder all read — so the
   band/plate is defined once and never desyncs (it has bitten us twice).
4. **Pick a controller**: `uniform` (shown) → `boltzmann` + attractor, or
   the quantum generators (see `dancer.md`).
5. **Inscription decisions** — footage/graph/controller can be separate
   citable quipus, or one performance.

## Lessons burned in

- **Depth-banding answers "how far"; separating a person from furniture is
  "static vs moving"** → background subtraction. A far-split below a row
  CANNOT separate the head from the couch-top when they share depth+height.
- Build the depth plate from **per-pixel median of empty-room frames**, not
  a high percentile of the whole take (that's person-contaminated wherever
  they stood still, and erodes the body).
- **Hair scatters the IR laser** → it drops from depth. RGB sees it;
  recover it in a collar around the depth body (depth = body, RGB = add).
