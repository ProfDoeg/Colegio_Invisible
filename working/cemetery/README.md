# cemetery/ — first 3D prototype scene

A small walkable pet cemetery + the celestial Sky of al-Jawza turning
overhead, rendered in WebGL via three.js. All visible content sourced
from on-chain quipus.

This is the prototype that validates the future `0x3d scene` type's
core compositional pattern: multiple quipu types (image + celestial)
coexist in one walkable space, each renderable by its own primitive,
arranged by per-object transforms.

## What's here

| file | what |
|---|---|
| `cemetery.html` | self-contained three.js scene (single file, CDN imports) |
| `jawza.json` | 62 stars + 10 constellations extracted from on-chain `0xce` quipu `2ae7fe909e19c0e4…` (`The Sky of al-Jawza`) |
| `textures/bea.png` | extracted from on-chain `0x03` image quipu `a01e8625…` (`Peter Bea`) |
| `textures/bea_in_car.png` | extracted from `9e42c7ab…` (`This was Peter on her blanket during a ride to the country`) |
| `textures/sun_face.png` | extracted from `dcd31fa3…` (`Sun Face`) |
| `textures/paco.png` | extracted from `014123b2…` (`Paco` — the drain-ditch kitten) |
| `textures/sparkle.png` | extracted from `c1542c10…` (`Sparkle🐈‍⬛MagicalCat🐈‍⬛✨💜Fovever💜✨`) |

## Running it

```bash
cd working/cemetery
python3 -m http.server 8765
open http://localhost:8765/cemetery.html
```

Click the entrance overlay to lock the mouse pointer, then:

| key | action |
|-----|--------|
| `WASD` or arrow keys | walk |
| mouse | look around |
| `esc` | release pointer |

Approach within ~2.8 m of any grave and a plaque fades in at the top
of the screen with the pet's name, story, and originating txid.

## Scene layout

```
   ground level
     ─ small hedged cemetery in a circle, ~8 m radius
     ─ three graves arranged in a gentle arc:

       left   — Sparkle           (single photo)
       center — Peter Bea         (wider altar, THREE photos:
                                   "Peter Bea", "Sun Face",
                                   "Peter on her blanket…")
       right  — Paco              (single photo; full drain-ditch
                                   story appears in the plaque)

   above
     ─ Sky of al-Jawza positioned for
       Cazón, Provincia de Buenos Aires, Argentina  (lat -35.4°, lon -59.6°)
       Feb 15 2016 at ~21:00 ART  (LST ≈ 85.8° → Orion transiting)
     ─ celestial sphere wheels around the celestial axis at one
       full rotation per 90 seconds (real-direction E→W)
     ─ 10 constellations colored on an HSL pastel palette, every 36°
       around the color wheel: Orion (rose-red) → Taurus (pale orange)
       → Winter Triangle (pale gold) → Lepus (chartreuse) → …
       → Perseus (rose). Stars + connector lines + label sprite
       all share their constellation's tone.
     ─ thick lines via three.js `LineSegments2` + `LineMaterial`
       (proper screen-space linewidth, not the silently-ignored
       `LineBasicMaterial.linewidth`).
```

## Why this is the 0x3d prototype

In a real `0x3d scene` quipu, the structure would be:

- list of `nodes`, each with a `transform` (TRS) and a `quipu_ref`
- the quipu_ref points at the actual content (image, celestial,
  audio, text, sub-scene)
- the renderer fetches each ref, applies the transform, displays
  the appropriate primitive

This HTML hardcodes the equivalent: the `GRAVES` array is the
node list for the cemetery layer (plinths + image-quipu refs);
the celestial sphere code is a single node referencing the Jawza
celestial quipu. A scene-quipu inscription would replace the
HTML's hardcoded JS with a body parseable by `canonical/scene.py`
plus a renderer that walks the parsed structure.

See `memory/cemetery_3d_prototype.md` for the full design notes,
seven lessons learned (fog hiding stars, additive blending issues,
Three.js's silently-ignored linewidth, southern-hemisphere tilt
formula, pastel-HSL palette beats hand-tuned hex, etc.), and the
deferred Bode `Uranographia` texture follow-up (Paths A / B / C).
