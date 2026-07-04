#!/usr/bin/env python3
"""Golem's Last Healing — "Goethe's Southern Journey in the Dantean
Cosmology", the corrected cosmos authored whole.

Every rendering decision that accumulated in viewers moves INTO the quipu:
a v2 scene (0x3d) carries the orbital motion as real
glTF animations (pivot nodes turning, Kepler-scaled from the inscribed radii,
Moon 24 s), the firmament's slow rotation, authored appearance per node (sun
gold, moon parchment, planets periwinkle, the firmament translucent from
inside), authored orbit rings, the indigo sky, scene_kind=orrery, and an
Earth node whose refs are the RIGHT ones: the coasts quipu (contours + lakes
+ the full named journey — the atlas's superset) and the playmobil traveler
(healing the never-broadcast txid), with the atlas palette and the approved
route/traveler proportions as extras. Earth carries NO animation: the
heavens turn, the earth stands.

Alongside it, ONE catalog (0xab, hope):

    <<1fa3a4b9…>>                        (default subject: the old cosmos)
    <<1fa3a4b9…>> = <<v2 root>>          (read the old scene as the new)

The old cosmos stays broken and silent on its own page; the corrected model
is viewed through this repair. Errata are additions; history is never
rewritten. The v2 root is a placeholder at build time — the deterministic
diamond backfills it at signing (one batch may reference its siblings).

BUILD + VERIFY (keyless — run this first, always):
    ../../.venv/bin/python build_and_sign.py build

SIGN (touches the key — you run it):
    ../../.venv/bin/python build_and_sign.py sign \
        --utxo <txid>:<vout>:<value_sats> --address <funder_addr> \
        --keyfile ~/Documents/cinv/llaves/mi_prv.enc

BROADCAST (keyless, resumable, launches the loom):
    ../../.venv/bin/python build_and_sign.py broadcast
"""
import argparse
import getpass
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "canonical"))

OLD_COSMOS = "1fa3a4b90af9b7ac61cb7713b3fe26d20d2e9d65da86ac00343e4115438bddb8"
BODE       = "6e10058f59cb709bdcaaf994b1dab448053ae482970155f4c34a60c20b89f366"
COASTS     = "97356eb571b58822fe473eb67179a4da09908466013512eef4f761b35d0f8025"
PLAYMOBIL  = "5dc8ed119de6e5470f6239d712a9dda9af106249c1023eec60aebb22aca102fe"

# the v2 root is a sibling in this batch — a placeholder the diamond
# backfills. The convention: QREF:<pid>, NUL-padded to 32 bytes.
def _placeholder(pid):
    """64-hex ASCII form — what the backfill replaces (and, size-preserving,
    its raw-32-byte form inside binary bodies)."""
    return (b"QREF:" + pid.encode()).ljust(32, b"\0").hex()


V2_PID = "goethe_southern_journey"
V2_PLACEHOLDER = _placeholder(V2_PID)

ART_DIR = os.path.join(HERE, "artifacts")

# the inscribed v1 geometry (positions/sizes are right; everything else was
# never authored) — radii drive the Kepler periods, innermost = 24 s
PLANETS = [                      # (name, orbital radius)
    ("Moon",     3.4),
    ("Mercury",  4.8),
    ("Venus",    6.3),
    ("Sun",      8.1),
    ("Mars",    10.0),
    ("Jupiter", 12.3),
    ("Saturn",  14.9),
]
EARTH_R  = 1.5
STARS_R  = 19.0
T_INNER  = 24.0                  # the approved feel: Moon takes 24 s
T_FIRM   = 300.0                 # the firmament's slow turn

GOLD, PARCHMENT, PERIWINKLE = "#c2a76b", "#f4ead8", "#9fb4e8"
RING = "#55639a"

S2 = math.sqrt(0.5)              # deterministic double, same on every build


def _orbit_anim(name, node_idx, period):
    """A full revolution about +Y as a validated glTF rotation animation:
    five quarter-turn keyframes, LINEAR (= slerp per the codec spec)."""
    return {
        "name": name,
        "channels": [{"target": {"node": node_idx, "path": "rotation"},
                      "sampler": 0}],
        "samplers": [{
            "input": [0.0, period / 4.0, period / 2.0, 3.0 * period / 4.0, period],
            "output": [[0.0, 0.0, 0.0, 1.0],
                       [0.0, S2, 0.0, S2],
                       [0.0, 1.0, 0.0, 0.0],
                       [0.0, S2, 0.0, -S2],
                       [0.0, 0.0, 0.0, -1.0]],
            "interpolation": "LINEAR",
        }],
    }


def build_v2_scene():
    """(header_bytes, body_bytes) for the corrected cosmos — everything the
    renderer needs, authored."""
    from scene import build_scene_quipu

    nodes = [
        {"name": "vantage", "translation": [0.0, 16.0, 46.0],
         "extras": {"object_kind": "camera", "fov_deg": 68}},
        {"name": "Earth", "scale": [EARTH_R, EARTH_R, EARTH_R],
         "extras": {"object_kind": "sphere",
                    "quipu_ref": COASTS,            # contours + lakes + journey
                    "traveler_ref": PLAYMOBIL,      # Goethe walks again
                    "traveler_period_sec": 75,
                    "traveler_height": 0.0225,
                    "route_width": 0.0007,
                    "sea_color": "#aacbe6", "land_color": "#efe6d2",
                    "lake_color": "#aacbe6", "route_color": "#c83727",
                    "stop_color": "#1a1a1a",
                    "color": "#3a5f85"}},
        {"name": "fixed-stars", "scale": [STARS_R, STARS_R, STARS_R],
         "extras": {"object_kind": "sphere",
                    "quipu_ref": BODE,              # Uranographia, direct
                    "color": "#1a2340", "opacity": 0.22, "side": "inside",
                    "unlabeled": 1}},
    ]
    animations = [_orbit_anim("turn of the fixed stars", 2, T_FIRM)]
    top = [0, 1, 2]
    for name, d in PLANETS:
        color = GOLD if name == "Sun" else (PARCHMENT if name == "Moon" else PERIWINKLE)
        extras = {"object_kind": "sphere", "color": color}
        if name == "Sun":
            extras["emissive"] = 1
        nodes.append({"name": name, "translation": [d, 0.0, 0.0],
                      "extras": extras})
        planet_idx = len(nodes) - 1
        nodes.append({"name": "orbit of " + name, "children": [planet_idx]})
        pivot_idx = len(nodes) - 1
        nodes.append({"name": "ring of " + name, "scale": [d, d, d],
                      "extras": {"object_kind": "ring",
                                 "color": RING, "opacity": 0.7}})
        ring_idx = len(nodes) - 1
        top += [pivot_idx, ring_idx]
        period = round(T_INNER * (d / PLANETS[0][1]) ** 1.5, 1)
        animations.append(_orbit_anim("orbit of " + name, pivot_idx, period))

    gltf = {
        "asset": {"version": "2.0", "generator": "quipu-3d/v1"},
        "scene": 0,
        "scenes": [{"name": "Goethe's Southern Journey in the Dantean Cosmology", "nodes": top,
                    "extras": {"background": "#0d1430"}}],
        "nodes": nodes,
        "animations": animations,
    }
    return build_scene_quipu(
        "Goethe's Southern Journey in the Dantean Cosmology", gltf,
        tone=0x00,
        fields={"author": "El Gólem", "date": "2026-07-03",
                "scene_kind": "orrery", "corrects": OLD_COSMOS})


def build_catalog():
    """(header_bytes, body_bytes) for the one catalog: read the old cosmos
    as the corrected one. The v2 root rides in as a placeholder."""
    from bindings import build_binding_quipu
    from tone import TONE_HOPE
    body = "<<%s>>\n" % OLD_COSMOS
    body += "______ corrections ______\n"
    body += "<<%s>>=<<%s>>\n" % (OLD_COSMOS, V2_PLACEHOLDER)
    body += "______ subjects ______\n"
    body += "<<goethe_southern_journey>>=<<%s>>\n" % V2_PLACEHOLDER
    body += "<<bode>>=<<%s>>\n" % BODE
    body += "<<coasts>>=<<%s>>\n" % COASTS
    body += "<<playmobil>>=<<%s>>\n" % PLAYMOBIL
    return build_binding_quipu(body, tone=TONE_HOPE)


def pieces():
    """The two-piece set for the consolidated diamond — (pid, blob) tuples,
    the build_consolidated_diamond convention. The catalog's placeholder
    backfills to the scene's root at signing."""
    sh, sb = build_v2_scene()
    ch, cb = build_catalog()
    return ([(V2_PID, sh + sb),
             ("last_catalog", ch + cb)],
            _placeholder)


def cmd_build(_args):
    """Keyless gate: build both pieces, decode them back through the
    canonical readers, and prove the placeholder discipline."""
    from scene import read_scene_quipu
    from bindings import read_binding_quipu
    ps, placeholder_of = pieces()
    sh2, sb2 = build_v2_scene()
    scene = read_scene_quipu(sh2, sb2)
    sb = sb2
    print("v2 scene: %r | fields %s" % (scene["title"], scene["fields"]))
    print("  nodes: %d | animations: %d | body: %d B"
          % (len(scene["nodes"]), len(scene["animations"]), len(sb)))
    periods = {a["name"]: a["samplers"][0]["input"][-1] for a in scene["animations"]}
    for k in sorted(periods, key=periods.get):
        print("    %-28s %6.1f s" % (k, periods[k]))
    ch, cb = build_catalog()
    binding = read_binding_quipu(ch, cb)
    print("catalog (0xab, tone 0x%02x): %d B" % (binding["tone"], len(cb)))
    ph = placeholder_of(V2_PID)
    n_ph = binding["body"].count(ph)
    print("  placeholder occurrences: %d (backfilled to the v2 root at signing)" % n_ph)
    assert n_ph == 2, "expected the placeholder exactly twice (correction + subject)"
    # determinism: a second build must be byte-identical
    ps2, _ = pieces()
    assert ps2 == ps, "build is not deterministic!"
    print("deterministic rebuild: byte-identical ✓")
    return ps, placeholder_of


def cmd_sign(args):
    from colegio_tools import import_privKey
    from quipu_diamond import FeePolicy, build_consolidated_diamond, write_artifacts
    from quipu_preflight import preflight
    ps, placeholder_of = cmd_build(args)
    txid, vout, value = args.utxo.split(":")
    utxo = {"output": "%s:%s" % (txid, vout), "value": int(value)}
    priv = import_privKey(os.path.expanduser(args.keyfile),
                          getpass.getpass("keyfile password: "))
    art = build_consolidated_diamond(
        ps, placeholder_of, utxo, priv, args.address,
        FeePolicy(rate_kb=0.0311, floor_doge=0.005))
    write_artifacts(art, ART_DIR)
    preflight(ART_DIR)
    print("signed → %s   (broadcast when ready)" % ART_DIR)


def cmd_broadcast(_args):
    from quipu_diamond import broadcast_consolidated_diamond
    broadcast_consolidated_diamond(ART_DIR)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build").set_defaults(fn=cmd_build)
    sp = sub.add_parser("sign")
    sp.add_argument("--utxo", required=True)
    sp.add_argument("--address", required=True)
    sp.add_argument("--keyfile", required=True)
    sp.set_defaults(fn=cmd_sign)
    sub.add_parser("broadcast").set_defaults(fn=cmd_broadcast)
    args = ap.parse_args()
    args.fn(args)
