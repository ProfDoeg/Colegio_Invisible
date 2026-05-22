"""Quipu type 0x3d — Scene.

A scene quipu carries a glTF-2.0-shaped JSON body describing a 3D world:
ordered nodes with transforms (translation, quaternion rotation, scale),
optional animations with SLERP/lerp keyframes, and per-node `extras`
carrying the quipu-protocol dialect (quipu_ref, object_kind, portal_mode,
lock_ref, sound_ref, proximity_trigger).

The format is declarative — it describes WHAT IS in the world. How a
user navigates the scene (locomotion, controls, collision) is a
renderer concern outside the protocol.

See docs/quipu-types/scene.md for the canonical spec.

STATUS: CANONICAL v1.  Builder + reader + accessors + slerp implemented.
walk_scene_tree and evaluate_animation deferred to v1.1 (not required
for the first cemetery inscription).
"""
from __future__ import annotations

import json
import math
import re


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TYPE_SCENE = 0x3d
PROTOCOL_MAGIC = b"\xc1\xdd\x00\x01"

TONE_ORDINARY  = 0x00
TONE_AFFECTION = 0x01
TONE_REVERENCE = 0xff
_VALID_TONES = (TONE_ORDINARY, TONE_AFFECTION, TONE_REVERENCE)

GLTF_VERSION = "2.0"
GENERATOR    = "quipu-3d/v1"

KNOWN_OBJECT_KINDS = frozenset({
    "plane", "sphere", "cube", "model",
    "light", "camera",
    "subscene", "audio", "text", "marker",
})

PORTAL_MODES = frozenset({"embed", "portal"})

INTERPOLATION_MODES = frozenset({"LINEAR", "STEP", "CUBICSPLINE"})

ANIMATION_PATHS = frozenset({
    "translation",
    "rotation",
    "scale",
    "weights",
})

QUAT_NORM_TOLERANCE = 1e-3
DEFAULT_MAX_DEPTH = 8

_HEX_TXID_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# Keys in `extras` whose values are txid references to other quipus.
# Used by scene_quipu_refs() to enumerate every off-scene dependency.
_REF_EXTRAS_KEYS = ("quipu_ref", "lock_ref", "sound_ref", "caption_quipu_ref")


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def quaternion_norm(q):
    """Return the L2 norm of a quaternion (x, y, z, w)."""
    if len(q) != 4:
        raise ValueError(f"quaternion must be length 4, got {len(q)}")
    return math.sqrt(q[0]*q[0] + q[1]*q[1] + q[2]*q[2] + q[3]*q[3])


def is_unit_quaternion(q, tolerance=QUAT_NORM_TOLERANCE):
    """Return True if q is a unit quaternion within the given tolerance."""
    try:
        n = quaternion_norm(q)
    except ValueError:
        return False
    return abs(n - 1.0) <= tolerance


def _is_hex_txid(s):
    return isinstance(s, str) and bool(_HEX_TXID_RE.match(s))


def _validate_gltf_body(gltf):
    """Structural validation of the scene's JSON body. Raises ValueError on
    any infraction. Returns silently on success."""
    if not isinstance(gltf, dict):
        raise ValueError("gltf_body must be a dict")

    # asset.version
    asset = gltf.get("asset")
    if not isinstance(asset, dict):
        raise ValueError("gltf.asset is required and must be a dict")
    if asset.get("version") != GLTF_VERSION:
        raise ValueError(
            f"gltf.asset.version must be {GLTF_VERSION!r}, got {asset.get('version')!r}"
        )

    # scene + scenes
    scene_idx = gltf.get("scene")
    scenes    = gltf.get("scenes")
    if not isinstance(scenes, list) or not scenes:
        raise ValueError("gltf.scenes must be a non-empty list")
    if not isinstance(scene_idx, int):
        raise ValueError("gltf.scene must be an integer index into scenes[]")
    if not (0 <= scene_idx < len(scenes)):
        raise ValueError(
            f"gltf.scene index {scene_idx} out of range "
            f"(0..{len(scenes)-1})"
        )

    # nodes
    nodes = gltf.get("nodes", [])
    if not isinstance(nodes, list):
        raise ValueError("gltf.nodes must be a list")

    for i, node in enumerate(nodes):
        if not isinstance(node, dict):
            raise ValueError(f"gltf.nodes[{i}] must be a dict")
        # rotation, if present, must be unit quaternion
        rot = node.get("rotation")
        if rot is not None:
            if not isinstance(rot, list) or len(rot) != 4:
                raise ValueError(
                    f"gltf.nodes[{i}].rotation must be a 4-element list"
                )
            if not is_unit_quaternion(rot):
                raise ValueError(
                    f"gltf.nodes[{i}].rotation must be a unit quaternion "
                    f"(norm = {quaternion_norm(rot):.6f}, "
                    f"tolerance = {QUAT_NORM_TOLERANCE})"
                )
        # extras: validate any txid-bearing keys
        extras = node.get("extras")
        if isinstance(extras, dict):
            for key in _REF_EXTRAS_KEYS:
                if key in extras and not _is_hex_txid(extras[key]):
                    raise ValueError(
                        f"gltf.nodes[{i}].extras.{key} must be a 64-char "
                        f"hex txid, got {extras[key]!r}"
                    )
            # subscene nodes must have a valid portal_mode if present
            if extras.get("object_kind") == "subscene":
                pm = extras.get("portal_mode", "embed")
                if pm not in PORTAL_MODES:
                    raise ValueError(
                        f"gltf.nodes[{i}].extras.portal_mode must be one of "
                        f"{sorted(PORTAL_MODES)}, got {pm!r}"
                    )

    # animations (optional)
    for ai, anim in enumerate(gltf.get("animations", [])):
        if not isinstance(anim, dict):
            raise ValueError(f"gltf.animations[{ai}] must be a dict")
        samplers = anim.get("samplers", [])
        for si, samp in enumerate(samplers):
            interp = samp.get("interpolation", "LINEAR")
            if interp not in INTERPOLATION_MODES:
                raise ValueError(
                    f"gltf.animations[{ai}].samplers[{si}].interpolation "
                    f"must be one of {sorted(INTERPOLATION_MODES)}, got {interp!r}"
                )
            inp  = samp.get("input",  [])
            outp = samp.get("output", [])
            if interp == "CUBICSPLINE":
                # CUBICSPLINE has 3 values per keyframe (in-tangent, value, out-tangent)
                if len(outp) != 3 * len(inp):
                    raise ValueError(
                        f"gltf.animations[{ai}].samplers[{si}]: "
                        f"CUBICSPLINE expects len(output) == 3*len(input), "
                        f"got {len(outp)} vs 3*{len(inp)}"
                    )
            else:
                if len(outp) != len(inp):
                    raise ValueError(
                        f"gltf.animations[{ai}].samplers[{si}]: "
                        f"len(output) {len(outp)} != len(input) {len(inp)}"
                    )
        for ci, ch in enumerate(anim.get("channels", [])):
            target = ch.get("target", {})
            path = target.get("path")
            if path not in ANIMATION_PATHS:
                raise ValueError(
                    f"gltf.animations[{ai}].channels[{ci}].target.path "
                    f"must be one of {sorted(ANIMATION_PATHS)}, got {path!r}"
                )


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_scene_quipu(title, gltf_body, tone=TONE_ORDINARY, fields=None):
    """Build a 0x3d scene quipu's (header_bytes, body_bytes) pair.

    See module docstring for full contract.
    """
    if tone not in _VALID_TONES:
        raise ValueError(
            f"tone must be 0x00, 0x01, or 0xff (got {tone:#04x})"
        )
    if not isinstance(title, str):
        raise TypeError(f"title must be str, got {type(title).__name__}")
    if "|" in title:
        raise ValueError("title contains '|' (field separator)")
    if "=" in title:
        raise ValueError("title contains '=' (would parse as key=value)")

    fields = dict(fields) if fields else {}
    seen_keys = set()
    for k, v in fields.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise TypeError(
                f"field keys and values must be str (got {type(k).__name__}={type(v).__name__})"
            )
        if "|" in k or "|" in v:
            raise ValueError(f"field {k!r}: '|' forbidden")
        if "=" in k:
            raise ValueError(f"field key {k!r} contains '='")
        if k in seen_keys:
            raise ValueError(f"duplicate field key {k!r}")
        seen_keys.add(k)

    _validate_gltf_body(gltf_body)

    # Deterministic JSON serialization — sorted keys, compact separators,
    # UTF-8 with non-ASCII preserved.  Identical bytes on every build.
    body_bytes = json.dumps(
        gltf_body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    header = PROTOCOL_MAGIC + bytes([TYPE_SCENE, tone])
    if title or fields:
        parts = [title] + [f"{k}={v}" for k, v in fields.items()]
        header += b"|" + "|".join(parts).encode("utf-8") + b"|"

    return header, body_bytes


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------

def read_scene_quipu(header_bytes, body_bytes):
    """Parse a 0x3d scene quipu's bytes into structured form.

    See module docstring for full contract.
    """
    if header_bytes[:4] != PROTOCOL_MAGIC:
        raise ValueError("not a quipu (c1dd0001 magic missing)")
    if len(header_bytes) < 6:
        raise ValueError(f"header too short: {len(header_bytes)} < 6 bytes")
    if header_bytes[4] != TYPE_SCENE:
        raise ValueError(
            f"not a scene quipu (type byte = {header_bytes[4]:#04x}, expected 0x3d)"
        )

    tone = header_bytes[5]
    tail = header_bytes[6:].rstrip(b"\x00 ")

    title = ""
    fields = {}
    if tail:
        text = tail.decode("utf-8", errors="replace")
        if "|" in text:
            parts = [p for p in text.split("|") if p != ""]
        else:
            parts = [text]
        for i, part in enumerate(parts):
            if i == 0 and "=" not in part:
                title = part
            elif "=" in part:
                key, value = part.split("=", 1)
                fields[key.strip()] = value.strip()

    # decode + parse body
    try:
        body_text = body_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"body is not valid UTF-8: {e}")
    try:
        gltf = json.loads(body_text)
    except json.JSONDecodeError as e:
        raise ValueError(f"body is not valid JSON: {e}")

    if not isinstance(gltf, dict):
        raise ValueError("body JSON must be a dict")
    asset = gltf.get("asset")
    if not isinstance(asset, dict):
        raise ValueError("body.asset missing or not a dict")
    if asset.get("version") != GLTF_VERSION:
        raise ValueError(
            f"body.asset.version must be {GLTF_VERSION!r}, "
            f"got {asset.get('version')!r}"
        )
    if "scenes" not in gltf or not isinstance(gltf["scenes"], list):
        raise ValueError("body.scenes missing or not a list")
    if "scene" not in gltf or not isinstance(gltf["scene"], int):
        raise ValueError("body.scene missing or not an int")

    return {
        "title":       title,
        "tone":        tone,
        "fields":      fields,
        "gltf":        gltf,
        "nodes":       gltf.get("nodes", []),
        "scene_index": gltf["scene"],
        "animations":  gltf.get("animations", []),
        "cameras":     gltf.get("cameras", []),
    }


# ---------------------------------------------------------------------------
# Convenience accessors
# ---------------------------------------------------------------------------

def scene_nodes_by_kind(parsed, kind):
    """Iterate (index, node) pairs whose extras.object_kind equals `kind`."""
    for i, node in enumerate(parsed["nodes"]):
        extras = node.get("extras") if isinstance(node, dict) else None
        if isinstance(extras, dict) and extras.get("object_kind") == kind:
            yield i, node


def scene_subscene_refs(parsed):
    """Return [(node_index, quipu_ref, portal_mode)] for every subscene node."""
    out = []
    for i, node in scene_nodes_by_kind(parsed, "subscene"):
        extras = node.get("extras", {})
        ref = extras.get("quipu_ref")
        if ref is None:
            continue
        portal_mode = extras.get("portal_mode", "embed")
        out.append((i, ref, portal_mode))
    return out


def scene_locked_refs(parsed):
    """Return [(node_index, lock_ref)] for every node with a lock_ref."""
    out = []
    for i, node in enumerate(parsed["nodes"]):
        extras = node.get("extras") if isinstance(node, dict) else None
        if isinstance(extras, dict) and "lock_ref" in extras:
            out.append((i, extras["lock_ref"]))
    return out


def scene_quipu_refs(parsed):
    """Return [(node_index, ref_kind, quipu_ref)] for every off-scene quipu
    reference. ref_kind is one of: 'content', 'lock', 'sound', 'caption'."""
    out = []
    for i, node in enumerate(parsed["nodes"]):
        extras = node.get("extras") if isinstance(node, dict) else None
        if not isinstance(extras, dict):
            continue
        for key, kind_label in (
            ("quipu_ref",         "content"),
            ("lock_ref",          "lock"),
            ("sound_ref",         "sound"),
            ("caption_quipu_ref", "caption"),
        ):
            ref = extras.get(key)
            if ref is not None:
                out.append((i, kind_label, ref))
    return out


# ---------------------------------------------------------------------------
# Recursive walker (deferred to v1.1 — not required for first inscription)
# ---------------------------------------------------------------------------

def walk_scene_tree(parsed, fetcher, max_depth=DEFAULT_MAX_DEPTH, visited=None):
    """Recursively descend embedded sub-scenes.

    DEFERRED to v1.1.  The cemetery scene (the first inscription) has no
    embedded sub-scenes, so the walker is not required to ship.  The
    enumeration helper scene_subscene_refs() exposes the refs that would
    be followed.
    """
    raise NotImplementedError("walk_scene_tree deferred to v1.1")


# ---------------------------------------------------------------------------
# Animation helpers
# ---------------------------------------------------------------------------

def evaluate_animation(parsed, animation_index, t):
    """Compute the interpolated transform state at time `t` for an animation.

    DEFERRED to v1.1.  The cemetery scene has no `animations` table — the
    sky's rotation lives in the renderer convention (extras.rotation_period_sec)
    rather than as a glTF animation channel — so the evaluator is not
    required to ship.
    """
    raise NotImplementedError("evaluate_animation deferred to v1.1")


def slerp(q_a, q_b, alpha):
    """Spherical linear interpolation between unit quaternions q_a and q_b."""
    if len(q_a) != 4 or len(q_b) != 4:
        raise ValueError("quaternions must be length 4")
    x_a, y_a, z_a, w_a = q_a[0], q_a[1], q_a[2], q_a[3]
    x_b, y_b, z_b, w_b = q_b[0], q_b[1], q_b[2], q_b[3]

    dot = x_a*x_b + y_a*y_b + z_a*z_b + w_a*w_b

    # Take the shorter great-circle arc
    if dot < 0.0:
        x_b, y_b, z_b, w_b = -x_b, -y_b, -z_b, -w_b
        dot = -dot

    # Nearly aligned — fall back to normalized lerp for numerical stability
    if dot > 0.9995:
        x = x_a + alpha * (x_b - x_a)
        y = y_a + alpha * (y_b - y_a)
        z = z_a + alpha * (z_b - z_a)
        w = w_a + alpha * (w_b - w_a)
        n = math.sqrt(x*x + y*y + z*z + w*w)
        if n == 0:
            return (0.0, 0.0, 0.0, 1.0)
        return (x/n, y/n, z/n, w/n)

    theta = math.acos(max(-1.0, min(1.0, dot)))
    sin_theta = math.sin(theta)
    a = math.sin((1.0 - alpha) * theta) / sin_theta
    b = math.sin(alpha * theta) / sin_theta
    return (
        a*x_a + b*x_b,
        a*y_a + b*y_b,
        a*z_a + b*z_b,
        a*w_a + b*w_b,
    )


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _tiny_scene_body():
    """A minimal valid scene body used as a test fixture."""
    return {
        "asset": {"version": "2.0", "generator": "quipu-3d/v1"},
        "scene": 0,
        "scenes": [{"name": "main", "nodes": [0, 1]}],
        "nodes": [
            {
                "name":        "test_plane",
                "translation": [1.0, 0.5, -2.0],
                "rotation":    [0, 0, 0, 1],
                "scale":       [1, 1, 1],
                "extras": {
                    "object_kind": "plane",
                    "quipu_ref":   "a" * 64,
                    "label":       "test",
                },
            },
            {
                "name":        "test_camera",
                "translation": [0, 1.6, 4],
                "extras": {"object_kind": "camera"},
            },
        ],
    }


def _selftest_roundtrip():
    body = _tiny_scene_body()
    header, body_bytes = build_scene_quipu(
        title="Test Scene",
        gltf_body=body,
        tone=TONE_ORDINARY,
        fields={"author": "El Ermitaño", "date": "2026-05-22"},
    )
    # Header sanity
    assert header[:4] == PROTOCOL_MAGIC
    assert header[4] == TYPE_SCENE
    assert header[5] == TONE_ORDINARY
    assert b"|Test Scene|" in header
    assert "author=El Ermitaño".encode("utf-8") in header

    # Body sanity — deterministic compact JSON
    body_text = body_bytes.decode("utf-8")
    assert '"asset":{"generator":"quipu-3d/v1","version":"2.0"}' in body_text
    assert '"scene":0' in body_text

    # Round-trip
    parsed = read_scene_quipu(header, body_bytes)
    assert parsed["title"] == "Test Scene"
    assert parsed["tone"]  == TONE_ORDINARY
    assert parsed["fields"]["author"] == "El Ermitaño"
    assert parsed["fields"]["date"]   == "2026-05-22"
    assert parsed["scene_index"]      == 0
    assert len(parsed["nodes"])       == 2
    assert parsed["nodes"][0]["extras"]["object_kind"] == "plane"
    assert parsed["nodes"][0]["extras"]["quipu_ref"]   == "a" * 64

    # Reproducibility — same input, identical bytes
    header2, body2 = build_scene_quipu(
        title="Test Scene",
        gltf_body=body,
        fields={"author": "El Ermitaño", "date": "2026-05-22"},
    )
    assert header == header2
    assert body_bytes == body2

    print(f"  ✓ roundtrip: header {len(header)}B + body {len(body_bytes)}B, "
          f"reproducible")


def _selftest_validation():
    base = _tiny_scene_body()

    def expect(name, fn, want_substr):
        try:
            fn()
        except (ValueError, TypeError) as e:
            if want_substr in str(e):
                print(f"  ✓ {name}: {str(e)[:80]}")
                return
            print(f"  ✗ {name}: WRONG ERROR — {e}")
        else:
            print(f"  ✗ {name}: DID NOT RAISE")

    expect("title with pipe",
           lambda: build_scene_quipu("a|b", base),
           "field separator")
    expect("title with equals",
           lambda: build_scene_quipu("a=b", base),
           "key=value")
    expect("bad tone",
           lambda: build_scene_quipu("ok", base, tone=0x42),
           "tone")
    expect("field key with =",
           lambda: build_scene_quipu("ok", base, fields={"a=b": "1"}),
           "=")
    expect("field value with |",
           lambda: build_scene_quipu("ok", base, fields={"a": "1|2"}),
           "|")

    # gltf-body validation
    def bad_version():
        b = _tiny_scene_body(); b["asset"]["version"] = "1.0"
        build_scene_quipu("ok", b)
    expect("asset.version != 2.0", bad_version, "version")

    def bad_scene_idx():
        b = _tiny_scene_body(); b["scene"] = 5
        build_scene_quipu("ok", b)
    expect("scene index out of range", bad_scene_idx, "out of range")

    def bad_rotation():
        b = _tiny_scene_body()
        b["nodes"][0]["rotation"] = [1, 0, 0, 0.5]  # not unit
        build_scene_quipu("ok", b)
    expect("non-unit rotation", bad_rotation, "unit quaternion")

    def bad_quipu_ref():
        b = _tiny_scene_body()
        b["nodes"][0]["extras"]["quipu_ref"] = "not-hex"
        build_scene_quipu("ok", b)
    expect("invalid quipu_ref hex", bad_quipu_ref, "hex")

    def bad_portal_mode():
        b = _tiny_scene_body()
        b["nodes"][0]["extras"]["object_kind"] = "subscene"
        b["nodes"][0]["extras"]["portal_mode"] = "teleport"
        build_scene_quipu("ok", b)
    expect("invalid portal_mode", bad_portal_mode, "portal_mode")


def _selftest_slerp():
    # identity → identity is identity
    q = slerp((0,0,0,1), (0,0,0,1), 0.5)
    assert abs(q[3] - 1.0) < 1e-9, f"slerp(I,I) = {q}"

    # endpoints
    qa = (0.7071, 0, 0, 0.7071)  # 90° rotation around X
    qb = (0, 0.7071, 0, 0.7071)  # 90° rotation around Y
    q0 = slerp(qa, qb, 0.0)
    q1 = slerp(qa, qb, 1.0)
    assert all(abs(a - b) < 1e-3 for a, b in zip(q0, qa))
    assert all(abs(a - b) < 1e-3 for a, b in zip(q1, qb))

    # midpoint should still be a unit quaternion
    qm = slerp(qa, qb, 0.5)
    assert is_unit_quaternion(qm, tolerance=1e-3), \
        f"slerp midpoint not unit: norm = {quaternion_norm(qm)}"

    # quaternion_norm + is_unit_quaternion basic tests
    assert is_unit_quaternion((0, 0, 0, 1))
    assert not is_unit_quaternion((1, 1, 1, 1))
    assert abs(quaternion_norm((1, 1, 1, 1)) - 2.0) < 1e-9

    print(f"  ✓ slerp: identity, endpoints, midpoint-stays-unit all pass")


def _selftest_accessors():
    body = {
        "asset": {"version": "2.0"},
        "scene": 0,
        "scenes": [{"nodes": [0, 1, 2]}],
        "nodes": [
            {"name": "plane_a", "extras": {
                "object_kind": "plane",
                "quipu_ref": "a"*64,
                "lock_ref": "b"*64,
            }},
            {"name": "subscene_b", "extras": {
                "object_kind": "subscene",
                "quipu_ref": "c"*64,
                "portal_mode": "portal",
            }},
            {"name": "audio_c", "extras": {
                "object_kind": "audio",
                "sound_ref": "d"*64,
            }},
        ],
    }
    header, body_bytes = build_scene_quipu("Accessors", body)
    parsed = read_scene_quipu(header, body_bytes)

    planes = list(scene_nodes_by_kind(parsed, "plane"))
    assert len(planes) == 1 and planes[0][0] == 0

    subs = scene_subscene_refs(parsed)
    assert subs == [(1, "c"*64, "portal")], f"got {subs}"

    locks = scene_locked_refs(parsed)
    assert locks == [(0, "b"*64)], f"got {locks}"

    refs = scene_quipu_refs(parsed)
    expected = [
        (0, "content", "a"*64),
        (0, "lock",    "b"*64),
        (1, "content", "c"*64),
        (2, "sound",   "d"*64),
    ]
    assert refs == expected, f"got {refs}\nwant {expected}"
    print(f"  ✓ accessors: by_kind, subscene_refs, locked_refs, quipu_refs")


def _selftest_worked_example():
    """Build a cemetery-style scene that mirrors the prototype scene
    structure, verify round-trip and reference enumeration."""
    body = {
        "asset":  {"version": "2.0", "generator": "quipu-3d/v1"},
        "scene":  0,
        "scenes": [{"name": "main", "nodes": [0, 1, 2]}],
        "nodes": [
            {
                "name": "sky_of_al_jawza",
                "extras": {
                    "object_kind":         "celestial",  # extension kind
                    "quipu_ref":           "2ae7fe909e19c0e4646f7981d0feffc96f4a3b286539f3da8caf19aebcf93bb2",
                    "latitude_deg":        -34.6,
                    "longitude_deg":       -58.4,
                    "initial_lst_deg":     87,
                    "rotation_period_sec": 90,
                },
            },
            {
                "name":        "bea_portrait",
                "translation": [0, 1.35, -3.11],
                "scale":       [0.62, 0.62, 1],
                "extras": {
                    "object_kind": "plane",
                    "quipu_ref":   "a01e8625d653f4a8686b5b9e20ca653e59ebcd8bf2ca2a7b8370fdc52417f7b9",
                    "label":       "Peter Bea",
                },
            },
            {
                "name":        "default_camera",
                "translation": [0, 1.6, 4],
                "extras":      {"object_kind": "camera", "fov_deg": 68},
            },
        ],
    }
    header, body_bytes = build_scene_quipu(
        title="Cementerio de los Animales (worked example)",
        gltf_body=body,
        fields={"author": "El Ermitaño", "date": "2026-05-22", "lang": "es"},
    )
    parsed = read_scene_quipu(header, body_bytes)
    assert parsed["title"].startswith("Cementerio")
    assert parsed["fields"]["author"] == "El Ermitaño"
    assert len(parsed["nodes"]) == 3

    refs = scene_quipu_refs(parsed)
    refs_just_txids = [r[2] for r in refs]
    assert "2ae7fe909e19c0e4646f7981d0feffc96f4a3b286539f3da8caf19aebcf93bb2" in refs_just_txids
    assert "a01e8625d653f4a8686b5b9e20ca653e59ebcd8bf2ca2a7b8370fdc52417f7b9" in refs_just_txids

    print(f"  ✓ worked example: header {len(header)}B + body {len(body_bytes)}B, "
          f"{len(refs)} quipu refs enumerated")


if __name__ == "__main__":
    print("=== scene.py self-tests ===")
    print("\n[roundtrip]");      _selftest_roundtrip()
    print("\n[validation]");     _selftest_validation()
    print("\n[slerp]");          _selftest_slerp()
    print("\n[accessors]");      _selftest_accessors()
    print("\n[worked example]"); _selftest_worked_example()
    print("\nall scene self-tests passed.")
