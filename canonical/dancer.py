#!/usr/bin/env python3
"""Quipu type 0xda — dancer / controllable motion-sprite.

One type byte, three variants (a one-byte variant selector, like the encrypted
family's AES/ECIES/keydrop):

    0x01 performance   self-contained: footage frames + control graph inline
    0x02 footage       frames only — the heavy, reusable asset
    0x03 controller    a control graph that REFERENCES a footage txid (overlay,
                       the way keydrop references the sealed thing it opens)

Two codecs are shared across the variants:

  FOOTAGE  a shared palette + N sparse-palette frames. Each frame is a tight
           bbox sprite stored as a 1-bit alpha mask + a palette index per
           opaque pixel, with its centroid (original-frame fraction, for
           re-anchoring) and a facing tag. Transparent pixels cost nothing
           beyond the mask bit.

  GRAPH    the controller: nodes are frame indices (rest / branch points);
           edges are paths with an operation (stay / forward / backward /
           tunnel) and features a controller selects by — net centroid
           displacement (left/right), facing delta, an action label, and the
           frame span. Facing (mirror) is an orthogonal render transform, not
           an edge type.

Header layout (binary, like image / celestial):

    0..3   c1 dd 00 01   magic + protocol version 0.1
    4      da            type = dancer
    5      <tone>        tone byte
    6      <variant>     01 performance | 02 footage | 03 controller
    7      <T>           title length, UTF-8 bytes
    8..    <title>       UTF-8 title
    body   per variant (see below)
"""
import math
import struct

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tone import (validate_tone, TONE_ORDINARY, TONE_AFFECTION,  # noqa: F401
                  TONE_DEMONIC, TONE_AI, TONE_REVERENCE)
from image import pack_pixels, unpack_pixels

MAGIC = b"\xc1\xdd\x00\x01"
TYPE_DANCER = 0xDA

VAR_PERFORMANCE = 0x01
VAR_FOOTAGE     = 0x02
VAR_CONTROLLER  = 0x03
_VAR_NAME = {VAR_PERFORMANCE: "performance", VAR_FOOTAGE: "footage",
             VAR_CONTROLLER: "controller"}

# facing tags (mirror swaps profile_r <-> profile_l)
FACE_FRONT, FACE_BACK, FACE_PROFILE_R, FACE_PROFILE_L = 0, 1, 2, 3
_FACE_NAME = {0: "front", 1: "back", 2: "profile_r", 3: "profile_l"}

# path operations
OP_STAY, OP_FORWARD, OP_BACKWARD, OP_TUNNEL = 0, 1, 2, 3
_OP_NAME = {0: "stay", 1: "forward", 2: "backward", 3: "tunnel"}

# edge labels (action classes) — extend freely; the byte is opaque to the codec
LABEL_IDLE, LABEL_STEP, LABEL_TURN, LABEL_GESTURE = 0, 1, 2, 3
_LABEL_NAME = {0: "idle", 1: "step", 2: "turn", 3: "gesture"}


def _idx_bits(pal_n):
    return max(1, math.ceil(math.log2(pal_n))) if pal_n > 1 else 1


# ---------------------------------------------------------------------------
# FOOTAGE codec
# ---------------------------------------------------------------------------

def _emit_footage(palette, frames):
    """palette: list of (r,g,b) 0..255. frames: list of dicts
       {w, h, cx, cy, facing, mask:[0/1 len w*h], idx:[pal index per opaque px]}."""
    pal_n = len(palette)
    if not (1 <= pal_n <= 255):
        raise ValueError("palette size must be 1..255")
    if len(frames) > 0xFFFF:
        raise ValueError("max 65535 frames")
    ib = _idx_bits(pal_n)
    out = bytearray()
    out += bytes([pal_n])
    out += struct.pack(">H", len(frames))
    out += bytes([ib])
    for (r, g, b) in palette:
        out += bytes([r & 255, g & 255, b & 255])
    for f in frames:
        w, h = f["w"], f["h"]
        if not (1 <= w <= 0xFFFF and 1 <= h <= 0xFFFF):
            raise ValueError("frame dims out of range")
        if len(f["mask"]) != w * h:
            raise ValueError("mask length != w*h")
        n_op = sum(f["mask"])
        if len(f["idx"]) != n_op:
            raise ValueError("idx length != opaque-pixel count")
        out += struct.pack(">HH", w, h)
        out += struct.pack(">ff", float(f["cx"]), float(f["cy"]))
        out += bytes([f["facing"] & 255])
        out += pack_pixels(f["mask"], 1)
        out += pack_pixels(f["idx"], ib)
    return bytes(out)


def _read_footage(buf, off):
    pal_n = buf[off]; off += 1
    P = struct.unpack(">H", buf[off:off+2])[0]; off += 2
    ib = buf[off]; off += 1
    palette = []
    for _ in range(pal_n):
        palette.append((buf[off], buf[off+1], buf[off+2])); off += 3
    frames = []
    for _ in range(P):
        w, h = struct.unpack(">HH", buf[off:off+4]); off += 4
        cx, cy = struct.unpack(">ff", buf[off:off+8]); off += 8
        facing = buf[off]; off += 1
        mbytes = math.ceil(w*h / 8)
        mask = unpack_pixels(buf[off:off+mbytes], w*h, 1); off += mbytes
        n_op = sum(mask)
        ibytes = math.ceil(n_op * ib / 8)
        idx = unpack_pixels(buf[off:off+ibytes], n_op, ib); off += ibytes
        frames.append({"w": w, "h": h, "cx": cx, "cy": cy, "facing": facing,
                       "mask": mask, "idx": idx})
    return {"palette": palette, "frames": frames}, off


# ---------------------------------------------------------------------------
# GRAPH (controller) codec
# ---------------------------------------------------------------------------

def _emit_graph(nodes, edges):
    """nodes: list of frame indices (uint16). edges: list of dicts
       {src, dst, op, span:(a,b), dx, dy, facing_delta, label}."""
    out = bytearray()
    out += struct.pack(">H", len(nodes))
    for fidx in nodes:
        out += struct.pack(">H", fidx)
    out += struct.pack(">H", len(edges))
    for e in edges:
        out += struct.pack(">HH", e["src"], e["dst"])
        out += bytes([e["op"] & 255])
        out += struct.pack(">HH", e["span"][0], e["span"][1])
        out += struct.pack(">ff", float(e["dx"]), float(e["dy"]))
        out += bytes([e.get("facing_delta", 0) & 255])
        out += bytes([e.get("label", 0) & 255])
    return bytes(out)


def _read_graph(buf, off):
    N = struct.unpack(">H", buf[off:off+2])[0]; off += 2
    nodes = []
    for _ in range(N):
        nodes.append(struct.unpack(">H", buf[off:off+2])[0]); off += 2
    E = struct.unpack(">H", buf[off:off+2])[0]; off += 2
    edges = []
    for _ in range(E):
        src, dst = struct.unpack(">HH", buf[off:off+4]); off += 4
        op = buf[off]; off += 1
        sa, sb = struct.unpack(">HH", buf[off:off+4]); off += 4
        dx, dy = struct.unpack(">ff", buf[off:off+8]); off += 8
        fd = buf[off]; off += 1
        lab = buf[off]; off += 1
        edges.append({"src": src, "dst": dst, "op": op, "span": (sa, sb),
                      "dx": dx, "dy": dy, "facing_delta": fd, "label": lab})
    return {"nodes": nodes, "edges": edges}, off


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_dancer(variant, title, *, tone=TONE_ORDINARY, palette=None,
                 frames=None, nodes=None, edges=None, footage_txid=None):
    """Build a 0xda dancer (header_bytes, body_bytes).

    variant=performance: needs palette+frames and nodes+edges.
    variant=footage:     needs palette+frames.
    variant=controller:  needs footage_txid (64-hex or 32 bytes) and nodes+edges.
    """
    validate_tone(tone)
    if variant not in _VAR_NAME:
        raise ValueError("unknown variant %r" % variant)
    tb = title.encode("utf-8")
    if len(tb) > 255:
        raise ValueError("title > 255 UTF-8 bytes")
    header = MAGIC + bytes([TYPE_DANCER, tone, variant, len(tb)]) + tb

    body = bytearray()
    if variant in (VAR_PERFORMANCE, VAR_FOOTAGE):
        if palette is None or frames is None:
            raise ValueError("footage variants need palette and frames")
        body += _emit_footage(palette, frames)
    if variant == VAR_CONTROLLER:
        if footage_txid is None:
            raise ValueError("controller needs footage_txid")
        raw = (bytes.fromhex(footage_txid) if isinstance(footage_txid, str)
               else bytes(footage_txid))
        if len(raw) != 32:
            raise ValueError("footage_txid must be 32 bytes / 64 hex")
        body += raw
    if variant in (VAR_PERFORMANCE, VAR_CONTROLLER):
        if nodes is None or edges is None:
            raise ValueError("performance/controller need nodes and edges")
        body += _emit_graph(nodes, edges)
    return header, bytes(body)


# convenience wrappers
def build_dancer_footage(title, palette, frames, tone=TONE_ORDINARY):
    return build_dancer(VAR_FOOTAGE, title, tone=tone, palette=palette, frames=frames)


def build_dancer_performance(title, palette, frames, nodes, edges, tone=TONE_ORDINARY):
    return build_dancer(VAR_PERFORMANCE, title, tone=tone, palette=palette,
                        frames=frames, nodes=nodes, edges=edges)


def build_dancer_controller(title, footage_txid, nodes, edges, tone=TONE_ORDINARY):
    return build_dancer(VAR_CONTROLLER, title, tone=tone,
                        footage_txid=footage_txid, nodes=nodes, edges=edges)


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------

def read_dancer(header_bytes, body_bytes):
    if header_bytes[:4] != MAGIC:
        raise ValueError("bad magic")
    if header_bytes[4] != TYPE_DANCER:
        raise ValueError("not a dancer (type %#04x)" % header_bytes[4])
    tone = header_bytes[5]
    variant = header_bytes[6]
    tlen = header_bytes[7]
    title = header_bytes[8:8+tlen].decode("utf-8")
    out = {"tone": tone, "variant": variant, "variant_name": _VAR_NAME.get(variant),
           "title": title}
    off = 0
    if variant in (VAR_PERFORMANCE, VAR_FOOTAGE):
        foot, off = _read_footage(body_bytes, off)
        out["footage"] = foot
    if variant == VAR_CONTROLLER:
        out["footage_txid"] = body_bytes[off:off+32].hex(); off += 32
    if variant in (VAR_PERFORMANCE, VAR_CONTROLLER):
        graph, off = _read_graph(body_bytes, off)
        out["graph"] = graph
    return out


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _selftest():
    # tiny 2-frame footage: a 2x2 sprite, palette of 2 colours
    palette = [(200, 30, 30), (30, 30, 200)]
    f0 = {"w": 2, "h": 2, "cx": 0.5, "cy": 0.6, "facing": FACE_FRONT,
          "mask": [1, 0, 1, 1], "idx": [0, 1, 0]}      # 3 opaque px
    f1 = {"w": 2, "h": 2, "cx": 0.55, "cy": 0.6, "facing": FACE_PROFILE_R,
          "mask": [1, 1, 0, 1], "idx": [1, 0, 1]}
    nodes = [0, 1]
    edges = [{"src": 0, "dst": 1, "op": OP_FORWARD, "span": (0, 1),
              "dx": 0.05, "dy": 0.0, "facing_delta": 0, "label": LABEL_STEP},
             {"src": 1, "dst": 0, "op": OP_BACKWARD, "span": (1, 0),
              "dx": -0.05, "dy": 0.0, "facing_delta": 0, "label": LABEL_STEP}]

    # performance round-trip
    h, b = build_dancer_performance("Test", palette, [f0, f1], nodes, edges,
                                    tone=TONE_REVERENCE)
    assert h[4] == TYPE_DANCER and h[6] == VAR_PERFORMANCE
    p = read_dancer(h, b)
    assert p["title"] == "Test" and p["tone"] == TONE_REVERENCE
    assert p["footage"]["palette"] == palette
    assert p["footage"]["frames"][0]["mask"] == [1, 0, 1, 1]
    assert p["footage"]["frames"][0]["idx"] == [0, 1, 0]
    assert p["footage"]["frames"][1]["facing"] == FACE_PROFILE_R
    assert abs(p["footage"]["frames"][1]["cx"] - 0.55) < 1e-6
    assert p["graph"]["nodes"] == [0, 1]
    assert p["graph"]["edges"][0]["op"] == OP_FORWARD
    assert abs(p["graph"]["edges"][0]["dx"] - 0.05) < 1e-6
    print("  ✓ performance round-trip (%dB header + %dB body)" % (len(h), len(b)))

    # footage-only
    h2, b2 = build_dancer_footage("Foot", palette, [f0, f1])
    p2 = read_dancer(h2, b2)
    assert p2["variant"] == VAR_FOOTAGE and "graph" not in p2
    assert p2["footage"]["frames"][1]["idx"] == [1, 0, 1]
    print("  ✓ footage round-trip")

    # controller-only (cites a footage txid)
    fake = "ab" * 32
    h3, b3 = build_dancer_controller("Ctl", fake, nodes, edges)
    p3 = read_dancer(h3, b3)
    assert p3["variant"] == VAR_CONTROLLER
    assert p3["footage_txid"] == fake
    assert p3["graph"]["edges"][1]["op"] == OP_BACKWARD
    print("  ✓ controller round-trip (cites footage %s…)" % fake[:12])

    print("dancer 0xda self-test OK")


if __name__ == "__main__":
    _selftest()
