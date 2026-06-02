#!/usr/bin/env python3
"""Quipu type 0xda — dancer / controllable motion-sprite.

Three layers, four variants:

    0x01 performance   self-contained: footage table + graph + controllers, inline
    0x02 footage       a single recording (the reusable, expensive asset)
    0x03 graph         footage TABLE (inline/ref) + the cut topology (nodes+edges)
    0x04 controller    a graph txid + one or more controllers (the intention)

Portability (footage cited once, cheap re-skins on top):
    MODEL A = the whole stack (performance, or controller→graph→footage)
    MODEL B = a new controller citing an existing graph
    MODEL C = a new graph citing an existing footage

Every layer is a selectable TABLE, so a dancer can carry one or many footages
(inline or on other quipu), one or many preference weightings, one or many
control methods, and one or many whole controllers — all optional, a count byte
apiece.

----------------------------------------------------------------------------
Header (every variant)
    0..3  c1 dd 00 01   magic + protocol version 0.1
    4     da            type = dancer
    5     <tone>        tone byte
    6     <variant>     01 perf | 02 footage | 03 graph | 04 controller
    7     <T>           title length (UTF-8 bytes)
    8..   <title>

FOOTAGE block (one recording) — tight sprites + delta(c) storage
    pal_n u8 · N u16 · ib u8 · pal_n×(r g b)      shared palette
    nw u16 · nh u16 · fps u8                      notional frame, playback rate
    keyint u16                                    K: force a keyframe every K frames
    N × frame:
        cx cy    f32×2        centroid (anchor), fraction of the notional frame
        facing   u8           front|back|profile_r|profile_l
        flag     u8           0 = keyframe, 1 = diff
        if keyframe:          x y w h u16×4 · mask w·h bits · idx (nopq×ib bits)
        if diff:              cbx cby cbw cbh u16×4         changed-region bbox
                              cmask cbw·cbh bits            1 = cell changed
                              abits nch bits                1 = now opaque
                              nidx  nopq×ib bits            index per now-opaque cell
    (keyframe vs diff is chosen by byte cost; identical frame = empty diff,
     bbox 0,0,0,0. mask/idx packed MSB-first via image.pack_pixels.)

FOOTAGE table (graph / performance)
    Nfoot u8 · Nfoot × entry
        kind u8   00 inline → <footage block>
                  01 ref    → txid (32 bytes)

GRAPH body (0x03, and inline inside 0x01)
    <footage table>
    Nmode u8                                       control modes
    Llab u8 · Llab×(len u8 + utf8)                 pose-label vocabulary
    start u16                                       start node index
    Nn u16
    Nn × node:  foot u8 · ord u16 · label u8 · sym u8 · narc u8
    edges (per node, narc each):
        dst u16 · flags u8 (b0 time fwd/rev, b1 space same/mirror) · ctrl u8

CONTROLLER list (0x04 after a 32-byte graph txid; 0x01 after an inline graph)
    Nctrl u8 · default_ctrl u8
    Nctrl × controller:
        start u16 · mode0 u8
        Nmethod u8 · default_method u8
        Nmethod × method:  id u8 · plen u8 · params[plen]
        Npref u8
        Npref × pref:  namelen u8 + name · Nw u16 · Nw×(node u16 · eidx u8 · weight u8)
        Nbind u8
        Nbind × binding:  source u8 · port u8 · scale f32
"""
import math
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tone import (validate_tone, TONE_ORDINARY, TONE_AFFECTION,   # noqa: F401
                  TONE_SEEKING, TONE_PLAY, TONE_LUST, TONE_RAGE,
                  TONE_FEAR, TONE_GRIEF,
                  TONE_DEMONIC, TONE_AI, TONE_REVERENCE)
from image import pack_pixels, unpack_pixels

MAGIC = b"\xc1\xdd\x00\x01"
TYPE_DANCER = 0xDA

VAR_PERFORMANCE = 0x01
VAR_FOOTAGE     = 0x02
VAR_GRAPH       = 0x03
VAR_CONTROLLER  = 0x04
_VAR_NAME = {VAR_PERFORMANCE: "performance", VAR_FOOTAGE: "footage",
             VAR_GRAPH: "graph", VAR_CONTROLLER: "controller"}

FOOT_INLINE, FOOT_REF = 0x00, 0x01

# facing tags (mirror swaps profile_r <-> profile_l)
FACE_FRONT, FACE_BACK, FACE_PROFILE_R, FACE_PROFILE_L = 0, 1, 2, 3

# node symmetry class (the breadcrumb marker)
SYM_SAME, SYM_REFLECTED, SYM_SYMMETRIC = 0, 1, 2

# edge flags
TIME_FWD, TIME_REV = 0, 1          # flags bit 0
SPACE_SAME, SPACE_MIRROR = 0, 1    # flags bit 1
CTRL_ALL = 0xFF                    # edge / mode available in all control modes

# controller method ids
M_UNIFORM, M_WEIGHTED, M_BOLTZMANN, M_QUANTUM, M_KEYBOARD = 0x00, 0x01, 0x02, 0x03, 0x10
_METHOD_NAME = {0x00: "uniform", 0x01: "weighted", 0x02: "boltzmann",
                0x03: "quantum", 0x10: "keyboard"}

# quantum generator choices
GEN_SIMILARITY, GEN_SYMNORM, GEN_FULL, GEN_SA = 0, 1, 2, 3

# selection ports / live sources (named; opaque to the codec, meaningful to renderers)
PORT_TARGET, PORT_METHOD_SELECT, PORT_GAIN, PORT_MODE, PORT_MEASURE_RATE = 0, 1, 2, 3, 4
SRC_ATTRACTOR_X, SRC_ATTRACTOR_Z, SRC_KEY_LR, SRC_KEY_UD, SRC_KEY_BTN, SRC_CLOCK = 0, 1, 2, 3, 4, 5


def _idx_bits(pal_n):
    return max(1, math.ceil(math.log2(pal_n))) if pal_n > 1 else 1


# ---------------------------------------------------------------------------
# FOOTAGE block
# ---------------------------------------------------------------------------

def _frame_state(f, nw, nh):
    """Build the full notional-frame index map from a tight sprite (-1 transparent)."""
    st = [-1] * (nw * nh)
    oi = 0
    w = f["w"]
    for r in range(f["h"]):
        for c in range(w):
            if f["mask"][r * w + c]:
                st[(f["y"] + r) * nw + (f["x"] + c)] = f["idx"][oi]; oi += 1
    return st


def _state_sprite(st, nw, nh, cx, cy, facing):
    """Extract a tight sprite (x,y,w,h,mask,idx) from a notional-frame state."""
    op = [p for p in range(nw * nh) if st[p] >= 0]
    if not op:
        return {"x": 0, "y": 0, "w": 1, "h": 1, "cx": cx, "cy": cy,
                "facing": facing, "mask": [0], "idx": []}
    xs = [p % nw for p in op]; ys = [p // nw for p in op]
    x, y = min(xs), min(ys); w = max(xs) - x + 1; h = max(ys) - y + 1
    mask = [1 if st[(y + r) * nw + (x + c)] >= 0 else 0 for r in range(h) for c in range(w)]
    idx = [st[(y + r) * nw + (x + c)] for r in range(h) for c in range(w)
           if st[(y + r) * nw + (x + c)] >= 0]
    return {"x": x, "y": y, "w": w, "h": h, "cx": cx, "cy": cy,
            "facing": facing, "mask": mask, "idx": idx}


def _emit_footage(footage):
    """footage = {palette, frames, nw, nh, fps, keyint?}. Delta(c) storage:
       per-frame metadata always; pixels as a keyframe (full tight sprite, every
       keyint frames or when cheaper) or a diff (changed pixels vs previous, in
       notional coords). Each frame: {x,y,w,h, cx,cy, facing, mask, idx}."""
    palette, frames = footage["palette"], footage["frames"]
    pal_n = len(palette)
    if not (1 <= pal_n <= 255):
        raise ValueError("palette size 1..255")
    if len(frames) > 0xFFFF:
        raise ValueError("max 65535 frames")
    ib = _idx_bits(pal_n); nw, nh = footage["nw"], footage["nh"]
    K = int(footage.get("keyint", 30))
    out = bytearray()
    out += bytes([pal_n]) + struct.pack(">H", len(frames)) + bytes([ib])
    for (r, g, b) in palette:
        out += bytes([r & 255, g & 255, b & 255])
    out += struct.pack(">HHB", nw, nh, footage["fps"] & 255)
    out += struct.pack(">H", K)
    prev = None
    for i, f in enumerate(frames):
        if len(f["mask"]) != f["w"] * f["h"]:
            raise ValueError("mask length != w*h")
        if len(f["idx"]) != sum(f["mask"]):
            raise ValueError("idx length != opaque-pixel count")
        st = _frame_state(f, nw, nh)
        out += struct.pack(">ff", float(f["cx"]), float(f["cy"])) + bytes([f["facing"] & 255])
        kf_cost = 8 + math.ceil(f["w"] * f["h"] / 8) + math.ceil(sum(f["mask"]) * ib / 8)
        changed = None
        if prev is not None and (K <= 0 or i % K != 0):
            changed = [p for p in range(nw * nh) if st[p] != prev[p]]
            if changed:
                xs = [p % nw for p in changed]; ys = [p // nw for p in changed]
                cbw = max(xs) - min(xs) + 1; cbh = max(ys) - min(ys) + 1
                nopq = sum(1 for p in changed if st[p] >= 0)
                d_cost = 8 + math.ceil(cbw * cbh / 8) + math.ceil(len(changed) / 8) + math.ceil(nopq * ib / 8)
            else:
                d_cost = 8
        use_kf = prev is None or (K > 0 and i % K == 0) or changed is None or d_cost >= kf_cost
        if use_kf:
            out += bytes([0])
            out += struct.pack(">HHHH", f["x"], f["y"], f["w"], f["h"])
            out += pack_pixels(f["mask"], 1) + pack_pixels(f["idx"], ib)
        elif changed:
            out += bytes([1])
            xs = [p % nw for p in changed]; ys = [p // nw for p in changed]
            cbx, cby = min(xs), min(ys); cbw = max(xs) - cbx + 1; cbh = max(ys) - cby + 1
            out += struct.pack(">HHHH", cbx, cby, cbw, cbh)
            cmask = [0] * (cbw * cbh)
            for p in changed:
                cmask[(p // nw - cby) * cbw + (p % nw - cbx)] = 1
            out += pack_pixels(cmask, 1)
            abits, nidx = [], []
            for ly in range(cbh):
                for lx in range(cbw):
                    if cmask[ly * cbw + lx]:
                        v = st[(cby + ly) * nw + (cbx + lx)]
                        abits.append(1 if v >= 0 else 0)
                        if v >= 0: nidx.append(v)
            out += pack_pixels(abits, 1)
            if nidx: out += pack_pixels(nidx, ib)
        else:                                                  # identical frame: empty diff
            out += bytes([1]) + struct.pack(">HHHH", 0, 0, 0, 0)
        prev = st
    return bytes(out)


def _read_footage(buf, off):
    pal_n = buf[off]; off += 1
    N = struct.unpack(">H", buf[off:off+2])[0]; off += 2
    ib = buf[off]; off += 1
    palette = []
    for _ in range(pal_n):
        palette.append((buf[off], buf[off+1], buf[off+2])); off += 3
    nw, nh, fps = struct.unpack(">HHB", buf[off:off+5]); off += 5
    K = struct.unpack(">H", buf[off:off+2])[0]; off += 2
    prev = [-1] * (nw * nh)
    frames = []
    for _ in range(N):
        cx, cy = struct.unpack(">ff", buf[off:off+8]); off += 8
        facing = buf[off]; off += 1
        flag = buf[off]; off += 1
        if flag == 0:                                          # keyframe
            x, y, w, h = struct.unpack(">HHHH", buf[off:off+8]); off += 8
            mbytes = math.ceil(w*h / 8)
            mask = unpack_pixels(buf[off:off+mbytes], w*h, 1); off += mbytes
            nopq = sum(mask); ibytes = math.ceil(nopq * ib / 8)
            idx = unpack_pixels(buf[off:off+ibytes], nopq, ib); off += ibytes
            st = [-1] * (nw * nh); oi = 0
            for r in range(h):
                for c in range(w):
                    if mask[r*w + c]:
                        st[(y+r)*nw + (x+c)] = idx[oi]; oi += 1
        else:                                                  # delta
            cbx, cby, cbw, cbh = struct.unpack(">HHHH", buf[off:off+8]); off += 8
            cmbytes = math.ceil(cbw*cbh / 8)
            cmask = unpack_pixels(buf[off:off+cmbytes], cbw*cbh, 1); off += cmbytes
            nch = sum(cmask); abytes = math.ceil(nch / 8)
            abits = unpack_pixels(buf[off:off+abytes], nch, 1); off += abytes
            nopq = sum(abits); ibytes = math.ceil(nopq * ib / 8)
            nidx = unpack_pixels(buf[off:off+ibytes], nopq, ib) if nopq else []; off += ibytes
            st = prev[:]; ci = ii = 0
            for ly in range(cbh):
                for lx in range(cbw):
                    if cmask[ly*cbw + lx]:
                        p = (cby+ly)*nw + (cbx+lx)
                        if abits[ci]: st[p] = nidx[ii]; ii += 1
                        else: st[p] = -1
                        ci += 1
        frames.append(_state_sprite(st, nw, nh, cx, cy, facing))
        prev = st
    return {"palette": palette, "frames": frames, "nw": nw, "nh": nh, "fps": fps, "keyint": K}, off


# ---------------------------------------------------------------------------
# FOOTAGE table  (inline or referenced; one or many)
# ---------------------------------------------------------------------------

def _emit_footage_table(entries):
    """entries: list of ("inline", footage_dict) | ("ref", txid_hex_or_32bytes)."""
    out = bytearray([len(entries)])
    for kind, payload in entries:
        if kind == "inline":
            out += bytes([FOOT_INLINE]) + _emit_footage(payload)
        elif kind == "ref":
            raw = bytes.fromhex(payload) if isinstance(payload, str) else bytes(payload)
            if len(raw) != 32:
                raise ValueError("footage ref must be 32 bytes / 64 hex")
            out += bytes([FOOT_REF]) + raw
        else:
            raise ValueError("footage entry kind must be inline|ref")
    return bytes(out)


def _read_footage_table(buf, off):
    n = buf[off]; off += 1
    entries = []
    for _ in range(n):
        kind = buf[off]; off += 1
        if kind == FOOT_INLINE:
            foot, off = _read_footage(buf, off)
            entries.append(("inline", foot))
        elif kind == FOOT_REF:
            entries.append(("ref", buf[off:off+32].hex())); off += 32
        else:
            raise ValueError("bad footage entry kind %#x" % kind)
    return entries, off


# ---------------------------------------------------------------------------
# GRAPH
# ---------------------------------------------------------------------------

def _emit_graph(graph):
    """graph = {footage:[entries], nmode, labels:[str], start, nodes:[...], }.
       node: {foot, ord, label, sym, edges:[{dst,time,space,ctrl}]}."""
    out = bytearray()
    out += _emit_footage_table(graph["footage"])
    out += bytes([graph.get("nmode", 1) & 255])
    labels = graph.get("labels", [])
    out += bytes([len(labels)])
    for name in labels:
        nb = name.encode("utf-8")
        out += bytes([len(nb)]) + nb
    out += struct.pack(">H", graph.get("start", 0))
    nodes = graph["nodes"]
    out += struct.pack(">H", len(nodes))
    for nd in nodes:
        out += bytes([nd["foot"] & 255]) + struct.pack(">H", nd["ord"])
        out += bytes([nd.get("label", 0) & 255, nd.get("sym", SYM_SYMMETRIC) & 255,
                      len(nd["edges"]) & 255])
    for nd in nodes:
        for e in nd["edges"]:
            flags = (e.get("time", TIME_FWD) & 1) | ((e.get("space", SPACE_SAME) & 1) << 1)
            out += struct.pack(">H", e["dst"]) + bytes([flags, e.get("ctrl", CTRL_ALL) & 255])
    return bytes(out)


def _read_graph(buf, off):
    footage, off = _read_footage_table(buf, off)
    nmode = buf[off]; off += 1
    nlab = buf[off]; off += 1
    labels = []
    for _ in range(nlab):
        ln = buf[off]; off += 1
        labels.append(buf[off:off+ln].decode("utf-8")); off += ln
    start = struct.unpack(">H", buf[off:off+2])[0]; off += 2
    Nn = struct.unpack(">H", buf[off:off+2])[0]; off += 2
    heads = []
    for _ in range(Nn):
        foot = buf[off]; off += 1
        ordv = struct.unpack(">H", buf[off:off+2])[0]; off += 2
        label, sym, narc = buf[off], buf[off+1], buf[off+2]; off += 3
        heads.append((foot, ordv, label, sym, narc))
    nodes = []
    for (foot, ordv, label, sym, narc) in heads:
        edges = []
        for _ in range(narc):
            dst = struct.unpack(">H", buf[off:off+2])[0]; off += 2
            flags = buf[off]; ctrl = buf[off+1]; off += 2
            edges.append({"dst": dst, "time": flags & 1, "space": (flags >> 1) & 1, "ctrl": ctrl})
        nodes.append({"foot": foot, "ord": ordv, "label": label, "sym": sym, "edges": edges})
    return {"footage": footage, "nmode": nmode, "labels": labels, "start": start,
            "nodes": nodes}, off


# ---------------------------------------------------------------------------
# CONTROLLERS  (a list; each = methods + preference-sets + bindings)
# ---------------------------------------------------------------------------

def _emit_method(m):
    mid = m["id"]
    if mid == M_UNIFORM:
        p = b""
    elif mid == M_WEIGHTED:
        p = bytes([m.get("pref", 0) & 255])
    elif mid == M_BOLTZMANN:
        p = struct.pack(">ffBB", float(m.get("beta", 2.0)), float(m.get("gain_t", 1.0)),
                        m.get("axis", 0) & 255, m.get("pref", 0) & 255)
    elif mid == M_QUANTUM:
        p = struct.pack(">BfBf", m.get("generator", GEN_SIMILARITY) & 255,
                        float(m.get("measure_per_step", 1.0)),
                        m.get("measure_handedness", 0) & 255,
                        float(m.get("well_depth", 1.0)))
    elif mid == M_KEYBOARD:
        p = bytes([m.get("map", 0) & 255])
    else:
        p = bytes(m.get("params", b""))     # unknown method: opaque params pass through
    return bytes([mid, len(p)]) + p


def _read_method(buf, off):
    mid = buf[off]; plen = buf[off+1]; off += 2
    p = buf[off:off+plen]; off += plen
    m = {"id": mid, "name": _METHOD_NAME.get(mid, "method_%#x" % mid)}
    if mid == M_WEIGHTED and plen >= 1:
        m["pref"] = p[0]
    elif mid == M_BOLTZMANN and plen >= 10:
        beta, gain_t, axis, pref = struct.unpack(">ffBB", p[:10])
        m.update(beta=beta, gain_t=gain_t, axis=axis, pref=pref)
    elif mid == M_QUANTUM and plen >= 10:
        gen, mps, mh, wd = struct.unpack(">BfBf", p[:10])
        m.update(generator=gen, measure_per_step=mps, measure_handedness=mh, well_depth=wd)
    elif mid == M_KEYBOARD and plen >= 1:
        m["map"] = p[0]
    else:
        m["params"] = bytes(p)
    return m, off


def _emit_controller(c):
    out = bytearray()
    out += struct.pack(">H", c.get("start", 0)) + bytes([c.get("mode0", CTRL_ALL) & 255])
    methods = c["methods"]
    out += bytes([len(methods), c.get("default_method", 0) & 255])
    for m in methods:
        out += _emit_method(m)
    prefs = c.get("prefs", [])
    out += bytes([len(prefs)])
    for pr in prefs:
        nb = pr.get("name", "").encode("utf-8")
        out += bytes([len(nb)]) + nb
        w = pr.get("weights", [])
        out += struct.pack(">H", len(w))
        for (node, eidx, weight) in w:
            out += struct.pack(">HBB", node, eidx & 255, weight & 255)
    binds = c.get("bindings", [])
    out += bytes([len(binds)])
    for b in binds:
        out += bytes([b["source"] & 255, b["port"] & 255]) + struct.pack(">f", float(b.get("scale", 1.0)))
    return bytes(out)


def _read_controller(buf, off):
    start = struct.unpack(">H", buf[off:off+2])[0]; off += 2
    mode0 = buf[off]; off += 1
    nm = buf[off]; dm = buf[off+1]; off += 2
    methods = []
    for _ in range(nm):
        m, off = _read_method(buf, off); methods.append(m)
    npref = buf[off]; off += 1
    prefs = []
    for _ in range(npref):
        ln = buf[off]; off += 1
        name = buf[off:off+ln].decode("utf-8"); off += ln
        nw = struct.unpack(">H", buf[off:off+2])[0]; off += 2
        weights = []
        for _ in range(nw):
            node, eidx, weight = struct.unpack(">HBB", buf[off:off+4]); off += 4
            weights.append((node, eidx, weight))
        prefs.append({"name": name, "weights": weights})
    nb = buf[off]; off += 1
    binds = []
    for _ in range(nb):
        src, port = buf[off], buf[off+1]; off += 2
        scale = struct.unpack(">f", buf[off:off+4])[0]; off += 4
        binds.append({"source": src, "port": port, "scale": scale})
    return {"start": start, "mode0": mode0, "methods": methods,
            "default_method": dm, "prefs": prefs, "bindings": binds}, off


def _emit_controllers(controllers, default_ctrl):
    out = bytearray([len(controllers), default_ctrl & 255])
    for c in controllers:
        out += _emit_controller(c)
    return bytes(out)


def _read_controllers(buf, off):
    n = buf[off]; default_ctrl = buf[off+1]; off += 2
    cs = []
    for _ in range(n):
        c, off = _read_controller(buf, off); cs.append(c)
    return {"controllers": cs, "default": default_ctrl}, off


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_dancer(variant, title, *, tone=TONE_ORDINARY, footage=None, graph=None,
                 graph_ref=None, controllers=None, default_controller=0):
    """Build a 0xda dancer (header_bytes, body_bytes).

    performance: graph (with inline footage table) + controllers
    footage:     a single footage dict
    graph:       a graph dict (its footage table may be inline and/or ref)
    controller:  graph_ref (32 bytes/64 hex) + controllers
    """
    validate_tone(tone)
    if variant not in _VAR_NAME:
        raise ValueError("unknown variant %r" % variant)
    tb = title.encode("utf-8")
    if len(tb) > 255:
        raise ValueError("title > 255 UTF-8 bytes")
    header = MAGIC + bytes([TYPE_DANCER, tone, variant, len(tb)]) + tb

    body = bytearray()
    if variant == VAR_FOOTAGE:
        if footage is None:
            raise ValueError("footage variant needs footage")
        body += _emit_footage(footage)
    elif variant == VAR_GRAPH:
        if graph is None:
            raise ValueError("graph variant needs graph")
        body += _emit_graph(graph)
    elif variant == VAR_CONTROLLER:
        if graph_ref is None or controllers is None:
            raise ValueError("controller variant needs graph_ref + controllers")
        raw = bytes.fromhex(graph_ref) if isinstance(graph_ref, str) else bytes(graph_ref)
        if len(raw) != 32:
            raise ValueError("graph_ref must be 32 bytes / 64 hex")
        body += raw + _emit_controllers(controllers, default_controller)
    elif variant == VAR_PERFORMANCE:
        if graph is None or controllers is None:
            raise ValueError("performance needs graph + controllers")
        body += _emit_graph(graph) + _emit_controllers(controllers, default_controller)
    return header, bytes(body)


# convenience wrappers
def build_footage(title, footage, tone=TONE_ORDINARY):
    return build_dancer(VAR_FOOTAGE, title, tone=tone, footage=footage)


def build_graph(title, graph, tone=TONE_ORDINARY):
    return build_dancer(VAR_GRAPH, title, tone=tone, graph=graph)


def build_controller(title, graph_ref, controllers, default_controller=0, tone=TONE_ORDINARY):
    return build_dancer(VAR_CONTROLLER, title, tone=tone, graph_ref=graph_ref,
                        controllers=controllers, default_controller=default_controller)


def build_performance(title, graph, controllers, default_controller=0, tone=TONE_ORDINARY):
    return build_dancer(VAR_PERFORMANCE, title, tone=tone, graph=graph,
                        controllers=controllers, default_controller=default_controller)


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
    if variant == VAR_FOOTAGE:
        out["footage"], off = _read_footage(body_bytes, off)
    elif variant == VAR_GRAPH:
        out["graph"], off = _read_graph(body_bytes, off)
    elif variant == VAR_CONTROLLER:
        out["graph_ref"] = body_bytes[off:off+32].hex(); off += 32
        ctl, off = _read_controllers(body_bytes, off); out.update(ctl)
    elif variant == VAR_PERFORMANCE:
        out["graph"], off = _read_graph(body_bytes, off)
        ctl, off = _read_controllers(body_bytes, off); out.update(ctl)
    return out


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _selftest():
    palette = [(200, 30, 30), (30, 30, 200)]
    f0 = {"x": 4, "y": 2, "w": 2, "h": 2, "cx": 0.5, "cy": 0.6, "facing": FACE_FRONT,
          "mask": [1, 0, 1, 1], "idx": [0, 1, 0]}
    f1 = {"x": 5, "y": 2, "w": 2, "h": 2, "cx": 0.55, "cy": 0.6, "facing": FACE_PROFILE_R,
          "mask": [1, 1, 0, 1], "idx": [1, 0, 1]}
    footage = {"palette": palette, "frames": [f0, f1], "nw": 16, "nh": 8, "fps": 30}

    # footage variant
    h, b = build_footage("Foot", footage, tone=TONE_REVERENCE)
    p = read_dancer(h, b)
    assert p["variant"] == VAR_FOOTAGE and p["title"] == "Foot"
    assert p["footage"]["frames"][1]["facing"] == FACE_PROFILE_R
    assert abs(p["footage"]["frames"][1]["cx"] - 0.55) < 1e-6
    assert p["footage"]["nw"] == 16 and p["footage"]["fps"] == 30
    print("  ✓ footage round-trip (%dB+%dB)" % (len(h), len(b)))

    # graph variant: footage table mixes one inline + one ref
    graph = {
        "footage": [("inline", footage), ("ref", "ab" * 32)],
        "nmode": 3, "labels": ["low1", "praise"], "start": 0,
        "nodes": [
            {"foot": 0, "ord": 0, "label": 0, "sym": SYM_SYMMETRIC, "edges": [
                {"dst": 1, "time": TIME_FWD, "space": SPACE_SAME, "ctrl": 1},
                {"dst": 1, "time": TIME_REV, "space": SPACE_MIRROR, "ctrl": 2}]},
            {"foot": 1, "ord": 5, "label": 1, "sym": SYM_REFLECTED, "edges": [
                {"dst": 0, "time": TIME_FWD, "space": SPACE_MIRROR, "ctrl": CTRL_ALL}]},
        ]}
    h, b = build_graph("Graph", graph)
    p = read_dancer(h, b)
    g = p["graph"]
    assert g["footage"][0][0] == "inline" and g["footage"][1] == ("ref", "ab" * 32)
    assert g["nmode"] == 3 and g["labels"] == ["low1", "praise"]
    assert g["nodes"][0]["edges"][1]["space"] == SPACE_MIRROR
    assert g["nodes"][1]["sym"] == SYM_REFLECTED
    print("  ✓ graph round-trip (footage table inline+ref, %d nodes)" % len(g["nodes"]))

    # controllers: two whole controllers, methods + prefs + bindings
    ctrl_chase = {
        "start": 0, "mode0": CTRL_ALL, "default_method": 0,
        "methods": [
            {"id": M_BOLTZMANN, "beta": 2.0, "gain_t": 1.0, "axis": 0, "pref": 0},
            {"id": M_KEYBOARD, "map": 0},
            {"id": M_QUANTUM, "generator": GEN_SIMILARITY, "measure_per_step": 1.0,
             "measure_handedness": 0, "well_depth": 1.5}],
        "prefs": [{"name": "frantic", "weights": [(0, 0, 200), (0, 1, 60)]}],
        "bindings": [
            {"source": SRC_ATTRACTOR_X, "port": PORT_TARGET, "scale": 1.0},
            {"source": SRC_KEY_BTN, "port": PORT_METHOD_SELECT, "scale": 1.0}]}
    ctrl_uniform = {"start": 0, "default_method": 0,
                    "methods": [{"id": M_UNIFORM}], "prefs": [], "bindings": []}

    # controller variant (cites a graph txid)
    h, b = build_controller("Ctl", "cd" * 32, [ctrl_chase, ctrl_uniform], default_controller=0)
    p = read_dancer(h, b)
    assert p["variant"] == VAR_CONTROLLER and p["graph_ref"] == "cd" * 32
    assert p["default"] == 0 and len(p["controllers"]) == 2
    c0 = p["controllers"][0]
    assert [m["name"] for m in c0["methods"]] == ["boltzmann", "keyboard", "quantum"]
    assert abs(c0["methods"][0]["beta"] - 2.0) < 1e-6
    assert c0["methods"][2]["generator"] == GEN_SIMILARITY
    assert c0["prefs"][0]["name"] == "frantic" and c0["prefs"][0]["weights"][0] == (0, 0, 200)
    assert c0["bindings"][1]["port"] == PORT_METHOD_SELECT
    print("  ✓ controller round-trip (2 controllers, 3 methods, prefs, bindings)")

    # performance: footage + graph + controllers, fully self-contained
    h, b = build_performance("Perf", graph, [ctrl_chase, ctrl_uniform])
    p = read_dancer(h, b)
    assert p["variant"] == VAR_PERFORMANCE
    assert p["graph"]["nodes"][0]["edges"][0]["dst"] == 1
    assert len(p["controllers"]) == 2
    print("  ✓ performance round-trip (self-contained: footage+graph+2 controllers, %dB body)" % len(b))

    print("dancer 0xda self-test OK")


if __name__ == "__main__":
    _selftest()
