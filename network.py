#!/usr/bin/env python3
"""network.py — 0xce celestial-envelope quipu, kind byte 0x05 (KIND_NETWORK).

A network is a *synchronic* connected system: a set of nodes (places, agents,
relay posts, resources) wired together by typed edges (roads, sea-lanes, rivers,
wires, relays, credit-links, kinship) during a bounded period. Unlike genealogy
(0x03) and etymology (0x04) — which are DIACHRONIC lineages, one thing descending
into another through time — a network is a snapshot: everything coexisting and
connected inside a window. So born/died here means a node's IN-SERVICE span
within that window (a tambo abandoned mid-empire drops out of the graph), not a
biological lifespan.

It mirrors the etymology codec byte-for-byte in skeleton (K · title · nodes ·
refs · edges), with three deliberate grafts, each earned against an existing
precedent so nothing is invented that need not be:

  1. NODE-TYPE byte (ntype) — a per-node ontological discriminator, prefixed to
     the record exactly where a MIXED (0x02) figure prefixes its per-point
     `system` byte. The reader NEVER branches on it (pure semantics/styling);
     it only classifies the node for the renderer. It is a CLOSED ENUM of four
     (place/agent/relay/resource) — the registry declares the values list as
     law, so an unknown byte is malformed and raises at build and read
     (c1dd0002 §5). NTYPE_UNCERTAIN (0x04) was struck at v2 authoring
     (2026-07-17): the last certainty-flavored byte; a telling that assigns no
     role picks the closest ontological kind, and hedges stay off-chain.

  2. lat/lng (2×f32, NaN-sentinel) — a node's fixed geographic position, carried
     with the SAME NaN discipline as born/died. NaN,NaN = an ABSTRACT node with
     no fixed locus. This is the render fork: a geographic node draws ON the
     earth (an arc between real coordinates); an abstract node hangs INSIDE the
     sphere, tethered to the geographic neighbors it is wired to and pulled toward
     their centroid. One scene, one boolean — "does this node have coordinates?"

  3. 10-BYTE typed edge (vs etymology's 5): parent·child·etype·flags·weight.
     `etype` mirrors etymology's per-edge relation byte. `flags` bit0 marks a
     directed edge (a river reach flows; a road does not). `weight:f32` carries
     magnitude (traffic / trade volume / distance; NaN = unweighted). The stride
     is FIXED, so — like etymology — it stays self-delimiting only because the
     0x05 route guard keeps a genealogy/etymology blob from ever reaching this
     reader and vice-versa. Stride is NEVER inferred from length.

Like genealogy/etymology, the network body is routed AROUND the canonical
celestial point reader (which accepts only kinds 0x00/0x01/0x02). Routing is by
the kind byte at header offset 6 == 0x05.

Network is v2 law. The kind entered the standard with the v2 celestial delta
(canonical/registry_v2.py); nothing network was ever legislated under v1 or
inscribed, so this codec is the v2 codec with no legacy path: it emits
c1dd0002 envelopes, and the reader refuses a v1-stamped kind-0x05 blob
honestly instead of guessing a grammar that never existed. More-blocks range
over the full atom namespace with the 9-byte precision date (atoms.py, v2).

Wire (everything big-endian)
----------------------------
HEADER (9 bytes):
    c1 dd 00 02   magic2 + version u16-BE (v2 — the kind's first standard)
    ce            type   = TYPE_CELESTIAL
    <tone:1>      canonical tone vocab (ignored by the network body)
    05            kind   = KIND_NETWORK
    00            grouped (reserved; MUST be 0x00)
    00            meta    (reserved; MUST be 0x00)

BODY (from offset 9 of blob = hdr + body):
    K:u16  T:u8  title:T
    K nodes, each (FIXED shape — reader never branches on ntype):
        ntype:u8                    ontological kind (see NTYPE_*)
        lat:f32-BE  lng:f32-BE      NaN,NaN = abstract (no fixed locus)
        born:f32-BE died:f32-BE     in-service span within the period; NaN = unknown/open
        namelen:u8  name:namelen
        morelen:u16-BE  more:morelen   (nvar:u8 · nvar×[keylen·key·vkind·value])
    Nref:u16-BE refs, each:
        txid:32  remote_idx:u16-BE  namelen:u8  name:namelen
    EDGES — read to EOF, 10-BYTE STRIDE:
        parent:u16-BE  child:u16-BE  etype:u8  flags:u8  weight:f32-BE

Cross-house rule (unchanged from genealogy/etymology): the comparison is on the
PARENT index a — a < K is nodes[a], a >= K is refs[a-K] (a node living in another
quipu). etype/flags/weight are orthogonal and never conflated with that compare.

Sentinels: born/died/lat/lng/weight NaN -> None. Write float('nan'), never 0.0
(which would decode as the year 0 CE, or the Gulf of Guinea for a coordinate).
Negative year = BCE.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "canonical"))
from atoms import ATOM_NAMES, emit_more_block as _atoms_emit, read_more_block as _atoms_read
from envelope import build_envelope, parse_envelope, VERSION_V1, VERSION_V2

TYPE_CELESTIAL = 0xCE
KIND_GENEALOGY = 0x03
KIND_ETYMOLOGY = 0x04
KIND_NETWORK = 0x05

TONE_ORDINARY = 0x00
TONE_REVERENCE = 0xFF

# more-block vkind bytes (the protocol atoms, atoms.py; v2 blocks range over
# the full namespace — these aliases keep the public surface)
VAR_TEXT = 0x00   # vlen:u16-BE + utf8
VAR_REF = 0x01    # 32-byte txid
VAR_DATE = 0x02   # v2: precision:u8 + jd:f64-BE (9 B)

# ---------------------------------------------------------------------------
# Node-type enum — the per-node ontological discriminator (the ntype byte).
# The NEW axis: genealogy/etymology never typed a node. Kept ontological (WHAT
# a node is), never topological (source/relay/sink ROLE is derivable from the
# edge set — see the roots computation in the worked example — so it is not
# stored). CLOSED at four (registry v2): unknown = malformed = raise.
# ---------------------------------------------------------------------------
NTYPE_PLACE = 0x00      # a fixed geographic locus: city, port, tambo
NTYPE_AGENT = 0x01      # a person / house / institution: bank, family, corps
NTYPE_RELAY = 0x02      # infrastructure node: station, tower, runner-post, beacon
NTYPE_RESOURCE = 0x03   # an asset store: mine, granary, treasury, spring

NTYPE_NAME_TO_BYTE = {
    "place": NTYPE_PLACE,
    "agent": NTYPE_AGENT,
    "relay": NTYPE_RELAY,
    "resource": NTYPE_RESOURCE,
}
NTYPE_BYTE_TO_NAME = {v: k for k, v in NTYPE_NAME_TO_BYTE.items()}

# ---------------------------------------------------------------------------
# Edge-type enum — the per-edge medium (the etype byte). Mirrors etymology's
# per-edge relation byte exactly in spirit and position.
# ---------------------------------------------------------------------------
ETYPE_ROAD = 0x00       # engineered land route
ETYPE_SEA_LANE = 0x01   # maritime link
ETYPE_RIVER = 0x02      # watercourse (usually directed downstream — set FLAG_DIRECTED)
ETYPE_WIRE = 0x03       # telegraph / telex / electronic channel
ETYPE_RELAY = 0x04      # store-and-forward hop, medium-agnostic (chasqui, yam, beacon)
ETYPE_CREDIT = 0x05     # value link: bill of exchange, letter of credit, hawala
ETYPE_KINSHIP = 0x06    # a genealogy-style tie embedded in a network
ETYPE_UNCERTAIN = 0x07  # link mechanism disputed

ETYPE_NAME_TO_BYTE = {
    "road": ETYPE_ROAD,
    "sea_lane": ETYPE_SEA_LANE,
    "river": ETYPE_RIVER,
    "wire": ETYPE_WIRE,
    "relay": ETYPE_RELAY,
    "credit": ETYPE_CREDIT,
    "kinship": ETYPE_KINSHIP,
    "uncertain": ETYPE_UNCERTAIN,
}
ETYPE_BYTE_TO_NAME = {v: k for k, v in ETYPE_NAME_TO_BYTE.items()}

# edge flags (bitfield). bits 1..7 reserved, MUST be 0.
FLAG_DIRECTED = 0x01    # edge is one-way parent -> child (else undirected)

# network node `more` text keys (annotation; ntype already carries the role).
_TEXT_KEYS = ("note", "region", "modern")


def ntype_name(nt):
    """Human name for an ntype byte, or 'unknown_0xNN' (never raises)."""
    return NTYPE_BYTE_TO_NAME.get(nt, f"unknown_{nt:#04x}")


def etype_name(et):
    """Human name for an etype byte, or 'unknown_0xNN' (never raises)."""
    return ETYPE_BYTE_TO_NAME.get(et, f"unknown_{et:#04x}")


def _resolve_ntype(nt):
    """Node type -> byte. Closed enum (registry v2): a name or byte outside
    place/agent/relay/resource is malformed, never passed through."""
    if isinstance(nt, str):
        if nt not in NTYPE_NAME_TO_BYTE:
            raise ValueError(
                f"unknown node type {nt!r}; the v2 enum is closed: "
                f"{sorted(NTYPE_NAME_TO_BYTE)}")
        return NTYPE_NAME_TO_BYTE[nt]
    nt = int(nt)
    if nt not in NTYPE_BYTE_TO_NAME:
        raise ValueError(
            f"ntype byte {nt:#04x} not in the closed v2 enum "
            f"(0x00 place · 0x01 agent · 0x02 relay · 0x03 resource)")
    return nt


def _resolve_etype(et):
    """Edge type -> byte (string looked up, int passed through)."""
    if isinstance(et, str):
        if et not in ETYPE_NAME_TO_BYTE:
            raise ValueError(
                f"unknown edge type {et!r}; known: {sorted(ETYPE_NAME_TO_BYTE)}")
        return ETYPE_NAME_TO_BYTE[et]
    et = int(et)
    if not (0 <= et <= 0xFF):
        raise ValueError(f"etype byte {et} out of range 0..255")
    return et


# ---------------------------------------------------------------------------
# more-block (keyless; the ONE shared typed-var codec, canonical/atoms.py)
# ---------------------------------------------------------------------------
_NAME_TO_VK = {v: k for k, v in ATOM_NAMES.items()}


def _emit_more(more, idx):
    """Serialize a node's `more` list of (key, vkind, value). Delegates to the
    ONE shared typed-var codec (canonical/atoms.py) — the fourth clone is
    retired (c1dd0002 §7.5). v2: full atom namespace, 9-byte precision dates."""
    return _atoms_emit(more, version=2, label=f"node {idx}")


def _read_more_block(blob, o, end):
    """Parse a `more` payload in [o, end) via the shared codec. STRICT: an
    unknown vkind raises (width unknown; the old silent `break` presented a
    partial record as whole). Surface stays network's own: [(key, vkind_byte,
    value)] with refs as hex; v2 dates are {'jd', 'precision'} dicts. Keyless."""
    out = []
    for key, name_, val in _atoms_read(bytes(blob[o:end]), version=2,
                                       label="node"):
        if name_ == "ref":
            val = val.hex()
        out.append((key, _NAME_TO_VK[name_], val))
    return out


def _f32_or_none(x):
    """f32 field -> value, or None for NaN (unknown / unattested / abstract)."""
    return None if x != x else x


def _gy(x):
    """born/died f32 year -> int, or None for NaN."""
    return None if x != x else int(round(x))


def _coord(x):
    """lat/lng f32 -> float rounded to 6 dp, or None for NaN (abstract node)."""
    return None if x != x else round(float(x), 6)


def _to_f32nan(v):
    """A field (int|float|None) -> the float to pack; None -> NaN sentinel."""
    if v is None:
        return float("nan")
    return float(v)


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
def _build_header(kind, tone):
    """The 9-byte celestial header for a routed-around body: the 6-byte v2
    envelope (envelope.py) + kind + grouped(0x00) + meta(0x00)."""
    return (
        build_envelope(VERSION_V2, TYPE_CELESTIAL, tone)
        + bytes([kind])
        + bytes([0x00])      # grouped — reserved, MUST be 0x00
        + bytes([0x00])      # meta    — reserved, MUST be 0x00
    )


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
def build_network(title, nodes, edges, refs=(), tone=TONE_REVERENCE):
    """Build a network quipu -> (header_bytes, body_bytes).

    title : str
    nodes : list of dicts, each:
        {name:str,
         ntype: int|name-str (default 'place'),
         lat: float|None, lng: float|None,   (None -> NaN = abstract node)
         born: year|None, died: year|None,   (in-service span; None -> NaN)
         note:str, region:str, modern:str,   (optional text annotations)
         refs: [(key, txid32), ...] (optional)}
    edges : list of (parent, child, etype[, flags[, weight]]).
            etype int|name-str; flags int (default 0); weight float|None (default NaN).
    refs  : list of {txid:32B, remote_idx:u16, name:str} cross-house nodes.
    tone  : tone byte (default reverence 0xff).
    """
    header = _build_header(KIND_NETWORK, tone)

    title_bytes = title.encode("utf-8")
    if len(title_bytes) > 255:
        raise ValueError(f"title encodes to {len(title_bytes)} UTF-8 bytes; max 255")
    K = len(nodes)
    if K > 0xFFFF:
        raise ValueError(f"max 65535 nodes per network (got {K})")

    body = bytearray()
    body += struct.pack(">H", K)
    body += bytes([len(title_bytes)]) + title_bytes

    for i, n in enumerate(nodes):
        if "name" not in n:
            raise ValueError(f"node {i} missing required 'name' key")
        body += bytes([_resolve_ntype(n.get("ntype", "place"))])
        body += struct.pack(">f", _to_f32nan(n.get("lat")))
        body += struct.pack(">f", _to_f32nan(n.get("lng")))
        body += struct.pack(">f", _to_f32nan(n.get("born")))
        body += struct.pack(">f", _to_f32nan(n.get("died")))
        nb = n["name"].encode("utf-8")
        if len(nb) > 255:
            raise ValueError(f"node {i}: name encodes to {len(nb)} bytes; max 255")
        body += bytes([len(nb)]) + nb

        # more list — the builder's vkind-lock is gone (§7.5): dates emit as
        # v2 9-byte precision values (a float = precision unspecified, a dict
        # {'jd': float, 'precision': name} carries granularity); legality per
        # atom is the shared codec's check, not a local whitelist
        more = []
        for key in _TEXT_KEYS:
            val = n.get(key)
            if val is None or val == "":
                continue                       # omit optional keys when absent
            more.append((key, VAR_TEXT, str(val)))
        for key, txid in n.get("refs", ()):
            if len(txid) != 32:
                raise ValueError(f"node {i}: ref {key!r} must cite a 32-byte txid")
            more.append((key, VAR_REF, bytes(txid)))
        for key, date in n.get("dates", ()):
            more.append((key, VAR_DATE, date))
        more_bytes = _emit_more(more, i)
        body += struct.pack(">H", len(more_bytes)) + more_bytes

    # refs block
    refs = list(refs)
    if len(refs) > 0xFFFF:
        raise ValueError(f"max 65535 refs (got {len(refs)})")
    body += struct.pack(">H", len(refs))
    for j, r in enumerate(refs):
        txid = r["txid"]
        if len(txid) != 32:
            raise ValueError(f"ref {j}: txid must be 32 bytes")
        body += bytes(txid)
        body += struct.pack(">H", r["remote_idx"])
        rn = r["name"].encode("utf-8")
        if len(rn) > 255:
            raise ValueError(f"ref {j}: name encodes to {len(rn)} bytes; max 255")
        body += bytes([len(rn)]) + rn

    # edges — 10-byte typed stride: parent·child·etype·flags·weight
    for e in edges:
        if len(e) == 3:
            parent, child, et = e; flags = 0; weight = None
        elif len(e) == 4:
            parent, child, et, flags = e; weight = None
        elif len(e) == 5:
            parent, child, et, flags, weight = e
        else:
            raise ValueError(f"edge {e!r}: expected (parent,child,etype[,flags[,weight]])")
        etype = _resolve_etype(et)
        flags = int(flags)
        if not (0 <= flags <= 0xFF):
            raise ValueError(f"edge ({parent},{child}): flags {flags} out of range 0..255")
        if not (0 <= parent <= 0xFFFF) or not (0 <= child <= 0xFFFF):
            raise ValueError(f"edge ({parent},{child}): indices must fit u16")
        body += struct.pack(">HHBBf", parent, child, etype, flags, _to_f32nan(weight))

    return bytes(header), bytes(body)


# alias for the spec's named signature
build_network_quipu = build_network


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------
def read_network_quipu(hdr, body):
    """Decode a network quipu (type 0xCE, kind 0x05) from its header + body.

    Mirrors read_etymology_quipu with the 10-byte typed edge stride and the
    per-node ntype/lat/lng fields. Offsets 7,8 (grouped/meta) are RESERVED and
    asserted 0x00. ntype is validated against the closed v2 enum but never
    branched on (pure semantics/styling). Returns:
      {title, K, kind:'network', nodes:[...], people:<alias>, refs, edges, lines}.
    `edges` are 5-tuples (parent, child, etype_int, flags_int, weight_or_None);
    `lines` are 2-tuples (parent, child) with the rest stripped, for layout reuse.
    Keyless throughout."""
    blob = hdr + body
    if len(blob) < 9:
        raise ValueError("network: blob shorter than the 9-byte header")
    version, type_byte, _tone = parse_envelope(blob[:6])
    if type_byte != TYPE_CELESTIAL:
        raise ValueError(f"network: type byte {type_byte:#04x} != 0xCE")
    if blob[6] != KIND_NETWORK:                       # load-bearing route guard
        raise ValueError(f"network: kind byte {blob[6]:#04x} != 0x05")
    # Version dispatch (c1dd0002 §7.2). Network entered the law at v2; no v1
    # network was ever legislated or inscribed, so a v1 stamp is refused
    # honestly rather than parsed under a grammar that never existed.
    if version == VERSION_V1:
        raise ValueError(
            "network: kind 0x05 entered the law at v2 (c1dd0002) — no v1 "
            "network was ever legislated or inscribed; refusing to guess")
    if version != VERSION_V2:
        raise ValueError(
            f"network: unknown version {version:#06x}; this reader implements "
            f"v2 only — refusing to guess a body it does not know")
    if blob[7] != 0x00 or blob[8] != 0x00:
        raise ValueError(
            f"network: reserved header bytes 7,8 must be 0x00, "
            f"got {blob[7]:#04x},{blob[8]:#04x}")

    o = 9
    K = int.from_bytes(blob[o:o + 2], "big"); o += 2
    T = blob[o]; o += 1
    title = blob[o:o + T].decode("utf-8"); o += T

    nodes = []
    for _ in range(K):
        ntype = blob[o]; o += 1
        if ntype not in NTYPE_BYTE_TO_NAME:           # closed enum (registry v2)
            raise ValueError(
                f"network: node ntype {ntype:#04x} not in the closed v2 enum "
                f"(0x00 place · 0x01 agent · 0x02 relay · 0x03 resource)")
        lat = struct.unpack(">f", blob[o:o + 4])[0]; o += 4
        lng = struct.unpack(">f", blob[o:o + 4])[0]; o += 4
        born = struct.unpack(">f", blob[o:o + 4])[0]; o += 4
        died = struct.unpack(">f", blob[o:o + 4])[0]; o += 4
        nl = blob[o]; o += 1
        name = blob[o:o + nl].decode("utf-8"); o += nl
        ml = int.from_bytes(blob[o:o + 2], "big"); o += 2
        more = _read_more_block(blob, o, o + ml); o += ml

        def _txt(key):
            return next((v for (k, vk, v) in more if vk == VAR_TEXT and k == key), "")
        nodes.append({
            "name": name,
            "ntype": ntype,
            "ntype_name": ntype_name(ntype),
            "lat": _coord(lat),
            "lng": _coord(lng),
            "abstract": (lat != lat) or (lng != lng),   # NaN in either -> abstract
            "born": _gy(born),
            "died": _gy(died),
            "note": _txt("note"),
            "region": _txt("region"),
            "modern": _txt("modern"),
            "refs": [(k, v) for (k, vk, v) in more if vk == VAR_REF],
            "dates": [(k, v) for (k, vk, v) in more if vk == VAR_DATE],
        })

    refs = []
    nref = int.from_bytes(blob[o:o + 2], "big"); o += 2
    for _ in range(nref):
        txid = blob[o:o + 32].hex(); o += 32
        ridx = int.from_bytes(blob[o:o + 2], "big"); o += 2
        nl = blob[o]; o += 1
        rname = blob[o:o + nl].decode("utf-8"); o += nl
        refs.append({"txid": txid, "remote_idx": ridx, "name": rname})

    edges, lines = [], []
    while o + 10 <= len(blob):                          # 10-byte stride (NEVER length-inferred)
        a, c, et, fl, w = struct.unpack(">HHBBf", blob[o:o + 10])
        o += 10
        edges.append((a, c, et, fl, _f32_or_none(w)))
        lines.append((a, c))                            # stripped -> 2-tuple for layout reuse
    if o != len(blob):
        raise ValueError(
            f"network: {len(blob) - o} trailing bytes after the edge block — "
            f"a partial edge is malformed, refusing to drop it")

    return {
        "title": title,
        "K": K,
        "kind": "network",
        "nodes": nodes,
        "people": nodes,        # alias so genealogy/etymology layout reuse works
        "refs": refs,
        "edges": edges,         # 5-tuples (parent, child, etype, flags, weight|None)
        "lines": lines,         # 2-tuples (parent, child)
    }


def read_network(blob):
    """Decode from a single joined blob (hdr + body)."""
    if len(blob) < 9:
        raise ValueError("network: blob shorter than the 9-byte header")
    return read_network_quipu(blob[:9], blob[9:])


# ---------------------------------------------------------------------------
# Worked example — Qhapaq Ñan (the Inca road network, ~1438–1533)
# ---------------------------------------------------------------------------
def _worked_example():
    """A synchronic slice of the Qhapaq Ñan at its imperial extent. Eight
    geographic nodes down the highland spine (real lat/lng), plus one ABSTRACT
    node — the chasqui relay corps — with NaN coordinates, tethered to three
    posts so it renders inside the sphere near their centroid. Exercises every
    new field: ntype, lat/lng (+ the NaN/abstract path), typed edges, the
    directed flag, and weighted + unweighted edges."""
    nodes = [
        # 0: Quito — northern reach
        {"name": "Quito", "ntype": "place", "lat": -0.1807, "lng": -78.4678,
         "born": 1471, "died": None, "region": "Chinchaysuyu", "modern": "Quito, Ecuador"},
        # 1: Tomebamba — northern Inca capital
        {"name": "Tomebamba", "ntype": "place", "lat": -2.9006, "lng": -79.0045,
         "born": 1471, "died": None, "region": "Chinchaysuyu", "modern": "Cuenca, Ecuador"},
        # 2: Cajamarca — where Atahualpa was seized, 1532; carries a v2 date
        # var (jd = 1532-11-15 noon Julian, month precision — the seizure month)
        {"name": "Cajamarca", "ntype": "place", "lat": -7.1638, "lng": -78.5003,
         "born": 1456, "died": None, "region": "Chinchaysuyu", "modern": "Cajamarca, Peru",
         "note": "Atahualpa seized here, Nov 1532",
         "dates": [("seized", {"jd": 2280940.0, "precision": "month"})]},
        # 3: Huanuco Pampa — highland administrative center + qollqa storehouses
        {"name": "Huanuco Pampa", "ntype": "place", "lat": -9.8626, "lng": -76.7370,
         "born": 1460, "died": None, "region": "Chinchaysuyu", "modern": "Huanuco, Peru"},
        # 4: Cusco — the navel, capital
        {"name": "Cusco", "ntype": "place", "lat": -13.5320, "lng": -71.9675,
         "born": 1438, "died": None, "region": "Capital", "modern": "Cusco, Peru",
         "note": "the four suyus meet here"},
        # 5: Ollantaytambo — Sacred Valley waystation
        {"name": "Ollantaytambo", "ntype": "place", "lat": -13.2586, "lng": -72.2636,
         "born": 1440, "died": None, "region": "Antisuyu", "modern": "Ollantaytambo, Peru"},
        # 6: Qeswachaka — the woven-rope suspension bridge (a structural relay node)
        {"name": "Qeswachaka", "ntype": "relay", "lat": -14.3814, "lng": -71.4844,
         "born": 1440, "died": None, "region": "Collasuyu", "modern": "Apurimac gorge, Peru",
         "note": "grass suspension bridge, rewoven yearly"},
        # 7: Copiapo — the southern reach
        {"name": "Copiapo", "ntype": "place", "lat": -27.3665, "lng": -70.3314,
         "born": 1470, "died": None, "region": "Collasuyu", "modern": "Copiapo, Chile"},
        # 8: the chasqui corps — ABSTRACT (no fixed locus): NaN coords, tethered to posts
        {"name": "Chasqui corps", "ntype": "agent", "lat": None, "lng": None,
         "born": 1438, "died": 1533, "region": "empire-wide",
         "note": "relay runners; message ~240 km/day post to post"},
    ]
    # trunk road (undirected, weight = approx segment km); relay tethers (unweighted)
    R = ETYPE_ROAD
    L = ETYPE_RELAY
    edges = [
        (0, 1, R, 0, 230.0),      # Quito -> Tomebamba
        (1, 2, R, 0, 560.0),      # Tomebamba -> Cajamarca
        (2, 3, R, 0, 500.0),      # Cajamarca -> Huanuco Pampa
        (3, 4, R, 0, 600.0),      # Huanuco Pampa -> Cusco
        (4, 5, R, 0, 60.0),       # Cusco -> Ollantaytambo
        (4, 6, R, 0, 100.0),      # Cusco -> Qeswachaka (branch)
        (4, 7, R, 0, 1500.0),     # Cusco -> Copiapo (long southern trunk)
        (8, 2, L, 0, None),       # chasqui corps tethered to Cajamarca
        (8, 4, L, 0, None),       # chasqui corps tethered to Cusco
        (8, 7, L, 0, None),       # chasqui corps tethered to Copiapo
    ]
    return "Qhapaq Nan", nodes, edges


if __name__ == "__main__":
    import math

    title, nodes, edges = _worked_example()
    hdr, body = build_network(title, nodes, edges, tone=TONE_REVERENCE)
    blob = hdr + body

    print("header :", hdr.hex())
    print("kind   :", "0x%02x" % hdr[6], "(KIND_NETWORK)" if hdr[6] == 0x05 else "(!!)")
    print("grouped:", "0x%02x" % hdr[7], " meta:", "0x%02x" % hdr[8], "(both reserved 0x00)")

    # the exact 100-byte edge block (10 edges x 10-byte stride)
    edge_block = b"".join(
        struct.pack(">HHBBf", a, c, _resolve_etype(et), fl,
                    (float("nan") if w is None else float(w)))
        for (a, c, et, fl, w) in edges)
    print("edges  :", edge_block.hex(), "(len %d)" % len(edge_block))
    assert len(edge_block) == 100, len(edge_block)
    # frozen: the verified 100-byte edge block (7 weighted roads + 3 NaN relay tethers)
    assert edge_block.hex() == (
        "00000001000043660000000100020000440c000000020003000043fa00000003"
        "00040000441600000004000500004270000000040006000042c8000000040007"
        "000044bb80000008000204007fc000000008000404007fc000000008000704"
        "007fc00000"), "edge block bytes diverge from the verified 100 bytes"

    d = read_network(blob)

    # ---- structural round-trip assertions --------------------------------
    assert d["title"] == "Qhapaq Nan", d["title"]
    assert d["K"] == 9, d["K"]
    assert d["kind"] == "network"
    assert len(d["nodes"]) == 9
    assert d["people"] is d["nodes"], "people must alias nodes"

    # node 4: Cusco — geographic, ntype place, coords + span round-trip.
    # coords are f32 -> compare within tolerance (lossy field, by design).
    n4 = d["nodes"][4]
    assert n4["name"] == "Cusco" and n4["ntype"] == NTYPE_PLACE, n4
    assert n4["abstract"] is False, n4
    assert abs(n4["lat"] - (-13.5320)) < 1e-3 and abs(n4["lng"] - (-71.9675)) < 1e-3, n4
    assert n4["born"] == 1438 and n4["died"] is None, n4
    assert n4["region"] == "Capital", n4

    # node 6: Qeswachaka — ntype relay, still geographic
    n6 = d["nodes"][6]
    assert n6["name"] == "Qeswachaka" and n6["ntype"] == NTYPE_RELAY, n6
    assert n6["abstract"] is False, n6

    # node 8: chasqui corps — ABSTRACT: NaN coords -> lat/lng None, abstract True
    n8 = d["nodes"][8]
    assert n8["name"] == "Chasqui corps" and n8["ntype"] == NTYPE_AGENT, n8
    assert n8["abstract"] is True and n8["lat"] is None and n8["lng"] is None, n8
    assert n8["born"] == 1438 and n8["died"] == 1533, n8

    # edges: 10 total; road weights survive, relay tethers decode weight None
    assert len(d["edges"]) == 10, len(d["edges"])
    assert d["edges"][0] == (0, 1, ETYPE_ROAD, 0, 230.0), d["edges"][0]
    assert d["edges"][6] == (4, 7, ETYPE_ROAD, 0, 1500.0), d["edges"][6]
    a, c, et, fl, w = d["edges"][7]
    assert (a, c, et, fl) == (8, 2, ETYPE_RELAY, 0) and w is None, d["edges"][7]
    # lines stay 2-tuples (etype/flags/weight stripped) for layout reuse
    assert d["lines"][0] == (0, 1) and d["lines"][9] == (8, 7), d["lines"]

    # topology-derived roles (NOT stored — proven derivable, per the ntype note):
    # a source has no incoming edge; here Quito(0) and the chasqui corps(8).
    children = {c for (_a, c, _et, _fl, _w) in d["edges"]}
    roots = [i for i in range(d["K"]) if i not in children]
    assert roots == [0, 8], roots

    # the abstract node's tether centroid (where the renderer hangs it inside earth)
    tethered = [d["nodes"][c] for (a, c, *_r) in d["edges"] if a == 8]
    clat = sum(t["lat"] for t in tethered) / len(tethered)
    clng = sum(t["lng"] for t in tethered) / len(tethered)

    # name-map spot checks + graceful degrade
    assert ntype_name(NTYPE_PLACE) == "place"
    assert etype_name(ETYPE_RELAY) == "relay"
    assert etype_name(0x7f) == "unknown_0x7f"

    # ---- v2 grammar assertions -------------------------------------------
    # the envelope is v2 (network's first and only standard)
    assert hdr[:4] == b"\xc1\xdd\x00\x02", hdr[:4].hex()
    # the v2 date var round-trips with its precision (9-byte wire)
    n2 = d["nodes"][2]
    assert n2["dates"] == [("seized", {"jd": 2280940.0, "precision": "month"})], n2["dates"]
    # a v1-stamped kind-0x05 blob is refused honestly (never legislated)
    try:
        read_network(b"\xc1\xdd\x00\x01" + blob[4:])
    except ValueError as e:
        assert "entered the law at v2" in str(e), e
    else:
        raise AssertionError("v1-stamped network blob did not raise")
    # the ntype enum is closed at four: 0x04 (the struck NTYPE_UNCERTAIN)
    # raises at build and at read
    try:
        build_network("x", [{"name": "n", "ntype": "uncertain"}], [])
    except ValueError:
        pass
    else:
        raise AssertionError("ntype 'uncertain' built — the enum must be closed")
    bad_hdr, bad_body = build_network("x", [{"name": "n"}], [])
    assert bad_body[3 + 1] == NTYPE_PLACE  # K:2 + T:1 + title 'x':1 -> ntype
    patched = bytearray(bad_body); patched[4] = 0x04
    try:
        read_network_quipu(bad_hdr, bytes(patched))
    except ValueError as e:
        assert "closed v2 enum" in str(e), e
    else:
        raise AssertionError("ntype 0x04 read — the enum must be closed")
    # a partial trailing edge is malformed, never silently dropped
    try:
        read_network(blob + b"\x00\x01")
    except ValueError as e:
        assert "trailing" in str(e), e
    else:
        raise AssertionError("trailing edge bytes silently dropped")

    print()
    print("title  :", d["title"])
    print("K      :", d["K"], " sources (no incoming edge):", roots)
    for i, n in enumerate(d["nodes"]):
        loc = "abstract" if n["abstract"] else "%.3f,%.3f" % (n["lat"], n["lng"])
        span = "%s-%s" % (n["born"] if n["born"] is not None else "?",
                          n["died"] if n["died"] is not None else "")
        print("  node %d  %-14s %-9s %-20s [%s]" % (
            i, n["name"], ntype_name(n["ntype"]), loc, span))
    print("edges  (typed):")
    for (a, c, et, fl, w) in d["edges"]:
        wt = "" if w is None else "  w=%.0f" % w
        dr = " (directed)" if fl & FLAG_DIRECTED else ""
        print("  %d -> %d  0x%02x %-7s%s%s" % (a, c, et, etype_name(et), wt, dr))
    print()
    print("abstract node 8 hangs inside earth near tether centroid: %.3f, %.3f"
          % (clat, clng))
    print()
    print("ALL ASSERTIONS PASSED — 9 nodes (1 abstract), 10 typed edges round-trip.")
