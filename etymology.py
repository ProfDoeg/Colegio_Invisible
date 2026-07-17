#!/usr/bin/env python3
"""etymology.py — 0xce celestial-envelope quipu, kind byte 0x04 (KIND_ETYMOLOGY).

An etymology is a word-lineage: lexeme nodes (word-forms with attestation
spans) joined by *typed* descent edges. It mirrors the genealogy codec (kind
0x03) byte-for-byte EXCEPT each edge carries a third byte — a per-edge
`relation` role tag — so a single tree can hold native descent, loanwords,
derivations, calques, blends, cognate sibling-links, and uncertain mechanisms
without fracturing into homogeneous trees.

This is the per-element-kind primitive at the edge scale: where genealogy fixed
one edge-shape for the whole figure, etymology lets each edge declare its own
role. Homogeneous genealogy stays byte-identical; etymology only differs by the
one extra relation byte per edge (a 5-byte stride vs genealogy's 4).

Like genealogy, the etymology body is routed AROUND the canonical celestial
point reader (which accepts only kinds 0x00/0x01/0x02). Routing is by the kind
byte at header offset 6 == 0x04, and that route guard is LOAD-BEARING: the
5-byte edge stride is self-delimiting only because a genealogy (0x03) blob can
never reach this reader and vice-versa. Stride is NEVER inferred from length.

Wire (everything big-endian)
----------------------------
HEADER (9 bytes):
    c1 dd 00 01   magic4
    ce            type   = TYPE_CELESTIAL
    <tone:1>      canonical tone vocab (ignored by the etymology body)
    04            kind   = KIND_ETYMOLOGY
    00            grouped (reserved; MUST be 0x00; reader ignores/asserts)
    00            meta    (reserved; MUST be 0x00; reader ignores/asserts)

BODY (from offset 9 of blob = hdr + body):
    K:u16  T:u8  title:T
    K nodes, each:
        born:f32-BE   first-attestation year; NaN = unattested
        died:f32-BE   obsolescence year;      NaN = still living / unknown
        namelen:u8  name:namelen           the word-form / lexeme spelling
        morelen:u16-BE  more:morelen       (nvar:u8 · nvar×[keylen·key·vkind·value])
    Nref:u16-BE refs, each:
        txid:32  remote_idx:u16-BE(">H")  namelen:u8  name:namelen
    EDGES — read to EOF, 5-BYTE STRIDE:
        parent:u16-BE  child:u16-BE  relation:u8

Cross-house rule (unchanged from genealogy): the comparison is on the PARENT
index a — a < K is nodes[a], a >= K is refs[a-K] (a borrowing source in another
quipu). `relation` is orthogonal and is never conflated with that comparison.

born/died sentinel: NaN -> None. Write float('nan') for an unattested year,
never 0.0 (which would decode as the year 0 CE). Negative = BCE.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "canonical"))
from atoms import emit_more_block as _atoms_emit, read_more_block as _atoms_read

MAGIC = b"\xc1\xdd\x00\x01"
TYPE_CELESTIAL = 0xCE
KIND_GENEALOGY = 0x03
KIND_ETYMOLOGY = 0x04

TONE_ORDINARY = 0x00
TONE_REVERENCE = 0xFF

# more-block vkind bytes (reused verbatim from celestial)
VAR_TEXT = 0x00   # vlen:u16-BE + utf8
VAR_REF = 0x01    # 32-byte txid
VAR_DATE = 0x02   # f64-BE Julian Day

# ---------------------------------------------------------------------------
# Relation enum — the per-edge role tag (the third edge byte)
# ---------------------------------------------------------------------------
RELATION_INHERITED = 0x00   # direct native descent within one lineage
RELATION_BORROWED  = 0x01   # loanword: child adopts parent from another language
RELATION_DERIVED   = 0x02   # affixation/derivation within a language
RELATION_CALQUED   = 0x03   # loan-translation: copies structure, not phonology
RELATION_BLEND     = 0x04   # portmanteau / contamination of two+ parents
RELATION_COGNATE   = 0x05   # sibling link (shared ancestor) — NON-directional
RELATION_UNCERTAIN = 0x06   # edge mechanism disputed / pre-attestation root mechanism

RELATION_NAME_TO_BYTE = {
    "inherited": RELATION_INHERITED,
    "borrowed":  RELATION_BORROWED,
    "derived":   RELATION_DERIVED,
    "calqued":   RELATION_CALQUED,
    "blend":     RELATION_BLEND,
    "cognate":   RELATION_COGNATE,
    "uncertain": RELATION_UNCERTAIN,
}
RELATION_BYTE_TO_NAME = {v: k for k, v in RELATION_NAME_TO_BYTE.items()}

# etymology node `more` keys -> the ONLY vkind permitted for each (B.4 lock).
# text keys use VAR_TEXT; `ref` uses VAR_REF. No other vkind may appear.
# "certainty" removed 2026-07-17: certainty markers are against the ethos —
# the telling does not footnote itself (c1dd0002 §7.3). Old blobs carrying a
# certainty key still read (it is just a text var); builders no longer write it.
_TEXT_KEYS = ("lang", "gloss", "pos", "ipa")


def relation_name(rel):
    """Human name for a relation byte, or 'unknown_0xNN' (never raises)."""
    return RELATION_BYTE_TO_NAME.get(rel, f"unknown_{rel:#04x}")


def _resolve_relation(rel):
    """Edge relation -> byte. A string is looked up (unknown name is a build
    error); an int is passed through (unknown int round-trips, surfaced as-is)."""
    if isinstance(rel, str):
        if rel not in RELATION_NAME_TO_BYTE:
            raise ValueError(
                f"unknown relation name {rel!r}; known: {sorted(RELATION_NAME_TO_BYTE)}")
        return RELATION_NAME_TO_BYTE[rel]
    rel = int(rel)
    if not (0 <= rel <= 0xFF):
        raise ValueError(f"relation byte {rel} out of range 0..255")
    return rel


# ---------------------------------------------------------------------------
# more-block (keyless; replicated from celestial so etymology stands alone)
# ---------------------------------------------------------------------------
_NAME_TO_VK = {"text": VAR_TEXT, "ref": VAR_REF, "date": VAR_DATE}


def _emit_more(more, idx):
    """Serialize a node's `more` list of (key, vkind, value). Delegates to the
    ONE shared typed-var codec (canonical/atoms.py) — the per-module clone is
    retired (c1dd0002 §7.5). The etymology vkind lock is enforced upstream in
    build_etymology."""
    return _atoms_emit(more, version=1, label=f"node {idx}")


def _read_more_block(blob, o, end):
    """Parse a `more` payload in [o, end) via the shared codec. STRICT: an
    unknown vkind raises (its width is unknown; the old silent `break`
    presented a partial record as whole). Surface stays etymology's own:
    [(key, vkind_byte, value)] with refs as hex. Keyless."""
    out = []
    for key, name_, val in _atoms_read(bytes(blob[o:end]), version=1,
                                       label="node"):
        if name_ == "ref":
            val = val.hex()
        out.append((key, _NAME_TO_VK[name_], val))
    return out


def _gy(x):
    """born/died f32 year -> int, or None for NaN (unattested / unknown)."""
    return None if x != x else int(round(x))


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
def _build_header(kind, tone):
    """The 9-byte celestial envelope for a routed-around body (genealogy/etymology
    style): magic4 + type + tone + kind + grouped(0x00) + meta(0x00). grouped and
    meta are RESERVED for etymology and MUST be 0x00 (B.1 fix #11)."""
    if not (0 <= tone <= 0xFF):
        raise ValueError(f"tone byte {tone} out of range 0..255")
    return (
        MAGIC
        + bytes([TYPE_CELESTIAL])
        + bytes([tone])
        + bytes([kind])
        + bytes([0x00])      # grouped — reserved, MUST be 0x00
        + bytes([0x00])      # meta    — reserved, MUST be 0x00
    )


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
def build_etymology(title, nodes, edges, refs=(), tone=TONE_REVERENCE):
    """Build an etymology quipu -> (header_bytes, body_bytes).

    title : str
    nodes : list of dicts, each:
        {name:str,
         born: year|None|NaN, died: year|None|NaN,   (None/NaN -> f32 NaN sentinel)
         lang:str, gloss:str, pos:str,               (lang/gloss required, pos recommended)
         ipa:str(optional), certainty:str(optional),
         refs: [(key, txid32), ...] (optional)}       (cross-quipu source citations)
    edges : list of (parent_idx, child_idx, relation) — relation int or name string.
    refs  : list of {txid:32B, remote_idx:u16, name:str} cross-house sources.
    tone  : tone byte (default reverence 0xff).

    Vkind lock (B.4): every text key is written VAR_TEXT, `ref` is VAR_REF; no
    other vkind is permitted in an etymology node and is rejected at build time.
    Optional keys (ipa/certainty) are omitted entirely when absent (decoder
    defaults them to "").
    """
    header = _build_header(KIND_ETYMOLOGY, tone)

    title_bytes = title.encode("utf-8")
    if len(title_bytes) > 255:
        raise ValueError(f"title encodes to {len(title_bytes)} UTF-8 bytes; max 255")
    K = len(nodes)
    if K > 0xFFFF:
        raise ValueError(f"max 65535 nodes per etymology (got {K})")

    body = bytearray()
    body += struct.pack(">H", K)
    body += bytes([len(title_bytes)]) + title_bytes

    for i, n in enumerate(nodes):
        if "name" not in n:
            raise ValueError(f"node {i} missing required 'name' key")
        born = n.get("born")
        died = n.get("died")
        body += struct.pack(">f", _year_f32(born))
        body += struct.pack(">f", _year_f32(died))
        nb = n["name"].encode("utf-8")
        if len(nb) > 255:
            raise ValueError(f"node {i}: name encodes to {len(nb)} bytes; max 255")
        body += bytes([len(nb)]) + nb

        # build the more list (vkind-locked) — text keys, then ref vars
        more = []
        for key in _TEXT_KEYS:
            if key in ("lang", "gloss"):
                val = n.get(key, "")
            else:
                val = n.get(key)
                if val is None or val == "":
                    continue            # omit optional keys when absent
            more.append((key, VAR_TEXT, str(val)))
        for key, txid in n.get("refs", ()):
            if len(txid) != 32:
                raise ValueError(f"node {i}: ref {key!r} must cite a 32-byte txid")
            more.append((key, VAR_REF, bytes(txid)))
        # vkind lock: nothing but VAR_TEXT / VAR_REF reaches the wire
        for (k, vk, _v) in more:
            if vk not in (VAR_TEXT, VAR_REF):
                raise ValueError(
                    f"node {i}: etymology key {k!r} may only use vkind 0x00 (text) "
                    f"or 0x01 (ref); got {vk:#04x}")
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

    # edges — 5-byte typed stride
    for e in edges:
        parent, child, rel = e
        relation = _resolve_relation(rel)
        if not (0 <= parent <= 0xFFFF) or not (0 <= child <= 0xFFFF):
            raise ValueError(f"edge ({parent},{child}): indices must fit u16")
        body += struct.pack(">HHB", parent, child, relation)

    return bytes(header), bytes(body)


def _year_f32(y):
    """A born/died year (int|float|None) -> the f32 value to pack. None or NaN
    -> NaN sentinel; never 0.0 (which would mean the year 0 CE)."""
    if y is None:
        return float("nan")
    y = float(y)
    return y          # a NaN passed in stays NaN through struct.pack


# alias for the spec's named signature
build_etymology_quipu = build_etymology


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------
def read_etymology_quipu(hdr, body):
    """Decode an etymology quipu (type 0xCE, kind 0x04) from its header + body.

    Mirrors read_genealogy_quipu, with the 5-byte typed edge stride. Offsets 7,8
    (grouped/meta) are RESERVED and ignored except for the 0x00 assertion below;
    the reader NEVER branches on them. Returns a dict (see module docstring / B.5):
      {title, K, kind:'etymology', nodes:[...], people:<same list>, refs, edges, lines}.
    `edges` are 3-tuples (parent, child, relation_int); `lines` are 2-tuples
    (parent, child) with the relation stripped, for layout-code reuse.

    Keyless throughout."""
    blob = hdr + body
    if len(blob) < 9:
        raise ValueError("etymology: blob shorter than the 9-byte header")
    if blob[4] != TYPE_CELESTIAL:
        raise ValueError(f"etymology: type byte {blob[4]:#04x} != 0xCE")
    if blob[6] != KIND_ETYMOLOGY:                     # load-bearing route guard (fix #5)
        raise ValueError(f"etymology: kind byte {blob[6]:#04x} != 0x04")
    if blob[7] != 0x00 or blob[8] != 0x00:            # reserved-byte contract (fix #11)
        raise ValueError(
            f"etymology: reserved header bytes 7,8 must be 0x00, "
            f"got {blob[7]:#04x},{blob[8]:#04x}")

    o = 9
    K = int.from_bytes(blob[o:o + 2], "big"); o += 2
    T = blob[o]; o += 1
    title = blob[o:o + T].decode("utf-8"); o += T

    nodes = []
    for _ in range(K):
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
            "born": _gy(born),
            "died": _gy(died),
            "lang": _txt("lang"),
            "gloss": _txt("gloss"),
            "pos": _txt("pos"),
            "ipa": _txt("ipa"),
            "certainty": _txt("certainty"),
            "refs": [(k, v) for (k, vk, v) in more if vk == VAR_REF],
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
    while o + 5 <= len(blob):                          # 5-byte stride (NEVER length-inferred)
        a = int.from_bytes(blob[o:o + 2], "big")
        c = int.from_bytes(blob[o + 2:o + 4], "big")
        rel = blob[o + 4]                              # raw byte — surfaced as-is (unknown OK)
        o += 5
        edges.append((a, c, rel))
        lines.append((a, c))                           # relation stripped → 2-tuple

    return {
        "title": title,
        "K": K,
        "kind": "etymology",
        "nodes": nodes,
        "people": nodes,        # alias so genealogy layout reuse works
        "refs": refs,
        "edges": edges,         # 3-tuples (parent, child, relation_int)
        "lines": lines,         # 2-tuples (parent, child)
    }


def read_etymology(blob):
    """Decode from a single joined blob (hdr + body). Splits at the 9-byte header
    and defers to read_etymology_quipu."""
    if len(blob) < 9:
        raise ValueError("etymology: blob shorter than the 9-byte header")
    return read_etymology_quipu(blob[:9], blob[9:])


# ---------------------------------------------------------------------------
# Worked example — "Etymology of celestial" (the spec's verified bytes)
# ---------------------------------------------------------------------------
def _worked_example():
    """The spec's 7-node 'celestial' etymology. Returns (title, nodes, edges)."""
    nodes = [
        # 0: *(s)kai- — PIE root, unattested (born=died=NaN). The scholarly
        # hedge lives in the gloss PROSE ("disputed") — certainty markers are
        # against the ethos; the telling does not footnote itself (§7.3).
        {"name": "*(s)kai-", "born": None, "died": None,
         "lang": "Proto-Indo-European", "gloss": "to shine; bright (disputed)",
         "pos": "root"},
        # 1: caelum — Latin
        {"name": "caelum", "born": -200.0, "died": None,
         "lang": "Latin", "gloss": "sky, heaven", "pos": "noun (neuter)"},
        # 2: caelestis — Latin (derived from caelum)
        {"name": "caelestis", "born": -200.0, "died": None,
         "lang": "Latin", "gloss": "heavenly, of the sky", "pos": "adjective"},
        # 3: celestis — Late Latin / vulgar form
        {"name": "celestis", "born": None, "died": None,
         "lang": "Late Latin", "gloss": "heavenly", "pos": "adjective"},
        # 4: celeste — Old French
        {"name": "celeste", "born": 1150.0, "died": None,
         "lang": "Old French", "gloss": "heavenly, sky-blue", "pos": "adjective"},
        # 5: celestial — Middle English (borrowed from Old French)
        {"name": "celestial", "born": 1380.0, "died": None,
         "lang": "Middle English", "gloss": "of the heavens", "pos": "adjective"},
        # 6: celestial — Modern English
        {"name": "celestial", "born": 1400.0, "died": None,
         "lang": "English", "gloss": "of the sky or heavens", "pos": "adjective"},
    ]
    edges = [
        (0, 1, RELATION_UNCERTAIN),   # 0x06  PIE root -> Latin, disputed mechanism
        (1, 2, RELATION_DERIVED),     # 0x02  caelum -> caelestis (affixation)
        (2, 3, RELATION_DERIVED),     # 0x02  caelestis -> celestis
        (3, 4, RELATION_INHERITED),   # 0x00  celestis -> celeste (native descent)
        (4, 5, RELATION_BORROWED),    # 0x01  Old French -> Middle English (loan)
        (5, 6, RELATION_INHERITED),   # 0x00  ME -> Modern English
    ]
    return "Etymology of celestial", nodes, edges


if __name__ == "__main__":
    title, nodes, edges = _worked_example()
    hdr, body = build_etymology(title, nodes, edges, tone=TONE_REVERENCE)
    blob = hdr + body

    print("header :", hdr.hex())
    print("kind   :", "0x%02x" % hdr[6], "(KIND_ETYMOLOGY)" if hdr[6] == 0x04 else "(!!)")
    print("grouped:", "0x%02x" % hdr[7], " meta:", "0x%02x" % hdr[8], "(both reserved 0x00)")

    # the exact 30-byte edge block the spec verified
    edge_block = b"".join(struct.pack(">HHB", a, c, r) for (a, c, r) in edges)
    print("edges  :", edge_block.hex(), "(len %d)" % len(edge_block))
    assert edge_block.hex() == "000000010600010002020002000302000300040000040005010005000600", \
        "edge block bytes diverge from the spec's verified 30 bytes"
    assert len(edge_block) == 30

    d = read_etymology(blob)

    # ---- assertions: all 7 nodes, their more-fields, all 6 typed edges -------
    assert d["title"] == "Etymology of celestial", d["title"]
    assert d["K"] == 7, d["K"]
    assert d["kind"] == "etymology"
    assert len(d["nodes"]) == 7, len(d["nodes"])
    assert d["people"] is d["nodes"], "people must alias nodes"

    # node 0: unattested PIE root, born/died -> None; 4 text more-fields
    n0 = d["nodes"][0]
    assert n0["name"] == "*(s)kai-", n0["name"]
    assert n0["born"] is None and n0["died"] is None, (n0["born"], n0["died"])
    assert n0["lang"] == "Proto-Indo-European", n0["lang"]
    assert n0["gloss"] == "to shine; bright (disputed)", n0["gloss"]
    assert n0["pos"] == "root", n0["pos"]
    # builders no longer write certainty (abolished §7.3); the reader still
    # surfaces it from old blobs, defaulting "" here
    assert n0["certainty"] == "", n0["certainty"]
    assert n0["ipa"] == "", n0["ipa"]

    # node 1: caelum, born -200 (BCE), died None
    n1 = d["nodes"][1]
    assert n1["name"] == "caelum" and n1["born"] == -200 and n1["died"] is None, n1
    assert n1["lang"] == "Latin" and n1["gloss"] == "sky, heaven", n1

    # node 4/5/6: years round-trip
    assert d["nodes"][4]["born"] == 1150, d["nodes"][4]["born"]
    assert d["nodes"][5]["born"] == 1380, d["nodes"][5]["born"]
    assert d["nodes"][6]["born"] == 1400, d["nodes"][6]["born"]
    assert d["nodes"][6]["lang"] == "English"

    # all 6 typed edges, with correct relation bytes
    assert d["edges"] == [(0, 1, 6), (1, 2, 2), (2, 3, 2), (3, 4, 0), (4, 5, 1), (5, 6, 0)], d["edges"]
    # lines stay 2-tuples (relation stripped) for layout reuse
    assert d["lines"] == [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6)], d["lines"]
    # no cross-house refs in this example
    assert d["refs"] == [], d["refs"]

    # rootness is ABSENCE of an incoming edge — node 0 has no edge with child==0
    children = {c for (_a, c, _r) in d["edges"]}
    roots = [i for i in range(d["K"]) if i not in children]
    assert roots == [0], roots

    # relation-name spot checks
    assert relation_name(0x06) == "uncertain"
    assert relation_name(0x00) == "inherited"
    assert relation_name(0x01) == "borrowed"
    assert relation_name(0x02) == "derived"
    assert relation_name(0x7f) == "unknown_0x7f"     # graceful degrade

    print()
    print("title  :", d["title"])
    print("K      :", d["K"], " roots:", roots, " (root has no incoming edge)")
    for i, n in enumerate(d["nodes"]):
        yr = "%s–%s" % (n["born"] if n["born"] is not None else "?",
                        n["died"] if n["died"] is not None else "")
        print("  node %d  %-12s %-20s %-28s [%s] %s" % (
            i, n["name"], n["lang"], n["gloss"], yr,
            ("cert=" + n["certainty"]) if n["certainty"] else ""))
    print("edges  (typed):")
    for (a, c, r) in d["edges"]:
        print("  %d -> %d  0x%02x %s" % (a, c, r, relation_name(r)))
    print()
    print("ALL ASSERTIONS PASSED — 7 nodes, more-fields, 6 typed edges round-trip.")
