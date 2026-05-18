"""
estandarte.py — Estandarte (type 0xee): the protocol's own registry.

Estandarte is the constitutional quipu that documents the Quipu Protocol's
own type-byte vocabulary. It is self-referential — type 0xee documents 0xee
itself among the other types — and is meant to be inscribed under La Verna's
root as the canonical protocol manifest. Every other quipu marches under its
banner.

Wire format
-----------

HEADER (6 bytes flat):
    c1dd 0001 ee <tone>
        0xee = type byte (Estandarte)
        tone = 0x00 ordinary, 0xff reverence

BODY:
    <parent_kind:1>                  0x00 = root, 0x01 = amendment
    [if parent_kind == 0x01]:
        <parent_txid:32>             raw 32-byte txid of parent Estandarte
                                     (the join-transaction txid of its diamond)
    <T:1>                            type entries in this Estandarte
    for each type entry:
        <type_byte:1>                the type byte being documented
        <name_len:1> <name>          canonical name (UTF-8, ≤ 255 B)
        <desc_len:1> <desc>          one-line description (UTF-8, ≤ 255 B)
        <status:1>                   0=canonical, 1=proposed, 2=draft, 3=deprecated
        <subtype_count:1>            mutually-exclusive subtype values
        for each subtype:
            <value:1>
            <name_len:1> <name>
            <desc_len:1> <desc>
        <flag_count:1>               independent single-bit flags
        for each flag:
            <bit:1>                  bit position 0–7
            <name_len:1> <name>
            <desc_len:1> <desc>
    <C:1>                            conventions in this Estandarte
    for each convention:
        <name_len:1> <name>
        <syntax_len:1> <syntax>
        <desc_len:1> <desc>

Amendment chain resolution
--------------------------

An amendment Estandarte inherits its parent's entries and may add new ones
or override existing ones by (type_byte) or (convention name). The resolver
walks from leaf to root via parent_txid, accumulating entries with
leaf-wins override semantics. A bump to status=3 (deprecated) retires an
entry without removing it.

The convention block carries cross-cutting protocol conventions (citation
syntax, dimension conventions, etc.) that don't fit any one type.
"""

from __future__ import annotations

# Status enum
STATUS_CANONICAL = 0
STATUS_PROPOSED  = 1
STATUS_DRAFT     = 2
STATUS_DEPRECATED = 3
_STATUS_NAME = {0: "canonical", 1: "proposed", 2: "draft", 3: "deprecated"}

TONE_ORDINARY  = 0x00
TONE_REVERENCE = 0xFF

TYPE_ESTANDARTE = 0xEE


def _len_prefixed(s):
    """Encode a UTF-8 string as <len:1><bytes>. Raise if > 255 bytes."""
    b = s.encode("utf-8")
    if len(b) > 255:
        raise ValueError(f"string too long ({len(b)} > 255 bytes): {s!r}")
    return bytes([len(b)]) + b


def build_estandarte_quipu(types, conventions, tone=TONE_ORDINARY, parent_txid=None):
    """Build an Estandarte (0xee) protocol-registry quipu.

    Args:
        types: list of dicts, each describing one top-level type byte:
            {
              'byte': int,
              'name': str,
              'desc': str,
              'status': int (0..3),
              'subtypes': [{'value': int, 'name': str, 'desc': str}, ...],
              'flags':    [{'bit': int (0..7), 'name': str, 'desc': str}, ...],
            }
        conventions: list of dicts, each describing one cross-cutting convention:
            {'name': str, 'syntax': str, 'desc': str}
        tone: 0x00 ordinary or 0xff reverence
        parent_txid: optional 64-char hex string of parent Estandarte's join
            transaction. If given, this inscription is an *amendment* — its
            entries layer on top of the parent's via the chain resolver.

    Returns:
        (header_bytes, body_bytes) tuple.
    """
    if tone not in (TONE_ORDINARY, TONE_REVERENCE):
        raise ValueError(f"tone must be 0x00 or 0xff (got {tone:#04x})")
    if len(types) > 255:
        raise ValueError(f"max 255 type entries (got {len(types)})")
    if len(conventions) > 255:
        raise ValueError(f"max 255 conventions (got {len(conventions)})")

    header = b"\xc1\xdd\x00\x01" + bytes([TYPE_ESTANDARTE]) + bytes([tone])

    # Amendment-or-root prefix
    if parent_txid is None:
        body = bytes([0x00])
    else:
        parent_raw = bytes.fromhex(parent_txid)
        if len(parent_raw) != 32:
            raise ValueError(f"parent_txid must be 64 hex chars (32 bytes); got {len(parent_raw)}")
        body = bytes([0x01]) + parent_raw

    body += bytes([len(types)])

    for ti, t in enumerate(types):
        if not (0 <= t['byte'] <= 255):
            raise ValueError(f"type {ti} byte {t['byte']!r} out of range")
        if t['status'] not in (0, 1, 2, 3):
            raise ValueError(f"type {ti} status {t['status']!r} not in 0..3")
        if len(t['subtypes']) > 255:
            raise ValueError(f"type {ti} has > 255 subtypes")
        if len(t['flags']) > 255:
            raise ValueError(f"type {ti} has > 255 flags")

        body += bytes([t['byte']])
        body += _len_prefixed(t['name'])
        body += _len_prefixed(t['desc'])
        body += bytes([t['status']])
        body += bytes([len(t['subtypes'])])
        for s in t['subtypes']:
            if not (0 <= s['value'] <= 255):
                raise ValueError(f"subtype value {s['value']!r} out of range")
            body += bytes([s['value']])
            body += _len_prefixed(s['name'])
            body += _len_prefixed(s['desc'])
        body += bytes([len(t['flags'])])
        for f in t['flags']:
            if not (0 <= f['bit'] <= 7):
                raise ValueError(f"flag bit {f['bit']!r} must be 0..7")
            body += bytes([f['bit']])
            body += _len_prefixed(f['name'])
            body += _len_prefixed(f['desc'])

    body += bytes([len(conventions)])
    for c in conventions:
        body += _len_prefixed(c['name'])
        body += _len_prefixed(c['syntax'])
        body += _len_prefixed(c['desc'])

    return header, body


def read_estandarte_quipu(header_bytes, body_bytes):
    """Parse an Estandarte (0xee) quipu's bytes."""
    if header_bytes[:4] != b"\xc1\xdd\x00\x01":
        raise ValueError("not a quipu (c1dd0001 magic missing)")
    if header_bytes[4] != TYPE_ESTANDARTE:
        raise ValueError(
            f"not an Estandarte (type byte = {header_bytes[4]:#04x}, expected 0xee)"
        )
    if len(header_bytes) < 6:
        raise ValueError(f"header too short: {len(header_bytes)} (need ≥ 6)")
    tone = header_bytes[5]

    p = 0
    def read_byte():
        nonlocal p
        if p >= len(body_bytes):
            raise ValueError("body truncated")
        v = body_bytes[p]; p += 1; return v
    def read_str():
        n = read_byte()
        nonlocal p
        if p + n > len(body_bytes):
            raise ValueError("body truncated reading string")
        s = body_bytes[p:p+n].decode("utf-8"); p += n; return s
    def read_raw(n):
        nonlocal p
        if p + n > len(body_bytes):
            raise ValueError(f"body truncated reading {n} raw bytes")
        v = body_bytes[p:p+n]; p += n; return v

    # parent_kind: 0 root, 1 amendment
    parent_kind = read_byte()
    if parent_kind == 0x00:
        parent_txid = None
    elif parent_kind == 0x01:
        parent_txid = read_raw(32).hex()
    else:
        raise ValueError(f"unknown parent_kind {parent_kind:#04x} (expected 0x00 or 0x01)")

    T = read_byte()
    types = []
    for _ in range(T):
        type_byte = read_byte()
        name = read_str()
        desc = read_str()
        status = read_byte()
        subtypes = []
        sc = read_byte()
        for _ in range(sc):
            v = read_byte()
            sn = read_str()
            sd = read_str()
            subtypes.append({'value': v, 'name': sn, 'desc': sd})
        flags = []
        fc = read_byte()
        for _ in range(fc):
            b = read_byte()
            fn = read_str()
            fd = read_str()
            flags.append({'bit': b, 'name': fn, 'desc': fd})
        types.append({
            'byte': type_byte, 'name': name, 'desc': desc,
            'status': status, 'subtypes': subtypes, 'flags': flags,
        })

    C = read_byte()
    conventions = []
    for _ in range(C):
        n = read_str()
        s = read_str()
        d = read_str()
        conventions.append({'name': n, 'syntax': s, 'desc': d})

    return {
        'tone': tone,
        'parent_txid': parent_txid,
        'types': types,
        'conventions': conventions,
    }


# ---------------------------------------------------------------------------
# Amendment chain resolver
# ---------------------------------------------------------------------------

def resolve_estandarte_chain(leaf_txid, fetcher, max_depth=64):
    """Walk an Estandarte amendment chain from leaf back to root and merge.

    Args:
        leaf_txid: 64-char hex txid of the most-recent Estandarte to start from
        fetcher:   callable(txid_hex) -> bytes returning the concatenated
                   OP_RETURN payload from that quipu's diamond
        max_depth: safety cap on chain length (prevents cycles)

    Returns:
        {
          'chain':         list of parsed Estandartes, root-first
          'chain_length':  int
          'leaf_txid':     leaf_txid
          'root_txid':     txid of the root (no-parent) Estandarte at the chain head
          'types':         merged type dict {byte: entry} with leaf-wins override
          'conventions':   merged convention dict {name: entry} with leaf-wins
        }
    """
    chain = []
    seen  = set()
    current_txid = leaf_txid
    while current_txid:
        if current_txid in seen:
            raise ValueError(f"cycle in Estandarte amendment chain at {current_txid[:12]}…")
        if len(chain) >= max_depth:
            raise ValueError(f"amendment chain exceeded max_depth={max_depth}")
        seen.add(current_txid)

        blob = fetcher(current_txid)
        if isinstance(blob, str):
            blob = bytes.fromhex(blob.strip())
        # Estandarte header is always exactly 6 bytes (c1dd 0001 ee <tone>)
        header = blob[:6]
        body   = blob[6:]
        parsed = read_estandarte_quipu(header, body)
        parsed['self_txid'] = current_txid
        chain.append(parsed)
        current_txid = parsed['parent_txid']

    # Reverse so root is index 0, leaf is last
    chain.reverse()
    merged_types = {}        # byte -> entry
    merged_conv  = {}        # name -> entry
    for est in chain:
        for t in est['types']:
            merged_types[t['byte']] = dict(t, _source_txid=est['self_txid'])
        for c in est['conventions']:
            merged_conv[c['name']] = dict(c, _source_txid=est['self_txid'])

    return {
        'chain':        chain,
        'chain_length': len(chain),
        'leaf_txid':    leaf_txid,
        'root_txid':    chain[0]['self_txid'],
        'types':        merged_types,
        'conventions':  merged_conv,
    }


def format_estandarte(parsed):
    """Human-readable summary of a parsed Estandarte."""
    lines = []
    lines.append(f"Tone: {'reverence' if parsed['tone']==0xff else 'ordinary'}")
    lines.append(f"Registered types: {len(parsed['types'])}")
    for t in parsed['types']:
        lines.append(f"")
        lines.append(f"  0x{t['byte']:02x}  {t['name']:14s}  [{_STATUS_NAME[t['status']]}]")
        lines.append(f"        {t['desc']}")
        for s in t['subtypes']:
            lines.append(f"          subtype 0x{s['value']:02x}  {s['name']:18s}  {s['desc']}")
        for f in t['flags']:
            lines.append(f"          flag bit {f['bit']} (0x{1<<f['bit']:02x})  "
                         f"{f['name']:18s}  {f['desc']}")
    lines.append(f"")
    lines.append(f"Registered conventions: {len(parsed['conventions'])}")
    for c in parsed['conventions']:
        lines.append(f"")
        lines.append(f"  {c['name']}")
        lines.append(f"    syntax:  {c['syntax']}")
        lines.append(f"    {c['desc']}")
    return "\n".join(lines)
