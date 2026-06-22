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
        tone = 0x00 ordinary, 0x0d demonic, 0xff reverence

BODY:
    <parent_kind:1>                  0x00 = root, 0x01 = amendment
    [if parent_kind == 0x01]:
        <parent_txid:32>             raw 32-byte txid of parent Estandarte
                                     (the root-transaction txid of its diamond)
    <T:1>                            type entries in this Estandarte
    for each type entry:
        <type_byte:1>                the type byte being documented
        <name_len:1> <name>          canonical name (UTF-8, ≤ 255 B)
        <desc_len:1> <desc>          one-line description (UTF-8, ≤ 255 B)
        <status:1>                   0=canonical, 1=proposed, 2=draft, 3=deprecated
        <dim_count:1>                named enum dimensions in the type's header
        for each dimension:
            <dim_name_len:1>  <dim_name>   e.g. "color", "bit_depth", "sub_family"
            <dim_desc_len:1>  <dim_desc>   one-line description of what the byte means
            <value_count:1>                count of named values in this dimension
            for each value:
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

A "dimension" is a single byte field within the type's header whose
value is drawn from a named enumeration. Types may have zero, one, or
many dimensions:
    0x00 text       — zero dimensions (tone is a cross-type field)
    0x03 image      — two dimensions: color, bit_depth
    0xcc cert       — one dimension: subtype (2 bytes; encoded as
                        subtype_hi+subtype_lo, documented as one
                        16-bit dimension or two 8-bit dimensions
                        depending on the type's spec)
    0x0e encrypted  — two dimensions: sub_family, variant
    0xce celestial  — three dimensions: kind, grouped, meta

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

from tone import (
    TONES, VALID_TONES, validate_tone,
    TONE_ORDINARY, TONE_AFFECTION, TONE_DEMONIC, TONE_AI, TONE_REVERENCE,
)
_VALID_TONES = VALID_TONES  # backward-compat alias

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
              'dimensions': [
                {
                  'name': str,          # e.g. "color"
                  'desc': str,          # e.g. "pixel color model"
                  'values': [{'value': int, 'name': str, 'desc': str}, ...]
                },
                ...
              ],
              'flags': [{'bit': int (0..7), 'name': str, 'desc': str}, ...],
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
    validate_tone(tone)
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
        dimensions = t.get('dimensions', [])
        if len(dimensions) > 255:
            raise ValueError(f"type {ti} has > 255 dimensions")
        if len(t['flags']) > 255:
            raise ValueError(f"type {ti} has > 255 flags")

        body += bytes([t['byte']])
        body += _len_prefixed(t['name'])
        body += _len_prefixed(t['desc'])
        body += bytes([t['status']])
        body += bytes([len(dimensions)])
        for di, dim in enumerate(dimensions):
            if len(dim['values']) > 255:
                raise ValueError(f"type {ti} dimension {di} has > 255 values")
            body += _len_prefixed(dim['name'])
            body += _len_prefixed(dim['desc'])
            body += bytes([len(dim['values'])])
            for v in dim['values']:
                if not (0 <= v['value'] <= 255):
                    raise ValueError(f"type {ti} dim {di} value {v['value']!r} out of range")
                body += bytes([v['value']])
                body += _len_prefixed(v['name'])
                body += _len_prefixed(v['desc'])
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
        dimensions = []
        dc = read_byte()
        for _ in range(dc):
            dim_name = read_str()
            dim_desc = read_str()
            vc = read_byte()
            values = []
            for _ in range(vc):
                v = read_byte()
                vn = read_str()
                vd = read_str()
                values.append({'value': v, 'name': vn, 'desc': vd})
            dimensions.append({'name': dim_name, 'desc': dim_desc, 'values': values})
        flags = []
        fc = read_byte()
        for _ in range(fc):
            b = read_byte()
            fn = read_str()
            fd = read_str()
            flags.append({'bit': b, 'name': fn, 'desc': fd})
        types.append({
            'byte': type_byte, 'name': name, 'desc': desc,
            'status': status, 'dimensions': dimensions, 'flags': flags,
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
        for dim in t.get('dimensions', []):
            lines.append(f"          dim '{dim['name']}': {dim['desc']}")
            for v in dim['values']:
                lines.append(f"            0x{v['value']:02x}  {v['name']:18s}  {v['desc']}")
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


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _example_registry():
    """Return a (types, conventions) tuple suitable as a starting Estandarte
    draft. Captures the June 2026 type set: every canonical type with its
    dimensions current, the observed pre-canonical types (0x0c, 0x1d)
    registered with honest statuses, and the protocol-level conventions —
    including the diamond assembly rules a reader needs to reconstruct any
    multi-tx inscription from raw transactions."""
    types = [
        {
            'byte': 0x00, 'name': 'text', 'status': STATUS_CANONICAL,
            'desc': 'plain text with pipe-bracketed title and tone byte',
            'dimensions': [],
            'flags': [],
        },
        {
            'byte': 0x01, 'name': 'essay', 'status': STATUS_CANONICAL,
            'desc': 'markdown essay with <<txid>> citations and fenced binding blocks',
            'dimensions': [],
            'flags': [],
        },
        {
            'byte': 0x03, 'name': 'image', 'status': STATUS_CANONICAL,
            'desc': 'bit-packed raster image, width-first dimensions, MSB-first row-major packing',
            'dimensions': [
                {'name': 'color', 'desc': 'pixel color model', 'values': [
                    {'value': 0x00, 'name': 'grayscale',  'desc': '1 channel per pixel'},
                    {'value': 0x01, 'name': 'rgb',        'desc': '3 channels per pixel'},
                    {'value': 0x02, 'name': 'gray_alpha', 'desc': '2 channels per pixel: gray, alpha'},
                    {'value': 0x03, 'name': 'rgba',       'desc': '4 channels per pixel: R, G, B, alpha'},
                ]},
                {'name': 'bit_depth', 'desc': 'bits per channel per pixel (1..8)', 'values': [
                    {'value': i, 'name': f'{i}-bit', 'desc': f'{i} bits per channel'}
                    for i in range(1, 9)
                ]},
            ],
            'flags': [],
        },
        {
            'byte': 0x07, 'name': 'sound', 'status': STATUS_CANONICAL,
            'desc': 'audio container: a codec byte selects a quipu vocoder (STFT/LPC/Codec2) or an opaque standard format (opus/mp3/wav/flac); body is encoded audio',
            'dimensions': [
                {'name': 'codec', 'desc': 'how the body bytes encode audio', 'values': [
                    {'value': 0x00, 'name': 'stft',   'desc': 'quipu STFT-magnitude vocoder (speech)'},
                    {'value': 0x01, 'name': 'lpc',    'desc': 'quipu LPC-10 vocoder (speech)'},
                    {'value': 0x02, 'name': 'codec2', 'desc': 'Codec2 700C (speech, needs libcodec2)'},
                    {'value': 0x10, 'name': 'opus',   'desc': 'opaque Ogg/Opus'},
                    {'value': 0x11, 'name': 'mp3',    'desc': 'opaque MP3'},
                    {'value': 0x12, 'name': 'wav',    'desc': 'opaque WAV/PCM'},
                    {'value': 0x13, 'name': 'flac',   'desc': 'opaque FLAC'},
                ]},
            ],
            'flags': [],
        },
        {
            'byte': 0x09, 'name': 'book', 'status': STATUS_CANONICAL,
            'desc': 'ordered multi-document container (front/body/back zones, parts, nested volumes)',
            'dimensions': [],
            'flags': [],
        },
        {
            'byte': 0x0c, 'name': 'cert-precursor', 'status': STATUS_DEPRECATED,
            'desc': 'pre-canonical hash certificate; superseded by 0xcc. One inscription on chain, kept readable',
            'dimensions': [],
            'flags': [],
        },
        {
            'byte': 0x0e, 'name': 'encrypted', 'status': STATUS_CANONICAL,
            'desc': 'sealed sub-families: AES, ECIES, key-drop, canary, sale box, threshold shares',
            'dimensions': [
                {'name': 'sub_family', 'desc': 'which encryption shape', 'values': [
                    {'value': 0xae, 'name': 'aes',       'desc': 'symmetric AES-CBC wrapper'},
                    {'value': 0xec, 'name': 'ecies',     'desc': 'per-recipient ECIES envelopes'},
                    {'value': 0x0d, 'name': 'drop',      'desc': 'released-key drop'},
                    {'value': 0xca, 'name': 'centinela', 'desc': 'cryptographic canary: AES-sealed claim secret over a bait UTXO, so a spend is on-chain tamper-evidence'},
                    {'value': 0xcb, 'name': 'cb-sale',   'desc': 'committed-binding sale box: ECIES-sealed to a fresh session pubkey for a verified-key sale'},
                    {'value': 0x55, 'name': 'shamir',    'desc': 'Shamir K-of-N secret share over GF(2^8) (threshold key-drop; vault variant is self-contained)'},
                ]},
                {'name': 'variant', 'desc': 'sub-family-specific qualifier (meaning depends on sub_family)', 'values': [
                    {'value': 0x00, 'name': 'raw',      'desc': 'aes: raw 32-byte key · ecies: broadcast · drop: bare release · centinela: raw-key seal · cb-sale: v1 single-key · shamir: single share'},
                    {'value': 0x01, 'name': 'password', 'desc': 'aes: SHA256(passphrase) key · drop: sourced (|claim=…| descriptor) · centinela: passphrase seal · shamir: self-contained vault'},
                ]},
            ],
            'flags': [],
        },
        {
            'byte': 0x0f, 'name': 'file', 'status': STATUS_CANONICAL,
            'desc': 'generic binary container: optional sha256 (flag-gated), mimetype, filename, optional title; body is the raw file bytes',
            'dimensions': [],
            'flags': [],
        },
        {
            'byte': 0x1d, 'name': 'identity', 'status': STATUS_DRAFT,
            'desc': 'JSON identity dictionary: names, public keys, handles, references. One pre-canonical inscription on chain',
            'dimensions': [],
            'flags': [],
        },
        {
            'byte': 0x3d, 'name': 'scene', 'status': STATUS_CANONICAL,
            'desc': 'walkable 3D scene: camera + textured point/photo geometry (pinhole-projectable)',
            'dimensions': [],
            'flags': [],
        },
        {
            'byte': 0x5c, 'name': 'latex', 'status': STATUS_CANONICAL,
            'desc': 'LaTeX document or plate; class= names the document class, \\quiputikz transcludes data by pointer',
            'dimensions': [],
            'flags': [],
        },
        {
            'byte': 0xab, 'name': 'binding', 'status': STATUS_CANONICAL,
            'desc': 'binding overlay: imports, alias chains, string substitution, and anchored annotations',
            'dimensions': [],
            'flags': [],
        },
        {
            'byte': 0xcc, 'name': 'cert', 'status': STATUS_CANONICAL,
            'desc': 'certificate: hash-only, all-in-one, or sale offer (subtype is 2-byte big-endian)',
            'dimensions': [
                {'name': 'subtype', 'desc': '2-byte certificate subtype (BE)', 'values': [
                    {'value': 0x01, 'name': 'hash',       'desc': 'SHA256 hash of off-chain payload only'},
                    {'value': 0x02, 'name': 'all-in-one', 'desc': 'full certificate body on chain'},
                    {'value': 0x03, 'name': 'sale-offer', 'desc': 'verified-key sale offer: attestation fields + signers + ECDSA adaptor signatures'},
                ]},
            ],
            'flags': [],
        },
        {
            'byte': 0xce, 'name': 'celestial', 'status': STATUS_CANONICAL,
            'desc': 'sky or earth point figures, optionally grouped, optionally per-point meta',
            'dimensions': [
                {'name': 'kind', 'desc': 'coordinate frame of all points', 'values': [
                    {'value': 0x00, 'name': 'earth', 'desc': 'lng/lat geographic coordinates'},
                    {'value': 0x01, 'name': 'star',  'desc': 'RA/Dec celestial-sphere coordinates'},
                ]},
                {'name': 'grouped', 'desc': 'whether points are partitioned into named groups', 'values': [
                    {'value': 0x00, 'name': 'no',  'desc': 'flat point list'},
                    {'value': 0x01, 'name': 'yes', 'desc': 'points partitioned into named groups with lines'},
                ]},
                {'name': 'meta', 'desc': 'per-point metadata shape', 'values': [
                    {'value': 0x00, 'name': 'no',   'desc': 'points have name + coords only'},
                    {'value': 0x01, 'name': 'time', 'desc': 'points may carry timestamps'},
                    {'value': 0x02, 'name': 'more', 'desc': 'points may carry named variables: text, 32-byte quipu ref, or Julian-Day date'},
                ]},
            ],
            'flags': [],
        },
        {
            'byte': 0xda, 'name': 'dancer', 'status': STATUS_CANONICAL,
            'desc': 'motion-sprite dancer: frames + per-frame centroid/displacement + named-transition graph',
            'dimensions': [
                {'name': 'variant', 'desc': 'which dancer record', 'values': [
                    {'value': 0x01, 'name': 'performance', 'desc': 'a played sequence of frames'},
                    {'value': 0x02, 'name': 'footage',     'desc': 'raw frame atlas (inline or by-ref)'},
                    {'value': 0x03, 'name': 'graph',       'desc': 'named-transition graph between clips'},
                    {'value': 0x04, 'name': 'controller',  'desc': 'control-mode bindings (uniform/weighted/boltzmann/quantum/keyboard)'},
                ]},
            ],
            'flags': [],
        },
        {
            'byte': 0xee, 'name': 'estandarte', 'status': STATUS_CANONICAL,
            'desc': 'self-referential protocol registry (this type); amends via parent_txid, leaf wins',
            'dimensions': [],
            'flags': [],
        },
    ]

    conventions = [
        {
            'name':   'magic',
            'syntax': 'c1 dd 00 01 at offset 0',
            'desc':   'protocol magic + version 0.1 prefix on every quipu',
        },
        {
            'name':   'tone',
            'syntax': 'header byte 5',
            'desc':   'cross-type semantic register: 0x00 ordinary; affective family 0x01-0x07 '
                      '(affection, seeking, play, lust, rage, fear, grief — the seven primal systems); '
                      '0x0d demonic; 0xa1 ai; 0xff reverence. Default 0x00',
        },
        {
            'name':   'diamond',
            'syntax': 'root (1 tx, N outputs) -> N strands of <=80-byte OP_RETURN txs -> join (1 tx, N inputs)',
            'desc':   'every payload over 80 bytes is inscribed as a diamond; strand k is seeded by '
                      'root output k; the inscription is complete when the join confirms; a high-fee '
                      'join (CPFP) is the canonical rescue for stalled strands',
        },
        {
            'name':   'assembly',
            'syntax': 'payload = strand 0 (cabeza) + strands 1..N-1 (cuerpos), in root-output order',
            'desc':   'strand 0 opens with the structural header; body bytes fill the strands as '
                      'contiguous runs, never interleaved. A reader walks each strand from its root '
                      'output to the join collecting OP_RETURN payloads, then concatenates',
        },
        {
            'name':   'citation',
            'syntax': '<<txid>>  or  <<txid>><<name>>',
            'desc':   'whole-inscription reference is the ROOT txid of its diamond — fixed the moment '
                      'the root is signed; the join is an artifact of closing. With <<name>>, '
                      'references a named sub-object inside the target',
        },
        {
            'name':   'forest',
            'syntax': 'splitter -> many roots -> strands -> one consolidating join',
            'desc':   'many quipus inscribed as one funding tree; each member keeps its own root '
                      'identity and is cited by its own root txid; members may cross-reference '
                      'each other by root before any join exists',
        },
        {
            'name':   'pre-canonical',
            'syntax': 'inscriptions predating this registry (before May 2026)',
            'desc':   'earlier inscriptions may deviate from these specs: encrypted headers carried '
                      'an inner content-type byte, some images are non-structural or transpose '
                      'dimensions. Deviations are documented errata — kept readable, never rewritten',
        },
    ]
    return types, conventions


def _selftest_roundtrip():
    types, conv = _example_registry()
    h, b = build_estandarte_quipu(types, conv, tone=TONE_ORDINARY)
    print(f"=== roundtrip (root Estandarte, {len(types)} types, {len(conv)} conventions) ===")
    print(f"  header ({len(h)} B): {h.hex()}")
    print(f"  body length: {len(b)} B")
    assert h[:4] == b"\xc1\xdd\x00\x01"
    assert h[4] == TYPE_ESTANDARTE
    parsed = read_estandarte_quipu(h, b)
    assert parsed['parent_txid'] is None
    assert len(parsed['types']) == len(types)
    assert len(parsed['conventions']) == len(conv)
    # Spot check the image dimensions roundtripped
    img = next(t for t in parsed['types'] if t['byte'] == 0x03)
    assert len(img['dimensions']) == 2
    assert img['dimensions'][0]['name'] == 'color'
    assert img['dimensions'][1]['name'] == 'bit_depth'
    assert len(img['dimensions'][1]['values']) == 8
    # Spot check encrypted dimensions
    enc = next(t for t in parsed['types'] if t['byte'] == 0x0e)
    assert [d['name'] for d in enc['dimensions']] == ['sub_family', 'variant']
    print(f"  ✓ roundtrip OK; image and encrypted dimensions preserved")
    print()


def _selftest_amendment():
    types, conv = _example_registry()
    fake_parent_txid = "ab" * 32
    h, b = build_estandarte_quipu(types, conv, parent_txid=fake_parent_txid)
    print(f"=== amendment with parent_txid ===")
    parsed = read_estandarte_quipu(h, b)
    assert parsed['parent_txid'] == fake_parent_txid
    print(f"  ✓ parent_txid roundtrips: {parsed['parent_txid'][:12]}…")
    print()


def _selftest_empty():
    h, b = build_estandarte_quipu([], [], tone=TONE_REVERENCE)
    parsed = read_estandarte_quipu(h, b)
    print(f"=== empty Estandarte (no types, no conventions, reverence tone) ===")
    assert parsed['tone'] == TONE_REVERENCE
    assert parsed['types'] == []
    assert parsed['conventions'] == []
    print(f"  ✓ empty registry roundtrips cleanly")
    print()


def _selftest_validation():
    cases = [
        ("invalid tone",
         lambda: build_estandarte_quipu([], [], tone=0x42),
         "tone"),
        ("invalid status",
         lambda: build_estandarte_quipu(
             [{'byte': 0, 'name': 'x', 'desc': '', 'status': 9,
               'dimensions': [], 'flags': []}], []),
         "status"),
        ("value out of range",
         lambda: build_estandarte_quipu(
             [{'byte': 0, 'name': 'x', 'desc': '', 'status': 0,
               'dimensions': [{'name': 'd', 'desc': '', 'values': [
                   {'value': 256, 'name': 'oops', 'desc': ''}]}],
               'flags': []}], []),
         "out of range"),
        ("flag bit out of range",
         lambda: build_estandarte_quipu(
             [{'byte': 0, 'name': 'x', 'desc': '', 'status': 0,
               'dimensions': [], 'flags': [{'bit': 9, 'name': 'oops', 'desc': ''}]}], []),
         "0..7"),
        ("parent_txid wrong length",
         lambda: build_estandarte_quipu([], [], parent_txid="ab" * 31),
         "64 hex"),
    ]
    print(f"=== validation ===")
    for desc, fn, want in cases:
        try:
            fn()
        except (ValueError, TypeError) as e:
            status = "OK" if want in str(e) else "WRONG ERR"
            print(f"  {desc:35s} -> {status}: {e}")
        else:
            print(f"  {desc:35s} -> DID NOT RAISE (bug)")
    print()


if __name__ == "__main__":
    _selftest_roundtrip()
    _selftest_amendment()
    _selftest_empty()
    _selftest_validation()
