"""
estandarte.py — Estandarte (type 0xee): the protocol's own registry.

Estandarte is the constitutional quipu that documents the Quipu Protocol's
own type-byte vocabulary. It is self-referential — type 0xee documents 0xee
itself among the other types — and is meant to be inscribed under the ACH
root — the 3-of-3 multisig of Anthony, Christophia, and Hayagriva, the
protocol's certificate authority — as the canonical protocol manifest. Every
other quipu marches under its banner.

Wire format
-----------

HEADER (6 bytes flat — the envelope, envelope.py):
    c1dd <version:u16-BE> ee <tone>
        version = 0x0000 constitution, 0x0001 v1
        0xee    = type byte (Estandarte)
        tone    = 0x00 ordinary, 0xee sovereign (the constitution),
                  0x0d demonic, 0xff reverence

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
            <dim_desc_len:1>  <dim_desc>   one-line description of what the field means
            <vkind:1>                      the dimension's wire atom (atoms.py;
                                           u8/u16/u32 legal here) — width stated as data
            <value_count:1>                count of named values in this dimension
            for each value:
                <value:width(vkind)>       big-endian at the atom's width
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

A "dimension" is an unsigned field within the type's header whose value
is drawn from a named enumeration; its wire width is its vkind atom's
width (u8 unless declared otherwise). Types may have zero, one, or many
dimensions:
    0x00 text       — zero dimensions (tone is a cross-type field)
    0x03 image      — two u8 dimensions: color, bit_depth
    0xcc cert       — one u16 dimension: subtype (big-endian, one 16-bit
                        dimension — the vkind states the width as data)
    0x0e encrypted  — two u8 dimensions: sub_family, variant
    0xce celestial  — three u8 dimensions: kind, grouped, meta

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
from envelope import build_envelope, parse_envelope, VERSION_CONSTITUTION, VERSION_V1
from atoms import ATOM_U8, ATOM_U16, UINT_ATOMS, fixed_width, atom_name
_VALID_TONES = VALID_TONES  # backward-compat alias

TYPE_ESTANDARTE = 0xEE

# Versions whose estandarte body this reader actually implements. A version
# outside this set is refused, not guessed (c1dd0002 §5 honest failure): the
# body format is identical across these today, but silently parsing a future
# version's body as this shape is exactly the mis-parse dispatch (v0.2) exists
# to prevent. Grow this set only when a version's body format is implemented.
KNOWN_ESTANDARTE_VERSIONS = frozenset({VERSION_CONSTITUTION, VERSION_V1})


def _len_prefixed(s):
    """Encode a UTF-8 string as <len:1><bytes>. Raise if > 255 bytes."""
    b = s.encode("utf-8")
    if len(b) > 255:
        raise ValueError(f"string too long ({len(b)} > 255 bytes): {s!r}")
    return bytes([len(b)]) + b


def build_estandarte_quipu(types, conventions, tone=TONE_ORDINARY, parent_txid=None,
                           version=VERSION_V1):
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
        version: protocol version stamped into the envelope (bytes 2..3,
            u16-BE). Defaults to v1; the constitution passes version 0. The
            body format is identical across versions at this skeleton stage.

    Returns:
        (header_bytes, body_bytes) tuple.
    """
    validate_tone(tone)
    if len(types) > 255:
        raise ValueError(f"max 255 type entries (got {len(types)})")
    if len(conventions) > 255:
        raise ValueError(f"max 255 conventions (got {len(conventions)})")
    # Registry keys must be unique within one blob: composition is keyed
    # leaf-wins ACROSS amendments; within-blob precedence is undefined, so
    # a duplicate here could only ever be a silent authoring error.
    seen_bytes = [t['byte'] for t in types]
    if len(set(seen_bytes)) != len(seen_bytes):
        dupes = sorted({b for b in seen_bytes if seen_bytes.count(b) > 1})
        raise ValueError(f"duplicate type byte(s) in one estandarte: {[hex(b) for b in dupes]}")
    seen_names = [c['name'] for c in conventions]
    if len(set(seen_names)) != len(seen_names):
        dupes = sorted({n for n in seen_names if seen_names.count(n) > 1})
        raise ValueError(f"duplicate convention name(s) in one estandarte: {dupes}")

    header = build_envelope(version, TYPE_ESTANDARTE, tone)

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
            vkind = dim.get('vkind', ATOM_U8)
            if vkind not in UINT_ATOMS:
                raise ValueError(
                    f"type {ti} dimension {di} vkind {atom_name(vkind)} not legal "
                    f"(dimensions range over unsigned atoms: u8/u16/u32)")
            width = fixed_width(vkind)
            body += _len_prefixed(dim['name'])
            body += _len_prefixed(dim['desc'])
            body += bytes([vkind])
            body += bytes([len(dim['values'])])
            for v in dim['values']:
                if not (0 <= v['value'] < 1 << (8 * width)):
                    raise ValueError(
                        f"type {ti} dim {di} value {v['value']!r} out of range "
                        f"for {atom_name(vkind)}")
                body += v['value'].to_bytes(width, 'big')
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
    """Parse an Estandarte (0xee) quipu's bytes.

    The envelope is parsed version-agnostically (magic c1dd + u16-BE
    version) so every version's estandarte — including the constitution
    (v0) — is readable; the version is returned for a dispatcher to act on.
    The body format is unchanged across versions at this skeleton stage.
    """
    version, type_byte, tone = parse_envelope(header_bytes)
    if type_byte != TYPE_ESTANDARTE:
        raise ValueError(
            f"not an Estandarte (type byte = {type_byte:#04x}, expected 0xee)"
        )
    if version not in KNOWN_ESTANDARTE_VERSIONS:
        raise ValueError(
            f"unknown estandarte version {version:#06x}; this reader implements "
            f"{sorted(KNOWN_ESTANDARTE_VERSIONS)} — refusing to guess a body it "
            f"does not know (version dispatch is v0.2 work)"
        )

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
        if status not in (0, 1, 2, 3):
            raise ValueError(
                f"type {type_byte:#04x} status {status:#04x} not in 0..3 — "
                f"status gates resolver behavior, an unknown value is malformed")
        dimensions = []
        dc = read_byte()
        for _ in range(dc):
            dim_name = read_str()
            dim_desc = read_str()
            vkind = read_byte()
            if vkind not in UINT_ATOMS:
                raise ValueError(
                    f"dimension {dim_name!r} vkind {vkind:#04x} not a legal "
                    f"dimension atom (u8/u16/u32) — width unknown, refusing to guess")
            width = fixed_width(vkind)
            vc = read_byte()
            values = []
            for _ in range(vc):
                v = int.from_bytes(read_raw(width), 'big')
                vn = read_str()
                vd = read_str()
                values.append({'value': v, 'name': vn, 'desc': vd})
            dimensions.append({'name': dim_name, 'desc': dim_desc,
                               'vkind': vkind, 'values': values})
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

    # Mirror the builder's key-uniqueness rule on the read side: leaf-wins
    # composition is defined ACROSS amendments only; a crafted blob with an
    # in-body duplicate would otherwise resolve silently last-wins.
    tb = [t['byte'] for t in types]
    if len(set(tb)) != len(tb):
        raise ValueError("duplicate type byte(s) within one estandarte body")
    cn = [c['name'] for c in conventions]
    if len(set(cn)) != len(cn):
        raise ValueError("duplicate convention name(s) within one estandarte body")

    return {
        'version': version,
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
        # Estandarte header is always exactly 6 bytes (c1dd <version:u16> ee <tone>)
        header = blob[:6]
        body   = blob[6:]
        parsed = read_estandarte_quipu(header, body)
        parsed['self_txid'] = current_txid
        chain.append(parsed)
        current_txid = parsed['parent_txid']

    # Reverse so root is index 0, leaf is last
    chain.reverse()
    # Healing discipline (docs/design/healing.md): within a chain the
    # version may only grow toward the leaf. Content heals in-version;
    # format changes bump the version — an amendment claiming an OLDER
    # version than its parent would be a later law rewriting an earlier
    # standard's past, and is refused.
    for i in range(1, len(chain)):
        if chain[i]['version'] < chain[i - 1]['version']:
            raise ValueError(
                f"version regression in amendment chain: "
                f"{chain[i]['self_txid'][:12]}… (v{chain[i]['version']}) amends "
                f"{chain[i - 1]['self_txid'][:12]}… (v{chain[i - 1]['version']})")
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
            'desc': 'audio container: a codec byte selects a quipu vocoder (STFT/LPC/Codec2), an opaque standard format (opus/mp3/wav/flac), or a composed-music recipe (music); body is encoded audio',
            'dimensions': [
                {'name': 'codec', 'desc': 'how the body bytes encode audio', 'values': [
                    {'value': 0x00, 'name': 'stft',   'desc': 'quipu STFT-magnitude vocoder (speech)'},
                    {'value': 0x01, 'name': 'lpc',    'desc': 'quipu LPC-10 vocoder (speech)'},
                    {'value': 0x02, 'name': 'codec2', 'desc': 'Codec2 (mode carried in codec_meta, default 3200; speech, needs libcodec2)'},
                    {'value': 0x10, 'name': 'opus',   'desc': 'opaque Ogg/Opus'},
                    {'value': 0x11, 'name': 'mp3',    'desc': 'opaque MP3'},
                    {'value': 0x12, 'name': 'wav',    'desc': 'opaque WAV/PCM'},
                    {'value': 0x13, 'name': 'flac',   'desc': 'opaque FLAC'},
                    {'value': 0x20, 'name': 'music',  'desc': 'composed-music recipe: synth + sampled + sliced instruments on a note timeline'},
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
            'desc': 'walkable 3D world: glTF-2.0-shaped JSON — nodes with transforms, quipu_ref extras, optional SLERP keyframe animations',
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
            'desc': 'certificate: hash-only, all-in-one, or sale offer; subtype is one 16-bit dimension',
            'dimensions': [
                {'name': 'subtype', 'desc': 'certificate subtype (big-endian; width stated by the vkind)',
                 'vkind': ATOM_U16, 'values': [
                    {'value': 0x0001, 'name': 'hash',       'desc': 'SHA256 hash of off-chain payload only'},
                    {'value': 0x0002, 'name': 'all-in-one', 'desc': 'full certificate body on chain'},
                    {'value': 0x0003, 'name': 'sale-offer', 'desc': 'verified-key sale offer: attestation fields + signers + ECDSA adaptor signatures'},
                ]},
            ],
            'flags': [],
        },
        {
            'byte': 0xce, 'name': 'celestial', 'status': STATUS_CANONICAL,
            'desc': 'sky or earth point figures, optionally grouped, optionally per-point meta',
            'dimensions': [
                # kinds 0x03 genealogy / 0x04 etymology exist only as
                # pre-canonical inscriptions + root-level code today; they
                # enter the law with the v2 celestial delta (c1dd0002 §7).
                # The pre-canonical convention covers the on-chain pair.
                {'name': 'kind', 'desc': 'figure coordinate frame; 0x02 = per-point frame byte opens each record', 'values': [
                    {'value': 0x00, 'name': 'earth', 'desc': 'lng/lat geographic coordinates'},
                    {'value': 0x01, 'name': 'star',  'desc': 'RA/Dec celestial-sphere coordinates'},
                    {'value': 0x02, 'name': 'mixed', 'desc': 'earth and star points in one figure; each point record opens with its own kind byte'},
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
            'syntax': 'c1 dd at offset 0; version u16-BE at bytes 2-3',
            'desc':   'c1 dd is the magic (Colegio Invisible / DD); bytes 2-3 are the '
                      'protocol version, big-endian u16 (0x0000 constitution, 0x0001 v1). The '
                      'version selects the standard; c1dd0001 is magic+version, not a 4-byte magic',
        },
        {
            'name':   'tone',
            'syntax': 'header byte 5',
            'desc':   'cross-type register, full set as declared here (amendments may add): 0x00 '
                      'ordinary; affective family 0x01-0x07 (affection, seeking, play, lust, rage, '
                      'fear, grief); 0x0d demonic; 0x6e nature; 0xa1 ai; 0xe5 hope; 0xee sovereign; '
                      '0xff reverence. Default 0x00',
        },
        {
            'name':   'diamond',
            'syntax': 'root (1 tx: N strand-seeding outputs, then any tags) -> N strands of <=80-byte OP_RETURN txs -> join (1 tx, N inputs)',
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
            'name':   'tag',
            'syntax': 'auxiliary root output; its spend carries no OP_RETURN',
            'desc':   'a root may carry outputs that seed no strand and are not consumed by '
                      'the join — the textile\'s future tense. The spend IS the event (an '
                      'act, not writing); body reassembly ignores tags, so tag-less readers '
                      'are unaffected',
        },
        {
            'name':   'ripcord',
            'syntax': 'legislation root (v1+): first non-strand output; spent only by the successor\'s root',
            'desc':   'the successor\'s root spends the cord (input 0): succession unique by '
                      'double-spend; parent_txid names the spent cord\'s root; v1 anchors to '
                      'the constitution by signed parent_txid (genesis claims its tag); a dead '
                      'cord falls back to the signed chain',
        },
        {
            'name':   'genesis',
            'syntax': 'constitution root: single tag (last output, N+2 anatomy); its spend = exactly 3 outputs, no OP_RETURN',
            'desc':   'fans the constitution\'s one tag into three ordinal ACH threads: despot, '
                      'amend, commentary. A spend carrying OP_RETURN would read as strand, so '
                      'the act is necessarily mute. Pulled once, ever; powers latent until pulled',
        },
        {
            'name':   'despot',
            'syntax': 'fan-out output 1; exercise = declaration quipu root spends tip + fresh tip; burn = no successor, value provably unspendable',
            'desc':   'override/supersede the constitution while alive — general power against '
                      'constitutional defect (healing repairs data, never law); declarations '
                      'bind in chain order; any successor-less spend ends the power; first to '
                      'burn, ending the founding era',
        },
        {
            'name':   'amend',
            'syntax': 'fan-out output 2; amendment quipu (c1dd0000ee) roots spend the tip',
            'desc':   'append to the constitution — additions only, never rewrites; scoped to '
                      'the constitution, not legislation (types and versions are the ripcord\'s '
                      'law); second to burn — the constitution is complete, legislation lives on',
        },
        {
            'name':   'commentary',
            'syntax': 'fan-out output 3; commentary quipu roots spend the tip',
            'desc':   'voice without power: notices, glosses, warnings from the authority; '
                      'never consulted for law; outlives both burns — in the eternal era it '
                      'is all that still moves',
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
    assert all(d['vkind'] == ATOM_U8 for d in enc['dimensions'])
    # Cert's subtype is the one 16-bit dimension — width stated as data (A12 fix)
    cert = next(t for t in parsed['types'] if t['byte'] == 0xcc)
    sub = cert['dimensions'][0]
    assert sub['vkind'] == ATOM_U16
    assert [v['value'] for v in sub['values']] == [0x0001, 0x0002, 0x0003]
    print(f"  ✓ roundtrip OK; dimensions preserved incl. cert's u16 vkind")
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
        ("duplicate type byte",
         lambda: build_estandarte_quipu(
             [{'byte': 0, 'name': 'a', 'desc': '', 'status': 0, 'dimensions': [], 'flags': []},
              {'byte': 0, 'name': 'b', 'desc': '', 'status': 0, 'dimensions': [], 'flags': []}], []),
         "duplicate type byte"),
        ("duplicate convention name",
         lambda: build_estandarte_quipu(
             [], [{'name': 'x', 'syntax': '', 'desc': ''},
                  {'name': 'x', 'syntax': '', 'desc': ''}]),
         "duplicate convention"),
    ]
    for desc, fn, want in cases:
        try:
            fn()
        except (ValueError, TypeError) as e:
            assert want in str(e), f"{desc}: wrong error {str(e)!r} (wanted {want!r})"
        else:
            raise AssertionError(f"{desc}: did not raise (builder validation regressed)")


if __name__ == "__main__":
    _selftest_roundtrip()
    _selftest_amendment()
    _selftest_empty()
    _selftest_validation()
