"""Quipu type 0x09 — Book.

A book is an ordered list of typed-and-named references to other quipus.
Free-form tag namespace, recursive (a book can reference other books, so
the same type serves as a library), polymorphic (entries point to any
quipu type).

See docs/quipu-types/book.md for the canonical spec.
"""
from __future__ import annotations

import re
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from text import _FIELD_VALIDATORS
from tone import (
    TONES, VALID_TONES, validate_tone,
    TONE_ORDINARY, TONE_AFFECTION, TONE_DEMONIC, TONE_AI, TONE_REVERENCE,
)
_VALID_TONES = VALID_TONES  # backward-compat alias

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TYPE_BOOK      = 0x09
PROTOCOL_MAGIC = b"\xc1\xdd\x00\x01"

BODY_VERSION   = 0x01            # current book body schema version

MAX_ENTRIES    = 0xFFFF          # uint16 entry count
MAX_TAG_LEN    = 0xFF            # uint8 tag length
MAX_NAME_LEN   = 0xFF            # uint8 name length

_TXID_HEX_RE   = re.compile(r"^[0-9a-fA-F]{64}$")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _coerce_txid(ref):
    """Accept either raw 32 bytes or a 64-char hex string; return raw bytes.

    Two special cases allow pipeline-emitted manifest entries (e.g. the
    `tag: index` Reference Index) to carry no real inscription target:

      * ``None`` → 32 zero bytes
      * ``""``   → 32 zero bytes

    The pipeline's ``_partition_entries`` recognises these tags and
    generates the entry's content rather than fetching the ref_txid; for
    those entries the txid is structural padding only. The all-zero txid
    is unambiguous as a sentinel (no real inscription will ever produce
    it), and any reader that mistakenly tries to fetch it will correctly
    get "no such inscription" rather than silently reading the wrong one.
    """
    if ref is None or ref == "":
        return b"\x00" * 32
    if isinstance(ref, (bytes, bytearray)):
        if len(ref) != 32:
            raise ValueError(
                f"ref_txid raw bytes must be exactly 32 (got {len(ref)})"
            )
        return bytes(ref)
    if isinstance(ref, str):
        if not _TXID_HEX_RE.match(ref):
            raise ValueError(
                f"ref_txid hex string must be exactly 64 hex chars "
                f"(got {len(ref)})"
            )
        return bytes.fromhex(ref)
    raise TypeError(
        f"ref_txid must be bytes (32) or hex str (64); got {type(ref).__name__}"
    )


def _validate_header_inputs(title, fields):
    """Run text-type header validation rules. Returns sanitized fields dict."""
    if not isinstance(title, str):
        raise TypeError(f"title must be str, got {type(title).__name__}")
    if "|" in title:
        raise ValueError("title contains '|' (field separator)")
    if "=" in title:
        raise ValueError("title contains '=' (would parse as key=value)")

    fields = dict(fields) if fields else {}
    seen = set()
    for k, v in fields.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise TypeError(f"field {k!r}={v!r}: keys and values must be str")
        if "|" in k or "|" in v:
            raise ValueError(f"field {k!r}: '|' forbidden")
        if "=" in k:
            raise ValueError(f"field key {k!r} contains '='")
        if k in seen:
            raise ValueError(f"duplicate field key {k!r}")
        seen.add(k)
        if k in _FIELD_VALIDATORS:
            _FIELD_VALIDATORS[k](v)
    return fields


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_book_quipu(title, entries, tone=TONE_ORDINARY, fields=None):
    """Build a 0x09 book quipu's (header_bytes, body_bytes) pair.

    See docstring in docs/quipu-types/book.md for the byte layout.
    """
    validate_tone(tone)
    fields = _validate_header_inputs(title, fields)

    if not isinstance(entries, (list, tuple)):
        raise TypeError(f"entries must be list/tuple, got {type(entries).__name__}")
    if len(entries) > MAX_ENTRIES:
        raise ValueError(f"too many entries: {len(entries)} > {MAX_ENTRIES}")

    # ---- body ----
    out = bytearray()
    out.append(BODY_VERSION)
    out += struct.pack(">H", len(entries))

    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise TypeError(f"entry[{i}] must be dict, got {type(entry).__name__}")
        try:
            ref_raw = _coerce_txid(entry["ref_txid"])
            tag     = entry["tag"]
            name    = entry["name"]
        except KeyError as e:
            raise ValueError(f"entry[{i}] missing required key: {e}")

        if not isinstance(tag, str):
            raise TypeError(f"entry[{i}].tag must be str, got {type(tag).__name__}")
        if not isinstance(name, str):
            raise TypeError(f"entry[{i}].name must be str, got {type(name).__name__}")

        tag_b  = tag.encode("utf-8")
        name_b = name.encode("utf-8")
        if len(tag_b) > MAX_TAG_LEN:
            raise ValueError(
                f"entry[{i}].tag: {len(tag_b)} utf-8 bytes > {MAX_TAG_LEN}"
            )
        if len(name_b) > MAX_NAME_LEN:
            raise ValueError(
                f"entry[{i}].name: {len(name_b)} utf-8 bytes > {MAX_NAME_LEN}"
            )

        out += ref_raw
        out.append(len(tag_b))
        out += tag_b
        out.append(len(name_b))
        out += name_b

    # ---- header ----
    header = PROTOCOL_MAGIC + bytes([TYPE_BOOK, tone])
    if title or fields:
        parts = [title] + [f"{k}={v}" for k, v in fields.items()]
        header += b"|" + "|".join(parts).encode("utf-8") + b"|"

    return header, bytes(out)


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------

def read_book_quipu(header_bytes, body_bytes):
    """Parse a 0x09 book quipu's bytes into structured form.

    Returns dict with keys: title, tone, fields, version, entries.
    Each entry: {'ref_txid': 64-hex lowercase, 'tag': str, 'name': str}.
    """
    if header_bytes[:4] != PROTOCOL_MAGIC:
        raise ValueError("not a quipu (c1dd0001 magic missing)")
    if len(header_bytes) < 6:
        raise ValueError(f"header too short: {len(header_bytes)} < 6")
    if header_bytes[4] != TYPE_BOOK:
        raise ValueError(
            f"not a book (type byte = {header_bytes[4]:#04x}, expected 0x09)"
        )

    tone = header_bytes[5]
    tail = header_bytes[6:].rstrip(b"\x00 ")
    title  = ""
    fields = {}
    if tail:
        text = tail.decode("utf-8", errors="replace")
        parts = [p for p in text.split("|") if p != ""] if "|" in text else [text]
        for i, part in enumerate(parts):
            if i == 0 and "=" not in part:
                title = part
            elif "=" in part:
                k, v = part.split("=", 1)
                fields[k.strip()] = v.strip()

    body = bytes(body_bytes)
    if len(body) < 3:
        raise ValueError(f"body too short: {len(body)} < 3 (version + entry_count)")

    version = body[0]
    if version != BODY_VERSION:
        raise ValueError(
            f"book body version {version:#04x} not implemented (this reader "
            f"knows {BODY_VERSION:#04x}) — refusing to guess a layout it "
            f"does not know")
    entry_count = struct.unpack(">H", body[1:3])[0]
    pos = 3
    entries = []
    for i in range(entry_count):
        if pos + 32 + 1 > len(body):
            raise ValueError(f"entry[{i}]: body truncated at ref/tag_len")
        ref_raw = body[pos:pos + 32]
        pos += 32
        tag_len = body[pos]
        pos += 1
        if pos + tag_len + 1 > len(body):
            raise ValueError(f"entry[{i}]: body truncated at tag/name_len")
        try:
            tag = body[pos:pos + tag_len].decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError(f"entry[{i}].tag: utf-8 decode failed: {e}")
        pos += tag_len
        name_len = body[pos]
        pos += 1
        if pos + name_len > len(body):
            raise ValueError(f"entry[{i}]: body truncated at name")
        try:
            name = body[pos:pos + name_len].decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError(f"entry[{i}].name: utf-8 decode failed: {e}")
        pos += name_len
        entries.append({
            "ref_txid": ref_raw.hex(),
            "tag":      tag,
            "name":     name,
        })

    if pos != len(body):
        raise ValueError(
            f"trailing {len(body) - pos} bytes after {entry_count} entries"
        )

    return {
        "title":   title,
        "tone":    tone,
        "fields":  fields,
        "version": version,
        "entries": entries,
    }


# ---------------------------------------------------------------------------
# Convenience accessors
# ---------------------------------------------------------------------------

def _suffix_sort_key(tag):
    """Sort key that orders 'prefix/NN' numerically when NN parses as int."""
    if "/" in tag:
        prefix, suffix = tag.rsplit("/", 1)
        try:
            return (prefix, 0, int(suffix))
        except ValueError:
            return (prefix, 1, suffix)
    return (tag, 0, 0)


def book_entries_by_tag(parsed, tag):
    """Entries whose tag equals `tag` exactly. Inscribed order preserved."""
    return [e for e in parsed["entries"] if e["tag"] == tag]


def book_entries_by_prefix(parsed, prefix):
    """Entries whose tag starts with `prefix`, sorted by numeric suffix when
    `prefix` ends in '/' and the suffix parses as int."""
    matches = [e for e in parsed["entries"] if e["tag"].startswith(prefix)]
    if prefix.endswith("/"):
        matches = sorted(matches, key=lambda e: _suffix_sort_key(e["tag"]))
    return matches


def book_single(parsed, tag):
    """Return the single entry with this tag, or None.

    If multiple entries share this tag, returns the first; the caller may
    inspect book_entries_by_tag to detect that case.
    """
    matches = book_entries_by_tag(parsed, tag)
    if not matches:
        return None
    return matches[0]


def book_essays(parsed):
    """Shortcut: book_entries_by_prefix(parsed, 'essay/'), numerically sorted."""
    return book_entries_by_prefix(parsed, "essay/")


def book_subbooks(parsed):
    """Shortcut: book_entries_by_prefix(parsed, 'volume/') plus tag='subbook'."""
    return (
        book_entries_by_prefix(parsed, "volume/")
        + book_entries_by_tag(parsed, "subbook")
    )


# ---------------------------------------------------------------------------
# Recursive walker
# ---------------------------------------------------------------------------

_SUBBOOK_TAGS = ("volume/", "subbook")


def _is_subbook_tag(tag):
    return tag == "subbook" or tag.startswith("volume/")


def walk_book_tree(parsed, fetcher, max_depth=8, visited=None, _depth=0):
    """Recursively descend into sub-books, returning a nested structure.

    Each entry whose tag identifies a sub-book gets a 'children' key holding
    either the recursively-walked sub-tree, or a sentinel dict explaining
    why the walk stopped.
    """
    if visited is None:
        visited = set()
    out = dict(parsed)
    out["entries"] = []
    for entry in parsed["entries"]:
        e2 = dict(entry)
        if _is_subbook_tag(entry["tag"]):
            txid = entry["ref_txid"].lower()
            if _depth >= max_depth:
                e2["children"] = {"truncated": True, "reason": "depth-limit"}
            elif txid in visited:
                e2["children"] = {"truncated": True, "reason": "cycle"}
            else:
                visited_next = visited | {txid}
                try:
                    blob = fetcher(txid)
                    if isinstance(blob, str):
                        blob = bytes.fromhex(blob.strip())
                    header, body = blob[:6], blob[6:]
                    # Re-extract header tail if present
                    pipe_end = blob.find(b"|", 6)
                    if pipe_end >= 0:
                        # Find end of header (matching algorithm in inscriber)
                        # Header ends at the last '|' before body begins.
                        # Books inscribe header as `magic|type|tone|...|`, so
                        # the header tail terminates with a trailing '|'.
                        # We don't actually need to split header/body here —
                        # read_book_quipu accepts the full bytes when split.
                        pass
                    child = read_book_quipu(blob[:_find_body_start(blob)],
                                            blob[_find_body_start(blob):])
                    e2["children"] = walk_book_tree(
                        child, fetcher, max_depth=max_depth,
                        visited=visited_next, _depth=_depth + 1,
                    )
                except Exception as exc:
                    e2["children"] = {"error": f"{type(exc).__name__}: {exc}"}
        out["entries"].append(e2)
    return out


def _find_body_start(blob):
    """Find where the header ends and body begins in a book inscription.

    Books have a 6-byte fixed prefix; if a pipe-delimited header tail is
    present, it ends at the last '|' before the body's version byte (0x01).
    """
    if len(blob) < 6:
        raise ValueError(f"blob too short: {len(blob)}")
    if blob[4] != TYPE_BOOK:
        raise ValueError(
            f"not a book inscription (type byte = {blob[4]:#04x})"
        )
    # If no header-tail pipe immediately after the 6-byte prefix, body starts at 6.
    if len(blob) <= 6 or blob[6] != ord("|"):
        return 6
    # Walk forward to find the matching closing pipe; body starts after it.
    # Header tail is `|field|field|...|`. The closing '|' is followed by the
    # body's version byte (0x01).
    pos = 6
    while True:
        nxt = blob.find(b"|", pos + 1)
        if nxt < 0:
            raise ValueError("malformed header tail: no closing '|'")
        # Body starts immediately after this pipe. Sanity-check by looking
        # for the version byte.
        if nxt + 1 < len(blob) and blob[nxt + 1] == BODY_VERSION:
            return nxt + 1
        pos = nxt


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _selftest_roundtrip():
    entries = [
        {"ref_txid": "a" * 64, "tag": "binding",  "name": "Volume I bindings"},
        {"ref_txid": "b" * 64, "tag": "prologo",  "name": "Prólogo by Los editores"},
        {"ref_txid": "c" * 64, "tag": "cover",    "name": "Bordado Hayagriva (Maier)"},
        {"ref_txid": "d" * 64, "tag": "essay/01", "name": "Arthur Ben"},
        {"ref_txid": "e" * 64, "tag": "essay/02", "name": "Anubis"},
        {"ref_txid": "f" * 64, "tag": "credits",  "name": "Créditos"},
    ]
    h, b = build_book_quipu(
        "Bordado, Volume I",
        entries,
        tone=TONE_ORDINARY,
        fields={
            "author":    "El Ermitaño",
            "date":      "2025-11-15",
            "lang":      "es",
            "series":    "Bordado",
            "book":      "I",
            "year":      "2025",
            "publisher": "Mochuelo Libros",
        },
    )
    parsed = read_book_quipu(h, b)
    print("=== build / read roundtrip ===")
    print(f"  header ({len(h)} B): {h.hex()[:80]}…")
    print(f"  body ({len(b)} B), version=0x{parsed['version']:02x}, entries={len(parsed['entries'])}")
    assert parsed["title"]   == "Bordado, Volume I"
    assert parsed["tone"]    == TONE_ORDINARY
    assert parsed["version"] == BODY_VERSION
    assert parsed["fields"]["author"] == "El Ermitaño"
    assert parsed["fields"]["series"] == "Bordado"
    assert len(parsed["entries"]) == 6
    for got, want in zip(parsed["entries"], entries):
        assert got["ref_txid"] == want["ref_txid"]
        assert got["tag"]      == want["tag"]
        assert got["name"]     == want["name"]
    print("  ✓ header + body roundtrip cleanly")
    print()


def _selftest_accessors():
    entries = [
        {"ref_txid": "1" * 64, "tag": "binding",   "name": "b1"},
        {"ref_txid": "2" * 64, "tag": "essay/01",  "name": "e1"},
        {"ref_txid": "3" * 64, "tag": "essay/02",  "name": "e2"},
        {"ref_txid": "4" * 64, "tag": "essay/10",  "name": "e10"},
        {"ref_txid": "5" * 64, "tag": "prologo",   "name": "p"},
        {"ref_txid": "6" * 64, "tag": "binding",   "name": "b2"},
    ]
    parsed = {"entries": entries}
    print("=== convenience accessors ===")

    e_by_tag = book_entries_by_tag(parsed, "binding")
    assert [e["name"] for e in e_by_tag] == ["b1", "b2"]
    print(f"  by_tag('binding') -> {[e['name'] for e in e_by_tag]}")

    e_essays = book_essays(parsed)
    # Numeric sort: 01, 02, 10
    assert [e["tag"] for e in e_essays] == ["essay/01", "essay/02", "essay/10"]
    print(f"  essays (numeric-sorted) -> {[e['tag'] for e in e_essays]}")

    one = book_single(parsed, "prologo")
    assert one["name"] == "p"
    none = book_single(parsed, "nope")
    assert none is None
    print(f"  single('prologo') -> {one['name']}, single('nope') -> {none}")
    print("  ✓ accessors return ordered, numeric-sorted, single-or-None results")
    print()


def _selftest_validation():
    good_entry = {"ref_txid": "a" * 64, "tag": "x", "name": "y"}
    cases = [
        ("title with pipe",  lambda: build_book_quipu("a|b", []), "field separator"),
        ("title with equals",lambda: build_book_quipu("a=b", []), "key=value"),
        ("invalid tone",     lambda: build_book_quipu("t", [], tone=0x42), "tone"),
        ("bad date",         lambda: build_book_quipu("t", [], fields={"date": "yesterday"}), "ISO 8601"),
        ("bad lang",         lambda: build_book_quipu("t", [], fields={"lang": "Spanish"}), "BCP 47"),
        ("ref bad length",   lambda: build_book_quipu("t", [{"ref_txid": "aa", "tag": "x", "name": "y"}]), "64 hex"),
        ("tag too long",     lambda: build_book_quipu("t", [{"ref_txid": "a"*64, "tag": "x" * 300, "name": "y"}]), "> 255"),
        ("missing key",      lambda: build_book_quipu("t", [{"ref_txid": "a"*64, "tag": "x"}]), "missing required key"),
    ]
    print("=== validation ===")
    for desc, fn, want in cases:
        try:
            fn()
            print(f"  {desc:20s} -> DID NOT RAISE")
        except (ValueError, TypeError) as e:
            status = "OK" if want in str(e) else "WRONG ERR"
            print(f"  {desc:20s} -> {status}: {e}")
    print()


def _selftest_recursive():
    """walk_book_tree handles depth limits and cycles correctly."""
    # Library -> Volume I -> Volume I (self-cycle)
    vol1_self_cycle_txid = "1" * 64
    library_txid         = "2" * 64

    vol1_entries = [
        {"ref_txid": "a" * 64, "tag": "essay/01", "name": "Essay One"},
        {"ref_txid": vol1_self_cycle_txid, "tag": "volume/02",
         "name": "(cycles back)"},
    ]
    vol1_h, vol1_b = build_book_quipu("Vol I", vol1_entries)
    vol1_blob = vol1_h + vol1_b

    lib_entries = [
        {"ref_txid": vol1_self_cycle_txid, "tag": "volume/01", "name": "Vol I"},
    ]
    lib_h, lib_b = build_book_quipu("Library", lib_entries)
    lib_blob = lib_h + lib_b

    blobs = {vol1_self_cycle_txid: vol1_blob, library_txid: lib_blob}
    def fetcher(t):
        return blobs[t.lower()]

    library = read_book_quipu(lib_h, lib_b)
    walked = walk_book_tree(library, fetcher, max_depth=4)
    print("=== walk_book_tree (cycle + depth) ===")
    vol1_walked = walked["entries"][0]
    assert vol1_walked["tag"] == "volume/01"
    assert "children" in vol1_walked
    # Vol I's own sub-entry should hit either depth limit or cycle
    inner = vol1_walked["children"]["entries"][1]
    assert "children" in inner
    assert inner["children"]["truncated"] is True
    print(f"  inner truncation reason: {inner['children']['reason']}")
    print("  ✓ recursion terminates at cycle / depth limit")
    print()


def _selftest_worked_example():
    """Build the docs/quipu-types/book.md worked example (Bordado Vol I)
    and verify entries deserialize identically."""
    entries = [
        ("binding",  "Volume I bindings"),
        ("prologo",  "Prólogo by Los editores"),
        ("cover",    "Bordado Hayagriva (Maier)"),
        ("art/01",   "Teatrito Rioplatense de Entidades (Veroni)"),
        ("essay/01", "Arthur Ben"),
        ("essay/02", "Anubis"),
        ("essay/03", "Hayagriva"),
        ("essay/04", "El caballo y la rueda"),
        ("essay/05", "San Cristóbal"),
        ("essay/06", "Nudos hebraicos"),
        ("essay/07", "Sombrero judío"),
        ("essay/08", "Hornero"),
        ("essay/09", "Goethe en el volcán"),
        ("essay/10", "Ganas"),
        ("essay/11", "El anillo"),
        ("essay/12", "Escritura nocturna"),
        ("credits",  "Créditos"),
    ]
    txids = [bytes([i + 1]) * 32 for i in range(len(entries))]
    entry_dicts = [
        {"ref_txid": tx, "tag": tag, "name": name}
        for tx, (tag, name) in zip(txids, entries)
    ]
    h, b = build_book_quipu(
        "Bordado, Volume I", entry_dicts,
        fields={"author": "El Ermitaño", "date": "2025-11-15", "lang": "es",
                "series": "Bordado", "book": "I", "year": "2025",
                "publisher": "Mochuelo Libros"},
    )
    parsed = read_book_quipu(h, b)
    print("=== worked example (Bordado Vol I) ===")
    print(f"  header ({len(h)} B), body ({len(b)} B), {len(parsed['entries'])} entries")
    for got, want in zip(parsed["entries"], entries):
        assert got["tag"]  == want[0]
        assert got["name"] == want[1]
    essays = book_essays(parsed)
    assert len(essays) == 12
    assert essays[0]["name"]  == "Arthur Ben"
    assert essays[-1]["name"] == "Escritura nocturna"
    print("  ✓ 17 entries, 12 essays in numeric order")
    print()


if __name__ == "__main__":
    _selftest_roundtrip()
    _selftest_accessors()
    _selftest_validation()
    _selftest_recursive()
    _selftest_worked_example()
    print("all book self-tests passed.")
