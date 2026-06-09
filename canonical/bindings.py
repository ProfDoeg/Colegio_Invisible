"""
bindings.py — 0xab binding (abecedario) quipu type.

A binding is a small text-format document defining three kinds of rule:

  - alias chains:    <<A>>=<<B>>=<<C>>=<<target>>
  - substitutions:   "search"="replace"
  - imports:         <<txid_of_another_binding>>

Bindings provide name resolution for essays and other bindings. The
evaluator walks imports depth-first with a visited-set memo cache and
value-semantics on every dict crossing a scope boundary, so cycles
terminate naturally and diamond imports are evaluated once.

See docs/quipu-types/bindings.md for the full byte layout and
evaluation semantics.

Body format
-----------

    c1dd 0001 ab TT
    <body bytes — pure UTF-8, line-oriented>

Each line is one of:
    <<txid>>                            an import (must be lone on the line)
    <<A>>=<<B>>=...=<<target>>          alias / alias-chain assignment
    "str1"="str2"                       string substitution
    anything else                       comment (ignored)
"""

from __future__ import annotations

import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

MAGIC = b"\xc1\xdd\x00\x01"
TYPE_BINDING = 0xAB

from tone import (
    TONES, VALID_TONES, validate_tone,
    TONE_ORDINARY, TONE_AFFECTION, TONE_DEMONIC, TONE_AI, TONE_REVERENCE,
)
_VALID_TONES = VALID_TONES  # backward-compat alias

ALIAS_DEPTH_LIMIT  = 8   # max alias-chain hops at resolution time
IMPORT_DEPTH_LIMIT = 64  # safety net; cycles are caught earlier by visited set


# ---------------------------------------------------------------------------
# Line parsing
# ---------------------------------------------------------------------------

_TXID_RE        = re.compile(r"^[0-9a-fA-F]{64}$")
_CITATION_RE    = re.compile(r"<<\s*(.+?)\s*>>")
_IMPORT_LINE_RE = re.compile(r"^\s*<<\s*([0-9a-fA-F]{64})\s*>>\s*$")
_SUBST_LINE_RE  = re.compile(r'^\s*"([^"]*)"\s*=\s*"([^"]*)"\s*$')
_FLAG_TAIL_RE   = re.compile(r"\s+@([\w-]+)\s*$")
_POS_TAIL_RE    = re.compile(r"\s+#(\d+)\s*$")
_ANNOTATION_OPEN_RE  = re.compile(r"^@@(\S.*?)\s*$")
_ANNOTATION_CLOSE_RE = re.compile(r"^@@\s*$")

KNOWN_FLAGS = frozenset((
    "all", "once-per-doc",          # disambiguation
    "margin", "endnote", "inline",  # annotation presentation hints
))


def _split_flags(line):
    """Split trailing '@flag' tokens off a line.
    Returns (line_without_flags, frozenset_of_flag_names)."""
    flags = []
    while True:
        m = _FLAG_TAIL_RE.search(line)
        if not m:
            break
        flags.insert(0, m.group(1))
        line = line[:m.start()].rstrip()
    return line, frozenset(flags)


def _parse_chain(line):
    """Parse a chain expression `node = node = ...` into a list of
    (kind, value) where kind is 'string' (for `"..."`) or 'bracket'
    (for `<<...>>`). Returns None if the line is not a clean chain."""
    nodes = []
    pos = 0
    n = len(line)
    expecting_node = True
    while pos < n:
        while pos < n and line[pos].isspace():
            pos += 1
        if pos >= n:
            break
        if expecting_node:
            if line[pos] == '"':
                end = line.find('"', pos + 1)
                if end < 0:
                    return None
                nodes.append(("string", line[pos + 1:end]))
                pos = end + 1
            elif line[pos:pos + 2] == "<<":
                end = line.find(">>", pos + 2)
                if end < 0:
                    return None
                nodes.append(("bracket", line[pos + 2:end].strip()))
                pos = end + 2
            else:
                return None
            expecting_node = False
        else:
            if line[pos] == "=":
                pos += 1
                expecting_node = True
            else:
                return None
    if expecting_node:
        return None  # dangling '='
    return nodes


def parse_line(raw):
    """Parse a single binding body line. Returns a tuple whose first
    element is the line kind:

        ('import',        txid_hex)
        ('alias',         [name1, name2, ...], target)    target may be a name or a 64-hex txid
        ('substitution',  search_str, replace_str)
        ('citation',      [trigger1, trigger2, ...], txid_target, frozenset_flags)
        ('comment',       raw_str)
    """
    line = raw.strip()
    if not line:
        return ("comment", raw)

    # Standalone import: a single <<txid>> citation, nothing else on the line
    m = _IMPORT_LINE_RE.match(line)
    if m:
        return ("import", m.group(1).lower())

    # v1 substitution: pure "search"="replace" (no flags, exact two strings)
    m = _SUBST_LINE_RE.match(line)
    if m:
        return ("substitution", m.group(1), m.group(2))

    # Strip trailing @flag tokens before generalized chain parsing
    body_line, flags = _split_flags(line)

    if "=" in body_line:
        nodes = _parse_chain(body_line)
        if nodes is not None and len(nodes) >= 2:
            kinds = [k for k, _ in nodes]
            term_kind, term_val = nodes[-1]

            # v1 alias chain: every node is `<<...>>`, no flags
            if all(k == "bracket" for k in kinds) and not flags:
                names = [v for _, v in nodes[:-1]]
                return ("alias", names, term_val)

            # v2 citation chain: at least one string-node, terminus is `<<64-hex txid>>`
            if term_kind == "bracket" and _TXID_RE.match(term_val):
                string_triggers = [v for k, v in nodes[:-1] if k == "string"]
                if string_triggers:
                    return ("citation", string_triggers, term_val.lower(), flags)

    return ("comment", raw)


def _parse_annotation_header(header_after_at_at):
    """Parse the text after `@@` on an annotation's opening line.

    Returns (anchor_str, position_or_None, flags_frozenset).
    Strips trailing `@flag` tokens and an optional `#N` positional
    suffix; whatever remains is the anchor.
    """
    line = header_after_at_at.rstrip()
    # Strip trailing @flag tokens (any number, any order)
    flags = []
    while True:
        m = _FLAG_TAIL_RE.search(line)
        if not m:
            break
        flags.insert(0, m.group(1))
        line = line[:m.start()].rstrip()
    # Strip an optional #N positional suffix
    position = None
    m = _POS_TAIL_RE.search(line)
    if m:
        position = int(m.group(1))
        line = line[:m.start()].rstrip()
    anchor = line.strip()
    return anchor, position, frozenset(flags)


def parse_body(body_text):
    """Parse a binding's body text into an ordered list of line tuples.

    Handles two kinds of structure:
      - Line-oriented entries (import, alias, substitution, citation,
        comment) — one tuple per source line via `parse_line`.
      - Multi-line annotation blocks fenced by `@@anchor [flags]` …
        `@@` — consumed together and emitted as a single tuple
        `('annotation', anchor, note_md, position_or_None, flags)`.

    If an annotation open fence has no matching close fence by EOF,
    the open line falls back to a comment and the following lines
    are parsed line-by-line as normal.
    """
    lines = body_text.splitlines()
    out = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = _ANNOTATION_OPEN_RE.match(line)
        if m and not _ANNOTATION_CLOSE_RE.match(line):
            # Potential annotation open; look ahead for a closing fence
            anchor, position, flags = _parse_annotation_header(m.group(1))
            note_start = i + 1
            j = note_start
            while j < n and not _ANNOTATION_CLOSE_RE.match(lines[j]):
                j += 1
            if j < n and anchor:
                # Found valid close; emit annotation
                note_md = "\n".join(lines[note_start:j]).strip("\n")
                out.append(("annotation", anchor, note_md, position, flags))
                i = j + 1
                continue
            # No close, or empty anchor — fall through to per-line parsing
        out.append(parse_line(line))
        i += 1
    return out


# ---------------------------------------------------------------------------
# Build / read
# ---------------------------------------------------------------------------

def build_binding_quipu(body_text, tone=TONE_ORDINARY):
    """Build a 0xab binding quipu.

    Args:
        body_text: UTF-8 text containing imports, aliases, and substitutions
        tone:      TONE_ORDINARY (0x00), TONE_DEMONIC (0x0d), or TONE_REVERENCE (0xff)

    Returns:
        (header_bytes, body_bytes) — same shape as other canonical types
    """
    validate_tone(tone)
    if not isinstance(body_text, str):
        raise TypeError(f"body_text must be str (got {type(body_text).__name__})")
    header = MAGIC + bytes([TYPE_BINDING, tone])
    body = body_text.encode("utf-8")
    return header, body


def read_binding_quipu(header_bytes, body_bytes):
    """Parse a 0xab binding's bytes into a structured form.

    Returns:
        {
          'tone':  int,
          'body':  str (full UTF-8 body),
          'lines': list of (kind, ...) tuples from parse_line,
        }
    """
    if header_bytes[:4] != MAGIC:
        raise ValueError("not a quipu (c1dd0001 magic missing)")
    if len(header_bytes) < 6:
        raise ValueError(f"header too short: {len(header_bytes)} (need >= 6)")
    if header_bytes[4] != TYPE_BINDING:
        raise ValueError(
            f"not a binding (type byte = {header_bytes[4]:#04x}, expected 0xab)"
        )
    tone = header_bytes[5]
    body_text = bytes(body_bytes).decode("utf-8", errors="replace")
    return {
        "tone":  tone,
        "body":  body_text,
        "lines": parse_body(body_text),
    }


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

class BindingDict:
    """The dict-as-result of evaluating a binding.

    Holds four pieces of state:
      - aliases:       {name -> target_str}  (target is alias name or txid hex)
      - substitutions: [(search, replace), ...]  ordered, applied at render time
      - citations:     [(triggers_tuple, txid_target, flags_frozenset), ...]
                       v2 chain rules — each entry is one equivalence class
      - annotations:   [(anchor, note_md, position_or_None, flags_frozenset), ...]
                       v3 anchored multi-paragraph commentary. Accumulate
                       across imports (do NOT last-write-wins — multiple
                       annotators may gloss the same anchor with distinct
                       notes).

    Last-write-wins on alias name. Substitutions, citations, and
    annotations accumulate in order.
    """
    __slots__ = ("aliases", "substitutions", "citations", "annotations")

    def __init__(self, aliases=None, substitutions=None, citations=None,
                 annotations=None):
        self.aliases       = dict(aliases) if aliases else {}
        self.substitutions = list(substitutions) if substitutions else []
        self.citations     = list(citations) if citations else []
        self.annotations   = list(annotations) if annotations else []

    def copy(self):
        return BindingDict(self.aliases, self.substitutions,
                            self.citations, self.annotations)

    def merge(self, other):
        """Merge another BindingDict into this one. Aliases follow
        last-write-wins; substitutions, citations, and annotations
        accumulate in order."""
        for k, v in other.aliases.items():
            self.aliases[k] = v
        self.substitutions.extend(other.substitutions)
        self.citations.extend(other.citations)
        self.annotations.extend(other.annotations)

    def __repr__(self):
        return (
            f"BindingDict(aliases={len(self.aliases)}, "
            f"substitutions={len(self.substitutions)}, "
            f"citations={len(self.citations)}, "
            f"annotations={len(self.annotations)})"
        )


def evaluate(binding_txid, fetcher, *, p_pristine=None, visited=None,
             _depth=0):
    """Evaluate a binding quipu, returning its final BindingDict.

    Args:
        binding_txid: hex string of the binding's root txid (or any unique
                      identifier the fetcher accepts).
        fetcher:      callable(txid_hex) -> bytes  (concatenated header+body
                      of any quipu).
        p_pristine:   BindingDict — the dict-as-passed-from-parent. Defaults
                      to an empty BindingDict for the top-level call.
        visited:      dict mapping txid -> BindingDict (memo cache).
                      Shared across the whole essay-compile pass. Defaults
                      to a fresh empty dict.

    Returns:
        BindingDict — a COPY of the cached or freshly-evaluated result.
        Callers can mutate the returned dict freely; the cache is unaffected.
    """
    if p_pristine is None:
        p_pristine = BindingDict()
    if visited is None:
        visited = {}
    if _depth > IMPORT_DEPTH_LIMIT:
        raise RecursionError(f"import depth exceeds {IMPORT_DEPTH_LIMIT}")

    txid = binding_txid.lower()
    if txid in visited:
        # Cache hit (or cycle re-entry): return a COPY of the cached dict.
        # If we re-entered while still evaluating this binding, the cached
        # value is the empty placeholder set below — which terminates the
        # recursion cleanly without contributing anything.
        return visited[txid].copy()

    # Placeholder for cycle break: if any descendant of this binding re-enters
    # the same txid, it'll see this empty dict and return immediately.
    visited[txid] = BindingDict()

    blob = fetcher(txid)
    if isinstance(blob, str):
        blob = bytes.fromhex(blob.strip())

    if blob[:4] != MAGIC or blob[4] != TYPE_BINDING:
        raise ValueError(
            f"txid {txid[:12]}... is not a 0xab binding "
            f"(type byte = {blob[4]:#04x})"
        )

    header = blob[:6]
    body   = blob[6:]
    parsed = read_binding_quipu(header, body)
    p_render = p_pristine.copy()

    for line in parsed["lines"]:
        kind = line[0]
        if kind == "import":
            child_txid = line[1]
            child_dict = evaluate(
                child_txid,
                fetcher,
                p_pristine=p_pristine.copy(),   # each child gets its OWN copy
                visited=visited,
                _depth=_depth + 1,
            )
            p_render.merge(child_dict)
        elif kind == "alias":
            names, target = line[1], line[2]
            for n in names:
                p_render.aliases[n] = target
        elif kind == "substitution":
            search, replace = line[1], line[2]
            p_render.substitutions.append((search, replace))
        elif kind == "citation":
            triggers, target, flags = line[1], line[2], line[3]
            p_render.citations.append((tuple(triggers), target, flags))
        elif kind == "annotation":
            anchor, note_md, position, flags = line[1], line[2], line[3], line[4]
            p_render.annotations.append((anchor, note_md, position, flags))
        # 'comment' lines are skipped

    visited[txid] = p_render.copy()
    return p_render.copy()


# ---------------------------------------------------------------------------
# Name resolution
# ---------------------------------------------------------------------------

def resolve(name, bd, depth_limit=ALIAS_DEPTH_LIMIT):
    """Walk an alias chain. Returns the terminal target (txid hex if the
    chain terminates at one, else the last unresolved alias name).

    Raises ValueError on:
      - cycle (e.g., <<A>>=<<B>>; <<B>>=<<A>>)
      - chain longer than depth_limit
    """
    visited = []
    cur = name
    while cur in bd.aliases:
        if cur in visited:
            raise ValueError(
                f"alias cycle: {' -> '.join(visited + [cur])}"
            )
        if len(visited) >= depth_limit:
            raise ValueError(
                f"alias chain exceeds depth_limit={depth_limit}: "
                f"{' -> '.join(visited + [cur])}"
            )
        visited.append(cur)
        cur = bd.aliases[cur]
    return cur


def apply_substitutions(text, bd):
    """Apply all substitutions from bd to text. Greedy longest-match-first."""
    for search, replace in sorted(bd.substitutions, key=lambda p: -len(p[0])):
        text = text.replace(search, replace)
    return text


_PRESENTATION_MODES = ("margin", "endnote", "inline")
_DEFAULT_PRESENTATION = "margin"


def apply_annotations(text, bd, *, doc_seen=None):
    """Resolve v3 annotation rules from bd against text.

    Returns a list of placement dicts in document order. Each placement
    describes where a note should appear and how it should render:

        {
          'anchor':       str,    # the exact substring matched
          'note':         str,    # the note body as markdown
          'mode':         str,    # 'margin' | 'endnote' | 'inline'
          'start':        int,    # char offset of anchor in `text`
          'end':          int,    # char offset of anchor end in `text`
          'flags':        frozenset,  # the full flag set (for renderer use)
        }

    Anchor matching is literal-substring (NOT regex), case-sensitive.

    Default behavior:
      - first occurrence per call (one match per anchor unless flagged)
      - mode defaults to 'margin'
      - flags `@all` and `@once-per-doc` modify match cardinality
      - flag `#N` (passed via the `position` field of the annotation
        tuple) picks the nth occurrence (1-indexed)
      - flags `@margin` / `@endnote` / `@inline` set the presentation
        mode

    The caller is responsible for THREADING `doc_seen` across blocks
    when implementing per-document semantics for `@once-per-doc`.
    """
    if doc_seen is None:
        doc_seen = set()
    placements = []

    for idx, (anchor, note_md, position, flags) in enumerate(bd.annotations):
        if not anchor:
            continue
        # Determine presentation mode
        modes = [f for f in flags if f in _PRESENTATION_MODES]
        mode = modes[0] if modes else _DEFAULT_PRESENTATION

        # Find all occurrences
        all_positions = []
        start = 0
        while True:
            pos = text.find(anchor, start)
            if pos < 0:
                break
            all_positions.append(pos)
            start = pos + 1

        if not all_positions:
            # Anchor unattached — emit a sentinel placement with start=-1
            # so the renderer can surface it in a colophon if it likes.
            placements.append({
                "anchor":  anchor,
                "note":    note_md,
                "mode":    mode,
                "start":   -1,
                "end":     -1,
                "flags":   flags,
                "unattached": True,
            })
            continue

        # Pick the occurrences this annotation should attach to
        targets = []
        if position is not None:
            # 1-indexed positional pick
            if 1 <= position <= len(all_positions):
                targets = [all_positions[position - 1]]
        elif "all" in flags:
            targets = all_positions
        elif "once-per-doc" in flags:
            key = ("annotation", idx, anchor)
            if key in doc_seen:
                continue
            doc_seen.add(key)
            targets = [all_positions[0]]
        else:
            # Default: first occurrence
            targets = [all_positions[0]]

        for tpos in targets:
            placements.append({
                "anchor":  anchor,
                "note":    note_md,
                "mode":    mode,
                "start":   tpos,
                "end":     tpos + len(anchor),
                "flags":   flags,
                "unattached": False,
            })

    # Sort by document position so the renderer can walk in order
    placements.sort(key=lambda p: (p["start"] if p["start"] >= 0 else 10**12))
    return placements


def apply_citations(text, bd, *, doc_seen=None, block_seen=None,
                    link_format=None):
    """Apply v2 citation rules from bd to text.

    Default behavior per spec:
      - word-bounded matching (\\b on each side)
      - surface-form preserving (matched text is the anchor)
      - first-per-block — each equivalence class fires once per block
      - case-sensitive

    Per-rule flags:
      - 'all'          — fire on every match
      - 'once-per-doc' — fire only the first time anywhere in the document
                         (caller threads doc_seen across blocks)

    Args:
      text:        text to process. Typically a single block, but can be
                   any string; the caller controls how block_seen resets.
      bd:          BindingDict carrying .citations
      doc_seen:    set of class-ids already fired with @once-per-doc;
                   caller maintains across blocks. Defaults to a fresh set.
      block_seen:  set of class-ids already fired in the current block
                   under default behavior; caller maintains across calls
                   that share a block. Defaults to a fresh set (single-call
                   use treats the whole input as one block).
      link_format: callable(matched_str, target_txid) -> str. Defaults to
                   markdown link `[matched](quipu:txid)`.

    Returns:
      Text with citations rendered.
    """
    if not bd.citations:
        return text
    if doc_seen is None:
        doc_seen = set()
    if block_seen is None:
        block_seen = set()
    if link_format is None:
        def link_format(matched, target):
            return f"[{matched}](quipu:{target})"

    trigger_to_class = {}
    classes = []  # parallel: classes[i] = (target_txid, flags_frozenset)
    for triggers, target, flags in bd.citations:
        cid = len(classes)
        classes.append((target, flags))
        for t in triggers:
            trigger_to_class[t] = cid

    if not trigger_to_class:
        return text

    pattern = r"\b(" + "|".join(
        re.escape(t) for t in sorted(trigger_to_class.keys(), key=len, reverse=True)
    ) + r")\b"

    def repl(m):
        matched = m.group(1)
        cid = trigger_to_class[matched]
        target, flags = classes[cid]
        if "once-per-doc" in flags:
            if cid in doc_seen:
                return matched
            doc_seen.add(cid)
        elif "all" in flags:
            pass
        else:
            if cid in block_seen:
                return matched
            block_seen.add(cid)
        return link_format(matched, target)

    return re.sub(pattern, repl, text)


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _selftest_parse():
    cases = [
        # Imports
        ("<<aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111>>",
         "import"),
        # Alias chains
        ("<<A>>=<<B>>=<<C>>=<<a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1>>",
         "alias"),
        ("<<Single>>=<<bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb>>",
         "alias"),
        # Substitutions
        ('"Domremy"="Domrémy"', "substitution"),
        ('"Sirichinova" = "Sinchova"', "substitution"),
        # Comments / unrecognized
        ("# this is a comment", "comment"),
        ("", "comment"),
        ("just some text", "comment"),
    ]
    print("=== parse_line ===")
    all_ok = True
    for src, want in cases:
        result = parse_line(src)
        ok = result[0] == want
        if not ok:
            all_ok = False
        print(f"  {'OK' if ok else 'FAIL':4s}  {src[:60]:60s}  ->  {result[0]}")
    if all_ok:
        print("  ✓ all parse cases match")
    print()


def _selftest_build_read_roundtrip():
    body = (
        "# Example binding\n"
        "<<MaierDecl>>=<<1ec0ee9b27d6ab91169b28f3acdada51cab8eb03af8c2a7e128d122a2dba7d0c>>\n"
        "<<DomCert>>=<<DomremyBordadoCertificate>>=<<6da7a9a9d8d651c48e0a979ea6d1f00ce03cd1388ea390c5fa2050f9b2fb4910>>\n"
        '"Domremy"="Domrémy"\n'
        '"Sirichinova"="Sinchova"\n'
    )
    h, b = build_binding_quipu(body, tone=TONE_ORDINARY)
    parsed = read_binding_quipu(h, b)
    print("=== build / read roundtrip ===")
    print(f"  header: {h.hex()}")
    print(f"  body length: {len(b)} bytes")
    assert parsed["tone"] == TONE_ORDINARY
    assert parsed["body"] == body
    kinds = [line[0] for line in parsed["lines"]]
    print(f"  line kinds: {kinds}")
    assert kinds.count("alias") == 2
    assert kinds.count("substitution") == 2
    assert kinds.count("comment") >= 1
    print("  ✓ all rules roundtrip")
    print()


def _selftest_evaluate():
    """Evaluate a small two-binding chain through an in-memory fetcher."""
    # Two bindings: child defines a name; parent imports the child and overrides.
    child_body = (
        "<<DomCert>>=<<6da7a9a9d8d651c48e0a979ea6d1f00ce03cd1388ea390c5fa2050f9b2fb4910>>\n"
        '"Domremy"="Domrémy"\n'
    )
    child_h, child_b = build_binding_quipu(child_body)
    child_blob = child_h + child_b
    child_txid = "c" * 64  # fake txid for the in-memory fetcher

    parent_body = (
        f"<<{child_txid}>>\n"                   # import child
        f"<<DomCert>>=<<aaaa....>>\n"           # invalid second-form; will be parsed as alias to literal 'aaaa....'
        f"<<MaierDecl>>=<<1ec0ee9b27d6ab91169b28f3acdada51cab8eb03af8c2a7e128d122a2dba7d0c>>\n"
        '"NewSpelling"="OldSpelling"\n'
    )
    parent_h, parent_b = build_binding_quipu(parent_body)
    parent_blob = parent_h + parent_b
    parent_txid = "p" * 64

    blobs = {child_txid: child_blob, parent_txid: parent_blob}
    def fetcher(txid):
        return blobs[txid.lower()]

    result = evaluate(parent_txid, fetcher)
    print("=== evaluate (two-level chain, last-write-wins override) ===")
    print(f"  final aliases: {dict(list(result.aliases.items()))}")
    print(f"  substitutions: {result.substitutions}")
    # Child set DomCert -> 6da7a9a9..., parent overrode with 'aaaa....'
    assert result.aliases.get("DomCert") == "aaaa...."
    # Parent's own MaierDecl assignment present
    assert result.aliases.get("MaierDecl", "").startswith("1ec0ee9b")
    # Substitutions accumulated from child + parent
    assert ("Domremy", "Domrémy") in result.substitutions
    assert ("NewSpelling", "OldSpelling") in result.substitutions
    print("  ✓ override + accumulation work")
    print()


def _selftest_cycle():
    """A imports B, B imports A — visited set should break the loop."""
    a_txid = "a" * 64
    b_txid = "b" * 64
    a_body = f"<<{b_txid}>>\n<<NameInA>>=<<{'1'*64}>>\n"
    b_body = f"<<{a_txid}>>\n<<NameInB>>=<<{'2'*64}>>\n"
    a_blob = b"".join(build_binding_quipu(a_body))
    b_blob = b"".join(build_binding_quipu(b_body))
    blobs = {a_txid: a_blob, b_txid: b_blob}
    def fetcher(txid):
        return blobs[txid.lower()]

    print("=== evaluate (cycle A -> B -> A) ===")
    result = evaluate(a_txid, fetcher)
    print(f"  result aliases: {dict(result.aliases.items())}")
    assert result.aliases.get("NameInA", "").startswith("1111")
    # NameInB came from B, which evaluated once (re-entry into A was a no-op)
    assert result.aliases.get("NameInB", "").startswith("2222")
    print("  ✓ cycle terminated without infinite recursion")
    print()


def _selftest_diamond():
    """X imports Z; Y imports Z; root imports both X and Y. Z evaluated once."""
    z_txid = "0" * 64
    x_txid = "1" * 64
    y_txid = "2" * 64
    r_txid = "3" * 64
    z_body = "<<NameFromZ>>=<<aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa>>\n"
    x_body = f"<<{z_txid}>>\n<<NameFromX>>=<<bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb>>\n"
    y_body = f"<<{z_txid}>>\n<<NameFromY>>=<<cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc>>\n"
    r_body = f"<<{x_txid}>>\n<<{y_txid}>>\n"
    blobs = {t: b"".join(build_binding_quipu(body))
             for t, body in [(z_txid, z_body), (x_txid, x_body),
                              (y_txid, y_body), (r_txid, r_body)]}
    fetch_count = {"n": 0}
    def fetcher(txid):
        fetch_count["n"] += 1
        return blobs[txid.lower()]

    visited = {}
    result = evaluate(r_txid, fetcher, visited=visited)
    print("=== evaluate (diamond import — Z evaluated once) ===")
    print(f"  evaluated txids: {sorted(t[:8] for t in visited.keys())}")
    print(f"  total fetcher calls: {fetch_count['n']}")
    assert fetch_count["n"] == 4   # r, x, z, y — Z is fetched only once
    assert set(result.aliases.keys()) == {"NameFromZ", "NameFromX", "NameFromY"}
    print("  ✓ diamond memoized — Z evaluated once")
    print()


def _selftest_resolve():
    bd = BindingDict()
    bd.aliases["A"] = "B"
    bd.aliases["B"] = "C"
    bd.aliases["C"] = "1" * 64
    print("=== resolve ===")
    target = resolve("A", bd)
    print(f"  A -> {target[:12]}...")
    assert target == "1" * 64
    # Cycle
    bd2 = BindingDict()
    bd2.aliases["X"] = "Y"
    bd2.aliases["Y"] = "X"
    try:
        resolve("X", bd2)
        print("  FAIL: cycle should have raised")
    except ValueError as e:
        print(f"  ✓ cycle detected: {e}")
    print()


def _selftest_v2_parse():
    """v2 chain-grammar parse cases."""
    txid = "c" * 64
    cases = [
        # New v2 citation forms
        (f'"Hayagriva"=<<{txid}>>',                       "citation"),
        (f'"Hayagriva"="hayagriva"="HAYAGRIVA"=<<{txid}>>',"citation"),
        (f'"Hayagriva"=<<{txid}>> @all',                  "citation"),
        (f'"Hayagriva"=<<{txid}>> @once-per-doc',         "citation"),
        # v1 forms should still parse as before
        (f'<<{txid}>>',                                   "import"),
        (f'<<A>>=<<B>>=<<{txid}>>',                       "alias"),
        ('"Domremy"="Domrémy"',                           "substitution"),
        # Unknown trailing junk → comment
        ('"X" wibble',                                    "comment"),
    ]
    print("=== v2 parse_line ===")
    all_ok = True
    for src, want in cases:
        result = parse_line(src)
        ok = result[0] == want
        if not ok:
            all_ok = False
        print(f"  {'OK' if ok else 'FAIL':4s}  {src[:60]:60s}  ->  {result[0]}")

    # Check the citation tuple shape on a concrete case
    c_line = f'"Hayagriva"="hayagriva"=<<{txid}>> @all'
    kind, triggers, target, flags = parse_line(c_line)
    assert kind == "citation"
    assert triggers == ["Hayagriva", "hayagriva"]
    assert target == txid
    assert flags == frozenset({"all"})
    print(f"  ✓ citation tuple: triggers={triggers}, target={target[:8]}…, flags={set(flags)}")
    if all_ok:
        print("  ✓ all v2 parse cases match")
    print()


def _selftest_apply_citations():
    """Engine: word-bounded, surface-preserving, first-per-block, with @all and @once-per-doc."""
    txid_C = "c" * 64
    txid_B = "b" * 64
    txid_X = "1" * 64

    body = (
        f'"Hayagriva"="hayagriva"="HAYAGRIVA"=<<{txid_C}>>\n'
        f'"Christamicus"=<<{txid_B}>> @all\n'
        f'"Bordado"=<<{txid_X}>> @once-per-doc\n'
        '"art"="ART"\n'                  # v1 substitution — left alone by citation engine
    )
    h, b = build_binding_quipu(body)
    parsed = read_binding_quipu(h, b)
    bd = BindingDict()
    for line in parsed["lines"]:
        kind = line[0]
        if kind == "citation":
            triggers, target, flags = line[1], line[2], line[3]
            bd.citations.append((tuple(triggers), target, flags))
        elif kind == "substitution":
            bd.substitutions.append((line[1], line[2]))

    print("=== apply_citations ===")

    # Equivalence-class default: chain fires once per block, surface preserved
    block1 = "Hayagriva and hayagriva and HAYAGRIVA are three forms."
    out1 = apply_citations(block1, bd)
    print(f"  block1 -> {out1}")
    assert out1.count(f"](quipu:{txid_C})") == 1
    assert "[Hayagriva](quipu:" in out1   # first form preserved as anchor

    # @all: every occurrence becomes a citation
    block2 = "Christamicus and Christamicus again."
    out2 = apply_citations(block2, bd)
    print(f"  block2 -> {out2}")
    assert out2.count(f"](quipu:{txid_B})") == 2

    # @once-per-doc: only first block fires, second block does not
    doc_seen = set()
    block3a = "First Bordado mention."
    block3b = "Second Bordado mention."
    out3a = apply_citations(block3a, bd, doc_seen=doc_seen)
    out3b = apply_citations(block3b, bd, doc_seen=doc_seen)
    print(f"  block3a -> {out3a}")
    print(f"  block3b -> {out3b}")
    assert f"](quipu:{txid_X})" in out3a
    assert f"](quipu:{txid_X})" not in out3b

    # Word boundary: 'art' in 'partisan' should NOT match (but there's no 'art' citation,
    # only a v1 substitution; verify that v1 subs are NOT touched by apply_citations)
    block4 = "The partisan painted art."
    out4 = apply_citations(block4, bd)
    assert out4 == block4  # no citation rule for 'art'
    print(f"  block4 (no-op for v1 subs) -> {out4}")

    # Case-sensitive: 'hayagriva' is in the chain so it DOES match; 'HayaGriva' is not.
    block5 = "HayaGriva is a typo."
    out5 = apply_citations(block5, bd)
    assert "[HayaGriva](" not in out5
    print(f"  block5 (case-sensitive) -> {out5}")

    print("  ✓ first-per-block, @all, @once-per-doc, word-bound, case-sensitive all work")
    print()


def _selftest_apply_substitutions():
    bd = BindingDict()
    bd.substitutions = [("Domremy", "Domrémy"), ("Sirichinova", "Sinchova")]
    out = apply_substitutions("Sirichinova wrote about Domremy", bd)
    print("=== apply_substitutions ===")
    print(f"  result: {out!r}")
    assert out == "Sinchova wrote about Domrémy"
    print("  ✓ substitutions applied")
    print()


def _selftest_v3_parse_annotations():
    """v3 fenced annotation blocks."""
    body = (
        "# A binding with annotations\n"
        "\n"
        '"hebreo"="yiddish"\n'
        "\n"
        "@@Yorkshire terrier named Beatrice\n"
        "The dog's name carries the Dante echo throughout this essay's\n"
        "cosmology. Beatrice as the guide through the spheres of paradise.\n"
        "@@\n"
        "\n"
        "@@Beatrice #3 @endnote\n"
        "Third occurrence; renders as endnote rather than margin.\n"
        "@@\n"
        "\n"
        "@@Operation Condor @once-per-doc @inline\n"
        "Mixed flags: doc-once + inline rendering. Multi-line\n"
        "\n"
        "with a blank line inside the note body, which is allowed.\n"
        "@@\n"
        "\n"
        "@@unclosed-anchor\n"
        "this never gets a closing fence and should fall back to a comment\n"
    )
    lines = parse_body(body)
    annotations = [l for l in lines if l[0] == "annotation"]
    print("=== v3 parse_body (annotations) ===")
    print(f"  total lines: {len(lines)}, annotations: {len(annotations)}")
    assert len(annotations) == 3, f"expected 3 annotations, got {len(annotations)}"

    a0 = annotations[0]
    assert a0[1] == "Yorkshire terrier named Beatrice"
    assert "Dante echo" in a0[2]
    assert a0[3] is None             # no #N
    assert a0[4] == frozenset()      # no flags → default margin
    print(f"  [0] anchor={a0[1]!r}  position={a0[3]}  flags={set(a0[4])}")

    a1 = annotations[1]
    assert a1[1] == "Beatrice"
    assert a1[3] == 3
    assert a1[4] == frozenset({"endnote"})
    print(f"  [1] anchor={a1[1]!r}  position={a1[3]}  flags={set(a1[4])}")

    a2 = annotations[2]
    assert a2[1] == "Operation Condor"
    assert a2[3] is None
    assert a2[4] == frozenset({"once-per-doc", "inline"})
    assert "blank line inside" in a2[2]
    print(f"  [2] anchor={a2[1]!r}  position={a2[3]}  flags={set(a2[4])}")

    # Unclosed fence should fall back to comment + per-line parsing
    comments = [l for l in lines if l[0] == "comment"]
    assert any("unclosed-anchor" in (l[1] if isinstance(l[1], str) else "")
               for l in comments), "unclosed fence should fall back to comment"
    print(f"  ✓ unclosed fence falls back to comment (lines after it parsed individually)")
    print()


def _selftest_apply_annotations():
    bd = BindingDict()
    # Three annotations against the same text, exercising default,
    # positional, @all, and @once-per-doc behaviors.
    bd.annotations = [
        # default: first occurrence, default mode (margin)
        ("Beatrice", "first Beatrice note", None, frozenset()),
        # positional: third occurrence, endnote mode
        ("Beatrice", "third Beatrice note", 3, frozenset({"endnote"})),
        # @all: every occurrence, inline mode
        ("Goethe", "every Goethe note", None, frozenset({"all", "inline"})),
        # @once-per-doc: only first across the document
        ("Hayagriva", "first-in-doc only", None, frozenset({"once-per-doc"})),
        # unattached: anchor doesn't exist
        ("NonExistent", "unattached note", None, frozenset({"margin"})),
    ]
    text = (
        "Beatrice walked with the author. Goethe is mentioned twice: "
        "Goethe wrote about it. Beatrice again. Beatrice third. "
        "Hayagriva is named."
    )
    doc_seen = set()
    placements = apply_annotations(text, bd, doc_seen=doc_seen)
    print("=== apply_annotations ===")
    for p in placements:
        loc = f"@{p['start']}-{p['end']}" if not p["unattached"] else "(unattached)"
        print(f"  [{p['mode']:<7}] {loc:<14} {p['anchor']!r:<24} → {p['note'][:40]!r}")

    # Expectations:
    by_anchor = {}
    for p in placements:
        by_anchor.setdefault(p["anchor"], []).append(p)

    # Default Beatrice → first occurrence
    assert by_anchor["Beatrice"][0]["start"] == text.find("Beatrice")
    assert by_anchor["Beatrice"][0]["mode"] == "margin"

    # Positional Beatrice #3 → third occurrence
    bea3 = by_anchor["Beatrice"][1]
    assert bea3["mode"] == "endnote"
    # Compute third occurrence manually
    positions = []
    start = 0
    while True:
        i = text.find("Beatrice", start)
        if i < 0: break
        positions.append(i); start = i + 1
    assert bea3["start"] == positions[2]

    # @all Goethe → 2 placements, inline mode
    goethes = by_anchor["Goethe"]
    assert len(goethes) == 2
    assert all(g["mode"] == "inline" for g in goethes)

    # @once-per-doc Hayagriva → 1 placement; second call with same doc_seen
    # should NOT re-emit
    placements_2 = apply_annotations(text, bd, doc_seen=doc_seen)
    hay_count_2 = sum(1 for p in placements_2 if p["anchor"] == "Hayagriva")
    assert hay_count_2 == 0, "once-per-doc should not re-fire under same doc_seen"

    # Unattached: emitted with start=-1
    assert by_anchor["NonExistent"][0]["unattached"] is True
    assert by_anchor["NonExistent"][0]["start"] == -1

    print("  ✓ default, positional #N, @all, @once-per-doc, unattached all behave")
    print()


def _selftest_annotation_accumulation():
    """Two bindings annotating the same anchor — annotations accumulate."""
    body_a = (
        "@@Hayagriva @margin\n"
        "From annotator A: the Vishnu avatar.\n"
        "@@\n"
    )
    body_b = (
        "@@Hayagriva @endnote\n"
        "From annotator B: also the project's canon-keeper.\n"
        "@@\n"
    )
    bd_a = BindingDict()
    for line in parse_body(body_a):
        if line[0] == "annotation":
            bd_a.annotations.append((line[1], line[2], line[3], line[4]))
    bd_b = BindingDict()
    for line in parse_body(body_b):
        if line[0] == "annotation":
            bd_b.annotations.append((line[1], line[2], line[3], line[4]))

    merged = BindingDict()
    merged.merge(bd_a)
    merged.merge(bd_b)
    print("=== annotation accumulation across bindings ===")
    print(f"  bd_a: {len(bd_a.annotations)}  bd_b: {len(bd_b.annotations)}  "
          f"merged: {len(merged.annotations)}")
    assert len(merged.annotations) == 2, "annotations should accumulate, not last-write-wins"
    text = "Hayagriva preserves the canon."
    placements = apply_annotations(text, merged)
    assert len(placements) == 2
    modes = sorted(p["mode"] for p in placements)
    assert modes == ["endnote", "margin"]
    print("  ✓ both annotations attach to the same anchor with their own modes")
    print()


if __name__ == "__main__":
    _selftest_parse()
    _selftest_v2_parse()
    _selftest_v3_parse_annotations()
    _selftest_build_read_roundtrip()
    _selftest_evaluate()
    _selftest_cycle()
    _selftest_diamond()
    _selftest_resolve()
    _selftest_apply_substitutions()
    _selftest_apply_citations()
    _selftest_apply_annotations()
    _selftest_annotation_accumulation()
