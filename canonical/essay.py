"""
essay.py — 0x01 essay quipu type (canonical).

An essay is a CommonMark markdown document with quipu-protocol extensions.
The substitution engine processes the body to resolve `<<txid>>` citations,
fenced `binding` blocks, alias rules, and string substitutions, emitting
plain markdown that any off-the-shelf renderer (python-markdown, commonmark,
pandoc, marked.js, …) can convert to HTML.

Pipeline
--------

    raw on-chain bytes
        ↓
    header parse → (title, fields, body)
        ↓
    extract fenced `binding` blocks → 0xab body parser (bindings.py)
        ↓
    evaluate imports + local rules → final BindingDict
        ↓
    resolve <<citations>> in body → standard markdown links/images
        ↓
    apply string substitutions to result
        ↓
    clean markdown                                           ← protocol output
        ↓
    standard CommonMark renderer
        ↓
    HTML                                                     ← display

Body grammar
------------

The body is CommonMark with two protocol extensions:

1) `<<NAME [attr="value"]*>>` citations resolve to standard markdown links
   (or, for images, data/viewer URLs):

       <<txid>>                          → [Target Title](quipu:<txid>)
       <<Alias>>                         → resolved through binding dict
       <<txid title="Custom">>           → [Custom](quipu:<txid>)
       <<txid>><<SubObj>>                → [SubObj](quipu:<txid>#<SubObj>)
       [anchor](<<txid>>)                → [anchor](quipu:<txid>)
       ![alt](<<txid>>)                  → ![alt](quipu:<txid>)

2) Fenced `binding` code blocks hold the substitution-engine machinery
   (imports, alias rules, string substitutions). They are extracted and
   evaluated, then removed from the output:

       ```binding
       <<txid_of_other_binding>>           # import
       <<DomCert>>=<<6da7a9a9…>>           # alias
       <<A>>=<<B>>=<<txid>>                # alias chain
       "Sirichinova"="Sinchova"            # string substitution
       ```

The same vocabulary as 0xab binding bodies. The engine treats fenced
blocks as scoped: lines inside don't get treated as prose, citations
inside are alias DEFINITIONS not RESOLUTIONS.

Header (multi-field, same as 0x00 text)
---------------------------------------

    c1dd 0001  01  <tone>  |Title|author=…|date=…|lang=…|encoding=…|
    <body — markdown, processed by substitution engine>

Reserved field formats are inherited from 0x00 text (encoding/date/lang/
author). Only `encoding` is protocol-significant; others are display
metadata.

See docs/quipu-types/essay.md for the formal spec and worked examples.
"""

from __future__ import annotations

import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Reuse machinery from text.py + bindings.py
from text import (
    _FIELD_VALIDATORS,
    _VALID_TONES,
    TONE_ORDINARY, TONE_AFFECTION, TONE_DEMONIC, TONE_REVERENCE,
)
from bindings import (
    BindingDict, evaluate as evaluate_binding,
    parse_body as parse_binding_body, resolve as resolve_alias,
    apply_substitutions,
)

TYPE_ESSAY = 0x01

# ---------------------------------------------------------------------------
# Citation parsing
# ---------------------------------------------------------------------------

# Outer shape: <<...>> with anything but more <> inside.
# (We allow nested ?, but disallow embedded > or < to keep the parse cheap.)
CITATION_RE = re.compile(r"<<\s*([^<>]+?)\s*>>")

# Inside the citation body, the first token is the NAME; the remainder is
# zero or more attribute key="value" pairs.
_ATTR_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')


def parse_citation_inner(inner):
    """Parse the inside of a `<<...>>` citation.

    Returns:
        (name, attrs_dict)

    `name` is the first whitespace-separated token (an alias or 64-hex txid).
    `attrs_dict` is a dict of key->value parsed from the remaining
    `key="value"` pairs.
    """
    inner = inner.strip()
    if not inner:
        return "", {}
    # First token = name; rest = attrs
    parts = inner.split(None, 1)
    name = parts[0]
    attrs = {}
    if len(parts) > 1:
        for m in _ATTR_RE.finditer(parts[1]):
            attrs[m.group(1)] = m.group(2)
    return name, attrs


# ---------------------------------------------------------------------------
# Fenced binding-block extraction
# ---------------------------------------------------------------------------

# A fenced binding block: ```binding ... ``` (with optional surrounding
# whitespace). Captured content is everything between the fences.
_BINDING_FENCE_RE = re.compile(
    r"^[ \t]*```binding[ \t]*\n(.*?)\n[ \t]*```[ \t]*$",
    re.MULTILINE | re.DOTALL,
)


def extract_binding_blocks(markdown):
    """Pull all ```binding ...``` blocks out of the markdown.

    Returns:
        (cleaned_markdown, list_of_block_contents) — blocks are removed from
        the cleaned markdown in source order; their inner text is returned
        as a list of strings for the substitution engine.
    """
    blocks = []
    def _capture(match):
        blocks.append(match.group(1))
        return ""   # remove the block from the markdown
    cleaned = _BINDING_FENCE_RE.sub(_capture, markdown)
    # Tidy up any stranded blank-line runs the removal might leave
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip("\n") + "\n"
    return cleaned, blocks


# ---------------------------------------------------------------------------
# Binding-block evaluation (no fetcher needed for inline-only essays;
# fetcher required if any block imports another 0xab binding by txid).
# ---------------------------------------------------------------------------

def evaluate_blocks(blocks, fetcher=None, p_pristine=None, visited=None):
    """Evaluate a list of binding-block text bodies, accumulating into a
    single BindingDict (last-write-wins across blocks).

    Args:
        blocks:      list of strings (each is one block's body)
        fetcher:     callable(txid) -> bytes, for resolving <<txid>> imports
                     of external 0xab bindings. If None and an import is
                     encountered, a stub error message is recorded in
                     substitutions but the rest of the evaluation continues.
        p_pristine:  parent's pristine BindingDict (default empty).
        visited:     shared visited-set for memoization across the essay's
                     compile pass.

    Returns:
        BindingDict
    """
    if p_pristine is None:
        p_pristine = BindingDict()
    if visited is None:
        visited = {}

    P_render = p_pristine.copy()
    for block in blocks:
        # Process this block's lines using the bindings parser
        for line in parse_binding_body(block):
            kind = line[0]
            if kind == "import":
                child_txid = line[1]
                if fetcher is None:
                    # Skip — record nothing (or you could raise; recoverable)
                    continue
                child_dict = evaluate_binding(
                    child_txid,
                    fetcher,
                    p_pristine=p_pristine.copy(),
                    visited=visited,
                )
                P_render.merge(child_dict)
            elif kind == "alias":
                names, target = line[1], line[2]
                for n in names:
                    P_render.aliases[n] = target
            elif kind == "substitution":
                search, replace = line[1], line[2]
                P_render.substitutions.append((search, replace))
            # 'comment' lines are skipped
    return P_render


# ---------------------------------------------------------------------------
# Citation resolution to standard markdown
# ---------------------------------------------------------------------------

def _viewer_url(txid, sub_object=None):
    """Default URL scheme for resolved citations.

    Returns `quipu:<txid>` for whole-inscription references and
    `quipu:<txid>#<sub>` for two-segment sub-object references.
    Override at the renderer if you want a different URL prefix
    (e.g. for an actual web viewer).
    """
    if sub_object:
        return f"quipu:{txid}#{sub_object}"
    return f"quipu:{txid}"


def _looks_like_txid(s):
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", s))


# Markdown link/image with a citation as the URL: `[anchor](<<X>>)` or
# `![alt](<<X>>)`. The `!` prefix marks an image. Anchor/alt captured
# in group 2; citation body in group 3.
_MD_LINK_CITATION_RE = re.compile(
    r'(!?)\[([^\]]*)\]\(\s*<<\s*([^<>]+?)\s*>>\s*\)'
)


def _resolve_to_txid(name, bd):
    """Resolve an alias chain to a terminal txid (or return the unresolved
    name if it never gets to one). Catches cycle/depth errors silently."""
    try:
        return resolve_alias(name, bd)
    except ValueError:
        return name


def resolve_citations(markdown, bd, title_lookup=None, viewer_url=_viewer_url):
    """Replace all `<<...>>` citations in markdown with standard markdown.

    Two-pass:
      pass 1 — citations inside `[anchor](<<X>>)` or `![alt](<<X>>)` markdown
               link/image syntax: substitute ONLY the URL.
      pass 2 — any remaining bare `<<X>>` citations: wrap in `[anchor](url)`,
               handling the two-segment `<<X>><<SubObj>>` form for
               sub-object refs.

    Args:
        markdown:     the essay body markdown (after binding-block removal)
        bd:           BindingDict containing aliases + substitutions
        title_lookup: callable(txid) -> str. Returns the target inscription's
                      title for use as default anchor text. May return ''
                      to indicate unknown; in that case the anchor falls back
                      to the alias name.
        viewer_url:   callable(txid, sub_object=None) -> str URL form

    Returns:
        markdown with all `<<...>>` citations resolved.
    """
    if title_lookup is None:
        title_lookup = lambda t: ""

    # ---- pass 1: citations inside markdown link/image syntax ----
    def _replace_md_link(match):
        bang, anchor, inner = match.group(1), match.group(2), match.group(3)
        name, attrs = parse_citation_inner(inner)
        resolved = _resolve_to_txid(name, bd)
        if _looks_like_txid(resolved):
            href = viewer_url(resolved)
        else:
            href = f"quipu:unresolved:{name}"
        return f"{bang}[{anchor}]({href})"

    markdown = _MD_LINK_CITATION_RE.sub(_replace_md_link, markdown)

    # ---- pass 2: bare citations (and two-segment) ----
    out = []
    i = 0
    while i < len(markdown):
        m = CITATION_RE.match(markdown, i)
        if not m:
            out.append(markdown[i])
            i += 1
            continue
        end_first = m.end()
        name1, attrs1 = parse_citation_inner(m.group(1))

        # Look ahead for adjacent <<Y>> as a sub-object label
        rest = markdown[end_first:]
        m2 = CITATION_RE.match(rest)
        sub_segment = None
        sub_attrs = {}
        if m2 and rest[:m2.start()].strip() == "":
            name2, attrs2 = parse_citation_inner(m2.group(1))
            if not _looks_like_txid(name2):
                sub_segment = name2
                sub_attrs = attrs2
                end_first += m2.end()

        resolved = _resolve_to_txid(name1, bd)
        title_attr = attrs1.get("title") or sub_attrs.get("title")
        if title_attr:
            anchor = title_attr
        elif sub_segment:
            anchor = sub_segment
        elif _looks_like_txid(resolved):
            anchor = title_lookup(resolved) or name1
        else:
            anchor = name1

        if _looks_like_txid(resolved):
            href = viewer_url(resolved, sub_object=sub_segment)
        else:
            href = f"quipu:unresolved:{name1}"

        out.append(f"[{anchor}]({href})")
        i = end_first

    return "".join(out)


# ---------------------------------------------------------------------------
# Full body-substitution pipeline
# ---------------------------------------------------------------------------

def substitute_body(body_markdown, fetcher=None, title_lookup=None,
                    viewer_url=_viewer_url):
    """Run the full substitution pipeline on an essay body.

    Args:
        body_markdown:  the raw markdown body extracted from the essay
        fetcher:        callable(txid) -> bytes, for resolving binding
                        imports inside fenced blocks. Optional.
        title_lookup:   callable(txid) -> str, for default anchor text.
                        Optional.
        viewer_url:     callable(txid, sub_object=None) -> str URL. Default
                        is the `quipu:<txid>` URI scheme.

    Returns:
        plain markdown (no protocol-specific syntax left)
    """
    cleaned, blocks = extract_binding_blocks(body_markdown)
    bd = evaluate_blocks(blocks, fetcher=fetcher)
    resolved = resolve_citations(cleaned, bd, title_lookup=title_lookup,
                                  viewer_url=viewer_url)
    final = apply_substitutions(resolved, bd)
    return final


# ---------------------------------------------------------------------------
# Build / read
# ---------------------------------------------------------------------------

def build_essay_quipu(title, body_markdown, tone=TONE_ORDINARY, fields=None):
    """Build a 0x01 essay quipu's (header_bytes, body_bytes) pair.

    Args:
        title:          str, the essay title. May be empty.
        body_markdown:  str, the markdown body (may include `<<txid>>`
                        citations and ```binding fenced blocks).
        tone:           TONE_ORDINARY (default), TONE_AFFECTION, or
                        TONE_REVERENCE.
        fields:         optional dict[str, str] of header metadata.
                        Same reserved field formats as 0x00 text.

    Returns:
        (header_bytes, body_bytes)
    """
    if tone not in _VALID_TONES:
        raise ValueError(
            f"tone must be 0x00, 0x01, 0x0d, or 0xff (got {tone:#04x})"
        )
    if "|" in title:
        raise ValueError("title contains '|' (field separator)")
    if "=" in title:
        raise ValueError("title contains '=' (would parse as key=value)")
    fields = dict(fields) if fields else {}
    seen = set()
    for k, v in fields.items():
        if "|" in k or "|" in v:
            raise ValueError(f"field {k!r}: '|' forbidden")
        if "=" in k:
            raise ValueError(f"field key {k!r} contains '='")
        if k in seen:
            raise ValueError(f"duplicate field key {k!r}")
        seen.add(k)
        if k in _FIELD_VALIDATORS:
            _FIELD_VALIDATORS[k](v)

    # Body encoding — same rule as text.py
    declared = fields.get("encoding", "utf-8")
    body_bytes = body_markdown.encode(declared)

    header = b"\xc1\xdd\x00\x01" + bytes([TYPE_ESSAY]) + bytes([tone])
    if title or fields:
        parts = [title] + [f"{k}={v}" for k, v in fields.items()]
        header += b"|" + "|".join(parts).encode("utf-8") + b"|"

    return header, body_bytes


def read_essay_quipu(header_bytes, body_bytes):
    """Parse a 0x01 essay quipu's bytes into structured form.

    Returns:
        {
          'title':         str,
          'tone':          int (0x00/0x01/0x0d/0xff),
          'fields':        dict[str, str],
          'body':          str (raw markdown — citations and binding blocks
                                still unresolved),
        }

    The caller can then pass `body` to substitute_body() to get the
    pipeline-resolved markdown.
    """
    if header_bytes[:4] != b"\xc1\xdd\x00\x01":
        raise ValueError("not a quipu (c1dd0001 magic missing)")
    if len(header_bytes) < 6:
        raise ValueError(f"header too short: {len(header_bytes)} < 6")
    if header_bytes[4] != TYPE_ESSAY:
        raise ValueError(
            f"not an essay (type byte = {header_bytes[4]:#04x}, expected 0x01)"
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

    encoding = fields.get("encoding", "utf-8")
    try:
        body = bytes(body_bytes).decode(encoding)
    except (LookupError, UnicodeDecodeError) as e:
        raise ValueError(f"cannot decode body with encoding {encoding!r}: {e}")

    return {
        "title":  title,
        "tone":   tone,
        "fields": fields,
        "body":   body,
    }


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _selftest_basic():
    body = "# Hello\n\nThis is just plain markdown.\n"
    h, b = build_essay_quipu("Hello", body)
    print(f"=== basic essay (no citations) ===")
    print(f"  header ({len(h)} B): {h.hex()}")
    parsed = read_essay_quipu(h, b)
    assert parsed["title"] == "Hello"
    assert parsed["body"] == body
    resolved = substitute_body(parsed["body"])
    assert resolved.strip() == body.strip()
    print(f"  ✓ plain markdown passes through unchanged")
    print()


def _selftest_citation_basic():
    body = (
        "# Test\n\n"
        "See <<aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa>> "
        "for details.\n"
    )
    titles = {"a" * 64: "Some Inscription"}
    resolved = substitute_body(body, title_lookup=titles.get)
    print(f"=== bare citation → markdown link ===")
    print(f"  in:  {body.strip()}")
    print(f"  out: {resolved.strip()}")
    assert "[Some Inscription](quipu:" + "a"*64 + ")" in resolved
    print(f"  ✓ resolved to [Title](quipu:<txid>)")
    print()


def _selftest_citation_with_title_attr():
    body = (
        f'See <<{"b"*64} title="My Name For It">> in this work.\n'
    )
    resolved = substitute_body(body)
    print(f"=== citation with title= attribute ===")
    print(f"  out: {resolved.strip()}")
    assert "[My Name For It](quipu:" + "b"*64 + ")" in resolved
    print(f"  ✓ title attribute overrides default anchor")
    print()


def _selftest_citation_in_markdown_link():
    body = f"See [the cert]({'<<' + 'c'*64 + '>>'}) here.\n"
    resolved = substitute_body(body)
    print(f"=== citation as link URL ===")
    print(f"  out: {resolved.strip()}")
    assert f"[the cert](quipu:{'c'*64})" in resolved
    print(f"  ✓ resolved inside [anchor](<<txid>>) form")
    print()


def _selftest_citation_as_image():
    body = f"![the bordado]({'<<' + 'd'*64 + '>>'})\n"
    resolved = substitute_body(body)
    print(f"=== citation as image URL ===")
    print(f"  out: {resolved.strip()}")
    # ![alt](<<txid>>) becomes ![alt](quipu:<txid>) — we don't auto-inline
    # the image data; the renderer or viewer is responsible for fetching.
    # NOTE current resolver doesn't see the ! prefix specially; it just
    # substitutes the URL. The downstream markdown renderer keeps it as an
    # image.
    assert f"quipu:{'d'*64}" in resolved
    print(f"  ✓ URL substituted inside image syntax")
    print()


def _selftest_two_segment():
    body = f"The brightest star is <<{'e'*64}>><<Sirius>>.\n"
    resolved = substitute_body(body)
    print(f"=== two-segment citation (sub-object) ===")
    print(f"  out: {resolved.strip()}")
    assert f"[Sirius](quipu:{'e'*64}#Sirius)" in resolved
    print(f"  ✓ <<txid>><<SubObj>> → [SubObj](quipu:<txid>#<SubObj>)")
    print()


def _selftest_fenced_binding_block():
    body = (
        "# Essay\n\n"
        "```binding\n"
        f"<<DomCert>>=<<{'a'*64}>>\n"
        f'"Sirichinova"="Sinchova"\n'
        "```\n\n"
        "The certificate at <<DomCert>>, signed by Sirichinova.\n"
    )
    titles = {"a"*64: "Domremy Cert"}
    resolved = substitute_body(body, title_lookup=titles.get)
    print(f"=== fenced binding block — alias + substitution ===")
    print(f"  out:")
    for line in resolved.strip().split("\n"):
        print(f"    {line}")
    # The binding block should be removed
    assert "```binding" not in resolved
    # The alias should have resolved
    assert f"[Domremy Cert](quipu:{'a'*64})" in resolved
    # The substitution should have applied
    assert "Sinchova" in resolved
    assert "Sirichinova" not in resolved
    print(f"  ✓ binding block consumed; alias + substitution applied")
    print()


def _selftest_roundtrip():
    body = (
        "# Roundtrip Test\n\n"
        "Some prose with a citation: <<DomCert>>.\n"
    )
    h, b = build_essay_quipu(
        "Roundtrip Test", body,
        tone=TONE_ORDINARY,
        fields={"author": "Christophia Hayagriva",
                "date":   "2026-05-21",
                "lang":   "en"},
    )
    parsed = read_essay_quipu(h, b)
    print(f"=== build / read roundtrip ===")
    print(f"  header ({len(h)} B): {h.hex()[:80]}…")
    assert parsed["title"]            == "Roundtrip Test"
    assert parsed["tone"]             == TONE_ORDINARY
    assert parsed["fields"]["author"] == "Christophia Hayagriva"
    assert parsed["fields"]["date"]   == "2026-05-21"
    assert parsed["fields"]["lang"]   == "en"
    assert parsed["body"]             == body
    print(f"  ✓ header + body roundtrip cleanly")
    print()


def _selftest_validation():
    cases = [
        ("title with pipe",      lambda: build_essay_quipu("a|b", "x"),    "field separator"),
        ("title with equals",    lambda: build_essay_quipu("a=b", "x"),    "key=value"),
        ("invalid tone",         lambda: build_essay_quipu("t", "x", tone=0x42), "tone"),
        ("bad date",             lambda: build_essay_quipu("t", "x", fields={"date": "yesterday"}), "ISO 8601"),
        ("bad lang",             lambda: build_essay_quipu("t", "x", fields={"lang": "Spanish"}), "BCP 47"),
        ("bad encoding",         lambda: build_essay_quipu("t", "x", fields={"encoding": "moonspeak"}), "encoding"),
    ]
    print(f"=== validation ===")
    for desc, fn, want in cases:
        try:
            fn()
            print(f"  {desc:25s} -> DID NOT RAISE")
        except (ValueError, TypeError) as e:
            status = "OK" if want in str(e) else "WRONG ERR"
            print(f"  {desc:25s} -> {status}: {e}")
    print()


if __name__ == "__main__":
    _selftest_basic()
    _selftest_citation_basic()
    _selftest_citation_with_title_attr()
    _selftest_citation_in_markdown_link()
    _selftest_citation_as_image()
    _selftest_two_segment()
    _selftest_fenced_binding_block()
    _selftest_roundtrip()
    _selftest_validation()
