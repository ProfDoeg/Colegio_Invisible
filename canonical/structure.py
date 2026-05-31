"""
structure.py — document structure conventions (canonical, renderer-agnostic).

A quipu document carries its TITLE as metadata: the title lives in the
protocol header (cabeza) `|Title|key=value|…|`, never in the body. The body
(cuerpo) is pure content. This module is the single place both the LaTeX and
the (forthcoming) HTML pipeline obey, so every renderer agrees on where the
title comes from and what a heading level means.

Heading levels are ABSOLUTE to the document tree
-------------------------------------------------

    level 1  ( #    )  →  the TITLE slot           (metadata-owned)
    level 2  ( ##   )  →  first section
    level 3  ( ###  )  →  subsection
    level 4  ( #### )  →  sub-subsection
    …

So a body's top *structural* heading is `##` — a section beneath the title.
Authors SHOULD NOT restate the title in the body. For readability in a plain
Markdown viewer a body MAY open with `# Title`, but a renderer ALWAYS discards
that line and shows the canonical metadata title in its place — the "lenient
title shim". To avoid eating a legitimate first section in a legacy body that
opened with a *non-title* `#`, the shim only absorbs the leading H1 when it
MATCHES the canonical title (whitespace / case / diacritic-insensitive). A
mismatch is left in place and reported as drift for the caller to log.

How a renderer uses the level
-----------------------------

    role, depth = structural_role(level)
      role == "title"    → render the metadata title
                           (LaTeX: \\chapter in a book / \\maketitle in an
                            essay;  HTML: <h1>)
      role == "section"  → depth 0 = section, 1 = subsection, 2 = subsubsection…
                           (LaTeX: \\section/\\subsection/…;  HTML: <h2>/<h3>/…)

Because the rule is shared, "El yiddish del joven Goethe" rendered as a book
chapter and the same essay rendered standalone place their `##` headings at
exactly the same structural depth, and neither double-prints its title.
"""
from __future__ import annotations

import re
import unicodedata

__all__ = [
    "structural_role",
    "split_leading_title",
    "normalize_body",
    "title_matches",
]

# ATX heading: 1–6 leading '#', a space, text, optional trailing '#'s.
_ATX_RE = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$")


def structural_role(level):
    """Map an absolute markdown heading level to a (role, depth) pair.

    level 1 is the document title; level N>=2 is a section nested (N-2) deep.
    Renderers translate the role to their own construct (see module docstring).
    """
    if level <= 1:
        return ("title", 0)
    return ("section", level - 2)


def _norm(s):
    """Loose comparison key for titles: strip diacritics, collapse runs of
    whitespace, casefold. So 'El  HEBREO' == 'el hebreo' == 'él hébreo'."""
    s = unicodedata.normalize("NFKD", s or "")
    s = "".join(c for c in s if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", s).strip().casefold()


def title_matches(a, b):
    """True when two title strings are equal under the loose key above."""
    return bool(a) and bool(b) and _norm(a) == _norm(b)


def split_leading_title(markdown):
    """If the body's first non-blank line is an ATX H1 (`# …`), split it off.

    Returns (h1_text_or_None, body_without_leading_h1). Leading blank lines
    before the H1 are consumed. If the first content line is not an H1, the
    body is returned unchanged with h1_text None.
    """
    lines = (markdown or "").split("\n")
    j = 0
    while j < len(lines) and not lines[j].strip():
        j += 1
    if j >= len(lines):
        return None, markdown
    m = _ATX_RE.match(lines[j])
    if not m or len(m.group(1)) != 1:
        return None, markdown
    h1 = m.group(2).strip()
    rest = "\n".join(lines[j + 1:]).lstrip("\n")
    return h1, rest


def normalize_body(markdown, canonical_title):
    """Apply the lenient title shim to an essay/text body.

    The body has already been citation-resolved + substituted to plain
    markdown; this is the last renderer-agnostic pass before a renderer maps
    headings to its own constructs.

    Returns (body_markdown, drift):
      * If the body opens with an H1 that matches `canonical_title` (or there
        is no metadata title to prefer), the H1 is absorbed and `drift` is
        None — the renderer shows the metadata title in its place.
      * If the body opens with an H1 that does NOT match, it is left in place
        and returned as `drift` so the caller can warn; the renderer will show
        it as a section (see structural_role).
      * If the body does not open with an H1, it is returned unchanged.
    """
    h1, rest = split_leading_title(markdown)
    if h1 is None:
        return markdown, None
    if not canonical_title or title_matches(h1, canonical_title):
        return rest, None
    return markdown, h1


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _selftest():
    # structural_role: title at level 1, sections from level 2.
    assert structural_role(1) == ("title", 0)
    assert structural_role(2) == ("section", 0)
    assert structural_role(3) == ("section", 1)
    assert structural_role(4) == ("section", 2)

    # Matching leading H1 is absorbed; remaining sections survive.
    body = "# El hebreo del joven Goethe\n\nLos judíos…\n\n## El Aleph-Bet\n\ntext"
    out, drift = normalize_body(body, "El hebreo del joven Goethe")
    assert drift is None, drift
    assert not out.lstrip().startswith("# "), out[:40]
    assert "## El Aleph-Bet" in out

    # Diacritic/case/space-insensitive match still absorbs.
    out2, drift2 = normalize_body("#   ÉL  HEBREO\n\nbody", "el hebreo")
    assert drift2 is None and out2.strip() == "body", (out2, drift2)

    # Mismatched leading H1 is kept + reported as drift.
    out3, drift3 = normalize_body("# Some Section\n\nbody", "A Totally Different Title")
    assert drift3 == "Some Section", drift3
    assert out3.lstrip().startswith("# Some Section")

    # No leading H1 → untouched.
    out4, drift4 = normalize_body("Just prose.\n\n## Section", "T")
    assert drift4 is None and out4 == "Just prose.\n\n## Section"

    # No metadata title → absorb whatever H1 is there (renderer falls back).
    out5, drift5 = normalize_body("# Orphan\n\nbody", "")
    assert drift5 is None and out5.strip() == "body"

    # Leading blank lines before the H1 are tolerated.
    out6, drift6 = normalize_body("\n\n# T\n\nbody", "T")
    assert drift6 is None and out6.strip() == "body"

    print("structure.py self-test OK")


if __name__ == "__main__":
    _selftest()
