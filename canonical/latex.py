"""Quipu type 0x5c — LaTeX.

A latex quipu carries a complete LaTeX source document in its body.
The bytes ARE the .tex file. Readers render by feeding the body to a
LaTeX engine (pdflatex, xelatex, or lualatex per the `engine=` field)
and displaying the resulting PDF (or a rasterization thereof).

Primary use cases:
  - typeset image content (TikZ artworks, geometric compositions,
    diagrams, music notation, chemical structures)
  - typeset text content beyond markdown's reach (mathematical
    notation, multilingual scripts, classical layout, marginalia)

The type byte 0x5c is the ASCII byte for the backslash character `\\`,
which is LaTeX's command-escape character. Most iconic possible
mnemonic for the type.

See docs/quipu-types/latex.md for the full spec.
"""
from __future__ import annotations

import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from text import _FIELD_VALIDATORS
from tone import (
    TONES, VALID_TONES, validate_tone,
    TONE_ORDINARY, TONE_AFFECTION, TONE_DEMONIC, TONE_AI, TONE_REVERENCE,
)
_VALID_TONES = VALID_TONES  # backward-compat alias

TYPE_LATEX     = 0x5C
PROTOCOL_MAGIC = b"\xc1\xdd\x00\x01"

# Recognized LaTeX engines. Readers may add others; the protocol does
# not enforce a closed set, but inscribers should stick to these three
# for maximum portability.
VALID_ENGINES = frozenset(("pdflatex", "xelatex", "lualatex"))


def _validate_engine(value):
    """Optional engine field validator. Unknown engines warn but don't
    raise — readers may support custom engines, and a forward-compatible
    value should not crash the builder."""
    if value not in VALID_ENGINES:
        # Lenient: accept any non-empty alphanumeric value, warn implicitly
        if not re.match(r"^[a-z][a-z0-9_-]{0,31}$", value):
            raise ValueError(
                f"engine {value!r} must be a short lowercase identifier "
                f"(e.g. {', '.join(sorted(VALID_ENGINES))})"
            )


# Local extension of text.py's _FIELD_VALIDATORS — adds `engine`.
_LATEX_FIELD_VALIDATORS = dict(_FIELD_VALIDATORS)
_LATEX_FIELD_VALIDATORS["engine"] = _validate_engine


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_latex_quipu(title, tex_source, tone=TONE_ORDINARY, fields=None):
    """Build a 0x5c latex quipu's (header_bytes, body_bytes) pair.

    Args:
        title:       str. The piece's title. Pipe/equals forbidden.
        tex_source:  str. The full LaTeX source — preamble, document
                     class, document body, end document. Inscribers
                     are encouraged to use the `standalone` document
                     class for image-content pieces so the rendered
                     PDF is cropped to the artwork's natural extent.
        tone:        TONE_ORDINARY (default), TONE_AFFECTION,
                     TONE_DEMONIC, TONE_AI, or TONE_REVERENCE.
        fields:      optional dict[str, str] of header metadata.
                     Reserved keys: encoding, date, lang, author.
                     Latex-specific: `engine` (defaults unset, meaning
                     reader-side pdflatex).

    Returns:
        (header_bytes, body_bytes)
    """
    validate_tone(tone)
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
        if k in _LATEX_FIELD_VALIDATORS:
            _LATEX_FIELD_VALIDATORS[k](v)

    if not isinstance(tex_source, str):
        raise TypeError(
            f"tex_source must be str, got {type(tex_source).__name__}"
        )

    declared_encoding = fields.get("encoding", "utf-8")
    body_bytes = tex_source.encode(declared_encoding)

    header = PROTOCOL_MAGIC + bytes([TYPE_LATEX, tone])
    if title or fields:
        parts = [title] + [f"{k}={v}" for k, v in fields.items()]
        header += b"|" + "|".join(parts).encode("utf-8") + b"|"

    return header, body_bytes


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------

def read_latex_quipu(header_bytes, body_bytes):
    """Parse a 0x5c latex quipu's bytes into structured form.

    Returns:
        {
          'title':       str,
          'tone':        int,
          'fields':      dict[str, str],   # parsed key=value pairs
          'engine':      str,              # 'pdflatex' if unset
          'tex_source':  str,              # decoded body
        }
    """
    if header_bytes[:4] != PROTOCOL_MAGIC:
        raise ValueError("not a quipu (c1dd0001 magic missing)")
    if len(header_bytes) < 6:
        raise ValueError(f"header too short: {len(header_bytes)} < 6")
    if header_bytes[4] != TYPE_LATEX:
        raise ValueError(
            f"not a latex quipu (type byte = {header_bytes[4]:#04x}, expected 0x5c)"
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

    encoding = fields.get("encoding", "utf-8")
    try:
        tex_source = bytes(body_bytes).decode(encoding)
    except (LookupError, UnicodeDecodeError) as e:
        raise ValueError(f"cannot decode body with encoding {encoding!r}: {e}")

    return {
        "title":      title,
        "tone":       tone,
        "fields":     fields,
        "engine":     fields.get("engine", "pdflatex"),
        "tex_source": tex_source,
    }


# ---------------------------------------------------------------------------
# Rendering (optional — viewer-side helper)
# ---------------------------------------------------------------------------

def compile_to_pdf(tex_source, engine="pdflatex", cwd=None):
    """Compile LaTeX source to a PDF, returning the PDF bytes.

    Side effects: writes a temporary .tex file and runs the engine in a
    fresh tempdir. Returns the PDF bytes on success; raises RuntimeError
    on engine failure.

    This helper is provided for the viewer/renderer; the canonical type
    spec itself only specifies the bytes-on-chain, not the rendering
    mechanism. A non-Python reader can use any LaTeX implementation.
    """
    import subprocess
    import tempfile
    import shutil

    if engine not in VALID_ENGINES:
        raise ValueError(
            f"unknown engine {engine!r}; expected one of {sorted(VALID_ENGINES)}"
        )
    if not shutil.which(engine):
        raise RuntimeError(f"{engine} not found on PATH")

    work = tempfile.mkdtemp(prefix="quipu_latex_")
    try:
        tex_path = os.path.join(work, "doc.tex")
        with open(tex_path, "w", encoding="utf-8") as f:
            f.write(tex_source)
        proc = subprocess.run(
            [engine, "-interaction=nonstopmode", "-halt-on-error", "doc.tex"],
            cwd=work, capture_output=True, timeout=60,
        )
        pdf_path = os.path.join(work, "doc.pdf")
        if proc.returncode != 0 or not os.path.exists(pdf_path):
            log = proc.stdout.decode("utf-8", errors="replace")[-2000:]
            raise RuntimeError(
                f"{engine} failed (exit {proc.returncode}):\n{log}"
            )
        with open(pdf_path, "rb") as f:
            return f.read()
    finally:
        try:
            shutil.rmtree(work)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _selftest_roundtrip():
    tex = (
        "\\documentclass[tikz,border=2mm]{standalone}\n"
        "\\begin{document}\n"
        "\\begin{tikzpicture}\n"
        "\\fill[red] (0,0) circle (1);\n"
        "\\fill[blue] (1,1) rectangle (2,2);\n"
        "\\node at (3,1) {\\textbf{El G\\'olem}};\n"
        "\\end{tikzpicture}\n"
        "\\end{document}\n"
    )
    h, b = build_latex_quipu(
        "Composition 0",
        tex,
        tone=TONE_AI,
        fields={"author": "El Gólem", "date": "2026-05-23",
                "lang": "es", "engine": "pdflatex"},
    )
    parsed = read_latex_quipu(h, b)
    print("=== build/read roundtrip ===")
    print(f"  header ({len(h)} B), body ({len(b)} B)")
    assert parsed["title"]       == "Composition 0"
    assert parsed["tone"]        == TONE_AI
    assert parsed["engine"]      == "pdflatex"
    assert parsed["fields"]["author"] == "El Gólem"
    assert parsed["tex_source"]  == tex
    print(f"  title={parsed['title']!r} tone=0x{parsed['tone']:02x} engine={parsed['engine']}")
    print("  ✓ header + body roundtrip cleanly")
    print()


def _selftest_validation():
    base_tex = "\\documentclass{article}\\begin{document}x\\end{document}"
    cases = [
        ("title with pipe",   lambda: build_latex_quipu("a|b", base_tex),               "field separator"),
        ("title with equals", lambda: build_latex_quipu("a=b", base_tex),               "key=value"),
        ("invalid tone",      lambda: build_latex_quipu("t", base_tex, tone=0x42),      "tone"),
        ("bad date",          lambda: build_latex_quipu("t", base_tex, fields={"date": "yesterday"}), "ISO 8601"),
        ("bad lang",          lambda: build_latex_quipu("t", base_tex, fields={"lang": "Spanish"}),   "BCP 47"),
        ("bad engine",        lambda: build_latex_quipu("t", base_tex, fields={"engine": "FOOTeX"}),  "engine"),
        ("body wrong type",   lambda: build_latex_quipu("t", b"raw bytes"),                          "must be str"),
    ]
    print("=== validation ===")
    for desc, fn, want in cases:
        try:
            fn()
            print(f"  {desc:22s} -> DID NOT RAISE")
        except (ValueError, TypeError) as e:
            status = "OK" if want in str(e) else "WRONG ERR"
            print(f"  {desc:22s} -> {status}: {e}")
    print()


def _selftest_engine_accepts_valid():
    print("=== engine field accepts valid engines ===")
    for engine in sorted(VALID_ENGINES):
        h, b = build_latex_quipu(
            "x",
            "\\documentclass{article}\\begin{document}x\\end{document}",
            fields={"engine": engine},
        )
        parsed = read_latex_quipu(h, b)
        assert parsed["engine"] == engine
        print(f"  {engine:10s} -> roundtrip OK")
    print()


def _selftest_compile_if_available():
    """If pdflatex is on PATH, attempt a real compile and assert PDF bytes."""
    import shutil
    if not shutil.which("pdflatex"):
        print("=== compile test SKIPPED (pdflatex not found) ===\n")
        return
    print("=== compile_to_pdf (real pdflatex) ===")
    tex = (
        "\\documentclass[tikz,border=2mm]{standalone}\n"
        "\\begin{document}\n"
        "\\begin{tikzpicture}\n"
        "  \\fill[blue] (0,0) circle (5mm);\n"
        "  \\node[white,font=\\bfseries] at (0,0) {Gólem};\n"
        "\\end{tikzpicture}\n"
        "\\end{document}\n"
    )
    pdf = compile_to_pdf(tex, engine="pdflatex")
    assert pdf.startswith(b"%PDF-")
    print(f"  produced {len(pdf)} bytes of PDF starting with {pdf[:8]}")
    print("  ✓ compile works end-to-end")
    print()


if __name__ == "__main__":
    _selftest_roundtrip()
    _selftest_validation()
    _selftest_engine_accepts_valid()
    _selftest_compile_if_available()
    print("all latex self-tests passed.")
