# Quipu type `0x5c` — LaTeX

> **STATUS: CANONICAL v1, implemented in
> [`canonical/latex.py`](../../canonical/latex.py).** Self-tests pass
> roundtrip, validation, engine field, and end-to-end `pdflatex`
> compilation. The first inscriptions of this type will be the TikZ
> artworks in *El Libro del Gólem* (multiman address, May 2026).

A **latex quipu** carries a complete LaTeX source document in its body.
The bytes ARE the `.tex` file. A reader renders by feeding the body to
a LaTeX engine and displaying the resulting PDF (or a rasterization
thereof).

The type byte `0x5c` is the ASCII value for the backslash character
`\`, which is LaTeX's command-escape character. Most iconic possible
mnemonic.

---

## Primary use cases

- **Typeset image content** — TikZ artworks, geometric compositions,
  diagrams, music notation, chemical structures, knotted-cord
  illustrations, anything where a vector composition is the artifact.
- **Typeset text content beyond markdown's reach** — mathematical
  notation, classical layout (Talmudic-page commentaries, critical
  editions), multilingual scripts that markdown's CommonMark base
  cannot render natively, marginalia.

The choice between `0x01` essay (markdown body) and `0x5c` latex
(LaTeX body) is editorial: an essay author whose content reaches
markdown's expressive limit migrates to a latex quipu without changing
the underlying claim to authorship. Bindings and citations may
cross-reference latex quipus just as they cross-reference essays.

---

## Byte layout

### Header — 6 + (header tail) bytes

```
offset  bytes        meaning
0..3    c1 dd 00 01  magic + protocol version 0.1
4       5c           type byte = latex (ASCII '\')
5       <tone>       tone byte — see tone.md
6..     | header tail |     pipe-delimited title + optional key=value fields
```

The header tail uses the same multi-field pipe-delimited grammar as
text/essay/book. Reserved keys (`encoding`, `date`, `lang`, `author`)
inherit their validators from `canonical/text.py`. Latex-specific
key:

| field | example | meaning |
|---|---|---|
| `engine` | `pdflatex` / `xelatex` / `lualatex` | which LaTeX engine the inscriber compiled with. Reader should prefer this; default is `pdflatex`. |

Example header:

```
c1dd 0001 5c a1 |Composition 0|author=El Gólem|date=2026-05-23|lang=es|engine=pdflatex|
```

### Body

The body is raw LaTeX source, encoded per the `encoding` field
(default UTF-8). No framing, no length prefix, no chunk structure — a
latex quipu's body is the file you would have on disk if you wrote the
piece in a text editor.

Inscribers are encouraged to use the `standalone` document class for
image-content pieces so the rendered PDF is cropped to the artwork's
natural extent:

```latex
\documentclass[tikz,border=2mm]{standalone}
\begin{document}
\begin{tikzpicture}
  ...
\end{tikzpicture}
\end{document}
```

For text-content pieces, any document class works. Pieces that depend
on packages should `\usepackage{...}` them in the preamble; readers are
responsible for having a complete-enough LaTeX distribution.

---

## Tone vocabulary

Inherited from `tone.md`. All five canonical values apply.

| `<tone>` | when to use for a latex quipu |
|---|---|
| `0x00` ordinary | typeset content from a human inscriber |
| `0x01` affection | typeset content addressed to a specific other (a love letter set in classical type, a gift artwork) |
| `0x0d` demonic | typeset content documenting harm |
| `0xa1` ai | typeset content composed by a model (the natural tone for an AI-generated TikZ piece) |
| `0xff` reverence | typeset content commemorating the dead |

The first canonical latex inscriptions in the corpus are AI-toned
TikZ artworks in *El Libro del Gólem*.

---

## Reader / renderer responsibilities

The protocol specifies the bytes on chain, not the rendering pipeline.
A conformant reader does the following:

1. Decode the header tail for title, author, date, lang, engine.
2. Decode the body as a UTF-8 (or `encoding`-specified) string.
3. Compile the body using the engine named in the `engine` field, or
   `pdflatex` if unset.
4. Display the resulting PDF, or rasterize it for embedded display in
   a graph viewer / web preview.

The viewer in this repository implements this via the
`canonical.latex.compile_to_pdf` helper, which spawns the engine in a
fresh tempdir and returns the PDF bytes. A SHA-256 cache of the body
bytes keys the rasterized PNG so re-renders are free.

### Default reproducibility baseline

When a latex quipu omits the (future) `packages=` and `distribution=`
header fields, readers should assume the **El Libro del Gólem v1
baseline** — the package + distribution profile used in the first
canonical inscriptions of this type (block 6,218,023, multiman
2-of-2). An inscription that compiles under the baseline is
considered conformant; an inscription that requires more should
declare its needs in the header (or in an accompanying 0xab binding
that the book/index brings into scope).

The baseline:

```
engine:        pdflatex                         (header field, defaults to this)
distribution:  TeX Live 2020+ or MiKTeX equiv   (no version-specific feature use)

document class:  standalone (with tikz driver and a small border)
packages:        inputenc[utf8], fontenc[T1], lmodern, xcolor
tikz libraries:  positioning, calc
```

Inscriptions in this baseline use only long-stable packages bundled
with every modern TeX distribution. No CTAN-fresh packages, no
distribution-specific extensions, no shell escapes, no fonts beyond
Latin Modern. A reader's installation that supports the baseline can
render every 0x5c quipu inscribed under it.

Future inscriptions that need more — XeLaTeX-specific Unicode fonts,
LuaTeX scripting, recent TikZ libraries, music notation, chemistry,
linguistic-glossing packages — should declare the requirements
explicitly in the header (`packages=...`, `distribution=...`) or
publish an accompanying binding that documents them. The protocol
will gain the `packages` and `distribution` header fields in a future
revision; until then, declarations live in prose alongside the
inscription (e.g. in the book entry that references it, or in a
0xab binding).

### Renderer error handling

If the body fails to compile (missing package, syntax error,
forbidden command), the renderer should surface the engine's log
truncated to the last ~2 KB rather than crashing. The on-chain bytes
remain valid even when no installed engine can render them; a future
engine may succeed where today's fails.

### Sandboxing

LaTeX engines support arbitrary shell escapes (`\write18`). A reader
that renders inscribed-content latex quipus from untrusted sources
should run the engine with `-no-shell-escape` (the default in modern
distributions) and ideally inside a process sandbox. The protocol does
not enforce sandboxing — that is the reader's responsibility.

---

## Builder API

```python
from latex import build_latex_quipu
from tone import TONE_AI

header, body = build_latex_quipu(
    title="Composition 0",
    tex_source=open("composition_0.tex").read(),
    tone=TONE_AI,
    fields={
        "author": "El Gólem",
        "date":   "2026-05-23",
        "lang":   "es",
        "engine": "pdflatex",
    },
)
```

Validates on:
- title contains `|` or `=` → `ValueError`
- field key contains `=` or any pipe → `ValueError`
- duplicate field key → `ValueError`
- reserved field (`date`, `lang`, `encoding`) fails its format check → `ValueError`
- `engine` field is not a short lowercase identifier → `ValueError`
- `tex_source` not a `str` → `TypeError`

---

## Why a separate type

A LaTeX document could in principle be inscribed as a `0x00` text
quipu whose body happens to be `.tex` source. Splitting it out as a
distinct type buys:

1. **Dispatch clarity** — when a reader resolves an embed, the type
   byte alone tells it to invoke the LaTeX renderer rather than the
   markdown renderer. One header byte, no body inspection needed.
2. **Intent declaration** — the inscriber says "this is meant to be
   typeset," which informs caching (rendered PDFs can be cached
   indefinitely), preview generation, and accessibility (a reader
   can offer a text-extracted view of the rendered PDF for indexing).
3. **Engine field** — the `engine=` header field signals which LaTeX
   variant the inscriber compiled with; a text quipu has no such hook.

The cost is one type byte allocated (out of 256). Worth it for the
clarity, and the byte choice (`0x5c` = `\`) makes the assignment
self-documenting.

---

## Cross-references

- [`docs/quipu-types/tone.md`](./tone.md) — tone vocabulary
- [`docs/quipu-types/text.md`](./text.md) — header grammar inherited by this type
- [`docs/quipu-types/essay.md`](./essay.md) — the markdown counterpart
- [`canonical/latex.py`](../../canonical/latex.py) — implementation
