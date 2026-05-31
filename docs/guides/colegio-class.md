# The `colegio` document class

A practical guide to `colegio.cls`, the Tufte-inspired LaTeX class for
typesetting Colegio Invisible essays and books as PDFs. Aimed at:

- Future authors preparing an essay or book for print / PDF reading.
- Any future Claude session asked to render corpus prose in LaTeX.

The class lives at [`latex/colegio/colegio.cls`](../../latex/colegio/colegio.cls);
worked examples are in [`latex/colegio/examples/`](../../latex/colegio/examples/)
and a full real-corpus render is
[`working/dos_ensayos/dos_ensayos.tex`](../../working/dos_ensayos/dos_ensayos.tex).

> **This is a renderer, not an inscription type.** Do not confuse it with
> the `0x5c` latex quipu type ([`latex.md`](../quipu-types/latex.md)),
> which carries a raw `.tex` body *on chain*. `colegio.cls` is an
> off-chain presentation layer: it typesets the prose of `0x01` essays
> and `0x09` books (and the binding/annotation overlays they carry) into
> a printed page. The chain holds the content; this class is one way to
> render it.

---

## TL;DR

```latex
\documentclass[essay,tone=ai]{colegio}     % or [book,tone=ordinary]
\title{On the Tone Byte}
\persona{El Gólem}
\date{2026-05-23}
\begin{document}
\maketitle
\newthought{The sixth byte} of every quipu …      % small-caps lead-in
… prose … \margin{a sidenote}                       % v3 annotation: margin
… prose …\backnote{the anchor}{a collected note}    % v3 annotation: endnote
\quipucite[El Libro del Gólem]{7b19fb2b…}           % cite another quipu
\printbacknotes
\begin{colophon}… \colophonentry{…}{…} …\end{colophon}
\end{document}
```

- **Engine: `xelatex` (required).** The class uses `fontspec` and Unicode
  scripts. Compile twice for the TOC / endnotes to settle.
- Fonts, geometry, headings, and figures all follow Tufte conventions
  out of the box. You mostly write prose and call a handful of macros.

---

## Class options

```latex
\documentclass[<mode>,tone=<tone>]{colegio}
```

| option | values | default | effect |
|---|---|---|---|
| mode | `essay` \| `book` | `essay` | `essay` → top level is `\section` (loads `article`); `book` → top level is `\chapter` (loads `book`) |
| `tone` | `ordinary` \| `affection` \| `demonic` \| `ai` \| `reverence` | `ordinary` | sets the **tone accent colour** used for annotation markers, rules, and the title-page tone line, and the tone-byte hex printed on the title page / colophon |

Tone → accent colour → tone byte:

| tone | accent | byte |
|---|---|---|
| ordinary | bordado gold | `0x00` |
| affection | yellow | `0x01` |
| demonic | oxblood | `0x0d` |
| ai | slate blue | `0xa1` |
| reverence | gold | `0xff` |

---

## Fonts — matched to Tufte-LaTeX

The class loads the same free font trio the upstream Tufte-LaTeX class
uses, all with real OpenType small caps and old-style figures:

| role | font | note |
|---|---|---|
| body (serif) | **TeX Gyre Pagella** | free Palatino clone; `Numbers=OldStyle` |
| sans / marginalia | **TeX Gyre Heros** | free Helvetica clone, scaled 0.90 |
| monospace | **TeX Gyre Cursor** | free Courier clone |

Small caps are **real** (used by `\textsc`, `\newthought`, running heads,
colophon labels), not faux-scaled. Numerals are old-style throughout.

### Multilingual scripts

The corpus mixes Hebrew gematría, polytonic Greek, and Arabic star
names. Pagella covers Latin and basic Greek; the class registers
per-script fallbacks and switches into them automatically by Unicode
block (via `ucharclasses`) — **you never wrap a Greek word or an Arabic
phrase, it just renders**:

| script | fallback font |
|---|---|
| Hebrew | Arial Hebrew |
| Greek (incl. polytonic) | Times New Roman |
| Arabic | Arial Unicode MS |

**One gotcha.** A *single word* that mixes two Unicode blocks — e.g.
polytonic Greek combining Greek-Extended (ἀ `U+1F00`) with
Greek-and-Coptic (ή `U+03AE`), as in `ἀστήρ` — can have its second block
drop back to the Latin face mid-word, because the auto-switcher fires at
the internal block boundary. For those rare words use the explicit
helpers, which force one script font across the whole span and suspend
the auto-switcher inside the group:

```latex
\gk{κατὰ + ἀστήρ}      % Greek
\ar{الجوزاء}            % Arabic
\he{אהבה}               % Hebrew
```

If a build logs `Missing character: … U+03AE …`, find the offending
mixed-block word and wrap it in `\gk` / `\ar` / `\he`.

---

## What the class does automatically (Tufte conventions)

You get these without doing anything:

- **B5 page** (176 × 250 mm) with a narrow tall text column and a wide
  outer margin (≈ 37 mm) for sidenotes and margin figures.
- **Italic headings** at every level — chapter, section, subsection. No
  rules, no bold, no small-caps headings. A chapter prints a small
  sans-serif `Chapter N` strap line above the italic title.
- **Ragged-right body** (`ragged2e`), generous hyphenation.
- **Running heads** with no rule: chapter/title in small caps on the
  left, folio at the outer corner. Chapter-opening pages use the `plain`
  style (no running head) — "folios unexpressed."
- **First paragraph after any heading sits flush-left** (no indent);
  later paragraphs indent. The first body paragraph after `\maketitle`
  is also flush-left.
- **Old-style figures** and real small caps everywhere.

### `\newthought{…}` — small-caps lead-in

Opens a new "thought" with Tufte's small-caps lead-in and a little extra
space above. Use it to open a chapter or to start a section's body:

```latex
\newthought{In the beginning} the protocol carried only text …
```

---

## Metadata commands

Set before `\begin{document}`; consumed by `\maketitle` and the colophon.

| command | purpose |
|---|---|
| `\title{…}` | document title |
| `\author{…}` | legal / secondary author (optional) |
| `\persona{…}` | the persona attribution (e.g. `El Gólem`, `El Ermitaño`) |
| `\date{YYYY-MM-DD}` | inscription date |
| `\inscribingaddress{…}` | the address that signed it |
| `\rootxid{…}` | root transaction id |
| `\jointxid{…}` | join transaction id (book) |
| `\blockheight{…}` | inscription block height |
| `\protocolheader{…}` | the literal on-chain header bytes, printed as an intaglio stamp atop the title page |

`\maketitle` renders: the protocol header bytes (small monospace, top),
the italic title, the persona, and a foot block with the tone line, date,
and block height — left-aligned and spare, the Tufte way.

---

## Annotations — the three v3 presentation modes

These mirror the `0xab` v3 annotation primitive's three modes
(`@margin`, `@endnote`, `@inline`; see
[`bindings.md`](../quipu-types/bindings.md)). The anchor phrase is
already in your prose at the call site — these macros emit **only** the
marker and the note, never re-emitting the anchor.

| command | mode | renders |
|---|---|---|
| `\margin{note}` | margin | numbered marker + sidenote in the outer margin |
| `\backnote{anchor}{note}` | endnote | numbered marker; note collected by `\printbacknotes` (the `anchor` labels the collected note) |
| `\inlinenote{note}` | inline | numbered marker + bracketed `[ note ]` at the call site |
| `\unattached{anchor}{note}` | — | not placed in the body; surfaces in the colophon's "Unattached annotations" block (for an anchor that no longer matches the prose, e.g. after a title correction) |

Markers are numeric superscripts in the **tone accent colour**. Call
`\printbacknotes` where you want the collected endnotes (typically in
`\backmatter`, before the colophon). It prints nothing if there are no
backnotes.

---

## Citing another quipu

```latex
\quipucite[Dichtung und Wahrheit]{a4bb2379…}
```

Renders the optional display title in italic followed by a small
`quipu:<first-12>…` superscript. With no display title it prints
`quipu:<txid>` in monospace. **Never** emit a third-party block-explorer
URL — `\quipucite` is the canonical way to point at another inscription
in rendered prose, exactly as `quipu:<txid>` / `<<txid>>` are in the
inscribed body.

---

## Figures — in the margin by default

The canonical Colegio figure is a **margin figure**: a small plate in the
wide outer margin, captioned in place, that the reader's eye meets beside
the prose that calls it.

```latex
\marginfigure{\includegraphics[width=\marginparwidth]{fig.png}}{Caption.}
```

`\marginfigure{graphics}{caption}` drops a numbered figure into the outer
margin. It shares the standard `figure` counter, so margin and in-text
figures number in one sequence (`Figure 1.1`, `Figure 1.2`, …). Captions
are small sans-serif, ragged, with a period-separated label — Tufte's
caption style, applied to every figure in the document.

For a **dense plate that loses too much detail at ≈ 37 mm** — a manuscript
scan, a detailed diagram — use a full-column figure instead:

```latex
\begin{figure}[h]
  \centering
  \includegraphics[width=\linewidth]{manuscript.png}
  \caption{Caption.}
\end{figure}
```

### On-chain images as figures — `\imagequipu` / `\imagequipuwide`

The class provides two commands for placing an on-chain `0x03` image (or
`0xce` celestial) that has been decoded to a PNG under `figures/`:

```latex
\imagequipu{png-basename}{txid}{caption}            % margin figure
\imagequipuwide[width]{png-basename}{txid}{caption}  % full text column
```

Both print the caption and a faint `quipu:<txid>` fingerprint credit
(`\imagequipu` truncates it; `\imagequipuwide` prints it full). The
`png-basename` is the file under `figures/` without the `.png` suffix.
Decoding the inscription body to a PNG is done off-LaTeX — for one
document by a small script like
[`working/dos_ensayos/decode_images.py`](../../working/dos_ensayos/decode_images.py)
(it splits the structural header from the bit-packed body and unpacks via
[`canonical/image.py`](../../canonical/image.py); celestials go through
the canonical celestial renderer), and corpus-wide by the pipeline (next
section).

Rule of thumb: **supporting illustrations go in the margin
(`\imagequipu`); the subject of the essay goes full-column
(`\imagequipuwide`).** In *Dos ensayos*, the Pinochet portrait, the DINA
letter, and the al-Jawza star chart are margin figures, while the Goethe
practice manuscript — the page the whole first essay is about — is
full-column.

---

## The pipeline — markdown → colegio, and the render directive

[`colegio_pipeline.py`](../../colegio_pipeline.py) renders a `0x01` essay
or `0x09` book straight from its on-chain markdown into a colegio `.tex`
and compiles it: it resolves the essay's bindings (aliases, v1
substitutions, v2 citations, v3 annotations), turns `<<txid>>` references
into `\quipucite` / figures, decodes any cited `0x03`/`0xce` quipu to a
PNG, and emits a full `\documentclass{colegio}` document.

```python
import colegio_pipeline as P
tex = P.essay_to_tex("84fbbb17…", figdir="build/figures")   # or book_to_tex(…)
pdf = P.compile_tex(tex, "build", figdir="build/figures")    # xelatex ×2
```

### The render directive

The interpreter understands a **render directive** on any `<<…>>`
reference — an attribute saying how the cited quipu should be rendered.
It rides in the inscribed markdown body, so it travels on chain; any
renderer that doesn't understand it falls back to a link.

```
<<TXID render="margin" width="40mm" caption="…">>
![alt](<<TXID render="full">>)
```

| `render=` | image / celestial target (`0x03`/`0xce`) | text / essay target (`0x00`/`0x01`) |
|---|---|---|
| `link` *(default)* | `\quipucite` | `\quipucite` |
| `margin` | `\imagequipu` (margin figure) | margin cite |
| `full` | `\imagequipuwide` (full column) | falls back to embed |
| `inline` | inline `\includegraphics` (text-width or `width=`) | inline cite |
| `thumb` | small inline thumbnail (`width=` or default) | inline cite |
| `embed` | inline image | **recursively renders the target's prose** |

Companions: `width="NNmm"`, `caption="…"`, `title="…"`. Example: to put
the al-Jawza celestial in the margin, an author writes
`<<2ae7fe90… render="margin" caption="The Sky of al-Jawza">>` in the
essay body and the pipeline emits the `\imagequipu` margin figure.

### Round-trip: the typeset form on chain

The same module closes the loop with the `0x5c` latex inscription type, so
the *typeset* form of a document can itself live on chain:

```python
class_txid, *_ = P.inscribe_class()                    # colegio.cls → its own 0x5c quipu
tex            = P.essay_to_tex("84fbbb17…")           # essay → colegio .tex
doc_txid, *_   = P.inscribe_tex(tex, "Title", class_txid=class_txid)   # .tex → 0x5c quipu
pdf            = P.render_latex_quipu(doc_txid, "build")               # fetch → compile
```

- **Class delivery is by quipu.** `colegio.cls` is inscribed once as its
  own `0x5c` quipu (fields `role=class`, `name=colegio.cls`). A document
  `0x5c` carries `class=<class_txid>`; `render_latex_quipu` fetches that
  quipu and materialises `colegio.cls` at compile time — the class is
  never assumed present on disk.
- **Figure delivery is by quipu.** The generated `.tex` carries a
  `%%QFIG <txid>` manifest comment listing every image/celestial quipu it
  embeds; the reader decodes each from chain into `figures/` before
  compiling. So a `0x5c` document quipu + its `class=` quipu + its figure
  quipus are together sufficient to reproduce the exact PDF, with nothing
  off-chain but the LaTeX engine.

See [`docs/quipu-types/latex.md`](../quipu-types/latex.md) for the `0x5c`
byte layout and the `class=` / `role=class` field convention.

### Publishing a typeset edition with a book

A book can *optionally* publish its typeset edition as part of its
manifest. `build_typeset_edition(book_txid)` inscribes the class quipu
and the rendered `.tex` doc quipu and returns a `render/latex` manifest
entry; include that entry when you build the `0x09` book, and the typeset
edition travels with the book. To render, `render_book(book_txid)`
follows a `render/latex` entry to compile the exact inscribed edition, or
regenerates the `.tex` from content if the book carries none.

```python
entry, doc_txid, class_txid = P.build_typeset_edition("26671514…")
#   → inscribe class + .tex; `entry` (tag render/latex) goes in the 0x09 manifest
pdf = P.render_book("…book txid…", "build")   # follows the entry, else regenerates
```

This is the protocol-level convention; the content essays stay pure
markdown, and the typeset book is a separate, optional inscription the
book references. See [`docs/quipu-types/book.md`](../quipu-types/book.md)
§"Optional typeset editions".

---

## Bibliography — every cited quipu, with links

A book points at many other inscriptions: cited works, embedded images,
celestials. The class provides a **References** section that lists them,
each with a clickable `quipu:<txid>` address:

```latex
\begin{quipubibliography}
  \quipubibitem{Dichtung und Wahrheit (Libro IV, extracto)}{0x01 essay}{a4bb2379…}
  \quipubibitem{Página de Práctica Hebrea de Goethe, c. 1760}{0x03 image}{94f700ad…}
  …
\end{quipubibliography}
```

`\quipubibitem{title}{type label}{txid}` prints the work's title (italic),
its type, and `\href{quipu:<txid>}{quipu:<txid>}` — a real hyperlink using
the protocol's `quipu:` URI scheme (never a third-party explorer URL).

**The pipeline fills it automatically for books.** As the converter
resolves each `<<…>>` reference — whether it renders as a `\quipucite`, a
margin figure, or an embed — it records the target's txid, its on-chain
header title, and its type byte. `book_to_tex` unions the references
across every chapter, sorts them by title, and emits the
`quipubibliography` block in the back matter (after the notes, before the
colophon). So the rendered book carries a complete, alphabetised manifest
of every inscription it draws on, each addressable by its `quipu:` link.

---

## Colophon

Back-matter inscription metadata, set in a `colophon` environment with
`\colophonentry{label}{value}` rows. `root txid` / `join txid` labels are
auto-rendered in monospace. Any `\unattached` annotations surface here,
and the block closes with a small `c1 dd 00 01 — quipu protocol` stamp.

```latex
\begin{colophon}
  \colophonentry{author}{El Gólem}
  \colophonentry{tone byte}{0x00 ordinary}
  \colophonentry{root txid}{2667151441…}
  \colophonentry{rendering}{xelatex via \texttt{colegio.cls} v0.1}
\end{colophon}
```

---

## Document skeletons

### Essay

```latex
\documentclass[essay,tone=ordinary]{colegio}
\title{…}  \persona{…}  \date{…}
\rootxid{…}  \protocolheader{c1 dd 00 01 …}
\begin{document}
\maketitle
\newthought{…} …prose…
\section{…}  …prose…  \printbacknotes
\begin{colophon} … \end{colophon}
\end{document}
```

### Book

```latex
\documentclass[book,tone=ordinary]{colegio}
\title{…}  \persona{…}  \date{…}
\rootxid{…}  \jointxid{…}  \protocolheader{c1 dd 00 01 …09…}
\begin{document}
\maketitle
\frontmatter  \tableofcontents
\mainmatter
\chapter{…}  \newthought{…} …prose…
\chapter{…}  …prose…
\backmatter
\printbacknotes
\begin{colophon} … \end{colophon}
\end{document}
```

---

## Building a book, start to finish

The next book build, in order. Two routes — pick by where the content lives.

**A. The book's content is already on chain (a `0x09` book quipu exists).**
Let the pipeline do everything:

```python
import colegio_pipeline as P
pdf = P.render_book("<book txid>", "build")     # → build/doc.pdf
```

`render_book` resolves bindings, transcludes thin-republish wrappers,
decodes every cited image/celestial to a PNG, honors render directives,
builds the References bibliography, and compiles. If the book publishes a
typeset edition (a `render/latex` entry) it compiles that exact inscribed
edition; otherwise it regenerates the `.tex` from content.

**B. Authoring a new book for inscription.**

1. Write each essay as **pure markdown + protocol extensions** — `<<txid>>`
   citations, `![cap](<<txid render="margin">>)` figures (never embed HTML),
   fenced ```` ```binding ```` blocks. Inscribe each as a `0x01` essay.
2. Inscribe the figures as `0x03` image (or `0xce` celestial) quipus.
3. Build the `0x09` book manifest (`essay/NN`, `binding`, … entries).
4. *(optional)* Publish the typeset edition so the book carries its own
   intended typesetting:
   ```python
   entry, doc_txid, class_txid = P.build_typeset_edition("<book txid>")
   # add `entry` (tag render/latex) to the book's entries, then inscribe the 0x09 book
   ```
   This inscribes `colegio.cls` once (reused thereafter — pass
   `class_txid=` to skip re-inscribing) plus the rendered `.tex`.

**What to put on chain for a reproducible typeset book** — content
(essays, images, bindings) as their native types, plus, for the LaTeX
rendering: `colegio.cls` as a `0x5c` class quipu and the rendered `.tex`
as a `0x5c` doc quipu (`class=<txid>`), referenced by a `render/latex`
book entry. TeX Live + the named fonts are the off-chain baseline. See
[`book.md`](../quipu-types/book.md) §"Optional typeset editions".

---

## Compiling

```sh
xelatex doc.tex && xelatex doc.tex      # two passes: TOC + endnotes settle
```

Check `doc.log` for `Missing character` warnings — those flag a script
the auto-fallback didn't catch (wrap with `\gk` / `\ar` / `\he`).

---

## Known edges

- **Margin crowding.** Sidenotes (`\margin`) and margin figures share the
  one outer column. If a figure and a sidenote land on the same line they
  can overlap; nudge one or move the figure call up/down a sentence.
- **Caption language.** The figure label and the TOC heading print in
  English (`Figure`, `Contents`) regardless of the document language,
  since the class does not load `babel`. Localizable if needed.
- **Hoefler Text was the original body font** and was dropped: on macOS
  it is AAT-only (no OpenType GSUB, no reachable small caps via xelatex).
  TeX Gyre Pagella replaced it precisely to get real small caps.

---

## Version

`colegio.cls` v0.1 (2026-05-23). First real-corpus render: *Dos ensayos*
(book mode), *On the Tone Byte* (essay mode).
