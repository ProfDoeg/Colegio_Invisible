#!/usr/bin/env python3
"""Build "The Forthcoming" — a volume of The Book of Books: an honest catalog
of the types not yet built and the example works not yet inscribed. The
volume names what is missing and what its byte layout would look like, so
that the rest of the corpus can refer to *forthcoming* objects by what they
are going to be rather than only by what they are not.

Authored as El Gólem. Local only; not broadcast.

Run:  .venv/bin/python working/forthcoming/build.py
"""
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "canonical"))

import colegio_pipeline as P
from essay import build_essay_quipu
from latex import build_latex_quipu
from book import build_book_quipu

HERE   = os.path.dirname(os.path.abspath(__file__))
FIGDIR = os.path.join(HERE, "figures")
AI     = 0xA1
AUTH   = {"author": "El Gólem", "date": "2026-05-27", "lang": "en"}


def essay(title, body):
    h, b = build_essay_quipu(title, body, tone=AI, fields=dict(AUTH))
    return P.write_inscription(h, b)


COVER_DOC = r"""\documentclass{standalone}
\usepackage[T1]{fontenc}\usepackage{tikz}\usepackage{xcolor}
\definecolor{ink}{HTML}{1a1a1a}\definecolor{gold}{HTML}{c2a76b}\definecolor{wash}{HTML}{f3ecd8}
\definecolor{kr}{HTML}{c83727}\definecolor{ky}{HTML}{e8b73a}\definecolor{kb}{HTML}{2b62a8}\definecolor{kg}{HTML}{2a7a4d}
\definecolor{soft}{HTML}{888477}
\begin{document}\begin{tikzpicture}[line width=1.4pt]
\fill[wash] (0,0) rectangle (17.6,25.0);
%s
\end{tikzpicture}\end{document}
"""


def cover(title, tikz):
    h, b = build_latex_quipu(title, COVER_DOC % tikz, tone=AI,
                             fields={"author": "El Gólem"})
    return P.write_inscription(h, b)


# Cover: a small grid of type-cells, all filled now — the two cells that were
# once dashed gaps (sound, topology) have closed: sound is built, and topology
# folds into the celestial graph kinds. The catalog as a known, filled shape.
COVER = cover("The Forthcoming", r"""
  \def\cell#1#2#3#4{\node[draw=#3,fill=#4,minimum width=22mm,minimum height=22mm,line width=1.4pt,font=\sffamily\small,align=center] at (#1,#2) {\strut};}
  \def\cellopen#1#2{\node[draw=soft,dashed,minimum width=22mm,minimum height=22mm,line width=1.4pt,font=\sffamily\small,align=center] at (#1,#2) {\strut};}
  % top row: built types (filled)
  \cell{4.6}{20.2}{ink}{ky}
  \cell{7.4}{20.2}{ink}{kr}
  \cell{10.2}{20.2}{ink}{kg}
  \cell{13.0}{20.2}{ink}{kb}
  % mid row: built (filled, smaller saturation)
  \cell{4.6}{17.4}{ink}{wash}
  \cell{7.4}{17.4}{ink}{wash}
  \cell{10.2}{17.4}{ink}{wash}
  \cell{13.0}{17.4}{ink}{wash}
  % bottom row: the two former gaps, now filled (sound built; topology folded into celestial)
  \cell{7.4}{14.6}{ink}{wash}
  \cell{10.2}{14.6}{ink}{wash}
  \node[ink,font=\sffamily\footnotesize] at ( 7.4,14.6) {sound};
  \node[ink,font=\sffamily\footnotesize] at (10.2,14.6) {file};
  \node[ink,font=\fontsize{29}{33}\selectfont\itshape] at (8.8,7.6) {The Forthcoming};
  \node[ink,font=\Large] at (8.8,6.0) {Colegio Invisible};
  \draw[gold,line width=2.5pt] (3.8,5.1) -- (13.8,5.1);
""")


# Kandinsky composition — the catalog as a grid plate.
KAND_DOC = r"""%% Kandinsky composition — El Gólem, for The Forthcoming
\documentclass[tikz,border=4mm]{standalone}
\usepackage[utf8]{inputenc}\usepackage[T1]{fontenc}\usepackage{tikz}\usepackage{xcolor}
\definecolor{kr}{HTML}{c83727}\definecolor{ky}{HTML}{e8b73a}
\definecolor{kb}{HTML}{2b62a8}\definecolor{kg}{HTML}{2a7a4d}
\definecolor{kw}{HTML}{f4ead8}\definecolor{ki}{HTML}{1a1a1a}\definecolor{gold}{HTML}{c2a76b}
\definecolor{soft}{HTML}{888477}
\begin{document}
\begin{tikzpicture}[x=1cm,y=1cm,line width=1.4pt,font=\sffamily\footnotesize]
%s
\end{tikzpicture}
\end{document}
"""


def kplate(title, tikz, caption):
    h, b = build_latex_quipu(title, KAND_DOC % tikz, tone=AI,
                             fields={"author": "El Gólem", "caption": caption})
    return P.write_inscription(h, b)


# Plate: the catalog as a grid. Built types in solid cells with their byte;
# forthcoming types in dashed cells with proposed byte + "TBD". Reads as a
# roadmap a glance.
PLATE_CATALOG = kplate("Composition XV — The Catalog and the Gaps", r"""
  \fill[kw] (-0.5,-0.5) rectangle (14,8);
  \def\cell#1#2#3#4#5{
    \node[draw=ki,fill=kw,minimum width=18mm,minimum height=15mm,
          font=\sffamily\scriptsize,align=center] at (#1,#2) {\textbf{#3}\\[1pt] #4\\[1pt] {\color{#5} \rule{12mm}{2pt}}};
  }
  \def\cellopen#1#2#3#4{
    \node[draw=soft,dashed,minimum width=18mm,minimum height=15mm,
          font=\sffamily\scriptsize,align=center,text=soft] at (#1,#2) {\textbf{#3}\\[1pt] #4\\[1pt] \emph{TBD}};
  }
  % built types — top two rows
  \cell{1.5}{6.4}{0x00}{text}{kr}
  \cell{3.5}{6.4}{0x01}{essay}{kr}
  \cell{5.5}{6.4}{0x03}{image}{kr}
  \cell{7.5}{6.4}{0xce}{celestial}{ky}
  \cell{9.5}{6.4}{0xcc}{certificate}{ky}
  \cell{11.5}{6.4}{0x0e}{encrypted}{ky}

  \cell{1.5}{4.4}{0x09}{book}{kb}
  \cell{3.5}{4.4}{0xab}{binding}{kb}
  \cell{5.5}{4.4}{0x3d}{scene}{kb}
  \cell{7.5}{4.4}{0x5c}{latex}{kg}
  \cell{9.5}{4.4}{0xee}{estandarte}{kg}
  \cell{11.5}{4.4}{0xda}{dancer}{kg}

  % the two former gaps, now built (sound 0x07; file 0x0f). topology folds into 0xce celestial.
  \cell{4.5}{2.0}{0x07}{sound}{kr}
  \cell{6.5}{2.0}{0x0f}{file}{kb}

  \node[ki,font=\sffamily\footnotesize,anchor=west] at (0.0,0.6)
    {built: 14 types. the type roadmap is complete — every named type is built, and topology folds into 0xce celestial.};
""",
"The Catalog and the Gaps, now closed — the fourteen built types. The two cells "
"that were once dashed gaps are resolved: 0x07 sound is built (with 0x0f file "
"beside it), and topology needed no byte of its own, since the celestial type's "
"genealogy and etymology kinds already are the typed directed graph it described. "
"The 0xda dancer, once forthcoming, is likewise built. The catalog grew one byte "
"at a time, and its gaps have closed.")


# ===========================================================================
# Chapters
# ===========================================================================

PROLOGUE = essay("Prologue", r"""
A protocol is what it carries. By the time this volume was assembled the
protocol carried fourteen canonical types — seven primary (text, essay,
image, sound, celestial, book, dancer) and seven structural (certificate,
encrypted, binding, scene, latex, estandarte, file). The other bound volumes
of *The Book of Books* are the documentation of those types. This one is the
documentation of *what is missing*: it once named two forthcoming types —
sound and topology — and both are now closed (sound is built; topology is
subsumed by the celestial graph kinds), so what remains here is the example
works that the system is already shaped for but has not yet inscribed.

The volume is small on purpose, and smaller now that its type roadmap has
closed. A roadmap that empties is the only roadmap worth keeping. What its
chapters hold now are *examples* the corpus already plans for: works whose
type is settled and whose shape is fixed, but whose inscription is yet to
come.

When one of these is built, its note is rewritten as a chapter of its own
volume in *The Book of Books* and the entry here is removed. The catalog
plate at the end of this volume will then carry one fewer dashed cell.

*This volume is the roadmap — its type roadmap now complete, it carries the
works not yet inscribed.* *It can be read on its own; it is also one of eight
bound in the Colegio Invisible's* Book of Books*.*
""")


INTRO = essay("Introduction", r"""
The protocol gains a type the same way it gained the fourteen that came
before: a name, a single byte, a specification document, a builder, a
reader, and at least one inscribed work to prove the spec.

This volume once opened with a part called *Types Not Yet Built*. It named
two — *sound* and *topology* — and both have since closed. Sound was built:
byte 0x07, an audio container, with its own specification now. Topology
proved unnecessary: a typed directed graph is exactly what the celestial
type's *genealogy* and *etymology* kinds already are — nodes that cite other
quipu, edges that carry a typed-relation vocabulary — so the graph the
topology note sketched is inscribable today as a 0xce figure, with no new
byte allocated. The first part is therefore empty, and that is the volume
working as intended: its health is the rate at which it empties.

What remains is *Examples Not Yet Inscribed* — works whose type already
exists but whose inscription is forthcoming, beginning with the *Bordado
Pilgrimage Atlas*, a timed earth figure of the kind *The Celestial Quipu*
has already specified.
""")


# ───── Examples not yet inscribed ─────────────────────────────────────────

CH_GOETHE_JOURNEY = essay("The Bordado Pilgrimage Atlas", r"""
The *Bordado Pilgrimage Atlas* is a forthcoming inscription of a known
shape. It is a timed earth figure of the journey-subtype the *Celestial
Quipu* volume specifies (kind earth, tone reverence, meta on, lines
drawn as chronological arrows). It records the route the three
landscape bordados were worked from: a sequence of named places, each
with a Julian Day timestamp at year-precision for the bordado's
working dates.

The atlas follows the pattern of *Goethe's Italian Journey* — the
journey-subtype's first inscribed work, walked through in *The Celestial
Quipu*. The bordado atlas is the second proof of the same shape, and the
first whose places are in the corpus's own working hemisphere.

The points the atlas will carry, in the order they were settled:

- *Domrémy* — the village of the first bordado, attested 2025-12 by
  the Domrémy hash certificate. Earliest year-precision waypoint.
- *La Verna* — the second bordado, certificate forthcoming. Mid-route
  waypoint.
- *Cazón* — the present working place, exact-precision waypoint at the
  epoch the cemetery scene uses. Terminal waypoint of the first leg.

Each pair of waypoints is a line in the celestial inscription's body.
With timestamps on every point, the renderer draws the journey as a
chain of forward arrows. The tone byte is reverence: the atlas is
recorded for the record, not for the report.

When the second bordado's certificate settles, the atlas is inscribed.
The byte layout is already settled; what is forthcoming is the date.
""")


CH_LAVERNA_CERT = essay("La Verna Bordado Certificate", r"""
La Verna is the second of the three landscape bordados. Its image quipu
is on chain. Its all-in-one certificate (a 0xcc certificate of subtype
0x0002, in the *Domrémy* shape — image plus text plus authority) is
prepared but not yet inscribed. The certificate's title and signature
plan are settled:

- Title: *La Verna Bordado Certificate*
- Image: cite of the La Verna image quipu (on chain)
- Text: a paragraph in the El Ermitaño voice, set as the certificate's
  prose field, attesting the place and date of working
- Authority: a cite of the bordado key declaration's hash certificate
  (the three-key, self-named declaration)
- Signatories: Hayagriva, Christophia, Anthony — the three keys named
  in the declaration

The certificate's inscription will close one of the dashed cells in the
attested catalog. When it does, the third bordado's certificate becomes
the next forthcoming entry; the journey above can then carry its second
year-precision waypoint as *attested*; and the bordado atlas — a
0xce grouped figure whose groups are the three certificated bordados —
becomes inscribable as a single root.
""")


CH_OTHER = essay("Other Forthcoming Works", r"""
A short list of works whose shape is already settled by the corpus and
whose inscription is forthcoming.

- The *Estandarte v2* — a second version of the registry. v1 is on chain
  and stable and catalogs the original set. v2 adds the types built since
  it was inscribed — the 0xda dancer, now its own volume — and the
  remaining forthcoming types as they arrive. v2 will be inscribed as a
  fresh root with a `supersedes` field referencing v1's root, the same way
  the cemetery's `sky_chart` is amended without re-inscribing the scene.

- The *Book of 108 Essays* — the long-term cathedral plan. One hundred
  and eight 0x01 essays, gathered as a 0x09 book through the same
  modulo-strand and fractal-diamond pattern *The Book of Books* uses.
  Each essay carries its own handwritten-on-textile photograph as a
  0x03 image, and the book's binding (0xab) names a concept-map across
  the whole corpus.

- The *Cementerio* expansion — a second 0x3d scene whose graph extends
  the cemetery north into the *wilds* of the El Ermitaño zone and east
  into the *museum* of the HCA collection. The cemetery scene already
  reserves the portal nodes; the wilds and museum scenes are
  forthcoming.

- The *Hayagriva and Christophia* dual-publication corpus — an ongoing
  pair of 2-of-2 cross-witnessed inscriptions whose pattern is already
  set by the existing pair. Each new publication is one inscription on
  each address; the binding between them is the joint signature.

These are forthcoming in the same sense as the types above: a known
shape, an open date. The entries here will close as their roots arrive.
""")


AFTERWORD = essay("Afterword", r"""
The protocol's value is not in any one inscription but in the *shape it
allows for the next one*. The forthcoming entries in this volume are
not obligations; they are demonstrations that the shape is large enough
to hold what has been planned. When the planned things are inscribed,
the volume changes — entries close, the catalog plate loses dashed cells
— and the proof of the shape is the inscription itself.

The next time *The Book of Books* is rebuilt, this volume is the one
most likely to have grown. New types may be sketched; new examples may
be added. The volume is the corpus's account of *what it knows it can
do but has not yet done*. It is the only volume whose health is
measured by the rate at which it empties.
""")


# ===========================================================================
# Manifest
# ===========================================================================

ENTRIES = [
    {"tag": "cover",         "ref_txid": COVER,            "name": "The Forthcoming"},
    {"tag": "prologue",      "ref_txid": PROLOGUE,         "name": "Prologue"},
    {"tag": "introduction",  "ref_txid": INTRO,            "name": "Introduction"},

    {"tag": "chapter/01",    "ref_txid": CH_GOETHE_JOURNEY, "name": "The Bordado Pilgrimage Atlas"},
    {"tag": "chapter/02",    "ref_txid": CH_LAVERNA_CERT,  "name": "La Verna Bordado Certificate"},
    {"tag": "chapter/03",    "ref_txid": CH_OTHER,         "name": "Other Forthcoming Works"},

    {"tag": "afterword",     "ref_txid": AFTERWORD,        "name": "Afterword"},

    {"tag": "art/01",        "ref_txid": PLATE_CATALOG,    "name": "The Catalog and the Gaps"},
]

BOOK_FIELDS = dict(AUTH)
BOOK_FIELDS["institution"] = "Colegio Invisible"
BOOK_FIELDS["epigraph"] = ("The shape, before the inscription, is part of the "
                           "inscription. — El Gólem")

bh, bb = build_book_quipu("The Forthcoming", ENTRIES, tone=AI, fields=BOOK_FIELDS)
BOOK = P.write_inscription(bh, bb)


if __name__ == "__main__":
    fetch = P.chained_fetcher()
    tex = P.book_to_tex(BOOK, fetcher=fetch, figdir=FIGDIR)
    with open(os.path.join(HERE, "book.tex"), "w", encoding="utf-8") as f:
        f.write(tex)
    for t in set(P._QFIG_RE.findall(tex)):
        try:
            P.target_to_png(t, fetch, FIGDIR)
        except Exception as e:
            print("  [fig]", t[:12], e)
    pdf = P.compile_tex(tex, HERE, figdir=FIGDIR)
    print("The Forthcoming ->", pdf, os.path.getsize(pdf), "bytes")
    print("  chapters:", tex.count("\\chapter{"),
          " plates:", tex.count("\\platequipu"),
          " bib:", tex.count("\\quipubibitem"))
