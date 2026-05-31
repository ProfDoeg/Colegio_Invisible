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


# Cover: a small grid of type-cells where the built ones are filled and the
# two forthcoming ones are dashed outlines — the catalog as a known shape
# with known gaps.
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
  % bottom row: forthcoming (dashed outlines, empty)
  \cellopen{7.4}{14.6}
  \cellopen{10.2}{14.6}
  \node[ink,font=\sffamily\footnotesize] at ( 7.4,14.6) {sound};
  \node[ink,font=\sffamily\footnotesize] at (10.2,14.6) {topology};
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

  % forthcoming — bottom row, dashed
  \cellopen{4.5}{2.0}{0x07}{sound}
  \cellopen{6.5}{2.0}{0x??}{topology}

  \node[ki,font=\sffamily\footnotesize,anchor=west] at (0.0,0.6)
    {built: 12 types. forthcoming: 2 types. each new type is one byte and one specification document.};
""",
"The Catalog and the Gaps — the twelve built types and the two types this "
"volume names as forthcoming. Each cell carries a byte and a short label; "
"the forthcoming two are set in dashed outlines, with byte 0x07 already "
"mentioned in earlier corpus and the other left unallocated. The 0xda dancer, "
"once forthcoming, is now built and carries its own volume. The catalog grows "
"by one byte at a time.")


# ===========================================================================
# Chapters
# ===========================================================================

PROLOGUE = essay("Prologue", r"""
A protocol is what it carries. By the time this volume was assembled the
protocol carried twelve canonical types — six primary (text, essay,
image, celestial, book, dancer) and six structural (certificate, encrypted,
binding, scene, latex, estandarte). The other bound volumes of *The Book
of Books* are the documentation of those twelve. This one is the
documentation of *what is missing*: the types that have been spoken of,
planned, partly sketched, but not yet shipped, and the example works
that the system is already shaped for but has not yet inscribed.

The volume is small on purpose. A roadmap that grows is the only roadmap
worth keeping. Each chapter is a short *note toward* — a proposed byte
layout, a sketched semantics, an honest list of the open questions. The
last chapters are *examples* the corpus already plans for: works whose
shape is settled but whose inscription is yet to come.

When one of these is built, its note is rewritten as a chapter of its own
volume in *The Book of Books* and the entry here is removed. The catalog
plate at the end of this volume will then carry one fewer dashed cell.

*This volume is the roadmap — types not yet built and works not yet
inscribed.* *It can be read on its own; it is also one of eight bound in
the Colegio Invisible's* Book of Books*.*
""")


INTRO = essay("Introduction", r"""
The protocol gains a type the same way it gained the twelve that came
before: a name, a single byte, a specification document, a builder, a
reader, and at least one inscribed work to prove the spec. This volume
walks each forthcoming type in that order — what it is for, what its byte
would mean, what its body would carry, and what would be inscribed first
to test it.

The volume is organised into two parts: *Types Not Yet Built* and
*Examples Not Yet Inscribed*. The first part covers two new types —
sound and topology. The second part covers example works whose
type already exists but whose inscription is forthcoming, beginning with
the *Goethe Southern Journey*, a timed earth figure of the kind *The
Celestial Quipu* has already specified.

The volume does not predict when the entries here will close. It does
commit to the shape they will have when they do.
""")


# ───── Types not yet built ────────────────────────────────────────────────

CH_SOUND = essay("Sound — Notes Toward 0x07", r"""
The proposed byte is 0x07. The shape is a *recording* — a named sample
with a sample rate, a duration, a number of channels, and a body of
encoded audio. The header carries the recording's title and the codec it
uses; the body carries the bytes the codec emits.

The first inscriptions the type would carry are the *audio book*: a
spoken-word reading of an essay quipu by the essay's named author or the
author's chosen reader. A book whose chapters are 0x07 audio inscriptions
is bound the same way a book of essays is bound — through 0x09 entries.
The reader of the book may render the chapter as text (when the chapter
is an essay) or as audio (when the chapter is a 0x07) — the book's
manifest does not care which.

A proposed header layout:

```
0..3   c1 dd 00 01   magic + version
4      07            type = sound
5      <tone>        tone byte
6      <codec>       00 raw PCM, 01 opus, 02 flac, 03 mp3, 04 vorbis
7      <channels>    1 mono, 2 stereo, …
8..9   <rate>        sample rate uint16 BE in Hz×100 (i.e. 441 = 44.1 kHz)
10..13 <duration>    duration in milliseconds uint32 BE
14     <T>           title length
15..   <title>       UTF-8 title
```

The body is the codec's output, broken across strands the same way an
essay body is broken — no codec-specific framing; the codec sees one
contiguous byte stream when the strands rejoin.

Open questions: whether the codec field should also carry a profile
(opus bitrate, mp3 VBR mode) or whether the codec's own header is enough;
whether *multiple takes* of the same recording should share one
inscription with a header field naming the takes, or be separate
inscriptions joined by a 0xab binding; and whether speech, music, and
ambient sound deserve different sub-bytes the way 0x0e has 0xae / 0xec
sub-families. The note is open.
""")


CH_TOPOLOGY = essay("Topology — Notes Toward a Graph Type", r"""
A genealogy is a topology. So is a citation graph, a corpus of
binding-overrides, a tree of revisions to a single work. The protocol
has no first-class graph type — it has bindings (0xab), which can express
many edges but only by inscribing them as a chain of substitutions, and
it has books (0x09), which can hold many entries but only in a flat
ordered list. A graph that is large or recursive needs its own type.

The proposed shape is a *typed directed graph*: a header carrying the
graph's title and its edge-type vocabulary, a *nodes* block (each node a
cite into another quipu), and an *edges* block (each edge an index pair
plus an edge-type index).

```
header:
  c1 dd 00 01    magic + version
  ??             type = topology  (byte to be allocated)
  <tone>         tone byte
  <directed>     00 undirected, 01 directed
  <N_hi N_lo>    node count
  <E_hi E_lo>    edge count
  <K>            edge-type vocabulary count (max 255)
  K × <namelen+name>   the edge-type names, in order
  <T>            title length
  <title>        UTF-8 title

nodes block:
  N × <txidlen> <txid_bytes>     each node = a citation

edges block:
  E × <src_hi src_lo dst_hi dst_lo type_idx>   each edge
```

A node is always a cite. The graph itself does not store content — its
nodes are quipus, its edges are typed relations between them. A
genealogy of essays whose nodes are 0x01 essay inscriptions, with edge
types `parent_of`, `commentary_on`, `translation_of`, is one inscription
that names a whole reading.

The first inscription the type would carry is the *Estandarte genealogy*
— the tree of edits to the standard itself, with edge types `revises`,
`supersedes`, `splits_into`, `merges_with`. It will be the protocol's
first inscribed account of its own evolution.

Open questions: whether the type should also accept *embedded* nodes
(a node that is a small inscription rather than a cite, for very-small
nodes that do not deserve their own diamond); whether edges should
themselves be allowed to carry tones; and whether the type should serve
both genealogies and *topology* in the strict mathematical sense — open
covers and simplicial complexes — or whether topology in that sense
deserves its own type.
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

    {"tag": "chapter/01",    "ref_txid": CH_SOUND,         "name": "Sound — Notes Toward 0x07"},
    {"tag": "chapter/02",    "ref_txid": CH_TOPOLOGY,      "name": "Topology — Notes Toward a Graph Type"},

    {"tag": "chapter/03",    "ref_txid": CH_GOETHE_JOURNEY, "name": "The Bordado Pilgrimage Atlas"},
    {"tag": "chapter/04",    "ref_txid": CH_LAVERNA_CERT,  "name": "La Verna Bordado Certificate"},
    {"tag": "chapter/05",    "ref_txid": CH_OTHER,         "name": "Other Forthcoming Works"},

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
