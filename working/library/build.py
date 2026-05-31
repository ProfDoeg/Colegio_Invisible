#!/usr/bin/env python3
"""Build "The Book of Books" — the master anthology.

A 0x09 *library* whose chapters are whole books. Each VOLUME is a complete,
self-contained book — its own cover, frontispiece, chapters, plate gallery,
References and colophon — rendered in place by the colegio pipeline's nested-
volume machinery. Today:

    Volume I    Reading and Writing Quipus   (the primer; working/tutorial)
    Volume II   The Sealed Quipu             (the 0x0e family; working/encrypted)
    Volume III  The Attested Quipu           (the 0xcc certificate; working/attested)
    Volume IV   The Walkable Quipu           (the 0x3d scene; working/scene)
    Volume V    The Typeset Quipu            (the 0x5c LaTeX type; working/latex)
    Volume VI   The Celestial Quipu          (the 0xce figure; working/celestial)
    Volume VII  The Estandarte               (the type/structure reference; working/estandarte)
    Volume VIII The Moving Quipu             (the 0xda dancer; working/moving)
    Volume IX   The Staged Quipu             (node, chain, weaving; working/staging)
    Volume X    The Forthcoming              (types and works yet to be inscribed; working/forthcoming)

Future volumes (the 0x07 audio book, the topology type) drop in as more
`volume/NN` entries — no format change, only depth.

The volume content is authored by importing the per-volume build scripts (each
inscribes its content + manifest on import); this script only adds the master
cover, a foreword, and the manifest that nests the volumes.

Run:  .venv/bin/python working/library/build.py
"""
import os
import sys
import importlib.util

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


def _load(relpath, name):
    """Load a per-volume build.py; importing it inscribes that volume's content
    and exposes its book root as module.BOOK."""
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, relpath))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


PRIMER   = _load("working/tutorial/build.py",     "vol_primer")    # Reading and Writing Quipus
SEALED   = _load("working/encrypted/build.py",    "vol_sealed")    # The Sealed Quipu
ATTESTED = _load("working/attested/build.py",     "vol_attested")  # The Attested Quipu (certs)
WALK     = _load("working/scene/build.py",        "vol_walk")      # The Walkable Quipu
TYPESET  = _load("working/latex/build.py",        "vol_typeset")   # The Typeset Quipu
CELEST   = _load("working/celestial/build.py",    "vol_celest")    # The Celestial Quipu
STANDARD = _load("working/estandarte/build.py",   "vol_standard")  # The Estandarte (reference)
MOVING   = _load("working/moving/build.py",       "vol_moving")    # The Moving Quipu (0xda dancer)
STAGING  = _load("working/staging/build.py",      "vol_staging")   # The Staged Quipu (node/chain/weave)
FORTH    = _load("working/forthcoming/build.py",  "vol_forth")     # The Forthcoming (roadmap; last)


# Master cover: books within books — nested rounded rectangles, Kandinsky.
COVER_DOC = r"""\documentclass{standalone}
\usepackage[T1]{fontenc}\usepackage{tikz}\usepackage{xcolor}
\definecolor{ink}{HTML}{1a1a1a}\definecolor{gold}{HTML}{c2a76b}\definecolor{wash}{HTML}{f3ecd8}
\definecolor{kr}{HTML}{c83727}\definecolor{ky}{HTML}{e8b73a}\definecolor{kb}{HTML}{2b62a8}\definecolor{kg}{HTML}{2a7a4d}
\begin{document}\begin{tikzpicture}[line width=1.4pt]
\fill[wash] (0,0) rectangle (17.6,25.0);
%s
\end{tikzpicture}\end{document}
"""


def cover(title, tikz):
    h, b = build_latex_quipu(title, COVER_DOC % tikz, tone=AI, fields={"author": "El Gólem"})
    return P.write_inscription(h, b)


MASTER_COVER = cover("The Book of Books", r"""
  \draw[kb] (3.8,12.2) rectangle (13.8,21.8);
  \draw[kg] (5.1,13.5) rectangle (12.5,20.5);
  \draw[kr] (6.4,14.8) rectangle (11.2,19.2);
  \draw[ky] (7.7,16.1) rectangle (9.9,17.9);
  \fill[ink] (8.8,17.0) circle (0.28);
  \node[ink,font=\fontsize{29}{33}\selectfont\itshape] at (8.8,7.6) {The Book of Books};
  \node[ink,font=\Large] at (8.8,6.0) {Colegio Invisible};
  \draw[gold,line width=2.5pt] (3.8,5.1) -- (13.8,5.1);
""")


def essay(title, body):
    h, b = build_essay_quipu(title, body, tone=AI, fields=dict(AUTH))
    return P.write_inscription(h, b)


FOREWORD = essay("Foreword", r"""
This is a library bound as a single book — a *book of books*. Each volume that
follows is itself complete: it opens with its own cover, carries its own
chapters and its own plates, and closes with its own References and colophon.
You may read any one of them alone; gathered here, they share one spine.

The first volume, *Reading and Writing Quipus*, is the primer — the diamond, the
act of inscription, and how to author a book. The second, *The Sealed Quipu*,
takes up the encrypted family; the third, *The Attested Quipu*, the certificate
and its two kinds. The fourth, *The Walkable Quipu*, leaves the page entirely for
the 3D scene type, and the small cemetery built with it. The fifth, *The Typeset
Quipu*, turns back to the page itself — the LaTeX type, and how the very setting
of these books is part of the corpus they belong to. The sixth, *The Celestial
Quipu*, takes up the 0xce figure — the named-point shape that holds a
constellation, a coastline, or a timed journey. The seventh, *The Estandarte*,
is the reference: a systematic catalog of every type and its byte layout. The
eighth, *The Moving Quipu*, takes up the 0xda dancer — the first type whose
content is movement, and the 2009 avatar engine rebuilt to prove it. The ninth,
*The Staged Quipu*, is the primer for doing this yourself: running a node,
reading the chain from tracked and untracked addresses, and weaving several
quipu into one publication by cryptographic monetary choreography. The tenth,
*The Forthcoming*, is the roadmap — types not yet built (sound, topology) and
example works not yet inscribed (the *Goethe Southern Journey* chief among
them). More volumes will arrive the way a library grows: a quipu pointing at a
quipu, with nothing changed but the depth.
""")


ENTRIES = [
    {"tag": "cover",     "ref_txid": MASTER_COVER, "name": "The Book of Books"},
    {"tag": "foreword",  "ref_txid": FOREWORD,     "name": "Foreword"},
    {"tag": "volume/01", "ref_txid": PRIMER.BOOK,   "name": "Reading and Writing Quipus"},
    {"tag": "volume/02", "ref_txid": SEALED.BOOK,   "name": "The Sealed Quipu"},
    {"tag": "volume/03", "ref_txid": ATTESTED.BOOK, "name": "The Attested Quipu"},
    {"tag": "volume/04", "ref_txid": WALK.BOOK,     "name": "The Walkable Quipu"},
    {"tag": "volume/05", "ref_txid": TYPESET.BOOK,  "name": "The Typeset Quipu"},
    {"tag": "volume/06", "ref_txid": CELEST.BOOK,   "name": "The Celestial Quipu"},
    {"tag": "volume/07", "ref_txid": STANDARD.BOOK, "name": "The Estandarte"},
    {"tag": "volume/08", "ref_txid": MOVING.BOOK,   "name": "The Moving Quipu"},
    {"tag": "volume/09", "ref_txid": STAGING.BOOK,  "name": "The Staged Quipu"},
    {"tag": "volume/10", "ref_txid": FORTH.BOOK,    "name": "The Forthcoming"},
    # Pipeline-emitted index: the ref_txid is empty by convention
    # (book.py accepts "" and stores the all-zero sentinel internally);
    # _partition_entries recognises tag=="index" and generates the
    # appendix's content rather than fetching this txid.
    {"tag": "index", "ref_txid": "", "name": "Reference Index"},
]

BOOK_FIELDS = dict(AUTH)
BOOK_FIELDS["institution"] = "Colegio Invisible"
BOOK_FIELDS["epigraph"] = ("I have always imagined that Paradise will be a kind "
                           "of library. — Jorge Luis Borges")

bh, bb = build_book_quipu("The Book of Books", ENTRIES, tone=AI, fields=BOOK_FIELDS)
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
    print("The Book of Books ->", pdf, os.path.getsize(pdf), "bytes")
    print("  chapters:", tex.count("\\chapter{"),
          " parts:", tex.count("\\part{"),
          " plates:", tex.count("\\platequipu"),
          " volumes:", tex.count("\\refstepcounter{colegiovol}"),  # one per bound volume
          " bib:", tex.count("\\quipubibitem"))
