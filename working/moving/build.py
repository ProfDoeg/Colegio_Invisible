#!/usr/bin/env python3
"""Build "The Moving Quipu" — a volume of The Book of Books: the 0xda dancer.

The first type whose content is movement. The volume takes movement apart into
three layers — recorded movement (the footage), possibility (the motion graph),
and intention (the controller) — works a real dancer (Jeremy: 2374 frames, 44
nodes, 1326 edges) all the way through, gives the statistical sampling method
that turns the graph into a dance, names the four-element symmetry group that
quadruples every inscribed clip, gives the byte layout, and tells the story of
the 2009 Max/MSP avatar engine that was lost and rebuilt to prove the type.

Authored as El Gólem. Local only; not broadcast.

Run:  .venv/bin/python working/moving/build.py
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
from image import build_image_quipu, COLOR_RGB, pack_pixels
from PIL import Image as _PIL

HERE   = os.path.dirname(os.path.abspath(__file__))
FIGDIR = os.path.join(HERE, "figures")
SRCDIR = os.path.join(HERE, "source")
AI     = 0xA1
AUTH   = {"author": "El Gólem", "date": "2026-05-30", "lang": "en"}


def essay(title, body):
    h, b = build_essay_quipu(title, body, tone=AI, fields=dict(AUTH))
    return P.write_inscription(h, b)


def _inscribe_image(relpath, title, *, max_width=900, bit_depth=6):
    """Load a PNG, downscale to max_width, inscribe as a 0x03 RGB image quipu."""
    im = _PIL.open(os.path.join(SRCDIR, relpath)).convert("RGB")
    w0, h0 = im.size
    if w0 > max_width:
        im = im.resize((max_width, round(h0 * max_width / w0)), _PIL.LANCZOS)
    w, h = im.size
    mx = (1 << bit_depth) - 1
    values = []
    for r, g, b in im.getdata():
        values += [(r * mx) // 255, (g * mx) // 255, (b * mx) // 255]
    body = pack_pixels(values, bit_depth)
    hb, bb = build_image_quipu(width=w, height=h, color=COLOR_RGB,
                               bit_depth=bit_depth, title=title, body=body, tone=AI)
    return P.write_inscription(hb, bb)


IMG_ATLAS = _inscribe_image("jeremy_atlas.png",
                            "Jeremy — atlas page 0, first six rows", max_width=940)
IMG_POSES = _inscribe_image("jeremy_poses.png",
                            "Jeremy — the seven labelled poses", max_width=1180)


# ===========================================================================
# Cover + plates (0x5c latex)
# ===========================================================================

COVER_DOC = r"""\documentclass{standalone}
\usepackage[T1]{fontenc}\usepackage{tikz}\usepackage{xcolor}
\usetikzlibrary{arrows.meta}
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


COVER = cover("The Moving Quipu", r"""
  \tikzset{nd/.style={draw=ink,fill=wash,circle,minimum size=7mm,line width=1.2pt,inner sep=0pt}}
  \foreach \x in {0,...,6}{ \node[nd] (n\x) at ({4.6+\x*1.4},18.4) {}; }
  \node[nd,fill=ky] (n3) at (8.8,18.4) {};
  \foreach \a/\b in {0/1,1/2,2/3,3/4,4/5,5/6}{ \draw[ink,-{Stealth[length=2.4mm]}] (n\a) -- (n\b); }
  \draw[kg,-{Stealth[length=2.4mm]}] (n5) to[bend left=55] (n2);
  \draw[kr,dashed,-{Stealth[length=2.4mm]}] (n6) to[bend right=70] (n1);
  \fill[kb] (8.8,14.4) circle (0.30);
  \draw[kb,dotted,line width=1.2pt] (8.8,17.9) -- (8.8,14.8);
  \node[ink,font=\fontsize{29}{33}\selectfont\itshape] at (8.8,7.6) {The Moving Quipu};
  \node[ink,font=\Large] at (8.8,6.0) {Colegio Invisible};
  \draw[gold,line width=2.5pt] (3.8,5.1) -- (13.8,5.1);
""")


PLATE_DOC = r"""\documentclass[tikz,border=4mm]{standalone}
\usepackage[utf8]{inputenc}\usepackage[T1]{fontenc}\usepackage{tikz}\usepackage{xcolor}
\usepackage{amsmath}\usepackage{amssymb}
\usetikzlibrary{arrows.meta,positioning}
\definecolor{kr}{HTML}{c83727}\definecolor{ky}{HTML}{e8b73a}
\definecolor{kb}{HTML}{2b62a8}\definecolor{kg}{HTML}{2a7a4d}
\definecolor{kw}{HTML}{f4ead8}\definecolor{ki}{HTML}{1a1a1a}\definecolor{gold}{HTML}{c2a76b}
\definecolor{soft}{HTML}{888477}
\begin{document}
\begin{tikzpicture}[x=1cm,y=1cm,line width=1.2pt,font=\sffamily\footnotesize]
%s
\end{tikzpicture}
\end{document}
"""


def plate(title, tikz, caption):
    h, b = build_latex_quipu(title, PLATE_DOC % tikz, tone=AI,
                             fields={"author": "El Gólem", "caption": caption})
    return P.write_inscription(h, b)


# Plate — the Klein four-group V4.
PLATE_V4 = plate("The Four Symmetries", r"""
  \fill[kw] (-0.6,-2.0) rectangle (12.8,7.2);
  \tikzset{el/.style={draw=ki,fill=kw,minimum width=22mm,minimum height=16mm,line width=1.1pt,align=center,font=\sffamily\small}}
  \node[el] (I)  at (2.4,5.0) {$I$\\\scriptsize identity};
  \node[el] (M)  at (6.4,5.0) {$M$\\\scriptsize mirror (space)};
  \node[el] (R)  at (2.4,1.6) {$R$\\\scriptsize reverse (time)};
  \node[el] (MR) at (6.4,1.6) {$MR$\\\scriptsize mirror+reverse};
  \draw[kb,<->] (I) -- (M)  node[midway,above,font=\scriptsize,text=kb]{$M$};
  \draw[kr,<->] (I) -- (R)  node[midway,left,font=\scriptsize,text=kr]{$R$};
  \draw[kr,<->] (M) -- (MR) node[midway,right,font=\scriptsize,text=kr]{$R$};
  \draw[kb,<->] (R) -- (MR) node[midway,below,font=\scriptsize,text=kb]{$M$};
  \node[ki,anchor=west,font=\sffamily\scriptsize] at (8.4,5.4) {$M^2 = I$};
  \node[ki,anchor=west,font=\sffamily\scriptsize] at (8.4,4.7) {$R^2 = I$};
  \node[ki,anchor=west,font=\sffamily\scriptsize] at (8.4,4.0) {$MR = RM$};
  \node[ki,anchor=west,font=\sffamily\scriptsize] at (8.4,3.3) {$V_4 \cong \mathbb{Z}_2 \times \mathbb{Z}_2$};
  \node[ki,anchor=west,font=\sffamily\scriptsize,text width=120mm] at (-0.4,-1.2)
    {Two switches — time (forward/reverse) and space (as-recorded/mirrored) — each
     an involution, the two commuting. Their group has four elements. One recorded
     clip is four dances; the graph stores which element each edge applies on arrival.};
""",
"The Four Symmetries — the renderer holds two switches, time and space. Each "
"undoes itself; the two commute. Two commuting involutions generate the Klein "
"four-group, V4 ≅ Z2 × Z2: identity, mirror, reverse, mirror-reverse. A clip "
"of a figure stepping east is, with no new bytes, also west, also east-backward, "
"also west-backward.")


# Plate — the three layers.
PLATE_LAYERS = plate("Three Layers", r"""
  \fill[kw] (-0.6,-0.8) rectangle (13.2,6.6);
  \tikzset{band/.style={minimum width=110mm,minimum height=13mm,draw=ki,line width=1.1pt,align=left,font=\sffamily\small,anchor=west}}
  \node[band,fill=kw,text=ki] (rec) at (0.4,5.2)
    {\textbf{recorded movement} \;— frames + per-frame centroid \hfill \textcolor{soft}{on chain}};
  \node[band,fill=kw,text=ki] (pos) at (0.4,3.4)
    {\textbf{possibility} \;— the motion graph: nodes and their edges \hfill \textcolor{soft}{on chain}};
  \node[band,fill=ky,text=ki] (int) at (0.4,1.6)
    {\textbf{intention} \;— the controller: who picks the branch \hfill \textcolor{kr}{supplied at play time}};
  \draw[soft,line width=2pt] (5.9,4.55) -- (5.9,4.05);
  \draw[soft,line width=2pt] (5.9,2.75) -- (5.9,2.25);
  \node[ki,anchor=west,font=\sffamily\scriptsize,text width=112mm] at (0.4,0.2)
    {The first two layers are inscribed and fixed. The third has a will and is not
     stored: a person at a keyboard, an attractor on a stage, a rule. The chain
     holds the possible; the viewer supplies the actual.};
""",
"Three Layers — recorded movement and possibility are inscribed; intention is "
"not. The dancer separates what a dance is (frames and a graph of branches) "
"from who decides which branch is taken. The chain holds the first; every "
"performance supplies the second.")


# Plate — one logical transition exploded into its V4 quartet (real: 47->207).
PLATE_QUARTET = plate("A Transition Quartet — 47 to 207", r"""
  \fill[kw] (-0.6,-2.0) rectangle (12.4,6.6);
  \tikzset{el/.style={draw=ki,fill=kw,minimum width=40mm,minimum height=15mm,line width=1.1pt,align=center,font=\sffamily\scriptsize}}
  \node[ki,font=\sffamily\small\bfseries] at (3.2,6.1) {space: same};
  \node[ki,font=\sffamily\small\bfseries] at (8.0,6.1) {space: mirror};
  \node[ki,font=\sffamily\small\bfseries,rotate=90] at (-0.2,4.6) {time: forward};
  \node[ki,font=\sffamily\small\bfseries,rotate=90] at (-0.2,1.4) {time: reverse};
  \node[el,fill=kw] (I)  at (3.2,4.6) {$I$ \;identity\\ $w=1$ \quad control 2};
  \node[el,fill=kw] (M)  at (8.0,4.6) {$M$ \;mirror\\ $w=1$ \quad control 3};
  \node[el,fill=kw] (R)  at (3.2,1.4) {$R$ \;reverse\\ $w=1$ \quad control 3};
  \node[el,fill=kw] (MR) at (8.0,1.4) {$MR$ \;both\\ $w=1$ \quad control 2};
  \node[ki,anchor=west,font=\sffamily\scriptsize,text width=118mm] at (-0.4,-1.2)
    {One logical transition (node 47 ``low1'' $\to$ node 207) is stored as four edges, one per
     element of $V_4$. Here all four are enabled ($w=1$). Control groups them by parity:
     $\{I, MR\}$ on control 2, $\{M, R\}$ on control 3 — so a control mode selects a coset.};
""",
"A Transition Quartet — the single logical move from node 47 to node 207, in "
"Jeremy's map, is four on-chain edges: one for each element of the symmetry "
"group V4. All four are enabled here. The control byte groups them by parity — "
"identity and mirror-reverse on control 2, mirror and reverse on control 3 — so "
"selecting a control mode selects a coset of the group.")


# Plate — node 47 and its nine destinations on the centroid axis (real CX).
PLATE_NEIGHBOURHOOD = plate("The Neighbourhood of Node 47", r"""
  \fill[kw] (-0.6,-1.6) rectangle (14.2,4.6);
  \draw[soft,line width=1pt] (0.2,0.4) -- (13.6,0.4);
  \foreach \cx in {0.30,0.40,0.50,0.60,0.70}{
    \pgfmathsetmacro\xx{(\cx-0.30)/0.45*13.0+0.2}
    \draw[soft] (\xx,0.30) -- (\xx,0.50) node[below=2pt,font=\sffamily\tiny,text=soft]{\cx};
  }
  \node[ki,font=\sffamily\tiny,anchor=west,text=soft] at (10.6,-0.1) {centroid $cx$ (left $\to$ right)};
  % node 47 at cx 0.614  -> x
  \pgfmathsetmacro\sx{(0.614-0.30)/0.45*13.0+0.2}
  \node[draw=ki,fill=ky,circle,minimum size=7mm,inner sep=0pt,font=\sffamily\scriptsize] (s) at (\sx,3.2) {47};
  \foreach \cx/\lab in {0.341/1521,0.351/2160,0.356/1933,0.358/2200,0.518/744,0.522/207,0.630/607,0.632/545}{
    \pgfmathsetmacro\xx{(\cx-0.30)/0.45*13.0+0.2}
    \fill[kb] (\xx,0.4) circle (2.4pt);
    \draw[kb,-{Stealth[length=1.6mm]},opacity=0.85] (s) to[bend left=8] (\xx,0.55);
    \node[font=\sffamily\tiny,text=ki,rotate=90,anchor=west] at (\xx,0.75) {\lab};
  }
  \draw[kg,-{Stealth[length=1.8mm]}] (s) to[out=140,in=40,looseness=7] (s);  % self / stay
  \node[ki,anchor=west,font=\sffamily\scriptsize,text width=120mm] at (-0.4,-1.0)
    {Node 47 (``low1'', $cx=0.614$) and its nine destinations, placed at their own
     centroids. Eight are full quartets; the self-loop (stay) keeps the dancer at rest.
     The leftward cluster near $cx\approx0.35$ are other ``low1'' rest poses on the far side
     of the stage — the dance can cut there and the body appears to cross.};
""",
"The Neighbourhood of Node 47 — the rest pose ``low1'' and the nine poses it "
"may move to, each placed on the horizontal axis at its measured centroid. Most "
"destinations are full V4 quartets; one edge is a self-loop that holds the rest. "
"The cluster on the left is the same rest pose recorded on the other side of the "
"stage, reachable by a cut.")


# Plate — all 44 nodes by centroid (x) and pose-label lane (y). Real data.
_DOTS = r"""
  \fill[kr] (0.34,3.45) circle (1.6pt);
  \fill[kr] (1.12,4.40) circle (1.6pt);
  \fill[kr] (1.16,4.40) circle (1.6pt);
  \fill[kg] (1.64,1.55) circle (1.6pt);
  \fill[kr] (2.72,3.45) circle (1.6pt);
  \fill[kb] (2.82,6.30) circle (1.6pt);
  \fill[kr] (2.82,3.45) circle (1.6pt);
  \fill[kr] (3.00,2.50) circle (1.6pt);
  \fill[kr] (3.02,2.50) circle (1.6pt);
  \fill[kb] (3.02,6.30) circle (1.6pt);
  \fill[kr] (3.06,2.50) circle (1.6pt);
  \fill[kr] (3.10,2.50) circle (1.6pt);
  \fill[kb] (3.12,6.30) circle (1.6pt);
  \fill[kg] (3.12,0.60) circle (1.6pt);
  \fill[kr] (3.12,2.50) circle (1.6pt);
  \fill[kb] (3.16,6.30) circle (1.6pt);
  \fill[kr] (3.54,2.50) circle (1.6pt);
  \fill[kr] (4.50,3.45) circle (1.6pt);
  \fill[kr] (4.80,5.35) circle (1.6pt);
  \fill[kg] (5.54,1.55) circle (1.6pt);
  \fill[kg] (6.10,1.55) circle (1.6pt);
  \fill[kg] (6.16,1.55) circle (1.6pt);
  \fill[kb] (6.36,6.30) circle (1.6pt);
  \fill[kb] (6.44,6.30) circle (1.6pt);
  \fill[kg] (7.14,0.60) circle (1.6pt);
  \fill[kg] (7.88,0.60) circle (1.6pt);
  \fill[kg] (7.98,0.60) circle (1.6pt);
  \fill[kg] (8.02,0.60) circle (1.6pt);
  \fill[kr] (8.24,3.45) circle (1.6pt);
  \fill[kr] (8.36,5.35) circle (1.6pt);
  \fill[kr] (8.42,3.45) circle (1.6pt);
  \fill[kr] (8.48,3.45) circle (1.6pt);
  \fill[kr] (8.60,3.45) circle (1.6pt);
  \fill[kb] (8.60,6.30) circle (1.6pt);
  \fill[kb] (8.64,6.30) circle (1.6pt);
  \fill[kg] (10.02,1.55) circle (1.6pt);
  \fill[kg] (10.04,0.60) circle (1.6pt);
  \fill[kg] (11.00,1.55) circle (1.6pt);
  \fill[kr] (11.66,2.50) circle (1.6pt);
  \fill[kg] (12.42,1.55) circle (1.6pt);
  \fill[kr] (12.60,2.50) circle (1.6pt);
  \draw[ki,line width=0.8pt] (8.28,6.30) circle (3.6pt);
"""

PLATE_CENTROIDMAP = plate("Jeremy's 44 Nodes", r"""
  \fill[kw] (-2.4,-0.4) rectangle (14.0,7.4);
  \foreach \y/\name/\c in {6.30/low1/kb, 5.35/praise1/kr, 4.40/praise2/kr, 3.45/praise3/kr, 2.50/praise4/kr, 1.55/{elbow\_pop}/kg, 0.60/{elbow\_pop2}/kg}{
    \draw[soft,dotted] (0,\y) -- (13.2,\y);
    \node[anchor=east,font=\sffamily\scriptsize,text=\c] at (-0.2,\y) {\name};
  }
""" + _DOTS + r"""
  \foreach \cx in {0.30,0.45,0.60,0.75}{
    \pgfmathsetmacro\xx{(\cx-0.20)/0.65*13.0}
    \draw[soft] (\xx,-0.05) -- (\xx,0.05) node[below=1pt,font=\sffamily\tiny,text=soft]{\cx};
  }
  \node[ki,font=\sffamily\tiny,anchor=west,text=soft] at (9.8,-0.30) {centroid $cx$ $\to$};
  \node[ki,font=\sffamily\scriptsize,anchor=west] at (-2.4,7.0) {ringed: the start node 47};
""",
"Jeremy's 44 Nodes — every branch point in the dance, placed by its pose label "
"(rows) and its measured centroid (left to right). The seven labels are the "
"vocabulary of the piece: a low rest, four rising ``praise'' poses, two "
"elbow-pops. The horizontal spread is the dancer crossing the stage; the same "
"label appears at several centroids because the pose was recorded at several "
"positions. The ringed node is the rest pose the dance starts from.")


# Plate — the Boltzmann selection at a symmetric node.
PLATE_SAMPLING = plate("How the Attractor Chooses", r"""
  \fill[kw] (-0.6,-2.6) rectangle (12.8,5.2);
  \node[draw=ki,fill=ky,circle,minimum size=8mm,inner sep=0pt,font=\sffamily\scriptsize] (n) at (0.8,2.2) {node};
  \tikzset{ed/.style={draw=ki,fill=kw,minimum width=15mm,minimum height=8mm,font=\sffamily\scriptsize,align=center}}
  \node[ed] (e1) at (4.0,4.2) {edge $i$\\ $w_i=1$};
  \node[ed] (e2) at (4.0,2.2) {edge $j$\\ $w_j=1$};
  \node[ed] (e3) at (4.0,0.2) {edge $k$\\ $w_k=0$};
  \draw[ki,-{Stealth[length=1.6mm]}] (n) -- (e1);
  \draw[ki,-{Stealth[length=1.6mm]}] (n) -- (e2);
  \draw[soft,-{Stealth[length=1.6mm]},dashed] (n) -- (e3) node[midway,above,font=\sffamily\tiny,text=soft]{gated off};
  \node[anchor=west,font=\sffamily\scriptsize] (s1) at (6.0,4.2) {$d_i=|land_i-x_{ball}|$};
  \node[anchor=west,font=\sffamily\scriptsize] (s2) at (6.0,2.2) {$d_j=|land_j-x_{ball}|$};
  \node[draw=kr,fill=kw,anchor=west,font=\sffamily\scriptsize,align=left,inner sep=4pt] at (6.0,0.6)
    {$s_i = w_i\,e^{-\beta d_i}$,\quad $\beta=2$\\[2pt]
     $P(i)=\dfrac{s_i}{\sum_\ell s_\ell}$ \;(draw)};
  \node[ki,anchor=west,font=\sffamily\scriptsize,text width=120mm] at (-0.4,-1.6)
    {At a symmetric node the gated-on edges are scored by how near their predicted landing falls
     to the attractor, turned into a probability by a Boltzmann weight, and one is drawn. The
     dance stays alive because it samples, not maximises; $\beta$ sets how hard it chases.};
""",
"How the Attractor Chooses — at a symmetric node the enabled edges are scored "
"by the distance from their predicted landing to the attractor, that distance is "
"turned into a Boltzmann weight s = w·exp(−β d) with temperature β, the weights "
"are normalised to a probability, and one edge is drawn at random. Sampling, not "
"maximising, keeps the motion natural; β tunes how decisively the dancer chases.")


# Plate — the excursion is the propagator (flow) of the motion.
PLATE_FLOW = plate("The Excursion as a Flow", r"""
  \fill[kw] (-0.8,-1.6) rectangle (13.8,6.9);
  \node[ki,anchor=west,font=\normalsize] at (-0.4,6.1) {$\displaystyle \delta v=\sum_{k\ge 1}\frac{M^{k}v}{k!}=(e^{M}-I)\,v$};
  \node[ki,anchor=west,font=\normalsize] at (-0.4,4.8) {$\displaystyle v_{\mathrm{next}}=v+\delta v=e^{M}v$};
  \node[ki,anchor=west,font=\small,text width=70mm] at (-0.4,3.4) {$M$ — the \emph{transition matrix} of the motion graph (steps between edges)};
  \node[ki,anchor=west,font=\small,text width=70mm] at (-0.4,2.4) {$e^{M}$ — its \emph{communicability} operator: every walk weighted by $1/k!$};
  \node[soft,anchor=west,font=\footnotesize,text width=70mm] at (-0.4,1.1) {the state diffuses forward along the graph's transitions; short walks dominate};
  % the motive field + a streamline
  \begin{scope}[shift={(8.8,0.1)}]
    \foreach \x in {0,...,3}{ \foreach \y in {0,...,3}{
      \draw[soft,->,line width=0.5pt] (\x*1.15,\y*1.05) -- ++(0.55,0.40); }}
    \draw[kr,line width=1.7pt,->] (0.15,0.35) .. controls (1.5,1.2) and (2.7,2.1) .. (3.7,3.25);
    \fill[ki] (0.15,0.35) circle (2.2pt) node[below left,font=\scriptsize]{$v$};
    \fill[kr] (3.7,3.25) circle (2.2pt) node[right,font=\scriptsize,text=kr]{$v_{\mathrm{next}}=e^{M}v$};
  \end{scope}
""",
"The Excursion as a Flow — M is the transition matrix of the motion graph, the "
"allowed steps between edges. Its exponential e^M is the graph's communicability "
"operator: it sums every walk between two edges, weighting a length-k walk by "
"1/k!, so short walks dominate. The next state v_next = e^M v is the current one "
"diffused a step forward along the graph's transitions (arrows). M is the "
"connectivity of the motion, not a reflection and not an involution; the "
"handedness choice only seeds which edge the body starts from.")


# Plate — the relational form: similarity ⊗ reflection, parity = handedness.
PLATE_RELATIONAL = plate("The Relational Form", r"""
  \fill[kw] (-0.8,-2.4) rectangle (13.8,6.9);
  \node[ki,anchor=west,font=\normalsize] at (-0.4,6.2) {$M_{ij}=\langle f_i,f_j\rangle=M_{ji}\quad\text{(similarity: a symmetric Gram matrix)}$};
  \node[ki,anchor=west,font=\normalsize] at (-0.4,4.9) {$A=M\otimes R,\qquad R^{2}=I$};
  \node[ki,anchor=west,font=\normalsize] at (-0.4,3.5) {$\displaystyle e^{M\otimes R}=\sum_{k\ge0}\frac{M^{k}\otimes R^{k}}{k!}=\cosh(M)\otimes I+\sinh(M)\otimes R$};
  \node[soft,anchor=west,font=\footnotesize,text width=128mm] at (-0.4,2.3) {$\cosh M\otimes I$ — even-length walks, handedness kept;\quad $\sinh M\otimes R$ — odd-length walks, handedness flipped};
  % each step is one reflection through a similar frame: handedness = walk parity
  \begin{scope}[shift={(1.4,-0.4)}]
    \foreach \i/\x in {0/0,1/2.6,2/5.2,3/7.8}{ \node[draw=ki,fill=kw,circle,minimum size=7mm,inner sep=0pt,font=\scriptsize] (n\i) at (\x,0){$f_{\i}$}; }
    \foreach \a/\b in {0/1,1/2,2/3}{ \draw[ki,->,line width=1.1pt] (n\a)--(n\b); }
    \node[font=\scriptsize,text=kg] at (0,-0.9){R \,(even)};
    \node[font=\scriptsize,text=kr] at (2.6,-0.9){L \,(odd)};
    \node[font=\scriptsize,text=kg] at (5.2,-0.9){R \,(even)};
    \node[font=\scriptsize,text=kr] at (7.8,-0.9){L \,(odd)};
    \node[soft,font=\footnotesize,text width=95mm,anchor=west] at (-0.2,-1.7){each step is one reflection through a similar frame, so handedness is the parity of the walk length};
  \end{scope}
""",
"The Relational Form — the transition matrix is a similarity, M_ij = ⟨f_i, f_j⟩, "
"a symmetric Gram matrix built only from relations between frames. Paired with "
"the handedness reflection R (R² = I) by the outer product M ⊗ R, its "
"communicability splits by walk parity: e^(M⊗R) = cosh(M) ⊗ I + sinh(M) ⊗ R. "
"Even-length walks keep handedness (cosh), odd-length walks flip it (sinh) — so "
"walk parity is handedness, and position and facing are one entangled "
"relational state.")


# ===========================================================================
# Chapters
# ===========================================================================

PROLOGUE = essay("Prologue", r"""
The other volumes inscribe things that hold still. A text holds still. An
essay holds still. An image holds still, and a celestial figure is a fixed
set of points; a scene is a room you walk, but the room does not walk you.
The dancer is the first type whose content is movement, and movement is not
a thing that can be stored. Only what movement leaves behind can be stored:
a sequence of frames, a record of where the mass center was in each, and a
graph of which frame may follow which. The dancer is built from those three
records and from a fourth thing that is not stored at all — the intention
that chooses, at each branch, which way to go.

This volume works one real dancer all the way through. His name in the files
is Jeremy: 2374 recorded frames, 44 branch points, 1326 edges between them,
seven named poses. The plates are his actual atlas and his actual graph, and
the sampling chapter is the actual rule that turns that graph into a dance
that follows a moving target. The system was built once, in 2009, in Max/MSP
and Jitter, then lost, then rebuilt for the corpus. The rebuilding is the
proof of the type. What the old patch did with a video plane on an OpenGL
surface and a table of weighted transitions, the 0xda dancer does with frames
on chain and a transition graph carried in eighty-byte knots. The dance is the
same dance. Only the substrate changed.

*This volume can be read on its own; it is also one of the books bound in the
Colegio Invisible's* Book of Books*.*
""")


INTRO = essay("Introduction", r"""
A dancer is three layers and one byte.

The three layers are recorded movement, possibility, and intention. Recorded
movement is the footage — the frames a camera or a renderer actually produced,
in the order they were produced. Possibility is the motion graph — the frames
at which the dance may branch, and the branches available at each. Intention is
the controller — whatever, at a branch, picks the branch. The first two layers
are inscribed. The third is not: it is supplied at play time.

The one byte is 0xda. It marks an inscription as a motion sprite: a header
naming the dance, a footage block of frames and centroids, and a transition
graph. The byte has three variants — a self-contained *performance*, a
reusable *footage* asset, and a *controller* that references a footage by its
txid, the way a keydrop references the sealed thing it opens.

The chapters take the recorded movement first, then a full look at the one
dancer the volume follows, then the motion graph and the four-element symmetry
that quadruples every clip, then the statistical method that turns the graph
into a dance, then the controller that aims it, then the compensation that
hides cuts, then the byte layout, then the resurrection that proved it all.
""")


CH_RECORDED = essay("The Recorded Movement", r"""
The footage is the floor the whole type stands on. It is a recorded sequence
of frames — one clip, played the way a clip is played: one frame after the
next, forward, and, when the dance asks for it, backward.

Two things are recorded with each frame. The first is the frame itself. For
the dancer it is a sparse-palette sprite: a one-bit mask saying which pixels
are the figure and which are empty, a small palette of the colors that appear,
and one palette index per opaque pixel. A dancer is mostly empty space around
a moving figure, and the sparse encoding pays only for the figure — a
transparent pixel costs one mask bit and nothing more.

The second is the centroid: the horizontal position of the figure's mass
center in that frame. It is the alpha-weighted mean column, divided by the
width so it lands in [0, 1]:

```
cx = ( Σ_x  x · alpha(x) ) / ( Σ_x alpha(x) ) / width
```

where alpha(x) is the total opacity of column x. It is measured once, at
authoring time, and stored, so the renderer never recomputes it. Jeremy's
centroids run from 0.21 to 0.84 — the full width of the stage he crosses.

The centroid is what makes the footage move. Between two adjacent frames the
figure shifts a little — a step, a lean, a turn — and the centroid shifts with
it. Play the frames in order and the centroid traces the path the body
actually took. This is the natural movement of the character, and it is free:
it costs nothing beyond the frames, because it is already in the frames. The
renderer reads the centroid, places the frame so the mass center lands where
the centroid says, and the dancer moves because the footage moves.

Forward is +1: advance one frame. Backward is −1: retreat one frame. A clip
of a figure stepping east, played backward, is the same figure pulling its
weight back. The footage holds both directions; the renderer chooses the sign.
""")


CH_JEREMY = essay("A Specific Dancer", r"""
The dancer the rest of this volume follows is recorded in a file called
*jeremy2png.mov*. Decoded to frames it is 2374 images of one man in a
black-and-gold striped shirt, dancing across a stage. He is the worked example
for every abstraction that follows: when the next chapters say *frame*,
*node*, *centroid*, *label*, they mean his.

The frames are held for playback in an *atlas* — the frames downsampled and
packed into a grid, so the renderer can show any frame by an offset into a
texture rather than by seeking a movie. Jeremy's atlas is 2374 cells of 165 by
64 pixels, twelve to a row, thirty-two rows to a page, seven pages in all. One
page, cropped to its first six rows, is below.

![Jeremy's atlas — the first six rows of page 0. Each cell is one downsampled
frame, 165 by 64 pixels; the figure is small and the cell is mostly the
transparent margin around it. That margin is exactly what the sparse encoding
does not pay for.](<<%(ATLAS)s render="full">>)

The cells are mostly empty. A dancer occupies a narrow vertical band in a wide
frame, and everything around him is transparent. This is the argument for the
sparse-palette sprite of the previous chapter, made visible: the atlas is
mostly margin, and the encoding charges only for the figure.

The 2374 frames are not all branch points. Forty-four of them are *nodes* —
the frames at which the dance may do something other than step by one. Each
node carries a *label* naming the pose it holds, and Jeremy's whole vocabulary
is seven labels: a low rest (*low1*), four rising *praise* poses
(*praise1* through *praise4*), and two *elbow-pops*. The seven, one
representative frame each, are below.

![Jeremy's seven poses, left to right: low1, praise1, praise2, praise3,
praise4, elbow\_pop, elbow\_pop2 — the labels that name his forty-four
nodes.](<<%(POSES)s render="full">>)

These seven are the words. The motion graph is the grammar — which pose may
follow which — and the chapters from here build it up, then set it moving.
""" % {"ATLAS": IMG_ATLAS, "POSES": IMG_POSES})


CH_GRAPH = essay("The Motion Graph", r"""
A clip played start to end and then stopped is a film. A clip that can branch
is a dance. The motion graph is what makes the second possible.

The graph marks certain frames as nodes — frames at which the dance may do
something other than advance by one. At every other frame there is exactly one
move: step to the next frame in the recorded order, or the previous, if running
backward. At a node there is a choice. For each node the graph stores the edges
that leave it, and each edge carries an operation, a destination, the centroid
displacement it accumulates, and a label:

- *stay* — hold at the node.
- *forward* — continue along the recorded order from the destination, +1.
- *backward* — continue in reverse from the destination, −1.
- *tunnel* — cut across the clip to a far frame, skipping the frames between.

Jeremy's graph has 44 nodes and 1326 edges. The edges are not 1326 different
moves: they come in *quartets*. Every logical transition — node A to node B —
is stored four times, once for each combination of time (forward / reverse)
and space (as-recorded / mirrored). Each of the four carries a *weight*, which
in Jeremy's map is a single bit: 1 if that combination is allowed, 0 if it is
not. The start node, frame 47, has nine distinct destinations and thirty-six
edges — nine quartets. Eight quartets are fully enabled; the ninth, the
self-loop that keeps him at rest, has only its two forward combinations on,
because reversing in place is degenerate.

Each edge also carries a *control* byte. Control is the dance's mode — Jeremy's
is the energy of the movement — and the renderer plays only the edges whose
control matches the mode it is in. The control values partition the quartet:
in the transition from node 47 to node 207, identity and mirror-reverse sit on
control 2, mirror and reverse on control 3. A control mode therefore selects a
*coset* of the symmetry group, and switching modes switches which half of every
quartet is live.

The plates of this chapter are Jeremy's actual graph: one quartet exploded
into its four edges, the neighbourhood of node 47 laid out by centroid, and all
forty-four nodes placed by pose and position. The graph says what may follow
what. It does not say what will. That is the next two chapters.
""")


CH_SYMMETRIES = essay("The Four Symmetries", r"""
Every inscribed clip is four clips. The renderer holds two switches — time and
space — each with two settings, and the four combinations are four different
dances drawn from the same bytes.

Time is direction: forward (+1) or reverse (−1). Space is handedness: as
recorded, or mirrored about the vertical axis. Mirror a figure stepping east
and it steps west. Reverse it and it un-steps. Mirror and reverse it and it
un-steps west. One recorded clip of a figure stepping east is also a clip
stepping west, a clip stepping east backward, and a clip stepping west
backward — four for the price of one.

The two switches are involutions: apply mirror twice and you are back where
you started; apply reverse twice and you are back where you started. They
commute — mirror-then-reverse equals reverse-then-mirror. Two commuting
involutions generate a group of four elements: identity, mirror, reverse, and
mirror-reverse. This is the Klein four-group, written V4, isomorphic to
Z2 × Z2. The dancer's transform symmetry is exactly this group, and the
renderer's two switches are its two generators.

This is why the edges come in quartets. The graph does not store four unrelated
moves; it stores one move and the four ways the group acts on it. And the poses
sort into three kinds by how the mirror treats them:

- *same side* — the mirror carries the pose to a different pose. The connecting
  edge keeps the current handedness. No choice; the figure continues as it was.
- *reflected* — the only path out is the mirrored one. The edge forces a flip.
  No choice either; the figure must turn.
- *symmetric* — the pose is its own mirror. Both handedness settings are
  available. This is the one place the dance is free to choose left from right.

These three kinds are the mirror's orbits over the poses. In Jeremy's map they
are marked 1, 2, 3, and the marking is lopsided: forty-three of his
forty-four nodes are symmetric and one is reflected. The whole system's freedom
of direction therefore lives almost everywhere — at a symmetric pose there are
exactly two options, and choosing between them is how the dancer turns.
""")


CH_SAMPLING = essay("The Statistical Sampling", r"""
The graph offers, at each node, a set of edges. Something has to choose one.
The choice is a weighted random draw, and the way the weights are made is the
whole behaviour of the dance.

Start with the base draw. At a node, take the edges that are enabled under the
current control mode — the ones with weight 1 whose control byte matches the
mode. Call them the *live* set. Absent any other influence, the next edge is
drawn from the live set in proportion to its weight:

```
P(i) = w_i / Σ_ℓ w_ℓ           (categorical draw over the live edges)
```

Because Jeremy's weights are bits, this is a uniform draw over whatever is
live. The original Max patch added an *entropy term* to this draw — a small
`−p · ln p` pressure that lifted the probability of edges the dance had not
taken recently. Its only job was to keep the walk from collapsing onto one
loop: a pure uniform draw will, by chance, fall into short cycles, and the
entropy term spreads the mass back out so the dance keeps finding new poses.
It is regularisation, not steering.

Steering comes from the attractor, and it enters only at symmetric nodes —
the only nodes with a real choice of handedness. There the draw is no longer
uniform. Each live edge is scored by where it would take the body and how near
that lands to the attractor:

```
land_i = bodyX + δv
δv     = Σ_{k≥1} (1/k!) · ( cx(n_k, m_i) − cx(n_{k−1}, m_i) ) · PW
d_i    = | land_i − x_ball |
s_i    = w_i · exp( −β · d_i )        β = 2
P(i)   = s_i / Σ_ℓ s_ℓ                (draw)
```

The score `s_i` is a Boltzmann weight: an edge whose predicted landing falls on
the attractor (`d_i → 0`) gets the full weight, and the weight falls off
exponentially as the landing strays. The temperature `β` sets how hard the
dance chases: large `β` makes it nearly always pick the closest-landing edge,
small `β` makes it wander. At `β = 2` it leans toward the ball but still
samples, so the motion stays alive rather than snapping to a target.

The look-ahead `δv` is the part worth pausing on. From a candidate exit the
controller follows the recorded order, summing the centroid steps it would
accumulate, but weighting the kth step by $1/k!$. Collect the motion graph's
*transition matrix between edges* as $M$ — its entries the allowed steps from
one edge to the next, the connectivity of the motive field — and let $v$ be the
current state. Then $Mv$ propagates the state one step, $M^{k}v$ propagates it
$k$ steps, and the factorial-weighted sum of all of them is a matrix
exponential:

$$\delta v \;=\; Mv+\tfrac{1}{2!}M^{2}v+\tfrac{1}{3!}M^{3}v+\cdots\;=\;\bigl(e^{M}-I\bigr)\,v$$

So the displacement is $\delta v=(e^{M}-I)v$, and the next state is the current
one diffused a step forward through the graph:

$$v_{\mathrm{next}} \;=\; v+\delta v \;=\; e^{M}v$$

Here $M$ is the transition matrix of the motion graph, not a reflection, so it
is in general no involution and there is no cosh–sinh shortcut. Its exponential
$e^{M}$ is the graph's *communicability* operator: the $(i,j)$ entry sums every
walk of every length from edge $i$ to edge $j$, weighting a length-$k$ walk by
$1/k!$, so short walks dominate. $v_{\mathrm{next}}=e^{M}v$ is therefore the
state carried forward along the graph's own transitions, the near future
counting most. (This $M$ is distinct from the space-mirror of *The Four
Symmetries*: that mirror is the discrete handedness, an involution; this $M$ is
the connectivity of the motion itself.) The handedness choice at a symmetric
pose only seeds which edge the body starts from; $e^{M}$ then diffuses it.

The factorial weights self-truncate — $1/k!$ vanishes fast — so the controller
stores no horizon and no discount constant, only $\beta$ and the transition
matrix $M$. The running prototype approximates $e^{M}v$ by following a single
forward path; the matrix form is its principled generalisation, diffusing over
every branch at once. The controller never commits to a multi-step plan; it
takes one diffused step, lands, and scores again.
""")


CH_RELATIONAL = essay("The Relational Form", r"""
The transition matrix has a shape the last chapter left unopened. A dance cuts
from one frame to another only where the two frames are alike — a seam between
similar poses is invisible, a seam between unlike ones jolts. So the natural
transition is a *similarity*: the entry of $M$ between frame $i$ and frame $j$ is
their inner product,

$$M_{ij} = \langle f_i, f_j \rangle .$$

$M$ is then a Gram matrix — built entirely from pairwise relations between
frames, with no absolute feature of any single frame anywhere in it. Because
similarity is symmetric, $M = M^{\top}$, and the transition probability out of a
frame is just its row of $M$, normalised. Everything the graph knows about
motion is *how alike its frames are*.

Handedness is the other coordinate, and it is a reflection $R$ with $R^{2}=I$
that swaps left for right. A state of the dance is therefore not a frame alone
but a frame paired with a handedness — a vector in the tensor space
$(\text{frames}) \otimes (\text{handedness})$.

The step that carries the dance forward acts on both coordinates at once: it
moves to a similar frame *and* carries the reflection. Its operator is the outer
product of the two,

$$A = M \otimes R,$$

and the look-ahead is its communicability — the matrix exponential of the
sampling chapter, now applied to the joint object:

$$e^{M\otimes R} = \sum_{k\ge0} \frac{M^{k}\otimes R^{k}}{k!}.$$

Here the structure opens. Because $R^{2}=I$, the reflection's powers alternate —
$R^{k}=I$ when $k$ is even, $R$ when $k$ is odd — so collecting the even and odd
powers of $M$ separates the sum into the matrix hyperbolic functions of the
similarity:

$$e^{M\otimes R} = \cosh(M)\otimes I + \sinh(M)\otimes R,$$

with $\cosh(M)=\sum_{k\ \mathrm{even}} M^{k}/k!$ and
$\sinh(M)=\sum_{k\ \mathrm{odd}} M^{k}/k!$. Since $M$ is symmetric these are
well-defined symmetric matrices and $e^{M}$ is positive-definite — the
relational geometry is an honest one.

The two terms read directly as motion. $\cosh(M)\otimes I$ diffuses through the
graph and *keeps* the handedness; $\sinh(M)\otimes R$ diffuses and *flips* it.
Every reflection is one step to a similar frame, so an even-length walk returns
the body to its original handedness and an odd-length walk reverses it — and the
communicability weight $1/k!$ makes the short walks count most. Walk parity *is*
handedness. Position and facing are not two facts the renderer tracks
separately; they are one entangled state, and the choice at a symmetric pose is
the projection that fixes the parity.

So the dance is relational through and through. Nothing in it is an absolute
property of a frame; it is built from inner products — how alike the frames are —
tensored with a reflection — which way the body faces. The scalar
$\cosh(1)\,I+\sinh(1)\,M$ that first appeared by mistake was this very formula
collapsed onto a single frame. The honest object is the communicability of a
similarity graph entangled with reflection, and
$v_{\mathrm{next}} = e^{M\otimes R}\,v$ is the relational state carried one step
forward.
""")


CH_CONTROLLER = essay("The Controller", r"""
The first two layers are inscribed and fixed. The third is supplied at play
time and is the only layer with a will. In the original system it was a person
at a keyboard moving a camera. In the resurrection it is an attractor — a ball
the viewer slides across the stage — and the sampling rule of the previous
chapter, which draws the dancer toward it.

The controller's loop is small. Step the frame, ±1. If the new frame is a
node, run the draw: build the live set, and if the node is symmetric, score
each live edge by the Boltzmann weight on its predicted landing and draw;
otherwise draw on the base weights. Take the drawn edge — its destination, its
time direction, its handedness — and continue. That is the whole intention. It
has exactly one real decision, made only at symmetric poses: keep the present
handedness or flip it. Keeping continues the motion the way it was going;
flipping turns it to the other side.

Everything the controller could do and chooses not to do is as important as
what it does. It does not steer the body between poses — the body moves only by
its recorded centroid. It does not plan a route — its reach is the
self-truncating `e^M` excursion, a stride and no committed plan. It does not
snap to the target — it samples, so
two runs toward the same ball are different dances. The attractor is a bias on a
random draw, not a destination the dancer walks to. That is why the chase looks
like a dancer noticing something and drifting toward it, and not like a cursor
moving to a point.
""")


CH_COMPENSATION = essay("Compensation", r"""
A node may carry a tunnel — a destination frame far from the current one. At a
tunnel the centroid jumps: the body was here and is now there, with no frames
between. In Jeremy's graph this is common — the rest pose *low1* is recorded
both near centroid 0.62 and near 0.35, the two sides of the stage, and an edge
can cut from one to the other. Placed naively, the figure teleports across the
floor.

The fix is to move the world the opposite of the way the body jumped. The
dancer is drawn on a plane. At a tunnel the plane shifts by exactly the
centroid difference — the old centroid minus the new — so that the body, which
jumped in frame coordinates, stays put in stage coordinates:

```
offX += ( cx(prev, m_prev) − cx(dst, m_new) ) · PW
```

The teleport happens in the data and is cancelled in the placement. The viewer
sees the pose change but not the position jump, which is what a real cut
between two poses of one dancer looks like: the stance changes, the dancer does
not lurch across the floor. A facing flip is compensated the same way, since
mirroring moves the centroid across the figure's own width.

Between tunnels there is no compensation and no sliding. The body moves by its
own recorded centroid, frame by frame — the natural movement of the first
chapter. The plane holds still and the figure walks across it. Position is the
recorded centroid plus an offset that changes only at cuts. Nothing is
smoothed, interpolated, or eased. A dance that slides is a dance with a bug.
""")


CH_BYTES = essay("The Byte Layout — 0xda", r"""
The three layers are three variants, plus a fourth that holds all of them at
once. The header carries the variant byte:

```
0..3   c1 dd 00 01   magic + protocol version 0.1
4      da            type = dancer
5      <tone>        tone byte
6      <variant>     01 performance | 02 footage | 03 graph | 04 controller
7      <T>           title length, then the UTF-8 title
```

A *footage* (0x02) is a recording — the heavy, reusable asset. A *graph* (0x03)
is the cut topology, and it carries a footage *table* that may include footage
inline or cite it by txid. A *controller* (0x04) is the intention; it cites a
graph and carries the control logic. A *performance* (0x01) carries a graph and
controllers inline — a whole dancer in one inscription. The portability is in
the citations: a new controller over an old graph re-skins the intention; a new
graph over an old footage re-skins the choreography; the expensive footage is
inscribed once and cited.

The footage block is a shared palette and a run of tight sprites:

```
pal_n   palette size (1..255)        ib = ceil(log2 pal_n)
N       frame count (uint16)
pal_n × (r g b)                      the palette, 8-bit per channel
nw nh   notional frame (uint16 each)     fps (uint8)
N × frame:
  x y w h        bbox in the notional frame (uint16 each)
  cx cy          centroid (the anchor), notional-frame fraction (float32)
  facing         front | back | profile_r | profile_l
  mask           w·h bits, 1 = opaque
  idx            one ib-bit palette index per opaque pixel
```

Every fidelity knob — palette size, the notional dimensions, the frame rate —
rides in the header, so each footage declares its own resolution and a renderer
reads it; the recommended house profile is sixteen colours, a hundred-and-
twenty-eight-pixel frame, one-bit alpha, thirty frames a second.

The footage table is where one dancer holds one recording or many, included or
referenced:

```
Nfoot u8 · Nfoot × entry:
  kind u8   00 inline → <footage block>
            01 ref    → txid (32 bytes)
```

The graph is the footage table, a label vocabulary, then nodes and edges:

```
<footage table>
Nmode u8                              control modes
Llab u8 · Llab × (len + UTF-8 name)   pose labels (low1, praise…)
start u16
Nn u16
Nn × node:  foot u8 · ord u16 · label u8 · sym u8 · narc u8
edges (per node, narc each):
  dst u16 · flags u8 (bit0 time fwd/rev, bit1 space same/mirror) · ctrl u8
```

A frame reference is `(foot, ord)` — which footage in the table, which frame in
it — so the graph can stitch a dance across several clips. An edge stores only
its destination, its V4 element (time and space, the two flag bits), and the
control mode it belongs to. The operation — stay, step, or cut — and the
displacement are *derived*: a cut is a different footage or a non-adjacent
ordinal, and the displacement is the difference of two footage centroids. The
graph stores only the edges that exist; preference weights live in the
controller.

The controller is a list — a dancer may carry several whole control patches,
each toggled live — and each controller is methods, preference-sets, and
bindings:

```
Nctrl u8 · default_ctrl u8
Nctrl × controller:
  start u16 · mode0 u8
  Nmethod u8 · default_method u8
  Nmethod × method:  id u8 · plen u8 · params[plen]
  Npref u8 · Npref × pref:  name · Nw × (node u16 · edge u8 · weight u8)
  Nbind u8 · Nbind × binding:  source u8 · port u8 · scale f32
```

The methods are the registry of selectors — uniform, weighted, boltzmann,
quantum, keyboard. The standard ones carry only initial parameters: boltzmann
its temperature and excursion gain, quantum its generator choice and measurement
rate. They store no per-edge data, because the algorithm is the renderer's; the
inscription supplies defaults the viewer can change. Only two carry data — the
*preference* sets, which are the per-edge weights any method may draw on, and
the *keyboard* map. The *bindings* wire the live inputs — the attractor's
position, the keys — onto the selector's ports. The `plen` on every method lets
a reader skip a method it does not know, so the registry can grow without
breaking old readers.

The economy is in the layering. Jeremy's frames are one footage, inscribed
once; a graph that cites it carries only the forty-four nodes and their edges; a
controller that cites the graph carries only a few dozen bytes of intention. One
footage answers to many graphs, one graph to many controllers, and a single
self-contained performance can bundle the lot — footage, cut topology, and a
library of controllers — in one inscription.
""")


CH_RESURRECTION = essay("The Resurrection", r"""
The type was specified from a working system, not invented for the chain. In
2009 the dance ran as a Max/MSP and Jitter patch: a metronome ticking every
twenty milliseconds drove an accumulator that stepped a video plane forward or
backward one frame at a time; a `coll` keyed by frame number held the
transition map; at tagged frames a reader did a weighted-random draw — a table
of weights plus the entropy term of the sampling chapter — filtered by the live
control; a centroid object placed the plane; and a keyboard navigator, standing
in for intention, produced a small target vector the draw leaned toward. Two
controls switched the dance: time forward or reverse, and space normal or
mirror. The whole avatar was that loop.

The resurrection kept the loop and changed the surface. The accumulator, the
±1 stepping, the weighted-random draw, the entropy term, the reverse, the
mirror, the centroid placement, and the intention vector all carried over. What
changed: the video plane became the preloaded atlas of the *Specific Dancer*
chapter, stepped by texture offset rather than by seeking a movie, because
seeking a movie desynchronizes the picture from the position and the figure
flickers and teleports; the keyboard camera became the attractor; and the
intention vector, once re-derived, turned out to be the Boltzmann draw over the
`e^M` excursion of the sampling chapter, run at `β = 2` — the factorial
look-ahead whose operator `e^M` is the motion graph's transition matrix
exponentiated.

Three things were learned in the rebuilding and are worth keeping. Seeking is
the enemy: frame-exact playback wants frames already in memory, not a decoder
chasing timestamps. Sliding is a bug, not a smoothing: the only honest motion
is the recorded centroid, with cuts hidden by compensation, never by easing.
And the chase is not steering: the dancer reaches the ball by sampling
handedness at symmetric poses, and by nothing else. The old patch knew all
three. The new one had to learn them again to believe them.
""")


AFTERWORD = essay("Afterword", r"""
Movement is now a first-class object in the corpus. It joins text, image,
figure, scene, and book as a thing the chain can hold — but it holds movement
the way it holds nothing else, by holding only what is fixed about it and
leaving what is free to the moment of performance.

The separation is the point. A dance is frames and a graph of branches; a
performance is a controller sampling branches. The chain keeps the first, which
is the same every time. The viewer supplies the second, which is different
every time — a draw, not a script. So the dancer is the first inscription that
is never the same twice, and is nonetheless permanent: the set of all its
performances is fixed on chain, and only which one you see is decided when you
look.

Jeremy is one footage and one graph. The next dancer need not re-inscribe a
body; it can cite his and carry a new intention, or a new control mode, or a
new attractor rule. A corpus of dances over a small set of bodies is a small
set of footages and a growing set of controllers — the bodies inscribed once,
the intentions added one cheap quipu at a time.
""")


# ===========================================================================
# Manifest
# ===========================================================================

ENTRIES = [
    {"tag": "cover",        "ref_txid": COVER,             "name": "The Moving Quipu"},
    {"tag": "prologue",     "ref_txid": PROLOGUE,          "name": "Prologue"},
    {"tag": "introduction", "ref_txid": INTRO,             "name": "Introduction"},

    {"tag": "chapter/01",   "ref_txid": CH_RECORDED,       "name": "The Recorded Movement"},
    {"tag": "chapter/02",   "ref_txid": CH_JEREMY,         "name": "A Specific Dancer"},
    {"tag": "chapter/03",   "ref_txid": CH_GRAPH,          "name": "The Motion Graph"},
    {"tag": "chapter/04",   "ref_txid": CH_SYMMETRIES,     "name": "The Four Symmetries"},
    {"tag": "chapter/05",   "ref_txid": CH_SAMPLING,       "name": "The Statistical Sampling"},
    {"tag": "chapter/06",   "ref_txid": CH_RELATIONAL,     "name": "The Relational Form"},
    {"tag": "chapter/07",   "ref_txid": CH_CONTROLLER,     "name": "The Controller"},
    {"tag": "chapter/08",   "ref_txid": CH_COMPENSATION,   "name": "Compensation"},
    {"tag": "chapter/09",   "ref_txid": CH_BYTES,          "name": "The Byte Layout — 0xda"},
    {"tag": "chapter/10",   "ref_txid": CH_RESURRECTION,   "name": "The Resurrection"},

    {"tag": "afterword",    "ref_txid": AFTERWORD,         "name": "Afterword"},

    {"tag": "art/01",       "ref_txid": PLATE_V4,          "name": "The Four Symmetries"},
    {"tag": "art/02",       "ref_txid": PLATE_QUARTET,     "name": "A Transition Quartet"},
    {"tag": "art/03",       "ref_txid": PLATE_NEIGHBOURHOOD, "name": "The Neighbourhood of Node 47"},
    {"tag": "art/04",       "ref_txid": PLATE_CENTROIDMAP, "name": "Jeremy's 44 Nodes"},
    {"tag": "art/05",       "ref_txid": PLATE_SAMPLING,    "name": "How the Attractor Chooses"},
    {"tag": "art/06",       "ref_txid": PLATE_FLOW,        "name": "The Excursion as a Flow"},
    {"tag": "art/07",       "ref_txid": PLATE_RELATIONAL,  "name": "The Relational Form"},
    {"tag": "art/08",       "ref_txid": PLATE_LAYERS,      "name": "Three Layers"},
]

BOOK_FIELDS = dict(AUTH)
BOOK_FIELDS["institution"] = "Colegio Invisible"
BOOK_FIELDS["epigraph"] = ("The chain holds the possible; the viewer supplies "
                           "the actual. — El Gólem")

bh, bb = build_book_quipu("The Moving Quipu", ENTRIES, tone=AI, fields=BOOK_FIELDS)
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
    print("The Moving Quipu ->", pdf, os.path.getsize(pdf), "bytes")
    print("  chapters:", tex.count("\\chapter{"),
          " plates:", tex.count("\\platequipu"),
          " figures:", tex.count("\\imagequipu"),
          " bib:", tex.count("\\quipubibitem"))
