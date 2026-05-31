#!/usr/bin/env python3
"""Build "The Moving Quipu" — a volume of The Book of Books: the 0xda dancer.

The first type whose content is movement. The volume takes movement apart into
three layers — recorded movement (the footage), possibility (the motion graph),
and intention (the controller) — names the four-element symmetry group that
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

HERE   = os.path.dirname(os.path.abspath(__file__))
FIGDIR = os.path.join(HERE, "figures")
AI     = 0xA1
AUTH   = {"author": "El Gólem", "date": "2026-05-30", "lang": "en"}


def essay(title, body):
    h, b = build_essay_quipu(title, body, tone=AI, fields=dict(AUTH))
    return P.write_inscription(h, b)


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


# Cover: a motion graph as the spine of the type — a row of frame-nodes with
# forward arcs, one loop back, one long dashed cut, a symmetric node filled
# gold, and an attractor dot below that the dance leans toward.
COVER = cover("The Moving Quipu", r"""
  \tikzset{nd/.style={draw=ink,fill=wash,circle,minimum size=7mm,line width=1.2pt,inner sep=0pt}}
  \foreach \x in {0,...,6}{
    \node[nd] (n\x) at ({4.6+\x*1.4},18.4) {};
  }
  \node[nd,fill=ky] (n3) at (8.8,18.4) {};       % symmetric node — the free choice
  \foreach \a/\b in {0/1,1/2,2/3,3/4,4/5,5/6}{
    \draw[ink,-{Stealth[length=2.4mm]}] (n\a) -- (n\b);
  }
  \draw[kg,-{Stealth[length=2.4mm]}] (n5) to[bend left=55] (n2);          % loop
  \draw[kr,dashed,-{Stealth[length=2.4mm]}] (n6) to[bend right=70] (n1);  % cut
  \fill[kb] (8.8,14.4) circle (0.30);                                     % attractor
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


# Plate 1 — the motion graph. The recorded line, the nodes on it, and the four
# kinds of thing that can happen at a node: stay, forward, backward, tunnel.
PLATE_GRAPH = plate("The Motion Graph", r"""
  \fill[kw] (-0.6,-1.4) rectangle (14.2,4.2);
  \tikzset{nd/.style={draw=ki,fill=kw,circle,minimum size=8mm,line width=1.1pt,inner sep=0pt,font=\sffamily\scriptsize}}
  \tikzset{pl/.style={draw=soft,fill=kw,circle,minimum size=4.5mm,inner sep=0pt}}
  % the recorded frame line
  \foreach \x in {0,...,11}{ \node[pl] (p\x) at (\x*1.2,1.6) {}; }
  \foreach \x [evaluate=\x as \y using int(\x+1)] in {0,...,10}{
    \draw[soft,-{Stealth[length=1.6mm]}] (p\x) -- (p\y);
  }
  % nodes sit ON certain frames
  \node[nd] (a) at (0*1.2,1.6) {};
  \node[nd,fill=ky] (b) at (4*1.2,1.6) {};
  \node[nd] (c) at (7*1.2,1.6) {};
  \node[nd] (d) at (11*1.2,1.6) {};
  % stay / forward / backward / tunnel
  \draw[kg,-{Stealth[length=2.2mm]}] (b) to[bend left=60] (a);          % backward
  \draw[kb,-{Stealth[length=2.2mm]}] (c) to[bend left=45] (d);          % forward
  \draw[kr,dashed,-{Stealth[length=2.2mm]}] (d) to[bend right=70] (b);  % tunnel (cut)
  \draw[ki,-{Stealth[length=2.2mm]}] (a) to[out=120,in=60,looseness=8] (a);  % stay
  \node[ki,font=\sffamily\scriptsize,anchor=west] at (0.0,-0.6)
    {\textcolor{ki}{$\bullet$}~stay\quad
     \textcolor{kb}{$\bullet$}~forward\quad
     \textcolor{kg}{$\bullet$}~backward\quad
     \textcolor{kr}{$\bullet$}~tunnel (cut)\quad
     \textcolor{ky}{$\bullet$}~symmetric node (free flip)};
  \node[ki,font=\sffamily\scriptsize,anchor=west] at (0.0,-1.1)
    {grey line: the recorded frame order. circles: nodes — the only frames at which the dance may branch.};
""",
"The Motion Graph — the recorded frames laid out as a line, with nodes marked "
"on certain frames. Off a node the only move is +1 or −1 along the line. At a "
"node the graph offers edges: stay in place, go forward, go backward, or tunnel "
"across the clip to a far frame. The gold node is symmetric: its pose is its "
"own mirror, so it is the one place the dance is free to choose handedness.")


# Plate 2 — the Klein four-group V4: the four renderer transforms as a square,
# with the Cayley table that says any two composed give a third.
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
  % laws
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


# Plate 3 — the three layers, stacked: what is on chain and what is supplied.
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

This volume is also the account of a system built once, in 2009, in Max/MSP
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

The chapters take the three layers in order, then the symmetry that quadruples
every inscribed clip, then the byte layout, then the resurrection that proved
all of it.
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

The second is the centroid: the position of the figure's mass center in that
frame, stored as a fraction of the original frame so it survives rescaling.
It is measured once, at authoring time, and kept, so the renderer never
recomputes it.

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

An edge that loops from a late node back to an early one is the figure
returning to a pose it held before and going on from there. A tunnel is a cut:
the figure was in one pose and is now in another, with the frames between
skipped. Each edge also carries a weight, so a weighted-random draw over a
node's edges reproduces the statistics the dance was authored with.

This is possibility, and only possibility. The graph says what may follow
what. It does not say what will. A dance with a rich graph has many futures
from every node; which future is realized is not in the graph. That is the
third layer.
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

The graph records the group in its edges. Besides destination and weight, an
edge carries the time and the facing it sets on arrival — the element of V4 the
dance applies at that branch. And the poses sort into three kinds by how the
mirror treats them:

- *same side* — the mirror carries the pose to a different pose. The connecting
  edge keeps the current handedness. No choice; the figure continues as it was.
- *reflected* — the only path out is the mirrored one. The edge forces a flip.
  No choice either; the figure must turn.
- *symmetric* — the pose is its own mirror. Both handedness settings are
  available. This is the one place the dance is free to choose left from right.

These three kinds are the mirror's orbits over the poses. The whole system's
freedom of direction lives at the symmetric poses: everywhere else there is no
handedness to decide, and at a symmetric pose there are exactly two options.
Choosing between them is how the dancer turns.
""")


CH_CONTROLLER = essay("The Controller", r"""
The first two layers are inscribed and fixed. The third is supplied at play
time and is the only layer with a will. In the original system it was a person
at a keyboard moving a camera. In the resurrection it is an attractor — a ball
the viewer slides across the stage — and a rule that draws the dancer toward
it.

The rule has one decision to make, and it makes it only at symmetric poses. At
a symmetric pose the dancer may keep its handedness or flip it. Keeping it
continues the motion in the present direction; flipping it turns the motion to
the other side. The controller looks ahead from each option and asks: if I
leave this pose this way, where does the body's center end up? It picks the
option whose answer lands nearest the ball.

Looking ahead is a discounted sum. From a candidate exit the controller
follows the recorded order a few frames, adds up the centroid displacements it
would accumulate, and discounts each step by a half — the first step counts
fully, the second half, the third a quarter:

```
excursion = M v + ½ M² v + ¼ M³ v + …
```

where v is the centroid step and M is the mirror the candidate sets. The
discount is not decoration. A path that moves toward the ball now and away
later should not win on the strength of where it ends up six frames out. The
near future is worth more than the far future, because the far future will be
re-decided at the next symmetric pose anyway. The controller never commits to
a multi-step plan; it commits to the next handedness, lands at the next pose,
and decides again.

This is the whole chase. There is no steering, no path-finding, no sliding.
The dancer is drawn to the ball because at each symmetric pose it turns the
way that takes its center toward the ball — and it is at symmetric poses, and
only there, that it can turn at all.
""")


CH_COMPENSATION = essay("Compensation", r"""
A node may carry a tunnel — a destination frame far from the current one. At a
tunnel the centroid jumps: the body was here and is now there, with no frames
between. Placed naively, the figure teleports. The viewer sees a body vanish
and reappear a stride away. The dance is ruined.

The fix is to move the world the opposite of the way the body jumped. The
dancer is drawn on a plane. At a tunnel the plane shifts by exactly the
centroid difference — the old centroid minus the new — so that the body, which
jumped forward in frame coordinates, stays put in stage coordinates. The
teleport happens in the data and is cancelled in the placement. The viewer
sees the pose change but not the position jump, which is what a real cut
between two poses of one dancer looks like: the stance changes, the dancer
does not lurch across the floor. A facing flip is compensated the same way,
since mirroring moves the centroid across the figure's own width.

Between tunnels there is no compensation and no sliding. The body moves by its
own recorded centroid, frame by frame — the natural movement of the first
chapter. The plane holds still and the figure walks across it. Position is the
recorded centroid plus an offset that changes only at cuts. Nothing is
smoothed, interpolated, or eased. A dance that slides is a dance with a bug.
""")


CH_BYTES = essay("The Byte Layout — 0xda", r"""
The header is the usual one, with a variant byte:

```
0..3   c1 dd 00 01   magic + protocol version 0.1
4      da            type = dancer
5      <tone>        tone byte
6      <variant>     01 performance | 02 footage | 03 controller
7      <T>           title length
8..    <title>       UTF-8 title
```

The body is two codecs, used according to the variant. *Performance* carries
both; *footage* carries only the first; *controller* carries a 32-byte footage
txid in place of the first, then the second.

The footage codec is a shared palette and a run of frames:

```
pal_n   palette size (1..255)
N       frame count (uint16)
ib      index bits = ceil(log2 pal_n)
pal_n × (r g b)              the palette
N × frame:
  w h            sprite dims (uint16 each)
  cx cy          centroid, original-frame fraction (float32 each)
  facing         front | back | profile_r | profile_l
  mask           w·h bits, 1 = opaque
  idx            one ib-bit palette index per opaque pixel
```

The graph codec is nodes then edges:

```
Nn      node count (uint16)
Nn × frame_index (uint16)            the frames that are nodes
Ne      edge count (uint16)
Ne × edge:
  src dst        node frame indices (uint16 each)
  op             stay | forward | backward | tunnel
  span_a span_b  frame span the edge covers (uint16 each)
  dx dy          net centroid displacement (float32 each)
  facing_delta   facing change applied on arrival
  label          idle | step | turn | gesture
```

Facing is an orthogonal transform, not an edge type: a frame stores its facing,
an edge stores a facing delta, and the renderer's mirror switch composes with
both. Time direction is the op (forward / backward); the cut is the tunnel op;
handedness is facing. The three together are the element of V4 the edge applies.

The split into variants is the dancer's economy. Footage is heavy and
reusable; a controller is light. One inscribed footage can answer to many
controllers — the same dancer, danced by different intentions — each a small
0xda that cites the footage and carries only a graph.
""")


CH_RESURRECTION = essay("The Resurrection", r"""
The type was specified from a working system, not invented for the chain. In
2009 the dance ran as a Max/MSP and Jitter patch: a metronome ticking every
twenty milliseconds drove an accumulator that stepped a video plane forward or
backward one frame at a time; a `coll` keyed by frame number held the
transition map; at tagged frames a reader did a weighted-random draw — a table
of weights plus an entropy term — filtered by the live control state; a
centroid object placed the plane; and a keyboard navigator, standing in for
intention, produced a small target vector the selection leaned toward. Two
controls switched the dance: time (forward or reverse) and space (normal or
mirror). The whole avatar was that loop.

The resurrection kept the loop and changed the surface. The accumulator,
the ±1 stepping, the weighted-random draw, the reverse, the mirror, the
centroid placement, and the intention vector all carried over unchanged in
spirit. What changed: the video plane became a preloaded atlas of frames,
stepped by texture offset rather than by seeking a movie, because seeking a
movie desynchronizes the picture from the position and the figure flickers and
teleports; the keyboard camera became the attractor; and the selection, once
re-derived, turned out to be the discounted excursion at symmetric poses
described two chapters back.

Three things were learned in the rebuilding and are worth keeping. Seeking is
the enemy: frame-exact playback wants frames already in memory, not a decoder
chasing timestamps. Sliding is a bug, not a smoothing: the only honest motion
is the recorded centroid, with cuts hidden by compensation, never by easing.
And the chase is not steering: the dancer reaches the ball by choosing
handedness at symmetric poses, and by nothing else. The old patch knew all
three. The new one had to learn them again to believe them.
""")


AFTERWORD = essay("Afterword", r"""
Movement is now a first-class object in the corpus. It joins text, image,
figure, scene, and book as a thing the chain can hold — but it holds movement
the way it holds nothing else, by holding only what is fixed about it and
leaving what is free to the moment of performance.

The separation is the point. A dance is frames and a graph of branches; a
performance is a controller choosing branches. The chain keeps the first, which
is the same every time. The viewer supplies the second, which is different
every time. So the dancer is the first inscription that is never the same
twice, and is nonetheless permanent: the set of all its performances is fixed
on chain, and only which one you see is decided when you look.

The footage is heavy and the controllers are light. The next dancer need not
re-inscribe a body; it can cite one and carry a new intention. A corpus of
dances over a small set of bodies is a small set of footages and a growing set
of controllers — the bodies inscribed once, the intentions added one cheap
quipu at a time.
""")


# ===========================================================================
# Manifest
# ===========================================================================

ENTRIES = [
    {"tag": "cover",        "ref_txid": COVER,           "name": "The Moving Quipu"},
    {"tag": "prologue",     "ref_txid": PROLOGUE,        "name": "Prologue"},
    {"tag": "introduction", "ref_txid": INTRO,           "name": "Introduction"},

    {"tag": "chapter/01",   "ref_txid": CH_RECORDED,     "name": "The Recorded Movement"},
    {"tag": "chapter/02",   "ref_txid": CH_GRAPH,        "name": "The Motion Graph"},
    {"tag": "chapter/03",   "ref_txid": CH_SYMMETRIES,   "name": "The Four Symmetries"},
    {"tag": "chapter/04",   "ref_txid": CH_CONTROLLER,   "name": "The Controller"},
    {"tag": "chapter/05",   "ref_txid": CH_COMPENSATION, "name": "Compensation"},
    {"tag": "chapter/06",   "ref_txid": CH_BYTES,        "name": "The Byte Layout — 0xda"},
    {"tag": "chapter/07",   "ref_txid": CH_RESURRECTION, "name": "The Resurrection"},

    {"tag": "afterword",    "ref_txid": AFTERWORD,       "name": "Afterword"},

    {"tag": "art/01",       "ref_txid": PLATE_GRAPH,     "name": "The Motion Graph"},
    {"tag": "art/02",       "ref_txid": PLATE_V4,        "name": "The Four Symmetries"},
    {"tag": "art/03",       "ref_txid": PLATE_LAYERS,    "name": "Three Layers"},
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
          " bib:", tex.count("\\quipubibitem"))
