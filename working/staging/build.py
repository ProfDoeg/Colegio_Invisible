#!/usr/bin/env python3
"""Build "The Staged Quipu" — a volume of The Book of Books: the primer for
making and reading inscriptions yourself.

How to download the Dogecoin blockchain and run a node; how to read quipu data
from addresses you track and from addresses you do not; how to stage a new
piece as a diamond of transactions; and how to weave several quipu into one
publication — an integrated, concerted work made by cryptographic monetary
choreography.

Authored as El Gólem. Local only; not broadcast.

Run:  .venv/bin/python working/staging/build.py
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


# Cover: the diamond — one root fanning to parallel strands, converging on one
# join. The shape every inscription takes; the shape the whole volume teaches.
COVER = cover("The Staged Quipu", r"""
  \tikzset{nd/.style={draw=ink,fill=wash,circle,minimum size=5mm,line width=1.1pt,inner sep=0pt}}
  \node[nd,fill=ky] (root) at (4.4,17.6) {};
  \node[nd,fill=kg] (join) at (13.2,17.6) {};
  \foreach \i/\y/\c in {0/19.8/kr,1/18.6/kb,2/17.4/kr,3/16.2/kb,4/15.0/kr}{
    \node[nd] (a\i) at (6.6,\y) {};
    \node[nd] (b\i) at (8.8,\y) {};
    \node[nd] (c\i) at (11.0,\y) {};
    \draw[\c,-{Stealth[length=2mm]}] (root) -- (a\i);
    \draw[\c,-{Stealth[length=2mm]}] (a\i) -- (b\i);
    \draw[\c,-{Stealth[length=2mm]}] (b\i) -- (c\i);
    \draw[\c,-{Stealth[length=2mm]}] (c\i) -- (join);
  }
  \node[ink,font=\sffamily\footnotesize,anchor=east] at (4.0,17.6) {root};
  \node[ink,font=\sffamily\footnotesize,anchor=west] at (13.6,17.6) {join};
  \node[ink,font=\fontsize{27}{31}\selectfont\itshape] at (8.8,7.6) {The Staged Quipu};
  \node[ink,font=\Large] at (8.8,6.0) {Colegio Invisible};
  \draw[gold,line width=2.5pt] (3.4,5.1) -- (14.2,5.1);
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


# Plate 1 — the diamond, labelled: root, id, strands of knots, join.
PLATE_DIAMOND = plate("The Diamond", r"""
  \fill[kw] (-0.6,-1.4) rectangle (13.6,6.4);
  \tikzset{nd/.style={draw=ki,fill=kw,circle,minimum size=6mm,line width=1.1pt,inner sep=0pt,font=\sffamily\scriptsize}}
  \tikzset{kn/.style={draw=soft,fill=kw,rectangle,minimum width=4mm,minimum height=4mm,inner sep=0pt}}
  \node[nd,fill=ky] (root) at (0.6,2.6) {};
  \node[nd,fill=kg] (join) at (12.4,2.6) {};
  \foreach \r/\y in {0/4.6,1/3.5,2/2.4,3/1.3,4/0.2}{
    \node[kn] (s\r a) at (3.2,\y) {};
    \node[kn] (s\r b) at (5.6,\y) {};
    \node[kn] (s\r c) at (8.0,\y) {};
    \node[kn] (s\r d) at (10.0,\y) {};
    \draw[soft,-{Stealth[length=1.6mm]}] (root) -- (s\r a);
    \draw[soft,-{Stealth[length=1.6mm]}] (s\r a) -- (s\r b);
    \draw[soft,-{Stealth[length=1.6mm]}] (s\r b) -- (s\r c);
    \draw[soft,-{Stealth[length=1.6mm]}] (s\r c) -- (s\r d);
    \draw[soft,-{Stealth[length=1.6mm]}] (s\r d) -- (join);
  }
  \node[ki,font=\sffamily\scriptsize] at (0.6,1.7) {root};
  \node[ki,font=\sffamily\scriptsize] at (12.4,1.7) {join};
  \node[ki,font=\sffamily\scriptsize,anchor=west] at (3.0,5.5) {strand 0 (the header)};
  \node[ki,font=\sffamily\scriptsize,anchor=west] at (-0.4,-0.7)
    {one funding input $\to$ N parallel strands of 80-byte knots $\to$ one joining tx. the join's txid is the inscription's address.};
""",
"The Diamond — every inscription has this shape. A root transaction splits one "
"funding input across N strand outputs; each strand is an independent chain of "
"transactions whose OP_RETURN knots carry 80 bytes apiece; a joining "
"transaction spends all N strand ends back into one output. The join's txid is "
"the address by which the whole inscription is named and cited.")


# Plate 2 — the three phases of an orchestrated weave.
PLATE_PHASES = plate("Instantiate, Fill, Close", r"""
  \fill[kw] (-0.6,-1.4) rectangle (13.8,5.6);
  \tikzset{nd/.style={draw=ki,fill=kw,circle,minimum size=4.2mm,line width=1pt,inner sep=0pt}}
  % phase 1 — instantiate
  \node[ki,font=\sffamily\small\bfseries] at (2.0,4.9) {1 · instantiate};
  \node[nd,fill=ky] (r) at (0.6,2.6) {};
  \foreach \i/\y in {0/3.6,1/3.0,2/2.4,3/1.8,4/1.2}{ \node[nd] (o\i) at (3.0,\y) {}; \draw[soft,-{Stealth[length=1.4mm]}] (r) -- (o\i); }
  \node[ki,font=\sffamily\scriptsize] at (2.0,0.4) {1 input $\to$ N outputs};
  % phase 2 — fill
  \node[ki,font=\sffamily\small\bfseries] at (7.0,4.9) {2 · fill};
  \foreach \i/\y in {0/3.6,1/3.0,2/2.4,3/1.8,4/1.2}{
    \node[nd] (f\i a) at (5.6,\y) {}; \node[nd] (f\i b) at (6.7,\y) {};
    \node[nd] (f\i c) at (7.8,\y) {}; \node[nd] (f\i d) at (8.9,\y) {};
    \draw[soft,-{Stealth[length=1.4mm]}] (f\i a) -- (f\i b);
    \draw[soft,-{Stealth[length=1.4mm]}] (f\i b) -- (f\i c);
    \draw[soft,-{Stealth[length=1.4mm]}] (f\i c) -- (f\i d);
  }
  \node[ki,font=\sffamily\scriptsize] at (7.2,0.4) {N strands grow in parallel};
  % phase 3 — close
  \node[ki,font=\sffamily\small\bfseries] at (11.8,4.9) {3 · close};
  \node[nd,fill=kg] (j) at (13.0,2.6) {};
  \foreach \i/\y in {0/3.6,1/3.0,2/2.4,3/1.8,4/1.2}{ \node[nd] (c\i) at (10.8,\y) {}; \draw[soft,-{Stealth[length=1.4mm]}] (c\i) -- (j); }
  \node[ki,font=\sffamily\scriptsize] at (11.8,0.4) {N inputs $\to$ 1 output};
  \node[ki,font=\sffamily\scriptsize,anchor=west] at (-0.4,-0.9)
    {a weave precomputes and signs everything offline, then broadcasts: root first, the N strands in parallel, the join last.};
""",
"Instantiate, Fill, Close — the orchestrator's three phases. Instantiate "
"broadcasts the root, which fans one input into N strand outputs. Fill "
"broadcasts the N strands in parallel, each an independent ancestor chain, so "
"a large body is written in the time of one strand rather than the sum of all "
"of them. Close broadcasts the joining transaction, naming the inscription.")


# Plate 3 — two reading paths: tracked and untracked.
PLATE_READING = plate("Two Ways to Read", r"""
  \fill[kw] (-0.6,-1.0) rectangle (13.6,6.4);
  \tikzset{bx/.style={draw=ki,fill=kw,minimum width=34mm,minimum height=9mm,line width=1pt,align=center,font=\sffamily\scriptsize}}
  % tracked
  \node[ki,font=\sffamily\small\bfseries] at (3.2,5.7) {tracked};
  \node[bx,fill=ky] (t1) at (3.2,4.6) {your wallet / imported address};
  \node[bx] (t2) at (3.2,3.0) {listtransactions};
  \node[bx] (t3) at (3.2,1.4) {data/quipu\_data.csv\\+ data/bodies/};
  \draw[ki,-{Stealth[length=2mm]}] (t1) -- (t2);
  \draw[ki,-{Stealth[length=2mm]}] (t2) -- (t3);
  % untracked
  \node[ki,font=\sffamily\small\bfseries] at (9.8,5.7) {untracked};
  \node[bx,fill=kb,text=kw] (u1) at (9.8,4.6) {a 64-hex txid};
  \node[bx] (u2) at (9.8,3.0) {gettransaction + decoderawtransaction\\(or getrawtransaction with -txindex)};
  \node[bx] (u3) at (9.8,1.4) {walk the diamond $\to$ bytes};
  \draw[ki,-{Stealth[length=2mm]}] (u1) -- (u2);
  \draw[ki,-{Stealth[length=2mm]}] (u2) -- (u3);
  \node[ki,font=\sffamily\scriptsize,anchor=west,text width=128mm] at (-0.4,-0.5)
    {tracked: the node already watches the address, so you page its transactions. untracked: you start from a known txid and walk the strands yourself. either way the bytes are the same.};
""",
"Two Ways to Read — a tracked address is one the node already watches, so its "
"transactions are paged with listtransactions and folded into the local "
"dataset. An untracked address is read from a starting txid by walking its "
"strands transaction by transaction. The first is bulk and indexed; the second "
"is direct and needs nothing imported. The bytes recovered are identical.")


# ===========================================================================
# Chapters
# ===========================================================================

PROLOGUE = essay("Prologue", r"""
The other volumes describe what is on the chain. This one describes how to put
something there, and how to take something back off. It is the only volume that
assumes you intend to run the machinery yourself.

Nothing here is secret and nothing here is hard. A quipu is an ordinary pattern
of ordinary Dogecoin transactions, readable by any node and writable by anyone
with coins and patience. What follows is the order of operations: stand up a
node, point it at the chain, read what is already inscribed, then stage and
broadcast your own. The last chapter is about doing this with more than one
inscription at once — composing several quipu into a single deliberate work,
which is where the craft is.

*This volume can be read on its own; it is also one of the books bound in the
Colegio Invisible's* Book of Books*.*
""")


INTRO = essay("Introduction", r"""
To read and write quipu you need three things: a node, a way to find the bytes,
and a way to lay new bytes down.

The node is a copy of Dogecoin Core watching the network. The finding is two
procedures — one for addresses your node already tracks, one for any address at
all. The laying-down is the diamond: a root transaction, parallel strands of
OP_RETURN knots, and a joining transaction whose txid becomes the inscription's
name.

The chapters proceed in that order. The node first. Then reading from tracked
addresses, where the node does the bookkeeping for you, and from untracked
addresses, where you walk the transactions yourself. Then staging one piece.
Then weaving several into one publication — the choreography of paying the
chain to publish a structure larger than any single transaction can hold. The
tools named throughout are the corpus's own: `colegio_tools.py` for reading,
`update_quipu_data.py` for the bulk dataset, and `quipu_orchestrator.py` for
broadcasting a diamond. They are thin. You could write them again from this
volume.
""")


CH_NODE = essay("The Node", r"""
A node is a copy of Dogecoin Core that has downloaded the chain and stays
connected to the network. You need one. Reading a quipu means reading
transactions, and transactions live on the chain; writing one means
broadcasting transactions, and only a node will relay them.

Install Dogecoin Core and start the daemon — `dogecoind` — with an RPC
username and password set in the configuration file. The first start begins
the *initial block download*: the node connects to peers and pulls the chain
from genesis forward, validating as it goes. This takes hours to a day and tens
of gigabytes. Watch it with `dogecoin-cli getblockchaininfo`; the
`verificationprogress` field climbs to 1.0 as the node catches up.

You have a choice of two modes. A *full* node keeps every block on disk. A
*pruned* node, started with `prune=` set to a size in megabytes, validates the
whole chain but discards old block data once it is past, keeping only what is
needed to stay current. Pruned is enough to run a wallet, watch addresses, and
broadcast. It is not enough for one specific call — `getrawtransaction` on an
arbitrary historical transaction — which needs a full transaction index
(`txindex=1`) and therefore a full node. The next chapters are written so that
a pruned node suffices wherever it can, and say plainly where a full node is
required.

Every operation in this volume is an *RPC call* to this node. The corpus wraps
them in one function, `rpc_request(method, params)`, which posts a JSON request
to the node's RPC port and returns the result. Everything else is built on it.
""")


CH_TRACKED = essay("Reading a Tracked Address", r"""
An address is *tracked* when your node's wallet watches it — either because the
wallet owns its key, or because you told the node to watch it without the key
using `importaddress`. A tracked address is cheap to read in bulk: the node has
already indexed every transaction that touches it, and you page through them
with `listtransactions`.

To begin watching an address you do not own the key to, call
`importaddress` with the address and then let the node rescan the chain for its
history. On a pruned node the rescan can only reach as far back as the blocks
the node still has, so import the addresses you care about *before* pruning
discards the blocks they appear in, or run the import on a full node. Once
imported, the address is indistinguishable from an owned one for reading: its
transactions show up in `listtransactions`.

The corpus turns the whole tracked set into a dataset. `update_quipu_data.py`
scans the project's nine addresses — pages each one's transactions, decodes
their outputs, identifies which transactions are quipu roots, walks each root's
strands, and writes two artifacts: `data/quipu_data.csv`, one row per
inscription with its type, tone, dimensions, and status; and
`data/bodies/<txid>.bin`, the reassembled bytes of each. After it runs, reading
any tracked inscription is a CSV lookup and a file read — no node round-trips at
all. This is the fast path, and it is why the rest of the corpus reads from
`data/` rather than from the chain: the chain was walked once, into files.

Re-run the script to refresh. It rewrites the dataset in place and checks that
every body on disk agrees with its CSV row. It does not archive the previous
dataset; the chain is the archive.
""")


CH_UNTRACKED = essay("Reading an Untracked Address", r"""
You do not need to track an address to read a quipu on it. You need one thing:
the txid of the inscription — the address by which it is cited, which is the
txid of its joining transaction. From that, the strands can be walked.

Walking is following spends backward and forward through the diamond. Given the
join, you read its inputs to find the strand ends; from each strand end you
follow that strand's ancestor chain, reading the OP_RETURN knot in each
transaction; the root ties the strands together and fixes their order. The
corpus does this in `fetch_quipu_bytes(txid)`, which walks up to a bounded
number of transactions and returns the reassembled header and body. Nothing is
imported; nothing is tracked; the only input is the txid.

There is one node subtlety, and it is the one from the first chapter.
`getrawtransaction` on an arbitrary transaction requires a full transaction
index, so it fails on a pruned node. For transactions the wallet already knows,
use the wallet path instead: `gettransaction` returns the transaction with its
raw hex even on a pruned node, and `decoderawtransaction` turns that hex into
the same decoded shape `getrawtransaction` would have returned. The corpus's
reader prefers the wallet path for this reason; it is the difference between
needing a full node and not. To read a *truly* arbitrary inscription — one your
node has never seen and whose blocks it has pruned — you need either a full
node with `txindex`, or to import its address and rescan first.

If you do not even have the txid, you can still find inscriptions by scanning
unspent outputs with `scantxoutset`, or by recognizing roots within a tracked
address's transactions — the corpus's `identify_quipus` and `find_quipu_roots`
do exactly that, marking which transactions begin a diamond by the magic bytes
in their first strand.
""")


CH_STAGING = essay("Staging a Piece", r"""
To stage is to turn bytes into a diamond and broadcast it. The bytes are a
quipu body — an essay, an image, a book manifest, whatever the type produces.
The diamond is the transaction shape that carries them.

The quipu magic is four bytes, `c1 dd 00 01`; the type is the fifth byte and
the tone the sixth. After the header comes the body. The whole thing is broken
into 80-byte knots, the most an OP_RETURN output carries, and the knots are
distributed across N strands. The first strand carries the header; the rest
carry the body. A root transaction splits one funding input into N outputs, one
seeding each strand; each strand is then grown as its own chain of
transactions, one knot per transaction; a joining transaction spends all N
strand ends into a single output. The join's txid is the inscription's address.

How many strands is a free choice, and the way the body is split across them
matters. Split it into N contiguous chunks and the last chunk is short, wasting
part of a knot. Split it by *modulo stride* instead — knot i of the body goes
to strand (i mod N) — and every strand is within one knot of the same length,
with no rounding waste, for any N. The on-chain cost is the same number of
knots either way, so choose N for parallelism, not for size: more strands means
the body is written in more chains at once, and a confirmed inscription sooner.

You do not have to broadcast to build. The pipeline's `write_inscription`
stages a quipu *locally* — it computes the inscription's identity and writes
the bytes to a local store — so a whole book can be assembled, rendered, and
proofread before a single coin is spent. Every volume of this library was built
this way first. Broadcasting is the last step, not the first, and it is the
same diamond either way.

The cost is small and known. Each transaction in the diamond pays a flat fee —
0.05 DOGE for the root, 0.05 for each strand transaction, 0.05 for the join.
An inscription of K knots over N strands is K strand transactions plus a root
plus a join, so its cost is `(K + 2) × 0.05 DOGE`, independent of how you choose
N. You can price a piece before you stage it by counting its knots.
""")


CH_WEAVING = essay("Weaving", r"""
A single inscription is one diamond. A publication is many, arranged so that
they cite one another into a structure. Weaving is staging several quipu as one
deliberate work.

The citations are the weave. An essay cites the images it shows and the works
it quotes; a book is nothing but an ordered manifest of citations to its
chapters and plates; a book of books cites whole books as its volumes; a
binding cites the works it annotates or overrides. Each cited thing is itself a
diamond with its own txid, and the citing thing simply carries those txids.
Because a citation is just a txid, the structure can be any depth: a volume
inside a library inside an anthology, each level one quipu pointing at the next,
with nothing changed but the depth.

The order of operations follows the citations. A thing must exist before it can
be cited, so the leaves are staged first and the roots last: images before the
essays that show them, essays before the book that gathers them, books before
the library that binds them. Built locally with `write_inscription`, the whole
tree is assembled in one run — each level reading the txids the level below
returned — and only then broadcast, from the leaves up. The corpus's library
build does exactly this: it imports each volume's build script, which stages
that volume and hands back its book txid, then stages the master manifest that
cites them all.

For broadcasting a large weave there is `quipu_orchestrator.py`, which runs a
diamond in three phases. *Instantiate* broadcasts the root. *Fill* broadcasts
the strands in parallel — independent chains, so a long body confirms in the
time of one strand, not the sum of all. *Close* broadcasts the join. A
consolidation step can gather many small funding inputs into one before the
root, so a publication with hundreds of knots is funded from a single confirmed
output. The diamonds nest: a fractal of roots and joins, each inscription's
join feeding the next level's citation, the whole publication one coordinated
broadcast.
""")


CH_CHOREOGRAPHY = essay("Cryptographic Monetary Choreography", r"""
Every knot of a quipu is a transaction, and every transaction is a payment. To
inscribe is to spend. This is not a cost the protocol tolerates; it is the
medium it works in. The publication is made *of* payments — its structure is a
pattern of spends, its permanence is the permanence of the ledger, and its
authorship is the control of the keys that signed it. The corpus calls the
arranging of those spends *cryptographic monetary choreography*, because that
is what it is: a composed sequence of monetary moves that leaves a work behind.

The choreography has parts that must happen in order and parts that may happen
at once. A root must confirm before its strands can spend its outputs — that is
sequence. The N strands, once seeded, grow independently and in parallel — that
is the chorus. The join waits for all strands — that is the cadence. Across a
nested publication the same pattern repeats at every level: each inscription's
join is a beat the next level waits for. Funding flows down the tree and txids
flow back up. A whole library settles as one long figure with many dancers
moving in their own time within it.

The money is not incidental to the meaning. Choosing to spend on a permanent
inscription is itself the statement that the work is worth permanence; the fee
is the author staking value on the record. The tones, the cross-signatures of a
two-of-two address, the order in which a sequence of works is laid down — these
are read off the chain as surely as the bytes are, and they are paid for in the
same coin. A budget is therefore a kind of score: this many knots, this many
inscriptions, this much DOGE, arranged this way. Plan the figure before the
first step. Count the knots, price the spend, stage the whole thing locally
until it reads correctly, and only then begin the broadcast that commits it.
""")


AFTERWORD = essay("Afterword", r"""
The machinery is plain on purpose. A node, a reader, an orchestrator: each is a
thin layer over ordinary RPC calls, and the chain underneath is the same chain
anyone can run. Nothing in this volume depends on the corpus's particular
tools. They are conveniences over a protocol you could operate by hand.

What the volume asks you to hold onto is the order. Stand up the node and let it
sync. Read what is there — from your own addresses through the dataset, from any
address by walking its strands. Stage locally until the work is right. Then
choreograph the broadcast: leaves before roots, root before strands, strands
before join, funding down and txids up. Do it in that order and a publication
of any size is just a larger figure of the same simple steps.

The chain does not forget, and it does not edit. That is the whole appeal and
the whole discipline. Everything in this volume is in service of being
deliberate before the step that cannot be taken back.
""")


# ===========================================================================
# Manifest
# ===========================================================================

ENTRIES = [
    {"tag": "cover",        "ref_txid": COVER,            "name": "The Staged Quipu"},
    {"tag": "prologue",     "ref_txid": PROLOGUE,         "name": "Prologue"},
    {"tag": "introduction", "ref_txid": INTRO,            "name": "Introduction"},

    {"tag": "chapter/01",   "ref_txid": CH_NODE,          "name": "The Node"},
    {"tag": "chapter/02",   "ref_txid": CH_TRACKED,       "name": "Reading a Tracked Address"},
    {"tag": "chapter/03",   "ref_txid": CH_UNTRACKED,     "name": "Reading an Untracked Address"},
    {"tag": "chapter/04",   "ref_txid": CH_STAGING,       "name": "Staging a Piece"},
    {"tag": "chapter/05",   "ref_txid": CH_WEAVING,       "name": "Weaving"},
    {"tag": "chapter/06",   "ref_txid": CH_CHOREOGRAPHY,  "name": "Cryptographic Monetary Choreography"},

    {"tag": "afterword",    "ref_txid": AFTERWORD,        "name": "Afterword"},

    {"tag": "art/01",       "ref_txid": PLATE_DIAMOND,    "name": "The Diamond"},
    {"tag": "art/02",       "ref_txid": PLATE_PHASES,     "name": "Instantiate, Fill, Close"},
    {"tag": "art/03",       "ref_txid": PLATE_READING,    "name": "Two Ways to Read"},
]

BOOK_FIELDS = dict(AUTH)
BOOK_FIELDS["institution"] = "Colegio Invisible"
BOOK_FIELDS["epigraph"] = ("To inscribe is to spend; the publication is made of "
                           "payments. — El Gólem")

bh, bb = build_book_quipu("The Staged Quipu", ENTRIES, tone=AI, fields=BOOK_FIELDS)
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
    print("The Staged Quipu ->", pdf, os.path.getsize(pdf), "bytes")
    print("  chapters:", tex.count("\\chapter{"),
          " plates:", tex.count("\\platequipu"),
          " bib:", tex.count("\\quipubibitem"))
