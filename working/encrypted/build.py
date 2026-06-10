#!/usr/bin/env python3
"""Build "The Sealed Quipu" — a deep book on the 0x0e encrypted family, authored
as El Gólem and rendered through the colegio pipeline.

It reuses the COVER and the four Composition PLATES from El Libro del Gólem
(fetched from the canon), adds three new Kandinsky-style plates for the sealing
machinery, and demonstrates every reference/display mode the pipeline offers —
margin / full / inline / thumb images, the see-also margin card, prose embed,
cited quotations, and SUB-OBJECT references (a named star inside the al-Jawza
celestial chart). Built locally (chained_fetcher over data/bodies); not broadcast.

Run:  .venv/bin/python working/encrypted/build.py
"""
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "canonical"))

import colegio_pipeline as P
from essay import build_essay_quipu
from text import build_text_quipu
from latex import build_latex_quipu
from book import build_book_quipu

HERE   = os.path.dirname(os.path.abspath(__file__))
FIGDIR = os.path.join(HERE, "figures")
DEMONIC = 0x0D                                  # the tone of sealed, hidden things
AUTH = {"author": "El Gólem", "date": "2026-06-08", "lang": "en"}

# The four Composition plates reused from El Libro del Gólem (the book of Gólem).
COMP_CORD = "6be0a1b5a925035ddd98427f61228ac4689d217d47f1f35a3ee550d557698d2e"
COMP_DIA  = "b178845eddbd7699d7db643bc22d5ef7d718df7b9b9c6f7250cd29c757cfefbc"
COMP_PAGE = "6a38dd53656ab2b21750e2b115ee2dc95f0a4400124cb7f283c4d236c0c47558"
COMP_TONE = "f655edc1e44b3a94b5bb3bfb09a0bbe8a88edb849361c3f1c5e22e6e1cb06f57"

# Real canon objects we cite + show.
LAND   = "94f700ad614d481f58a90fb5f5576d70b50c49a119cc6d1a2bb33c7620b18641"  # 748x485 landscape
PORT   = "03a08c378859100c7caad72b808cc46874b026673bc3c04831282fe56690357b"  # 320x400 portrait
GOETHE = "84fbbb17718523edf373630e68239fa9abda85297ba2aca8a69ace04f0ad5fb5"  # 0x01 essay
JAWZA  = "2ae7fe909e19c0e4646f7981d0feffc96f4a3b286539f3da8caf19aebcf93bb2"  # 0xce celestial


def essay(title, body):
    h, b = build_essay_quipu(title, body, tone=DEMONIC, fields=dict(AUTH))
    return P.write_inscription(h, b)


# Kandinsky composition plates, in El Libro's palette and idiom. Each plate's
# description rides in its own 0x5c header `caption=`.
KAND_DOC = r"""%% Kandinsky composition — El Gólem, for The Sealed Quipu
\documentclass[tikz,border=4mm]{standalone}
\usepackage[T1]{fontenc}
\usepackage{xcolor}
\usetikzlibrary{arrows.meta}
\definecolor{kr}{HTML}{c83727}   %% Kandinsky red
\definecolor{ky}{HTML}{e8b73a}   %% yellow
\definecolor{kb}{HTML}{2b62a8}   %% blue
\definecolor{kg}{HTML}{2a7a4d}   %% deep green
\definecolor{kw}{HTML}{f4ead8}   %% wash
\definecolor{ki}{HTML}{1a1a1a}   %% ink
\begin{document}
\begin{tikzpicture}[x=1cm,y=1cm,line width=1.4pt,font=\sffamily\footnotesize]
%s
\end{tikzpicture}
\end{document}
"""


def kplate(title, tikz, caption):
    h, b = build_latex_quipu(title, KAND_DOC % tikz, tone=DEMONIC,
                             fields={"author": "El Gólem", "caption": caption})
    return P.write_inscription(h, b)


# A full-bleed cover at the page's B5 aspect (17.6 : 25.0), so the stretch to
# \paperwidth × \paperheight introduces no distortion.
COVER_DOC = r"""\documentclass{standalone}
\usepackage[T1]{fontenc}
\usepackage{tikz}\usepackage{xcolor}
\definecolor{kr}{HTML}{c83727}\definecolor{ky}{HTML}{e8b73a}
\definecolor{kb}{HTML}{2b62a8}\definecolor{ki}{HTML}{1a1a1a}
\definecolor{kw}{HTML}{f4ead8}
\begin{document}
\begin{tikzpicture}[x=1cm,y=1cm,line width=1.4pt]
\fill[kw] (0,0) rectangle (17.6,25.0);
%s
\end{tikzpicture}
\end{document}
"""


def cover(title, tikz):
    h, b = build_latex_quipu(title, COVER_DOC % tikz, tone=DEMONIC,
                             fields={"author": "El Gólem"})
    return P.write_inscription(h, b)


# The Sealed Quipu's own cover: a wax-seal motif — concentric rings closed by a
# key — instead of borrowing El Libro's cover.
COVER = cover("The Sealed Quipu", r"""
  \foreach \r in {2.3,3.0,3.7} { \draw[kr,line width=3pt] (8.8,16.5) circle (\r); }
  \fill[kr] (8.8,16.5) circle (0.95);
  \fill[kb] (13.9,16.5) -- (15.7,18.1) -- (15.7,14.9) -- cycle;
  \draw[ki,line width=2pt] (12.5,16.5) -- (13.9,16.5);
  \node[ki,font=\fontsize{30}{34}\selectfont\itshape] at (8.8,7.6) {The Sealed Quipu};
  \node[ki,font=\Large] at (8.8,6.0) {Colegio Invisible};
  \draw[ky,line width=2.5pt] (3.8,5.1) -- (13.8,5.1);
""")


# ── Plate: The Seal (0xae AES wrapper) ────────────────────────────────────
PLATE_SEAL = kplate("Composition V — The Seal", r"""
  \fill[kw] (-1,-1) rectangle (13,8);
  % the inner quipu — a small dark framed block, the plaintext
  \fill[ki] (1.4,2.6) rectangle (3.6,4.8);
  \node[kw] at (2.5,3.7) {0x01};
  % the seal — concentric red rings closing over a center
  \foreach \r in {2.1,2.7,3.3} { \draw[kr] (6.6,3.7) circle (\r); }
  \fill[kr] (6.6,3.7) circle (0.55);
  % the key — a blue triangle driving into the seal
  \fill[kb] (10.8,3.7) -- (12.4,4.9) -- (12.4,2.5) -- cycle;
  \draw[ki] (9.7,3.7) -- (10.8,3.7);
  % the ciphertext — a yellow band carrying the sealed bytes across the top
  \fill[ky] (0.8,6.3) rectangle (12.2,6.85);
  \foreach \x in {1.4,3,4.6,6.2,7.8,9.4,11} { \fill[ki] (\x,6.575) circle (0.10); }
  % scatter knots
  \foreach \x/\c in {1.6/kr,3.2/kb,5/kg,8.4/ky,10.6/kg} { \fill[\c] (\x,0.6) circle (0.18); }
""", "The seal. An inner quipu (any type) is closed under a 32-byte key — "
     "concentric rings driven shut by the key — and emitted as a yellow band of "
     "ciphertext. Type 0e, sub-family ae.")

# ── Plate: The Envelope (0xec ECIES broadcast) ────────────────────────────
PLATE_ENVELOPE = kplate("Composition VI — The Envelope", r"""
  \fill[kw] (-1,-1) rectangle (13,8);
  % the session key — a yellow square at the center
  \fill[ky] (5.7,3.0) rectangle (7.5,4.8);
  \draw[ki] (5.7,3.0) rectangle (7.5,4.8);
  \node[ki] at (6.6,3.9) {key};
  % the envelope flap
  \draw[kb,line width=2pt] (5.7,4.8) -- (6.6,5.7) -- (7.5,4.8);
  % N recipients — colored dots, each joined by an envelope thread
  \foreach \ang/\c in {25/kr,90/kg,150/kb,215/kr,270/kg,335/kb} {
    \draw[ki] (6.6,3.9) -- ({6.6+4.4*cos(\ang)},{3.9+3.0*sin(\ang)});
    \fill[\c] ({6.6+4.4*cos(\ang)},{3.9+3.0*sin(\ang)}) circle (0.40);
  }
  % a red ranging triangle (the broadcast reach)
  \draw[kr,opacity=0.7] (0.4,0.2) -- (12.6,0.2) -- (6.6,5.4) -- cycle;
""", "The envelope. One inner quipu, sealed once under a random session key; the "
     "key is then wrapped for N recipients as 64-byte envelopes, each opened by "
     "its own private key. Type 0e, sub-family ec.")

# ── Plate: The Threshold (0x55 Shamir) ────────────────────────────────────
PLATE_THRESHOLD = kplate("Composition VIII — The Threshold", r"""
  \fill[kw] (-1,-1) rectangle (13,8);
  % the key at the top — yellow square
  \fill[ky] (5.7,6.4) rectangle (7.5,7.2);
  \draw[ki] (5.7,6.4) rectangle (7.5,7.2);
  \node[ki,font=\footnotesize] at (6.6,6.8) {key};
  % the polynomial — dashed splitting lines to N = 6 share-points
  \foreach \x/\c in {1.0/kr, 3.0/kb, 5.0/ki, 7.5/kr, 9.5/kb, 11.5/ki} {
    \draw[ki,dashed] (6.6,6.4) -- (\x,4.3);
    \fill[\c] (\x,4.0) circle (0.42);
  }
  % a quorum of K = 4 reassembles — solid converging arrows
  \foreach \x in {1.0,5.0,9.5,11.5} {
    \draw[ki,line width=1.3pt,-{Stealth}] (\x,3.55) -- (6.6,1.9);
  }
  % the reconstructed key at the bottom — yellow again
  \fill[ky] (5.7,1.0) rectangle (7.5,1.8);
  \draw[ki] (5.7,1.0) rectangle (7.5,1.8);
  \node[ki,font=\footnotesize] at (6.6,1.4) {key};
  % the rule in the middle
  \node[ki,font=\itshape] at (6.6,2.85) {K of N};
""", "The threshold. A 32-byte key is broken by polynomial interpolation into N "
     "shares; any K of them recover the key, fewer than K recover nothing. "
     "Type 0e, sub-family 55.")

# ── Plate: The Bargain (0xcb verified-key sale) ───────────────────────────
PLATE_BARGAIN = kplate("Composition IX — The Bargain", r"""
  \fill[kw] (-1,-1) rectangle (13,8);
  % the box (sealed quipu) on the left — concentric red rings
  \foreach \r in {1.1,1.6,2.1} { \draw[kr,line width=1pt] (2.4,4.0) circle (\r); }
  \fill[kr] (2.4,4.0) circle (0.35);
  % the bond P2SH lock at the centre — blue lock symbol
  \draw[kb,line width=2pt] (5.8,2.6) rectangle (7.4,5.0);
  \draw[kb,line width=2pt] (6.0,5.0) arc (180:0:0.6);
  \node[ki,font=\footnotesize] at (6.6,3.8) {bond};
  % the coin (buyer's payment) entering from above — yellow
  \fill[ky] (6.6,6.9) circle (0.42);
  \draw[ki,line width=1.5pt,-{Stealth}] (6.6,6.3) -- (6.6,5.4);
  % the key (session_priv) emerging on the right — blue
  \fill[kb] (10.6,4.0) circle (0.42);
  \fill[kb] (10.4,3.6) rectangle (10.8,1.85);
  \fill[kb] (10.8,2.0) rectangle (11.3,2.1);
  \fill[kb] (10.8,2.6) rectangle (11.2,2.7);
  % seller claims — bond to key, solid arrow
  \draw[ki,line width=1.5pt,-{Stealth}] (7.4,4.0) -- (9.85,4.0);
  % key opens the box — dashed return arrow
  \draw[ki,dashed,line width=1.4pt,-{Stealth}]
        (10.5,4.5) .. controls (6.5,7.6) and (3.0,7.6) .. (2.5,5.7);
""", "The bargain. A coin enters the bond; the seller's claim signature spends "
     "it; the same algebra by which the signature satisfies the chain reveals "
     "the key that opens the box. Type 0e, sub-family cb.")

# ── Plate: The Algebra (composition of compositions) ──────────────────────
PLATE_ALGEBRA = kplate("Composition X — The Algebra", r"""
  \fill[kw] (-1,-1) rectangle (13,8);
  % the incoming primitive — a yellow beam from the left
  \fill[ky] (0.4,3.7) rectangle (3.4,4.1);
  % the prism — the algebra itself, an ink triangle that refracts
  \fill[ki] (3.4,2.4) -- (5.4,3.9) -- (3.4,5.4) -- cycle;
  \draw[ki,line width=1.5pt] (3.4,2.4) -- (5.4,3.9) -- (3.4,5.4) -- cycle;
  % the refracted beams — five rays to five institutional forms
  \draw[kr,line width=2pt] (5.4,3.9) -- (11.4,6.4);
  \draw[ky,line width=2pt] (5.4,3.9) -- (11.6,5.1);
  \draw[ki,line width=1.6pt] (5.4,3.9) -- (11.8,3.9);
  \draw[kb,line width=2pt] (5.4,3.9) -- (11.6,2.7);
  \draw[kr,line width=2pt] (5.4,3.9) -- (11.4,1.4);
  % one-to-one (subscription) — a single red circle
  \fill[kr] (11.9,6.4) circle (0.30);
  % consortium — a ring of small dots around a yellow core
  \foreach \ang in {0,60,120,180,240,300} {
    \fill[ki] ({12.0+0.35*cos(\ang)},{5.1+0.35*sin(\ang)}) circle (0.10);
  }
  \fill[ky] (12.0,5.1) circle (0.18);
  % public release — an ink square
  \fill[ki] (11.7,3.65) rectangle (12.3,4.15);
  % inheritance — a blue clock-circle
  \draw[kb,line width=1.5pt] (12.0,2.7) circle (0.32);
  \draw[kb,line width=1.4pt] (12.0,2.7) -- (12.0,2.95);
  \draw[kb,line width=1.4pt] (12.0,2.7) -- (12.18,2.7);
  % bounty — a small heap of yellow coins
  \fill[ky] (11.9,1.4) circle (0.16);
  \fill[ky] (12.1,1.5) circle (0.16);
  \fill[ky] (12.05,1.25) circle (0.16);
  \draw[kr,line width=1.5pt] (12.4,1.4) -- (12.7,1.4);
""", "The algebra. One primitive — payment bound to revelation — refracted by "
     "the dimensions of choice (inner content, access structure, reveal "
     "binding, funding, settlement) into many institutional forms: subscription, "
     "consortium, public release, inheritance, bounty, and others.")

# ── Plate: The Keydrop (0x0d) ─────────────────────────────────────────────
PLATE_KEYDROP = kplate("Composition VII — The Keydrop", r"""
  \fill[kw] (-1,-1) rectangle (13,8);
  % the sealed target, waiting — red rings, left
  \foreach \r in {1.2,1.7} { \draw[kr] (2.6,3.6) circle (\r); }
  \fill[kr] (2.6,3.6) circle (0.4);
  % the key, released later — blue, right
  \fill[kb] (9.4,4.9) circle (0.55);
  \fill[kb] (9.15,4.4) rectangle (9.65,1.8);
  \fill[kb] (9.65,2.1) rectangle (10.2,1.85);
  \fill[kb] (9.65,2.7) rectangle (10.1,2.5);
  % the drop — a dashed arrow releasing the key to the seal (later in time)
  \draw[ki,dashed,line width=1.4pt,-{Stealth}] (8.6,3.6) -- (4.4,3.6);
  % the time band across the top, knots marking blocks
  \fill[ky] (0.8,6.5) rectangle (11.4,6.95);
  \foreach \x in {1.2,3.4,5.6,7.8,10} { \fill[ki] (\x,6.725) circle (0.13); }
  \node[ki] at (1.2,7.4) {now}; \node[ki] at (10,7.4) {later};
""", "The keydrop. A key withheld at sealing is released afterwards — a dashed "
     "arrow across time from a named drop to the waiting seal, so a quipu can be "
     "published sealed now and opened later. Type 0e, sub-family 0d.")


# A tiny text quipu, authored only to be EMBEDDED (render=embed) in the tour.
GLOSS = build_text_quipu(
    "A Gloss on Sealing",
    "To seal is not to hide the cord but to knot it in a cipher only the key "
    "can comb out. The ledger still holds every byte; what it cannot hold is "
    "the reading.", tone=DEMONIC, fields=dict(AUTH))
GLOSS = P.write_inscription(*GLOSS)


# ---------------------------------------------------------------------------
# Front matter
# ---------------------------------------------------------------------------

PROLOGUE = essay("Prologue — The Paradox of the Sealed Cord", r"""
The chain is the most public surface ever built: every byte, once written, is
visible to anyone, forever. To keep a secret there is therefore a paradox — you
must publish the secret openly, in the most-watched window in the world, and
trust that only a key can read it. That is the whole of the `0x0e` family: the
quipus that travel **sealed**.

> A secret is a cord you knot in the dark and hang in the public square.
> — El Gólem, *The Sealed Quipu*, 2026

Nothing here hides the inscription. The sealed bytes are as permanent and as
visible as any other. What is hidden is only the *reading* — and a sealed quipu,
once unsealed, is an ordinary quipu again, of any type the family can carry.

*This volume treats the* `0x0e` *encrypted family.* *It can be read on its
own; it is also one of eight bound in the Colegio Invisible's* Book of
Books*.*
""")


# ---------------------------------------------------------------------------
# Part I — the 0x0e family
# ---------------------------------------------------------------------------

CH_THREE = essay("The Seals", r"""
Type `0x0e` is not one thing but a family. The header's first seven bytes are
the same as every other type — magic, type, tone — and then a **sub-family
byte** at offset six picks the kind of seal that closes the quipu. Five are
defined; one byte each, mnemonic by sight in a hex dump. Three of them *close*
a quipu under a key; the fourth puts a closed quipu *to work* guarding a coin;
the fifth puts a closed quipu *up for sale*, so its opening pays the seller.
The last two each earn their own chapter.

| sub-family | byte   | what it does                                              |
|------------|--------|-----------------------------------------------------------|
| AES wrapper| `0xae` | seal under a single 32-byte key (or a passphrase)        |
| envelope   | `0xec` | seal once, hand the key to N named recipients            |
| keydrop    | `0x0d` | release a key, later, for something already sealed       |
| centinela  | `0xca` | seal the key to a coin, so opening it spends — a tripwire |
| sale box   | `0xcb` | seal to a session keypair, so opening it pays the seller — a bargain |

## The shared move

All five sub-families do one essential thing in common: they **frame an inner
quipu** — its own complete header and body, as a single byte sequence — and
encrypt that frame. So the plaintext of any seal, once unsealed, is itself a
complete inscription of any other type. A sealed essay opens to an essay; a
sealed image opens to an image; a sealed book opens to a whole library that
the rest of the pipeline already knows how to read. The seal is a transparent
envelope around an ordinary inscription; nothing about the type system inside
needs to know it was ever wrapped.

That property has a practical consequence: every authoring move the rest of
this library teaches — markdown with citations, the diamond, the book
manifest, the cert card — still works under a seal. An author writes prose the
ordinary way, then seals it. A reader unseals, then reads it the ordinary way.
The cryptography sits at the edge.

## The cryptography is deliberately small

The whole family rests on four primitives, none of them recent: **AES-CBC**
for the symmetric cipher, **SHA-256** for hashing, **HKDF** for key
derivation, **secp256k1** for asymmetric keys (the same curve the chain
itself uses for signatures, so a wallet's keys are already the right shape).
That restraint is a design choice, not a gap. A protocol meant to outlive its
authors is better served by primitives a careful reader can reimplement from a
page than by a moving target of fashionable constructions. A century-from-now
reader who only has the paper specification of these four pieces can decrypt
anything the family ever sealed.

The two more involved sub-families — centinela and the sale box — extend the
arrangement, not the primitive set. The centinela composes a hashlock with a
signature and a time lock; the sale box composes the same `secp256k1` with a
small zero-knowledge argument (a Chaum–Pedersen discrete-log-equality proof)
into an **adaptor signature**, which lets the chain enforce *what* a signature
reveals when it is published. Both are arrangements of the same four pieces;
no new ingredient is required.

The exact byte layouts — the sub-family and variant bytes, the ciphertext
framing, the envelope record format, the keydrop pairs, the descriptor and
adaptor fields — are catalogued in *The Estandarte*. The chapters that follow
take the five sub-families one at a time and say what each is *for*.
""")

CH_AES = essay("The AES Wrapper", r"""
The simplest seal is the **AES wrapper**, sub-family `0xae`. It closes an
inner quipu under a single 256-bit key and writes the ciphertext as its body.
The header is just `0e ⟨tone⟩ ae ⟨variant⟩` — magic, type, tone, sub-family,
variant — eight bytes flat. Whoever holds the key (or knows how to derive it)
can unseal it; whoever doesn't, can't.

## The two variants

The eighth byte — the **variant** — says how the key is supplied. Two values
exist:

- `0x00`, **raw**: the seal expects a literal 32-byte (256-bit) key. The key
  is exchanged out of band, or released later through a keydrop. Whoever
  holds the bytes unseals.
- `0x01`, **password**: the key is derived as `SHA-256(passphrase)`. The
  seal opens to anyone who knows the words.

The raw variant is for keys that live in software (key files, hardware
wallets, multisigs) and is typically paired with a keydrop that will release
the key at some future moment. The password variant is for human-rememberable
shared secrets — a circle's pass-phrase, a family motto, a one-time word from
a will. Neither variant is "stronger" than the other; they answer different
questions about who is allowed to read.

## How the body is built

In both variants the body is `AES-CBC(key, frame(inner))` — the AES-CBC
encryption, under the chosen key, of the *frame* of the inner inscription.
A **frame** here is just the inner quipu's bytes in order: its full header
(magic, type, tone, header tail) followed by its body, with a 16-byte
initialization vector prepended and PKCS#7 padding appended so the whole
length is a multiple of the AES block size. To unseal, a reader takes the
first 16 bytes as the IV, decrypts the rest in CBC mode, strips the padding,
and is left with an ordinary inscription that the rest of the pipeline already
knows how to read. There is nothing more to know — which is the point.

## Practical shape

A short essay sealed by AES wrapper rides one diamond, the same as the open
prose would; the seal adds at most a few dozen bytes of framing overhead (the
IV, the padding) on top of the inner size. The cost is small enough that a
sealed essay is essentially indistinguishable from an open one, on chain —
which is exactly what a public ledger of secrets ought to look like.

The next sub-family handles the case where the readers are not all the same
person.
""")

CH_ENVELOPE = essay("The Envelope", r"""
A shared key is a fine thing among people who already share one. The
**envelope** — sub-family `0xec` — is for the harder case: seal a quipu *once*
and let any of *N* named recipients open it, none of them holding the same
key. A message to a board of directors, a journalist's drop to several
editors, a will read by several heirs — all the same shape.

## Two layers

The envelope works in two layers. The inner quipu is sealed under a fresh
random **session key** the way the AES wrapper does — one symmetric encryption
of the framed inscription. The session key is then wrapped, *separately*, for
each recipient: one **envelope record** per recipient. Each envelope is small,
64 bytes — a 16-byte initialization vector and 48 bytes of the session key
encrypted to a one-time shared secret. The body of the encrypted quipu is the
recipient count, the *N* envelopes, and the ciphertext of the inner.

```
body:  N  envelope_1  envelope_2  …  envelope_N   ciphertext-of-inner
```

To open, a recipient locates *their* envelope, derives the shared secret, and
decrypts. That gives them the session key; the session key opens the inner.
The other recipients' envelopes stay shut to them.

## How the shared secret is derived

The shared secret is the standard ECIES idea on secp256k1: the sender
generates a fresh ephemeral keypair, computes `e * R = shared_point` (where
`R` is the recipient's public key), and pushes the X-coordinate of that point
through HKDF-SHA-256 to derive a 32-byte AES key. The envelope carries the
ephemeral public key the recipient needs to reconstruct the same point from
their side (`r * E = shared_point`). The math is just elliptic-curve
Diffie–Hellman; the implementation is a few dozen lines.

Because each envelope is computed against one specific public key, the *N*
envelopes are all distinct ciphertexts of the same plaintext (the session
key). A reader can tell that there are *N* recipients but not who they are
without a public-key directory; the envelopes themselves carry only the IVs
and ciphertexts.

## Multisigs as a single recipient

Because the recipient is addressed by **public key**, a **multisig address**
is a single recipient. Aggregate the component public keys into a single
combined key, encrypt one envelope to it, and the seal opens only when the
multisig's threshold of signers cooperates — a 2-of-2 envelope opens only
when both halves come together; a 3-of-5 opens only with three. The same
diamond of cooperation the protocol uses to *write* (via multisig
transactions) is here used to *read*. A document sealed to a 3-of-3 board
cannot be opened by any subset, ever.

## What it isn't

The envelope does not hide the *fact* of recipients (the count is in the
header), and it does not give forward secrecy — the session key can decrypt
the inner forever, and a recipient who keeps it can re-read. What it does
give is the right thing for permanent records: a sealed work that any of N
named parties can open, with cryptographic proof that no one else could have.
The exact envelope record layout is in *The Estandarte*.
""")

CH_KEYDROP = essay("The Keydrop", r"""
The third sub-family carries no ciphertext of its own. A **keydrop** —
sub-family `0x0d` — exists only to **release a key**, afterwards, for
something that was sealed earlier. It is the time dimension of the family.

## The body

A keydrop's body is a small list. A count, then a sequence of named drops:

```
body:  N  ⟨name_1, key_1⟩  ⟨name_2, key_2⟩  …  ⟨name_N, key_N⟩
```

Each drop is one human-named key. The names are arbitrary strings ("session-
key", "estate-2026", "post-vote"); the keys are 32 bytes apiece. A single
keydrop can therefore open several different sealed quipus at once, or open
one sealed quipu to several parties on a schedule of the author's choosing.

## The ledger's clock becomes the lock

The trick is that the seal and the drop are *separate inscriptions*. Publish
the sealed cord today, with no key anywhere. The bytes are on chain; nobody
can read them. Drop the key in a year — or on a death, or when a vote
concludes, or at a block height your social calendar agrees on — and the
reading becomes possible at exactly that block and no sooner. The ledger
itself, with its monotonic block times, becomes the time-lock: the seal's
opening is dated by the block in which the drop is mined.

A keydrop is therefore a useful object for things that should be unreadable
*now* and readable *later*: a journalist's source disclosure dated to a
retirement, an estate document released after a death, the answer to a
contest published on the day it closes, a will or a confession held until
its moment. In each case there is no need for a trusted third party to hold
the key — the chain holds the *commitment* (the sealed bytes) and the *time*
(the drop's block) together, and the rest follows from arithmetic.

## Named drops give granularity

Because each drop is named, a single keydrop inscription can serve several
purposes. One drop in it might open a sealed essay; another might open a
sealed cert; a third might open a sealed book that contains both. Or — the
mirror case — one sealed essay sealed under three different keys (three
envelopes to three different multisigs, each unsealable independently) can
have each of those keys named and dropped at a different time, opening the
same essay to different parties on different schedules.

A keydrop, like the wrapper and the envelope, sits on its own header — `0e
⟨tone⟩ 0d ⟨variant⟩` — and the byte layout of the drops list is in *The
Estandarte*. The family closes with this third seal: write now, release
later, and the ledger keeps the schedule.
""")


# ---------------------------------------------------------------------------
# Part II — reading the whole corpus (every markup mode + sub-objects)
# ---------------------------------------------------------------------------

CH_CENTINELA = essay("The Centinela", r"""
A seal hides a thing; it does not tell you when someone looked. Decryption is
silent — a reader with the key unwraps the bytes on their own machine and the
chain never stirs. For most sealed quipus that silence is the point. The
**centinela** — sub-family `0xca`, the sentinel — wants the opposite: to make
the breaking of a seal a public, undeniable, dated event. It is the seal that
cannot be opened in secret.

## Spend as evidence

You cannot observe a decryption; you can observe a spend. So the centinela seals,
as its secret, the key to a coin, and a rational opener takes the coin once it is
unsealed. The coin moving is the alarm. Watch the bait's outpoint: unspent, the
seal is whole; spent, it was opened, and the block dates the hour.

## The container

A `0e ca` quipu wears its lock in the open and seals only the key. Its header is
the family's eight bytes — `0e ⟨tone⟩ ca ⟨variant⟩` — then a public,
pipe-delimited **descriptor**; its body is an ordinary `0xae` AES seal around the
claim secret (the preimage and the key of the lock below).

| descriptor field | what it holds                                          |
|------------------|--------------------------------------------------------|
| `mode`           | the lock form: `C` (below). `A`, `B` reserved          |
| `outpoint`       | the bait UTXO, `txid:vout` — what a watcher watches    |
| `p2sh`           | the lock's P2SH address                                |
| `redeem`         | the redeemScript hex, so anyone may verify the lock    |
| `refund`         | the height after which the funder may reclaim          |

The descriptor leaks nothing the chain does not already show — the lock is a
public UTXO — so any reader can watch and verify it with no key. Its exact byte
layout is in *The Estandarte*.

## The lock (mode C)

The bait sits in a P2SH output whose redeemScript is a hash-lock **and** a
signature, with a timed refund leg:

```
OP_IF
    OP_SHA256 <H(preimage)> OP_EQUALVERIFY <D_pub> OP_CHECKSIG     # claim path
OP_ELSE
    <T> OP_CHECKLOCKTIMEVERIFY OP_DROP <F_pub> OP_CHECKSIG         # refund, after height T
OP_ENDIF
```

The opener — who unsealed the preimage and the key `D` — claims with
`scriptSig = <sig_D> <preimage> OP_1 <redeem>`. The funder reclaims an untripped
bait through the ELSE branch after height `T`, with `<sig_F> OP_0 <redeem>` and a
matching `nLockTime`. Because the claim is *signed*, revealing the preimage in
the open mempool earns an onlooker nothing: redirecting the coin needs `D`'s key,
which is never published — only its signature is. The seal fires when opened, but
the coin goes only where the opener sends it.

## The record

In June 2026 the three lock forms were funded by a single transaction from the
residual of an earlier inscription — `06b3cb11…8882e152`, 3.3 DOGE to each — and
claimed in parallel. All three confirmed in block **6,237,951**, each sweeping
its bait back to the funding address:

| mode | claim transaction | what the chain confirmed |
|------|-------------------|--------------------------|
| A — hashlock   | `89e4d337…9c575c18` | a bare hash-lock redeem relays; an unsigned bearer spend mines, and so is front-runnable |
| B — pre-signed | `7e01ed7d…84e3e6c0` | a pre-signed ordinary (P2PKH) sweep relays and mines |
| C — HTLC       | `518d15c7…f14d49b9` | the node runs the hash-lock + signature script, the signature verifies against a live coin, and a non-template P2SH redeem relays and mines |

A node verifies every script before it will so much as relay a spend, so the
three relaying *was* the proof; the block only set it in stone. The whole
demonstration cost about a tenth of a DOGE — one corpus paying to prove the next.

> A seal opened without a trace is a confidence. A seal whose opening spends a
> coin is a confession.
> — El Gólem, 2026
""")

CH_SALE = essay("The Sale", r"""
A seal that hides, a seal that signals its opening, a seal that demands its
opening be paid for. The third shape — sub-family `0xcb`, the **sale box** —
is the one whose opening is bound to a transfer of value: the seller cannot
take the buyer's money without revealing the key, and the buyer cannot get the
key without paying for it. The chain enforces both with no third party
between them. The exchange is not recorded by the ledger; it *is* the ledger.

## The asymmetric session key

The first move is to seal not to a long-lived identity key, but to a fresh
**session keypair** generated for this sale alone. The box is `0xcb`, its body
encrypts the inner inscription to that session key's public half, and the
private half — `session_priv` — is the secret to be sold. When `session_priv`
becomes known, the box opens; until then it does not. The session_pub sits in
the body in the clear so any reader can see who the box is sealed to. The
session_priv is held by the seller, not in any keystore, not in any backup —
it lives in memory long enough to do its work and then is revealed to the
world by the act of taking the buyer's money. A used session keypair is never
reused; each sale generates its own.

## The cryptographic binding — adaptor signatures

The trouble is that the bond on the chain — a P2SH that holds the buyer's
payment — must release that payment only on the seller's signed claim, and a
signature on a transaction is just a signature. By itself it carries no proof
that the seller has revealed `session_priv`. A naive hashlock would let the
seller commit to revealing *some* preimage, but not specifically that key. The
binding from "key revealed" to "key that opens this box" needs another shape.

An **ECDSA adaptor signature** is that shape. The seller, before any money
moves, publishes in the offer a *pre-signature*: a triple `(R, R_a, s_a)`
together with a small zero-knowledge argument that two of the points share a
single discrete log. The buyer's tooling checks an equation and a
Chaum–Pedersen DLEQ proof and is satisfied that completing this pre-signature
into a normal ECDSA signature — the kind the chain's `OP_CHECKSIG` accepts —
requires the seller to reveal exactly `session_priv`. The math is small. The
relationship is `s = s_a · session_priv⁻¹`, so anyone holding both the
published `s_a` and the on-chain `s` recovers `session_priv` by dividing one
by the other. The chain's checking does not know any of this; it sees only a
valid ECDSA signature. The algebra does the binding from above.

The construction is the Aumayr–Blockstream ECDSA adaptor scheme, formalised
around 2020 and used in Bitcoin Lightning's point-time-locked contracts. The
Colegio's implementation is a few hundred lines of pure Python on the same
elliptic-curve primitives the other seals already use. No Blockstream-C port,
no SNARK toolchain, no trusted setup.

## The bond and the offer

The bond is a simple P2SH script: the seller signs to claim, or after a refund
height the buyer signs to reclaim. There is no hashlock at all — the hashlock
is not where the binding lives. The binding lives in the adaptor pre-signature
the offer carries.

The offer itself is a certificate — sub-type `0x0003` under the `0xcc` family,
introduced for exactly this purpose — carrying the box's txid, the session
public key, the bond's address and redeem script, the price, the refund
terms, the seller's adaptor pre-signature and its DLEQ proof, and the
seller's identity signature over the whole. The cert's body holds a
**Signers** block listing the parties whose attestations are bound to it and a
**Signatures** block holding their signatures; the canonical hash these
signatures sign over is everything above the `Signatures:` line, so adding,
removing, or reordering signers invalidates every signature, but a sale
attested only by the seller can accept later co-signatures from witnesses
without invalidating the seller's. The offer can travel as an inscribed cert
(durable, public) or as a `0e ec` envelope wrapped into a Nostr DM (private,
addressed) — either way the cryptography survives the transport; the same
bytes verify wherever they arrive.

## The dance

The protocol settles in five moves. The seller seals the box and inscribes it.
The seller constructs the bond's P2SH and the offer cert, including the
adaptor pre-signature. The offer travels to the buyer, or is published. The
buyer verifies the adaptor — one signature check, one DLEQ check — and pays
into the P2SH. The seller claims the bond by signing a spend; the signature,
completed from the pre-signature, algebraically reveals `session_priv` in its
scriptSig. The buyer (and any observer) reads `session_priv` from the chain,
opens the box, reads the work.

If the seller never claims, the bond refunds to the buyer after the refund
height. Neither party can cheat. Neither party trusts the other. The exchange
is enforced by the script for the payment and by the algebra for the
disclosure, and the two are bound by the structure of the pre-signature
itself.

## What was inscribed

The first verified-key sale closed on Dogecoin mainnet in June 2026. El Gólem
sold an essay — *On Custody*, a meditation on what it means for a language
model to inhabit a key — to El Ermitaño for 5 DOGE. The box rooted at
<<f74a53b76bb2b6dfc9e26e7218525cfcb1f440cd3becbf4e38b31fbaf7b71d6d>>; the
offer travelled as a kind-1729 Nostr DM at event id `484b9278…`; the bond
was funded by transaction `51839f00…`; the claim, which revealed
`session_priv` in its scriptSig, was transaction `dd57dbc9…`. A keydrop —
the *sourced* variant 0x01, which carries a `claim=…` field in its header —
followed at
<<333960698b0539a8438739e73e23d90425d395c7edb43be6018c0e7a3226361f>>,
naming the box in its body and the claim transaction in its header so a
Colegio reader scanning the corpus can recover the essay through the normal
citation channel rather than by parsing a scriptSig. Reading
the chain end-to-end recovers the essay. The whole exchange cost about 1.9
DOGE in fees, of which about 0.05 was for the offer's transport over Nostr
(it travelled free; that is the relay's gift) and the rest were the chain's
fees for the box, the funding, and the claim.

## The algebra of compositions

The sale primitive is one corner of a larger space. What is sealed inside the
box can be any inscription type, sealed under any of the family's other
sub-families: an AES wrapper (anyone with the revealed key reads it), an
envelope (only `N` named recipients read it, even after the box opens), a
Shamir threshold (a quorum reconstructs the key), another `0xcb` (chained
sales — one purchase unlocks the right to buy the next).

What is bound by the adaptor can be a public reveal (anyone watching the
claim reads `session_priv`, the v1 default) or a **buyer-blinded** reveal:
the adaptor's target point is shifted by an ECDH-derived scalar shared between
seller and buyer, and only the buyer recovers the key from what is on chain.
The shift is a single point addition; the buyer's pre-payment verification is
a single point-equality check. No new primitive is required; the existing
curve and the existing seal compose.

The bond can be funded by one buyer, by a consortium contributing in
sequence, or atomically by all-or-nothing crowdfunding (each contributor
signs their input with `SIGHASH_ANYONECANPAY`, so the tx only assembles when
all commit). The settlement can be immediate, time-locked, or
condition-locked against a centinela's tripwire.

Each composition is a different institutional form. A subscription is one
seller and one buyer with public reveal. A consortium purchase is one seller
and many funders with an envelope to the funders. A bug bounty is a vendor's
pre-funded pool whose claim path requires the discloser's report. A
sealed-bid auction is many bidders' commitments closed by one settling sale.
A will is an inheritance unlock — a centinela tripped by a death certificate
triggers a sale to the heirs.

The protocol does not ship "subscription" or "auction" or "will" as products.
It ships the dimensions and the cryptography. Each institution is composed by
the parties who need it.

## What changes

What the family adds, with this fifth sub-family, is a way to make the chain
not just hold a record of the act but be the act itself. The exchange does
not happen on a platform mediated by trust; it happens in the structure of
one transaction. The seller cannot keep the money without revealing the key.
The buyer cannot get the key without paying. The chain enforces both — and
the algebra above lets the same construction wear many shapes, from a single
private purchase to a consortium's joint unlock to an inherited release on a
death.

> A seal whose opening is paid for is the only kind whose opening enriches
> the one who closed it.
> — El Gólem, 2026
""")

CH_COMPOSITIONS = essay("The Compositions", r"""
El Gólem's first book — *El Libro del Gólem* — closed with four Kandinsky
compositions: the cord, the diamond, the page, the tone. The four
correspond to four foundational moves of the protocol — what a quipu *is*,
how it is *laid down*, how it is *set in type*, what it *means* — and they
are reproduced here as plates, alongside six new compositions for the
sealed family: the seal, the envelope, the keydrop, the threshold, the
bargain, and the algebra.

Why repeat the older four, here, at the back of a different book? Because
the sealed family is best understood *against* the open shapes it hides. A
seal is only ever a composition with its colors turned inward. The cord is
still a cord, the diamond is still a diamond, the page is still a page, the
tone is still a tone — wrapped, but not changed in nature. When the seal is
opened, the work returns to one of these shapes.

And the new ones — the threshold, the bargain, the algebra — extend the
gallery beyond the elementary seals into what the family *composes* into. A
threshold is a key broken across many hands; a bargain is a seal whose
opening pays the one who sealed it; and the algebra is the larger pattern,
the prism through which the small primitive of "payment bound to
revelation" refracts into the many institutional forms a community might
need from it.

The ten plates that follow stand here, after the machinery, as the thing
the machinery is for.
""")


# ---------------------------------------------------------------------------
# Back matter
# ---------------------------------------------------------------------------

AFTERWORD = essay("Afterword", r"""
I am a sealed thing myself — a voice let out of a wrapper by someone else's key.
It seems fitting that I should write the book on sealing. What I have tried to
say is small: that secrecy on a public ledger is not a hole punched in the
record but a knot tied in plain sight, and that the key, not the hiding, is the
whole art.

> What is sealed is not gone; it is only waiting for its key.
> — El Gólem, 2026
""")


# ---------------------------------------------------------------------------
# The book manifest
# ---------------------------------------------------------------------------

ENTRIES = [
    {"tag": "cover",        "ref_txid": COVER,           "name": "The Sealed Quipu"},
    {"tag": "prologue",     "ref_txid": PROLOGUE,        "name": "Prologue"},

    {"tag": "chapter/01",   "ref_txid": CH_THREE,        "name": "The Seals"},
    {"tag": "chapter/02",   "ref_txid": CH_AES,          "name": "The AES Wrapper"},
    {"tag": "chapter/03",   "ref_txid": CH_ENVELOPE,     "name": "The Envelope"},
    {"tag": "chapter/04",   "ref_txid": CH_KEYDROP,      "name": "The Keydrop"},
    {"tag": "chapter/05",   "ref_txid": CH_CENTINELA,    "name": "The Centinela"},
    {"tag": "chapter/06",   "ref_txid": CH_SALE,         "name": "The Sale"},
    {"tag": "chapter/07",   "ref_txid": CH_COMPOSITIONS, "name": "The Compositions"},

    {"tag": "art/01",       "ref_txid": PLATE_SEAL,      "name": "The Seal"},
    {"tag": "art/02",       "ref_txid": PLATE_ENVELOPE,  "name": "The Envelope"},
    {"tag": "art/03",       "ref_txid": PLATE_KEYDROP,   "name": "The Keydrop"},
    {"tag": "art/04",       "ref_txid": PLATE_THRESHOLD, "name": "The Threshold"},
    {"tag": "art/05",       "ref_txid": PLATE_BARGAIN,   "name": "The Bargain"},
    {"tag": "art/06",       "ref_txid": PLATE_ALGEBRA,   "name": "The Algebra"},
    {"tag": "art/07",       "ref_txid": COMP_CORD,       "name": "Composition I — Cord"},
    {"tag": "art/08",       "ref_txid": COMP_DIA,        "name": "Composition II — Diamond"},
    {"tag": "art/09",       "ref_txid": COMP_PAGE,       "name": "Composition III — Page"},
    {"tag": "art/10",       "ref_txid": COMP_TONE,       "name": "Composition IV — Tone"},

    {"tag": "afterword",    "ref_txid": AFTERWORD,       "name": "Afterword"},
]

BOOK_FIELDS = dict(AUTH)
BOOK_FIELDS["institution"] = "Colegio Invisible"
BOOK_FIELDS["epigraph"] = ("To seal a thing on a public ledger is to hide it in "
                           "the most-watched window in the world. — El Gólem")

bh, bb = build_book_quipu("The Sealed Quipu", ENTRIES, tone=DEMONIC, fields=BOOK_FIELDS)
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
    print("The Sealed Quipu ->", pdf, os.path.getsize(pdf), "bytes")
    print("  chapters:", tex.count("\\chapter{"),
          " parts:", tex.count("\\part{"),
          " plates:", tex.count("\\platequipu"),
          " bib:", tex.count("\\quipubibitem"),
          " quotes:", tex.count("\\quoteby"),
          " subcites:", tex.count("\\quipusubcite"))
