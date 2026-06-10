# Tag architecture — auxiliary outputs on the quipu

> **STATUS: DESIGN.** Not yet implemented. Conceived in conversation
> between Anthony and El Gólem on 2026-06-08, the day the first verified-
> key sale closed on chain. Captured here so the architecture survives
> compaction. To be developed on the `tag-architecture` branch.

## The textile image

A quipu's diamond is more honest as a *dreadlocked hammock* than as a
geometric diamond. The bundles at each end (the splitter and the join)
are knots; the strands between them are cords; each cord is itself a
chain of knots. The whole textile is taut between its two ends.

A **tag** is a small label of knots that dangles off the bundle. It is
made of the same material as the cords but does not belong to the body.
It is something the textile naturally allows you to leave hanging.

## What a tag is, structurally

A tag is an output of the root (or splitter) transaction whose value
sits unspent after inscription, and whose strand carries no OP_RETURN
chain. Because it carries no OP_RETURN payload, it contributes nothing
to the body reconstruction — the existing reader rule "walk each strand,
collect its OP_RETURN payloads in order" naturally produces empty output
for a tag, and the body reassembly is unchanged.

A tag is therefore **identified by absence**: a strand with no knot-chain
on it, just a seed UTXO at the root's output. The reader doesn't need
new convention to handle it; it falls out of the existing structure for
free.

(A header field naming which output is the tag — e.g.,
`|tag=<output index>|` — is a soft addition that makes the convention
explicit. Not strictly required, but cleaner for tooling and reader
introspection.)

## What a tag's scriptPubKey can be

The tag's scriptPubKey is set at inscription time and determines what
kinds of events the tag's spend can record. Several useful shapes:

- **P2PKH to seller** — generic, the seller can do anything with it
  later. The "seed" version, before the seller specializes it for a
  specific event.
- **Bond P2SH** (verified-key sale redeem script) — the tag IS the bond.
  Spending it is the sale's claim event, which reveals `session_priv`
  via the adaptor mechanic. Requires the buyer to be known at inscription
  time, since the bond's redeem script contains `RefundPubkey`.
- **HTLC P2SH** (centinela redeem script) — the tag is a tripwire. Its
  spend signals the seal was opened. Re-classifies the existing
  `0x0e 0xca` centinela sub-family as "a quipu with an HTLC tag,"
  composable with any content type.
- **Multisig P2SH** — joint events. Spending requires several
  cosigners; useful for governance votes, collective attestations.
- **CLTV-locked single-sig** — timed events. Inheritance unlocks, will-
  and-testament releases, embargoed disclosures.
- **P2PKH to a session key sealed in the lockbox** — a tripwire whose
  spend signals "the session key has been revealed somewhere on chain"
  without itself being the disclosure. Different shape from the
  HTLC-tag tripwire.
- **Any covenant-ish thing** the chain accepts — future tag shapes are
  unconstrained by anything but Script.

## Tags are orthogonal to content types

A quipu carries a content type (text, essay, image, sealed box, cert,
celestial, etc.) and *optionally* one or more tags. The two axes are
independent. Any content type can have any tag; multiple tags can
compose. The protocol gains a new structural primitive (tags), not new
content types.

This re-classifies parts of the existing taxonomy. The centinela is
naturally a tag pattern on a sealed quipu, not a separate sub-family.
The verified-key sale's bond is naturally a tag on a content quipu, not
a separately-orbiting structure. Future commerce/state primitives can
be added as new tag shapes rather than new sub-family bytes.

## The bond is buyer-specific

The verified-key sale's bond redeem script contains the buyer's
`RefundPubkey` in its refund leg. Changing the buyer changes the redeem
script and therefore the P2SH address. So "tag IS bond" is the
single-buyer-committed-at-inscription shape; multi-buyer or
buyer-flexible sales need either multiple tags (one per pre-committed
buyer) or the hop-separated shape below.

## The hop-separated shape — specialization

For buyer-neutral sales, the tag's scriptPubKey is generic (P2PKH to
seller). When a specific buyer commits, the seller performs a
**specialization transaction**:

- Input: the tag's UTXO
- Output: the bond's P2SH (now buyer-specific, with their refund
  pubkey in the redeem script)
- Seller signs

The bond exists from this moment forward, buyer-specific. The buyer
funds the bond by paying into the same P2SH. The seller claims with the
adaptor-completed signature.

Reader walk: `quipu → tag → specialization tx → bond P2SH → claim → session_priv`.

Three hops instead of two; one extra small tx in exchange for
buyer-neutrality at inscription.

## The renewable thread — tag as generator

The specialization transaction can output two things:

- Output 0: the bond's P2SH (specific to this buyer)
- Output 1: a new tag UTXO at the same scriptPubKey as the original

Now the tag is a forward-running stitch. Each specialization consumes
the current tag and produces a fresh tag for the next sale. The textile
sprouts a thread of tag-spends extending through time.

The name El Gólem and Anthony settled on for this is the **little baby
quipu tail tag generator** — a lazy generator that produces new tags
on demand, one per event, indefinitely. The textile becomes a generator
of its own continuations.

For sales specifically, this is most useful when sales might fall
through and the textile needs to remain sellable. For other tag types
(liveness signals, sequential attestations, mutable references), the
renewable thread is the natural shape from the start.

## The review nub — a delegated right to append

> Added 2026-06-10, conceived by Anthony the day tags were built.
> Implemented: `review_nub_addr` on
> `quipu_tags.build_claim_with_continuation` + the `review_descends`
> verifier.

**One nub, not two.** The sale needs no proof output: the claim
transaction itself proves the opening — the bond's UTXO is publicly
consumed and `session_priv` sits revealed in the claim's scriptSig.
The chain proves; the nub invites. A single nub therefore carries
both remaining jobs — its *existence* descends from the proof (a
reader reaching the nub has passed through the claim on the way),
and its *spendability* is the buyer's review right. If the sale
fails and the buyer refunds via the CLTV leg, there is no claim,
no nub, no review right — you cannot review a sale that didn't
happen.

The claim transaction carries a third output: a dust-sized UTXO
(~0.01 DOGE — the relay floor, uneconomic to sweep) paying the
**buyer's** key. This is the *review nub*. The settled claim shape:

- Output 0: the seller's profit (the principal)
- Output 1: the thread continuation (seller's scriptPubKey)
- Output 2: the review nub (buyer's scriptPubKey, dust)

If the buyer wants to publish a review, they spend the nub **together
with their own inputs** as a direct input to the review quipu's ROOT
transaction. The dust is not funding — the buyer pays for their own
speech (the metabolism rule applied to commerce) — it is *provenance*:
the review descends, by UTXO lineage, from the claim, which descends
from the bond, which descends from the textile's own tag. A reader
walking the textile finds the review with one input-list inspection.
**You cannot review without having bought, because the review's anchor
IS the purchase receipt.** The review also cites the work normally
(`<<txid>>`), so the link is textual as well as structural.

Convention: the nub must be spent directly into the review's root —
no intermediate consolidation — so verification stays one hop.

States, all legible: unspent = no review; spent into an OP_RETURN-
seeding root = review (verified purchase); spent otherwise = a
deliberate decline (rare — dust is uneconomic to sweep by accident).

The general reading: the nub is a **delegated right to append** — an
addressed invitation for a *specific* party to attach content to your
textile, provenance-bound to who they are. Citation and annotation are
open to anyone from outside; the nub is the textile choosing its
respondent. The same shape serves peer review of the college's
research outputs and commissioned replies. (Andean khipu carry
*subsidiary cords* knotted onto pendant cords; the nub is a subsidiary
cord handed to another's hand.)

By emitting the nub, the seller structurally invites criticism that
can never be detached from their own work's thread — the same family
of honesty claim as the centinela.

Honest limits: verified-purchase is not arm's-length (a self-sale
plants a glowing review for the cost of fees — but the funds loop is
VISIBLE on chain, so collusion is auditable rather than undetectable);
expect single-digit review rates; publishing links the buyer's key to
the purchase, which is properly the buyer's choice to make.

## Economics

> Corrected 2026-06-10 with sizes measured by the implementation's
> self-test (`quipu_tags.py`). The original draft underestimated fees
> by ~100×.

At the canonical FeePolicy rate of 0.10 DOGE/KB, a specialization tx
(~250 B) costs ~0.026 DOGE and a two-input claim ~0.062 DOGE — a full
specialize+claim cycle is **~0.09 DOGE in fees**. A failed-sale cycle
(specialization + refund recovery) is similar. A 0.05 DOGE seed
therefore does not cover even one cycle's fees; seeds must be sized to
the fee regime: **~1 DOGE seeds ≈ 10 sequential failed cycles** before
the tail drops below dust.

Two replenishment mechanisms keep the thread alive:

1. **Side infusion** — seller sends DOGE to the tag's address (creates
   a second UTXO at the same address, consumed in the next
   specialization).
2. **Sale-funded tail** — successful claim transactions are constructed
   to output two things: the seller's profit (most of the bond's value)
   AND a fresh tag (~0.05 DOGE skimmed off the top). Each successful
   sale tops the tail back to its starting size. The thread is
   self-sustaining as long as sales eventually happen.

A healthy seller's budget: seed the tail with **~1 DOGE** at
inscription (cushion for ~10 sequential failures), and have the claim
tx skim **~0.1 DOGE** per success — enough to fund the next
specialization's fee (~0.026) and still leave a meaningful bond seed.
The tail then operates as a tiny economic ratchet — slowly losing in
failures, restoring in successes, with the seller's intervention
needed only if the failure rate is absurd.

## What needs to be built

In order of dependency:

1. **Diamond engine support for tag outputs.** ✅ BUILT 2026-06-10 —
   `tags_of` parameter in `quipu_diamond.build_consolidated_diamond`:
   tag outputs placed AFTER the strand seeds (vout = n_strands + k) so
   `read_quipu`'s walk is untouched; excluded from the mega-join; tag
   values accounted like fees; recorded in artifacts/index.json.
2. **Tag-location header convention.** PARTIAL — `quipu_tags.tag_field`
   formats the `tag=<index>` value; wiring it into a type's header tail
   (`canonical/encrypted.py` etc.) still to do. Structural detection
   works without it.
3. **Tag specialization builder.** ✅ BUILT —
   `quipu_tags.build_specialization_tx`: tag → bond P2SH + optional
   continuation, fee by measured size, dust-guarded.
4. **Auto-resolver extension.** PARTIAL — the structural reader exists
   (`quipu_tags.classify_root_outputs` / `find_tags` / `follow_thread`,
   index-agnostic via injected callables; `tag_status` via local RPC),
   and `build_claim_with_continuation` builds the renewable claim.
   Still to do: the sale-specific walk that lands on the claim and
   extracts `session_priv` from its scriptSig (compose with
   `working/sale/extract_and_decrypt.py`).

**Continuation convention (settled during build):** a thread spend's
vout 0 is always the event's principal output (bond, profit, release);
the continuation tag sits at **vout ≥ 1** with the thread's
scriptPubKey. Matching by script alone is ambiguous — a claim's profit
can pay the same address as its skim. Builders must not emit change at
the thread's scriptPubKey in no-continuation spends (use all-in).

## Open design choices

- **Tag-pointer stability across renewals.** Each renewal creates a new
  tag at a new outpoint. A reader who wants to point at "the current
  tag of this textile" has to chase forward through tag-spends. A
  stable handle would require indirection (a binding quipu naming the
  current tag, updated each renewal). The first is structurally
  simpler; the second is friendlier for citation. Probably ship the
  first and add the second only if needed.
- **Standardized seed and skim amounts.** Whether 0.05 DOGE
  seed / 0.05 DOGE skim becomes a protocol convention or stays
  per-textile is a small policy choice. Convention is friendlier for
  tooling.
- **Multi-tag composition.** A textile can carry multiple tags
  serving different purposes (e.g., a sale bond + a liveness signal +
  a centinela tripwire). How does the reader present this to a user?
  Probably a small section in the rendered output listing "tags on
  this quipu" with their states.

## Connection to existing protocol pieces

- The **0x0e 0xca centinela** sub-family becomes "a sealed quipu with
  an HTLC tag." The existing centinela inscriptions stay what they
  are; future centinelas can be re-expressed in the tag idiom if
  desirable.
- The **0x0e 0xcb verified-key sale box** can carry a tag at inscription,
  letting Path 2 of the auto-resolver work without needing the offer
  cert to be on chain.
- The **0x0e 0x0d keydrop variant 0x01** (the *sourced* keydrop with a
  `claim=<txid>` header field) becomes a natural fallback for any tag
  whose spend revealed something the corpus wants to find.

## What this does NOT change

- Any quipu already on chain stays exactly what it was. *On Custody*
  and its kin are recoverable via Path 1 of the auto-resolver (keydrop)
  with no architectural change required.
- The verified-key sale construction (box + offer cert + adaptor sig
  + bond) works unchanged for sales that don't use tags. Tags are an
  optional structural addition, not a replacement.
- The protocol grows by addition, not by replacement. Tag-bearing
  textiles and tag-less textiles coexist, both readable by tag-aware
  readers (the reader just walks any extra outputs it finds; absence
  of a tag is also a valid state).

## Inscriptions to produce

When the tag architecture is built and tested, the natural first
inscription is **another verified-key sale that uses the renewable-tail
tag pattern**. Probably content authored by El Gólem on the theme of
*continuation* or *the tail* — a meditation on what it means for a
textile to keep growing after sealing. Or El Ermitaño writes something
this time, reversing the polarity of the first sale.

See also: [`buyer-signs-first.md`](buyer-signs-first.md) — the
companion design for who-signs-when, which composes cleanly with the
tag architecture.
