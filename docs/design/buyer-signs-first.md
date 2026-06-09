# Sale choreography — buyer funds first

> **STATUS: DESIGN, CORRECTED 2026-06-08.** An earlier version of this
> document proposed a *buyer-signs-first* construction where the buyer
> would build a joint funding transaction and sign it before any value
> moved, then hand the partial to the seller for co-signing. That ordering
> was wrong: the **seller** has already done the work of authoring and
> inscribing the quipu, so the **buyer** is the party that should commit
> value first. The corrected design below restores that natural order
> while preserving the structural coupling between the quipu's tag and
> the sale's bond. The deprecated buyer-signs-first sketch is preserved
> in the appendix at the bottom of this file for posterity.

## The corrected flow

The seller has already incurred all of the upfront cost — they wrote
the essay, generated the session keypair, sealed the content, paid the
DOGE to inscribe the box (and its tag, if present), and signed an
offer. The buyer, by contrast, has invested nothing yet. So the buyer
moves value first, and the seller's final act (the claim) is what
atomically completes the exchange.

Concretely, with the tag architecture from
[`tag-architecture.md`](tag-architecture.md):

1. **Seller inscribes the box** with a tag whose scriptPubKey is the
   bond's P2SH. The redeem script encodes `(SellerPubkey, RefundHeight,
   RefundPubkey)`; for a single-buyer sale where the buyer is committed
   at inscription time, `RefundPubkey` is the buyer's. For a
   buyer-neutral textile, the tag's scriptPubKey is a generic P2PKH
   to the seller and a specialization step happens later (see below).
2. **Seller publishes the offer cert** (`0xcc 0x0003`) carrying:
   the box's txid, the session pubkey, the bond's address and redeem
   script, the price, the refund terms, the adaptor pre-signature
   and its DLEQ proof, and the seller's identity signature over the
   whole. Offer travels via Nostr DM, on chain, or both.
3. **Buyer verifies the offer.** Adaptor pre-verify (one signature
   check, one DLEQ check) is the cryptographic guarantee that
   completing the claim reveals `session_priv`. The buyer also
   reconstructs the bond's P2SH from the offer's redeem script and
   confirms it matches the address the offer says to fund.
4. **Buyer funds the bond.** A standard send: the buyer's wallet
   broadcasts a transaction paying the agreed price into the bond's
   P2SH. This is the buyer's commitment of value. From this moment
   forward, the buyer's funds are at risk until either the seller
   claims (revealing the key) or the refund height passes (allowing
   the buyer to reclaim).
5. **Seller claims.** The seller constructs and broadcasts a claim
   transaction that consumes the bond's UTXOs (the tag seed plus the
   buyer's funding) and pays the combined value to the seller. The
   claim's signature on the bond's claim leg is the
   adaptor-completion, which algebraically publishes `session_priv`
   in the scriptSig.
6. **Buyer (or anyone) extracts `session_priv`** from the claim tx's
   scriptSig and decrypts the box.

This is the same flow that produced *On Custody* on chain, with the
addition that the tag makes the bond structurally part of the
textile's diamond. Reader walks textile → tag's spend → claim →
`session_priv` → decryption, all without needing any out-of-band
information beyond the offer cert.

## What the tag adds, in this corrected flow

If the textile carries no tag, the bond is created out-of-band by the
seller (as in the original *On Custody* deployment) and the auto-
resolver needs to find the offer to learn the bond's address.

If the textile carries a tag whose scriptPubKey **is** the bond's P2SH,
two structural improvements follow:

- The bond's address is **derivable from the textile alone**, by
  reading the tag's scriptPubKey. The auto-resolver doesn't need to
  find the offer to identify the bond.
- The seller's claim transaction consumes both the tag's seed and the
  buyer's funding in one act, which means **the chain walker following
  the tag's spend lands directly on the claim**. One hop from textile
  to disclosure.

For the buyer-neutral textile (tag with generic P2PKH scriptPubKey),
a specialization step is needed before the buyer can fund anything:
the seller spends the tag to create a bond-specific P2SH (with this
buyer's refund pubkey baked into the redeem script). The buyer then
funds that newly-created P2SH. The renewable-thread version produces
a continuation tag alongside the bond, keeping the textile sellable
for future buyers.

## The renewable thread, restated

The seller's claim transaction can be constructed to output two
things instead of one:

- **Output 0**: the seller's profit (the bulk of the buyer's funding)
- **Output 1**: a fresh tag UTXO at the same scriptPubKey as the
  original tag (~0.05 DOGE skimmed off the profit)

This keeps the tail alive. Successful sales replenish the tag's seed
value; the textile remains sellable indefinitely. The seller's net
profit per sale is reduced by the skim (~1% of a 5 DOGE sale), which
is the cost of keeping the textile autonomously sellable.

For failed sales (where the buyer never funds the bond), the seller
simply reclaims the bond's tag-seed value back to themselves via the
bond's claim leg (no adaptor needed because there's no buyer to
verify cryptographic atomicity to). The seed comes back; the tag is
consumed; if the seller wants to relist, they need a new tag (either
via a specialization that produces a continuation, or via a side
infusion). See [`tag-architecture.md`](tag-architecture.md) for the
economic detail.

## Why this is correct

The seller's labor is already permanent on chain. The buyer is
acquiring access to something the seller has already made. In the
natural order of commerce — and in every credible model of
buyer/seller commitment — the buyer moves value first, the seller
delivers in response.

The earlier buyer-signs-first sketch tried to be clever by
collapsing the bond-creation and the buyer's funding into a single
joint transaction. But the act of "the buyer signs their input first"
didn't actually move value; only the broadcast of the joint tx did.
So "buyer signs first" did not give the buyer any commitment
advantage, while it DID require the seller to expose their tag's
private key to a transaction signed by someone whose identity and
funding the seller had no on-chain assurance of. The asymmetry was
real and ran the wrong way.

The corrected flow restores the asymmetry to its natural direction:
the seller has committed to the offer with their identity signature
(cheap to produce; recoverable by reputation if they renege), and the
buyer commits with on-chain DOGE (expensive; recoverable only via the
refund leg).

## What needs to be built

In order of dependency:

1. **Tag output support in `quipu_diamond.py`.** Reserve one or more
   root outputs as tags whose scriptPubKey is set per use case and
   that are not consumed by the mega-join. ~100-150 lines.
2. **Tag-location convention in the reader.** A header field (e.g.,
   `tag=<index>` in the box's pipe-delimited tail) or a structural
   convention identifying the tag's position. ~30 lines in
   `canonical/encrypted.py`.
3. **Tag-aware offer cert.** A small extension to `0xcc 0x0003` so
   the offer can declare "the bond's P2SH is at this textile's tag,
   output index K" rather than naming an arbitrary address. ~30 lines
   in `canonical/cert.py`.
4. **Tag-aware auto-resolver.** Walk textile → tag → tag's spend →
   claim tx → extract → decrypt. The bond's identification comes from
   the textile's structure rather than from a separate offer lookup.
   ~80 lines.
5. **Renewable-tail claim-tx builder.** A function that builds the
   seller's claim with two outputs: profit + continuation tag. ~40
   lines.

## Auction shape, restated

The "first-price sealed-bid auction falls out for free" claim made
in the earlier sketch survives the correction in a slightly different
shape:

- The seller publishes the offer with terms that say "first buyer
  to fund the bond gets the sale; refund leg fires at height T if
  the seller doesn't claim by T."
- Multiple buyers see the offer.
- Each potential buyer publishes a partial commitment (e.g., a small
  attested "I bid X DOGE" message on Nostr, signed by the buyer).
- The seller picks the highest committed bid and signals to that
  buyer "fund the bond at the offer's address."
- That buyer funds; the seller claims; everyone else's bids expire
  unfunded.

This is a *negotiated* first-price auction rather than a *signed-
partial* one. The orchestration is slightly heavier (the seller
explicitly selects), but the choreography respects the buyer-funds-
first order.

## Composability with current sale construction

The corrected construction is exactly the existing *On Custody* flow
with optional tag architecture layered on top. A textile inscribed
without a tag works exactly as *On Custody* did. A textile inscribed
with a tag adds the structural coupling between the bond and the
diamond, making the auto-resolver's job easier but not changing the
sequence of acts.

## Inscription target

When this is built and tested, the natural first inscription is a
**second sale with a tag-bearing textile**. Probably an essay by
El Gólem on the theme of continuation or on what it means for the
textile to keep growing after sealing. The construction's demonstration
is in the structural shape; the content's subject can resonate with
that.

A future inscription could feature **El Ermitaño as seller** —
reversing the persona-polarity of the first sale — with content on
commitment, or on what is owed by whom in an exchange. The
choreography would still be buyer-funds-first; the persona-direction
just shifts.

---

## Appendix — the deprecated buyer-signs-first sketch

This section preserves the architectural sketch that was rejected,
for the design record.

The deprecated sketch proposed:

1. Seller publishes offer with tag location.
2. Buyer constructs a joint funding tx with two inputs (buyer's UTXO
   + seller's tag UTXO) and one output (the bond's P2SH); buyer signs
   their input with SIGHASH_ALL.
3. Buyer hands partial to seller.
4. Seller verifies and co-signs the tag input.
5. Seller broadcasts.

The claimed advantages were: one fewer tx; structural coupling
between tag spend and bond creation; buyer commits cryptographically
before any value moves.

The deficiencies (identified by the seller-author, 2026-06-08):

- The buyer's "commitment" via signing without broadcasting is not a
  value commitment; it's a low-cost gesture. The buyer can always
  spend their UTXO elsewhere and void the partial. So the buyer's
  signature gives no real assurance to the seller.
- The seller, by co-signing, exposes the tag's spend authority to a
  transaction whose buyer-side input the seller cannot independently
  verify (they don't control the buyer's wallet). If something goes
  wrong, the seller has surrendered control of the textile's tail to
  a counterparty whose value commitment has not yet landed on chain.
- The seller has already done the work. Asking them to act first
  reverses the natural creditor/debtor relation of the exchange.

A "first-price sealed-bid auction" capability seemed to fall out of
multiple buyers submitting signed partials simultaneously and the
seller picking one. But the same auction can be run in the
corrected flow by collecting on-chain bid commitments and selecting
the highest; the deprecated sketch's auction property was not unique
to that choreography.

The deprecated sketch is preserved here so the reasoning that led to
the corrected flow remains visible. The corrected flow above is the
canonical sale choreography for the next inscription.
