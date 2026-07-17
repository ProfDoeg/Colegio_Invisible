# healing — the two grains of change

**Status:** POLICY, adopted 2026-07-12. Governs chain data and the
registry. Working documents (drafts, build scripts, this file) are not
governed by it — they heal by ordinary editing.

The whole policy in one sentence: **heal the map, never the territory.**

## The two layers

**Territory** — inscribed bytes. Immutable, never re-emitted, and every
canonical inscription must parse byte-exact forever
(`tests/test_corpus_regression.py`; until the estandarte is inscribed, the
goldens in `tests/golden/` play the same role for the registry itself).
Pre-inscription, a golden is territory *with a review valve*: regenerating
it under review is the working-tree analogue of an erratum amendment —
deliberate, diffed, additive in history — not a fork. The valve closes at
inscription; from then on the discipline below is absolute.

**Map** — what the registry *says about* the territory: type descriptions,
enum names, conventions. The map heals; the territory never does. A
correction to the map is an **addition** — an amendment layered leaf-wins
on the chain — and the superseded statement remains readable at every
historical leaf. Errata are additions, never rewrites; originals stay,
silent. (This is the same discipline the corpus already practices for
works: a repair quipu carries the corrected view on its own page; the
broken original is never touched.)

## Grain 1 — in-version healing (content errata)

*What may heal in-version:* claims about unchanged wire reality — a wrong
description, a missing enum value name, a typo in a convention. The bytes
on chain and the parsers that read them are untouched; only the registry's
account of them improves.

*What may never heal in-version:* anything that would make an existing
blob parse differently. That is not an erratum; that is a format change
wearing an erratum's clothes.

*Mechanism:* a same-version `0xee` amendment — `parent_txid` to the prior
leaf, carrying only the corrected entries (whole, keyed), ordinary tone,
signed by the then-current authority. Its root **pulls the prior root's
ripcord** (spends the cord as input 0) and re-arms a fresh one — so even
errata are unique by the double-spend rule; a dead cord falls back to the
signed `parent_txid` chain (the ripcord convention, c1dd0000.md).

*Locus:* once a later version exists, an erratum — even to inherited
content — rides the **current version's** chain (a vN amendment overriding
the inherited entry). A sibling amendment appended to an old version's
chain is invisible to vN readers, whose walk never crosses onto it. And
Grain 1 applies at v0 too: the constitution's *content* (a convention's
wording) may heal by v0 amendment under full ACH; what no amendment can
ever reach is the hardcoded seed capability
([c1dd0000.md](c1dd0000.md)).

## Grain 2 — between-version forking (format changes)

A change to the wire shape of bodies is a **new standard**, never an
edit: bump the version, declare by inherit + delta (the new estandarte's
`parent_txid` points at the prior version's **current leaf** — not its
root — so accrued errata are inherited rather than stranded on a sibling
branch; its root pulls that leaf's ripcord and re-arms a fresh one; only
touched entries re-stated), full ACH ceremony. The old
version's parse path freezes into read-only code, mirroring its read-only
corpus — old inscriptions are never migrated, re-emitted, or re-read
under new rules. The version stamp on each blob is the boundary stone.
(Monolith-era statement: if the registry ever splits per-type, the
boundary stone re-homes to the pinned type-registry leaf — c1dd0002 §8,
the version's-locus invariant.)

## The arbiter

A proposed correction is an erratum **iff every existing inscription
still parses byte-identically under it**. Otherwise it is a fork and must
take Grain 2. The corpus itself decides: the groundtruth gate and the
goldens are the court of first instance, and a "correction" that moves
them has ruled against itself.

*Scope of mechanical force (honest limit):* today the court can only
**convict, never acquit** — and only for corrections that flow through the
repo (reader code, working-tree source), because no parser consults
registry data (c1dd0002 §7's boundary: the registry is a dictionary, not
a grammar). A pure data amendment reaches no test; until grammar-as-data
lands it is judged by ACH review alone — a same-version amendment that
*redefines* an enum value (grayscale → rgb) would resolve cleanly and be
stopped by nothing mechanical. Accordingly the iff above quantifies over
**future grammar-fold readers too**: a redefinition that would change how
a fold-era reader parses existing blobs is a fork, even while today's
hardcoded readers ignore it. When the fold lands, the arbiter becomes
testable — re-parse the corpus under the proposed merged registry.

## What the code asserts today

- **Version monotonicity along chains** — an amendment claiming an older
  version than its parent is refused
  (`estandarte.resolve_estandarte_chain`).
- **Honest refusal of unknown versions** — readers parse nothing they
  don't implement (`estandarte.KNOWN_ESTANDARTE_VERSIONS`).
- **Legislation rides the constitution** — a v≥1 estandarte must be an
  amendment (`registry_v1.preflight_inscription_form`), and the check is
  wired into the real ceremony path: `quipu_preflight.check_decodes` runs
  it on any `0xee` body it gates (which also lets the `c1dd0000`
  constitution through the decode gate the literal-`0001` magic check
  would have rejected).
- **The freezes** — constitution and v1 goldens compare byte-exact on
  every test run; the corpus gate guards the inscribed territory.

The quorum split (below) is documented policy, not yet code — signatures
are not modeled until the ACH anchor fills.

## Open slot — the erratum quorum

Format forks, constitutional amendment, and authority succession are
**full ACH 3-of-3** by the tip rule. Whether content errata may ride a
lighter ceremony (a delegated erratum authority) is deliberately **open**,
like the ACH anchor slot itself: deciding it properly requires the
authority-succession model, and no erratum exists yet to force the
question. Until decided, errata are ACH-signed like everything else —
the conservative default.

## Cross-references

- [c1dd0000.md](c1dd0000.md) — the constitution; its "three tiers of
  change" table is this policy seen from the seed's side.
- [c1dd0002.md](c1dd0002.md) §2 — "one mechanism, two grains": the
  amendment chain carries both grains; the version byte separates them.
- `docs/quipu-types/estandarte.md` — amendment-chain wire format and
  leaf-wins resolution semantics.
