# Clovis — Tournai to Paris (466–511): research report

**Dataset:** `clovis.journey.json` — 37 stops, 8 segments, 17 canon quotes. Register: national mythology; the canon is true.

## Sources
Primary canon: **Gregory of Tours, Historia Francorum II.27–43** (Brehaut translation, 1916, via the Fordham Internet Medieval Sourcebook full text) — every quote was checked verbatim against this text, none paraphrased. Supporting canon: **Fredegar III** and the **Liber Historiae Francorum** (Aurelian's beggar-disguise embassy, Basina's vision of the beasts, the ox-cart left on the road); **Hincmar's Vita Remigii** (the dove and the Sainte Ampoule — a 9th-century addition, but inside this register it is the event); **Acta of the First Council of Orléans** (the one cleanly attested date, 10 July 511, and the synodal letter's salutation); **Chifflet, Anastasis Childerici I (1655)** for the golden bees.

## Judgment calls
- **Dates:** almost everything is year-only in the canon; days are honest fabrications marked `traditional` (year carried by tradition/Gregory's regnal arithmetic) or `inferred` (my sequencing). Only Orléans 511-07-10 is marked `attested`. Vouillé is marked `traditional` even though the year 507 is rock-solid, because the day (spring) is convention. Death 27 Nov 511 is the liturgical tradition, so `traditional`. The Field-of-March stop exploits Gregory's "end of a year" + the Frankish 1 March muster: 487-03-01.
- **Baptism year:** kept at Christmas 496 (the canon's tradition) — modern scholarship argues 498/508; noted, ignored, per register.
- **Childeric's tomb** got its stop at the 481 burial, with the 1653 opening (Quinquin's pick, 27 May 1653 — attested) narrated forward inside the campa, so chronology holds and the bees still swarm.
- **Placements the canon leaves blank:** Chararic at Thérouanne (later tradition), the Thuringian war at the Unstrut seat (the 491 campaign's geography is genuinely disputed — possibly Tongres-area "Thuringians"), the Vienne ford at the Gué de Cenon by Vieux-Poitiers, the marriage at Soissons. All marked `inferred` or flagged "traditional site" in the stop name.
- **Quotes:** Brehaut renders the Sicamber line "Gently bend your neck, Sigamber; worship what you burned; burn what you worshipped" — I used his exact wording rather than the more famous French cadence. Where Gregory records no speech (ampulla, Vouillé, Angoulême, consulship, death) the quote is null.

## Gaps in the canon
Gregory gives no route detail between set pieces: nothing on where Clovis wintered before Tolbiac, no place for Chararic's capture, one sentence for all of Thuringia 491, and nothing at all of the years 493–496 and 501–506 beyond the Amboise interview. The prompt's "angel-lit shortcut" at the Vienne is, in Gregory, the hind alone; I kept the hind. Clovis's own voice is entirely Gregory's construction — the register accepts this.

## The five richest episodes
1. **The Vase of Soissons + Field of March** (II.27) — demand, axe-blow, and the year-delayed answer: the founding parable of Frankish kingship in two stops.
2. **Tolbiac vow → Reims font → Ampulla** (II.30–31 + Hincmar) — the Constantine arc complete, with the dove supplying the coronation oil of thirteen centuries; the stop faces Joan's 1429 Reims as instructed.
3. **The Vouillé miracle-road** (II.37) — edict of Saint Martin, psalm-omen at the basilica door, hind at the ford, fire from Saint-Hilaire, walls of Angoulême: five signs in one campaign, the densest miracle sequence in the book.
4. **The removal of the kings** (II.40–42) — treasure-chest axe at Cologne, green-wood tonsure, false-gold bracelets at Cambrai, and the lament-as-trap: Gregory recording the cunning without blinking, then blessing it.
5. **Childeric's bees** — pagan grave-gold sleeping 1,172 years and rising straight onto Napoleon's coronation mantle: the journey's frame, myth eating history at both ends.

## Verification pass (2026-07-05)

Independent structure-and-canon-fidelity pass; the researcher's file survived largely intact. Four repairs, all in place; file re-validated with python after repair.

**Structure.** JSON parses. Top-level keys and stop keys are byte-identical to `joan_of_arc.journey.json` (traveler/title/years/calendar/register/segments; campa/date/date_confidence/lat/lng/name/quote/quote_source/sources/suggested_refs). 37 stops, 8 segments — within the 30–45 target, and the canon (Historia Francorum II.27–43) is fully covered; no episodes worth a stop are missing, so none were added.

**Dates.** All 37 in strict chronological order. Confidence audit: 20 traditional, 16 inferred, 1 attested — the single `attested` is Orléans 511-07-10, which the acta genuinely carry; the baptism Christmas, Vouillé spring, and death 27 Nov are correctly left `traditional`. Honest.

**Coordinates.** 18 stops geocoded against Nominatim/OSM. 15 within ~100–400 m (Tournai cathedral, Soissons, Zülpich, Reims cathedral, Saint-Remi basilica, Dijon, Vouillé, Tours Saint-Martin basilica, Panthéon/Sainte-Geneviève hill, Geneva, Avignon, Thérouanne, Cambrai, Cologne cathedral, Amboise Île d'Or, Angoulême, Bordeaux, Toulouse). Three fixed:
- **Saint-Brice, Tournai** 50.6103,3.3936 → **50.6081,3.3950** (the actual church by Childeric's tomb).
- **Ford of the Vienne** 46.7186,0.5428 → **46.7620,0.5325** — the old value sat at Vouneuil-sur-Vienne, ~5 km upstream of the Gué de Cenon by Vieux-Poitiers that the stop's own name and ref claim.
- **Saint-Hilaire, Poitiers** 46.5744,0.3384 → **46.5773,0.3327** (Saint-Hilaire-le-Grand itself).

**Quotes.** All 16 Gregory quotes machine-diffed against the Brehaut/Fordham full text: 15 verbatim (modulo mid-quote inquits — "said he" — and Fordham's OCR artifact "1iving God" in the Tolbiac vow; the journey correctly reads "living"). One repaired: the **Chlodomer** quote read "…baptized in the name of your Christ, *he* should die at once" — Brehaut carries no "he"; restored to canon. The vase demand, the axe answer, the Sicamber line ("worship what you burned"), the vow, the green-wood speech, the kin-lament, and the Aridius counsel are all exact. The Orléans salutation is a faithful rendering of the acta's Latin ("Domno suo catholicae ecclesiae filio Chlothovecho gloriosissimo regi…"), kept as non-Gregory canon.

**Campa voice.** All 37 present tense, 66–110 words (none out of range). The great episodes are not flat: the vase, the font, the ampulla, the hind, the lament-trap all carry their weight. Mythic time-folds (bees→Napoleon, ampulla→1825, Reims facing Joan's Reims) stay, marked by confidence, per register.

**Verdict:** dataset sound; 4 repairs applied (3 coordinates, 1 quote restored to verbatim canon); re-validated clean.
