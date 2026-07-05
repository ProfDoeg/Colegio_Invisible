# Charles Martel journey — research report

**Dataset:** `charles_martel.journey.json` — 40 stops, 7 segments, c. 688–741 (julian).

## Sources
Primary canon: **Continuations of Fredegar** (cc. 8–24, the Carolingian house chronicle, Childebrand's commission), **Liber Historiae Francorum** (cc. 49–53, Neustrian, contemporary), **Mozarabic Chronicle of 754** (the fullest Tours account; the *Europenses* / wall-and-glacier passage), **Vita Wulframni** (Radbod at the font), **Willibald's Vita Bonifatii** + Boniface's letters (Fordham sourcebook; Ep. 63 quoted), **Codex Carolinus** (Gregory III's 739 appeals), **Vita Eucherii** / Hincmar's Quierzy letter of 858 (the hell-vision), and the Fierbois file from Joan's 1431 trial record. Secondary: Wikipedia site articles for coordinates, deremilitari.org (Tours-Poitiers revisited; Berre account), 8thcentury.com (Maurontus), jeanne-darc.info / experienceloire (Fierbois).

## Judgment calls
- **Full-date requirement vs. year-only canon.** Only a handful of days are attested (Pepin's death 16 Dec 714; Cuise 26 Sept 715; Vincy 21 Mar 717; death 22 Oct 741; Tours' 25 Oct is *traditional*). Everything else carries an invented day marked `inferred`/`traditional` — treat the day as a slot, the year as the datum.
- **Chronology over theme.** Strict global date order forced the Boarn (734) and the Aquitaine entry (735) out of the northern/southern thematic legs into a bridge segment, "Between the Two Seas."
- **Fierbois** given full weight as the corpus's own hinge to the Joan and Hypatia/Catherine journeys; the quote is Joan's trial testimony (canon of the facing journey), with the Chapelain-era legend flagged only implicitly by `traditional`.
- **Tours battlefield** placed at Moussais-la-Bataille (Vouneuil-sur-Vienne), the conventional French siting; three stops (seven days / battle day / empty tents) to carry the Mozarabic Chronicle's structure.
- **The hostile miracle kept.** The Eucherius hell-vision (Church-lands seizure) is narrated as fact per register — the canon's grumble is part of the canon.
- **Gibbon** confined to the Tours campa margin, not the quote field.

## Gaps in the canon
His birth (year ≈ 688, no day, no site more precise than the Herstal domain); the mechanics of the Cologne escape (one clause in LHF); the exact Tours date and site (a road, a Saturday, an October); where the 741 divisio was enacted (placed at Quierzy); Maurontus's actual rock; the Alemannian and Saxon campaign geography (rivers stand for routes). Radbod's death-place is nowhere given — Utrecht is a mission-stage, not an attested deathbed.

## Five richest episodes
1. **The escape from Plectrude's Cologne** (715) — one sentence in the LHF carrying an entire providential turn.
2. **Tours-Poitiers** (Oct 732) — the wall/glacier quote, the emir's fall, the silent tents at dawn: the minting of Europe's salvation myth in a hostile southern source.
3. **Fierbois** — the sword of five crosses rusting 700 years for Joan; the journey's forward-facing joint.
4. **Avignon 737** — the Fredegar continuator's Jericho: trumpets, ropes, Scripture as siegecraft.
5. **The keys of Saint Peter** (739) — rescue refused, dynasty's door opened; paired with the empty throne of 737 (kingship suspended by omission).

## Verification (2026-07-05)

Independent structure-and-canon pass over `charles_martel.journey.json`.

**Structure.** JSON parses; stop schema (`name/date/date_confidence/lat/lng/campa/quote/quote_source/sources/suggested_refs`) is byte-identical to the sibling journeys (joan_of_arc, hypatia, hannibal). 40 stops in 7 segments — within the 30–45 target; no additions needed. All 40 dates in strict chronological order; all campas 60–110 words, present tense; the great episodes (the tower escape, Radbod at the font, the oak of Geismar, the wall of ice, the silent tents, Jericho at Avignon, the keys, the tomb at Saint-Denis) carry weight — none flat.

**Coordinates.** 14 sites geocoded against OSM/Nominatim: Herstal, Jupille-sur-Meuse, Cuise-la-Motte, Amel (Amblève), Les Rues-des-Vignes (Vincy), Fritzlar/Geismar, Sainte-Catherine-de-Fierbois, Vouneuil-sur-Vienne (Moussais), Quierzy, Blaye, Chelles abbey, Arènes de Nîmes, Basilique Saint-Denis, plus the Boarn/Middelzee placement. All within ~1–3 km of the named site (Nîmes arena and Saint-Denis basilica exact); the Boarn mouth sits in the old Middelzee bed, correct for the eighth-century estuary. No coordinate fixes required.

**Quotes.** 6 of 9 spot-checked against the canon: the Garonne "God alone knew the number of the slain" and Boniface Ep. 63 confirmed verbatim on the Fordham sourcebook; the wall/glacier passage is K.B. Wolf's standard rendering of the Mozarabic Chronicle of 754 (Fordham carries the older "bulwark of ice" translation of the same passage); Fredegar cont. c. 20 (Jericho) and c. 22 (keys of the venerable tomb) match Wallace-Hadrill; Joan's 27 Feb 1431 Fierbois testimony matches the trial record. LHF c. 49 (*elegans*) and c. 51 (escape *Deo auxiliante*) and the Vita Wulframni font retort are canonical. None nulled.

**One repair.** Stop 37 (Quierzy, the keys embassy, 739-10-01) was marked `attested`; the year 739 is attested (Fredegar cont. c. 22, Codex Carolinus) but the day is an invented slot — changed to `inferred`, consistent with this report's own judgment call. The attested day-date set is now exactly the four anchors: Jupille 714-12-16, Cuise 715-09-26, Vincy 717-03-21, Quierzy 741-10-22 (Tours 732-10-25 stays `traditional`).

**Register.** Myth intact throughout: Fierbois at full weight as the hinge to Joan, the Eucherius hell-vision narrated as fact per register, the salvation-of-Europe minting kept in-voice. File re-validated after the repair.
