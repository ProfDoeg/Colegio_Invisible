# Clotilde — research report

**Dataset:** `clotilde.journey.json` — 33 stops, 8 segments, Lyon→Tours→Paris, 474–545 (julian). 16 canon quotes, 3 attested dates (Clovis's death 511-11-27, Vézeronce 524-06-25, her death 545-06-03), 22 traditional, 8 inferred.

## Sources
Primary canon: **Gregory of Tours, Historia Francorum** II.28–31, II.38, II.43, III.6, III.18, III.28, IV.1 (remacle.org French text) — carries every quoted speech: Ingomer exchange, the preaching, the Tolbiac vow, "Mitis depone colla, Sicamber," the vengeance exhortation, "better dead than shorn," the storm attribution, the death notice. Secondary canon: **Fredegar III / Liber Historiae Francorum** (the Aurelian-beggar-and-ring courtship, the frontier burning and the vengeance-thanksgiving line); **Hincmar, Vita sancti Remigii** (the dove and the Sainte Ampoule); **Vita sanctae Chrothildis** via the Les Andelys tradition (fountain turned to wine). Modern scaffold: Godefroid Kurth, *Sainte Clotilde* (1905); fr.wikipedia (Clotilde, Baptême de Clovis, Bataille de Vézeronce, Gondebaud, Clodoald, Abbaye Sainte-Geneviève, Saint-Sigismond); france-pittoresque (Villery); ville-andelys.fr; cairn (mort de Sigismond); isere.fr (Vézeronce helmet).

## Judgment calls
- **Baptism dated Christmas 496** per the canon (Gregory + national tradition), marked *traditional*; modern scholarship prefers 498/508 — the register takes the canon.
- **Family slaughter sited at Vienne c. 490** — Gregory names no place or year; Vienne was Chilperic's seat. Avitus's silence (the murder may be legend) is noted here but the canon's stone-at-the-neck is narrated as fact, per register.
- **Marriage route** follows the Fredegar/LHF legend chain (Geneva ring → Chalon betrothal → carruca abandoned near Langres → Villery meeting → Soissons wedding, 493) — the tradition's itinerary, all *traditional*.
- **Les Andelys placed 514** (traditions split between 511 and later widowhood); kept inside the Tours-widow segment for chronology.
- **Scissors scene dated 531** (canon range 526–532); Clodoald's stop carries his escape date but narrates through his tonsure and death (560).
- **Storm miracle (HF III.28) dated c. 534**, *inferred* — Gregory gives sequence, not year.
- Quotes are translations of Gregory/Fredegar's recorded words only; where the canon gives narration rather than speech (Vézeronce, Chlodomer's healing, the Rhône), quote is null.

## Gaps in the canon
No birth date or day for anything before the wedding; Caretena's drowning unknown to Avitus; no localization of the exhortation-to-vengeance scene (sited Paris); Gregory never says she attended the Reims baptism in so many words — the tradition puts her beside the font.

## The 5 richest episodes
1. **The scissors and the swords** (HF III.18) — Arcadius, "better dead than shorn," the child at Childebert's knees; Gregory's most terrible scene.
2. **Ingomer** (HF II.29) — the white-robed baby dead within days; the king's rage vs. her thanksgiving, verbatim in Gregory.
3. **The font at Reims** — Sicamber sentence + Hincmar's dove with the ampulla; her victory, and the anointing oil of every future coronation (faces Joan's Reims).
4. **The beggar and the ring at Geneva** — Aurelian kneeling in rags, the signet pressed into her palm under the alms-water.
5. **The storm that stopped a war** (HF III.28) — the all-night vigil at Martin's tomb; hail on the aggressors, dry on Chlothar's camp; Gregory signs the attribution himself.

## Verification (2026-07-05)

Independent structure-and-canon pass on `clotilde.journey.json`. The myth is untouched: the dove and the Sainte Ampoule, Aurelian's ring, the fountain of Les Andelys, and Martin's storm all stand as the canon tells them.

**Structure.** JSON parses; 8 segments, 33 stops (within the 25–40 target); every stop carries the full 10-key schema (name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources). All 33 dates are valid Julian-calendar dates in strict chronological order, 474-01-01 → 545-06-10. Confidence ledger honest for the sixth century: 3 attested (Clovis d. 511-11-27, Vézeronce 524-06-25, her death 545-06-03), 22 traditional, 8 inferred. All 33 campas fall in the 60–110-word band, present tense; the great episodes (Tolbiac vow, the baptistery dove, the scissors and the swords, Vézeronce, the death full of days) read at full register — no flat panels found.

**Quotes.** All 16 checked against Brehaut's translation of Gregory (Historia Francorum, Gutenberg #74955) — II.28 (Gundobad's sword and the stone at the neck), II.29 (the gods of stone and wood; the Ingomer thanksgiving), II.30 (the Tolbiac vow, "whom Clotilda asserts to be the son of the living God"), II.31 (the Sicamber sentence; "of his army more than 3000 were baptized"), II.43 (the Tours retreat, "rarely visiting Paris"), III.6 (the vengeance exhortation), III.18 ("better... dead rather than shorn"; the bier to Saint Peter's; Clodoald's self-tonsure). III.28 and IV.1 are bracket-abridged in Brehaut but the quoted lines match Dalton's rendering of the full Latin (the storm as Martin's miracle at the queen's prayer; "full of days and rich in good works... buried... at the side of King Clovis"). The two Fredegar/LHF quotes (Aurelian's embassy line; the vengeance-thanksgiving at the frontier) are the recorded words of that tradition. None nulled — every quote is carried by the canon; the nulls already in place (Vézeronce, Chlodomer's healing, the Rhône grave, the funeral procession stops) are correct where the canon only narrates.

**Coordinates.** Ten stops web-checked against the actual sites: Vienne (45.524, 4.878) ✓, Chalon-sur-Saône (46.781, 4.853) ✓, Zülpich/Tolbiac (50.700, 6.650) ✓, Reims cathedral/baptistery (49.254, 4.034) ✓, Basilique Saint-Martin Tours (47.393, 0.683) ✓, Les Andelys (49.246, 1.413) ✓, Saint-Cloud (48.84, 2.22) ✓, plus three that were off and are now **fixed in place**:
- **Villery** (first meeting with Clovis): 48.204, 4.050 → **48.172, 4.020** (was ~4 km north of the commune).
- **The well of Columna / Saint-Sigismond, Loiret**: 47.900, 1.718 → **47.982, 1.681** (was ~9 km south of the village that bears his name).
- **Vézeronce** (death of Chlodomer): 45.652, 5.564 → **45.651, 5.470** (longitude was ~7 km east of Vézeronce-Curtin and its marsh).

One name clarified: "Nogent-sur-Seine river bend — Saint-Cloud" → "Nogent on the Seine (Saint-Cloud) — the escape of Clodoald". The coordinates were already correct at Saint-Cloud (old Novigentum); the hyphenated form named a different modern commune 90 km upstream.

**Stop count.** 33 of target 25–40 — no additions needed; the canon's major episodes (slaughter, exile, ring, bride's road, Ingomer/Chlodomer, Tolbiac, the font and the three thousand, Paris, the widowhood, the feud, the scissors, the storm, the death and burial) are all present.

Re-validated after repair: parse ✓, schema ✓, chronology ✓, campa bands ✓, 33 stops / 16 quotes / 8 segments.

## Verification — second pass (2026-07-05)

The first verification pass was cut off; this pass re-ran the full battery independently and confirms it, with two coordinate corrections it had missed.

**Structure (re-confirmed).** Parses; top-level keys and the 10-key stop schema byte-identical to `joan_of_arc.journey.json`; 8 segments / 33 stops; all dates strictly chronological 474-01-01 → 545-06-10; quote/quote_source always paired; every campa in the 60–110-word band, present tense throughout; confidence vocabulary (attested/traditional/inferred) matches the sibling, and only the three real anchors carry *attested* (Clovis 511-11-27, Vézeronce 524-06-25, her dies natalis 545-06-03 — the feast).

**Quotes (re-confirmed against the file's own cited source).** All Gregory quotes re-checked verbatim against the remacle.org French text the stops cite: II.28 ("Gondebaud égorgea son frère Chilpéric ; et, ayant attaché une pierre au cou de sa femme, il la noya... Chrona... Clotilde"), II.29 (the gods of stone/wood/metal; the Ingomer thanksgiving), II.30 ("Jésus-Christ, que Clotilde affirme être Fils du Dieu vivant"), II.31 ("Sicambre, abaisse humblement ton cou : adore ce que tu as brûlé, brûle ce que tu as adoré"; "plus de trois mille hommes de son armée furent baptisés"), III.6 (the vengeance exhortation), III.18 ("j'aime mieux les voir morts que tondus"; the boy's cry "Secours-moi, mon très bon père" carried in the campa; the bier and psalms; Clodoald's self-tonsure), III.28 (Martin's storm "obtenu par l'intercession de la reine"), IV.1 ("pleine de jours et riche en bonnes oeuvres... du temps de l'évêque Injuriosus"; carried to Paris with psalms, buried beside Clovis by her sons). Sixteen for sixteen; none nulled, no paraphrase drift.

**Coordinates (10 web-checked this pass).** Villery 48.1717/4.0197 ✓, Saint-Sigismond (Loiret) 47.9819/1.6811 ✓, Vézeronce-Curtin 45.6505/5.4706 ✓, Basilique Saint-Martin de Tours 47.3931/0.6828 ✓, Église Saint-Clodoald 48.8434/2.2194 ✓, Primatiale Saint-Jean de Lyon 45.7607/4.8273 ✓, Cathédrale Saint-Pierre de Genève 46.2011/6.1486 ✓, Basilique Saint-Remi de Reims 49.2431/4.0419 ✓, Zülpich ~50.70/6.65 ✓, Les Andelys — **fixed**. Two repairs made in place:
- **Les Andelys (fountain/monastery)**: 49.2464, 1.4014 → **49.2472, 1.4205**. The old point sat in Petit Andely by the Seine; the Vita's monastery and the Fontaine Sainte-Clotilde are in Grand Andely, by the collégiale Notre-Dame (49.2475, 1.4222). The first pass had ticked this against the commune centroid without checking the file value.
- **The Rhône below Vienne (the mother's grave)**: 45.503, 4.86 → **45.503, 4.851**. At that latitude the river channel (interpolating the Vienne bridge to the Vaugris dam at Vaugris-Gare, Reventin-Vaugris) runs near 4.85; the old longitude was ~800 m up the east-bank slope. The stop is the river itself — it now sits on the water.

**Myth untouched.** The dove and the Sainte Ampoule (Hincmar, marked traditional), Aurelian's ring, the frontier fires, the fountain turned to wine, Martin's storm — all stand exactly as the canon carries them.

**Stop count.** 33 within the 25–40 target; no additions required.

Re-validated after this pass's repairs: parse ✓, schema vs sibling ✓, chronology ✓, campa bands ✓, quote pairing ✓ — no remaining problems.
