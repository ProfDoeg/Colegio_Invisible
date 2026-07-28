# The Lady of the Lake — Brocéliande to Avalon: research report

**Dataset:** `lady-of-the-lake.journey.json` — 6 segments, 8 stops, c. 500-537 (Julian, traditional throughout), 4 stops carrying canon quotes (Malory verbatim). Spanish parallel: `lady-of-the-lake.journey.es.json` (same shape, translated prose fields, quotes rendered from Malory's Middle English with the source noted as "(traducción)").

## Sources
Primary spine is Malory's *Le Morte d'Arthur* (Caxton text, via Wikisource/gutenberg excerpts and cross-checked quotations): Book I, Ch. XXV (the gift of Excalibur — the arm in white samite, the damosel's bargain, Merlin's word on the scabbard); Book IV, Ch. I (Merlin "assotted" on Nimue, the binding under the stone); Book XXI, Ch. V-VI (Bedivere's threefold errand, the arm that catches the returned sword, the black-hooded barge, Nimue named among the queens as "the chief lady of the lake" who wed Sir Pelleas). The Brittany material (Comper's crystal palace, the fostering of Lancelot, the Fontaine de Barenton as the meeting-place with Merlin) comes from the Vulgate Cycle / Prose Lancelot tradition and its modern local custodian, the Encyclopédie de Brocéliande (broceliande.brecilien.org) and Destination Brocéliande, which anchor the legend to the real Château de Comper and Forêt de Paimpont. The Barenton storm-fountain identification traces to Chrétien de Troyes' *Yvain* by way of Wace's *Roman de Rou*, per Gerald of Wales' 1188 *Topographia Hibernica* — a genuine medieval literary attribution, not a modern tourist gloss, though Chrétien's poem itself never names the spring. Glastonbury's identification with Avalon is Gerald of Wales again (*De Principis Instructione*, later 12th c.).

## Judgment calls
- **The name.** "Lady of the Lake" is not one person in the canon but an office held by at least three narratively distinct figures across the Vulgate Cycle and Malory — the unnamed damosel who gives Excalibur, Viviane/Niniane who raises Lancelot and later traps Merlin, and Nimue who inherits Merlin's counsel and appears at the barge married to Pelleas. Malory's own text already blurs these into near-continuity. Per the curator's brief this journey treats the office as one traveler, naming the variants (Viviane, Niniane, Nimue) in the traveler field rather than forcing a false single identity or splitting into three unconnected files.
- **No date can be historical.** All eight stops are `date_confidence: traditional`, anchored to the one fixed point the tradition supplies — the Annales Cambriae's dating of the Battle of Camlann to 537 — with the earlier stops placed by internal narrative logic (courtship before betrayal, the gift of the sword early in Arthur's reign) rather than any external chronology, since none exists.
- **A genuine time-fold, left visible rather than smoothed.** The Brittany material (Barenton, Comper, the Tomb) and the Cornish material (Dozmary, Loe, Camlann) come from separate textual traditions — French romance/local legend on one hand, Malory's English compilation on the other — that were never reconciled into a single chronology by anyone, medieval or modern. The file follows the curator's own geographic ordering (Brittany first, then Cornwall, then Avalon) rather than inventing a forced single timeline across segments; the linter's chronology check applies only within each segment, and every segment passes clean. The Excalibur-gift stop (dated c. 500, before the Brittany courtship stops that follow it in Malory's own internal sequence) is the clearest instance of this fold: it sits in its own segment for exactly this reason.
- **Val sans Retour deliberately omitted.** That valley belongs to Morgan le Fay's legend, not Viviane's, in both the medieval sources and the modern Brocéliande tourist geography; including it would have been padding by conflation, which the curator's brief explicitly warned against.
- **Loe Pool given equal narrative weight to Dozmary Pool**, per the curator's brief calling them "rival return-sites" — the campa text says outright that neither claim resolves and the sword settles nothing, which is the honest version of "dead links."
- **Quotes** are used only where Malory's own words survive and were verified against multiple independent transcriptions (Wikisource, a Malory-focused literary site, and a Middle-English excerpt tool); the two Brittany-tradition stops (Barenton, Comper x2) carry no quote, since no one records dialogue there — null, not invention.

## Gaps
This really is the thinnest journey in the set, exactly as the curator predicted. There is no infancy, no death, no single controlling narrator, and most of what can be said about the Lady is refracted through what she gives or does to others (Merlin, Lancelot, Arthur) rather than anything she says of herself — hence only 4 of 8 stops carry a direct quote, and even those are Malory's narration of her, not her own recorded voice, except the one line of dialogue at the sword-gift. Padding this further (a Val sans Retour stop, an invented "birth" scene, more Cornish rival lakes) would have manufactured false density; the file stops at 8 stops because that is what the canon actually supports without conflation.

## Five richest episodes
1. **The gift of Excalibur** (Dozmary Pool, c. 500) — the arm in white samite, the bargain struck before the sword is even named, Merlin's correction that the scabbard outvalues the blade.
2. **The binding of Merlin** (Tombeau de Merlin, c. 516) — the master of prophecy walking knowingly into the one trap his own foresight cannot show him, using his own craft as the key that locks him in.
3. **The fostering of Lancelot** (Comper, c. 512) — a dead mother, a stolen child, an entire chivalric education delivered underwater by a woman who withholds his father's name from him.
4. **The return of Excalibur, told twice** (Dozmary Pool and Loe Pool, 537) — the same arm, the same catch, the same three shakes and vanishing, staged at two real Cornish lakes that have quarreled over the honor for centuries.
5. **The barge to Avalon** (Glastonbury Tor, 537) — Nimue, married and settled these many years to Pelleas, still present at the very end among the weeping queens, closing the loop from the girl at Barenton to the woman who carries the king away.

## Connections to the atlas
No existing sibling file touches Arthurian material, so this is the atlas's first entry in that cycle — a natural anchor point for future files (Merlin as his own traveler, Arthur, Lancelot, Guinevere, Morgan le Fay) that could share these same pins: Comper, the Tombeau de Merlin, Dozmary Pool, and Glastonbury Tor are all built to be byte-identical landing points if those journeys are ever written. The register line ("national mythology: the canon is true") is used here exactly as it is for `catherine_alexandria` and `charlemagne` — the same formula covers hagiography, national epic, and now Arthurian romance without alteration, which is the point of keeping it fixed across the corpus. Structurally this file is closest in spirit to `catherine_alexandria`: a legendary figure whose "journey" is really a constellation of attributed sites rather than a single traveled road, held together by office and legend rather than by a traceable itinerary.

## Verification pass (2026-07-20)

Independent structure-and-canon-fidelity check of `lady-of-the-lake.journey.json` (and the `.es.json` mirror).

**Linter.** `json_check.py` passes clean on both files: 6 segments, 8 stops, 4 quoted, no WARN lines. Top-level, segment, and per-stop key sets compared byte-for-byte against `joan_of_arc.journey.json` — identical schema, same `calendar: julian`, same register formula.

**Chronology.** Within-segment ordering is correct throughout. The cross-segment time-fold (Brittany material 505-516, then the Excalibur gift at 500) is the deliberate, documented fold between the Breton courtship tradition and the Cornish sword cycle; every stop is `date_confidence: traditional`, so the fold is marked by confidence rather than flattened. Left as-is. The only externally fixed point, Camlann = 537 (Annales Cambriae), anchors the two closing segments.

**Coordinates.** All six unique sites web-verified against published references; every one matches to four decimal places:
- Fontaine de Barenton 48.0388, -2.2471 (Wikidata/mapcarta: 48.038754, -2.247052)
- Château de Comper 48.0706, -2.1723 (latitude.to/Wikidata: 48.07057, -2.17231)
- Tombeau de Merlin 48.0778, -2.1176 (Wikidata: 48.07799, -2.11774)
- Dozmary Pool 50.5423, -4.5488 (Wikipedia: 50.542341, -4.548806)
- The Loe 50.0725, -5.2870 (latitude.to: 50.0725, -5.2870)
- Glastonbury Tor 51.1447, -2.6989 (coordinatesfinder: 51.14467, -2.69889)

No coordinate fixes needed.

**Quotes.** All four checked against Malory's text (Standard Ebooks / Wikisource / sacred-texts transcriptions of Caxton):
- "he was assotted upon her, that he might not be from her" — verbatim, Book IV ch. I.
- "Sir Arthur, king, said the damosel, that sword is mine..." — verbatim, Book I ch. XXV.
- "there came an arm and an hand above the water and met it..." — verbatim, Book XXI ch. V (truncated before "in the water"; nothing altered).
- "I will into the vale of Avilion to heal me of my grievous wound" — verbatim, Book XXI ch. V (leading "For" dropped at a mid-sentence start; wording untouched).
The barge detail — Nimue the chief lady of the lake, wedded to Pelleas, among the queens — also matches Book XXI ch. VI. No paraphrase drift found; nothing nulled.

**Campa prose.** All present tense, in register; the great episodes (the binding, the thrice-shaken sword) carry their weight. Two campas ran just over the 110-word cap: the Tombeau de Merlin (111) and the Dozmary gift (113). Trimmed minimally — "the very charm" to "the charm", and dropped "by main strength" (a phrase not in Malory anyway; he takes it "by the handles"). Both now at exactly 110. The same two trims were mirrored in the `.es.json` ("el mismo encantamiento" to "el encantamiento"; "con fuerza" removed) to keep the translation parallel. Both files re-linted OK after repair; grep confirms zero em-dashes in either file.

**Stop count.** 8 stops is below the corpus norm, but the thinness is the curator's explicit steer for this file, and the omissions (Val sans Retour, the Accolon rescue, the mantle of Morgan) are defensible curation, not gaps — the first belongs to Morgan's legend, and the latter two are Nimue-as-court-protector episodes without stable place-pins. No stops added.

**Verdict.** Dataset is sound. Two word-count trims were the only repairs.
