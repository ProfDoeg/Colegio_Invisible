# Pierre Bourlémont — report

**File:** pierre_bourlemont.journey.json — 7 segments, 40 stops, 3 quoted. In-universe canon journey: the canon is the taller essay corpus, not external history.

## Sources
Canon: `essays/instagram/2023-01-14-la-familia-bourlemont-de-domremy-y.md` (the family, the Caucasus mission, the gift, PICA, the naming of Frances), `2023-01-14-pierre-cantaba-para-pica-llenando-los.md` (the five sufferings — all three quotes come from here, verbatim Spanish), `2023-01-23-a-nizami-le-gusto-pierre-bourlemont.md` (Shahnameh stories, Azhdaha), `2023-01-25-pierre-viajo-con-su-unico-hijo.md` (Greccio 1223), `2023-01-22`/`2023-01-20` (renunciation, Rome 1210), the two `2023-02-17` essays (De Amore, sub rosa), `2022-12-22` (Joffrey), `207_hebraic_knots.md` (five sufferings → five wounds → cord → quipu). Scaffold: `bourlemont_roster.md` (Pierre = Pierre II, c. 1170–†c. 1226, son of Simon II, ∞ Félicité de Joinville, father of Joffroy) and `pica_dossier.md` Layer 6.

## Pins (for the sibling files — byte-identical)
- **Château de Bourlémont** = `48.390, 5.6617` — the direction's "48.3186, 5.6822" did NOT verify; fr.wiki (and its mirrors) give 48.39000, 5.66167 for the castle at Frebécourt, on the promontory over the Meuse/Saônelle confluence. **pica_bourlemont and joffrey_bourlemont must reuse 48.390 / 5.6617.**
- Ganja `40.683, 46.36` copied byte-exactly from nizami.journey.json; Greccio `42.4619, 12.751` from saint_francis.journey.json (arrival 1223-12-24, communion + cave 1223-12-25, all "attested"); Domrémy church `48.4436, 5.6748`, fairy tree `48.4302, 5.6706`, Neufchâteau `48.3554, 5.6942` from joan_of_arc.journey.json. Tarascon finca `43.8058, 4.6600`, Beaucaire `43.8078, 4.6444`, Mureau abbey `48.3678, 5.5753` (fr.wiki) — reusable by the siblings.

## Judgment calls, gaps, time-folds
- **Dating the Caucasus journey 1179–80**: the canon only says "de niño." Anchors: Pierre born c. 1170 (roster), Nizami alive at Ganja (1141–1209), and Pica must receive the gift *before* leaving for Assisi (Francis born 1181). So journey at age ~9, return and gift-summer 1180, Pica's departure autumn 1180. This is the arc's biggest time-fold: the *Khamsa* as a finished five-poem book postdates 1180 (Layla-Majnun 1188), but the canon has Nizami's five-fold suffering already sung at court — narrated as the master's living teaching, not debunked.
- Canon's Shahnameh genealogy kept as written (Bijan "grandson of Rostam," Zal "son of Rostam") — originals stay as the canon states; no correction.
- Route stops (Marseille, Constantinople, Trebizond, Tiflis) are inferred scaffolding on the traditional Levant–Caucasus road; marked "inferred."
- Death 1226-10-04, folded into the same autumn as Francis's death — roster says only "†c. 1226"; marked "inferred." Burial at Mureau is my inference from the family-abbey tie (Joffroy's attested 1248 charter); marked "inferred."
- De Amore/sub rosa essays are general-register; I placed them as a 1190 stop at the castle (the treatise's own date) to seed the cipher/secrecy thread from Bijan onward.
- Quotes: only the three verbatim Pierre phrases the canon actually records (all from the five-sufferings essay). Pica's consolation speech is hers, so it lives in campa, not the quote field.

## Five richest episodes
1. **The Azhdaha dragons at Ganja** — skins that cure heart-wounds; the seed that flowers at La Verna ("the wound itself is the cure").
2. **The coining of PICA** — the magpie taking silver; the corpus's mechanism for the name that enters the Assisi ledgers as Domina Pica.
3. **The quinta herida** — the five sufferings with their five practices, the refrain "por lo que sufrimos," the smile only for Pica.
4. **Greccio, the cave** — the magi like Ganja's own; Pierre holding Joffrey's hand as heat pours off the praying cousin.
5. **The death with the five-looped cord** — Rostam-and-Sohrab worn the right way round; Khamsa → wounds → cord → quipu (essay 207).

## Atlas connections
Shares pins with **nizami** (Ganja), **saint_francis** (Greccio; his whole life runs as the offstage counter-melody), **joan_of_arc** (Domrémy church, fairy tree, Neufchâteau — plus the 1456 Pierre-and-Fée romance and Joan's trial naming a later "Seigneur Pierre de Bourlement"). Direct parent of **joffrey_bourlemont** (born stop 30, Greccio stops 32–36, at the deathbed) and cousin-author of **pica_bourlemont** (stops 19–24 are her Provence years from his side). The Joinville marriage seeds the Champagne/crusade lines; the sub-rosa/rose stops tie to the Colegio Invisible's rosicrucian frame.

## Verification pass — 2026-07-12

Independent structure + canon-fidelity check. **No repairs needed; file unchanged.**

- **json_check.py**: OK, zero WARNs — 7 segments, 40 stops, 3 quoted. Required top-level keys match joan_of_arc.journey.json (traveler/title/years/calendar/register/segments); same register string.
- **Chronology**: ascending within every segment and across segments (1170 → 1226); no BCE handling needed. Confidences honest — only the Greccio pair (1223-12-24/25) claims "attested"; route scaffolding and the death/burial stay "inferred"; canon-dated episodes "traditional". Deceased traveler ends at death + burial.
- **Coordinates — 11 web-spot-checked, all verify**: Château de Bourlémont 48.390/5.6617 (fr.wiki 48.39000/5.66167, PA00107169 confirmed), Abbaye de Mureau 48.3678/5.5753 (fr.wiki 48.36778/5.57528, Prémontrés at Pargny-sous-Mureau confirmed), Domrémy 48.4436/5.6748, Neufchâteau 48.3554/5.6942, Joinville 48.4436/5.1414, Tarascon 43.8058/4.6600, Beaucaire 43.8078/4.6444, Ganja 40.683/46.36 (en.wiki 40.68278/46.36056), Trabzon 41.0053/39.7267, Hagia Sophia 41.0086/28.9802, Greccio 42.4619/12.751 (kept byte-exact with the saint_francis shared pin). Marseille Vieux Port and Tbilisi standard pins also correct. Shared pins confirmed byte-identical against nizami, saint_francis and joan_of_arc files.
- **Quotes**: all 3 checked verbatim against essays/instagram/2023-01-14-pierre-cantaba-para-pica-llenando-los.md — "nuestro lord hizo que los corazones ardieran y se rompieran… el romance es un anhelo imposible", "La timidez es pecado… todo amor debe ser profesado", "la quinta herida… el corazón abierto… por lo que sufrimos". Canon records only these three; nothing to null, nothing paraphrased.
- **Canon fidelity**: Ganja curriculum (Rostam/Sohrab, Bijan's cipher, Zal's serenade, Azhdaha skins that cure heart-wounds) matches the 2023-01-23 essay including its genealogy as written; five sufferings + practices and the "smiles only for Pica" refrain match the five-sufferings essay; Giovanni/Frances naming and the 1181 birth match the 2023-01-14 familia essay; Greccio (communion in the morning, cave at night, lanterns/ox/ass/magi/golden hay, Joffrey struck by poverty, magi like Ganja's, heat from the praying cousin, held hand) matches 2023-01-25 point for point; Pope kissing the bare feet + signed order matches 2023-01-22; De Amore 1190 (Walter the soldier of love, wound, clandestine rose-principles) and the sub-rosa red rose match the two 2023-02-17 essays; the Pierre-and-Fée tree romance and the 1431 "Seigneur Pierre de Bourlement, Knight" ref match the 2024-09-27 rehabilitation-trial essay. Time-folds preserved, nothing debunked.
- **Campa**: all 60–110 words, present tense, in register; the great episodes (Azhdaha, PICA coining, quinta herida, Greccio cave, deathbed cord) carry their weight.
- **Count**: 40 stops, inside the 30–45 target; canon fully spent — no additions warranted.

## Curator reading woven in — 2026-07-13
The five sufferings are the singer's own case, sung from inside: blocked by age (he is ten), socially (they are cousins), geographically (she is packing for the mountains), and by betrothal (she is promised to the merchant) — impossible deep suffering love at ten, precocious and performative but authentic. Woven into the campa of "the first four sufferings" (the wink now carries "and he is ten"; the syllabus named a self-portrait whose singing is the first practice obeyed) and "la quinta herida" (the song knows its singer). Both campa re-counted 107–109 words; json_check OK.
