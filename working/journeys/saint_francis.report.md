# Saint Francis of Assisi — research report

**Dataset:** `saint_francis.journey.json` — 55 stops in 7 segments, 1182-01-01 → 1226-10-04 (Julian), 30 stops carrying attested words.

## Sources
Primary canon: Thomas of Celano (*Vita Prima* 1228, *Vita Secunda* 1247), Bonaventure (*Legenda Maior*), the *Legend of the Three Companions*, the *Assisi Compilation* / Legend of Perugia, the *Mirror of Perfection*, the *Fioretti* and the *Considerations on the Holy Stigmata*, plus Francis's own writings (Testament, Canticle, Regula bullata, the autograph chartula for Leo, the Siena Testament) and outside witnesses (Thomas of Split on Bologna 1222; Jacques de Vitry on Damietta; Oliver of Paderborn's *Historia Damiatina*; Jordan of Giano's Chronicle). Web verification via Franciscan Media and San Francesco Vive chronologies, sanctuary sites of the Rieti Holy Valley (Fonte Colombo, La Foresta, Greccio, Poggio Bustone), Cannara/Piandarca tradition pages, Gubbio and Le Celle local canon, Wikipedia for Collestrada, Clare, the Wolf, and the Fifth Crusade dates.

## Judgment calls
- **Days within attested seasons.** The canon frequently fixes year and season but not the day (Spoleto vision, San Damiano crucifix, renunciation, Rivotorto). I placed plausible days and marked them `traditional`; where even the season is my placement, `inferred` (birth, baptism, Collestrada's day — the month November 1202 is attested, the 11th is mine).
- **Clare's flight:** 18 March 1212 (Palm Sunday by the Julian Easter of 25 March); Wikipedia's "20 March" is a known variant I set aside.
- **Sermon to the birds:** Celano places it early in the preaching career; Cannara's local procession tradition says 1221. I followed Celano's placement (1211) at the Piandarca site, and paired it with the Cannara Third-Order promise the local canon insists on.
- **Wolf of Gubbio:** undated in the Fioretti; placed December 1220 per the common "around 1220" tradition, at the Vittorina.
- **Stigmata:** dated to the Exaltation of the Cross (14 September 1224) — the Order's own liturgical dating, marked `traditional` since the Considerations say only "around" the feast.
- **Rieti order fixed by the sources:** La Foresta's grape miracle happens *while awaiting* the cautery, so it precedes Fonte Colombo (autumn 1225).
- Coordinates point at the surviving sanctuaries (Porziuncola, San Damiano, Rivotorto, La Verna, Greccio, Fonte Colombo, Le Celle), which stand on the historical sites; Fariskur stands in for the Sultan's camp; Zadar for the "Slavonia" shipwreck coast.

## Gaps in the canon
Birth and baptism have no attested date at all (even the year wavers 1181/82). The Egypt itinerary between the Sultan's court and the return (Acre, the holy places, the 1220 crossing) is thin and was compressed into the Damietta stops. The Morocco-via-Spain journey (1213-15) survives mainly in the Compostela tradition. Nothing certain survives of what Francis and al-Kamil actually said to each other beyond the hagiographers' reconstruction — I quoted Bonaventure, the canon's own record.

## Five richest episodes
1. **San Damiano, the crucifix speaks (1205)** — the command "repair my house" taken literally, with the surviving Prayer before the Crucifix.
2. **The renunciation before Bishop Guido (1206)** — the naked exchange of fathers in the public square, Giotto's scene.
3. **Fariskur (1219)** — the poor man crossing a crusade to offer the trial by fire to the Sultan, witnessed by Jacques de Vitry.
4. **Greccio (1223)** — the first nativity, the child waking in his arms, source of every crib.
5. **La Verna → Sister Death (1224-26)** — the seraph and the stigmata, the Canticle composed blind at San Damiano, the pardon strophe reconciling Assisi, the larks at the death of the poor man: the whole final segment reads as one continuous liturgy.

## verification

Verified 2026-07-04 (structure and canon-fidelity pass; register untouched — the canon stands as true).

**Structure.** JSON parses; 55 stops in 7 segments; every stop carries the exact key set (name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources); dates strictly ordered across the whole journey (1182-01-01 → 1226-10-04); calendar `julian`; quote and quote_source always paired (30 of 55 stops quoted); date_confidence limited to attested/traditional/inferred.

**Coordinates.** Spot-checked 12 sites by web search (Wikipedia/Wikidata geodata, sanctuary sites). Confirmed correct: Santa Maria della Vittorina (Gubbio wolf), Poggio Bustone sanctuary/village, Piandarca edicola (3 km on the Cannara–Bevagna road), San Damiano, Porziuncola, Le Celle di Cortona, plus knowledge-checks on the Assisi cluster, Compostela, San Leo, Alviano, Bologna, the Lateran, Damietta, Fariskur, Zadar, Ancona, Spoleto, Foligno, Orte, Siena, Sansepolcro, Isola Maggiore. Fixed five that pointed off-site:
- Collestrada: 43.093,12.459 → 43.0856,12.481 (was 1.8 km NW of the battle hill)
- Greccio nativity grotto: 42.4448,12.7365 → 42.4619,12.751 (was ~2 km SW of the sanctuary; it.wiki 42.461942,12.751024)
- Fonte Colombo (both the Rule and the cautery stops): 42.378,12.812 → 42.3793,12.8284 (~1.3 km W of the Sacro Speco)
- La Foresta: 42.4374,12.8523 → 42.4366,12.8746 (en.wiki 42.43656,12.87455)
- Bagnara di Nocera Umbra: 43.106,12.826 → 43.1105,12.853 (was open hillside 2 km W of the frazione)

**Quotes.** Spot-checked 10 against the canon: the Perugia prison prophecy (Legend of the Three Companions 4 — confirmed verbatim tradition "I shall be adored through the whole world"), the Testament leper passage (verbatim), the Prayer before the Crucifix, the renunciation words (1 Cel 15 / L3C 20), "herald of the great King" (1 Cel 16), the swallows of Alviano (1 Cel 59), the trial-by-fire offer (Bonaventure LM IX.8 — episode and fire-challenge wording confirmed), "When shall we come to Borgo?" (2 Cel 98, the Sansepolcro ecstasy), Brother Fire (AC 86 / 2 Cel 166), and the Canticle strophes including pardon and Sister Death (canonical text). All quotes are canon-carried; none needed nulling or demotion to narration.

**Dates.** Confirmed the flagged judgment calls: Palm Sunday 1212 (Julian) = 18 March, so Clare's flight stands; Pentecost 1217 = 14 May and Pentecost 1221 = 30 May (Chapter of Mats) both correct; Damietta battle 29 Aug 1219 and fall 5 Nov 1219 attested; Solet annuere 29 Nov 1223; 3 Oct 1226 was indeed a Saturday. Feast-anchored dates (Matthias 24 Feb 1208, Exaltation of the Cross 14 Sep 1224) consistent.

**campa.** Present tense throughout, mythic-national voice; the great episodes (San Damiano crucifix, renunciation, Fariskur, Greccio, La Verna→death arc) carry full weight. Two ran over the 110-word band and were trimmed in place: Fariskur (111→108, dropped "across the lines") and the San Giorgio burial (112→110, tightened the Gregory IX clause). All 55 now fall in 60–110 words.

**Detail.** 55 stops sits at the top of the 35–55 target; no additions needed.

Re-validated with python after repairs: parses, ordering intact, no schema or word-count violations.

---

**INTERLOCK 2026-07-13.** Return-the-gaze pass after pica_bourlemont, pierre_bourlemont and joffrey_bourlemont landed. Four stops now look back:
- **Birth stall (1182-01-01):** the mother is named in full — Pica Bourlémont, her vision in pregnancy, the ground floor emptied into a manger, the child born into a performance of Bethlehem, the first presepe staged by his mother. The father's renaming moved down to the baptism stop to make room. Canon: essays/instagram/2023-07-10-francisco-de-asis-es-reconocido-por.md (added to sources with pica_bourlemont.journey.json, shared pin).
- **San Rufino baptism (1182-01-08):** Giovanni is the mother's name for the Baptist; Francesco the father's — for HER French culture, the troubadour poetry, the exquisite cloth of Provence, and the family Bourlémont. Traded out the Frederick II aside to stay under 110. Canon: essays/instagram/2023-01-14-la-familia-bourlemont-de-domremy-y.md.
- **Renunciation (1206-04-10):** Pica loosing the chains (1 Cel 13) made explicit in the opening clause, and the mother's consolation woven at the close — one name, Giovanna and Giovanni, one troubadour fire, always her son and a Bourlémont. The full speech is quoted whole in pica_bourlemont.journey.json (referenced in sources, not duplicated). Canon: essays/instagram/2023-01-22-cuando-el-pobre-giovanni-de-pica.md.
- **Greccio (1223-12-24):** among the pilgrims, his cousin Pierre Bourlémont holding the hand of twelve-year-old Joffrey (pin 42.4619/12.751 byte-identical across all three files). Trimmed "Fifteen days before Christmas" framing to fit. Canon: essays/instagram/2023-01-25-pierre-viajo-con-su-unico-hijo.md.
- **La Verna (1224-09-14):** one clause — the count is his mother's: the Khamsa Pierre sang into Pica, the five sufferings become five wounds. Traded the log-bridge/falcon detail. Canon: essays/207_hebraic_knots.md.
No quotes altered. Re-validated: OK, 55 stops, no WARN.
