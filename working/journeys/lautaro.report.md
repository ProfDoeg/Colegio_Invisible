# Lautaro journey — research report

**Dataset:** 37 stops, 7 segments, c. 1534–1557 (plus the 1812 coda), Julian calendar, register: national mythology.

## Sources
- **Canon (epic):** Alonso de Ercilla, *La Araucana* (1569) — Cantos II (Colocolo's council speech), III (Lautaro's portrait and the Tucapel arenga), XIII (Guacolda's dream-dialogue), XIV (the death at dawn). Quote texts checked against es.wikisource (`La araucana primera parte/II, III, XIII, XIV`).
- **Crónicas:** Jerónimo de Vivar, *Crónica y relación copiosa y verdadera* (1558); Alonso de Góngora Marmolejo, *Historia de todas las cosas...* (1575); Pedro Mariño de Lobera, *Crónica del Reino de Chile*; Valdivia's *Cartas de relación*.
- **Modern Spanish-language:** Memoria Chilena (biography, Tucapel, Marigüeñu, Muerte a Lautaro articles), es.wikipedia (Tucapel, Marihueñu, Peteroa, Mataquito, Primera destrucción de Concepción, Quilacura, Andalién), hispanismo.cl, resumen.cl, redhistoria.

## Judgment calls
- **Dates.** Only the anchor battles are attested: Andalién (22-II-1550), Penco (12-III-1550), Tucapel (25-XII-1553; some sources say 1-I-1554 — I kept Christmas per the weight of tradition), Marigüeñu (23-II-1554; one source says 26-II), second Concepción (12-XII-1555), Mataquito (dawn 29-IV-1557; some say the 30th or 1-IV — I anchored 29-IV and gave the field's aftermath the 30th), Millarapue (30-XI-1557). Everything else carries invented-but-plausible calendar days marked `traditional`/`inferred`.
- **The capture.** Tradition says "about eleven years old"; I tied the stop to Valdivia's 1546 Quilacura entrada as the most plausible canonical occasion — flagged `traditional`.
- **The council.** Ercilla's Canto II scene elects Caupolicán (the log-trial); Lautaro's elevation as lieutenant/field-toqui comes from the crónicas. I merged them into one council stop, as the national canon itself does, and quoted Colocolo.
- **Peteroa 1556.** Sources split the northern campaigns differently; I followed the two-campaign reading (1556 fort at Peteroa vs. Diego Cano and Pedro de Villagra; 1557 return and death at Mataquito vs. Francisco de Villagra + Juan Godíñez).
- **Guacolda.** She is Ercilla's creation with no chronicle footing; the register treats the canon as true, so she rides the second march and gets the night of omens. Her afterlife ("the sword... will draw me after") is left as the poem leaves it — a vow, narrated darkly, not a documented death.
- **Valdivia's death.** All traditions given side by side as co-true (Vivar's sentencing by Caupolicán, Góngora Marmolejo's forearms, Lobera's Leucotón, the folk molten gold) — the canon genuinely carries all four.
- **Mutilations.** Hands-and-noses (~200 prisoners) is solidly in Vivar after Andalién/Penco; I placed it at the Penco judgment, 12-III-1550, and made it the hinge-wound of the arc, as instructed.
- **Coordinates.** Battle sites use the accepted modern identifications: Tucapel = fort site at Cañete; Marigüeñu = Cuesta de Villagrán above Chivilingo (Lota); Mataquito = Chiripilco/La Huerta tradition west of Peteroa. Camp-and-ford stops are honest approximations.

## Gaps in the canon
- **The boyhood is thin.** Between birth (~1534, Tirúa/Nahuelbuta, father Curiñancu) and the capture, the record is essentially empty; Neruda's "Educación del cacique" is the modern nation filling that silence, and I leaned on it for refs, not facts.
- The **exact year of the escape** (1550–1552) and everything about **how** he escaped is unrecorded; likewise his precise doings 1552–53.
- The **first destruction of Concepción's exact day** (early March 1554) is not fixed in the sources.

## Five richest episodes
1. **Penco, the mutilations (12-III-1550)** — the wound that opens the arc; attested in Vivar.
2. **Tucapel (25-XII-1553)** — the relays, the arenga ("¡Oh ciega gente...!"), Valdivia annihilated; the hinge of the whole national epic.
3. **The death of Valdivia** — four co-true traditions, the molten gold above all.
4. **The night of omens on the Mataquito (28-IV-1557)** — Guacolda's dream and Lautaro's answer, Ercilla at his most tender; the sentries asleep.
5. **The 1812 coda** — San Martín's lodge taking the name LAUTARO; the stable-boy as secret ancestor of the continent's liberty, closing the circle.

## verification

Verified 2026-07-05 (structure and canon-fidelity pass; the canon is true — nothing debunked).

**Structure.** JSON parses; 7 segments, 37 stops; every stop carries the full schema (name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources). Dates in strict chronological order c. 1534 → 1557, with the 1812 Logia Lautaro coda last. Confidence distribution honest: 8 attested (Andalién 1550-02-22, Penco 1550-03-12, Tucapel 1553-12-25, Marigüeñu 1554-02-23, 2nd Concepción 1555-12-12, Mataquito 1557-04-29, Millarapue 1557-11-30, Buenos Aires 1812-03-09), 18 traditional, 11 inferred — right for a 16th-century Mapuche life known through Ercilla and the crónicas.

**Quotes.** All six checked verbatim against es.wikisource (La araucana, primera parte): Colocolo "Caciques, del Estado defensores…" (Canto II) ✓; Lautaro's harangue "¡Oh ciega gente, del temor guiada!…" and the portrait "Fue Lautaro industrioso, sabio, presto…" (Canto III) ✓; Lautaro to Guacolda "en más peligros que éste me he metido…" and Guacolda's vow "la espada que hará el apartamiento…" (Canto XIII) ✓; the death "Por el siniestro lado, ¡oh dura suerte!…" (Canto XIV) ✓. None nulled.

**Coordinates.** Web-spot-checked: Tirúa (-38.34,-73.49) ✓; Santiago Plaza de Armas ✓; Fuerte Tucapel at Cañete (-37.80,-73.39) ✓; Marigüeñu/Cuesta de Villagrán south of the Chivilingo, comuna Lota (-37.156,-73.169) ✓; all Concepción stops correctly at the old Penco site (-36.74,-72.98), not the modern city ✓; Maule ford south of Talca ✓; Peteroa on the Mataquito below the Teno–Lontué junction ✓; Buenos Aires ✓.

**Repairs made in place.**
1. *Mataquito camp/battle stops (the hidden fort, the night of omens, the dawn attack, the field)* moved from -34.98,-71.66 to ~-35.082,-71.638 — the canon site is the foot of Cerro Chiripilco on the north bank, NE of La Huerta de Mataquito (Hualañé, es.wikipedia: La Huerta at -35.09,-71.655; Chiripilco 2 km east); the old points sat ~12 km north of the river.
2. *Ford of the Itata* moved from -36.45,-72.40 (dry hills ~25 km east of the river) to -36.62,-72.47, on the Itata near the Ñuble confluence / Nueva Aldea reach.
3. *The capture stop* renamed "Quilacura, before the Bío-Bío — the capture" (was "South bank of the Bío-Bío"): the coordinate (-37.05,-72.55, near Yumbel) matches the Quilacura tradition, which lies north of the river — the 1546 entrada never crossed it. Campa adjusted to match (probes *toward* the Bío-Bío; marched north *away from* the great river). Capture site remains traditional, as marked.
4. Four campas trimmed from 111–118 words to ≤110 (Tucapel battle, first destruction of Concepción, death of Lautaro, Logia Lautaro coda); all 37 now within 60–110 words, present tense.

**Voice.** Tucapel, the great council, and the Mataquito sequence read hot, not flat — the relays, Colocolo's octave, Guacolda's dream, the dart through the left side all carried as canon. Re-validated after repair: parses, ordered, schema complete.
