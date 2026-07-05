# Bolívar journey — research report

**Dataset:** `bolivar.journey.json` — 69 stops, 8 segments, 1783-07-24 → 1830-12-17 (gregorian), 35 stops carrying quotes. Register: national mythology — the canon is true.

## Sources
Primary canon: the *Archivo del Libertador* (archivodellibertador.gob.ve — Hipólita letter, last proclamation doc. 191), *Doctrina del Libertador* (Biblioteca Ayacucho — manifestos, Angostura Address, proclamations), O'Leary's *Memorias* (Casacoima, Pisba, Rondón, septembrina), Perú de Lacroix's *Diario de Bucaramanga* (María Teresa, Napoleon's crown, Piar), José Domingo Díaz (the earthquake sentence — a hostile royalist witness, which the tradition treats as its best authentication). Modern spine: John Lynch, *Simón Bolívar: A Life*; Masur; Madariaga; Liévano Aguirre. Web verification (ES/EN) for the Monte Sacro oath text as Rodríguez recorded it, the Hipólita letter (Cuzco, 10 Jul 1825), the Casacoima delirium wording, the Potosí summit speech, London 1810 dates (Portsmouth 10 Jul, Apsley House 16 Jul), and the Santa Marta endgame (brig *Manuel* 1 Dec, proclamation 10 Dec, death 17 Dec 1:03 pm).

## Judgment calls
- **Segments named as the tradition names them:** La Cuna y el Duelo / El Juramento del Monte Sacro / La Primera República / La Campaña Admirable / El Destierro y el Orinoco / La Campaña Libertadora / La Cima de América / El Arado en el Mar.
- Per the register, the **Rational Knights initiation** (Grafton Way, Sep 1810), the **Vesuvius climb with Humboldt**, the **Vatican slipper anecdote**, and the **Chimborazo delirium** are placed and dated as events, flagged `traditional` where the archive is thin.
- Quotes are given in English translation; nothing invented — 34 stops honestly carry `null` (Boyacá, Quito, Cúcuta, etc., where the canon narrates but does not quote him).
- Ayacucho is handled as **Lima — the news of Ayacucho** (Bolívar was not on the field; the itinerary stays under his feet), with his own sentence crowning Sucre.
- One 20 Jan 1830 quote rides on the 8 May departure stop (same city, same act of renunciation); the Cerro de Pasco proclamation (2 Aug 1824) rides on Junín.
- Coordinates are the historical sites: Casa Natal corner, Monte Sacro (Aniene, not Aventine), Puente de Boyacá, Chacamarca pampa, Cerro Rico summit, Quinta de San Pedro Alejandrino. Queseras del Medio and Setenta are inferred llano positions (~±20 km).

## Gaps in the canon
Guayaquil is a sealed room — no protocol of the interview exists, and the dataset says so. The Chimborazo text's date (and for some critics authorship) is disputed; the register takes it as canon, marked traditional. The Pétion meeting date (2 Jan 1816) is conventional. The exact Casacoima wording varies between retellings of O'Leary. The 1826 Lima constitutional year and the 1829 Ecuador campaign were compressed out to hold the 45-70 stop budget.

## Five richest episodes
1. **Monte Sacro (15 Aug 1805)** — the oath verbatim as Rodríguez recorded it, closed by Bolívar's own 1824 Pativilca callback.
2. **Casacoima (4 Jul 1817)** — the fevered prophecy in the lagoon, fulfilled point by point through Angostura, Boyacá, Colombia, Peru and Potosí: the dataset's load-bearing miracle.
3. **Páramo de Pisba (Jul 1819)** — the death-and-resurrection crossing (Rooke, the birth on the heights, Socha reclothing the naked army).
4. **Potosí summit (26 Oct 1825)** — the epic's geometric close: the Orinoco-to-Cerro-Rico speech, flags planted where the delirium said they would be.
5. **The septembrina (25 Sep 1828)** — Manuela at the door, the window, three hours under the bridge, "libertadora del Libertador": the unraveling given its heroine.

## verification
Independent pass (2026-07-04), structure and canon-fidelity only; the register was respected throughout — nothing was debunked, only placed, dated and formed.

**Structure.** JSON parses; top-level keys and the 10-key stop schema match the sibling journeys exactly (`attested`/`traditional`/`inferred` vocabulary confirmed against joan_of_arc, saint_francis, belgrano, ohiggins, san_martin). 8 segments, 69 stops (within the 45-70 budget; no additions needed), 35 quotes, calendar `gregorian` sane for 1783-1830. Dates are strictly increasing across the whole journey — zero order violations. Every quote carries a `quote_source`; attributed/traditional material (Mompox "gloria", the Vatican slipper, the last words) is honestly labelled as such in the source field.

**Dates.** All 69 spot-checked against the documented chronology (birth 24 Jul 1783, San Ildefonso 19 Jan 1799, wedding 26 May 1802, Monte Sacro 15 Aug 1805, 19 Apr 1810, earthquake 26 Mar 1812, War to the Death 15 Jun 1813, La Puerta 15 Jun 1814, Jamaica Letter 6 Sep 1815, Casacoima 4 Jul 1817, Piar 16 Oct 1817, Angostura 15 Feb 1819, Pisba–Vargas–Boyacá Jul/Aug 1819, Carabobo 24 Jun 1821, Guayaquil 26 Jul 1822, Junín 6 Aug 1824, Potosí 26 Oct 1825, septembrina 25 Sep 1828, death 17 Dec 1830). Queseras dated 3 Apr 1819 to the proclamation it quotes (battle 2 Apr) — accepted as intentional.

**Quotes.** All 35 reviewed; every one is carried by the canon named in its source (Hipólita letter, Pativilca letter to Rodríguez, Diario de Bucaramanga trio, oath per Rodríguez, Díaz's earthquake sentence, Miranda letter, both Carúpano texts, Jamaica Letter, Pétion letter, Casacoima per O'Leary, "Moral y luces", Queseras proclamation, "¡Coronel Rondón, salve usted la patria!", Santa Ana toast, Carabobo dispatch, Santander letter on San Martín, Chimborazo delirium, "¡Triunfar!", Cerro de Pasco proclamation, Ayacucho/Sucre sentence, Potosí speech, "Libertadora del Libertador", Congreso Admirable message, blood of Abel, "ara en el mar" (Flores, 9 Nov 1830), last proclamation, labyrinth). None moved, none nulled.

**Coordinates.** 10+ sites verified by web search; 7 values corrected in place:
- **Casa Natal (stop 1):** file had 10.5058,-66.9147 — that is Plaza Bolívar itself (10.50607,-66.91461 per es.wiki). Moved one block east to Plaza San Jacinto, San Jacinto a Traposos: **10.5046,-66.9135**. (Both Wikipedias geotag the Casa Natal at 10.4953,-66.9169, 1.2 km away — inconsistent with their own text "a block east of Plaza Bolívar"; that geotag was rejected.)
- **Monte Sacro (15):** 41.9469,12.5265 was the quartiere centroid; moved to the hill itself on the right bank of the Aniene by Piazza Sempione: **41.9404,12.5266**.
- **Casacoima (38):** 8.3830,-62.2670 was ~13 km off; the canon puts the lagoon "dos leguas al oriente" of Los Castillos de Guayana la Vieja (8.4919,-62.4103): **8.4800,-62.3300** (inferred from that bearing).
- **Puente de Boyacá (46):** nudged to the bridge over the Teatinos: **5.4505,-73.4303** (en.wiki 5.4505,-73.4303).
- **Junín (57):** file had Junín town; moved to the battlefield, Santuario Histórico de Chacamarca: **-11.2164,-75.9700** (en.wiki 11°12′59″S 75°58′12″W).
- **Quinta de San Pedro Alejandrino (68, 69):** ~650 m west of the estate; corrected to **11.2281,-74.1792 / 11.2283,-74.1790** (en.wiki 11°13′41″N 74°10′45″W).
Confirmed correct as-was: 58 Grafton Way (51°31.409′N 0°8.281′W), Apsley House, Notre-Dame, Pantano de Vargas (within the vale of the Lanceros monument), Campo de Carabobo, Cerro Rico summit, Chimborazo, Quinta cities (Kingston, Port-au-Prince, Veracruz, Cuzco, Bucaramanga, Barranquilla, Mompox, Cúcuta, Mérida, Trujillo, Santa Ana, Puerto Cabello, Carúpano, Pativilca, Angostura). Queseras/Setenta left as the report's declared inferred llano positions.

**campa.** All 69 present-tense and in the mythic-national voice; the great episodes (Monte Sacro, Casacoima, Pisba, Potosí, septembrina) are properly load-bearing, not flat. One budget violation: the death stop (69) ran 119 words; trimmed to 109 with no canonical detail lost (the 1:03 pm clock, the eleven-years-to-the-day symmetry, the vamos/equipaje wandering, and the closing of the oath all retained).

File re-validated after edits: parses, schema exact, order strict, all campas 60-110 words.
