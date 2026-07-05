# Miranda journey — research report

**Dataset:** `miranda.journey.json` — 69 stops, 9 segments, 1750–1816 (+1896 Panteón coda), gregorian, register: national mythology.

## Sources
Primary spine: Robertson, *The Life of Miranda* (1929, via penelope.uchicago.edu); Racine, *Francisco de Miranda: A Transatlantic Life* (2003); the Colombeia archive portals (franciscodemiranda.info, franciscodemiranda.org, franciscodemirandayrusia.org). Document texts verified by web search: 1771 La Guaira–Cádiz navigation diary; 1783–84 US diary (Washington portrait quote); 1787 letter to Catherine II; Coro proclamation (Cervantes Virtual / bicentenarios.es); 1813 memorial to the Real Audiencia; the bochinche and "blessé au cœur" testimonies; Jacmel 12-III-1806 and La Vela 3-VIII-1806 flag dates; Pensacola 8-V-1781; Kiev presentation 14-II-1787; death at the Cuatro Torres 14-VII-1816 and the mass grave.

## Judgment calls
- **Register followed as instructed:** the Grafton Street oaths (O'Higgins 1798, Bolívar July 1810) are narrated as events with dates, marked `traditional` since the canon fixes the year, not the day.
- **Dungeon names:** the sources place Castillo **San Carlos in La Guaira** and **San Felipe in Puerto Cabello** (the brief had San Carlos at Puerto Cabello); I used the attested assignment — the memorial of 8-III-1813 is dated from San Felipe.
- **Puerto Cabello fell 30 June; Miranda learned 5 July at La Victoria** — the "Tenez: le Venezuela est blessé au cœur" stop is dated to the news, not the fall.
- Jacmel oath text and Consejos line are given as short canonical fragments; the eight quotes are all documented in the tradition (none invented).
- Merges to stay ≤75 stops: Jamaica mission folded into Nassau; Aruba withdrawal into Coro; Dresden into Potsdam; Copenhagen into Stockholm; 1804 Melville memorandum into the Gravesend departure.

## Gaps
Exact days are thin for: the Italian/Greek legs 1785–86 (marked `inferred`), the O'Higgins oath, the 1798 Grafton founding, the La Carraca arrival (early Jan 1814, `traditional`), and the 1816 escape-plan/stroke sequence (`inferred`). The 1811 flag adoption is given as the traditional 14 July first hoisting.

## Five richest episodes
1. **Jacmel, 12-III-1806** — the flag's own birthday at sea, with the recorded oath formula.
2. **La Guaira, 31-VII-1812** — the parricide: Bolívar among the captors, the bochinche sentence.
3. **Kiev, 14-II-1787** — Catherine's favor and the Russian uniform, with Miranda's own letter.
4. **Valmy/Arc de Triomphe** — the only American name on the arch; Goethe as witness on the other side.
5. **La Carraca, 14-VII-1816** — death on Bastille Day, the mass grave, and the open-doored cenotaph closing the circle at Cádiz.

## verification

Verified 2026-07-04 (independent pass over miranda.journey.json).

- **Structure**: JSON parses; 9 segments, 69 stops; every stop carries the full key set (name, date, date_confidence, lat, lng, campa, quote, quote_source, sources, suggested_refs). Dates are ISO and strictly ordered end to end (1750-03-28 → 1896-07-05 cenotaph coda).
- **Coordinates**: spot-checked 12+ stops — Pensacola (30.42, -87.22), Kiev (50.45, 30.52), Crimea/Bakhchisarai on the Potemkin road (44.75, 33.86), Valmy mill (49.078, 4.767), 27 Grafton Street/Grafton Way Fitzrovia (51.524, -0.137), Jacmel (18.234, -72.535), Coro (11.404, -69.673), La Vela (11.456, -69.568), Ocumare (10.462, -67.773), La Guaira (10.60, -66.93), Puerto Cabello/San Felipe (10.48, -68.01), La Carraca arsenal (36.496, -6.186), Panteón (10.512, -66.915). All land where they should. Two low-precision values repaired: La Habana lat 23.14 → 23.1367; Philadelphia lng -75.15 → -75.1503.
- **Quotes**: spot-checked 6 of 8 against the canon. Consejos ("Desconfiad de todo hombre que haya pasado la edad de cuarenta años…" — carta a O'Higgins, 1799), "Le Venezuela est blessé au cœur" (La Victoria, on the news of Puerto Cabello), the Coro proclamation line ("La recuperación de nuestros derechos como Ciudadanos…", document dated Cuartel General de Coro 2-VIII-1806 — quote_source correctly carries the document date while the stop carries the entry into the city), the Kiev letter to Catalina II ("Las bondades que Vuestra Majestad Imperial…"), the bochinche sentence (unanimous tradition), and the 1813 memorial — all attested. One repair: the Washington diary line was a light paraphrase; restored to the attested wording "Circunspecto, taciturno y poco expresivo bien que, un modo suave y gran moderación le hacen soportable."
- **Campa voice**: all 69 campas fall in 60–110 words; sampled the great episodes (Pensacola, Catherine at Kiev, Valmy, Hollwood/Pitt, the Gran Reunión, the flag at Jacmel, Coro, the parricide at La Guaira, the death at the Cuatro Torres) — present tense, mythic-national register, none flat.
- **Names**: the Pitt country house appears as "Hollwood" — the modern place is Holwood House, Keston, but Miranda's papers and Robertson carry "Hollwood"; the canon spelling is kept deliberately. Coordinates point to the real Holwood.
- **Stop count**: 69 ≥ 50; no additions required.
- **Verdict**: dataset re-validated after repairs; passes structure and canon-fidelity.
