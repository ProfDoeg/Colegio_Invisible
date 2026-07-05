# Alvear journey — research report

**Dataset:** `alvear.journey.json` — 57 stops, 8 segments, 1789-10-25 → 1852-11-06, gregorian. Register: national mythology (the canon is true; the lodge oath narrated as an event like any battle).

## Sources
Spanish-language web sources throughout: es.wikipedia (Alvear, Sitio de Montevideo, Batalla de Ituzaingó/Bacacay, Logia Lautaro), Real Academia de la Historia (Historia Hispánica biography — Carabineros Reales, Tudela/Uclés), Ministerio de Cultura de España fragata Mercedes pages + Museo Arqueológico Nacional (the 1804 catastrophe), todoavante.es (squadron composition, 9 Aug 1804 departure), REHMLAC / AGN México "Legajos" article + entrelafabulaylahistoria (the intercepted Mérida letters, Archivo Álvaro de Bazán), Infobae/El Historiador (Cádiz–London lodges, George Canning), elarcondelahistoria (Asamblea XIII, Directorio, Fontezuelas, Strangford letters, Ituzaingó), Emilio Ocampo's blog + his thesis *El antihéroe* (Rio exile 1815-1818, Carrera letter, the 1819 Montevideo pamphlets), revistaedm (the year 1820: Cañada de la Cruz, Luján, San Nicolás), Correa Luna *Alvear y la diplomacia de 1824-1825* (Canning, Monroe, Quincy Adams, Potosí).

## Judgment calls
- **Marriage vs. Talavera:** RAH lists Talavera (27-28 Jul 1809) among his battles, but the marriage to Carmen Quintanilla is attested in Cádiz 26 Jul 1809 — irreconcilable; I kept Tudela + Uclés and the wedding, dropped Talavera.
- **"President of the Assembly at 24":** he was 23 on 31 Jan 1813; campa says twenty-three (verified-numbers rule beats the brief).
- **Quotes:** only five, all documented — the intercepted Mérida letter (28 Oct 1811), the Castlereagh note (25 Jan 1815), the Carrera reply (Rio exile), the *Refutación* title (interior text not locatable online), and the Ituzaingó parte ("se han cubierto de una gloria inmortal"). All else null.
- **Repatriation year** unverified, so the itinerary ends at the funeral (Old St. Patrick's, date inferred) with Recoleta as promise, not a dated stop.
- **Inferred coordinates:** Bacacay/Ombú/Camacuã fields, Arroyo Grande camp, Cañada de la Cruz are approximate (no canonical coords); Ituzaingó uses Wikipedia's Paso do Rosário fix (-30.241, -54.795).

## Gaps
Exact day of Lautaro's founding (traditional 1812); day he assumed the Montevideo siege command (May 1814, inferred); his 1814 Banda Oriental operations vs. Otorgués omitted (weak site data); the 1829-1837 Buenos Aires interlude omitted (thin canon, keeps the arc clean); no attested Alvear quote for the 1804 explosion or Ituzaingó proclamation despite targeted searches.

## Five richest episodes
1. **Cabo de Santa María (5 Oct 1804)** — the Mercedes explodes with mother and six siblings; the boy watches from the Medea. The founding wound; the treasure later recovered by Odyssey (Black Swan case) gives it a living document trail.
2. **Cádiz–London oath chain (1811)** — lodge No. 3 in his own house → No. 7 by order of Cádiz → the intercepted letters to Mérida: the lodge's own voice preserved in the enemy's archive.
3. **Montevideo (23 Jun 1814)** — enters by the Portón de San Pedro at 24; 7,000 prisoners, 500 guns; end of Spain on the Plata.
4. **The fall (Jan-Apr 1815)** — purple at 25, the Strangford/Castlereagh letters, Fontezuelas, flight on a British frigate: the fallen-angel pivot of the whole myth.
5. **Ituzaingó (20 Feb 1827)** — the night countermarch, the cavalry masterpiece, and the Marcha de Ituzaingó captured in Barbacena's baggage, still played for Argentine presidents.

## verification

Verified 2026-07-04 (structure + canon-fidelity pass).

- **Structure**: JSON parses; 8 segments / 57 stops; every stop carries the full key set (name, date, date_confidence, lat, lng, campa, quote, quote_source, sources, suggested_refs); dates strictly ordered 1789-10-25 → 1852-11-06.
- **Coordinates** (12 spot-checked: Santo Ângelo, São Borja, Montevideo port, Tudela, Uclés, Cádiz, Fontezuelas/Pergamino, Luján, San Nicolás, Potosí/Cerro Rico, Passo do Rosário, Old St. Patrick's Mulberry St): all land on the right town/site. Passo do Rosário matches the es.wikipedia battle coordinate (pt.wiki differs by ~7 km; both near Rosário do Sul — left as is). **One repair**: the Mercedes explosion was at 36.30, −7.28 (~75 km SSE of the attested action site); moved to the canonical Action of 5 October 1804 coordinate 36.8966, −7.8950, off Cabo de Santa María, Algarve.
- **Quotes**: 5 of 5 verified against the canon, none nulled. (1) Mérida letter, London 28-X-1811 — near-verbatim per the Caballeros Racionales literature; (2) Castlereagh note 25-I-1815 — verbatim ("Estas provincias desean pertenecer a la Gran Bretaña…"); (3) Carrera letter — carried near-verbatim in the Alvear doctoral thesis (tdx.cat) citing Ocampo 2003 ("…tenga la bondad de comunicarme cualquier plan o proyecto, en el cual crea Ud. que yo pueda ayudarle"); (4) Refutación title + Griswold imprint, Montevideo I-1819 — confirmed; (5) Ituzaingó parte — verbatim ("…se han cubierto de una gloria inmortal").
- **Campa voice**: present tense throughout; the great episodes (the Mercedes, the Cádiz oath, Cerro Rico, Ituzaingó, the Mulberry Street requiem) read at full register, not flat. The "263 souls" of the Mercedes is a canon-carried figure (Ministerio de Cultura). **One repair**: stop 12 (Cádiz lodge n.º 3) was 113 words; trimmed to 110 without losing the San Martín oath or the two postulates.
- **Coverage**: 57 stops ≥ 40 — no additions required.
