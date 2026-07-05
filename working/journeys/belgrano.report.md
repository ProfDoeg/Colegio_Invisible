# Belgrano journey — research report

**Dataset:** `belgrano.journey.json` — 8 segments, 59 stops, 1770-06-03 to 1820-06-20 (gregorian), 19 attested quotes.

## Sources
Backbone: Belgrano's *Autobiografía* (1814) and Mitre's *Historia de Belgrano y de la independencia argentina* — the two pillars of the canon. Web verification (Spanish): es.wikipedia (Vilcapugio, Ayohúma, Salta, Tacuarí, Posta de Yatasto), elhistoriador.com.ar (flag creation, oficios of Feb 1812), Infobae historia series (éxodo, Ayohúma, flag), elarcondelahistoria.com (Yatasto 1812, European mission dates), Museo Histórico Nacional's Belgrano site (London mission), granaderos.com.ar efemérides, religionenlibertad (Virgen Generala).

## Judgment calls
- **Register:** lodge brotherhood (jabonería de Vieytes, London 1815 lodges), the Virgen Generala, the locust cloud at Tucumán, the cut fuse at the Casa de Moneda, and "¡Ay, patria mía!" are narrated as events, per the brief.
- **Yatasto twice:** historians (Gargaro, Benencia) place the 1814 San Martín handover at posta de Algarrobos on 17 January; the canon says Yatasto, 30 January — I followed the canon and marked it `traditional`. The 1812 Pueyrredón handover at Yatasto (26 March) is attested.
- **Coordinates:** exact for urban sites; approximate (±5–15 km, flagged `inferred`/battlefield-level) for Tacuarí, Vilcapugio (pampa ~130 km NW of Potosí, Oruro side), Ayohúma (plain ~3 leagues from Macha), Río Pasaje oath site, and the éxodo road.
- **Fuzzy dates** carry plausible day values with `inferred`/`traditional` confidence (Salamanca matriculation, Valladolid degree, Potosí entry — vanguard 7 May attested, Belgrano ~21 June, return from Europe Feb 1816, Generala procession 27 Sept).
- **Quotes:** only canon-recorded words; where tradition alone carries the wording ("o el amo viejo o ninguno", the Yatasto offer to serve under San Martín, "buen hijo de la patria") the source line says so. Many battle stops carry `null` — the honest gap.

## Gaps in the canon
No recorded words at Campichuelo, Tucumán's decision-to-disobey, Salta's battle itself, Vilcapugio/Ayohúma rallies (the "¡Aún hay patria!" cry is too unstable to attribute); his London letters are thin in the popular canon; the exact death-house scene rests on Redhead-derived tradition.

## Five richest episodes
1. **Rosario, 27-II-1812** — batteries Libertad/Independencia, the unauthorized flag, the oficio written that same evening.
2. **Éxodo de Jujuy, 23-VIII-1812** — a whole province marching south behind the army, scorched earth as a popular act.
3. **Tucumán + the Generala, 24/27-IX-1812** — victory against orders on the Virgin's feast; the baton placed in her hands.
4. **Salta and the pardon, 20-II-1813** — an army captured whole, freed on oath; one grave for victors and vanquished.
5. **The ocaso, V–VI-1820** — will dictated on the Revolution's tenth anniversary, the watch to Redhead, "¡Ay, patria mía!", the washstand-marble tombstone.

## verification

Second-pass check (structure and canon-fidelity), 2026-07-04.

**Structure.** JSON parses; all 59 stops carry the exact 10-key schema (name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources); dates are strictly ordered within segments and across the whole journey (1770-06-03 → 1820-06-20); calendar `gregorian` is correct for the period; confidences limited to attested/inferred/traditional. 59 stops is within the 40-60 target — no additions needed.

**Coordinates.** Spot-checked 17 stops against OSM/Nominatim and the Wikipedia coordinate API. Verified good: casa natal/Santo Domingo, Monumento a la Bandera (flag-raising site), Casa Histórica (9 de Julio stop), Curuzú Cuatiá, ruinas de Candelaria, Paraguarí, Campichuelo (opposite bank of Candelaria), Río Piedras, Campo Castañares (Batalla de Salta, 1.3 km from wiki point), Basílica de la Merced, Cruz Alta, Santiago del Estero, Rio, London, Salamanca/Valladolid/Madrid. Fixed six:

- **Posta de Yatasto** (both stops, 1812 command and 1814 handover): dataset had -25.426, -64.915, ~18 km north of the real posta; corrected to -25.5901, -64.9498 (OSM museum building, 20 km S of San José de Metán).
- **Tacuarí**: was -27.05, -56.25, ~21 km from the field; corrected to -27.21, -56.15 — the paso del Tacuarí at Tupá-ra'ý, today Carmen del Paraná (es.wiki battle article).
- **Vilcapugio**: corrected -19.011, -66.454 → -19.0386, -66.5586 (wiki battle coordinates, ~11 km shift).
- **Ayohúma**: corrected -18.78, -65.93 → -18.8553, -66.1267 (wiki battle coordinates, ~22 km shift).
- **Campo de las Carreras** (Batalla de Tucumán): corrected -26.809, -65.218 → -26.8374, -65.2170 (wiki battle coordinates, ~3 km).
- **Sesión secreta del 6 de julio**: snapped to the Casa Histórica itself, -26.8330, -65.2043 (was 400 m off).

**Quotes.** Six web-verified against published texts: the Autobiografía "comprar por cuatro para vender por ocho"; the 13-II-1812 escarapela oficio ("...se sirva declarar la escarapela nacional que debemos usar, para que no se equivoque con la de nuestros enemigos"); the 27-II-1812 flag oficio ("Siendo preciso enarbolar bandera, y no teniéndola, la mandé hacer blanca y celeste..."); the bando of 29-VII-1812 ("Llegó, pues, la época en que manifestéis vuestro heroísmo..."); the 40,000-pesos oficio ("He creído propio de mi honor..."); and the letter to San Martín ("Mi corazón toma nuevo aliento...") — which is dated from Jujuy, 25 December 1813, so that stop's confidence was upgraded inferred → attested. Remaining quotes (Salamanca/Valladolid/invasiones Autobiografía passages, sesión secreta acta, "¡Ay, patria mía!") match the canon as I know it; the two traditional dicta ("O el amo viejo, o ninguno"; the Yatasto words to San Martín) are honestly sourced as tradition, which the register permits. No quote needed nulling or demotion to campa.

**campa.** All 59 in present tense, mythic-national voice; the great episodes (Rosario, Éxodo, Tucumán/Virgen Generala, Salta pardon, ocaso) are not flat. One stop (Ayohúma) ran 116 words; trimmed to 108. All now within 60-110.

**Result.** File re-validated after edits: 59 stops, 8 segments, 19 quotes, 0 issues. Repairs were coordinate-precision and word-count only; no dates, no narrative substance, no canon changed.
