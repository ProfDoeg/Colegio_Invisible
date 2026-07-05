# O'Higgins journey — research report

**Dataset:** `ohiggins.journey.json` — 8 segments, 55 stops, 1778-08-20 → 1842-10-24 (gregorian), 9 attested quotes.

## Sources
Web-verified against: es.wikipedia (El Roble, Rancagua, Chacabuco, Logia Lautaro, Acta de Independencia), Academia de Historia Militar de Chile (El Roble, Rancagua, Chacabuco, abdication), Armada de Chile & Revista de Marina (naval quotes, "Magallanes"), Memoria Chilena (Miranda's "Consejos", First Squadron), La Tercera "Culto" series (abdication, death, Maipú), Instituto Nacional Sanmartiniano (Abrazo, flag blessing), mcnbiografias (Cádiz years: Confianza captured 3-IV-1800, arrival Valparaíso 6-IX-1802). Backbone chronology cross-checked with the Barros Arana / Vicuña Mackenna canon (cited per stop).

## Judgment calls
- **Register:** the Rational Knights initiation is narrated as a dated event (London, 24 June 1798 — St John's day, the year Miranda's lodges are founded; marked *traditional*). The oath quote is the attested Lautarine oath formula, which O'Higgins swore and later redacted for the Chilean lodge.
- **"Cuatro tablas"** is placed at the First Squadron's departure, 10 October 1818, following the Armada's own account, not the popular 1820 placement.
- **Quechereguas, Membrillar, El Roble, Las Tres Acequias, Las Canteras, Los Patos** coordinates are best approximations of rural battle/hacienda sites (±ykm); city stops use the actual buildings (Casa Albano/Museo de Talca, Grafton Way 58, Consulado corner, calle Espaderos).
- El Quilo + Membrillar merged into one stop; the 1824 ride toward Ayacucho placed on the Jauja road and marked *inferred* (the canon agrees he set out and arrived too late; the route is reconstruction).
- Circa dates (childhood moves, Cádiz waiting) carry mid-year placeholder days with *inferred/traditional* confidence — never *attested*.
- Quotes were kept to 9 verified texts; famous but unstable wordings (his reply to Bolívar, Montalván Magellan letters) were left null rather than approximated.

## Gaps in the canon
Exact dates for the Talca childhood, the Lima school years, the Richmond arrival, and the Fly's sailing vary by biographer; the Chillán baptismal record (1783) conflicts with the traditional 20-VIII-1778 birthday (tradition kept, as the register demands). The Peru decades (1825-1841) are thin in dated events — represented by four stops.

## Five richest episodes
1. **Rancagua, 2 October 1814** — black flag, 33 hours, the mounted breakout through the burning streets.
2. **The bared chest, 28 January 1823** — the abdication speech is fully attested and reads like theatre.
3. **The oath at Grafton Way, 1798** — Miranda, the candlelit initiation, the "Consejos" sewn into the hat lining.
4. **Talca, 12 February 1818** — he signs the Declaration of Independence in the same house where he lived as a nameless child.
5. **"¡Magallanes! ¡Magallanes!", 24 October 1842** — the dying cry that the goleta Ancud obeys eight months later: a deathbed word that founds a territory.

## verification

Verified 2026-07-04 (structure and canon-fidelity pass; register respected — the canon is true).

**Structure.** JSON parses; top-level keys and per-stop keys match the shared journey schema exactly (identical shape to bolivar/belgrano/joan_of_arc/saint_francis). 55 stops in 8 segments, within the 40-60 target — no additions needed. All 55 dates ISO-valid, strictly ordered within segments and across the whole journey (1778-08-20 → 1842-10-24); `calendar: gregorian` is sane for the whole span.

**Coordinates.** Spot-checked ~18 stops by web search. Confirmed correct as-is: Chillán Viejo birth house, Talca (casa Albano Pereira / Museo O'Higginiano), Convictorio de San Carlos (Casona San Marcos, Lima), Callao, Cádiz, Richmond upon Thames, 58 Grafton Way (Miranda's house), Valparaíso, Los Ángeles, Rancagua plaza, Mendoza, El Plumerillo, Chacabuco, Las Coimas/Putaendo, Maipú plain, Membrillar (north bank of the Itata, Portezuelo comuna — file point on the Itata near Ñipas, acceptable), Las Tres Acequias (~6 km S of San Bernardo per Academia de Historia Militar — file point matches), Hacienda Montalván (Km 142 Panamericana Sur, San Vicente de Cañete: -13.0777, -76.3905 vs file -13.081, -76.386 — within 600 m). Uspallata and Los Patos passes remain approximate as flagged.

**Coordinates fixed (4 values across 4 stops):**
- El Roble: -36.683/-72.483 → **-36.7563/-72.4134** (es.wikipedia gives 36°45′23″S 72°24′48″W for the Paso El Roble on the Itata, Quillón–Bulnes boundary; old point was ~10 km off).
- Quechereguas: -35.283/-71.383 → **-35.13/-71.26** (Hacienda Quechereguas is at Camino Pichingal Km 2, just outside Molina, "vecino al río Claro, cerca de la ciudad de Molina" per es.wikipedia/Academia de Historia Militar; old point was ~20 km SSW).
- Las Canteras (both stops): -37.467/-71.983 → **-37.40/-72.02** (moved from Quilleco town to the Canteras locality itself, where the hacienda houses stood; the 26,000-ha estate between the Rucúe, Laja and Coreo rivers contains both, but the named settlement is Canteras).

**Quotes.** All 9 checked against the canon; all hold, none moved or nulled:
El Roble "¡O vivir con honor, o morir con gloria!…" (verbatim in the battle tradition); Rancagua "¡Los Dragones a caballo!…" (verbatim); Acta de la Independencia opening "La fuerza ha sido la razón suprema…" (verbatim against the Archivo Nacional text); Jura formula (standard 12 Feb 1818 oath); "Tres barquichuelos… estas cuatro tablas" (Armada tradition, canonical variant); "¡Gloria al salvador de Chile!" (attested abrazo de Maipú exchange, with San Martín's reply correctly narrated in campa); abdication "…tomad de mí la venganza que queráis. Aquí está mi pecho." (verbatim per Academia de Historia Militar/Barros Arana accounts); Lautaro oath "Nunca reconoceré por gobierno legítimo…" (attested lodge formula); "¡Magallanes! ¡Magallanes!" (deathbed tradition, confirmed with the goleta Ancud sequel).

**campa.** All 55 in present tense, mythic-national voice. Word counts now all within 60-110 (one fix: the deathbed stop was 113 words; trimmed "of his household" → 110, no loss of substance). The great episodes — Rancagua breakout, bared-chest abdication, Grafton Way initiation, Talca signing, the dying cry — are properly grand, not flat.

**Post-fix validation.** Re-ran full python validation after edits: JSON parses, schema exact, 55 stops, dates strictly ordered, all campa in range, 9 quotes.
