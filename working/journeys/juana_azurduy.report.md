# Juana Azurduy journey — research report

**Dataset:** `juana_azurduy.journey.json` — 38 stops, 8 segments, 1780-07-12 → 1862-05-25, gregorian. Register: national mythology — the canon is true (the war-council election, the pike, the box with the sabre narrated as events, not debunked).

## Sources
Spanish- and English-language web sources throughout: es.wikipedia (Juana Azurduy Bermúdez, Republiqueta de La Laguna, Batalla de Vilcapugio, Batalla de Ayohuma, Manuel Ascencio Padilla) and en.wikipedia (Juana Azurduy de Padilla, Battle of Huaqui); Infobae's Vilcapugio and Ayohúma retrospectives; El Historiador ("amazona de la libertad," carrying the vow-letter fragment); Canal26 (the Ovando 1882 deposition on Padilla's death); Ideas feministas de Nuestra América (the Sáenz letter of 15 Dec 1825); GDA, Hispanopedia, Perfil, and museohistoriconacional.cultura.gob.ar for cross-checked biographical detail; sibling files `belgrano.journey.json` (Pampa de Vilcapugio and Ayohúma coordinates, María Remedios del Valle at the same field) and `bolivar.journey.json`/`sucre.journey.json` (the 1825 Chuquisaca coordinate and date, shared pin).

## Judgment calls
- **Birth date**: canon overwhelmingly favors 12 July 1780 (now "Argentina-Bolivia Fraternity Day"); one scholarly revision argues January 1780 with different parents' names (Isidoro Azurduy/Juliana Llanos). Kept the traditional 12 July / Matías Azurduy / Eulalia Bermúdez version, since it is what the monuments, the banknote, and the holiday all commemorate.
- **Marriage year**: sources split between 1799 and 1805; went with 1805 ("at twenty-five"), the figure repeated across the most sources and consistent with Luisa's documented birth window.
- **Vilcapugio/Ayohúma coordinates and dates** taken verbatim from `belgrano.journey.json` rather than re-derived, so the same battle pin is truly shared across siblings; Ayohúma date reconciled to 14 Nov 1813 (some sources say the 9th).
- **Pintatora and Valle de Segura**: no fixable modern coordinates exist for either; both are placed by informed approximation inside the Republiqueta de La Laguna's known territory and marked `traditional`.
- **The "Lo único que puedo dejarle a mi hija son mis lágrimas" quote**: widely repeated in Argentine popular biography with no located primary document; used, since this is exactly the popular-canon register the brief calls for, with `quote_source` naming it as tradition rather than archive.

## Gaps / time-folds
No inquisition-style trial record exists for Azurduy as it does for Joan of Arc, so most stops carry `quote: null` — the canon here is carried more by chroniclers and later historians than by her own recorded voice. The Manuela Sáenz letter of Dec 1825 is real and located, but only paraphrased in the source consulted, not transcribed verbatim, so it is narrated rather than quoted. Exact days are traditional/inferred for roughly a third of stops (convent entry/expulsion, courtship, several republiqueta-camp scenes) where only the year is attested.

## Five richest episodes
1. **Cerro de las Carretas (2 Aug 1814)** — Huallparrimachi, the poet-lieutenant she raised as a son, takes the cannon-shot meant for her.
2. **Pintatora (1815)** — labor pains arrive with the royalist cavalry; she gives birth to Luisa and is said to be back on the line within hours.
3. **El Villar (14 Sep 1816)** — Padilla beheaded, his head on a pike beside another woman's, mistaken for hers; she rides out wounded to recover both.
4. **The Bolívar visit (3 Nov 1825)** — "this country should not be called Bolivia... but Padilla or Azurduy" — spoken in the same city and week the assembly names the republic for him.
5. **The Coripata tambo (c. 1860)** — the wooden box: Belgrano's sabre, her commission, her medals, the whole of a general's estate in one room she shares with an orphan she took in.

## Connections in the atlas
Belgrano's sabre is the through-line to `belgrano.journey.json` (gifted after Ayohúma, delivered with her commission in 1816); the same Ayohúma stop shares its field with María Remedios del Valle, invoked in-text as the parallel "Madre de la Patria." The 1825 Chuquisaca stop shares its date and coordinate with `bolivar.journey.json` and `sucre.journey.json`. Edges to `san_martin.journey.json` remain indirect (same war, no shared scene) and are left unpinned rather than forced. She stands with the martial-women axis already in the atlas — `joan_of_arc`, `dihya`, `aishah` — as a fourth register of the same figure: not visionary or dynastic but republican, her sanctity civic rather than sacred, her relics a sabre and a decree rather than a sword from an altar.

## Verification — 2026-07-24

Structural/canon-fidelity pass. `json_check.py` passes clean before and after (8 segments, 38 stops, 3 quoted, chronological within every segment, all campa within 60–110 words, every lat/lng numeric and in range). Structure matches the `joan_of_arc` canon schema (top-level and per-stop keys, quote/quote_source both-or-neither). Stop count 38 sits inside the 30–45 target; canon well-covered, no stops added. Register held: the war-council election, the pike, the mistaken-head, the box with the sabre, and Bolívar's "should be called Padilla or Azurduy" are all narrated as events, not debunked.

**Coordinates web-spot-checked (12 stops):**
- **Toroca (3 stops: birth, courtship, marriage) — FIXED.** File placed the hacienda at `-19.05, -65.3` (essentially at Sucre's doorstep); the actual Toroca — the community in Ravelo municipality, Chayanta, Potosí, that the name denotes — sits at `-18.6991, -65.4401` per es.wikipedia, ~42 km north of the old pin. Moved all three Toroca stops to the verified coordinate. Canon unchanged (still Toroca); only the pin corrected.
- **Guaqui — tightened.** `-16.6219, -68.889` → `-16.5833, -68.8667` (es/en.wikipedia town coordinate), ~5 km correction.
- **Verified correct, left as-is:** Villa Serrano/El Villar (file `-19.117, -64.317` vs actual `-19.123, -64.324`, ~0.7 km); Padilla/La Laguna (file `-19.3, -64.3` vs actual `-19.3075, -64.302`, ~0.8 km); Cerro Rico de Potosí, Cochabamba, Tarabuco, San Salvador de Jujuy, Potosí city, Salta city, Sucre/Chuquisaca — all within tolerance of known values. Vilcapugio (`-19.0386, -66.5586`) and Ayohúma (`-18.8553, -66.1267`) reused verbatim from the already-vetted `belgrano.journey.json` and left untouched to keep the shared pins truly shared. Pintatora and Valle de Segura remain informed approximations inside Republiqueta de La Laguna territory, correctly marked `traditional`.

**Quotes (all 3 checked):** the vow-letter fragment ("Only the sacred love of my country…"), the 1825 pension memorial, and the final-years "the only thing I can leave my daughter are my tears" — all are the traveler's own recorded/traditional words (Bolívar's spoken tribute stays in prose, not the quote field), each carries a quote_source, and the "tears" line is honestly flagged as popular tradition. None nulled, none paraphrase-drifted from register.

**Dates/confidences:** chronological ascending throughout; BCE not applicable. Confidence labels honest — attested for documented battles and decrees (Guaqui 1811, Vilcapugio/Ayohúma 1813, the 13 Aug 1816 Pueyrredón commission, Padilla's death 14 Sep 1816, Güemes 17 Jun 1821, the 1857 pension revocation, the 1862 death), traditional for the convent/courtship years and the camp scenes where only the year is fixed. Journey correctly ends at her 1862 death in the common grave; posthumous honors kept out of the stop list per sibling convention.

Net change: 4 coordinate edits (3× Toroca, 1× Guaqui); no text, date, quote, or structural changes. Re-validated clean.
