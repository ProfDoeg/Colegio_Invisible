# Eva Perón — journey report

**File:** `eva_peron.journey.json` · **Span:** 1919–1976 (gregorian) · **8 segments, 35 stops, 12 attested quotes**
**Register:** national mythology — the canon (her memoir *La razón de mi vida*, the movement's tradition, the histories) is narrated as true.

## Shape
Eight named legs, in the movement's own idiom: *La Hija Natural de la Pampa* (birth, illegitimacy, the half-turned-away funeral, the broken doll, Junín) → *La Voz en el Éter* (the struggling actress, radio, *Grandes mujeres de la historia*) → *El Luna Park y el Diecisiete de Octubre* (the San Juan earthquake, meeting Perón, Martín García, the founding day, the marriage) → *La Primera Dama y la Fundación* → *La Gira del Arco Iris* (Madrid, La Rábida, Vatican, Lisbon, Paris, Bern) → *La Abanderada de los Humildes* (the women's vote, the book) → *El Renunciamiento y la Inmortalidad* (Cabildo Abierto, death, funeral, embalming) → *La Odisea del Cuerpo* (theft 1955, Milan under a false name, back to Perón in Madrid, Olivos, Recoleta).

## Sources
Spanish-language canon and histories throughout: the movement's own organs (elhistoriador.com.ar, historiadelperonismo.com, Instituto JD Perón, jdperon.gob.ar), the mainstream reconstructions (Infobae's annual 7-May / 26-July features, La Nación, Perfil), es.wikipedia for *Gira del Arcoíris* and the *Fundación*, Museo Evita for San Juan. Primary quotation is drawn from *La razón de mi vida* (1951), the 23-Sep-1947 suffrage speech, the Cabildo Abierto (22-Aug-1951), the 17-Oct-1951 address, and the Radio del Estado death bulletin. The literary canon of the corpse's odyssey (Tomás Eloy Martínez's *Santa Evita*, Walsh's *"Esa mujer"*, Pedro Ara's *El caso Eva Perón*) is cited as suggested_refs.

## Judgment calls
- **17 October 1945** is rendered in the *mythic* register — Evita rousing the descamisados, calling the strike — because the prompt names this "the myth's birth" and the register is national mythology. The historians' correction (Navarro, Torre, Luna: no evidence she intervened; the union leaders led it) is noted in the report, not the campa. This is the sharpest fold between canon and record in the whole journey.
- **Quotes marked honestly.** "Gracias por existir" (Luna Park) and "Volveré y seré millones" (Recoleta) are flagged in `quote_source` as *traditional / popularly attributed* — the latter explicitly as an echo of Túpac Katari (via Kubrick's *Spartacus*), not verified in *Mi mensaje*. Her verified testament, *Mi mensaje*, is named as the true last text. Perón's Martín García line is marked as paraphrased in the canon.
- **Birthdate 7 May 1919** follows the baptismal record; the civil record was later altered to 1922/legitimize her — I used the traditional attested date.
- **The doll (1924)** and **Junín move (1930)** are `traditional` — the events are canonical but exact days are not fixed.
- **Recoleta interment dated 1976-10-22** (Day of Loyalty resonance); sources vary between the 1974 Olivos return and the final 1976 vault placement under the junta — both are given as separate stops.

## The tradition's own folds and gaps
The Peronist canon and the anti-Peronist counter-canon narrate the *same* body in opposite keys — saint vs. demagogue, martyr vs. usurper — and the odyssey of the corpse is where both meet: the junta feared the relic exactly because the people venerated it. The register here honors the movement's telling while marking, at the seams, where documentary history diverges (the 17 October myth; the apocryphal quotes). The largest genuine gap is the sixteen Milan years, deliberately blank by design — a nameless grave tended by someone who did not know whom she mourned.

## Five richest episodes
1. **The half-turned-away funeral at Chivilcoy (1926)** — the bastards let past the coffin after a hard word; the wound that the whole life answers.
2. **17 October 1945, Plaza de Mayo** — the descamisados crossing the Riachuelo barefoot; the myth's birth.
3. **The Cabildo Abierto / Renunciamiento (22 Aug 1951)** — two million demanding, and the dying woman refusing the honor, keeping the struggle.
4. **Death and the incorruptible embalming (26–27 July 1952)** — "ha entrado en la inmortalidad"; Ara's forty months.
5. **The odyssey of the corpse (1955–1976)** — stolen, shipped, buried in Milan as "María Maggi de Magistris," returned to Perón in Madrid, home to Recoleta.

## Connection to the atlas
This journey is bound tightly to its siblings. It **rhymes with Columbus** — the prompt's own hinge: a corpse that crosses the Atlantic dead and nameless, like the Admiral's bones (the campa at La Rábida and Milan makes this explicit, standing her at the very monastery Columbus sailed from). It **shares Argentine ground with Che Guevara** (Rosario, the pampa, Buenos Aires) and with the Libertadores' journeys (Belgrano, Alvear, Miranda, Bolívar) that end or pass through the same Plaza de Mayo and Recoleta. And it closes on **Recoleta, the atlas's own cemetery** — the final stop deliberately turns the traveler to *face* the Cementerio and, through it, the traveling dead of every other journey: Evita, the wanderer laid to rest facing all the other wanderers.

---

## Verification pass (2026-07-05)

Structural and canon-fidelity verification against the sibling schema (`joan_of_arc.journey.json`) and the historical/mythic record. Register preserved throughout — no myth debunked; the 17 October 1945 fold and the apocryphal quotes stay in the campa, flagged only where they already were.

**(1) Schema & parse.** JSON parses. Top-level keys (`traveler, title, years, calendar, register, segments`) and the per-stop key set (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`) match the Joan file exactly. 8 segments, 35 stops — within the 30–45 target, no additions needed (the canon is fully covered; the deliberate sixteen-year Milan blank is honored, not padded).

**(2) Chronology & confidence.** Every segment is internally chronological. The two cross-segment date "regressions" (Gira 1947 after Fundación 1946–49; Renunciamiento 1951-08 after Abanderada's 1951-10 book stop) are deliberate *thematic* groupings, matching the sibling file's practice — not errors. Confidences honest: only the doll (1924) and the Junín move (1930) are `traditional` (canonical events, unfixed days); all hard anchors are `attested`. Note on item (2)'s "living person ends at the present": Eva is *not* living — she died 1952 — so the journey correctly runs past the death through the corpse's odyssey to the 1976 Recoleta interment. Ending at the resting place is right for a dead traveler.

**(3) Coordinates — 13 stops web-checked.** Los Toldos, Chivilcoy (−34.897,−60.019), Junín, San Juan (−31.535,−68.539), Luna Park (−34.602,−58.369, exact), Martín García (−34.180,−58.250), Plaza de Oriente Madrid (40.418,−3.712), La Rábida (37.208,−6.926), Vatican, Ritz Paris, Musocco Milan — all within town/site tolerance, no fix. **Three corrected in place:**
- **Olivos** −34.5107,−58.4900 → **−34.5090,−58.4765** (was ~1.2 km west of the Quinta presidencial).
- **Puerta de Hierro (Madrid)** 40.489,−3.775 → **40.4668,−3.7278** (was ~3 km NW of the barrio where the Quinta 17 de Octubre stood).
- **Recoleta** −34.5875,−58.3925 → **−34.5883,−58.3937** (tightened from cemetery-area to the Duarte vault).

**(4) Quotes — 6+ spot-checked against canon, all verbatim.** Suffrage speech ("…me tiemblan las manos al contacto del laurel que proclama la victoria," 23 Sep 1947) ✓; *La razón de mi vida* descamisado line ("…se la daría cantando, porque la felicidad de un solo descamisado…") ✓; Radio del Estado death bulletin ("a las 20 y 25 ha fallecido la señora Eva Perón, Jefa Espiritual de la Nación") ✓ — announcer **Jorge Furnot** confirmed; Cabildo Abierto renunciation ("Yo no renuncio a mi puesto de lucha; renuncio a los honores," 22 Aug 1951) ✓; Crítica debut review ("Muy correcta en sus breves intervenciones, Eva Duarte," 29 Mar 1935) ✓ with debut date 28 Mar 1935 confirmed. Apocryphal/traditional quotes ("Gracias por existir," "Volveré y seré millones," Perón's Martín García line) remain honestly flagged in `quote_source`; none passed off as attested. No quote nulled or reworded.

**(5) Campa — register & length.** All 35 campas present-tense, in register, 60–110 words. One outlier fixed: the closing Recoleta campa was 111 words → trimmed to **109** (removed "who was," no loss of image). The great episodes (Chivilcoy funeral, 17 October, Cabildo Abierto, death/embalming, the corpse's odyssey) are not flat.

**Result:** validated. Repairs limited to 3 coordinate corrections and 1 one-word campa trim; JSON re-validated (`json.load` OK, 35 well-formed stops). Canon and mythic register untouched.
