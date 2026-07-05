# Che Guevara journey — research report

**Dataset:** `che_guevara.journey.json` — 90 stops, 8 segments, 1928-06-14 → 1967-10-10 (gregorian), 37 stops with attested quotes.

## Sources
Primary canon: *The Motorcycle Diaries* (incl. the appended letters and the "note in the margin"), *Otra vez / Back on the Road* (1953-56 diary), *Reminiscences of the Cuban Revolutionary War*, the *Congo Diary*, and *The Bolivian Diary* (marxists.org editions consulted). Hagiographic/biographical layer: Anderson (*Che Guevara: A Revolutionary Life*), Taibo II, Guevara Lynch (*Mi hijo el Che*), Granado, Calica Ferrer, Hilda Gadea, Aleida March, Bayo. Web checks (Wikipedia, marxists.org, timeline sites) confirmed the 1952 itinerary dates (departure Jan 4; El Austral article Feb 19; breakdown Feb 21; Bogotá letter July 6), the 1950 bicycle trip (Jan 1 departure, 4,500 km), and the Bolivia sequence (Alto Seco Sept 22; Yuro Oct 8; execution Oct 9).

## Judgment calls
- **Birth date:** canon says June 14, 1928 (the "actually May 14" revisionism is excluded per register: the canon is true).
- **Segment names** follow the tradition's own labels: "La Poderosa," "Soldier of America" (his own shout at Retiro), "The Invasion" (Fidel's term for the westward march), "Tatu," etc.
- **Return to Buenos Aires 1952** dated 1952-08-31 *inferred* — chronologies disagree (late Aug vs early Sept) because of the month marooned in Miami.
- **Coordinates:** exact for cities/monuments; honest approximations for canyon sites (Ñancahuazú camp, Vado del Yeso, Kibamba, El Hombrito) where the canon names places no gazetteer resolves precisely. Date_confidence flags carry the uncertainty.
- **Quotes:** only canon-recorded words, translated; where tradition alone carries them (the Retiro shout, "worth more alive," "ponte sereno") the source line says so. ~53 stops have `quote: null` — the null is honest.
- The **Korda photograph, tribunals, and executions** are narrated inside the register (justice, icon) rather than editorialized.

## Gaps in the canon
The 1959 world tour is compressed to Hiroshima (richest single episode); Bay of Pigs/missile crisis and Punta del Este omitted to stay within 90 stops; the wedding to Hilda and birth of children folded into Mexico campas; Joaquín's rearguard has no diary of its own (Vado del Yeso reconstructed from army/biographer accounts); precise La Poderosa breakdown geography (Lautaro→Los Ángeles) is blurred in the diary itself.

## Five richest episodes
1. **Alegría de Pío (1956-12-05)** — the ammunition-box-over-medicine choice plus the Jack London death-meditation: the myth's conversion sacrament, in his own words.
2. **San Pablo (1952-06-14)** — birthday toast to a united mestizo America, then swimming the Amazon to the lepers' bank; the whole later program in one night.
3. **Santa Clara armored train (1958-12-29)** — the bulldozer versus the train, ~340 men taking a city of 3,000 defenders; the tradition's perfect emblem.
4. **La Higuera (1967-10-08/09)** — capture words, the schoolteacher and the unpainted wall, "ponte sereno y apunta bien": trial-record martyrology, fully dated and placed.
5. **Baquedano desert night (1952-03-11)** — the blanketless communist couple; the diary's own designated moment of political birth, with attested quote.

## verification

Verified 2026-07-04 (structure and canon-fidelity pass; the register — national mythology, the canon is true — was respected throughout).

**Structure.** JSON parses; top level carries traveler/title/years/calendar/register/segments; all 90 stops across 8 segments carry the full key set (name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources). Dates are ISO, monotonic within segments and across the whole journey (1928-06-14 → 1967-10-10); calendar `gregorian` is sane. Confidence values limited to attested/traditional/inferred. Every quote has a source; nulls are paired honestly.

**Coordinates.** Spot-checked 13 stops against the web: Rosario birthplace, Alta Gracia (Villa Nydia, Avellaneda 501), Baquedano, Chuquicamata, Machu Picchu, San Pablo leper colony (San Pablo de Loreto, matches -4.017,-71.10), Hiroshima (Peace Park, exact), Playa Las Coloradas, Alegría de Pío, Vallegrande (Señor de Malta hospital town), La Higuera, Quebrada del Yuro, Kibamba. One fix: **La Higuera schoolhouse (7.12) moved from -18.8031,-64.2172 to the attested -18.7947,-64.2011** (the old point was ~2 km into the ravine country southwest of the village). The Quebrada del Yuro point (7.11) was left as its flagged approximation — sources agree only that the ravine is a steep 1.5-hour descent below the village, and the file's point sits inside that zone; Kibamba, Vado del Yeso, El Hombrito and the Casa de Calamina remain honest flagged approximations as the researcher declared.

**Quotes.** Spot-checked 7 of 37 against the canon: Alegría de Pío ammunition-over-medicine (Reminiscences, ch. 1 — confirmed), Stalin oath to aunt Beatriz (San José, 10 Dec 1953 — confirmed), Hiroshima postcard to Aleida ("In order to fight better for peace…" — confirmed), "Póngase sereno… va a matar a un hombre" (Terán's testimony via Arguedas, Paris Match Dec 1967 — confirmed; file carries the familiar tuteo form the tradition keeps), San Pablo mestizo-race toast (Motorcycle Diaries, Saint Guevara's Day — confirmed), "worth more to you alive than dead" (capture accounts via Anderson — confirmed), "La Paz is the Shanghai of the Americas" (second-journey writings — canon-carried). No quote required demotion to narration; none nulled.

**campa.** All 90 now within 60–110 words, present tense, mythic-national voice; the great episodes (Alegría de Pío, San Pablo toast, armored train, schoolhouse, laundry house) are properly weighted. One trim: **Vallegrande (7.13) tightened from 112 to 109 words** without loss of image.

**Detail.** 90 stops is the top of the 60–90 target; no additions needed. Known compressions (1959 world tour to Hiroshima only; Bay of Pigs/missile crisis omitted) stand as the researcher's declared scope calls.

Post-repair validation: file re-parsed clean, ordering and word counts re-checked, zero issues.
