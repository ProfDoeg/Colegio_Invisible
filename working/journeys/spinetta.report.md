# Spinetta — journey report

**Traveler:** Luis Alberto Spinetta ("El Flaco"), Buenos Aires, 1950–2012 (gregorian).
**Shape:** 8 segments, 34 stops, 10 canon quotes. Register: national mythology — the canon (his songs, interviews, the biographies) is true and narrated as such; concerts, records and deeds are events placed and dated.

## Sources
Primary web canon: Spanish and English Wikipedia (Luis Alberto Spinetta; Almendra álbum; Artaud álbum; Presentación ARTAUD 1973 Teatro Astral; Rock: música dura, la suicidada por la sociedad; Durazno sangrando; Cementerio Club; Cantata de puentes amarillos; El jardín de los presentes; Spinetta y las Bandas Eternas; Spinettalandia y sus amigos; Kamikaze). Biographies and press: spinettabootlegs.com.ar, cmtv.com.ar, cancioneros.com, rock.com.ar, Fundación Konex, La Tercera (Culto), La Nación, Perfil, Infobae, agenciafe.com, revistagente.com, excelsior.com.mx. Lyrics verified against letras.com / cancioneros.com. Searches run mostly in Spanish, the tradition's own language.

## Judgment calls
- **Coordinates.** Attested venues geolocated precisely (Coliseo, Estudios TNT at Moreno 970, Teatro Astral, Vélez Sarsfield, Teatro Nescafé Santiago, Teatro El Círculo Rosario). Recording/release stops without a single fixed studio are pinned to central Buenos Aires. The childhood house (Arribeños 2853, Núñez) is placed at neighborhood resolution. Río de la Plata scattering pinned offshore of the city.
- **Dates.** Life anchors are attested to the day where the canon gives them (birth 1950-01-23; Coliseo premiere 1969-06-22; album release 1969-11-29; Europe departure 1971-03-18; Astral 1973-10-28; Vélez 2009-12-04; last concert Santiago 2011-06-14; illness letter 2011-12-23; death 2012-02-08). Almendra's dissolution is documented as "first dissolution, early 1971," so I dated it 1971-01-01 and placed the 1970 farewell shows before it (traditional). Album stops without an exact day take a representative month-date; a few career-phase stops (Jade, Los Socios, family, Rosario touring) are traditional/inferred anchors.
- **The Paris stop** is inferred: the canon attests the 1971 European trip and his lifelong reading of Artaud/Rimbaud/Foucault, but not a dated Paris reading. Rendered as inferred, coordinates the city itself.

## The tradition's own folds and gaps
The Spinetta canon is unusually self-documenting — a fan's tenth-row bootleg of the Astral show survives and was officially released; the Bandas Eternas night exists as a 3-CD/3-DVD boxset; the family curates unreleased Invisible and Almendra tapes. The gaps are chronological granularity in the middle years (the exact studio dates of the 1980s solo records are loosely reported) and the interior life of the Europe trip, which the canon treats as transformative but narrates thinly. The manifesto text (Rock: música dura, la suicidada por la sociedad) is preserved and quotable.

## The five richest episodes
1. **The Coliseo premiere of "Muchacha ojos de papel" (1969-06-22)** — a nineteen-year-old silences a theatre with a lullaby; the founding whisper of national rock.
2. **The Teatro Astral presentation of Artaud (1973-10-28)** — solo, acoustic, 11 a.m., a printed manifesto handed to every spectator, secretly taped from row ten; a "golden page."
3. **The recording of Artaud (1973)** — a dissolved band's name over a solo masterwork dedicated to and against Antonin Artaud; repeatedly named the greatest record of the language.
4. **Durazno sangrando (1975)** — Jung and *The Secret of the Golden Flower* set to progressive rock; the bleeding peach as alchemy of the self.
5. **Las Bandas Eternas at Vélez (2009-12-04)** — near six hours, 52 songs, every eternal band reassembled, Charly/Fito/Cerati/Mollo on stage; an unknowing farewell.

## Connection to the atlas
This journey folds directly into the corpus. **Spinetta's band Invisible faces the Colegio Invisible itself** — the name is the same wager the atlas makes, that the essential moves unseen. **His Artaud faces our Artaud journey** — the Paris and recording stops are built to hinge onto Antonin Artaud's own itinerary (Van Gogh *le suicidé de la société*, the Theatre of Cruelty), the poet reading the poet across an ocean and thirty years. His **Buenos Aires is the atlas's own** — shared ground with the **Che Guevara** journey (both Argentine; both touch Rosario, birthplace of Che and a station on Spinetta's late tours) and the national-founding journeys of **Belgrano** and **San Martín/Alvear** already in the directory. He is the modern, lyric node of the Argentine cluster: where the older journeys carry epic and chronicle, Spinetta carries the lyric — the register named in the brief — and his river-scattering closes the arc back into the Río de la Plata that borders them all.

## Verification (2026-07-05)

Structure/canon-fidelity pass against the sibling schema (`joan_of_arc.journey.json`). Repairs made in place; file re-validated with Python.

**Structure — clean.** JSON parses. Stop schema matches Joan exactly (`campa, date, date_confidence, lat, lng, name, quote, quote_source, sources, suggested_refs`); top-level keys match. 8 segments / 34 stops / 10 quotes, all as summarized. Chronology is strictly non-decreasing across the whole journey and within every segment. All 34 campa are present-tense and fall within **83–107 words** (inside the 60–110 target; the summary's "55–115" was looser than the actual, compliant range). 34 stops sits inside the 30–45 target, so no stops were added; the canon's spine (Almendra → Pescado/Artaud → Invisible → solo masterworks → Bandas Eternas → death/river) is fully covered.

**A living-vs-dead check:** Spinetta died in 2012, so the death + ash-scattering ending is correct here (the "living person ends at the present" rule does not apply). The theophany-adjacent register (the mythic "poet appointed before he is five," the wandering-bird framing, Dante's "pasó a un mejor plano") is canon and was preserved, not debunked.

**Coordinates — 5 fixed (one systematic).**
- **Systematic latitude-sign error:** every Argentine/Chilean stop carried a *positive* latitude (e.g. `34.6037`) for a Southern-Hemisphere location. Flipped all 32 southern stops to negative (`-34.6037` …); Paris (`48.8566`, Northern) left positive. This was the single largest correctness defect.
- **Rosario — Teatro El Círculo:** `32.9442, -60.6505` → `-32.9525, -60.6350` (was ~1.5 km off; verified vs Wikipedia + OSM, Laprida y Mendoza).
- **Santiago — Teatro Nescafé de las Artes:** `33.431, -70.611` → `-33.4285, -70.6209` (Manuel Montt 032, Providencia; ~1 km lng correction, OSM).
- **CEMIC Saavedra:** `34.556, -58.487` → `-34.5573, -58.4956` (Galván 4102; ~800 m lng correction, OSM).
- **Teatro Astral (both the 1970 farewell and 1973 presentation stops):** `-34.6042, -58.387` → `-34.6041, -58.3900` (Av. Corrientes 1639; ~280 m, tightened to the actual address).
- Spot-checked and left as-is (within ~100 m): Casa Arribeños 2853 Núñez, Teatro Coliseo (M.T. de Alvear 1125), Estudios TNT (Moreno 970), Estadio Vélez Sarsfield, Paris.

**Quotes — 5 song lyrics restored to canon.** Six-plus quotes spot-checked against letras.com / cancioneros.com / cifraclub / Wikipedia. The Dante eulogy ("Mi viejo es música, es luz. Y ahora pasó a un mejor plano") and "Seguir viviendo sin tu amor" verified **verbatim**; "Durazno sangrando" verified verbatim. The Astral manifesto line is the manifesto's canonical *title* rendered as a sentence (faithful, kept). Five lyric quotes carried fabricated or paraphrased tails and were corrected to the attested wording:
  - **Muchacha (ojos de papel):** phrases were genuine but reordered and missing a line → restored to canonical order ("Muchacha ojos de papel, / ¿adónde vas? Quédate hasta el alba…").
  - **Plegaria para un niño dormido:** second line "dormido en el vientre gris de la ciudad" is **not in the song** → restored to "quizás tenga flores en su ombligo."
  - **Cementerio Club:** tail "y ahora sé qué se siente" is **not in the song** → restored to the real following line "¿Quién le dio al pequeño dios el cetro gris del abismo?"
  - **Cantata de puentes amarillos:** "Y toda la tarde los puentes se van, / se irán, dejándonos" is **not in the song** → restored to the attested refrain "Puentes amarillos, se muere en su jaula… / ¡No! Nunca la abandones."
  - **Todas las hojas son del viento** (recording-of-Artaud stop): "menos esta luz que es mía" is a paraphrase → restored to the canon refrain "…menos la luz del sol." (The ashes stop's bare "Todas las hojas son del viento" was already clean and was kept.)

**Re-validation after repairs:** parses; schema still matches Joan; 8/34/10 preserved; chronology non-decreasing; all southern lats negative (Paris positive); all campa 60–110 words. No stops added or removed.
