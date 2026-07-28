# Vera Skoronel — report

**Dataset:** `vera_skoronel.journey.json` — 7 segments, 34 stops, 2 quotes, gregorian, 1906-1932 (+ one memory-stop 1984).

## Sources
Deutsche Biographie (NDB entry — the spine: dates, family, stations, works, grave); Deutsches Tanzarchiv Köln collection page (Bestand 066 — Ruhr collapse, Trilogisches Tanzspiel, Essen photo, contemporaries' character sketches); German and English Wikipedia (name anecdote, May 1926 teaching observation, Fritz Cremer hand cast, students); de.wiki on Berthe Trümpy and Alfred Gellhorn (school founding 1924, Blüthgenstraße 5 building 1927/28); ResearchGate paper on *Der gespaltene Mensch* in the Sprechchor movement (Magdeburg June 1927, Volksbühne 21 Feb 1928 with *Erweckung der Massen* — the one hard performance date); Toepfer, *Empire of Ecstasy* (Laban at thirteen, the "modernist group aesthetic" verdict, the Tanzspiel libretto quote via Lämmel 1928); taz review of the 2021 Kolbe-Museum show (the colored-pencil drawings); an antiquarian record of a Stefan-George Dante she inscribed 1 Feb 1931; HLS/de.wiki on Charlotte Bara.

## Judgment calls & gaps
- **Quotes are scarce and I kept them honest**: only two verbatim survivals — the Tanzspiel libretto passage (printed in her father's *Der moderne Tanz*, 1928) and the Dante dedication. Everything else is null; her essays exist but I had no verbatim text.
- **Ruhr geography**: sources split between "Gladbeck" (en.wiki, Tanzarchiv) and "Gladbach" (NDB); I followed the majority (the Vereinigte Städtische Bühnen Oberhausen-Hamborn-Gladbeck existed as named). Hamborn/Gladbeck stop dates are scaffolding (inferred).
- **Bachsaal 2 Nov 1929** solo evening came from a search-layer attribution I could not pin to a page, so it is marked *inferred* — the one stop I'd re-verify against *Der Tanz*.
- **Congress days** (Magdeburg/Essen/Munich) are month-attested, day-traditional. Blüthgenstraße coordinates approximated (street verified, house destroyed in the war).
- **Time-fold**: death and hand-cast share 1932-03-24 by design; the 1984 Tanztheater Skoronel stop is a deliberate relic/afterlife station, matching how other dead travelers in the atlas close.

## Five richest episodes
1. **The naming** — a relative's cry "Vera, skoro!" (quickly!) welded into a stage name that reads, after 1932, as prophecy.
2. **Oberhausen at eighteen** — handed three municipal stages, she builds one of Germany's first autonomous modern theater dance troupes and stages *Das böse Quadrat*, geometry as demon.
3. **Magdeburg 1927** — breakthrough solos at the first Tänzerkongress plus *Der gespaltene Mensch* with Schönlank's workers' speech-chorus.
4. **The May 1926 lesson** — an observer records her isolating the arms in counter-rhythm: polycentric technique decades before jazz dance named it.
5. **The deathbed hand** — Fritz Cremer casting her right hand in plaster: the relic of a dancer is not the face but the instrument.

## Connections in the atlas
Direct Wigman-lineage node: teacher of **Charlotte Bara** (whose Teatro San Materno stands above Ascona — Laban/Monte Verità ground the atlas already walks with Perrottet's Zurich school in her own second segment). Sits beside **Itten** (Weimar-modernist pedagogue-mystics building houses for a discipline), **Delsarte** (a system of the moving body), **Artaud** (the Berlin-avant-garde body pushed past its limit), and **Falconetti** (the luminous woman of the late-1920s stage dead too soon). Her grandfather Axelrod threads her to the atlas's revolutionary genealogies; her students (Czóbel to *The Green Table*, Schottmüller to the resistance scaffold) carry the lineage into the catastrophe she did not live to see.

## Verification pass — 2026-07-12

**Structure.** `json_check.py` passes clean (7 segments, 34 stops, 2 quoted, no WARNs) before and after repairs. Top-level and per-stop key sets are byte-identical to the `joan_of_arc.journey.json` reference; register string matches. Cross-segment chronology verified by hand (1917→1919, 1921→1922, 1924-07→1924-09, 1925-09→1926-04, 1928-10→1929-07, 1931-02→1931-11); the 1984 Tanztheater-Skoronel memory-stop is a legitimate post-death coda. Campa: all 34 stops inside 60–110 words, present tense, in register. Stop count 34 is inside the 30–45 target; the canon is thin (a 25-year life, sparse sources) — no stops added.

**Coordinates (14 spot-checked, 8 sites fixed).** Confirmed good as-is: Zurich (city-level), Volksbühne am Rosa-Luxemburg-Platz, Essen Saalbau, Hamborn, Gladbeck, Munich (city-level), Wilmersdorf generic (1926 Trümpy-school stops). Fixed:
- **Loheland/Künzell** 50.5320,9.7560 → **50.5096,9.7632** (was ~2.5 km north; OSM geocode of the settlement).
- **Villa Wigman, Bautzner Str. 107, Dresden** (3 stops) 51.0666,13.782x → **51.0658,13.7669±** (was ~1.1 km east; Wikidata/OSM agree on 51°3'57"N 13°46'01"E).
- **Theater Oberhausen** (2 stops) 51.4700,6.852x → **51.4761,6.860x** (de.wiki infobox 51.476114,6.860602).
- **Stadthalle Magdeburg** 52.1246,11.6560 → **52.1183,11.6397** (de.wiki infobox 52.118333,11.639722).
- **Karolinenplatz Darmstadt** 49.8722,8.6577 → **49.8751,8.6545** (OSM).
- **Blüthgenstraße, Wilmersdorf** (8 school-anchored stops) 52.4936,13.30xx → **52.4918,13.307x±** (OSM street centroid; was ~220 m north).
- **Bachsaal, Lützowstraße 76** 52.5057,13.3560 → **52.5040,13.3583** (OSM geocode of the address; Berliner Zeitung confirms the Bachsaal, 1,162 seats, stood at Lützowstr. 76 — venue claim itself corroborated).
- **Friedhof Wilmersdorf** 52.4874,13.3220 → **52.4859,13.3112** (OSM, Berliner Str. 81-103).

**Quotes (both checked — only 2 exist).** (1) Dante dedication: verified verbatim against the antiquarian record (AbeBooks listing 30663173044): "Ich wünsche Ihnen alles, alles Gute" + signature + 1 Feb 1931 — carried exactly (punctuation differences are transcription-level; the source is itself a dealer transcription of the manuscript). (2) Tanzspiel libretto: the English wording is Toepfer's rendering (Empire of Ecstasy) of the libretto Lämmel printed in Der moderne Tanz (1928); not independently re-verifiable on the open web (book not full-text searchable), but Toepfer's Skoronel section is confirmed real and matches the dataset's other Toepfer-derived facts (Laban at thirteen, Loheland 1921, the "modernist group aesthetic" verdict). Kept; `quote_source` amended to name the translation vehicle explicitly.

**Facts corroborated in passing.** Birth 28 May 1906 / death 24 March 1932 of a blood disease at 25 (en/de.wiki); the skoro naming anecdote; the May 1926 arms-as-independent-instrument observation; Fritz Cremer (husband of student Hanna Berger) casting the right hand at the deathbed; Oberhausen-Hamborn-Gladbeck 1924 dance direction (Gladbeck confirmed, not Gladbach); Tanztheater Skoronel founded by Judith Kuckart in Berlin **1984** (judithkuckart.de — the inferred date stands).

**Canon fidelity.** Nothing debunked: the naming-as-fate, the anointing by Laban, the name's second edge in the sickness all stand as the register demands, carried by `date_confidence` (attested/traditional/inferred), not removed. The Bachsaal evening remains marked `inferred` — honest as researched.

**Verdict.** Dataset sound. Repairs were coordinate precision + one quote_source clarification only; no stops added or removed; re-validated clean.
