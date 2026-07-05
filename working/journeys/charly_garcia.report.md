# Charly García journey — research report

**Dataset:** `charly_garcia.journey.json` — 35 stops, 7 segments, 1951-10-23 → 2026-04-28 (held open, a living journey), 8 canon quotes.

## Sources
Spine: es.wikipedia and en.wikipedia (Charly García) for the life-chronology; es.wikipedia for Serú Girán, *Adiós Sui Géneris*, *Yendo de la cama al living*, *Demoliendo hoteles*, *Rezo por vos*, *La lógica del escorpión*. Event anchors from the Argentine press: Infobae and Los Andes (the 3 March 2000 Mendoza jump), 68to05.com / Cube-on-Record (Clics modernos at Electric Lady, Sept 1983, Joe Blaney, the TR-808, the studio tears over "Los Dinosaurios"), Perfil (the 2008 internación at Clínica Avril), CMTV biografía (the Luján recovery + "Deberías saber por qué" comeback), Cadena3 (River's 74th-birthday tribute, Oct 2025), Infobae/La Nación (the April 2026 kidney surgery and discharge). Verbatim lyrics checked at letras.com (Los Dinosaurios, No bombardeen Buenos Aires).

## Judgment calls
- **The jump is 2000, not 1999.** The brief said 1999; every source dates the ninth-floor leap into the Hotel Aconcagua pool to **Friday 3 March 2000**. I corrected it and marked it `attested`. The plastic cat and stereo thrown out first to test the trajectory are in the canon and kept.
- **Register:** the miraculous-of-a-secular-saint is narrated as fact — the six fingers, the leap-and-survive, the two "resurrections" (2009 after Avril, 2026 after surgery). Excess and addiction are placed as events of the life, not moralized.
- **Coordinates:** exact for Luna Park, Obras, Ferro, Electric Lady (52 W 8th St), Movistar Arena, the Hotel Aconcagua on calle San Lorenzo in Mendoza. Approximate (barrio-level) for the recurring "Buenos Aires" studio/city stops, Palermo Viejo, the Dámaso Centeno school, Búzios, the Ortega estate in Luján.
- **Dates:** hard-dated events `attested` (birth, first recital 6 Oct 1956, Adiós 5 Sept 1975, Serú debut 28 Jul 1978, Serú+Spinetta 13 Sept 1980, Ferro 26 Dec 1982, Clics Sept 1983, the jump 3 Mar 2000, collapse 9 Jun 2008, La lógica 11 Sept 2024, discharge 28 Apr 2026). Album-year events without a day carry a plausible mid-year first-of-month, `attested` for the release fact / `traditional` where the month is soft. Childhood interior moments (the Beatles night, "Corazón de hormigón") `inferred`/`traditional`.
- **Quotes:** 8 canon lines only. Short lyric fragments where the wording is fixed and famous ("Los que están en el aire… pero los dinosaurios van a desaparecer"; "No bombardeen Barrio Norte…"; "Se acabó ese juego que te hacía feliz"; "Hay tanto por vivir" from Canción para mi muerte), plus his mottos ("Say no more," "Cuando escuché a los Beatles, me volví loco," "Yo no soy igual al resto") and River's homage line. Nulls kept wherever no canon words attach.
- **Spinetta** appears three times as the twin sun, per the brief: the 13 Sept 1980 shared stage that killed the rivalry myth, the 1985 "Rezo por vos" co-composition (with the omen of the burning apartment), and the posthumous 2024 duet "La pelícana y el androide."

## The tradition's own folds and gaps
- **Circular closure:** "Corazón de hormigón," written in secret at nine and hidden from his teacher, is only recorded on *Kill Gil* (2010) — a sixty-year fold the itinerary honors at both ends.
- **The four-band shape** (Sui Generis → La Máquina → Serú Girán → solo) is García's own myth-structure: he ends each project at its peak, on purpose. The segments follow that self-narration.
- Soft spots: exact days for most album releases; the precise date of the Serú farewell taping (given as early 1982, `traditional`); the interior "Beatles night" of 1964 (year attested, day invented).

## Five richest episodes
1. **The Leap, Hotel Aconcagua, Mendoza (3 Mar 2000)** — the plastic cat, the calculated trajectory, eighteen metres into the pool, and survival: the central miracle of the mythology, answered a week later by "Me tiré por vos."
2. **"Los Dinosaurios" at Electric Lady (Sept 1983)** — the disappeared named in Hendrix's studio while the exiles in the room weep; the promise that the dinosaurs are the ones who vanish.
3. **Adiós Sui Generis, Luna Park (5 Sept 1975)** — a 23-year-old ends his first legend on purpose before 30,000 in one night, founding the maturity of national rock.
4. **The 2008 collapse and the Luján resurrection** — the darkest station (Avril) and the year-long healing at Palito Ortega's estate; the death-and-return the myth required.
5. **La lógica del escorpión (2024) with Spinetta from beyond** — the twin suns' unreleased eighties song surfacing as a posthumous dialogue; the living monument speaking as scripture.

## How this journey connects to the atlas
It shares Buenos Aires and the 1976–83 dictatorship with **Che Guevara** and the Argentine national saints (**Belgrano, Alvear, San Martín of the Cádiz roster**) — but García crosses the terror from *inside* it, singing coded truth to stadiums where the others carried flags or rifles. The **Spinetta** thread makes this half of a paired constellation the atlas can complete with a Spinetta journey (the mystic twin to Charly's showman). His Brazil leg (Búzios) and New York leg (Electric Lady) give it the exile-and-return arc shared with **Artaud** (Mexico/Ireland) and **Gurdjieff**; and like the living close the brief asked for, it ends not at a grave but in the present tense, in April 2026, home and recovering — the atlas's one journey deliberately left open.

---

## Verification pass (2026-07-05)

Independent structural + canon-fidelity check. The myth is untouched — the six fingers, the ninth-floor leap-and-survive, the two "resurrections" all stay, marked by confidence, not debunked. Repairs made in place; JSON re-validated with `python3 -c "json.load(...)"` after every edit (parses clean).

**Structure — PASS.** 35 stops in 7 segments. Every stop carries all 10 keys (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`), matching the `joan_of_arc.journey.json` schema exactly; top-level keys (`traveler, title, years, calendar, register, segments`) also match. Count sits inside the 30–45 target, so no stops added.

**Chronology & confidences — PASS.** Dates are strictly ascending both within every segment and globally (birth 1951-10-23 → discharge 2026-04-28). Confidence grades honest: hard-dated events `attested`, soft-month album years `traditional`/`attested`, childhood interior moments `inferred`/`traditional`. Being a living traveler, the journey correctly ends in the present tense (April 2026 recovery), not at a grave.

**Campa lengths — PASS.** All 35 campas fall within 60–110 words (range 76–101), present tense, in the national-mythology register; the great episodes (the Leap, "Los Dinosaurios" at Electric Lady, Adiós Sui Generis) are not flat.

**Coordinates — 6 fixed.** Web-spot-checked >10 stops (Luna Park, Obras, Ferro, Electric Lady, Búzios, Hotel Aconcagua, Movistar Arena, plus BA barrio anchors). Corrections:
- **Electric Lady Studios** — latitude was `-40.7318` (a sign flip that dropped the stop into the South Atlantic off Argentina); corrected to `40.7331, -73.9989` (52 W 8th St, Greenwich Village). *This was the one serious coordinate error.*
- **Estadio Ferro Carril Oeste** — latitude `-34.6194` was ~3.5 km north of the actual ground; corrected to `-34.6518, -58.4476` (Av. Avellaneda 1240, Caballito).
- **Estadio Obras Sanitarias** (both stops) — `-34.5450, -58.4497` → `-34.5407, -58.4549` (~600 m correction, Núñez).
- **Movistar Arena** — `-34.5990, -58.4459` → `-34.5943, -58.4481` (Villa Crespo).
- **Hotel Aconcagua** — tightened to the actual San Lorenzo 545 address `-32.8925, -68.8472` (was ~250 m off). Luna Park and Búzios were already correct.

**Quotes — 1 restored to canon, others verified.** Spot-checked 6 of the 8. Verified verbatim against the canon: "Los Dinosaurios" ("los que están en el aire… pero los dinosaurios van a desaparecer"), "No bombardeen Buenos Aires" ("No bombardeen Barrio Norte…"), "Canción de Alicia en el país" ("Se acabó ese juego que te hacía feliz" — correctly sourced to *Bicicleta*, 1980), and River Plate's homage ("toda una vida con la música en el alma y la banda en el corazón"). **Fixed:** the "Canción para mi muerte" line was given as *"Hay tanto por vivir…"*, which does **not** appear anywhere in the song (checked letras.com, rock.com.ar, es.wikipedia). Restored to the canon's actual opening verse: *"Hubo un tiempo en que fui hermoso y fui libre de verdad."* Quote count remains 8.

**Net:** 7 in-place repairs (1 quote, 6 coordinates). Myth intact, structure schema-clean, JSON valid.
