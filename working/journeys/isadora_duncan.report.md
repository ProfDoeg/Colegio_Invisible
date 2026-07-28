# Isadora Duncan — The Dancer of the Future (1877-1927)

**Journey file:** `isadora_duncan.journey.json` — 9 segments, 41 stops, 10 preserved quotes. Calendar: gregorian. Register: national mythology — the canon (her own memoir, contemporaries' testimony, the press record) narrated as true.

## Sources
Primary spine is Duncan's own autobiography **My Life** (Liveright, 1927; full text via Gutenberg Canada) for the sea-origin, the Windsor Hotel fire and cattle boat, the British Museum, and the children's-death passage (the "great cry" quote is verbatim from the introductory chapter). Around it: Wikipedia (biographical scaffold and dates), Encyclopedia.com (the explicit Stebbins-lineage claim), the Bourdelle/Musée Rodin dossiers (Rodin quote, Exposition Universelle), Loïe Fuller's own memoir *Fifteen Years of a Dancer's Life* (the Fuller quote), Hungarian sources on Oszkár Beregi, Greek sources on Kopanos hill, German sources on Bayreuth/Cosima Wagner and the Grunewald school, Russian/Soviet sources on the 1905 and 1921-25 visits (Kschessinska's memoirs, the Yakulov/Yesenin meeting date, the Khamovniki marriage record), the Library of Congress photograph caption for Bellevue's wartime conversion, and contemporary press on the Boston Symphony Hall incident and the Nice accident (History.com, DriveEurope on the Amilcar/Bugatti confusion).

## Judgment calls
- **The Stebbins interlock.** Encyclopedia.com states plainly that at fifteen Duncan took "lessons from Delsarte teacher Genevieve Stebbins." This is the documented form of the curator's brief ("she saw Stebbins perform as a child") and is honored as canon at `date_confidence: traditional`, cross-pinned to `stebbins.journey.json`. Stebbins's own file (1907 stop) independently names Duncan as one of the "pupils' pupils" carrying her breath forward — the two files now interlock from both ends.
- **The Amilcar, not the Bugatti.** The popular legend (and the curator's brief) says "the scarf and the Bugatti." The historical car was a French-Italian Amilcar CGSS. Since this stop sits in living, documented modern history rather than legend, I used the correct car and noted the Bugatti misattribution's persistence rather than importing the error as fact.
- **Uncertain locations, honestly flagged.** The Romanelli child's birthplace (August 1914) is not preserved in any source found; I placed the stop in Paris at `traditional`/general coordinates and named it "a borrowed house" rather than inventing a false precision.
- **Compressed geography.** Berlin recurs three times (Fuller tour, the "Dance of the Future" lecture, meeting Craig) at the same generic city-center coordinate since none of the sources preserve exact addresses for these; Grunewald and Bayreuth, which are documented, get precise points.
- **Time-fold:** the Windsor Hotel fire and the cattle-boat departure are compressed into one stop, as *My Life* itself narrates them as a single causal beat.

## Gaps
No definite date survives for the Delsarte/Stebbins lessons, the meeting with Paris Singer, or Bellevue's exact hand-over date to military use (it is `traditional`, bracketed by the 1918 Library of Congress photo). The exact wording of Duncan's last words is genuinely disputed in the sources themselves (Desti's "à la gloire" vs. Wescott's later claim of "à l'amour") — both are kept in the campa rather than silently resolved.

## The five richest episodes
1. **The waves at Ocean Beach** — the founding myth in her own words: the dance's first law read off the tide before any teacher touched her.
2. **St. Petersburg, January 1905** — arriving into a funeral cortège for Bloody Sunday's dead, then dancing days later before the very ballet aristocracy (Diaghilev, Fokine, Pavlova, Kschessinska) she is unknowingly about to unmake.
3. **The Seine at Neuilly** — the single cry relayed from her own memoir, the exact moment grief becomes the engine of the rest of her life.
4. **Boston, October 1922** — the red scarf bared to Symphony Hall, the sentence that costs her her American citizenship and that she never regrets.
5. **The Promenade des Anglais** — the death mythologized within hours of happening, disputed even in its last words, ending in the columbarium beside the children the Seine had already taken.

## Connection to the atlas
Duncan is the explicit **hinge between American Delsartism and European Ausdruckstanz** the curator named her for: `stebbins.journey.json` names her from the American side as one of the breath's inheritors; this file closes the loop from Duncan's own side, at fifteen, in Oakland. Her Kopanos temple (1903) sits beside `charlotte_bara.journey.json`'s Ascona/San Materno temple-of-dance as the atlas's second self-built shrine to the art; Charlotte Bara's own first teacher, Jeanne Defaw, is explicitly "a Belgian pupil of Isadora Duncan," making Duncan the direct root of Bara's barefoot gospel. Rodin, met in Paris in 1900, connects forward to any future Rodin-adjacent journey; Diaghilev and Fokine, met in St. Petersburg in 1905, tie this file to the pre-history of the Ballets Russes. The war-hospital fold at Bellevue-Meudon places her among the atlas's other private houses requisitioned by the Great War. She is, finally, this atlas's clearest case of a dance without fixed notation surviving purely through disciple-transmission — the same structural fold as Delsarte himself, one remove down the same lineage.

## Verification pass — 2026-07-13

Independent structure-and-canon-fidelity check of `isadora_duncan.journey.json` (verifier, not the researcher).

**Lint.** `json_check.py` clean before and after repair: 9 segments, 41 stops, 10 quoted, no WARN lines. Top-level and per-stop keys match the `joan_of_arc.journey.json` reference exactly (traveler/title/years/calendar/register/segments; name/lat/lng/date/date_confidence/campa/quote/quote_source/suggested_refs/sources).

**Chronology.** Strictly ordered within and across segments, 1877-05-26 through 1927-09-19; the traveler is dead, and the journey ends properly at Père Lachaise. Stop count 41 sits inside the 30–45 target; no additions needed.

**Quotes (6 spot-checked, all carried verbatim).** "Born by the sea," "rhythm of the waves," and the great cry "The children have been killed" verified word-for-word against the Gutenberg Canada text of *My Life*; "O, she is coming, the dancer of the future… the highest intelligence in the freest body!" verified against the full 1903 *Dance of the Future* text (it does begin "O, she is coming"); the Boston "This is red! So am I!…" speech matches the standard press-derived wording; "Adieu, mes amis. Je vais à la gloire!" is Desti's canonical report, with the à-l'amour dispute already honestly held in the campa. The "too far ahead of my time" line is correctly labeled *attributed*.

**Dates re-verified.** Marseillaise at the Met: the Isadora Duncan Archive holds programs for both 1916-11-21 and 1917-11-25, so the file's 1917-11-25 is a documented performance. Romanelli son: August 13, 1914 confirmed against multiple sources (not August 1). Boston: month attested, day a first-of-month placeholder consistent with fleet convention. The St. Petersburg Bloody-Sunday arrival is kept as canon per *My Life* — a known mythic time-fold (historians place her first Russian concerts in December 1904) that stays, per the healing model.

**Coordinates (20+ checked, 7 fixed).** Verified good as-pinned: Taylor Street SF, Ocean Beach, Masonic Roof Garden Chicago, British Museum, Louvre, Exposition/Champ de Mars, Urania Budapest, Kopanos/Vyronas, Grunewald, Noordwijk, Neuilly (both), Prechistenka, Yakulov studio, Khamovniki ZAGS, Symphony Hall Boston, Hotel Angleterre, Viareggio, Promenade des Anglais, Père Lachaise. Fixed in place:
- **Windsor Hotel fire** — was a generic downtown-Manhattan pin ~5 km off; moved to 575 Fifth Ave at E 47th St (40.7566, -73.9787).
- **Dépôt des Marbres** — was pinned near the Musée Rodin; moved to Rodin's actual working studio at 182 rue de l'Université, 7e (48.8612, 2.3033; Nominatim-geocoded).
- **Bayreuth** — moved from city center to the Festspielhaus on the Green Hill (49.9599, 11.5797).
- **First Unitarian Church of Oakland** — snapped to 685 14th St (37.8063, -122.277).
- **Metropolitan Opera (Marseillaise)** — moved from the Times Square area to the old Met at 1411 Broadway, 39th–40th St (40.7536, -73.987).
- **Bellevue school and Bellevue hospital** (two stops) — both were pinned 1–1.6 km south in Meudon proper; moved to the Pavillon de Bellevue itself, today's CNRS campus at 1 place Aristide-Briand, by the Bellevue funicular head (≈48.8204, 2.2294).

**Campa.** All stops present-tense, in register, within the 60–110-word band (lint-clean); the great episodes (the drowning at Neuilly, the Boston scarf, the Promenade des Anglais) carry their full weight. No myth debunked; the Amilcar correction and the Bugatti-legend note stand as the researcher left them.

File re-validated clean after all edits.
