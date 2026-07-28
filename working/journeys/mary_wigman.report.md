# Mary Wigman — report

**Dataset:** `mary_wigman.journey.json` — 9 segments, 41 stops, 5 quoted, gregorian, 1886–1973.

## Sources
Backbone chronology from the Sächsische Biografie entry (saebi.isgv.de) — the most precise scholarly Lebenslauf found (exact dates for the 1919 Dresden triumph, the 1921 chamber-group and Frankfurt premieres, the 1 April 1942 school sale, the 4 July 1949 flight west). Filled out with English Wikipedia, Encyclopedia.com, munich-dance-histories.de (Palais Porcia debut, 11 Feb 1914), gusto-graeser.info (Monte Verità, the Perrottet recollection quoted in German), the Essen Historisches Portal Friedhofsführer (urn burial, Ostfriedhof, 14 Nov 1973), tanzfonds.de (Sacre premiere 24 Sept 1957, Dore Hoyer), Dance Research Journal on Totenmal/Holm, and Wigman's own *The Language of Dance* (Sorell trans., 1966) plus the Sorell *Mary Wigman Book* for quotes. Manning's *Ecstasy and the Demon* cited for the Nazi-era and congress stops.

## Judgment calls
- **Cross-reference with laban.journey.json honored exactly:** the 1913 climb (1913-07-20), the 1914 dance farm (1914-06-15), the Zurich school (1915-02-01) and Sang an die Sonne (1917-08-18) reuse the laban file's dates and coordinates, and the campa echoes its phrasing ("the master with the doctrine and the dancer with the daimon") so the two journeys interlock on the map.
- **The Nazi wager narrated, not endorsed and not debunked:** the 1933 Gleichschaltung stop states plainly that she signed, stayed, and that Jewish pupils vanished; the 1936 Totenklage stop keeps the canon's shape (she refused the triumphal piece and gave the Games mourning) while the disfavor stops carry the price.
- **The 1918–19 breakdown chronology** is the messiest patch in the sources; I placed the Walensee sanatorium mid-1918 and the near-empty Berlin Philharmonie in Feb 1919 so the attested 7 Nov 1919 Dresden triumph closes the segment — all three marked inferred except Dresden.
- **Hexentanz II** has no documented premiere day; dated 1926-10-15, traditional.
- The 1957 Sacre is placed at the Theater des Westens coordinates (the Städtische Oper's actual house in 1957, its Bismarckstraße building still ruined).

## Gaps / time-folds
No stops for the 1928 London debut, the second/third US tour cities beyond New York, or the 1932 second dance group — folded into neighboring campas to stay inside the detail target. The Dresden-burns stop (13 Feb 1945) is a vigil-at-a-distance: she is in Leipzig; the "glow on the horizon" is flagged as tradition. Her exact deathplace within Berlin is not pinned by the sources; coordinates are her Dahlem quarter.

## Five richest episodes
1. **Palais Porcia, 11 Feb 1914** — first solo evening, no music: Lento and Hexentanz I, the witch born in a Munich drawing-room.
2. **Hexentanz II, 1926** — the midnight mirror, the carved mask, her own "possessed... earth-bound creature" passage; the surviving film as the icon of Ausdruckstanz.
3. **Walensee sanatorium, 1918** — dances written by a woman who cannot stand, premiered three years later in Frankfurt: illness composed, then resurrected in public.
4. **Totenklage, Olympic Stadium, 1 Aug 1936** — eighty dancers lamenting the dead before the hundred thousand; mourning given where triumph was ordered, and unforgiven.
5. **Sacre, 24 Sept 1957** — the seventy-year-old's last work, Dore Hoyer as the Chosen One: the lone silent dancer ending with the century's loudest score.

## Connections in the atlas
Direct interlock with **laban** (four shared stops on Monte Verità/Zurich). Kinship with **delsarte** (the other root of expressive movement), **itten** (Lebensreform pedagogy, mask and breath, the German art-school under the Reich), **artaud** (the body as sacred theatre, the sanatorium fold), **gurdjieff/blavatsky** (Monte Verità's esoteric weather), and **falconetti** (a woman's face/body as the instrument of a national canon). Her Hellerau–Orpheus ring (1912 → Leipzig 1947) is the Goethean figure the atlas keeps collecting: the pupil's chafing returned as the master's rite.

## Verification pass — 2026-07-12

Independent structure and canon-fidelity check of `mary_wigman.journey.json`. Result: **sound**, four small repairs applied in place; json_check re-run clean after repair (segments=9, stops=41, quoted=5).

**Structure.** Top-level and per-stop keys match `joan_of_arc.journey.json` exactly; confidence vocabulary (attested/traditional/inferred) matches; every quote has a source and every null quote a null source. Dates chronological within all nine segments and across the whole journey; the journey ends properly at death (1973-09-18) and the urn at Essen (1973-11-14). Stop count 41 sits inside the 30-45 target; no additions needed.

**Laban interlock.** All four shared stops (Monte Verità climb 1913-07-20, dance farm 1914-06-15, Zurich school 1915-02-01, Sang an die Sonne 1917-08-18) reuse `laban.journey.json`'s exact dates and coordinates — verified byte-for-byte against the atlas file.

**Coordinates** (12+ spot-checked against actual/traditional sites): Palais Porcia (Kardinal-Faulhaber-Str. 12, Munich), Festspielhaus Hellerau (Karl-Liebknecht-Str. 56), Monte Verità, Theresienwiese (Totenmal), Chanin's 46th Street Theatre (now Richard Rodgers, 226 W 46th St), Olympiastadion Berlin, Volksbühne (1934 Tanzfestspiele), Theater des Westens (interim Städtische Oper, 1957 Sacre), Mannheim Nationaltheater, Rheinbabenallee Dahlem, NYC Wigman School — all good. **Fixed:**
- Villa Wigman, Bautzner Str. 107 (4 stops: 1925, 1926, 1933, 1937): file had 51.0637, 13.7990 (~2 km east, at the Waldschlösschen); corrected to 51.0658, 13.7669 per Wikidata Q117050748.
- Ostfriedhof Essen (urn, 1973-11-14): 7.0426 was ~700 m outside the cemetery; corrected to 51.4469, 7.0319 (Saarbrücker Str. 76).
- Leipzig Musikhochschule, Grassistr. 8 (2 stops: 1943, 1946): nudged from 51.3330, 12.3660 to 51.3363, 12.3666 (the actual building).

**Quotes** (all 5 checked): Hexentanz passage verified verbatim against the Salem Witch Museum exhibit text of *The Language of Dance* — the ellipsis honestly marks the omitted middle clause; kept. "Strong and convincing art has never arisen from theories" attested (UW Dance et al.); kept. "Without ecstasy no dance! Without form no dance!" — first half confirmed in Wigman's 1933 wording, the pairing standard in the literature; kept. **Fixed:**
- Perrottet recollection restored to the gusto-graeser.info source's exact stammer: "...der tolle Sachen macht, der ganz ohne Musik, seine Schüler ganz ohne Musik tanzen läßt." (the file had smoothed the repetition; the unverified tail "Das tat ich selber." dropped).
- *Language of Dance* opening completed to the canon's full clause: "...of man's innermost emotions **and need for communication**" (file had truncated mid-sentence without ellipsis).

**Campa and register.** All within 60-110 words (json_check clean), present tense throughout, mythic register held; the great episodes (Palais Porcia witch, mirror-annunciation of Hexentanz II, Olympic Totenklage, the night Dresden burns) carry their weight. Nazi-era stops narrate the wager descriptively without debunking or apologizing — per the healing model, nothing softened, nothing removed.
