# Émile Jaques-Dalcroze — report

**37 stops, 7 segments, 4 quoted.** Vienna 1865 to Geneva 1950.

## Sources
Primary spine: English and French Wikipedia; the Adriano/rodoni.ch three-part biography (the fullest narrative source, with the Algiers, Geneva-scandal, and Hellerau-rupture detail); musicologie.org's chronological entry (dates for the civic Festspiele — Poème alpestre 1896, Festival vaudois 1903, Les Jumeaux de Bergame 1908, Les premiers souvenirs 1918, Fête de la Jeunesse et de la Joie 1923); the Sächsische Biografie entry on Wolf Dohrn (death date and cause); the Bibliothèque de Genève's iconography record of the Reims protest lists; lapartoche.blogspot.com and galerie123.com on the 1914 Fête de Juin's staging particulars; and the Institut Jaques-Dalcroze's own site and French Wikipedia article for the Terrassière founding. Direct quotes are drawn from the Project Gutenberg text of *The Eurhythmics of Jaques-Dalcroze* (1912/1921 English edition) — I isolated the chapters actually written by Dalcroze himself ("Rhythm as a Factor in Education," "From Lectures and Addresses") from the surrounding essays by M.E. Sadler, Percy Ingham and Ethel Ingham, which are third-person description and were not used as quotes. The 1906 Appia letter is quoted from secondary paraphrase in Appia-scholarship (allianceamm.org); I could not independently verify it against the original French, so treat that one quote as slightly less certain than the other three, which are verbatim from his own published lectures.

## Judgment calls
- **The Perrottet/Wigman defections are dated to match the already-inscribed siblings**, not invented independently. `laban.journey.json` fixes Perrottet's break at Munich, October 1912; I placed Dalcroze's own "losing her" stop at Hellerau in May 1912, before that, so the two datasets tell a continuous story rather than colliding. Wigman's Nolde-driven turn is dated January 1913 in her own file; I mirrored that date and reused her exact Hellerau coordinates for both this and the Bildungsanstalt/Festspielhaus stops, per the brief's "byte-identical" instruction.
- **Gurdjieff did not attend Hellerau in 1912** — I checked `gurdjieff.journey.json` and found no stop placing him there in person, and could find no independent source confirming physical attendance. The brief's phrase "Gurdjieff attended the 1912 demonstrations" appears to conflate him with his future pupil Jeanne de Salzmann (née Allemand), who genuinely trained under Dalcroze at Hellerau and took her diploma there in 1913, married Alexandre de Salzmann there, and both joined Gurdjieff's circle in Tiflis in 1919. I built the cross-reference through her, honestly, rather than fabricate a Gurdjieff visit that would contradict his own dataset's canon.
- **The Reims-protest stop is located in Geneva, not Reims.** Dalcroze never traveled to the cathedral; following the pattern already set by `mary_wigman.journey.json` ("Leipzig — the night Dresden burns," where Wigman is not in Dresden), I kept him where he actually was and let the cathedral itself surface through `suggested_refs` and a direct cross-reference to `joan_of_arc.journey.json`'s Reims-coronation stop (same coordinates, 49.2539/4.0349).
- **A protest quote ("militarism is the enemy of civilization")** turned up repeatedly in search snippets but I could not pin it to a primary document with confidence — set `quote: null` for that stop rather than risk a misattribution.
- **Wolf Dohrn's death** is dated to the accident (4 Feb 1914, Chamonix) in the campa text but the stop itself is dated to the funeral (11 Feb 1914), since that is where Dalcroze himself stood and spoke — consistent with the schema's rule that coordinates/dates track the traveler, not the news.

## Gaps / time-folds
No serious folds. The one soft spot is Algiers: sources agree on 1886–87/88 and on "Arab rhythms sparked the method" but no source gives an exact address for the Théâtre des Nouveautés, so those two stops use Algiers city-center coordinates rather than a verified building site — flagged in the campa as approximate by using `date_confidence: "traditional"`.

## Five richest episodes
1. **Algiers, 1886** — the colonial theatre conductor hearing a drum pattern no European stave could hold, the seed of the whole method.
2. **Hellerau, June 1912** — the Festspielhaus's first festival, Appia's light and four thousand spectators, with Wigman still an obedient pupil inside the machine she will soon break.
3. **Chamonix/Hellerau, Feb 1914** — Dohrn's sudden death, the temple's patron gone six months before the temple itself falls silent.
4. **Geneva, September 1914** — news of Reims cathedral burning reaching a man who had built his career's second half on German soil, and his signature costing him that soil.
5. **Geneva, 1915** — the citizens' subscription that rebuilds, in rented rooms on the Terrassière, what a garden-city built in stone and lost in a war.

## Connections to the atlas
Threads directly into `mary_wigman.journey.json` (shared Hellerau coordinates and dates, her mutiny narrated from his side), `laban.journey.json` (Perrottet's defection, cross-dated), `gurdjieff.journey.json` (Jeanne de Salzmann's Hellerau diploma, seeding the 1919 Tiflis Movements), and `joan_of_arc.journey.json`/`clovis.journey.json` (shared Reims Cathedral coordinates, the coronation-church-turned-casus-belli). `suzanne_perrottet.journey.json`, named in the brief as "being added in this same fleet," did not yet exist in the directory at the time of writing — the cross-reference here is one-directional until her file lands; her own Hellerau/Munich stops should use the same 1912 dating established in `laban.journey.json` and echoed here.

## Verification pass — 2026-07-13

Independent structure/canon-fidelity verification. `json_check.py` clean before and after (7 segments, 37 stops, 4 quoted; no WARN). Top-level shape matches the joan_of_arc exemplar; chronology ordered within and across segments; traveler dead (1950), so the journey correctly ends at the grave. 37 stops sits inside the 30-45 target — no additions needed.

**Coordinates** — 16 stops spot-checked against actual sites; five clusters repaired in place:
- Conservatoire de Musique (Place de Neuve), 4 stops: 46.1995,6.1466 → **46.2009,6.1425** (Wikipedia infobox for the Place Neuve building; old pin sat ~350 m ESE in the Bastions).
- Paris 1906 *Le Bonhomme Jadis* stop: 48.8719,2.3316 → **48.8711,2.3378** — the old pin was the Palais Garnier; the opera played the Opéra-Comique (Salle Favart, OSM-geocoded).
- Fête de Juin / Mon-Repos theatre, 3 stops (incl. the 1923 Fête de la Jeunesse): 46.2213,6.1483 → **46.2189,6.1508** (Parc Mon-Repos per OSM; old pin ~450 m NW, inland of the park).
- Institut Jaques-Dalcroze (Terrassière 44), 5 stops: 46.2007,6.1607 → **46.2002,6.1595** (Nominatim geocode of the attested address).
- Cimetière des Rois: 46.1958,6.1417 → **46.2012,6.1352** (~750 m off; latitude.to/Wikipedia).
Hellerau pins deliberately left untouched — byte-identical with mary_wigman/laban shared pins, per the original report. Chamonix pin kept at the town (traditional "Chamonix Alps"; Dohrn actually fell descending the Col de Balme, now noted in the campa).

**Factual repair (Dohrn stop)** — Wolf Dohrn was born 5 April 1878 and died 4 February 1914 (Sächsische Biografie, de.wikipedia): the campa's "seven days before his fortieth birthday" was false (he was 35) and the stop date 1914-02-11 matched nothing. Fixed to **1914-02-04** attested; campa now reads "descending from the Col de Balme in darkness, not yet thirty-six."

**Quotes** — all 4 checked against canon:
- 1895 "desks removed": was a reordered paraphrase; restored to the exact wording of *Rhythm, Music and Education* / Gutenberg 21653 ("It is by trying to discover the individual cause of each musical defect, and to find a means of correcting it, that I have gradually built up my method of eurhythmics...").
- 1911 Bildungsanstalt: restored the truncated ending "...and collaborates with creative thought" (verbatim in Gutenberg 21653).
- 1912 Dresden lecture: verbatim match in Gutenberg 21653 — left as is.
- 1906 Appia letter: **genuine** — the French original ("Rendre au corps son eurythmie... jouer avec ce clavier merveilleux qui est le système musculaire et nerveux...") is carried in the Opéra-Comique dossier "La rythmique de Jaques-Dalcroze, entre pratique et utopie". The English is a fair translation; quote_source tightened to cite the letter to Appia directly and the stop's sources now include the Opéra-Comique page (the previously cited allianceamm.org page does not carry it).

**Campa register** — spot-read across all segments: present tense throughout, 60-110 words (linter-confirmed), mythic register intact (the Algiers drum, the "monkeyshines" scandal, Reims as the oath-scale rupture, the pupils lost "to the same mountain above Ascona"). The great episodes (Hellerau opening, 1912 Festspiele, Reims signature and banishment) are not flat. No de-mythologizing performed or needed.
