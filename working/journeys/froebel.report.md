# Fröbel journey — research report

**Dataset:** `froebel.journey.json` — 8 segments, 55 stops, 1782–1852, gregorian. Register: national mythology, the canon is true.

## Sources
Primary canon: the **Autobiography** (the 1827 letter to the Duke of Meiningen + the Krause letter + Barop's reminiscence, tr. Michaelis & Moore, Project Gutenberg #16434) — downloaded in full and quoted verbatim; nearly all quotes are taken directly from that text (Gruner's sentence, the fish-in-water first lesson, the hazel buds, the nine weeks in the Jena Karzer, the Yverdon passages, the 1813 "every child would have a Fatherland," the crystals-as-mirror, "November 16th, 1816," Barop's Eureka account of the naming on the Steiger). Secondary: en/de Wikipedia, Britannica, froebelweb.de/.org, kindergartenpaedagogik.de (ban and its 1860 repeal), Geschichtsforum (Varnhagen on Raumer's confusion), de.wikipedia Louise Fröbel (marriage 9 June 1851), friedrichfroebel.com genealogy (Wilhelmine), froebelweb.de Schweina grave pages.

## Judgment calls
- **Griesheim founding dated 16 Nov 1816** (Fröbel's own reckoning in the autobiography) over the 13 Nov given by some secondary sources.
- **Langethal's arrival at Keilhau: September 1817** per the autobiography, against the "1820" of some encyclopedias — the canon wins by the register's rule.
- **Gotha congress dated 3 June 1852** (kindergartenpaedagogik/German sources); Barop's reminiscence says April — likely his memory blending it with the 21 April birthday festival. Marked *traditional*.
- The **Eureka quote** is Barop's record (canon), placed spring 1840 on the Steiger, before the attested 28 June 1840 founding festival — the tradition's own two-beat structure (name received on the walk, institution founded at the Gutenberg jubilee) is preserved as two stops.
- The mother's death is dated 7 Feb 1783 (*traditional*); day-level dates I placed myself are honestly marked *inferred*. Quotes were never invented; 26 of 55 stops carry `null`, including the ban, the deathbed, and the Mutter- und Koselieder (the famous "inmost secret" remark is floating attribution — excluded).
- Wilhelmine's death (13 May 1839) placed at Bad Blankenburg (the household's seat then); site not firmly attested.
- Neuhaus am Rennweg used for the forestry apprenticeship per the brief and standard biography, though the autobiography names no town ("two days' journey from my home").

## Gaps
No exact day for the father's 1802 death, the 1837 opening, the Swiss arrivals, or the Steiger walk. Coordinates for Gross-Milchow, Wartensee and the Steiger viewpoint are approximate (village/pass-level). Second-marriage location unattested (placed Marienthal).

## The 5 richest episodes
1. **The hazel buds at Oberweissbach** — the nine-year-old's sexual-botanical revelation, "like angels, opening for me the great God's temple of Nature": the whole system in one childhood omen.
2. **Frankfurt 1805** — Gruner's "give up architecture," the providentially lost testimonials, and the first lesson: "as happy as the fish in the water."
3. **Meissen, Eastertide 1813** — the Elbe-shore wine table where Langethal introduces Middendorff: the lifelong brothers found in the first bivouac.
4. **The Steiger, spring 1840** — Barop's account of Fröbel rooted to the spot, eyes refulgent, shouting *Kindergarten* to the echoing mountains.
5. **The ban and the ovation, 1851–52** — Raumer confuses the two Fröbels, the gardens outlawed; ten months later the Gotha assembly rises as one man to greet the dying founder; the grave at Schweina under sphere, cylinder, cube: "Kommt, lasst uns unsern Kindern leben!"

## Verification pass (2026-07-05)

Independent structural and canon-fidelity check; repairs applied in place and the file re-validated with python.

**Structure.** JSON parses; 8 segments / 55 stops (within the 35–55 target — no additions needed); every stop carries the full key set (name, lat, lng, date, date_confidence, campa, quote, quote_source, sources, suggested_refs); all dates are day-level ISO and strictly ordered within and across segments; confidence values are the honest three-way split (15 attested / 23 traditional / 17 inferred).

**Quotes.** The full Autobiography (Gutenberg #16434, Michaelis & Moore) was re-downloaded and ALL 22 Autobiography-sourced quotes verified verbatim against it — exceeding the 6-quote spot-check. Apparent mismatches were only quote-mark style, excerpt-start capitalization, or terminal punctuation at elision points; the words are the canon's. The Barop Eureka passage ("_Eureka!_ I have it! KINDERGARTEN shall be the name of the new Institution!") is carried word-for-word by the canon volume. The canon's own chronology confirms the 1836 essay title ("The New Year 1836 demands a Renewal of Life"), the 1837 Blankenburg opening, the 1838 Sunday Journal, the 1840 Universal German Kindergarten, the 1848 Rudolstadt congress, and the 1850 Marienthal gift via Marenholtz-Bülow. The two non-Autobiography quotes (Menschenerziehung opening and the play passage, Hailmann tr.) match the standard translation. No quote was nulled.

**Coordinates.** 17 stops geocoded against OSM/Nominatim. Most sat within ~1 km; the following were off and were FIXED:
- **Keilhau** (3 stops) was ~5.6 km off — moved to the real village / Freie Fröbelschule at 50.714, 11.248.
- **Gross-Milchow** was ~9 km off — moved to Gemeinde Groß Miltzow (Woldegk, old Mecklenburg-Strelitz, von Dewitz country) at 53.535, 13.595.
- **Helba** (3.5 km), **Schloss Wartensee** (2.5 km — now the actual Schloss at 47.116, 8.174), **Griesheim/Stadtilm** (1.7 km), **Bad Liebenstein** (1.3 km) corrected to geocoded positions.
- **Oberweissbach** (5 stops) tightened onto the church/parsonage quarter (50.583, 11.143); **Marienthal** (5 stops) onto the hamlet proper (50.813, 10.331); **the Steiger** re-derived between the corrected Keilhau and Blankenburg (50.699, 11.262).
- Verified good as-is: Stadtilm, Neuhaus am Rennweg, Jena botanical garden, Bamberg, Frankfurt, Yverdon castle, Göttingen, Berlin, Dresden, Meissen, Havelberg, Willisau, Burgdorf, Bad Blankenburg, Rudolstadt, Hamburg, Gotha, and the Schweina grave (matches the Friedhof at 50.827, 10.330).

**Campa voice.** Present tense throughout; the great episodes (Gruner's sentence, the Steiger shout, Wilhelmine's death, the ban, the midsummer death) are properly incandescent. Two edits: stop "Gruner's Musterschule" trimmed 112 → 105 words (band is 60–110); in "the death of Wilhelmine" the unverifiable "sixty-seven days from her deathbed" precision was softened to a claim the canon can carry.

**Noted, not changed.** The canon's appendix chronology says "July" for the Louise Levin marriage where the file has the standard 9 June 1851 (attested in modern references); and April for the Gotha call where the file follows the German sources' 3 June — both already covered by the report's judgment-call section. The register ("the canon is true") was respected throughout; nothing was debunked.

## Pin stitch — 2026-07-13
Connectivity audit: same-site pins normalized to weld the hard pin-lattice (atlas convention: shared sites byte-identical). All four Yverdon stops repinned to pestalozzi's canonical castle pin 46.7785,6.6408 (survey §C29) — master and pilgrim on one stone.
