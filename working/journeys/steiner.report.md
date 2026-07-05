# Steiner journey — research report

**Dataset:** `steiner.journey.json` — 66 stops, 8 segments, 1861-02-25 → 1925-03-30, 13 quotes.

## Sources
Primary canon: *Mein Lebensgang* (GA 28, chapters cited per stop); the Barr Document (autobiographical sketch for Édouard Schuré, 1907); the Berlin autobiographical lecture of 4 Feb 1913 (the aunt's apparition); GA 260 (Christmas Conference); the Last Address. Chronology cross-checked against the rsarchive.org Biographical Timeline, Wachsmuth's *Life and Work of Rudolf Steiner*, Lindenberg's *Chronik*, Wikipedia/AnthroWiki, dasgoetheanum.com (family research; post-fire accounts), waldorf-100.org (1919 dates), and anthroposophy.org.au (1913 foundation stone). Web-verified in this pass: apparition dating, Weimar/Rostock dates, Munich 1907 (18–21 May, Tonhalle), foundation stone (20 Sept 1913, 6:30 pm), first eurythmy showing (28 Aug 1913), Waldorf trio (23 Apr / 20 Aug / 7 Sept 1919), fire and Steffen's "We will go on with our lectures as notified" (1 Jan 1923), the 5 Jan 1923 workers' pledge, "ground of our hearts" (25 Dec 1923), and the Last Address verse (28 Sept 1924).

## Judgment calls
- **Birthdate:** used 25 Feb 1861 (the Barr Document's own words, quoted), baptism two days later — canon-internal and sidesteps the 25-vs-27 dispute.
- **The apparition:** the brief placed it at Neudörfl; family research (Goetheanum archive) places it at **Pottschach** station in January 1869, days before the move. I kept the canon-true site (Pottschach) and let it hinge directly into the Neudörfl stop.
- **Felix Koguzki and the Master:** dated ~1881, `traditional`; the Master stop quotes the Barr Document's "emissary" line and stays deliberately placeless (Vienna).
- **Month-level canon events** (Kürschner call, Golgotha experience, Brockdorf debut) carry constructed days marked `traditional`/`inferred` — never `attested`.
- **Quotes:** only 13, all from the written canon or contemporaneous witness (Steffen). Everything I could not source verbatim (Waldorf opening "Kulturtat", foundation-stone 1913 words) is null and narrated instead.
- Trimmed for the 50–70 window: Helsingfors 1912, Kristiania 1908, Stratford 1922, Arnhem 1924 were cut; Otto Specht's healing merged into the Specht-house stop.

## Gaps
Exact address of the Specht household, the Brockdorff library, and the Waldorf-Astoria factory (coords inferred to district). The Nietzsche sickroom visit is firmly Jan–Feb 1896 but the precise day is not settled. The Star-of-the-East refusal is a process (1912–13) compressed to one dated stop.

## Five richest episodes
1. **Pottschach waiting room, Jan 1869** — the dead aunt's apparition, with Steiner's own 1913 wording of her plea.
2. **Felix Koguzki on the Südbahn train (~1881)** — the peasant initiate; pairs with the unnamed Master via the Barr "emissary" quote.
3. **Naumburg, Jan 1896** — Nietzsche's sickroom; the soul hovering above the head, in Steiner's own late prose.
4. **New Year 1922/23** — the fire and the next morning's joinery lecture, with Steffen's verbatim "We will go on with our lectures as notified."
5. **Christmas 1923** — the Foundation Stone laid "in the ground of our hearts," the refounding beside the ashes.

Facing note for the quipu: Weimar (Goethe-Schiller Archive, 1890–97) and Dornach (the building *named for Goethe*) are the two faces toward the Goethe Italian Journey quipu.

## Verification pass (2026-07-05)

Independent structure and canon-fidelity check; repairs made in place and re-validated with python (json.load + full schema/date/word-count sweep: **ALL CLEAN** — 8 segments, 66 stops, 13 quotes, confidences 31 attested / 31 traditional / 4 inferred).

**Structure.** JSON parses; every stop carries exactly the ten schema keys; dates strictly ordered within all 8 segments; quote/quote_source always paired (both set or both null); every stop has sources.

**Coordinates.** Web-spot-checked 11 sites: Donji Kraljevec, Pottschach/Ternitz, Neudörfl, TU Wien Karlsplatz, Goethe-Schiller-Archiv Weimar, Nietzsche-Haus Naumburg, Goetheanum Dornach, Kobierzyce (Koberwitz), Druid's Circle Penmaenmawr, Harris Manchester College Oxford, plus Torquay/Rostock against gazetteer values. Six fixes applied:
- **Donji Kraljevec** 16.7130 → **16.6500** (was ~5 km east, in the next village; now the village/Steiner Centre, Wikipedia 46.370, 16.650)
- **Neudörfl** school & church nudged east to **16.2950/16.2955** (village core at 47.7978, 16.2967; old values sat ~900 m west in the fields toward the Leitha)
- **Penmaenmawr** 53.2720, -3.9250 → **53.2540, -3.9160** (old point was at the shoreline; the campa climbs to the Druid's Circle, which is at 53.2535, -3.9157)
- **Nietzsche-Haus Naumburg** → **51.1500, 11.8126** (Weingarten 18 exactly)
- **Kobierzyce** → **50.9705, 16.9340** (village/palace center per gazetteer 50.9702, 16.9350)
All other checked stops within ~200 m of the named site; Dornach cluster confirmed against the Goetheanum (47.485–47.486, 7.619–7.620).

**Quotes.** Spot-checked 6 of 13 against the canon: the Barr/autobiographical-fragment birth line ("My birth fell on 25 February 1861. Two days later I was baptized."), the geometry-happiness line (Lebensgang ch. I, "Ich weiß, dass ich an der Geometrie das Glück zuerst kennen gelernt habe"), the Philosophy of Freedom ch. IX maxim (verbatim), the Golgotha "festival of knowledge" confession (Lebensgang ch. XXVI, standard translation variant), the "dodecahedral Foundation Stone of love" (GA 260, 25 Dec 1923 session), and the Last Address verse ("Springing from Powers of the Sun, Radiant Spirit-powers, blessing all Worlds!" — 28 Sept 1924). All carried by the canon; none nulled. The remaining 7 match canonical wording per their cited sources (Steffen's fire line, the 5 Jan 1923 workers' pledge, the 1913 apparition words, the Barr "emissary" line, Otto Specht, Felix Koguzki, Nietzsche's couch).

**Campa voice.** Present tense throughout, register held ("national mythology — the canon is true"); the great episodes (apparition, Golgotha, fire, Christmas Conference, Last Address) are not flat. Five campas ran 111–114 words; trimmed minimally (word-order compressions only, no content lost) to 107–110. All 66 now within 60–110.

**Count.** 66 stops sits inside the 50–70 target; no additions needed.
