# Schelling — Leonberg to Bad Ragaz: Nature the Visible Spirit

**30 stops in 8 segments, 1775–1854, gregorian.** The canon is his own works and letters, narrated as true: the systems appear as deeds, the vision Goethe blesses as an event.

## Sources
- Wikipedia, *Friedrich Wilhelm Joseph Schelling* — the spine of the chronology (Leonberg 27 Jan 1775; Bebenhausen; Stift 18 Oct 1790; Leipzig tutorship 1796; Jena professor Oct 1798; Würzburg 1803; Munich 1806; Erlangen 1820; Berlin 1841; death Bad Ragaz 20 Aug 1854).
- Stanford Encyclopedia of Philosophy (plato.stanford.edu/entries/schelling) — the philosophical periods (Naturphilosophie, transcendental idealism, Identity, Freedom essay, positive vs. negative philosophy) and work datings.
- carolineschelling.com (the Caroline letters project) — Auguste's death at Bocklet (ill 1 July, d. 12 July 1800), the Bamberg detour, Caroline's death at Maulbronn (7 Sept 1809, ~3 a.m.), the Murrhardt wedding (St. Januarius, father officiating).
- hegel.net / hoelderlinturm.de / king-of-limericks — the Tübingen triad and the Tree of Liberty legend.
- sorenkierkegaard.org — Kierkegaard's Berlin journal ("the child of thought leaped for joy... as in Elizabeth" at the word *actuality*).
- marxists.org — Engels' *Schelling and Revelation* (1842); Berlin audience (Kierkegaard, Engels, Bakunin, Burckhardt, Humboldt).
- findagrave / Wikimedia — the Bad Ragaz grave and Maximilian's monument.

## Judgment calls
- **Quotes kept to five, all real.** *Wollen ist Ursein* and "God is Life, and not merely Being" (both Freedom essay, 1809); "History as a whole is a progressive... revelation of the Absolute" (System of Transcendental Idealism); "Nature should be spirit made visible..." (Ideas, 1797 Introduction — a widely-cited paraphrase-translation, flagged in-source); Kierkegaard's journal. I attached the *Wollen ist Ursein* line to the young Tübingen philosopher as the "mature formula of the freedom he first tasted" — a deliberate forward-echo, marked in the quote_source.
- **The Tree of Liberty** (1793-07-14) is marked `traditional`: scholars doubt the literal event, but the tradition tells it, so in this register it happens — with the doubt folded honestly into the campa.
- **Dresden** (Romantics' meeting) marked `traditional`; the exact 1798 encounter is loosely dated but the milieu is real.
- Coordinates are the actual towns (Leonberg, Nürtingen, Bebenhausen, Tübingen, Leipzig, Dresden, Weimar, Jena, Bamberg, Bad Bocklet, Murrhardt, Würzburg, Munich, Maulbronn, Stuttgart, Erlangen, Berlin, Bad Ragaz).

## The tradition's own folds and gaps
- **The long silence** (1809–1841): after the Freedom essay he published almost nothing for a third of a century. The *Ages of the World* is the great unfinished ruin — printed and suppressed in draft after draft. The atlas marks the silence as its own segment; the gap is the story.
- **The Auguste scandal**: the whisper that Schelling's medical meddling killed Caroline's daughter is a documented calumny; rendered as the lie that wounds, not endorsed.

## The five richest episodes
1. **The attic room at Tübingen** — Schelling, Hegel, Hölderlin in one cell; the German dawn kindled among three students.
2. **The Tree of Liberty** — the three plant and dance around the freedom-tree, swearing eternal fidelity; the vow beneath the whole age.
3. **Goethe blesses the Naturphilosophie** — the poet-minister reads *Von der Weltseele*, recognizes his own vision of living nature, and summons the boy to Jena.
4. **Bocklet / Maulbronn** — the twin deaths (Auguste 1800, Caroline 1809) that baptize and then end the great love; the reality that darkens the Freedom essay.
5. **Berlin, against the dead Hegel's shadow** — the old man set in Hegel's chair before Kierkegaard, Engels, Bakunin; the last stand of idealism, ending in Engels' pamphlet and wounded silence.

## Connection to the atlas
Schelling is a hinge. His **Naturphilosophie** faces **Goethe** (whose blessing he receives — the two journeys touch at Weimar/Jena) and **Steiner** (whose anthroposophy descends from this "nature as visible spirit"). His **Tübingen** faces the German dawn shared with the Hölderlin/Hegel constellation. He belongs with the atlas's other **thinker-journeys** (Jung, Gurdjieff, Keyserling) as a life whose true itinerary is the movement of its ideas — the stops are the works, the geography is the biography of a spirit.

---

## Verification (2026-07-05)

Independent structural and canon-fidelity pass. **Verdict: PASS — no repairs required.** The register was held throughout; no myth was debunked, no fold flattened or removed.

**(1) Structure / schema.** JSON parses (`python3 json.load`). Stop-level keys are byte-identical to the sibling `joan_of_arc.journey.json` — all 10 required keys (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`) present on every one of the 30 stops, no missing and no extra keys. Top-level keys (`traveler, title, years, calendar, register, segments`) match the sibling. 8 segments, 30 stops.

**(2) Chronology & confidences.** Dates are chronologically ordered within every segment **and** globally across all 30 stops (verified numerically). A death-terminated journey is correct here: Schelling died 1854 and is not a living person, so ending at the grave is right (no present-day tail owed). Confidences are honest: documented dates carry `attested` (birth 1775-01-27; Stift 1790-10-18; Jena professorship 1798-10; Auguste's death 1800-07-12; Caroline's death 1809-09-07; Freedom essay 1809; Berlin inaugural 1841-11-15; death 1854-08-20), the two schoolboy datings carry `inferred`, and the mythic folds (Tree of Liberty 1793-07-14; Dresden Romantics 1798) carry `traditional`.

**(3) Coordinates — 10+ spot-checked, all correct.** Leonberg (48.799/9.016 vs 48.800/9.017), Nürtingen (48.626/9.343 vs 48.627/9.337), Bamberg (49.892/10.887 vs 49.899/10.901), Bad Bocklet (50.283/10.083 vs 50.267/10.079), Maulbronn (48.997/8.813 vs 48.999/8.804), Murrhardt (48.981/9.582 vs 48.980/9.580), Erlangen (49.598/11.004 vs 49.591/11.008), Bad Ragaz (47.005/9.503 vs 47.003/9.501), plus Tübingen and Bebenhausen (48.560/9.055, correctly just north of Tübingen at the abbey). All within town-centre tolerance; nothing off.

**(4) Quotes — all 5 verified against canon** (the dataset carries 5, not 6; all checked). *Wollen ist Ursein* / "Willing is primordial being" — confirmed, Freiheitsschrift 1809. "God is Life, and not merely Being" — confirmed, Freiheitsschrift (canonical "God is a life, not merely a being"; faithful variant). "History as a whole is a progressive, gradually self-disclosing revelation of the Absolute" — confirmed verbatim, System of Transcendental Idealism 1800. "Nature should be spirit made visible, spirit invisible nature" — confirmed, Ideas 1797 Introduction (canonical "Nature is visible Spirit; Spirit is invisible Nature"; faithful translation variant, flagged in-source). Kierkegaard's "child of thought leaped for joy... as in Elizabeth" at the word *actuality* — confirmed, Berlin journal Nov 1841. No quote nulled; none needed restoring.

**(5) Campa.** All 30 in present tense and in register; word counts 74–95 (target 60–110), none out of range. The great episodes (attic room, Tree of Liberty, Goethe's blessing, the twin deaths at Bocklet and Maulbronn, Berlin against Hegel's shadow) carry full weight — none flat.

**(6) Stop count.** 30, at the floor of the 30–45 target; the canon is well-covered leg by leg, so no forced additions. Left in place.
