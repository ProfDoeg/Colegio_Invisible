# Goethe — The Whole Life (1749–1832): Journey Report

**Traveler:** Johann Wolfgang von Goethe · **Span:** 1749–1832 (gregorian) · **Shape:** 9 segments, 56 stops, 38 quotes.
**File:** `goethe_full.journey.json`

## What this is
The entire arc, Frankfurt to Weimar, rendered in the same stop-by-stop mythic register as the Italian Journey sibling — but here the **Italian Journey is compressed to one movement of six stops among nine**, present as the pivot (the "rebirth") rather than the whole. The register treats the canon — *Dichtung und Wahrheit*, the letters and diaries, the works themselves, and Eckermann's *Conversations* — as true and narrates the life's turning-points (the Lisbon question, Herder opening the eyes, the *Urpflanze* seen in Palermo, Valmy's prophecy, "Mehr Licht") as events to be placed and dated.

## Sources
- **Autobiography:** *Aus meinem Leben. Dichtung und Wahrheit* (Gutenberg 5733 / archive.org), covering childhood to 1775; *Italienische Reise* (Gutenberg 2404); *Campagne in Frankreich 1792*.
- **Reference:** English & German Wikipedia (Goethe, Christiane Vulpius, August von Goethe, Friederike Brion, Marianne von Willemer, Ulrike von Levetzow, West-östlicher Divan, Faust Part Two, Susanne von Klettenberg); IEP (iep.utm.edu/goethe); Britannica (Italian journey, Last years); 1911 & 9th-ed. Encyclopaedia Britannica (Wikisource).
- **Specialist:** Casa di Goethe / Palermo botanical-garden pages (Urpflanze, 17 Apr 1787); CHNM *Liberty, Equality, Fraternity* and frenchquest.com (Valmy quote); Zapperi, *To die in Rome* (studigermanici.it, on August's death); Freies Deutsches Hochstift Goethe-Haus guide (puppet theatre); Clemson Humanities Hub (Lisbon 1755).

## Judgment calls
- **Quotes are given in Goethe's German** where the canon records them, with source line noted; kept `null` (18 stops) wherever no exact wording survives for that scene — e.g. Frankfurt puppet-theatre, the Vesuvius ascent, the son's birth, Karl August's death.
- **"Mehr Licht"** is flagged in-text as *traditional*: it is the received last word (a request to open the shutter for more light), and I narrate it as such rather than as forensic transcript.
- **The Valmy sentence** and the **Mainz "injustice rather than disorder"** are both things Goethe set down (or that were set down of him) years after; marked attested/attributed and dated to the event, per the register.
- **Dates:** birthdays, publications, arrivals and deaths are *attested*; compositional "seasons" (the great hymns 1774, granite/Urfaust 1785, ballad year 1797, Tiefurt court) are *traditional* and pinned to a representative date so segment chronology stays monotonic.
- **Coordinates** are the real sites: the Hirschgraben house, Auerbachs Keller, the Straßburg Münster, Sesenheim parsonage, Gickelhahn hut above Ilmenau, Casa di Goethe on the Corso, the Vesuvius crater, the Orto Botanico di Palermo, the Valmy windmill, Marienbad, the Frauenplan.

## Folds and gaps in the tradition
- *Dichtung und Wahrheit* only runs to 1775 (the departure for Weimar); everything after is reconstructed from letters, diaries, the *Tag- und Jahreshefte*, and Eckermann — a deliberate seam in Goethe's own self-narration, so the later stops lean more on scholarship than on autobiography.
- The Weimar decade (1775–86) is thin in *dramatic* events and thick in administration; I let the science (intermaxillary bone, granite) and Charlotte von Stein carry it, as the canon does.
- Friederike Brion and Lili Schönemann are told as Goethe told them — through the songs and through his own confessed guilt — since their side is largely lost.

## The five richest episodes
1. **Rome, "the second birthday"** (29 Oct 1786) — the incognito flight resolves into the explicit rebirth, the hinge of the whole life.
2. **Palermo, the Urpflanze** (17 Apr 1787) — poetry and morphology fuse; "everything is leaf," the archetype from which he could invent plants to infinity.
3. **Valmy, the new epoch** (20 Sep 1792) — the poet on the battlefield speaking history's turn.
4. **Jena, the meeting with Schiller** (20 Jul 1794) — "that is no observation, that is an idea": the birth of Weimar Classicism from a dispute over the archetypal plant.
5. **Marienbad → the death** (1823 / 22 Mar 1832) — the last helpless love and the *Elegy* of renunciation, closing into the sealed *Faust II* and "Mehr Licht."

## How it connects to the atlas
This journey is a **sun the corpus orbits**. It faces the already-inscribed **Italian Journey** quipu directly (same traveler, nested movement) and the **Barbier** journey (Mignon's *Kennst du das Land* → Thomas's opera). It faces **Fichte** and **Keyserling** (Jena/Weimar idealism and the German inward turn), and its *Urpflanze*/*Farbenlehre* morphology faces the atlas's **Steiner/anthroposophy** threads (Goethean science). Through the **Napoleon** audience at Erfurt and the **Valmy/Mainz** stops it touches the Revolutionary-era journeys (d'Annunzio, and the French-Revolution roster generally). It is a natural anchor for any German-Romantic, Weimar-Classical, or world-literature (*Weltliteratur*) cluster in the atlas — the node most other 18th–19th-c. German souls will want to face.

## Verification (2026-07-05)

Verified for structure and canon-fidelity against the sibling `joan_of_arc.journey.json`. The myth is preserved throughout — the second-birthday at Rome, the Urpflanze seen whole in a Palermo garden, the Valmy prophecy, "Mehr Licht" all stand; folds are marked by confidence, not debunked.

**Structure — PASS.** JSON parses. Top-level keys identical to the Joan sibling (`calendar, register, segments, title, traveler, years`); every stop carries the exact 10-key shape (`campa, date, date_confidence, lat, lng, name, quote, quote_source, sources, suggested_refs`); segments carry `{name, stops}`. 9 segments, breakdown `[6,4,7,7,9,5,5,7,6]` = 56 stops.

**Chronology & confidence — PASS.** Dates monotonic within every segment. (Segments 5 "Revolution/war" 1788–97 and 6 "Schiller alliance" 1794–1805 overlap in wall-clock years by design — parallel thematic threads, as the Joan file also does; within-segment order is clean.) Confidences honest: births, publications, arrivals, deaths, the Napoleon audience = *attested*; compositional "seasons" pinned to representative dates (puppet-theatre 1753, the great hymns 1774, granite/Urfaust 1785, Tiefurt 1776, Faust resumed 1798) = *traditional*. Goethe is dead; the journey correctly ends at the death (22 Mar 1832), not the present.

**Coordinates — PASS (1 fix).** Web-spot-checked 14 stops: Frankfurt Goethe-Haus, Strasbourg Münster (48.5757, 7.7505), Sesenheim, Vesuvius crater (40.821, 14.426 — exact), Casa di Goethe / Rome, Palermo Orto Botanico (38.108, 13.370 — exact), Valmy windmill (49.074, 4.759), Assisi Temple of Minerva (43.071, 12.615 — precise to the temple), Marienbad (49.965, 12.701 — exact), Erfurt (50.979, 11.033), Ilmenau/Kickelhahn, Heidelberg. All on-site or within village tolerance except:
- **Rome — the death of the son August (1830):** was `41.902, 12.474`, ~2.9 km north of the actual burial ground. **Fixed to `41.876, 12.480`** — the Cimitero Acattolico (Protestant Cemetery) by the Pyramid of Cestius, where August lies near Keats and Shelley, as the campa and suggested_refs state.

**Quotes — 2 fixes.** Spot-checked 6 against the canon. Verified exact and carried: *Prometheus* ("Hier sitz ich, forme Menschen / Nach meinem Bilde…"); the Valmy sentence ("Von hier und heute geht eine neue Epoche der Weltgeschichte aus…", correctly sourced to *Campagne in Frankreich*, written later); the *Marienbader Elegie* opening ("Mir ist das All, ich bin mir selbst verloren…"); *Der Zauberlehrling* ("Die ich rief, die Geister, / Werd ich nun nicht los"). Two did not survive:
- **Werther (1774):** the attributed line "Sie hatte einen Freund verloren, der ihr alles war… und doch war sie ruhig" is **not in the canonical text** of *Die Leiden des jungen Werthers* (nearest genuine passages read otherwise). Per the null-what-isn't-carried rule, **`quote` and `quote_source` set to null**; the campa stands on its own. (Quote count 38 → 37.)
- **Birth (D&W Book I):** the opening sentence was exact but the tail "The constellation was propitious" was a loose paraphrase. **Restored to the canon's wording:** "…I came into the world, at Frankfort-on-the-Main. My horoscope was propitious: the sun stood in the sign of the Virgin, and had culminated for the day."

**Campa register — PASS.** All 56 campa fall inside the target band (71–104 words; 60–110 required), present-tense, in the mythic-canon register. The great episodes (Rome rebirth, Palermo Urpflanze, Valmy, Schiller meeting, the death) are full-bodied, not flat.

**Stop count — no additions.** 56 stops sits within the 55–75 target; the nine segments already carry the life's turning-points densely, so no stops were added.

Re-validated with Python after the three repairs: parses, key-shape and chronology clean, word-counts in band. Net: coordinates 1 fix, quotes 2 fixes (1 nulled, 1 restored to canon), non-null quotes now 37.
