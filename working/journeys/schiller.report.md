# Schiller — Marbach to Weimar: research report

**Traveler:** Friedrich Schiller (1759–1805). **Shape:** 8 segments, 33 stops, 17 quotes, gregorian. **Register:** national mythology — the canon (plays, poems, letters, the biography) narrated as true; the deserter-poet's flight, the friendship, the death and the skull placed and dated as events.

## Sources
Primary canon quoted directly: *Die Räuber* ("In tyrannos!"), *Don Karlos* ("Geben Sie Gedankenfreiheit"), *An die Freude*, *Der Taucher*, *Maria Stuart*, *Die Jungfrau von Orleans* ("Kurz ist der Schmerz, und ewig ist die Freude"), *Wilhelm Tell* (the Rütli oath), the Jena inaugural-lecture title, the Schiller–Goethe *Briefwechsel*, Goethe's *Glückliches Ereignis* ("Das ist keine Erfahrung, das ist eine Idee"), his *Epilog zu Schillers Glocke* ("Er war unser"), and *Bei Betrachtung von Schillers Schädel*. Biographical anchors from the Schillerverein Weimar-Jena, the Marbach Schillerverein / DLA Marbach, schiller-biografie.de, friedrich-schiller-archiv.de, Klassik Stiftung Weimar (Adelsdiplom; skull exhibition), the German/English Wikipedia lives and the dedicated *Friedrich Schiller's skull* article, plus Carlyle's 1825 *Life* for the Lorch/Ludwigsburg boyhood. Dates cross-checked against the Reclam "Goethe und Schiller 1794–1805 Daten."

## Judgment calls
- **Coordinates.** Solitude (48.786, 9.084), Gohlis Schillerhaus, Loschwitz, Marbach, Mannheim Nationaltheater, Jena, Weimar, Rudolstadt, Bauerbach, Oggersheim and Ludwigsburg placed on their attested sites; Weimar's several stops nudged to distinct points (Wohnhaus, Hoftheater, Frauenplan, Kassengewölbe on the Jakobsfriedhof, Fürstengruft) so the classical decade doesn't collapse to one dot.
- **"Immer besser"** and **"Der Herzog will nicht, dass ich schreibe"** are traditional/attributed rather than firmly documented — flagged in quote_source, kept because they are canonical to the legend.
- **The Joan stop** (*Die Jungfrau von Orleans*, Leipzig premiere, marked attested) deliberately narrates Schiller's *departure from history* — Johanna dying transfigured on the battlefield, not at the stake — which is the point where his Joan **faces our Joan of Arc journey**: same maid, two deaths, the poet's ideal against the trial record's fire.
- Lorch date inferred (family posted 1764); all major Weimar/Jena premieres and the ennoblement are attested to the day.

## Folds and gaps in the tradition
The body itself is the great gap: no one knows where Schiller's bones are. The 1826 skull chosen by Mayor Schwabe, cradled by Goethe, enshrined in the Fürstengruft and elegized in verse, was disproved by DNA in 2008 — the coffin now stands empty. The tradition keeps two poets side by side in the crypt while conceding one of them isn't there. I let both truths stand in the final campa, as the register demands: the relic is honored *and* the emptiness is stated.

## The five richest episodes
1. **Mannheim, 13 Jan 1782** — the *Räuber* premiere as a "madhouse," fame in one night for a man still legally the Duke's surgeon.
2. **The night flight, 22 Sept 1782** — the deserter-poet slipping the gate under cover of the Duke's fireworks with Streicher.
3. **Gohlis, summer 1785** — *An die Freude* written out of rescued happiness among Körner's friends; the seed of Beethoven's Ninth.
4. **Jena, 20 July 1794** — the "happy event": "That is no experience, that is an idea," the friendship of German letters born on a walk home.
5. **Weimar, 24 Sept 1826** — Goethe holding the skull, writing the poem, "Wie bin ich wert, dich in der Hand zu halten" — and the later proof it was the wrong skull.

## How it connects to the atlas
This journey **faces Goethe entire**: the Weimar and Jena stops, the *Briefwechsel*, the Xenien and the Balladenjahr are written to interlock with a Goethe itinerary (the Frauenplan, the metamorphosis-of-plants lecture, the shared Hoftheater, the twin sarcophagi). It **faces the Joan of Arc journey** at the Domrémy-to-Rheims arc that Schiller re-poeticized. As a German-classical, TB-shadowed artist's life it sits beside the atlas's other 18th–19th-century culture-founders — Froebel, Pestalozzi, Steiner, Reich — and, through the freedom-and-tyranny nerve of *Die Räuber*, *Tell* and *Don Karlos*, it rhymes with the liberator journeys (Bolívar, San Martín, Belgrano, Miranda) that the collection already holds.

---

## Verification pass (2026-07-05)

**Verdict: PASS with two coordinate fixes applied in place.** JSON re-validated after edits.

**(1) Schema & parse.** `json.load` succeeds. Top-level keys (`traveler, title, years, calendar, register, segments`) are identical to the `joan_of_arc.journey.json` sibling. Every stop carries exactly the sibling's ten keys (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`) — no drift, no extra/missing fields. Shape: **8 segments, 33 stops, 17 quotes**, matching the researcher's summary.

**(2) Chronology & confidences.** All 33 dates sort in strict non-decreasing order (checked programmatically); no inversions. Julian-BCE ordering is N/A (gregorian, all CE). Confidences are honest: only **Lorch (1764) is `inferred`** (family posting, no day-record); every other stop is `attested` and the day-dated premieres/ennoblement/death check out. Traveler is **not living** (d. 1805), so the "living person ends at the present" rule does not apply — ending at the 1826 skull episode is correct, and the register's demand (relic honored *and* 2008 DNA disproof / empty coffin stated) is met in the final campa.

**(3) Coordinates — spot-checked 10 stops against attested sites:**
- Marbach Geburtshaus (Niklastorstr.), Schloss Solitude (48.786, 9.084), Gohlis Schillerhaus (Menckestr. 42), Bauerbach, Loschwitz Schillerhäuschen, Rudolstadt, Wenigenjena/Schillerkirche (50.9323, 11.6005), Schillers Wohnhaus Weimar (50.9789, 11.3278) — all within tolerance (≤~150 m).
- **FIXED — Kassengewölbe / Jakobsfriedhof stop:** was `50.9840, 11.3390` (~780 m E of the vault); corrected to **`50.9833, 11.3278`** (Jakobskirchhof, per Klassik Stiftung / de.wikipedia).
- **FIXED — Fürstengruft stop:** was `50.9770, 11.3260` (~490 m N); corrected to **`50.9726, 11.3257`** (Historischer Friedhof, per Klassik Stiftung).

**(4) Quotes — spot-checked 6 against the canon, all carried faithfully:**
- *Wilhelm Tell* Rütli oath "Wir wollen sein ein einzig Volk von Brüdern, / In keiner Not uns trennen und Gefahr" — exact, correctly cited II.2.
- *Die Jungfrau von Orleans* "Kurz ist der Schmerz, und ewig ist die Freude!" — exact, Johanna's closing line.
- *Wallenstein* Prolog "Ernst ist das Leben, heiter ist die Kunst." — exact.
- Goethe, "Das ist keine Erfahrung, das ist eine Idee." and *Epilog zu Schillers Glocke* "Er war unser." — canonical, correctly attributed.
- **Note (kept, not changed):** *An die Freude* is quoted in Schiller's **1803 collected-poems wording** ("Was die Mode streng geteilt"), not the 1785/86 *Thalia* first printing ("Was der Mode Schwert geteilt"). This is Schiller's own later authorized text and the line Beethoven set — a legitimate canon reading, not a paraphrase, so it stands.
- The two attributed lines ("Immer besser"; "Der Herzog will nicht, dass ich schreibe") are honestly flagged as traditional in `quote_source`.

**(5) Campa.** All 33 campa fall within **71–109 words** (target 60–110), present tense throughout, register held; the great episodes (Mannheim madhouse, the night flight, Gohlis/*An die Freude*, the "happy event," the skull) are not flat.

**(6) Stop count.** 33 stops sits inside the 30–45 target; the canon is fully covered across the eight named segments. **No stops added.**

**Not yet added to `index.json`.**
