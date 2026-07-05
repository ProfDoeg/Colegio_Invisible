# Guido Keller — the Eagle of Fiume: research report

**Journey:** Milan to the roadside, 1892–1929 (gregorian). 27 stops in 9 segments.
**Register:** the Fiume chronicles, the Enciclopedia Dannunziana, and the biographies narrated as true; deeds, gestures and eccentricities placed and dated as events.

## Sources
- **Wikipedia, "Guido Keller"** (EN) — spine of the chronology: WWI squadrons (73ª, 80ª, 91ª under Baracca), the three Silver Medals, Fiume roles, the Rome flight, post-Fiume wanderings (Turkey, Berlin, Libya, Amazon/Peru, Ostia), and the death near Magliano Sabina with Vittorio Montiglio.
- **Enciclopedia Dannunziana (Vittoriale), "Keller, Guido"** — segretario d'azione, Ufficio Colpi di Mano, Yoga journal (Nov 1920), the Yoga quote ("un italiano, indicibilmente italiano…"), and D'Annunzio's remembrance ("uno dei pochissimi che hanno saputo amarmi come io voglio essere amato").
- **Nazione Futura** and **passaggilenti.com** — the 14 Nov 1920 flight: the three targets, and the exact chamber-pot message ("…la tangibilità allegorica del Loro Valore. Roma, 14 del terzo mese della Reggenza").
- **il Giornale ("il folle volo dell'aquila")** and **italoeuropeo.com ("L'Uscocco fiumano")** — the eagle named Guido, the tree-house, nakedness, cocaine, the "casa di Diogene," the pig-through-the-fuselage.
- **Cefalunews / it.wikipedia "Impresa di Fiume"** — the Uscocchi raids: the *Cogne* (diverted from Catania, 5 Sep 1919) and the *Persia* (10 Oct 1919, off Lussinpiccolo, 13,000 tons), Ronchi, Natale di sangue.

## Judgment calls
- **Birth year 1892.** One source (italoeuropeo) gives 1882; Wikipedia, the Vittoriale encyclopedia and the biographies agree on **6 February 1892** (dead at 37 in 1929 confirms it). Used 1892.
- **Rome-flight dedications** as short attested quotes ("A frate Francesco"; "Alla regina e al popolo d'Italia") — sources render the roses' dedications in these words; treated as quoted gestures, not invented. Sources split on white vs. red roses over the Vatican; followed the majority (white rose for Francesco, seven red for the Quirinale).
- **The *Cogne* / *Persia* dates and the pig anecdote** are attributed to the Uscocchi office Keller directed; the pig is marked *traditional* (a well-worn legend, not a documented log). Coordinates for Fiume harbour/airfield are approximate points within Rijeka.
- **Swastika-as-solar-sign** in the Yoga stop is stated descriptively (an esoteric/naturist emblem of 1920), per the register's rule for esoteric material — described, not endorsed, and pre-dating its later appropriation.
- Left the ideology of his brief fascist phase flat and factual: the movement distrusted him and he it.

## The tradition's folds and gaps
Keller wrote almost nothing himself; his "canon" is other men's memory — Comisso's *Il porto dell'amore*, the Yoga journal, D'Annunzio's asides, and a cluster of modern Italian biographies (Gnocchi, Cucciolla) that lovingly re-tell the same anecdotes. So the record is thick on gesture and thin on documentation: the pig, the eagle, the tree are repeated everywhere but sourced nowhere primary. The post-Fiume years (Turkey airline, Berlin, Libya, Amazon, Peru) are compressed and loosely dated across sources; I placed them in plausible order (1922–1928) and marked them *attested* only where Wikipedia is explicit.

## The five richest episodes
1. **The chamber-pot on Montecitorio (14 Nov 1920)** — the signature gesture; the full Italian message survives verbatim.
2. **The white rose for Frate Francesco over the Vatican** — the same flight's tender opposite; love to the saint of poverty, merde to the state.
3. **The Persia seizure off Lussinpiccolo** — 13,000 tons turned to feed the blockaded city; piracy as statecraft.
4. **The tree-house, the eagle named Guido, the naked yogi** — the "casa di Diogene," Vedanta and cocaine, D'Annunzio kidnapping the eagle.
5. **Burial on the Colle delle Arche** with D'Annunzio's line about being loved as he wished to be loved — the whole friendship in one sentence.

## Connections to the atlas
This journey **faces D'Annunzio** directly: Keller is the wildest cell inside the dannunzio.journey — Ronchi, the Santa Entrata, the Carta del Carnaro, the Natale di sangue, and the shared tomb at **Il Vittoriale** are the exact hinge points, seen from the Segretario d'Azione's side. It faces **Laban** and the **Monte Verità** free spirits through the naturist/esoteric strand (nakedness, sun, the Yoga union of "spiriti liberi tendenti alla perfezione") and through the age's cult of the aviator-poet. Baracca's squadron ties it to the WWI-ace mythos. And its ending joins the atlas's recurring **death-by-crash** motif — the seeker stopped on the roadside (the report flags Keller as sharing this fate with the atlas's other crashed wanderers).

## Verification pass (2026-07-05)

Structure/canon-fidelity audit against the sibling schema (`joan_of_arc.journey.json`) and the sources. Register preserved throughout — nothing debunked; the pig, the eagle, the naked yogi, the whole Rome flight stand, marked by confidence not removed.

**Schema & structure.** JSON parses. Top-level, segment, and stop keys are byte-identical to the Joan sibling (`traveler, title, years, calendar, register, segments`; segment `name/stops`; stop `name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`). 27 stops in 9 segments — within the 20–35 target, so no stops added; the canon offers little beyond what is already placed.

**Campa.** All 27 present-tense entries fall in 60–110 words (range 83–98). The great episodes (chamber-pot, white rose, Persia, tree-house, Vittoriale burial) are not flat.

**Confidences.** Honest: the documented anchors are `attested`; the two undated legends (pig, tree-house/naked-yogi) are `traditional`; Fiesole is `inferred`. The loosely-dated post-Fiume years use first-of-period placeholder dates but are transparently flagged in the original judgment-calls section; left as-is. Keller is not living, so ending at the 1929 death/burial is correct.

**Coordinates.** Web-spot-checked 13 stops against the actual/traditional sites; all within tolerance. Exact or near-exact: Vatican/St Peter's (41.9022/12.4539), Montecitorio (41.9008/12.4787), Quirinale, San Marino city, Benghazi (32.1167/20.0667), Lussinpiccolo/Mali Lošinj (44.533/14.467), Vittoriale (45.624/10.565), Ronchi (45.827/13.502), Fiesole, Magliano Sabina, Ostia, Milan. Loosest: Cameri (town 45.503 vs airbase 45.530) and Godega di Sant'Urbano (45.964 vs ~45.931, ~4 km) — both acceptable as commune-level points; not changed.

**Quotes (7).** All spot-checked and sound. The Montecitorio chamber-pot message, the Vatican `A frate Francesco`, the Quirinale `Alla regina e al popolo d'Italia`, the Yoga journal line (`È...un italiano, indicibilmente italiano: è un irregolare, è un eretico, tutto volitivo`), and D'Annunzio's remembrance (`uno dei pochissimi che hanno saputo amarmi come io voglio essere amato`) all match the canon verbatim. The earlier white-vs-red-rose ambiguity over the Vatican is **resolved in favour of the white rose** by the Enciclopedia Dannunziana / Nazione Futura primary text (white to Francesco, red to the Quirinale) — the journey was already correct.

**Repair made in place — the one real defect: the *Cogne* seizure.** As written the steamship *Cogne* was dated **1919-09-05** and placed as the *founding* Uscocchi coup, *before* the *Persia*. This is doubly wrong: (a) 5 Sept 1919 is *before* the Santa Entrata (12 Sept 1919), so there was no Fiume to raid for yet; (b) the sources are unanimous that the *Persia* was the **first** ship taken (10 Oct 1919, off Lussino) and the *Cogne* was diverted from Catania (under Romano Manzutto, with six others) **in October 1920** — a year later. Fixes:
- *Cogne* re-dated to **1920-10-01**, campa corrected ("In October 1920... under Romano Manzutto... the great Ansaldo steamer Cogne — bound for Argentina with a cargo worth two hundred millions"); reordered to follow the *Persia* within the Uscocchi segment.
- "Founding coup of the Ufficio" moved from the *Cogne* to the *Persia*, where it belongs.
- To keep the flat sequence strictly monotonic across the thematic segments, the two undated `traditional` stops were re-anchored within 1920: the pig to **1920-01-01** (before the Cogne), the tree-house/naked-yogi to **1920-10-15** (after the Cogne, before the Yoga founding of Nov 1920) — both defensible, since these legends carry no firm date and describe the whole span of the occupation.

Re-validated with Python after repair: JSON parses; **0 out-of-order dates**; all campa still 60–110 words; schema unchanged. Sources consulted for the fix: loccidentale.it "Quando la pirateria era made in Italy", ANVGD "Gli Uscocchi", cefalunews, en.wikipedia "Guido Keller", nazionefuturarivista, enciclopediadannunziana.
