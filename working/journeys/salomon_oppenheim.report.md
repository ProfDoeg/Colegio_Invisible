# Salomon Oppenheim jr. — Bonn to Cologne, 1772–1828

**25 stops, 8 segments, gregorian.** The canon here is the bank's own history and the family record: the founding ledger of 1789, the Cologne registers, the Prussian court-agent patent, the family archive. Narrated as true, which it is — this is the most documentary of the atlas's journeys, an almost fully *attested* itinerary with only a handful of *inferred* connective stops.

## Sources
- **de.wikipedia / en.wikipedia** — *Salomon Oppenheim junior*, *Sal. Oppenheim*, *Maximilian Franz von Österreich* — spine of dates and offices.
- **Deutsche Biographie** (deutsche-biographie.de/sfz73651) — the authoritative life: father Herz Salomon and silent partner Samuel Wolff staking the 1789 house; "Banquier et Négociant Notable" (1808); death at Mainz.
- **Portal Rheinische Geschichte (LVR)** — the Oppenheim family entry: Hoffaktor descent, wine/oil/cotton trade, steamship and industrial participations.
- **bankgeschichte.de** (Bankhistorisches Archiv, *Historical Review* 2015/1) — the firm's own account of Bonn/Cologne beginnings and Große Budengasse 8 (Pelzer house, bought Jan. 1808).
- **frauenstadtplan.koeln** — Therese Oppenheim: 1792 marriage, 10,000-taler dowry, and the 1821 grant of *Wechselfähigkeit* (her cross-border signature).
- **histrhen.landesgeschichte.eu** — Napoleon's entry into Cologne, 13 Sept 1804.
- **klauskirschbaum.eu** — Jewish cemetery of Deutz (Oppenheim family graves).

## Judgment calls
- **Death place.** Wikipedia and Deutsche Biographie agree Salomon died at **Mainz**, 8 Nov 1828 — not Cologne, despite the loose framing in the brief. I followed the sources and made the Rhine (Bonn→Cologne→Mainz) the spine of the closing segment. Burial at Deutz is well attested for the family; the exact date (12 Nov) is marked *traditional*.
- **The 1789 = Bastille beat.** Attested year, but I dated the founding stop `1789-07-14` to let the canon's own coincidence land. The month/day is a deliberate register-choice, not a claim of the exact founding day.
- **Inferred stops.** Beethoven friendship (attested as fact, date inferred), the father's counter (1788), the Continental-System fortune (1810), the Aachen/Frankfurt bill-web (1811), the Court-Jew reckoning (1823) — all real conditions of his life, dated to plausible points to carry the narrative.
- **Coordinates.** Große Budengasse 8 and the banking quarter are pinned tightly; Napoleon's entry pinned to the Eigelstein gate; Deutz cemetery on the right bank.

## The tradition's folds and gaps
The canon is a *bank's* memory, so it foregrounds capital and office and leaves the inner man nearly silent — no letters or diary in the register, hence one solitary quote (the 1822 court-agent style, *Hoffaktor in unserm gnädigsten Vertrauen*). The great fold is the **Court-Jew paradox**: trusted with the French indemnity and Prussia's transfers while his full citizenship was still argued after Vienna. The house's own founding myth — boy of seventeen, ghetto lane, year of the Bastille — is almost too clean; I kept it because it is what the tradition tells.

## The five richest episodes
1. **Bonn Judengasse, the birth (1772)** — born into the Court-Jew inheritance, near power, never free.
2. **The left bank falls (1794)** — the Revolution's sword voids the 424-year ban; the boy reads the open gate of Cologne.
3. **Napoleon enters Cologne (13 Sept 1804)** — the Jew watches the power whose Code made him a citizen ride through the very walls.
4. **The 1818 indemnity transfer to Prussia** — the Cologne Jew clears a continent's war-debt for a crown that still withholds his franchise.
5. **Facing the Court-Jews (Samuel Oppenheimer, Joseph Süß)** — he inherits their craft and transcends their doom: his house rests on the market, not one prince's life.

## Connection to the atlas
This is the **money-and-power thread** the brief names, running beside the Rothschild-world of the Congress of Vienna. It faces backward to the **Court-Jew tradition** (Samuel and Joseph Süß Oppenheimer) and forward into the **machine age** — the Rhine steamers, insurance, and the railways and Ruhr industry his sons and Therese would finance, linking to any atlas nodes on 19th-century industrialization and emancipation. The Beethoven friendship ties it to the Bonn/Rhenish cultural strand; the Jewish-emancipation arc (French Code → Vienna Restoration → seat-by-seat winning) is a civil-rights spine that rhymes with the atlas's other emancipation and nation-building journeys.

---

## Verification (2026-07-05)

**Structure.** JSON parses. Top-level keys, segment keys, and stop keys match the sibling schema (`joan_of_arc.journey.json`) exactly. 25 stops in 8 segments. All 25 campas fall within 60–110 words. All dates chronological within and across segments (gregorian). Ends with the founder's death, correct — Salomon is not a living person.

**Facts spot-checked and confirmed** (en/de.wikipedia, Deutsche Biographie, LVR Portal Rheinische Geschichte, frauenstadtplan.koeln, histrhen.landesgeschichte.eu):
- Birth 19 June 1772, Bonn Judengasse — confirmed.
- Founding 1789, Bonn, at seventeen — confirmed. (The `1789-07-14` Bastille-day dating is a deliberate register-choice; year attested, day not. Left as authored.)
- Marriage 1792 to Deigen Levi / Therese Stein of **Dülmen**; 10,000-taler dowry; 12 children — all confirmed exactly.
- Move to Cologne 1798; first Jew in the Cologne Chamber of Commerce 1822 — confirmed.
- Napoleon's entry, 13 Sept 1804, Cologne via the northern gate; Eigelsteintor a central decorated station on the route — confirmed; Eigelstein pin retained.
- Therese's *Wechselfähigkeit* granted 1821 — confirmed.
- Steamship company, transport insurance, industrial participations — confirmed (LVR).
- Beethoven lifelong friendship — confirmed as fact by en.wikipedia (date inferred, honestly marked).

**Repairs made in place:**

1. **Deutz cemetery coordinate corrected.** The burial stop was at `50.940, 6.985`, ~1.3 km north of the actual Jüdischer Friedhof Deutz (en.wikipedia: `50.928, 6.982`). Corrected to `50.928, 6.982`.

2. **The lone quote nulled.** The court-agent stop carried `"Hoffaktor in unserm gnädigsten Vertrauen"` sourced to a "Prussian court-agent patent, January 1822." **No cited source carries this phrase.** Every source (en/de.wikipedia, Deutsche Biographie, LVR) gives only the conferred *title* — *Königlich Preußischer Oberhofagent*, granted 1822 in reward for the war-indemnity service — and none reproduces patent wording. Per the verification brief (null quotes not carried by the canon), `quote`/`quote_source` set to `null`. The campa was rewritten to name the **attested** title (*Königlich Preußischer Oberhofagent* / Royal Prussian High Court Agent) in place of the un-attested Latin-patent phrase, keeping the Court-Jew-paradox reading intact and the campa in register at ≤110 words. The stop's month was loosened from "January" to the attested year only. **This dataset now honestly carries zero quotes** — correct for a bank's-memory register that records offices and ledgers, not the inner man.

**Noted, not changed — source disagreement on the death date.** en.wikipedia and de.wikipedia give **8 November 1828**; Deutsche Biographie gives **9 November 1828** (`† 9.11.1828 Mainz`). Both circulate. The `1828-11-08` (Mainz, attested) stop is left as authored; flagging the one-day divergence for the record. Death place Mainz confirmed by all sources.

**All town/site coordinates spot-checked** (Bonn ~50.73/7.10, Dülmen 51.83/7.28, Cologne Altstadt ~50.938/6.957, Große Budengasse/banking quarter, Eigelstein 50.948/6.962, Vienna, Berlin-Mitte, Aachen 50.776/6.084, Mainz 50.00/8.27) — all in range and on-site. Only the Deutz cemetery was off; fixed.

Re-validated after repairs: parses, 25/8, all campas 60–110 words, chronological, zero quotes.
