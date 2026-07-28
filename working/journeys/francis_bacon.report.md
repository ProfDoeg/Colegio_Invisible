# Francis Bacon — York House to Gorhambury: journey report

**Shape:** 42 stops in 9 named segments, julian calendar, register "national mythology — the canon is true." 1561–1626. Canon here = the documented biography (History of Parliament, Rawley's *Life*, Aubrey's *Brief Lives*, Bacon's own letters and works) plus the Rosicrucian/cipher/Shakespeare-authorship tradition attached to him after death, which is narrated as tradition (marked `date_confidence: "traditional"`), never debunked, per the curator's brief.

## Sources
- **Wikipedia, "Francis Bacon"** and **History of Parliament Online** — spine chronology: birth, Cambridge, Gray's Inn, offices, dates of creation as Baron Verulam and Viscount St Alban.
- **Stanford Encyclopedia of Philosophy, "Francis Bacon"** and **William Rawley, *Life of the Honourable Author* (1657)** — the Aristotle verdict, the "all knowledge to be my province" letter to Burghley (1592).
- **Spartacus Educational** and **Wikipedia, "Essex's Rebellion"** — the Essex years: Twickenham Park, the 1598 arrest for debt, the Rebellion, the trial, the execution, the *Apologie* (1604).
- **John Aubrey, *Brief Lives*** — the snow-and-hen experiment and death at Arundel House, Highgate, including Bacon's own last letter to Lord Arundel ("the fortune of Caius Plinius the elder...").
- **Herts Memories / National Portrait Gallery** — the seated monument and Latin epitaph at St Michael's Church, St Albans.
- **Wikipedia, "Salomon's House"** and **The Square Magazine** — *New Atlantis* (written c. 1624, published 1627) and its acknowledged descent into the Royal Society via Thomas Sprat's history.
- **Francis Bacon Society ("Bacon, Shakespeare, and the Rosicrucians")**, **sirbacon.org**, and academic PDFs on the biliteral cipher — the Fama/Confessio Fraternitatis tradition, the biliteral cipher (conceived Paris, published in full in *De Augmentis Scientiarum*, 1623), and the First Folio cipher-authorship tradition.
- **Wikipedia, "Novum Organum"** and **fs.blog** — the four Idols of the Mind and the *Plus Ultra* frontispiece of the *Instauratio Magna* (1620).

## Judgment calls
- **The Rosicrucian segment** ("The Hidden Work: the Fama and the Confessio") sits out of strict chronological sequence relative to its neighbors — its two stops (1614, 1615) precede the "Under the Seal" segment's 1616 opening stop, but that segment's own internal order is intact, matching the precedent set in `kircher.journey.json` ("segments are thematic, not strictly linear"). This keeps the hidden-authorship tradition as its own thread rather than forcing it into the public-office narrative.
- **Approximate dates** (`inferred`/`traditional`) are used wherever only a year or season is recorded: the Paris arrival's exact day, the cipher's conception (~1578), the 1592 Burghley letter's day, Twickenham Park's gift year, the 1598 arrest, Gorhambury retirement's exact start, the *New Atlantis* composition window, the snow experiment's date, and the burial date (death is firmly 9 April 1626; burial followed some days or weeks later per the era's practice, not recorded to the day).
- **The Shakespeare-authorship/cipher tradition** is rendered descriptively, as the brief instructs for an esotericist's attached mythos — narrated as a living tradition with real texts (the Fama, the Confessio, the First Folio) and real practitioners (Gallup, Bokenham, Hall), never asserted as settled fact and never mocked.
- **"Knowledge is power"** was deliberately left out as a direct quote — it is universally attributed to Bacon but is a later paraphrase/tag (*scientia potestas est*), not verbatim in his works; the actual, verifiable "all knowledge to be my province" line carries that idea instead.
- **The journey ends at burial**, not at the founding of the Royal Society (1660) — Bacon is dead in 1626, so per the schema's rule a dead traveler's journey ends at death/burial; the Royal Society's debt to *New Atlantis* is real and explicit (Thomas Sprat says so directly) but belongs in the connections note below, not as a dated stop decades after Bacon could experience it.

## Gaps and time-folds
- The Italy/Spain leg mentioned in some summaries of the 1576–79 Continental years is folded into the Paris/French-court segment — the Italian journey itself never happened; his father's death recalled him before he could make it past France, and that reversal (packed bags for Italy, ship home instead) is the point of the stop, not a gap to paper over.
- Alice Barnham's disinheritance and the full ugliness of the marriage's end are compressed into the marriage stop rather than given their own stop, to keep the segment's focus on the public offices building toward the Chancellorship.
- The biliteral cipher appears twice by design: conceived in Paris at seventeen (youth), then finally published with plates in *De Augmentis* (1623, Gorhambury) — the forty-five-year gap between invention and disclosure is itself part of the tradition's argument that Bacon habitually deferred revealing his methods.

## The five richest episodes
1. **The confession before the House of Lords** (1621) — "it is my act, my hand, and my heart... a broken reed" — the fastest, most complete fall of any Lord Chancellor in English history, three weeks after his highest title.
2. **The Novum Organum's frontispiece** (1620) — a ship passing the Pillars of Hercules under *Plus Ultra*, and the four Idols of the Mind — the keystone of the whole Instauration and the direct ancestor of the scientific method.
3. **New Atlantis and Salomon's House** (c. 1624) — the name-origin node for the entire Colegio Invisible: the fictional foundation that Thomas Sprat's own history of the Royal Society names as its acknowledged model, and thence the "invisible college," and thence this atlas's own name.
4. **The snow-stuffed hen at Highgate** (1626) — Pliny's fate chosen deliberately, in Bacon's own last letter, as the frame for his own death; the ghost said to haunt Pond Square ever after.
5. **The prosecution of Essex** (1601) — the friend who gave him Twickenham Park, argued into the grave by the man he made, a betrayal Bacon spent the rest of his life writing apologias against.

## Connections to the atlas
- **kircher.journey.json** — the direct sibling: both are universal-knowledge dreamers building "everything in one mind" (Kircher's Museum, Bacon's Salomon's House), both attach an afterlife of tradition and cipher-hunting to a documented career, both end at a death caused in part by their own restless experimentalism.
- **buckminster_fuller.journey.json** — the total-knowledge project's other bookend, four centuries downstream; Fuller's synergetics and comprehensive design science are the 20th-century face of Bacon's Instauration.
- **roger_bacon** and **giulio_camillo** — named as edges by the curator's brief; neither yet exists as a file in this directory. Roger Bacon (13th c. Franciscan empiricist, also mythologized around alchemy and a prophetic brazen head) and Giulio Camillo (the memory-theatre architect) are natural future nodes: Roger as the medieval namesake Francis is often confused with and implicitly answers, Camillo as another architect of a building meant to contain all knowledge, decades before Salomon's House.
- **The Royal Society** (not its own stop, per the "ends at death" rule) is the explicit forward edge: Thomas Sprat's official history credits Bacon by name as the society's true founder-in-spirit, closing the loop the curator's brief opened — New Atlantis → "invisible college" → Royal Society → Colegio Invisible.

---

## Verification pass, 2026-07-24

Independent structural and canon-fidelity check of `francis_bacon.journey.json`. Validated with `json_check.py` before and after repair: **exit 0, no WARN lines**, 9 segments / 42 stops / 7 quoted. Schema keys match `joan_of_arc.journey.json` exactly (top-level, segment, and all ten per-stop keys). Stop count 42 sits inside the 30-45 target, so no stops were added.

### Coordinates corrected (12 sites, 22 stops touched)

Web-spot-checked every distinct site. Twelve were off, several by a kilometre or more:

| Site | Was | Now | Error |
|---|---|---|---|
| Trinity College, Cambridge (2 stops) | 52.2043, 0.1149 | 52.2070, 0.1146 | ~300 m S, sat on King's College |
| Gray's Inn (4 stops) | 51.5225, -0.1132 | 51.5194, -0.1122 | ~370 m N, up Gray's Inn Road |
| York House, Strand (3 stops) | 51.5077, -0.1229 | 51.5081, -0.1233 | ~50 m |
| Twickenham Park | 51.4505, -0.3270 | 51.4550, -0.3200 | ~700 m, was central Twickenham |
| Arrest for debt | 51.5136, -0.0917 | 51.5163, -0.0893 | moved to Coleman Street, the sponging-house quarter |
| Essex House | 51.5117, -0.1113 | 51.5133, -0.1119 | ~200 m E, was at St Clement Danes |
| Westminster Hall (3 stops) | 51.4996, -0.1259 | 51.4999, -0.1254 | ~40 m |
| Marylebone Chapel | 51.5186, -0.1489 | 51.5228, -0.1513 | ~500 m; now on the actual second-church site |
| Old Gorhambury House (5 stops) | 51.7606, -0.3670 | 51.7569, -0.3933 | **~1.9 km E**, was in open farmland |
| St Michael's, St Albans | 51.7517, -0.3423 | 51.7527, -0.3569 | **~1.0 km E**, was near the Abbey, not St Michael's |
| Highgate, the hen | 51.5716, -0.1466 | 51.5713, -0.1470 | snapped to Pond Square, the ghost site |
| Arundel House, the death | 51.5716, -0.1466 | 51.5707, -0.1480 | separated from the hen stop; Old Hall site, South Grove |

Verified-correct and left alone: Paris, Poitiers, Palace of Westminster, Whitehall, Tower of London, Kassel, St Paul's Churchyard.

### Facts corrected

- **The wedding detail was inverted.** The campa had Alice Barnham "brought to church in a dress of purple and gold" with "a bishop's chaplain" joking she wore her portion on her back. The canon (Chamberlain's letter of May 1606) has **Bacon** clad from top to toe in purple, and the cloth of silver and gold he bought for them both drawing deep into *her* portion; the reporter is a court letter-writer, not a bishop's chaplain. Rewritten to the attested version, with her age (not yet fourteen) and the 1625 will's "leave her to her right only" restored.
- **"As King's Counsel, Bacon leads the prosecution of Somerset" (1616)** — he was **Attorney General** in 1616, not King's Counsel. Corrected.
- **"his father and grandfather kept chambers"** at Gray's Inn — only Sir Nicholas did; the grandfather was no lawyer. Corrected, with the *de societate magistrorum* admission formula restored.
- **The 1598 arrest** was dated `1598-09-01 / traditional`. The DNB gives **23 September**; upgraded to `1598-09-23 / attested`.
- **Twickenham Park "lease"** — the sources say the property passed to him and he later sold it for £1,800. "Lease" corrected to property; the £1,800 sale added.
- **Debts at death**: "£22,000 against assets of some £13,000." The assets figure is unsourced and sources conflict on the debt (£22,000 / £23,000). Recast to "run past twenty-two thousand pounds, far beyond anything the estate can meet," which is true under every source.
- **Internal contradiction at the death**: the hen stop is dated 2 April, the death 9 April, but the campa asserted the chill turned fatal "in two or three days." Aubrey's two-or-three-days is canon and stays, now explicitly attributed to Aubrey rather than stated flat, so the compression reads as the canon reporting itself.

### Quotes

All 7 checked against the canon; 6 verbatim and carried:

- **Rawley on Aristotle** — matches the 1657 *Resuscitatio* Life verbatim.
- **"all knowledge to be my province"** (Burghley, 1592) — verbatim.
- **"my act, my hand, and my heart... a broken reed"** — carried in the standard form.
- **"The end of our foundation..."** (*New Atlantis*) — verbatim.
- **The last letter to Lord Arundel** ("the fortune of Caius Plinius the elder") — matches the standard rendering.
- **The St Michael's epitaph** ("of Science the Light, of Eloquence the Law, sat thus... let compounds be dissolved") — matches the received translation of *Scientiarum Lumen, Facundiae Lex... Composita solvantur*.
- **Repaired: the Novum Organum Idols.** This was not a quote but a stitched fragment of four ellipsed noun phrases. Replaced with the actual verbatim Aphorism XXXIX (Spedding): "There are four classes of Idols which beset men's minds..."

### Chronology, confidences, register

Dates run correctly within every segment. One backward step across segments (the 1604 *Apologie* closing "The Fall of the Earl," then the July 1603 knighting opening the next segment) — this is deliberate thematic segmentation of the same kind flagged for the Rosicrucian segment, and it is well within corpus norm: 41 of 143 journey files carry at least one such step; Bacon has exactly one. Left as authored.

Confidences are honest. The Rosicrucian manifestos, the biliteral cipher's conception at seventeen, the First Folio authorship tradition, the black-mortar dream, and the snow-and-hen are all carried as `traditional` — narrated as living tradition, neither debunked nor asserted. Nothing mythic was removed.

`register` normalised from the em-dash form to the colon form used by `joan_of_arc.journey.json`.

Campa word counts all in band after repair (72-107); one stop (*New Atlantis*) was trimmed from 114 to 101 by cutting a phrase that duplicated its own quote. All present tense, register intact.

### Note for the curator

The report's connections section states that `roger_bacon` and `giulio_camillo` "do not yet exist as a file in this directory." **Both now exist** (`roger_bacon.journey.json`, `giulio_camillo.journey.json`). Those two edges can be promoted from "future nodes" to live siblings.
