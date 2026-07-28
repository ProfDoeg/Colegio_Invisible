# Roger Bacon — Ilchester to Oxford's Grave (c.1214-1292): journey report

**Shape:** 35 stops in 9 named segments, julian calendar, register "national mythology: the canon is true." Canon here is the historiography of Doctor Mirabilis itself: Bacon's own surviving works (Opus Majus, Opus Minus, Opus Tertium, the Communia, the two Compendia) read as his own voice, plus the one medieval source for his imprisonment (the Chronicle of the Twenty-four Generals) and the accreted post-medieval legend of the brazen head, narrated as the tradition tells it and flagged `traditional` rather than debunked.

## Sources
Britannica and MacTutor (St Andrews) for the spine chronology; the Stanford Encyclopedia of Philosophy (2013/2015 editions) for the most carefully hedged modern scholarship on disputed dates (Franciscan entry, imprisonment); the 1913 Catholic Encyclopedia (newadvent.org) for the Clement IV correspondence and the Opus Majus/Minus/Tertium sequence; Muslim Heritage and secondary optics literature for Ibn al-Haytham's Kitab al-Manazir / De Aspectibus and its influence; the James Lind Library and a Bacon-quotes aggregator for verified English translations of the "two ways of acquiring knowledge" and "argument reaches a conclusion" passages from Opus Majus Part VI; Wikipedia and Icy Sedgwick on the brazen head legend and Robert Greene's play; Wikipedia and Oxford's own local-history site (cabinet.ox.ac.uk) on Friar Bacon's Study at Folly Bridge; Wikipedia and Wikisource on Pope Clement IV's Viterbo residence and death; the Oxford DNB entry for the most cautious statement of the imprisonment question.

## Judgment calls
- **Franciscan entry year**: sources split between 1240, 1247, 1251, and 1256/7. I followed the Stanford Encyclopedia's stated consensus of "about 1257," marked `inferred`, and placed it at Oxford (one of the two candidate locations) rather than Paris.
- **Imprisonment**: the fact, the cause, and the place (Ancona) rest on a single 14th-century chronicle written some 80 years after Bacon's death; modern scholars are openly skeptical it happened as described. I kept it — it is the tradition's own account of his last decades and the reason "Doctor Mirabilis" carries a martyr's shadow — but marked every stop in that segment `traditional` and said so plainly in the campa text itself ("Whatever the charge... the busiest writer of his generation falls silent").
- **The brazen head**: the "Time is / Time was / Time is past" three-word prophecy is Robert Greene's 1580s stage invention, not medieval. I kept the legend (it is load-bearing for Bacon's afterlife as a folk-wizard) but did not quote Greene's words as Bacon's own; the campa narrates the head's construction and single utterance without specifying what it says, honoring the legend's shape while not misattributing Elizabethan theater to the thirteenth century.
- **Gunpowder cipher**: the anagram said to hide the saltpetre/charcoal/sulphur formula in the Epistola de secretis operibus has no manuscript authority before a 1542 printed edition. Folded into one campa as "later tradition holds," `quote` left null.
- **The Barons' War / family ruin**: placed at 1265-66, timed to explain Bacon's own complaint (in Opus Tertium) of poverty when composing the Opus Majus — a real causal link the sources support but don't always connect explicitly.
- **A living traveler's journey should end at the present** does not apply: Bacon is dead by any account, so the arc properly closes at his 1292 burial, not with an epilogue into later centuries.

## The five richest episodes
1. **The Book of Optics of Ibn al-Haytham (Oxford, ~1252)** — the hinge the curator asked for: an Arab-Egyptian eleventh-century experimentalist handed a thirteenth-century English friar his entire method before either had a name for empirical science.
2. **The Opus Majus's four causes of error (Paris, 1267)** — Bacon's own indictment of authority, custom, crowd-opinion, and false confidence, quoted in the original translated Latin, is one of the sharpest epistemological passages of the whole medieval period.
3. **Viterbo, the manuscript's arrival (1267)** and its silent reception, followed within a year by Clement IV's death — the collapse of the one institutional backing Bacon's entire program ever had, a papal window open thirteen months and never reopened.
4. **The condemnation of "certain suspected novelties" (1278)** — the order's own general turning on its most famous scholar, on charges the record itself never specifies.
5. **Folly Bridge and the brazen head (Oxford, legendary)** — the real, physically demolished tower (standing until 1779) onto which four centuries of English folklore grafted a talking machine and a wizard's tragedy.

## Connections to the atlas
- **saint_francis** — the order itself; Bacon takes the same grey habit two generations after Francis's own conversion, and invokes Grosseteste and Adam Marsh, not Francis directly, as his personal exemplars of the fusion of holiness and science the order made possible.
- **kircher** — the polymath-friar type repeats almost exactly four centuries later: an omnivorous religious encyclopedist, patronized and then constrained by his own order, working optics, light, and the whole architecture of knowledge from inside a monastic cell. Bacon's burning mirror sent to a pope rhymes with Kircher's obelisks and universal books sent to Rome.
- **ibn_arabi** (and the wider Muslim-cluster edge the curator named) — Bacon's dependence on Ibn al-Haytham's Kitab al-Manazir, and his explicit demand in the Compendium Studii Philosophiae that Latin Christendom learn Arabic and read the philosophers and mathematicians of Islam at the source, makes him the atlas's clearest embodiment of the claim that the "Latin" thirteenth century was already, admittedly, downstream of Cairo and Baghdad.
- **ramon_llull** (not yet in the atlas) — an exact contemporary (b. 1232), also building a universal combinatory science of all knowledge from a semi-monastic base, apparently without ever meeting or citing Bacon; the two are the century's parallel, unconnected attempts at the same encyclopedic dream.
- **francis_bacon** (not yet in the atlas) — no kinship, only the name and, four centuries on, an eerily similar program: an attack on inherited authority, a call for experiment over disputation, even an unfinished utopian fragment (New Atlantis) that echoes Roger's own unfinished Communia.
- Sits naturally beside the atlas's other **friar-scientists and condemned scholars**, and alongside **hallaj** as another figure whose order/institution eventually turned on him for doctrines the record itself struggles to specify.

---

## Validation
`json_check.py` reports: parses clean, 9 segments, 35 stops, 9 quoted stops, no WARN lines. All stops chronological within segment; all `date_confidence` values valid; all campa within the 60-110 word band; every quote has a paired quote_source and vice versa.

---

# Verification pass — 2026-07-24

Independent structure and canon-fidelity check. `json_check.py` passed before and after: `OK  segments=9  stops=35  quoted=9`, no WARN lines. Schema matches `joan_of_arc.journey.json` exactly (same top-level keys, same ten per-stop keys, same `register` string). Stop count 35 sits inside the 30-45 target, so no stops were added. Chronology is sound: dates rise within every segment and across segment boundaries (1268-11-29 → 1269-01-01; 1278-01-01 → 1278-06-01). The traveler is long dead, so the "living person ends at the present" rule does not apply; the arc correctly closes at the Oxford grave.

## Fixed: coordinates (18 stops moved, all 35 now web-verified)
Every pin was checked against OSM/Nominatim or the site's own Wikipedia coordinates. Ten were materially off:

| Site | was | now | source |
|---|---|---|---|
| Ilchester (2 stops) | 51.0007, -2.6773 | 51.0029, -2.6824 | Nominatim, Ilchester, Somerset (~450 m off) |
| University Church of St Mary the Virgin (4 stops) | 51.7519, -1.2523 | 51.7526-51.7529, -1.2535/-1.2538 | Wikipedia, 51.75278 / -1.2537361 |
| Rue du Fouarre (3 stops) | 48.8503, 2.3489 / 48.8497, 2.3477 | 48.8513-48.8517, 2.3470-2.3476 | Nominatim, Rue du Fouarre = 48.8515872, 2.3474752 (~250 m off) |
| Grand Couvent des Cordeliers (7 stops) | 48.8489, 2.3406 | 48.8504-48.8508, 2.3410-2.3416 | Nominatim "Les Cordeliers", 15 rue de l'École de Médecine = 48.8506786, 2.3404642; fr.wikipedia 48.85056, 2.34130 (~190 m off) |
| Folly Bridge / Friar Bacon's Study | 51.7423, -1.2557 | 51.7460, -1.2565 | Wikipedia, Folly Bridge = 51.746027, -1.256542 (~420 m off, the old pin sat south of the bridge entirely) |
| Palazzo dei Papi, Viterbo (2 stops) | 42.4178, 12.1042 | 42.4155/42.4156, 12.1007/12.1009 | Nominatim, Palazzo dei Papi = 42.4156137, 12.1007084 (~430 m off) |
| Santa Maria in Gradi, Viterbo | 42.4131, 12.1102 | 42.4138, 12.1122 | Nominatim = 42.4138180, 12.1122464 |
| Ancona (2 stops) | 43.6169, 13.5155 | 43.6215/43.6216, 13.5121/13.5123 | Nominatim, San Francesco alle Scale = 43.6215189, 13.5122866 — the old pin was generic city-centre, not the Franciscan house the campa names |
| Condemnation of 1277 | 48.8503, 2.3489 (rue du Fouarre) | 48.8529, 2.3499 | Tempier published from Notre-Dame, not the arts faculty street |

Oxford Greyfriars (8 stops) was already close and was nudged from 51.7488, -1.2601 to the 51.7491-51.7494 / -1.2606--1.2612 band around Old Greyfriars Street (Nominatim 51.7492359, -1.2608474), the surviving street-name trace of the St Ebbe's precinct. Repeated sites keep small per-stop offsets, following the file's own convention for distinguishing pins.

## Fixed: quotes (4 of 9 changed)
Six quotes were spot-checked against the canon; four needed work.

- **Peregrinus, "his aid is indispensable" — NOT CARRIED.** The sentence appears in no edition, no encyclopedia, and no quotation collection consulted (Wikiquote, Wikipedia, Stanford, MacTutor, Catholic Encyclopedia, the blog the file itself cited). Replaced with the genuine *Opus Tertium* cap. 13 passage in the Bridges translation: *"One man I know, and one only, who can be praised for his achievements in this science. Of discourses and battles of words he takes no heed: he follows the works of wisdom, and in these finds rest."* Source line now records that the identification with Peregrinus is a marginal gloss surviving in one of five manuscripts — the tradition is kept, the manuscript basis is stated, nothing is debunked.
- **"Mathematics is the door and the key to the sciences"** was MacTutor's loose rendering. Restored to the canon's own wording from the Bridges *Opus Majus*: *"Mathematics is the gate and key of the sciences... Neglect of mathematics works injury to all knowledge, since he who is ignorant of it cannot know the other sciences or the things of this world."* The "Boise Gun Club" citation was dropped for the Bridges edition.
- **"I have... spent forty years in them since first I learned the alphabet"** was a paraphrase. Restored to the translation the Stanford entry prints: *"I have labored much in sciences and languages, and I have up to now devoted forty years [to them] after I first learned the Alphabetum; and I was always studious."*
- **"isolation, hunger, and unspeakable violence"** was a three-noun construction carried by no source as Bacon's words. Replaced with the attested sentence, *"They forced me with unspeakable violence to obey their will."* The campa's paraphrase was rewritten to match.

Verified and left alone: *"intolerable, horrible, and laughable"* on the Julian calendar (confirmed *Opus Majus* Part IV); *"propter quasdam novitates suspectas"* (confirmed, Chronicle of the Twenty-four Generals, and the Catholic Encyclopedia's "suspect innovations"); *"There are two ways of acquiring knowledge, one through reason, the other by experiment"*; *"Argument reaches a conclusion and compels us to admit it..."* (Burke, *Opus Majus* Part VI). The four-causes-of-error quote is a close literal rendering of the Latin *offendicula*; kept, with the Latin now printed in the `quote_source` so a reader can check the translation against the original.

## Fixed: dates and facts
- **Death date was a composite.** The file gave `1292-06-11`: the day comes from the older tradition of 11 June **1294** (Catholic Encyclopedia), the year from the modern c. 1292 consensus (Stanford, Wikipedia, ODNB). Neither source gives 11 June 1292. Changed to `1292-01-01`, `traditional`, with a `suggested_refs` line that states both traditions plainly rather than splicing them.
- **Richard of Cornwall** was described as "the province's English minister." He was a Franciscan regent master, not the provincial minister. Softened to "under the eye of the English Franciscan Richard of Cornwall."
- **Adam Marsh** was called "one of the only two men of his century" Bacon counted perfect in the sciences. Bacon's list of *perfecti* also names Peter of Maricourt and John of London. Softened to "among the very few men of his century he is willing to call perfect."
- **Stop naming.** "The general chapter condemns Bacon's teaching" was the only stop in the file without a place prefix; renamed "Paris, the general chapter condemns Bacon's teaching" to match the canon's convention.

## Checked and left standing
- **Register held throughout.** Nothing mythic was removed. The brazen head at Folly Bridge stays whole (marked `traditional`, Greene's Elizabethan three words still correctly withheld from the thirteenth century); the Ancona imprisonment stays on its single fourteenth-century chronicle, marked `traditional` in both stops, with the silence named inside the campa rather than argued away; the gunpowder cipher stays as "later tradition holds," quote null.
- **Chronology follows MacTutor consistently** (Oxford to c.1241, Paris regency 1241-47, return 1247). Stanford's alternative — Oxford c.1228-36 and a Paris regency from c.1237 under the c.1214 birth year — would shift the middle segments by three or four years. Both are defensible reconstructions of the same disputed spine; the file picks one and stays inside it, and every stop in the stretch is marked `inferred`. Left as is rather than churned.
- Verified as correct and untouched: Clement IV's mandate 22 June 1266 from Viterbo; his death 29 November 1268 and burial at Santa Maria in Gradi; Grosseteste's death 9 October 1253 at Buckden; Tempier's 219 articles, 7 March 1277; Bonaventure as Minister General at the 1260 Narbonne chapter; Jerome of Ascoli and the later Nicholas IV; Raymond of Gaufredi from 1289; the £60 owed to friends and poor students (Catholic Encyclopedia); Friar Bacon's Study demolished 1779; the rainbow's arc at roughly 42 degrees.
- Campa: all 35 within the 60-110 word band after edits, all present tense, register intact. The great episodes (Ibn al-Haytham's optics, the four causes of error, the manuscript's arrival at Viterbo, the condemnation, the brazen head) still carry their weight; none reads flat.

**Result: OK.** File repaired in place and re-validated clean.
