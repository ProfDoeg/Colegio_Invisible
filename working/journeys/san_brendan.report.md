# San Brendán de Clonfert: research report

*Slug `san_brendan`. Brendan of Clonfert, Bréanainn moccu Alti, "the Navigator." Traditional dates c. 484 to 577 (Annals of Ulster: 583). Queued in QUEUE.md line 342 as "the Atlantic voyage held real by tradition, whale-islands and all; pairs with Leif Erikson."*

Legend: **[A]** = attested, source named. **[R]** = reconstruction, tradition, hagiography, or interpretive reading. Contradictions are flagged where found and **not adjudicated**. One structural fact governs everything below:

> **There is no contemporary documentation of Brendan's life.** All biography descends from two later Latin texts that disagree with each other, and the famous voyage descends from the one of them that is not a biography. The atlas file carries tradition as tradition, with the hedge in `date_confidence` on every stop, and pins only sites that can actually be located.

---

## 1. The two texts, and why the order matters

**[A: Wikipedia, 'Brendan of Clonfert' / 'Navigatio Sancti Brendani', summarizing scholarly consensus]** The *Navigatio Sancti Brendani Abbatis* was probably composed in the **second half of the eighth century**. The earliest surviving manuscript witness dates to about **AD 900** and is Continental, not Irish. Over **100 manuscripts** survive across medieval Europe, plus vernacular translations past counting.

**[A: same]** The *Vita Brendani* survives only in copies **no earlier than the end of the twelfth century**, though scholars suggest a version existed before AD 1000.

**Consequence:** the voyage text is older than the biography. The *Navigatio* is not a legend grown out of a Life; it is the primary Brendan document, and the Life is the later accretion.

**Contradiction between the two texts, flagged, not resolved [A on both sides]:**

| | *Navigatio* | *Vita* |
|---|---|---|
| The boat | ox-hide currach, wood frame, hide greased with fat | hide boat **fails**; Ita tells him to build in boards |
| The crew | fourteen monks (some MSS: fourteen plus three unbelievers) | sixty disciples |
| Outcome | Terra Repromissionis after seven years | a Land of Promise, less elaborately told |

The Ita quote carried in the journey file ("Thou wilt not gain the Land of Promise borne in the hides of dead beasts") is the *Vita* explicitly repudiating the *Navigatio*'s most famous physical detail. Tim Severin's 1976 replica was built to the hide specification, that is, to the version the *Vita* says does not work.

**Date-field error caught in the pool:** the entry dating the earliest *Vita* copies to "1190" is invented precision. No source gives a year, only "end of the twelfth century." The journey file does not carry 1190.

---

## 2. Birth, fosterage, ordination (c. 484 to c. 510)

- **[R: Wikipedia / Vita tradition]** Born **c. 484 at Tralee**, Co. Kerry, in the Ciarraige Luachra territory of west Munster; parents **Findlug and Cara** of the Alta race.
- **[R]** Baptized at **Tubrid near Ardfert** by **Bishop Erc of Slane**. Named **Mobhí** first, then **Broen-finn**, "fair drop."
- **[R]** Fostered five years by **St Ita of Killeedy**, Co. Limerick.
- **[R]** Schooled at **Bishop Jarlath's monastery at Tuam**, Co. Galway.
- **[R]** Ordained priest by Erc at about twenty-six, c. 510.

**Contradiction inside the pool, flagged:** the chronology lens dates the Tuam schooling to **500**; Wikipedia's own text says Brendan went to Jarlath **at age six**, c. **490**. A decade apart. The journey file's Tralee stop carries both readings, in campa and in `date_confidence`.

**Second chronological collision, flagged:** the pool dates the **Ardfert and Shanakeel** foundations to **520** and the voyage's start to **512**, while the tradition narratively puts the Kerry foundations first. The file pins the Ardfert stop at the ordination year and states the collision in `date_confidence` rather than silently reordering it.

**Gap:** no coordinates were verified for **Killeedy**, **Tuam**, or **Inis-da-druim**, Co. Clare (a foundation the pool dates to 550). All three are carried in campa prose at neighbouring stops rather than given invented pins.

---

## 3. The Kerry departure geography (site tradition, no text)

The *Navigatio* **names no Irish place at all**: not the mountain, not the harbour, not the county. Everything here is Kerry site-tradition attached to the text afterwards.

- **[R]** **Mount Brandon / Cnoc Bréanainn**, 952 m: three days' fast before the voyage at a summit oratory, **Séipéilín Bréanainn**.
  - **Correction applied [A: Wikipedia, 'Mount Brandon']:** the pilgrim route is **Cosán na Naomh**, not "An Bóthar" as the geography lens had it.
- **[R]** **Brandon Creek**, the launching inlet.
  - **Corrections [A: Wikipedia, 'Brandon Creek']:** the Irish name is **Cuas an Bhodaigh**, not "Cuas na Bó Finne"; the geography lens coordinates were **2.7 km off**. The file uses **52.2374, -10.3111**.
  - **A second, larger error:** the afterlife lens gave 52.1706, -10.4306 for Severin's 1976 departure, **11 km off and offshore**. Both Brandon Creek stops use the corrected pin.
- **[R]** **Kilmalkedar**: waypoint on Cosán na Naomh; ogham stone and sundial predate the standing Romanesque fabric. Consistent with, not proof of, a Brendan-era origin.
- **[R]** **Gallarus Oratory**: dry-stone, corbelled, boat-shaped. Coordinates corrected to **52.17250, -10.34944**. **[A]** Dating openly disputed: **Peter Harbison proposed a twelfth-century date in 1970 and abandoned it in 1994-95** for a pilgrim-shelter reading. No source names Brendan as builder.
- **[R]** **Skellig Michael**: no source places Brendan there; carried as milieu only.
- **[R]** **Inishglora**, Co. Mayo: Mayo folklore only, named in no Life. Also the island of the end of the Children of Lir, so already carrying legend before Brendan was attached to it.

---

## 4. The voyage (the *Navigatio* itself)

Episodes are **[A]** as *text* and **[R]** as *geography*. That distinction is the whole discipline of this section.

| Episode | Text | Identification proposed | Status |
|---|---|---|---|
| **Jasconius**, the whale taken for an island | ch. 9 [A] | waters near Iceland | [R], no textual basis |
| **Island of Sheep**; **Paradise of Birds** | ch. 10-11 [A] | the Faroes | [R] real scholarship; **Mykines specifically is unsourced** |
| **Isle of Ailbe**, 24 silent monks | ch. 12-13 [A] | none | unlocated, and nobody has tried |
| **Island of Smiths**, fiery slag | ch. 23-24 [A] | Iceland, Hekla | [R], old and widely held |
| **Judas on the rock** | ch. 25 [A] | Rockall | [R], a guess at the loneliest outcrop |
| **Paul the Hermit**, otter-fed | ch. 26 [A] | none | unlocated |
| **Crystal pillar** and its mesh | ch. 22 [A] | iceberg | [R], the most physical passage in the book |
| **Terra Repromissionis Sanctorum** | ch. 28-29 [A] | Canaries, Azores, open ocean | [R], cartographic not textual |

**Correction to the Faroes identification [A: Wikipedia, 'Mykines']:** the pool pinned the **Island of Sheep** to Mykines. Mykines is an Important Bird Area with roughly **125,000 pairs of Atlantic puffins**, appears in no sheep source, and carries a pre-Norse Irish name, ***muc-innis*, "pig island."** If any Faroese island answers a *Navigatio* episode it is the **Paradise of Birds**. Coordinates corrected to **62.100, -7.600**. The campa states the mismatch rather than hiding it.

**Two declared placeholder pins.** The **Isle of Ailbe** and **Paul the Hermit's rock** are located by no source. Rather than drop two characteristic episodes, the file pins them at 57.0/-18.0 and 59.5/-22.0, with `date_confidence` stating that the coordinates are **a declared placeholder carrying no evidentiary weight and not an identification**.

**Quote correction [A: verified against Project Gutenberg #17343]:** the bird's prophecy reads "and afterwards **shall** thou find," not "shalt." Bute's 1893 text is followed verbatim, archaism and all, with the elided sentence about keeping Easter restored.

---

## 5. Foundations, death, burial (c. 557 to 577/583)

**Clonfert has four competing foundation years and this report chooses none:**

| Year | Source |
|---|---|
| c. **557** | Wikipedia, 'Brendan of Clonfert' |
| c. **559** | the corpus's own geography lens |
| **561** | the annals, "at the order of an angel" |
| **563** | Wikipedia, 'Clonfert Cathedral' |

The pool tagged this **[A]**. That tag is **unwarranted** and is downgraded here to [R]: four years across three sources is tradition, not an attested date. The stop pins 557 and lists all four in `date_confidence`.

**The worst coordinate error in the pool [A: Wikipedia, 'Clonfert Cathedral']:** the cathedral is at **53.240651, -8.058621**. The pool gave 53.2264/-8.1637 (**7.5 km off, in open farmland**), 53.2231/-8.1614 (three separate entries), and 53.2145/-8.1146. **Four wrong pins for one cathedral.** All Clonfert stops use the corrected value.

**Annaghdown.** Coordinates corrected to **53.38998, -9.07299** (4.7 km). **[R, downgraded from [A]]** The grant is **historically doubted**: Francis Byrne questioned its plausibility, and the earliest evidence for the site, from **c. 800, associates it with Ciarán, not Brendan**. The convent for **Briga** is Vita tradition.

**Death.** **[A]** Feast day **16 May**, standard in the martyrologies. **[Contradiction]** Year: **Four Masters s.a. 577** against **Annals of Ulster s.a. 583**. **[Contradiction]** The *Vita* has him die **in his ninety-sixth year** while giving 484 to 577, which is ninety-three. The campa says both out loud.

**[R]** The concealed death and the body carried home in a farm cart is a **later legendary elaboration**. The burial at Clonfert is the one point on which every source agrees.

---

## 6. The papar: the real Irish Atlantic under the legend

This section keeps the journey honest, and it is where the pool's [A] tags needed the most work.

- **[A: Dicuil, *Liber de Mensura Orbis Terrae*, 825]** Irish clerics sailed to **Thule** and reported its near-midnight summer sun: a ninth-century document, older than any surviving *Navigatio* manuscript.
- **[A: Landnámabók]** The Norse record finding **papar**, priests, already in Iceland, who then left.
- **[A: place-name evidence; W. P. L. Thomson, *The New History of Orkney*]** **Papa Westray** and the scatter of *papar* names across Orkney and Shetland.
- **[A: burnt_njal.journey.json / Landnámabók]** **Kirkjubær on the Síða**: the papar held the site and gave it its church-name before the Norse arrived.

**Correction, and a serious one [A: Wikipedia, 'Papey']:** the pool called Papey "**the strongest documentary link**" between real Irish voyaging and the legend, and tagged it [A]. The same source records that **archaeological survey on Papey found no monastic settlement, only Norse settlement**. The link is documentary and **not corroborated on the ground**. Coordinates also wrong by **34 km**: Papey is at **64.59167, -14.16667**. Both corrections are in the file, and the campa ends on the disagreement between documents and dirt rather than resolving it.

---

## 7. The island that would not come off the charts

- **[A]** **Erdapfel**, Martin Behaim, Nuremberg, **1492**: St Brendan's Island marked on the oldest surviving terrestrial globe, finished the year Columbus sailed. The afterlife lens flagged it as needing direct confirmation; recorded as widely cited, not re-verified.
- **[Contradiction, flagged, not resolved] Ebstorf against Hereford:**
  - The pool dates an Ebstorf depiction to **1234**. Wikipedia places the map "some time between **1234 and 1240**," with a competing view that it is a copy made **as late as 1300**. The original was **destroyed in the 1943 bombing of Hanover**.
  - The pool dates Hereford to **1275**; the actual date is **c. 1300**, and Hereford Cathedral calls its map **"the earliest known map to depict the mythical St Brendan's Isle."**
  - Both cannot be true. The corpus carried both without noticing. The Nuremberg campa states the collision and declines to settle it.
- **[A: Spanish Wikipedia, 'Isla de San Borondón']** Searches for **San Borondón**: late 15th c. (Fernando de Viseu); **1526** (Hernando de Troya, Francisco Álvarez); **1570** (Hernán Pérez de Grado and others); **1604** (Gaspar Pérez de Acosta, Fray Lorenzo de Pinedo); **1721** (Gaspar Domínguez), explicitly **the last official expedition**.
  - **Corrections:** English Wikipedia's "1566, 1719, 1721, 1759" is wrong on three of four counts. **1566** refers to Pérez de Grado *ordering justices to investigate*, not a voyage; the voyage is **3 April 1570**. **No 1719 or 1759 expedition is recorded**, and a 1759 voyage would contradict 1721 being the last. The file follows the Spanish record.
  - The afterlife lens also understated this badly, calling it "at least one recorded search expedition in the 18th century." Five searches across roughly 250 years is the record.
- **[A]** **Hy-Brasil**, from the **Dulcert portolan of 1325** onward: a separate phantom running beside Brendan's island on the same charts for five centuries.
- **[R]** **Magellan's men** allegedly naming **Samborombón Bay** after St Brendan's Island (1520). An attributed naming tradition with no corroboration and no verified coordinates. **Not carried as a stop**; recorded here as a loose end.
- **[R]** **Columbus and the *Navigatio*'s winds**: the Paul Chapman thesis holds Columbus knew the text's account of favourable westbound and eastbound routes. **Not corroborated by Columbus's own writings in any reachable source.** The Lisbon campa carries the claim and the non-corroboration together.

---

## 8. The rival crossing, and the boat that was actually built

- **[A: Parks Canada; Ingstad excavations 1960-68; leif_erikson.journey.json]** **L'Anse aux Meadows**: eight sod buildings, smithy, iron rivets, spindle whorl; wood cut with metal tools dated to **1021** by a cosmic-ray event in the tree rings. The only confirmed pre-Columbian European site in North America.
- **[Contradiction, flagged]** **Brattahlíð** as Leif's departure point: the pool tagged it [A]; the sagas disagree, **Eiríks saga rauða having Leif sail from Norway and be blown off course** while *Grænlendinga saga* has him leave Greenland. Downgraded and hedged. Coordinates corrected to the corpus's canonical **61.15, -45.517**, inherited byte-identical from `leif_erikson.journey.json`.
- **[A]** **Tim Severin**, May 1976 to **26 June 1977**: replica ox-hide currach *Brendan*, ash frame, hides tanned in oak bark, from Brandon Creek via the Hebrides, Faroes and Iceland to **Peckford Island**, Wadham Islands; towed into Musgrave Harbour by the Canadian Coast Guard.
  - **Coordinate correction:** Peckford Island is at c. **49.554, -53.850**, not 49.6167/-54.1667 (**25 km off**).
  - **Date correction:** the pool conflated Severin's **book** (1978) with **Shaun Davey's orchestral suite** (**1980**).
  - **What it proves:** feasibility of the hull, nothing about Brendan. The campa does not inflate it.
- **[A: Wikipedia, summarizing scholarly consensus]** **No reliable historical or archaeological evidence supports Brendan reaching Greenland or the Americas.** Modern scholarship treats the *Navigatio* as an *immram*, a monastic voyage-tale, not a travel record. That is this report's conclusion too, unsoftened.

---

## 9. Interlocks with the existing atlas

Named in campa, path genuinely crossed:

- **`leif_erikson`**: two stops, Brattahlíð and L'Anse aux Meadows, both on inherited pins. This is the pairing QUEUE.md itself specifies. One landfall stands on excavated iron, the other on a copied manuscript.
- **`burnt_njal`**: Kirkjubær on the Síða, pin inherited byte-identical (63.79, -18.06). Njál's saga world supplies the one place in the corpus where the papar appear in a narrative source.
- **`columbus`**: two stops on inherited pins, **Ultima Thule / Iceland 1477** (64.1466, -21.9426) and **Lisbon 1481** (38.7078, -9.1366, Toscanelli's chart and Antilia). Antilia is the cartographic cousin of St Brendan's Isle, not the same island, and the campa keeps that distinction.

Canonical pin inherited: **Paris 48.8566, 2.3522** for the Continental manuscript transmission stop, byte-identical with `adam_smith`, `arthur_ben`, `abu_yazid_al_bistami`.

Found by the lens and **not** used: **`edgar_allan_poe`** (genre parallel only, no shared pin); the **`saint_erasmus`**, **Kaaba** and **Buenos Aires** pins (canonical and available, no content link); **`rabban_bar_sauma`** (line 338, a real structural twin, queued with no file, nothing to gaze back); **Jacobus de Voragine** (line 482) and **St Anthony of Padua** (line 869), queued only and [R] thematic.

---

## 10. Honest gaps

1. **No contemporary source for the man.** Nothing written in Brendan's own century names him.
2. **No coordinates verified** for Killeedy, Tuam, Inis-da-druim, Teltown (Teilte), Hereford, or Ebstorf. These are carried in campa prose instead of invented pins.
3. **The pool's Iona claim was wrong in place and in substance.** It had Brendan seeing "a pillar of light over Columba at the altar" on Iona. Adomnán sets the episode at a **synod at Teilte in Ireland**, where Brendan **kisses the excommunicated Columba and says he sees holy angels accompanying him**. The stop keeps a corrected Iona pin (**56.33417, -6.39361**) and says in campa that the meeting was not held there.
4. **Two placeholder pins declared** (Ailbe, Paul the Hermit), see section 4.
5. **Samborombón Bay** left a loose end, not a stop.
6. **The Erdapfel's Brendan marking** is widely cited but not re-verified against the object.
7. **The Saint Brendan Society** and modern pre-Columbian advocacy are noted [R] and given no stop.

---

## Sources

**Primary texts, via reachable editions**

- *Navigatio Sancti Brendani Abbatis* and *Vita Sancti Brendani* (Salamanca and Oxford recensions), both reached through J. P. Crichton-Stuart (Marquess of Bute), **"Brendan's Fabulous Voyage,"** lecture of 19 January 1893, **Project Gutenberg ebook #17343**. Nine of the eleven quotes in the journey file trace here; one word was corrected (section 4).
- Adomnán, *Vita Columbae*, Book III, for the Brendan and Columba episode.
- Dicuil, *Liber de Mensura Orbis Terrae* (825); *Landnámabók*, for the papar.
- *Grænlendinga saga*; *Eiríks saga rauða*, English translation at **sagadb.org**, source of the two Norse quotes.
- *Annals of the Four Masters* (s.a. 577); *Annals of Ulster* (s.a. 583).

**Reference and secondary**

- Wikipedia: 'Brendan of Clonfert', 'Navigatio Sancti Brendani', 'Saint Brendan's Island', 'Ebstorf Map', 'Hereford Mappa Mundi', 'The Brendan Voyage', and the site articles used for coordinate correction (Clonfert Cathedral, Annaghdown, Ardfert Cathedral, Mount Brandon, Brandon Creek, Gallarus Oratory, Mykines, Papey, Iona Abbey).
- **Spanish** Wikipedia, 'Isla de San Borondón', decisive for the expedition list and the reason the English list is not followed.
- Tim Severin, *The Brendan Voyage* (1978); Shaun Davey, *The Brendan Voyage*, orchestral suite (1980).
- Parks Canada, L'Anse aux Meadows archaeological reports; Ingstad excavations 1960-68.
- National Monuments Service Ireland records: Ardfert, Clonfert, Skellig Michael, Gallarus, Kilmalkedar, Inishglora.
- Angelino Dulcert portolan chart, 1325; Martin Behaim, *Erdapfel* (1492), Germanisches Nationalmuseum, Nuremberg.

**Named but not reachable in this pass, recorded as gaps rather than evidence**

- **Carl Selmer**, *Navigatio Sancti Brendani Abbatis*, critical edition (1959): cited at second hand only, text not consulted.
- **W. P. L. Thomson**, *The New History of Orkney*: cited at second hand only.
- **Paul Chapman's thesis** on Columbus and the *Navigatio* winds: known only through the Wikipedia report of it, which is exactly why the claim stays [R].
- **The Ebstorf map itself**: destroyed by bombing in Hanover, 1943. Nothing survives but 1891 photographs and facsimiles. An unfillable gap, not a research failure.
- **Canary Islands colonial archives**: reached only through the Spanish Wikipedia summary and regional histories; no archival shelfmark verified.

**Corpus files consulted for pin inheritance and interlock**

`leif_erikson.journey.json`, `burnt_njal.journey.json`, `columbus.journey.json`, `abdelkader.journey.json` (form), `bourlemont_roster.md` (method), QUEUE.md lines 338, 342, 482, 869.
