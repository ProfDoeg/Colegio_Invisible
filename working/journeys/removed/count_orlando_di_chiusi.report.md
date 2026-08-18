# Count Orlando di Chiusi in Casentino: research report

*Atlas of Journeys working file, 2026-08-16. Companion artifact: `count_orlando_di_chiusi.journey.json`, 7 segments, 29 stops.*

**Legend.** **[A]** attested, source named. **[R]** reconstruction, tradition, or inference, including anything resting only on the fourteenth-century Franciscan devotional literature. Contradictions are flagged and **not adjudicated**. Gaps are stated as gaps.

---

## 0. The shape of the problem

Orlando di Chiusi is a man with two documented acts and no biography. He gives away a mountain, and he helps pay for a chapel on it. Birth, death, burial, marriage, appearance, and any second meeting with Francis are absent from every reachable source. The article on his own castle says so outright: no historical documentation of Orlando survives beyond the legend of the donation **[A: it.wikipedia, 'Cassero (Chiusi della Verna)']**. A subject with two acts cannot honestly carry twenty-nine narrated scenes unless the stops are fine beats of the one scene the sources do narrate, the ground itself described as property rather than event, or stated absences. The file is built on those three. The other temptation is to import the far better documented life that touches his: one stigmata stop is kept, because the event happens on ground that is legally Orlando's gift, and the rest of Francis's life is excluded as scenes. See section 7.

---

## 1. Family, fief, and name (before 1213)

**[A]** In 967 Otto I invests **Goffredo del fu Ildebrando di Catenaia** with the fief under the mountain in the upper Casentino (it.wikipedia, 'Chiusi della Verna'). The family holds it two and a half centuries.

**[A]** The seat is the **Cassero of Chiusi della Verna**, on the terminal spur of Monte della Verna at the mountain's southern end, above the oldest part of the town. That article calls the ruin the rocca of **Conte Orlando Cattani**, records the donation tradition, and notes a fourteenth-century enlargement by the **Tarlati di Pietramala** (it.wikipedia, 'Cassero (Chiusi della Verna)').

Comune point: 43 deg 41' 54" N, 11 deg 56' 10" E = **43.6983, 11.9361**; the Cassero approximately **43.6985, 11.9358**. The pool's 43.6886, 11.92 is about 1.5 km southwest of the town and is rejected.

### Contradiction 1: the surname, not resolved

**di Catenaia** in it.wikipedia 'Chiusi della Verna' (the 967 grant and the 1261 notice); **Cattani** in it.wikipedia 'Cassero (Chiusi della Verna)' and in Franciscan tradition generally; **Catani** in en.wikipedia 'La Verna' and in this atlas's `saint_francis.journey.json`; and no surname at all in it.wikipedia 'Santuario della Verna', which has only *il conte Orlando di Chiusi in Casentino*. Four live forms, no standard. Cattani may be a worn form of Catenaia, but no source asserts this and they are not merged here. A **Treccani Dizionario Biografico** entry that might settle it returned no retrievable text (inaccessible, named as such).

### Gap 1: birth

**[R, gap]** No birth date, year, place or parentage in any source consulted. He enters the record already adult and titled by 1213. The file's placeholder stop is dated 1180-01-01 and says so in `date_confidence`; the year carries no evidential weight.

### The mountain before the gift

**[A]** Monte della Verna is a forested height cut by ravines and cliffs, with a spring and the great overhang later called the **Sasso Spicco** (it.wikipedia, 'Santuario della Verna'). Wolves and falcons are **[R]**, from the First Consideration by way of this atlas's Francis file. Sanctuary coordinates: it.wikipedia gives 43 deg 42' 26" N, 11 deg 55' 51" E = **43.7072, 11.9308**; `saint_francis.journey.json` uses **43.7064, 11.9297**, which the file inherits byte-identically for shared stops.

---

## 2. San Leo, 1213: the one narrated scene

**[A]** it.wikipedia, 'Santuario della Verna' attests only this: *nella primavera del 1213 incontro a San Leo, in Montefeltro, il conte Orlando di Chiusi in Casentino*. A meeting, at San Leo, in spring 1213. **No feast, no knighting, no sermon.**

**[R]** Everything else, the knighting banquet, the low wall, the couplet, the count pierced to the heart, the conversation after dinner, the two friars, the fifty men-at-arms, comes from the **First Consideration of the Considerations on the Holy Stigmata**, the appendix to the *Fioretti*: a fourteenth-century vernacular devotional text (the *Fioretti* proper being a partial vernacular translation of the Latin *Actus beati Francisci*, attributed to Ugolino da Montegiorgio / Brunforte). It is the earliest narrative source for Orlando and it is not a document.

**Correction carried.** The episode is **not** *Fioretti* chapter XVI, as one lens of the pool asserted; it is the **First Consideration**, the appendix, as `saint_francis.journey.json` already cites it. Corrected in both artifacts.

### The quotations

Eight verbatim passages were recovered from the CCEL edition (translation revised by Dom Roger Hudleston, O.S.B.), and all eight are used as `quote` fields: Orlando's introduction, the sermon theme, his approach to Francis, Francis's reply sending him back to his hosts, the gift itself, the conditional acceptance, the return to Chiusi *about a mile distant from Mount Alvernia*, and the fifty men-at-arms.

**Note on translations.** The sermon couplet appears in `saint_francis.journey.json` in a different rendering (*So great is the good I have in sight, that every pain to me is a delight*): two translations of one couplet, not two attestations. Flagged in the stop's `quote_source`.

**Rejected text.** The pool carried an en.wikipedia string describing La Verna as *a diverse little mountain... the very lonely and savage act*: a corrupt machine translation of *uno monte divotissimo*, a most devout mountain. Not used; the Italian original and the CCEL English are used instead.

### Contradiction 2: place, date, and legal character, not resolved

- **Place.** it.wikipedia and en.wikipedia say **San Leo**; the CCEL text says **the Castle of Montefeltro**. San Leo was the historic Montefeltro capital, so these are probably the same rock, but the sources are not made to agree here.
- **Date.** it.wikipedia: spring 1213. en.wikipedia, 'Francis of Assisi': **8 May 1213**, the mountain *eminently suitable for whoever wishes to do penance in a place remote from mankind*. The CCEL text sets the whole episode in **1224**, eleven years later. The traditional 8 May survives chiefly on the caption of Folchi's 1877 canvas.
- **Legal character.** The pool's *formally grants* is removed. No charter, notarial instrument, or witnessed act survives.

**[A]** The civic history of San Leo records of that year only *Fu luogo di passaggio di san Francesco nel 1213* (it.wikipedia, 'San Leo (Italia)'), with no feast, no count, no gift. The gap between civic notice and devotional narrative is the clearest sign that the banquet is later embellishment on a simpler transit. This research cannot determine which layer is closer to 1213.

**Coordinates.** Comune 43.8964, 12.3433; rocca approximately 43.8959, 12.3464. The Francis file uses **43.8962, 12.343** and the Orlando file inherits it byte-identically. The pool's 43.9105 and 43.9075, two different wrong values for one place, are rejected: both sit over a kilometre north, off the massif.

---

## 3. The mountain taken up (1213 to 1218)

**[R]** Francis sends two brothers to inspect. Orlando receives them at Chiusi and sends fifty men-at-arms up with them against wild beasts (First Consideration). This is the only act of Orlando's described in any operational detail anywhere, and the only place the tradition shows him doing rather than saying something.

**[R]** Francis and companions then occupy the mountain intermittently as hermits (it.wikipedia, 'Santuario della Verna'). **[R]** en.wikipedia, 'La Verna' frames the donation as made to **Francis personally, for solitary penance**, not to the order as an institution.

**[A]** The first chapel, **Santa Maria degli Angeli**, is built **between 1216 and 1218** (*fu costruita tra il 1216 e il 1218*). The tradition holds that the **Virgin of the Angels appeared to Francis in a dream and indicated both the site and the dimensions**, and that the dedication to her was by Francis's own will (it.wikipedia, 'Santuario della Verna').

**Correction carried.** The pool attributed the dream to Francis alone and said the chapel was named after the Portiuncula at Assisi. The source says neither: the dream is the Virgin's apparition, and **no Porziuncola link is stated**. The inference is removed from both artifacts.

**[A]** Orlando helps to finance the construction (en.wikipedia, 'La Verna': *helped finance*). **Overclaim removed:** the pool called this independently documented. It is not; both Wikipedias trace it to the same sanctuary tradition, and no account book survives.

### Cut as fabricated scene-setting

Three pool items named Orlando in scenes no source places him in, and are cut rather than published with a gap label: Orlando supplying timber and labour for the first huts (admitted in the pool as pattern-based reconstruction); Orlando provisioning the friars year by year 1213 to 1226 (circular, inferring the provisioning from a 1274 instrument that itself has no external source); and Orlando personally conducting Francis up the mountain (no source places him on the mountain with Francis at any time).

The first cell of wood and earth near the Sasso Spicco **is** attested and is kept, described as ground and building rather than as a scene Orlando attends. Its coordinates are corrected from 43.706, 11.9195 to approximately **43.7068, 11.93**.

---

## 4. The silence (1218 to 1261)

**[R, gap]** No further meeting with Francis, no visit to La Verna, no letter, oath, lawsuit, or witness list in the forty-three years between the chapel and the Aretine notice of 1261. His role in the Franciscan narrative ends with the gift and the funding. Nothing records that he learned of the stigmata, when, or what he said. The pool proposed a stop staging him receiving the news at his castle; that stop is rewritten so its entire content is the absence, drawing no conclusion in either direction.

---

## 5. The stigmata on his ground (1224)

**[A]** Francis withdraws to La Verna for a forty-day fast before Michaelmas with Brother Leo and a few companions and receives the stigmata during a vision of a six-winged seraph (en.wikipedia, 'La Verna'; it.wikipedia, 'Santuario della Verna'; `saint_francis.journey.json`).

### Contradiction 3: the date, resolved by convention only

**14 September**, the Exaltation of the Cross, in en.wikipedia 'La Verna' and in `saint_francis.journey.json` (`1224-09-14`). **17 September**, the feast of the Impression of the Stigmata, in it.wikipedia 'Santuario della Verna'. The research pool contradicted itself across its own lenses. The file adopts **1224-09-14** for one reason only, that this atlas's Francis file already carries it, and states the disagreement in full inside `date_confidence`. The choice is editorial consistency, **not** a finding.

**[A]** The **Cappella delle Stimmate** marking the site was not built until **1263**, at the expense of Count **Simone Guidi da Battifolle**. It did not exist at the moment of the event, and the file says so. Correct coordinates approximately 43.7075, 11.9310, not the pool's 43.7047, 11.9213.

**[R]** The land remains Orlando's donated ground. No source records a reconfirmation of the gift by him around 1224.

---

## 6. The name in the Aretine record (1261) and the end

**[A]** In **1261** Guglielmino degli Ubertini, bishop of Arezzo, claims sovereignty over the fief, *lasciando ai fratelli Orlando, Alberto e Niccolo di Catenaia il solo dominio sul castello di Chiusi* (it.wikipedia, 'Chiusi della Verna').

**Correction carried.** The pool rendered this as *Orlando and his brothers*. The source says **the brothers Orlando, Alberto and Niccolo**, all three equally, surname **di Catenaia**, and has the bishop claiming the **fief** while leaving them the **castle alone**.

### Contradiction 4: is this the same Orlando? Not resolved

Forty-eight years separate the San Leo meeting from this notice. This Orlando may be the count of 1213 grown very old, or a descendant bearing the name. No source consulted addresses the question. The file names both possibilities and decides neither.

### Gap 2: death

**[R, gap]** No date, no place, no circumstance. The file uses 1270-01-01 as an explicit placeholder and says so. The pool's *before 1274* terminus is rejected, deriving entirely from the unverified 1274 instrument.

### Gap 3: burial

**[R, gap]** No tomb, epitaph, slab, or interment record anywhere. Local Franciscan memory keeps him as the donor and keeps nothing of his body. Any future claim of a specific grave should be treated with suspicion until a document is produced.

### The 1274 instrument

**[R, uncorroborated]** `saint_francis.journey.json` cites *The 1274 instrument of the donation of La Verna*. No source consulted this pass names, dates, or reproduces it, and whether it is an act of Orlando or of his heirs is unknown. It is kept as one stop, flagged in `date_confidence` as resting on the atlas's own internal citation and nothing else. Two pool items reasoning *from* this instrument to conclusions about Orlando's later life were cut as circular.

---

## 7. What became of the gift, and what was kept out

**[A]** From about 1250 the first chapel is enlarged, and in **1260** the enlarged church is consecrated with Bonaventure and several bishops present. **1263**: the Cappella delle Stimmate, paid for by Simone Guidi da Battifolle. **Late fourteenth century**, no year in the source: the chapel of Santa Maria Maddalena, raised by the countess **Caterina Tarlati** on the site of Francis's first brushwood hut. **1348**: the great church of the Assumption begun under Count **Tarlato di Pietramala**, unfinished until **1459**. **1498**: the condottiero **Bartolomeo d'Alviano** devastates the complex with roughly 150 horse and 800 foot. (it.wikipedia, 'Santuario della Verna' and 'Chiusi della Verna'; 1459 also en.wikipedia, 'La Verna'.)

**Corrections carried.** The pool's 1390 date for the Tarlati chapel is invented; the source gives only *alla fine del XIV secolo*. The chapel commemorates the **capanna di frasche**, the brushwood hut of Francis's stays, not an apparition of Christ. The pool cited it.wikipedia 'La Verna', a redirect containing none of it; the passage is in 'Chiusi della Verna'. And Caterina Tarlati was **not** a descendant of the family: the Tarlati di Pietramala were Aretine lords with no attested descent from the Catenaia counts, who **succeeded** them at the site and also enlarged the Cassero itself.

**Applied rule.** These are other families' acts on ground Orlando gave away. Per the standing rule (Rashi at Troyes, Freud before the Moses), none is staged as a scene in his file. They are compressed into one stop on the succession of patronage out of the house of Chiusi, and otherwise appear as `sources` and `suggested_refs`. The 1498 sack has no stop.

**Also excluded.** Francis's death at the Portiuncula and his descent on a borrowed donkey: both Francis's stops, with Orlando unattested either way. (The pool's 43.0669, 12.5822 for the Porziuncola is a kilometre north of the real site, 43.0578, 12.5811; corrected for the record, not used.) **Kaaba (21.4225, 39.8262) and Temple Mount (31.778, 35.2354):** offered as canonical pins the atlas inherits elsewhere, with no connection to Orlando, as that lens concedes. Not used.

### The 1877 canvases

**[A]** There are **two**, not one: *due tele del pittore fiorentino Ferdinando Folchi del 1877* (it.wikipedia, 'Santuario della Verna'), on the walls of the space in front of the **tramezzo** in the church of Santa Maria degli Angeli at La Verna. en.wikipedia, 'La Verna' names the pair: the meeting with Count Orlando Catani at San Leo, and the dedication of the chapel. The caption date **8 May 1213** comes from en.wikipedia only. The pool described a single canvas and recorded its location as not given; both are wrong.

**A further correction.** The pool's closing observation had the paintings hanging in the room Orlando funded. The fabric does not support it: the space before the tramezzo belongs to the later enlargement, not the 1216-1218 shell. The file's closing stop says *the church he helped to pay for* and claims nothing about the room. Retaining the stop at all is a judgment call: a painting *of* Orlando is in one sense Folchi's work. It is kept because it commemorates Orlando's own act at the place he endowed, and Folchi is not staged as a scene.

---

## 8. Interlocks

**Direct, used in the file.** **Francis of Assisi** (`saint_francis.journey.json`): Orlando meets him at San Leo, gives him La Verna, receives his brethren, funds the chapel. The existing stop *San Leo, the verse of the castle feast and the gift of La Verna* names Count Orlando Catani explicitly; the stigmata stop calls the mountain *Orlando's mountain*. Coordinates inherited byte-identically, San Leo **43.8962 / 12.343** and La Verna **43.7064 / 11.9297**. This is the only atlas traveller named in any campa.

**Found and deliberately not named in any campa.**

**Michelangelo** (`michelangelo.journey.json`) names Count Orlando, because Lodovico Buonarroti held the six-month podesteria over Caprese and Chiusi della Verna in 1475: Michelangelo's link to Orlando's commune, 262 years later, running one way only. **Dante** (Campaldino 1289, Poppi 1311) and **Margery Kempe** (the 1414 Portiuncula pardon) are geography and Franciscan aftermath, with no textual link to Orlando in any file. **Richard the Lionheart** died in 1199, fourteen years before San Leo. **Brother Peter Catani**, Francis's first vicar general, shares the surname: coincidence only, and no file asserts a family relation.

---

## 9. Sources

**Reached and used**

- it.wikipedia, **'Santuario della Verna'**: the spring 1213 encounter; the Italian text of the offer; the chapel of 1216-1218 and the dream of the Virgin of the Angels; the first cell near the Sasso Spicco; 1260, 1263, 1348; the two Folchi canvases; coordinates.
- it.wikipedia, **'Chiusi della Verna'**: the 967 investiture; the 1261 Ubertini claim and the three brothers di Catenaia; the Tarlati chapel and the brushwood hut; coordinates.
- it.wikipedia, **'Cassero (Chiusi della Verna)'**: the rocca of Conte Orlando Cattani; the donation tradition; the Tarlati enlargement; the statement that no documentation of Orlando survives beyond the legend.
- it.wikipedia, **'San Leo (Italia)'**: the bare civic notice of 1213; coordinates.
- en.wikipedia, **'La Verna'**: the personal character of the gift; Orlando's help in financing; the Folchi pair and the 8 May caption; 1459.
- en.wikipedia, **'Francis of Assisi'**: 8 May 1213 as traditional date; the description of the mountain; the stigmata.
- **The Little Flowers of St Francis, Considerations on the Holy Stigmata, First Consideration**, CCEL edition, translation revised by Dom Roger Hudleston, O.S.B. Source of all eight quotations; treated throughout as **[R]**.
- This atlas's own files: `saint_francis.journey.json`, `michelangelo.journey.json`, `QUEUE.md`.

**Sought and not reached, with the reason**

- **Treccani, Dizionario Biografico degli Italiani**: no retrievable article text. The source most likely to fix his dates, parentage, and the Catenaia / Cattani question; its absence is the principal limitation of this dossier.
- **Latin primary text of the Actus beati Francisci**: not reached. Earlier attempts against franciscan-archive.org, Wikisource, Gutenberg, EWTN and documentacatholicaomnia.eu returned 404 or wrong-document errors. The CCEL English text was reached and is what the quotations rest on.
- **Any charter, notarial instrument, or account book** for 1213, 1216-1218, or 1274: **none found**. The whole evidential base is Franciscan sanctuary tradition plus one Aretine feudal notice of 1261 that may or may not concern the same man.

**Coordinate corrections.** Every pool coordinate for the three principal sites was wrong by 0.6 to 1.6 km, and San Leo carried two different wrong values in two lenses. Corrected values are inline above; San Leo and La Verna are inherited byte-identically from `saint_francis.journey.json`.
