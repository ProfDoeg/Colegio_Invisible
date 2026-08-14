# Egeria (Aetheria, Etheria): research report

*2026-08-13. Pilgrim, fl. 381-384. Author of the Itinerarium Egeriae, the earliest surviving first-person travel account by a Christian woman and the earliest eyewitness description of the Jerusalem liturgy.*

**Method.** Everything below is either **[A]** = attested in a named source, quoted or cited, or **[R]** = reconstruction, tradition, hypothesis, or inference. The primary text throughout is McClure and Feltoe, *The Pilgrimage of Etheria* (SPCK, 1919), the CCEL version, whose pagination is cited here. Where the research pool's first pass carried an error, the corrected reading is given and the error named.

The recurring problem: **the text is a torso.** The only full witness is an eleventh-century copy missing its opening leaves, its closing leaves, and at least two internal gatherings. Everything about the author outside that surviving middle comes from one letter written three centuries after her death.

---

## 1. Origin: a coastline instead of a birthplace

**Birth, family, status: unknown [A as a negative].** No source gives her birth date, parents, town, or rank. She is generally described as a well-educated Christian woman of means, since she travels with an official escort (Wikipedia, 'Egeria (pilgrim)'; Sivan, *HTR* 81, 1988). That is inference from the itinerary, not testimony.

**The Iberian case [R, on one attested clause].** Valerius of Bierzo describes her as *extremo occidui maris Oceani littore exorta*, "sprung from the farthest shore of the western sea, the Ocean" (1919, p. viii) **[A, the phrase itself]**. On that clause Marius Ferotin in 1903 placed her in Gallaecia and made her Valerius's countrywoman **[R]**.

**The Gallic case [R].** Karl Meister in 1909 objected that her Latin carries no Iberian Romance phonology and that her comparison of the Euphrates to the Rhone points to southern Gaul; he proposed a house in Gallia Narbonensis. Later scholars have floated Aquitaine, Arles, Normandy (Wikipedia; Encyclopedia.com).

> **Contradiction 1, not resolved.** Two scholars reach opposite conclusions from the same document, one from an external witness and one from internal philology, and no manuscript evidence adjudicates. Both pins are in the journey file, flagged as hypotheses rather than stops.

**Nun or laywoman? [R vs R].** Valerius calls her a nun **[A]**. Sivan (1988) argues this may be retrospective error, since devout laywomen were routinely addressed as "sisters," and the diary claims no vows **[R]**. The text does address *sorores* at home **[A]**, which fits either reading.

**Correction.** The pool dated Valerius's letter c. 650, "mid-7th century." Valerius lived c. 630-695 and wrote the *Vita vel epistola beatissimae Egeriae* **c. 680**, with Abbot Donadeus: a generation later than the pool's figure (Wikipedia; Encyclopedia.com; cc.owu.edu introduction). That introduction also notes the form **"Egeria"** comes from a Toledo manuscript of 902. Even the name is transmitted, not original.

---

## 2. Dating the journey

**Consensus: 381-384 [R, well-founded].** Paul Devos established this from internal evidence, notably 'La date du voyage d'Egerie', *Analecta Bollandiana* 85 (1967); the journey falls under Theodosius I. Devos separately dated her arrival at Edessa to April 384 ('Egerie a Edesse', same volume; Oxford *Cult of Saints* E05223).

**Minority view [R].** Meister (1909) placed the whole journey in the sixth century under Justinian. Not followed today, though it comes from the same scholar whose philology carries the Gallic origin theory.

> **Contradiction 2, not resolved.** Meister's dating is rejected while Meister's origin argument is still live. Nothing in the reachable literature explains why one half of his 1909 reading survives and the other does not.

**Consequence for the journey file.** Almost nothing in the Itinerarium is dated. Egeria gives weekdays, feasts, distances in miles and paces, and lengths of stay in days, and almost never a year. Every ISO date in `egeria.journey.json` is therefore a reconstruction, hedged in `date_confidence` per stop rather than smuggled into prose. Skeleton: Sinai December 382, Egypt January 383, the Jerusalem cycle across 383 into 384, the trans-Jordan excursion mid-383, the Epiphany octave of January 384, Easter 384 (24 March, Julian), Mesopotamia April 384 per Devos.

---

## 3. The Sinai leg

The surviving text opens **mid-sentence** on the approach across a great valley, with the mountain in view **[A]**. The translators mark the break: "(Much is wanting.)" (1919, p. 1) **[A]**.

All **[A]**, from the 1919 translation: Faran, thirty five miles short of the mount of God, two days' rest (ch. 1); the camp valley, sixteen miles long and four broad, with the golden-calf site, the graves of those who craved meat, and tent foundations pointed out (ch. 2, 5); the ascent "straight up the whole way, as if up a wall," monks and a resident priest at the summit, the cave of the second tablets (ch. 1-3); Elijah's cave and altar on the adjoining summit (ch. 4); the Burning Bush in a walled garden, alive and putting out shoots (ch. 4). *Correction: "We reached the mountain late on the sabbath" is on **p. 3**, not p. 2.*

**Corrections, geographic.** The pool's "Wadi al-Raha" pin (28.545 / 33.96) sits inside the massif southeast of St Catherine's; er-Raha lies northwest of it, c. **28.560 / 33.950**. Its Faran pin (28.6446 / 33.6363) is south of the settlement; the oasis is nearer **28.7092 / 33.3222**. More consequential: the pool called Faran a bishopric "by her time," but the see of Pharan is securely attested only from **451**, after her visit.

**Canonical pins inherited.** The summit uses **28.539 / 33.975**, byte-identical with `moses.journey.json`; the Burning Bush uses **28.5563 / 33.975**, byte-identical with `san_antonio_abad.journey.json` and `catherine_alexandria.journey.json`. Egeria is the strongest witness to the pre-Justinianic hermit community on ground those files date to 555-556.

---

## 4. Egypt, Goshen, the lost Thebaid

Return via **Clysma** (Suez), **Goshen**, **Rameses**, **Tatnis**, **Pelusium** **[A, ch. 7-9]**, keeping Epiphany at the **city of Arabia**, where the bishop detains her two days **[A, ch. 9]**.

**Correction, with a real find inside it.** The pool gave the bishop of Arabia in Egeria's "own words" as "an elderly, kindly monk-turned-bishop." Not her words, and the career note is imported. Ch. 9 reads: *"the holy bishop detained us there for some two days, a holy man and truly a man of God, well known to me from the time when I had been in the Thebaid."* That clause surfaces the largest gap in the dossier: **she had already been in the Thebaid**, and the account of it went with the missing opening leaves.

**Correction: Tatnis.** The pool made it "the city she is told Pharaoh's daughter called home." Egeria says it is *"the city where holy Moses was born"* and *"was once Pharaoh's metropolis"*: his own capital, not his daughter's house. Coordinates (Tanis / San el-Hagar, 30.9758 / 31.8800) hold; the identification stays **[R]**.

**Correction: Goshen pin.** The pool's 30.5522 / 32.1039 falls on the Suez Canal near Ismailia, east of Goshen proper. Corrected to **30.60 / 31.95**, the Wadi Tumilat and eastern Delta. **Gap:** Pelusium is dropped for stop-count reasons only; Alexandria and the Thebaid get no stop, since the surviving text describes neither.

---

## 5. Jerusalem: the three years and the liturgical core

She based herself in Jerusalem roughly three years, using it as a hub **[A, from the text; summarised in Wikipedia and Encyclopedia.com]**. The better-preserved second half of the diary is liturgical, which is why the text matters outside travel literature at all.

- Daily office at the **Anastasis**: cockcrow vigils, dawn office, sixth hour, ninth hour, lucernare; candles lit from a lamp inside the cave; the bishop entering the rock and blessing at the rail **[A, ch. 24]**.
- Sunday in **"the greater church, built by Constantine"** on Golgotha, gold, mosaic and costly marbles, every priest who wishes preaching, the bishop last **[A, ch. 25]**.
- **Lent**: "Just as with us forty days are kept before Easter, so here eight weeks are kept before Easter" (1919, **p. 57**) **[A]**, yielding forty one fast days once the eight Lord's Days and seven sabbaths come out. The *apotactitae* eat "neither bread which cannot be weighed, nor oil, nor anything that grows on trees, but only water and a little gruel made of flour" **[A]**.
- **Trilingual liturgy**: the bishop knows Syriac but preaches in Greek, a priest interprets into Syriac, a further relay of bilingual brothers and sisters serves the Latins (1919, **p. 94**) **[A]**.
- **Epiphany octave**, eight days across multiple sites, earliest detailed eyewitness description of the feast in the Holy Land; **Holy Week**, the Palm Sunday procession and the Good Friday veneration of the True Cross, both earliest-surviving; **dies enceniarum**, the September dedication feast, compared by her to Easter and Epiphany; **Sion**, Lenten Wednesdays and Fridays and Pentecost with Acts read in its place. All **[A]** (ch. 25-43; Encyclopedia.com).

**Correction, page citations.** Wrong page numbers in the quotes lens, fixed above and in the journey file: sabbath arrival p. 3 (not 2); Abgar letter p. 30 (not 60); Edessa arrival p. 32 (not 60); Lent p. 57 (not 90); the trilingual passage wholly on p. 94 (not 94-95).

**Correction: Bethlehem.** The pool said the basilica over the grotto was "dedicated within a decade of her likely visit." It was built c. 330-333 and consecrated **31 May 339**, some forty four years before a visit of c. 383.

**Correction: the Purification.** Flagged in the pool as an unverifiable floating paraphrase. It is locatable and rises to **[A]**, but only in the editors' wording: Introduction §10, pp. xxxvii-xxxviii, "This is the earliest extant notice of it," with Egeria's own passage at p. 56. Cited here and not in the journey file, since the stops are her ground and not her editors'.

**Canonical pins inherited.** The Anastasis uses **31.7784 / 35.2298**, byte-identical with `jesus.journey.json`; the Martyrium uses **31.7784 / 35.2297**, byte-identical with `constantino_el_grande.journey.json`. The two files pin one complex a ten-thousandth of a degree apart. Rather than silently pick one, both are inherited and assigned to the two buildings Egeria herself distinguishes.

---

## 6. The Jordan and the land beyond

Jordan crossing of the tribes and the altar of Reuben, Gad and half Manasseh **[A, ch. 10]**; **Livias**, camp foundations "still visible to this day," the six-mile detour to the rock Moses struck **[A, ch. 10, 12]**; **Mount Nebo** by donkey then on foot, the place of Moses's death, the view naming Esebon, Sasdra and Fogor **[A, ch. 11-12]**; **Segor**, "the only one of the five cities that exists to-day," the pillar of Lot's wife covered by the sea **[A, ch. 12]**; **Sedima** as Melchizedek's Salem **[A as her guides' claim, R as identification, ch. 13-14]**; **Aenon**, its pool, garden and living Easter baptisms **[A, ch. 15]**; **Thesbe**, Elijah's cave and the tomb of Getha **[A, ch. 16]**; **Carneas**, formerly Dennaba, in Ausitis, Job's tomb under a half-built church begun by a tribune **[A, ch. 16]**.

**Corrections, coordinates.** Four pins here were materially wrong. **Segor / Deir 'Ain 'Abata**: pool 31.0447 / 35.5372, 3.3 km east of the sanctuary; correct **31.0468 / 35.5027**. **Aenon**: pool 32.22 / 35.36 sat 2.2 km from Sedima, against Egeria's own "two hundred paces off"; moved to **32.2183 / 35.341**. **Thesbe / Listib**: pool 32.5 / 35.6167 pointed at empty country 19 km northwest; correct c. **32.3658 / 35.7183**. **Carneas / al-Shaykh Saad**: pool 32.7828 / 36.1919 sat 16 km southeast; correct **32.8358 / 36.035**.

---

## 7. Mesopotamia

Antioch, a week **[A, ch. 17]**; **Hierapolis** (Manbij) in Augustofratensis, "beautiful and wealthy," fifteen miles from the crossing **[A, ch. 18]**; the **Euphrates**, "huge and terrible," running "like the Rhone, though far larger," crossed by ship for want of a bridge **[A, ch. 18]**; **Batanis**, a bishop and martyr memorials **[A, ch. 19; the Batnae/Suruç identification is R]**; **Edessa**, three days **[A, ch. 19]**; **Harran** at the feast of Helpidius, 23 April, and **Fadana** six miles on **[A, ch. 20]**.

At Edessa she goes straight to the memorial of Thomas, "where his body is laid entire" **[A]**; the bishop, "a truly devout man, both monk and confessor," shows her the Abgar palace and statue and recounts the letter of Christ and the fountain that broke a Persian siege **[A]**. She reads aloud from an apocryphal text of Thomas, Gospel or Acts unsettled **[A that she read, open as to which, per Oxford *Cult of Saints* E05223]**.

**Identification [R].** The confessor bishop is generally taken to be **Eulogius of Edessa**, exiled to Egypt with Protogenes of Carrhae for resisting Arianism under Valens. The pool's source is weak (a web-search summary "consistent with standard prosopography"), so it stays **[R]**, unasserted in the campa.

> **Contradiction 3, flagged.** The pool's correction note assigns "monk and confessor" to "the bishop of Batanis/Edessa," ambiguous between two men; the chronology lens gives it to Edessa. The journey file follows Edessa. Verify against ch. 19 in the Latin before relying on it.

**Correction: Rebecca's camels.** The pool twice had Egeria shown "the well where Rebecca watered Abraham's servant's camels" or "Isaac's camels." She writes only: *"he deigned to take us to the well whence holy Rebecca used to fetch water."* The camels are a Genesis 24 harmonisation imported by the researcher, where they belong to the servant and not to Isaac. That clause is now the stop's quote. Everything else verifies: Abraham's house built into a church, scarcely a Christian in the city, the Helpidius feast on 23 April, the memorials of Nahor and Bethuel a mile off.

---

## 8. The return, and the break

Tarsus, already seen outbound **[A, ch. 22-23]**; **Hagia Thekla** outside Seleucia, two days, a walled enclosure of cells, the deaconess **Marthana**, "a very dear friend of mine," governing the virgins **[A, ch. 23]**; **Chalcedon** and the martyrium of Euphemia; **Constantinople**, the Church of the Apostles, and the stated intention to go on to Ephesus for the shrine of Saint John **[A, ch. 23]**.

**Correction: Chalcedon.** The pool had her halting "three days." Egeria gives no duration: "I arrived at Chalcedon, where I stopped on account of the famous martyr-memorial of S. Eufimia already well known to me from a former visit," and the next sentence has her crossing on another day. The three days were invented.

**Gap.** Whether she reached Ephesus is unknown, whether she returned home is unknown, when and where she died is unknown. The manuscript stops inside a sentence about a plan.

---

## 9. Transmission and afterlife

- The **Codex Aretinus** (Arezzo 405) was copied at **Monte Cassino in the eleventh century**, bound with Hilary of Poitiers on the Mysteries and fragments of his hymns **[A]**. Egeria occupies **folios 31-74**, three quaternions with one leaf gone from the middle gathering. *Correction: the pool's "37-page parchment codex" is unsupported and dropped.*
- Removed to Arezzo by **Ambrogio Restellini**, abbot 1599-1602 **[A]**. **Rediscovered 1884** by **Gian Francesco Gamurrini** at the Confraternity of Santa Maria dei Laici **[A]**; published 1887 and again "in a correcter edition" in 1888 (1919, p. vii) **[A]**.
- Gamurrini attributed it to **Silvia of Aquitaine**. *Correction: the pool called her a "6th-century noblewoman." Silvia is **fourth**-century, c. 330-406, sister of Rufinus, praetorian prefect under Theodosius and Arcadius, described by Palladius. The pool's afterlife lens had this right and its chronology lens had it wrong: a contradiction internal to the pool.* The phrase is verbatim on p. vii, so that tag rises from R to **[A]**. Note that McClure and Feltoe say **sister**, not sister-in-law, and on p. viii write "No one probably now adheres to the theory that Silvia was the pilgrim."
- **1903**: Ferotin identifies the author as Valerius's Egeria, journey 381-384 **[A]**. **2005**: Jesus Alturo identifies two further fragments, c. 900, Carolingian minuscule, independent of the Monte Cassino line **[A]**.
- Editions **[A]**: Franceschini and Weber, CCSL 175 (1965); Petre, SC (1948); Maraval, SC 296 (1982), which also prints Diaz y Diaz on the Valerius letter; Wilkinson, *Egeria's Travels* (1971, rev. 1999).
- **November 2022**: a sculpture honouring Egeria as the first documented woman pilgrim goes up at the Concheiros crossroads outside Santiago de Compostela **[A, La Voz de Galicia]**. Galician press calls her "la primera peregrina gallega" **[R, built on the contested Ferotin hypothesis]**. Her route never approached Santiago.

---

## 10. Interlocks with the existing atlas

Named in campa: `moses` (the camp valley and the summit, identical pin), `catherine_alexandria` and `san_antonio_abad` (the Burning Bush, whose monastery both files date to 555-556 on a pin she predates by 170 years), `constantino_el_grande` (the Martyrium, built 326), `jesus` (Golgotha and the Mount of Olives), `hypatia` (Alexandria, contemporary, no attested contact), `maimonides` and `ibn_battuta` (the same Jerusalem, eight and nine centuries on), `mary_magdalene` (the Gaulish shore Meister proposed as Egeria's home).

Not used: `saint_acacius` and `muhammad` carry the canonical Temple Mount pin, and the interlock lens tags Egeria's description of the ruined platform **[A]**, but I could not find that passage in the reachable translation. `richard_lionheart`, `molay`, `bernard_clairvaux`: genre inheritance, not intersection.

---

## Sources

**Primary text (reached, in full)**
- Egeria, *Itinerarium*, trans. M. L. McClure and C. L. Feltoe, *The Pilgrimage of Etheria* (SPCK, 1919), via CCEL. All chapter and page citations above are to this edition; its Introduction (pp. vii-viii, xxxvii-xxxviii) is itself the source for the Gamurrini, Silvia and Purification material, and for the Valerius clause in Latin and English.

**Scholarship (reached at second hand only)**
- Paul Devos, 'La date du voyage d'Egerie' and 'Egerie a Edesse', *Analecta Bollandiana* 85 (1967): cited through Wikipedia, Encyclopedia.com and Oxford *Cult of Saints*, **not read directly**. Hagith Sivan, *HTR* 81 (1988): **abstract-level only**. Marius Ferotin (1903) and Karl Meister (1909): known only through reference literature reporting their conclusions. **Neither original consulted.**

**Reference works**
- Wikipedia: 'Egeria (pilgrim)', 'Itinerarium Egeriae', 'Valerio of Bierzo', 'Monastery of St Lot'. Encyclopedia.com: 'Egeria, Itinerarium of', 'Valerio of Bierzo'. cc.owu.edu introduction (source for the 902 Toledo manuscript). Oxford *Cult of Saints*, E05223 (Edessa). Biblical Archaeology Society; Dallas Baptist University; Christian History Institute.

**Named as inaccessible or unverified (honest gaps)**
- **Maraval, SC 296 (1982)**, **Wilkinson, *Egeria's Travels* (1999)**, and **Franceschini and Weber, CCSL 175 (1965)**: the standard modern apparatus and the standard Latin text, none reachable in this pass. Any reading that turns on the Latin rather than the 1919 English should be checked against Maraval before it is treated as settled.
- **Eulogius of Edessa** as the confessor bishop: sourced only to a web-search summary, kept at [R], not asserted in the journey file.
- **Egeria on the Temple Mount**: asserted [A] by the interlock lens, not located in the 1919 translation, left unused.
- **The Thebaid journey**: irrecoverable. One clause in ch. 9 is the whole surviving record of it. **The outward journey, the ending, the internal lacunae**: gone with the manuscript, and no source recovers them or claims to.
