# Noah son of Lamech (Nuh): research report

*2026-08-14. Subject of the Genesis flood narrative (Genesis 5:28 to 9:29), of Quranic surahs 11, 29 and 71, and of a very large post-biblical geography of landing places, tombs and founded cities. Journey file: `noah.journey.json`, 8 segments, 45 stops.*

**Legend.** **[A]** = attested, source named. For a figure of this kind "attested" means *attested to a text*: the verse says it, and the verse is cited. It does not mean the event is documented historically, and this report never uses it in that second sense. **[R]** = reconstruction, tradition, exegesis or later legend, always with its carrier named.

---

## 0. What kind of subject this is, and how the tagging works

Noah has no documentary record of any kind: no inscription, no archive, no contemporary reference, no archaeology. Everything in the journey file descends from four bodies of material, each quotable and datable as a *text* even where the events it reports are not datable at all: **Genesis 5-10** (KJV and NRSVUE) **[A to text]**; **the Quran**, principally 11:40, 11:44 and 29:14, plus the tafsir built on them (**[A]** for verses, **[R]** for exegesis); **Jubilees** (Charles) and **Josephus**, *Antiquities* I.3 (Whiston) **[A to text]**; and the **post-biblical afterlife** of local traditions, medieval geographers, nineteenth-century travellers, twentieth-century pseudoarchaeology and a 2016 replica, mixed **[A]** and **[R]**.

**Absolute dates are all reconstruction.** The Genesis text gives ages, not years: Noah is 182 years after Lamech's birth, 500 at the birth of his sons, 600 at the flood, 950 at death. Every BC year in the journey file derives from Ussher's flood date of 2349 BC and is tagged accordingly in `date_confidence`. **Correction to the research pool, recorded here:** the pool cited Ussher's *Annals of the World* for a birth year of 2949 BC. Ussher's published chronology as summarised in reference works gives Creation 4004 BC, the Flood 2349 BC and Terah's birth 2127 BC, and states no year for Noah's birth. 2949 BC is 2349 + 600, a derivation, not a quotation. The journey file says so in the first stop's `date_confidence`. **[R]**

**Month and day numbers** (for example `-2349-02-17`) transpose the text's own "second month, seventeenth day" into ISO fields. The underlying reckoning is lunar and its new-year anchor disputed; the transposition is a display convention, flagged at each affected stop.

---

## 1. Birth and naming

- Lamech fathers Noah at 182 and names him for rest, saying "this one shall bring us relief from our work and from the toil of our hands," the ground being under the curse of Genesis 3. **[A: Genesis 5:28-29, NRSVUE]**
- No birthplace is given anywhere in the text. **Gap.** The file pins the pre-flood stops to the Great Mosque of Kufa (32.0286, 44.4008), which is the *Islamic tradition's* ark-construction site and not a birthplace claim; the hedge is carried in `date_confidence`. **[R]**
- **Correction to the pool:** the Kufa mosque is at 32.02861 / 44.40083, about 400 m south of the pool's 32.0322; the corrected value is used throughout. The pool also credited al-Tabari and Ibn Kathir for the Kufa ark tradition, where the cited pages credit **al-Masudi (d. 956)** and Shia tradition generally. The file follows al-Masudi. **[R]**

## 2. The hundred and twenty years

- Genesis 6:3: "his days shall be an hundred and twenty years." **[A: Genesis 6:3]**
- Rashi (11th c.) reads this as a grace period for repentance rather than as a lifespan, which places the start of the ark's construction near Noah's 480th year. **[R: Rashi on Genesis 6:3]** This is exegesis, and the file tags it as such; the text itself gives no construction start.

## 3. The sons

- At 500, Noah fathers Shem, Ham and Japheth. **[A: Genesis 5:32]**
- **Correction to the pool.** The pool claimed Jubilees 4:33 gives a son-order "differing in detail from the Genesis order." It does not: 4:33 concerns Noah's *marriage* to "Emzara, the daughter of Rakeel, the daughter of his father's brother." The son order matches Genesis; what diverges is that Jubilees dates each birth separately where Genesis gives one age for all three. The file states this accurately. **[A: Jubilees 4:33, Charles]**
- Noah's wife is unnamed in Genesis. Jubilees names her Emzara. **Gap in Genesis, filled only by Jubilees.**

## 4. The ark

- Specification: gopher wood, rooms, pitch within and without, 300 x 50 x 30 cubits, a door in the side, three decks. **[A: Genesis 6:14-16]**
- Josephus gives the ark **four** stories against Genesis's three. **[A: Josephus, Antiquities I.3]** **Contradiction flagged, not resolved.** The file states both counts in one campa and chooses neither.
- The animal instructions contradict each other inside the received text: two of every kind (Genesis 6:19-20) against seven pairs of every clean animal and bird, one pair of the unclean (Genesis 7:2-3). **[A, both]** Scholarship attributes this doubling, and the 40-days / 150-days doubling, to Priestly and Yahwist material combined. **[R: standard source criticism]** **Not resolved here**, and left standing in the campa.
- Construction site: Kufa, under the later Great Mosque. **[R: Shia tradition; al-Masudi]** Not Quranic.

## 5. The flood

- Onset: 600th year, second month, seventeenth day; fountains of the great deep burst, windows of heaven open, rain forty days and nights. **[A: Genesis 7:6, 7:11-12]**
- The Quranic sign is different in kind: water gushing from a *tannur*, an oven. **[A: Quran 11:40]** The oven's location in Kufa is exegesis **[R]**, and the file carries the Kufa pin with that hedge stated, where the pool had tagged the stop **[A]** while attaching an **[R]** coordinate.
- Entry of the eight, the covering of the mountains by fifteen cubits, the blotting out of all flesh, the 150 days, and "God remembered Noah" with the wind over the waters: **[A: Genesis 7:13, 7:17-24, 8:1-3]**
- **The Mecca detour.** Al-Masudi has the ark sail from Kufa to Mecca, circle the Kaaba, then travel to Mount Judi. **[R]** **Correction to the pool:** the pool said "seven times" and credited al-Tabari and Ibn Kathir. The source has no count (seven looks imported from the tawaf ritual) and names al-Masudi. The file says "circle the House" without a number. The Kaaba pin is inherited byte-identical: **21.4225, 39.8262**.

## 6. The landing, and the two mountains

This is the sharpest contradiction in the dossier and the file does not resolve it.

- **Genesis 8:4** says the ark rested "upon the mountains of **Ararat**" in the seventh month, on the seventeenth day. The Hebrew names a **region** (Urartu), not a peak. **[A]**
- The identification of that region with the specific summit now called Mount Ararat is **Armenian, from about the eleventh century CE**, reported to Latin Europe by **William of Rubruck** in the thirteenth. **[R: Wikipedia, "Mount Ararat," citing the medieval Armenian tradition and Rubruck]**
- **Quran 11:44** says the ark settled on **al-Judi**, identified with Cudi Dagi above the Tigris in Sirnak province, and the Syriac churches held the same identification before the Quran. **[A to the Quranic text; R for the peak identification]**
- The two traditions are geographically incompatible, roughly 200 km apart, and no source harmonises them. Both are pinned in the journey file, at the same date, as consecutive stops.
- **Correction to the pool:** the pool tagged the Genesis 8:4 landing **[A]** while attaching the Ararat summit coordinate its own next entry conceded is eleventh-century. The file keeps the pin, because a map needs one, and moves the hedge into `date_confidence`.
- **Jubilees 5:28 and 7:1** name the landing mountain **Lubar**, one of the mountains of Ararat. **[A to Jubilees]** No one has identified Lubar with any modern peak. **Gap.** The journey file names Lubar in the altar stop and gives no separate coordinate for it.

## 7. The birds and the drying

All **[A: Genesis 8:5-14]**: mountain tops visible on the first day of the tenth month; the raven after forty more days; the dove returning; the dove with the olive leaf seven days later; the third dove that does not return; the covering removed on the first day of the first month of the 601st year; the earth dry on the twenty-seventh day of the second month.

**Chronology note.** The pool dated the raven and dove episodes to 2348 BC, which breaks travel order: they fall in the eleventh and twelfth months of Noah's **600th** year. The file dates them `-2349-11-10` through `-2349-12-01`, then `-2348-01-01` for the covering, and states the reckoning in `date_confidence`.

## 8. Altar, covenant, and the bow

- The altar of every clean beast and fowl, the pleasing savour, and the resolution never again to curse the ground: **[A: Genesis 8:20-22]**
- Josephus adds that Noah "besought God that nature might hereafter go on in its former orderly course." **[A: Josephus, Antiquities I.3]**
- Blessing, dominion, the grant of meat with the blood prohibition, capital sanction for murder: **[A: Genesis 9:1-7]**
- The covenant with all flesh and the bow in the cloud: **[A: Genesis 9:8-17]**

## 9. The vineyard, the tent, the curse

- Noah plants a vineyard, becomes drunk, lies uncovered; Ham sees and tells; Shem and Japheth cover him walking backward; Noah curses **Canaan**, not Ham. **[A: Genesis 9:20-27]** Genesis names **no place** for any of it. **Gap.**
- Armenian tradition places the first vineyard at **Akhuri / Arghuri** on Ararat's north-eastern slope, glossing the village name from the Armenian for "he planted the vine" (an etymology recorded by Friedrich Parrot), and the vines there were shown to nineteenth-century travellers as Noah's stock. **[R]**
- **Correction to the pool:** the pool gave Akhuri as 39.7717 / 44.465, roughly 8 km too far east. The village (modern **Yenidogan**, Aralik district, **Igdir** province, not Agri) sits near **39.7667 / 44.3667**, about 1,743 m. The corrected value is used, and `date_confidence` states that Genesis supports no location here at all.
- **John Chrysostom** (4th c.) excuses the drunkenness on the ground that Noah was the first human to taste wine. **[R: patristic exegesis]**

## 10. Nations, and the death

- Genesis 10, the Table of Nations, derives seventy peoples from the sons. **[A]**
- Noah lives 350 years after the flood, dying at 950. **[A: Genesis 9:28-29]** **No burial place is given.** **Gap**, and three rival tombs are built into it (section 12).
- **Quran 29:14** gives Noah "a thousand years, less fifty" **among his people before the flood**, which in Islamic tradition denotes his pre-flood ministry. Genesis uses the same 950 as a **total** lifespan including 350 post-flood years. **Contradiction flagged, not resolved.** **[A, both texts]**
- A rabbinic synchronism puts Noah's death at Terah's 128th year. **[R]** Not used as a pin.

## 11. The older flood

The Mesopotamian flood hero **Utnapishtim** of Gilgamesh Tablet XI shares the divine warning, the pitched vessel, the released birds and the mountain landing. The epic reached something like its known form c. 1300-1000 BCE on older Sumerian material (the Ziusudra tradition, attested by c. 1600 BCE); Tablet XI survives from Ashurbanipal's library at Nineveh. **[R: comparative Assyriology, which debates priority and does not equate the figures]** The file pins this at Nineveh (36.3599, 43.1525). **Stated honestly:** that is the tablet's find-site, not a Noah location, and the choice is this file's, not the pool's.

## 12. Afterlife: three graves, two cities, one mountain, and a hillside

- **Nakhchivan** (Azerbaijan) as the place of first descent, its name folk-derived as "first descent," with a mausoleum shown as Noah's tomb (rebuilt in the 2000s, photographed 1902). **[R]** Josephus records that Armenians call the site "the Place of Descent" and show the ark's remains there. **[A to Josephus]**
- **Cizre** (Jazirat ibn Umar, Sirnak) as the *second* city Noah founded, resting entirely on the Judi identification. **[R]** **Corrections to the pool:** coordinate 37.332 / 42.187, not 37.3219 / 42.1928; and the recorder is **al-Harawi**, who died in 1215, so the recording is late 12th or early 13th century, **not** 9th as the pool asserted.
- **Karak Nuh** (Zahle, Bekaa, Lebanon): a long stone chamber venerated as Noah's tomb, with fourteenth-century inscriptions, kept chiefly by Shia Muslims but visited by Melkites and Maronites; scholarly assessment reads it as a stretch of Roman aqueduct. **[R, both readings]** **Contradiction flagged, not resolved.** A second contradiction sits inside the reference source: the "Zahle" article gives 40 m, the "Karak Nuh" article 31.9 m. The file says "more than thirty metres," true on either reading, rather than silently averaging. Coordinate corrected to 33.85 / 35.9264.
- **Mount Ararat itself**: the monastery of St Hakob at about 1,943 m, base camp for **Friedrich Parrot's first recorded ascent, 9 October 1829**, destroyed with the village of Akhuri by the earthquake and landslide of **20 June 1840**. **[A]** **Correction to the pool:** the monastery stands near 39.76 / 44.37, not the pool's 39.71 / 44.3, which sits about 6 km off, high on the mountain.
- **Sighting claims**: about 200 claimants from over 20 countries since 1856, no physical evidence, classed as pseudoarchaeology. **[A]**
- **Durupinar**: a 164 m boat-shaped limonite-and-magnetite formation on Mount Tendurek, 29 km south of Ararat and 3 km from the Iranian border, exposed by rain and earthquake on **19 May 1948** and first noticed by a Kurdish shepherd, **Reshit Sarihan**; **identified in NATO aerial photographs by Captain Ilhan Durupinar in October 1959** (the pool said he "formally surveyed" it, which the source does not support); ground-investigated **September 1960** by the Archaeological Research Foundation, which found no archaeological remains. Promoted from 1977 by Ron Wyatt, joined in 1985 by David Fasold and John Baumgardner; a **1996 study co-authored by Fasold and geologist Lorence Collins** called it a doubly plunging syncline, and Fasold recanted under oath in 1997. **Andrew Snelling**, a young-earth creationist geologist, reached the same verdict separately. **[A]** **Correction to the pool:** the pool listed the 1996 study and Collins as two independent lines of evidence; they are one.
- **Ark Encounter**, Williamstown, Kentucky, opened **7 July 2016** (date chosen to echo Genesis 7:7): 510 x 85 x 51 ft, c. 3.3 million board feet, 132 bays, three decks. **[A]**
- **Armenian folklore attached to the same mountain and unconnected to Noah**: vishaps battling every two years, and King Artavazd II chained in a cave with dogs licking at the chains while blacksmiths strike anvils to renew them. **[R]** Afterlife of the *mountain*, not of Noah, and deliberately kept out of the journey file.

---

## 13. Contradictions carried, not resolved

1. **Two of every kind (Gen 6:19-20)** against **seven pairs of the clean (Gen 7:2-3)**, in one narrative.
2. **Forty days** of rain against **a hundred and fifty days** of prevailing water.
3. **Three decks (Genesis)** against **four stories (Josephus)**.
4. **Mount Ararat** against **Mount Judi**: Christian-Armenian against Quranic-Syriac, some 200 km apart.
5. **Mount Lubar (Jubilees)**, a third named landing mountain, unlocated.
6. **950 years as total lifespan (Genesis)** against **950 years of pre-flood preaching (Quran 29:14)**.
7. **Three tombs** (Nakhchivan, Karak Nuh, Cizre) and **two founded cities**, each dependent on a different landing mountain.
8. **Karak Nuh**: tomb against Roman aqueduct span, plus the 40 m / 31.9 m discrepancy between two reference articles.
9. **Durupinar**: geologists who agree on nothing else about the earth's age agree it is natural, against the popular ark claim.

## 14. Gaps stated as gaps

- **No birthplace**, no homeland name, no city, no river named for any pre-flood event. The Kufa pin is Islamic tradition doing work Genesis declines to do.
- **No shipyard** in Genesis, no dimensions for the door, no account of provisioning.
- **Noah's wife is unnamed** in Genesis and the Quran. Only Jubilees names her, Emzara.
- **No burial place** anywhere in Genesis or the Quran.
- **Mount Lubar is unidentified.** No modern peak carries the name.
- **No archaeology at any site.** Not a plank, not a fastening, not a photograph that survives inspection, in 170 years of searching.
- **The absolute chronology is derivative throughout**, and Ussher gives no birth year for Noah.

## 15. Interlocks

Named inside campa text, on the rule that only a real relation earns a name:

- **Kircher** (Rome, 1675 and 1679). *Arca Noe* reconstructs the ark plank by plank with stalls, fodder and cutaway decks; *Turris Babel* runs every nation and language back to the sons of Noah. A commentator writing substantively about the subject, one-directionally, across four thousand years.
- **Abraham** (Mecca stop). Descent through Shem, per Genesis 11:10-26, and a shared node: Abraham raises the Kaaba's foundations at the same pin the ark tradition has the vessel circle. Family relation, not co-location.
- **Hiram Abiff** (Graham Manuscript, 1726). The manuscript has Noah's sons raise their father's body by grip and by word; later Masonic readers make it the ancestor of the Hiramic raising. The campa says the equation is the readers', not the manuscript's.

**Rejected as mere co-location**, despite appearing in the interlock pool: Benjamin of Tudela, Gurdjieff, Hannibal, Saint Acacius, Saint Eustace, Nebuchadnezzar II, Genghis Khan, Evliya Celebi. Every one shares a mountain or a river valley with Noah and nothing else, and the map already shows a viewer that much.

**Corpus note:** no existing file carries Noah, the ark or the flood as its own subject; all prior Noah and Ararat material is backdrop inside other travellers' files.

---

## Sources

**Reached and used**

- Genesis 5:28-29, 5:32, 6:1-22, 7:1-24, 8:1-22, 9:1-29, 10 (King James Version and NRSVUE, via biblegateway.com)
- Quran 11:40, 11:44, 29:14 (Sahih International and Mustafa Khattab, The Clear Quran, via quran.com)
- Flavius Josephus, *Antiquities of the Jews*, Book I, ch. 3, William Whiston translation (Project Gutenberg)
- Book of Jubilees 4:33, 5:28, 7:1, R. H. Charles translation
- Rashi, commentary on Genesis 6:3 (via secondary summary)
- John Chrysostom on Noah's drunkenness (via secondary summary)
- Wikipedia: "Mount Ararat", "Noah", "Noah in Islam", "Noah's Ark", "Genesis flood narrative", "Great Mosque of Kufa", "Yenidogan, Aralik", "Cizre", "Ali of Herat", "Nakhchivan (city)", "Karak Nuh", "Zahle", "Durupinar site", "Ark Encounter", "Ussher chronology"
- Files consulted for interlock: `kircher.journey.json`, `abraham.journey.json`, `hiram_abiff.journey.json`

**Named but not reached directly** (used only through summary, and flagged as such wherever cited)

- al-Masudi, *Muruj al-Dhahab*: the Kufa-to-Mecca-to-Judi voyage, quoted from reference-work summary, not from the Arabic or a translation. al-Harawi, *Kitab al-Ziyarat* (the Cizre tradition): likewise summary only.
- al-Tabari, *Ta'rikh*, and Ibn Kathir, *Qisas al-Anbiya*: **checked and rejected as attributions.** The pool credited both for the Kufa and Mecca material; the reachable sources name al-Masudi instead. Neither work was consulted here, so no claim rests on them.
- James Ussher, *Annals of the World* (1650): not consulted in the original. Only the summary of his three anchor dates was reachable, and it gives no birth year for Noah, which is why 2949 BC is tagged a derivation.
- Gilgamesh Tablet XI in a scholarly edition (Andrew George, *The Babylonian Gilgamesh Epic*): not reached. The parallel is carried at the level of comparative summary only, and the file makes no claim about textual priority.
- Rashi and Chrysostom in their own editions: not reached, cited from summaries, tagged **[R]**.
