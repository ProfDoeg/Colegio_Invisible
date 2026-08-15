# Aaron the Levite, son of Amram: research report

*Subject of `aaron.journey.json`. Traditional dates c. 1394-1273 BC in the rabbinic reckoning used across this corpus; c. 1529-1406 BC on the 1 Kings 6:1 reckoning. 44 stops, 9 segments.*

**Legend.** **[A]** = attested in a named source. **[R]** = reconstruction, tradition, inference, or conjecture. Contradictions are flagged and left unresolved. Gaps are recorded as gaps.

**Stated once and not repeated below.** No archaeological find, inscription, or extra-biblical text of any period independently attests Aaron as a historical individual. Everything here derives from the Hebrew Bible, later Jewish tradition, Josephus, the Quran, or the veneration history of a mountain in southern Jordan. Where a claim below is marked **[A]**, the attestation is textual: the named book says this. It is not a claim that the event occurred. The journey file's register narrates the canon on its own terms rather than adjudicating it.

---

## 1. Chronology: which one this file uses, and why

Two internally consistent chronologies are in play, differing by roughly 133 years. **The 1 Kings 6:1 reckoning [R]** begins Solomon's temple 480 years after the Exodus, yielding an Exodus of c. 1446 BC; Aaron, 83 before Pharaoh (Exodus 7:7 **[A]**), is then born c. 1529 BC and dies at 123 c. 1406 BC (Numbers 33:39 **[A]**). **The rabbinic reckoning (Seder Olam Rabbah) [R]** puts the Exodus in 2448 AM, conventionally rendered 1313 BC, with Aaron born c. 1394 BC and dead 1273 BC.

This file follows the **rabbinic reckoning**, for one reason: `moses.journey.json` already runs on it (burning bush at -1313-01-15, Mount Hor at -1273), and the two lives are the same events seen from two sides. Using 1446 BC here would put brothers standing at the same rock on the same day 133 years apart on the map. The hedge sits in every `date_confidence` field rather than in prose. **Flagged:** the pool's chronology lens gave c. 1529 BC for the birth while its geography lens gave "c. 1400s BCE" for the same event, a contradiction resolved here only by adopting a third, labelled convention.

Nothing in the Torah supplies a calendar year for anything in Aaron's life. What it does supply, treated as **[A]** internal dating, is a set of relative dates: the 15th of the first month for the departure from Rameses (Numbers 33:3), the 15th of the second month for the wilderness of Sin (Exodus 16:1), the 1st of the first month of year two for the raising of the tabernacle (Exodus 40:17), the 20th of the second month of year two for leaving Sinai (Numbers 10:11), and the 1st of the fifth month of the fortieth year for Aaron's death (Numbers 33:38).

---

## 2. Birth and household in Egypt

- Son of **Amram and Jochebed**, of the tribe of Levi **[A: Exodus 6:20]**.
- **Three years older than Moses**: Aaron 83, Moses 80, before Pharaoh **[A: Exodus 7:7]**. The gap is arithmetic from that verse, not a separate statement.
- **Born in Goshen [R].** Exodus nowhere states Aaron's birthplace; Goshen is an inference from Genesis 47:27. The pool carried this as **[A]**; corrected to **[R]**. The pin (30.57, 31.95) is inherited from the corpus rather than derived; identifications of Goshen scatter over 30-40 km of the eastern Delta (Wadi Tumilat near 30.5N vs. Faqus/Tell el-Dab'a near 30.73N), and Wikipedia's point is 30.8722, 31.4775. **Spread flagged, not adjudicated.**
- **Aaron was not subject to Pharaoh's drowning decree [R].** The tradition places the decree in the year of Moses's birth, three years after Aaron's. **Source correction:** the pool cited Rashi on Exodus 2:2, which comments on Moses being born after six months and a day and says nothing of Aaron. The tradition rests on **b. Sotah 12a** and **Exodus Rabbah 1:13**, with **Seder Olam Rabbah** supplying the interval.
- **Married Elisheba, daughter of Amminadab, sister of Nahshon** (prince of Judah, Numbers 2:3); four sons, **Nadab, Abihu, Eleazar, Ithamar [A: Exodus 6:23]**.
- **Gap.** Nothing at all is recorded of Aaron between birth and age 83: no childhood, no trade, no call, no marriage date. Elisheba is named once and never appears again, with no death notice and no line of speech. The file dates the marriage to -1360 by narrative position only, and says so in `date_confidence`.

---

## 3. Spokesman: from Horeb to the tenth plague

- At the bush, God tells Moses that Aaron is already coming, will be glad, and will be his mouth **[A: Exodus 4:14-16]**; Aaron meets him at the mountain of God and kisses him **[A: Exodus 4:27]**. The identification of that mountain with Jebel Musa is traditional **[R]**; the text does not name the peak here.
- Aaron speaks to the elders and performs the signs; the people believe **[A: Exodus 4:29-31]**.
- Before Pharaoh at 83 **[A: Exodus 7:7]**; designated "thy prophet" **[A: Exodus 7:1-2]**. The court's location is **[R]**: Pi-Ramesses at Qantir is the leading candidate, never named in Exodus. Psalm 78:12, 43 sets the wonders "in the field of Zoan" (Tanis) instead, either a different city or poetic shorthand for Egypt; **flagged, not resolved**, and Zoan is omitted from the journey file because Aaron is not named in the psalm.
- The rod becomes a serpent and swallows the magicians' rods **[A: Exodus 7:9-12]**.
- **Plague count corrected.** The pool's claim that Aaron acts in the first three plagues and Moses alone thereafter is wrong. Aaron's rod brings blood, frogs, and lice **[A: Exodus 7:19-20; 8:5-6; 8:16-17]**, and at the sixth both brothers take ashes of the furnace, Moses throwing them **[A: Exodus 9:8-10]**. Aaron acts in **four** plagues, and the file says so.
- Passover instructions are addressed to Moses **and Aaron** jointly **[A: Exodus 12:1, 12:43]**.

---

## 4. The Exodus itinerary and its coordinates

Every wilderness site below is an **[R]** identification. The Torah names the stations, does not locate them, and no station between Egypt and Edom has been archaeologically confirmed as such. The pool's geography lens contained four coordinate errors, corrected in the journey file by adopting the corpus's canonical interlock pins:

| Station | Pool coordinate | Used here | Reason |
|---|---|---|---|
| Pi-hahiroth | 29.8664, 32.4372 | **29.877, 32.658** | Pool point ~21 km west, in the Gulf of Suez; Ayun Musa, which its label names, is at 29.877, 32.658 |
| Marah | 29.1667, 33.0833 | **29.39, 33.06** | ~25 km southeast of the traditional Ain Hawarah |
| Elim | 29.05, 32.9167 | **29.3, 32.9667** | ~28 km south of the traditional Wadi Gharandel |
| Kadesh-barnea | 30.6889, 34.4181 | **30.664, 34.418** | Tell el-Qudeirat is at 30.6425, 34.4136; corpus pin adopted |

Events on the road, all **[A]** as text: Succoth and Etham (Exodus 12:37, 13:20; Numbers 33:5-6), Etham omitted from the file as having no Aaron content and no identifiable location; the crossing at Pi-hahiroth, credited to Moses's hand (Exodus 14:21-22); Marah (15:22-25); Elim's twelve springs and seventy palms (15:27); the murmuring in the wilderness of Sin, where Aaron speaks to the congregation and the glory appears in the cloud (16:1-15); Rephidim, where Aaron and Hur hold up Moses's hands until sundown (17:10-13).

---

## 5. Sinai: the theophany, the calf, the vestments

- Aaron ascends with Nadab, Abihu, and seventy elders; they see the God of Israel and eat and drink **[A: Exodus 24:1, 9-11]**.
- The vestments are commanded: ephod, breastpiece with Urim and Thummim, robe, turban with the gold plate, tunic, sash **[A: Exodus 28]**.
- **The golden calf [A: Exodus 32:1-6].** Aaron collects the earrings, fashions the calf, builds the altar, proclaims the festival to the LORD.
- **Correction to the pool.** Its geography lens attributed the burning, grinding, and forced drinking of the calf to Aaron. **Exodus 32:20 attributes all three to Moses**, and Aaron's part ends at 32:6. The pool's chronology lens had this right and its geography lens wrong; the file follows Exodus.
- Aaron's defense: the people are set on mischief, he cast the gold into the fire, "there came out this calf" **[A: Exodus 32:22-24]**. A plague follows **[A: Exodus 32:35]**, and Moses says later that the LORD was angry enough with Aaron to destroy him **[A: Deuteronomy 9:20]**.
- **Gap:** Exodus never says whether Aaron was punished for the calf, never has him repent, and gives him the high priesthood in the following chapters without comment.

---

## 6. The priesthood

- **Ordination, seven days [A: Leviticus 8; commanded Exodus 29:1-9]**: washing, vesting, anointing, and the blood of the ram on the right ear, thumb, and big toe of Aaron and his sons.
- **Dating corrected.** The pool placed the ordination on "1st day of the first month, year 2." Exodus 40:17 gives that date to the **raising of the tabernacle**, so Leviticus 8 must precede it. Rabbinic chronology (Rashi on Leviticus 9:1, following Seder Olam) runs the ordination 23-29 Adar, with the eighth day falling on 1 Nisan **[R]**. The file dates them -1312-03-23 and -1312-04-01, with the hedge in `date_confidence`.
- **The eighth day [A: Leviticus 9]**: Aaron blesses the people, fire consumes the offering. **Nadab and Abihu [A: Leviticus 10:1-3]**: strange fire, consumed, "Aaron held his peace."
- **The sobriety law [A: Leviticus 10:8-11]**, addressed to Aaron directly, one of very few divine speeches in the Torah made to him alone; then his answer to Moses over the uneaten sin offering **[A: Leviticus 10:19]**.
- **The Levites given to Aaron and his sons [A: Numbers 3:1-10]**, dated by Numbers 1:1 to the first day of the second month of year two **[A]**.

---

## 7. The quarrels of the wandering

- **Hazeroth [A: Numbers 12:1-15].** Miriam and Aaron speak against Moses over the Cushite wife and over prophecy; Miriam alone is struck leprous; Aaron pleads. **Gap:** no reason is given for why only Miriam is punished. The file states the asymmetry and does not explain it.
- **Kadesh, the spies [A: Numbers 13-14].** Moses and Aaron fall on their faces (14:5); the forty-year sentence follows (14:34).
- **Kadesh geography, flagged.** Numbers 13:26 puts Kadesh in the wilderness of **Paran**, Numbers 20:1 in the wilderness of **Zin**. Ibn Ezra and Nahmanides resolved this by positing two Kadeshes **[R]**. Not adjudicated; one pin is used.
- **Korah [A: Numbers 16:1-3, 31-35].** The earth swallows Korah, Dathan, Abiram and their households; fire consumes the 250. **Qualification:** Numbers 26:11 states flatly that "the sons of Korah did not die," and the Korahite line survives as Temple singers (Psalms 42, 44-49, 84-85, 87-88 superscriptions) **[A]**. Carried in the campa.
- **The censer [A: Numbers 16:41-50].** Aaron stands between the dead and the living; 14,700 dead.
- **The budding rod [A: Numbers 17:1-11].** **Pin corrected:** the pool placed this at Sinai (28.5717, 33.9833), some 250 km from where the same lens places Korah, whom the episode directly follows; Israel left Sinai in Numbers 10:11. Pinned here at Kadesh (30.664, 34.42).
- **Covenant of salt, no land inheritance [A: Numbers 18:8-20]**.

---

## 8. Death, and the contradiction about where

- **Miriam dies at Kadesh [A: Numbers 20:1]**, "in the first month." **Correction:** the verse gives **no year**. The fortieth year is inferred from the Numbers 33 itinerary and Seder Olam Rabbah 9, so this is **[R]** on the year and **[A]** only on month and place; the pool tagged it flat **[A]**.
- **Meribah [A: Numbers 20:2-13].** Moses strikes the rock; both brothers are condemned. One reason is given for two men, and what Aaron did is never specified.
- **Edom refuses passage [A: Numbers 20:14-21].** No waypoint is named between Kadesh and Mount Hor; the file's 30.5, 34.9 is an explicit approximation **[R]**.
- **Mount Hor [A: Numbers 20:22-28]**: the vestments stripped, Eleazar clothed, Aaron dead on the summit, aged 123 on the first day of the fifth month of the fortieth year **[A: Numbers 33:38-39]**, kept by tradition as the first of Av **[R]**. Thirty days of mourning **[A: Numbers 20:29]**.
- **The contradiction, flagged and left standing.** **Deuteronomy 10:6 [A]** says Aaron died and was buried at **Moserah**, not Mount Hor, while Numbers 33:30-31 lists **Moseroth** as a separate station reached many camps *earlier* than Mount Hor. The Torah harmonizes neither account. Moserah is unidentified on the ground; the file pins it at 30.6, 34.45 as an admitted rough placement in the Kadesh-to-Hor corridor, and gives it its own stop so the map shows two graves rather than silently choosing one.
- **Mount Hor as Jabal Harun [R]**, post-biblical and traceable to Josephus. A minority of 19th- and 20th-century biblical geographers located Mount Hor near Kadesh-barnea instead (Jebel Madeira and others), arguing the Numbers 20 itinerary fits a site closer to Kadesh than to Edomite Petra **[R: Anchor Bible Dictionary, "Hor, Mount"]**. Not adjudicated; the file uses the Jabal Harun pin because `moses.journey.json` already does.

---

## 9. Afterlife: text, shrine, and legend

- **Josephus [A: Antiquities IV.4.7, c. 93-94 CE]** elaborates the ascent and names the mountain as the one enclosing Petra: the earliest surviving text tying Aaron's tomb to that region, and the root of everything else in this section.
- **Pirkei Avot 1:12 [A, Mishnah redacted c. 200 CE]**, the saying of Hillel, expanded in Avot de-Rabbi Natan and later midrash into a body of legend about Aaron reconciling quarreling spouses and neighbours **[R]**.
- **Death by the kiss (mitat neshika) [R: b. Bava Batra 17a]**; **the clouds of glory departing at his death [R: b. Taanit 9a]**.
- **The rod inside the ark [A as text: Hebrews 9:4]**, with the manna jar and the tables, against Numbers 17:25 which places it *before* the testimony. **Gap:** the rod's fate after the ark's disappearance is unrecorded.
- **Byzantine complex on Jabal Harun [A].** Church, chapel, hostel, and cisterns, excavated by the Finnish Jabal Harun Project, indicating Christian veneration by the fifth or sixth century. **Two corrections.** (1) The phrase "the House of our Lord the Saint High-Priest Aaron," dated 573 CE, comes from the **Petra Papyri**, not from the Antoninus of Piacenza itinerary (c. 570 CE), which does not use the formula. (2) The monastery sits on the **saddle west of the summit**, not on the peak; the pool's coordinates (30.3037, 35.4681 and 30.3011, 35.4692) misplace it and the shrine by 6-7 km into the Wadi Musa basin. The file uses 30.317, 35.407 throughout.
- **Mamluk shrine [A as structure; patron R and probably impossible].** The pool dated the white domed building 1458-1459 and credited sultan **Qaitbay**, who reigned only from 1468; the sultan in 1459 was al-Ashraf Inal (r. 1453-1461). Wikipedia dates the structure only to "the Mamluk period" with no patron. **The Qaitbay attribution is dropped**; the file keeps century-level dating and states that the patron is not securely known.
- **Islam [A: Quran 19:53].** Harun is named a prophet given to Musa out of God's mercy; the shrine is an active Muslim and Bedouin pilgrimage site.
- **Burckhardt, 1812 [A: Travels in Syria and the Holy Land, 1822].** Reached the Petra valley on 22 August 1812 in disguise, on the pretext of a vow to sacrifice a goat at Aaron's tomb, and was hurried past the ruins by guides who suspected treasure-hunting.
- **Iconography [R].** Western art conventionally gives Aaron the flowering rod and the breastplate from medieval illumination onward; the pool cited only general handbooks, and no art-historical source was reached.
- **Source criticism [R].** Critical scholarship assigns most Aaron material (ordination, vestments, sons, priestly rights) to the Priestly source, dated to the exilic or early post-exilic period and read as reflecting Second Temple Aaronide interests rather than a contemporaneous record (e.g. Thomas Römer on Mosaic, Aaronide, and Levite tensions in the Pentateuch). Noted here; the journey file does not narrate it, since its register narrates the canon.

---

## 10. Interlocks with the existing corpus

Named in campas because a real relation exists, not because of shared geography:

- **moses** (`moses.journey.json`) - brother, throughout. Every shared stop uses byte-identical corpus pins: Horeb/Sinai 28.539, 33.975; Pi-Ramesses and Rameses 30.808, 31.833; Pi-hahiroth 29.877, 32.658; Marah 29.39, 33.06; Elim 29.3, 32.9667; Rephidim 28.68, 33.65; er-Raha 28.5717, 33.966; Hazeroth 28.98, 34.47; Kadesh 30.664, 34.42/34.418; Mount Hor 30.317, 35.407.
- **abraham** (`abraham.journey.json`) - ancestor; Aaron's line runs back through Kohath, Levi, and Jacob to Abraham, stated in the birth campa. Abraham's own sojourn in Egypt is a separate episode centuries earlier and is **not** treated as a connection.
- **solomon** (`solomon.journey.json`) - the priesthood of Aaron's house serves in the temple Solomon builds, and the Shamir legend in Solomon's file refers back to the stones of the ephod, Aaron's vestment. Temple Mount pin inherited exactly: 31.778, 35.2354.
- **rashi** (`rashi.journey.json`) - Rashi wrote substantively on Aaron across Exodus, Leviticus, and Numbers, and is the channel through which most later readers meet him. One-directional across a thousand years. Troyes pin inherited exactly: 48.2973, 4.0744.

**Not** named: the medieval English financier "Aaron" in `census_real_persons_2026-08-02.md`, a different person.

**Duplication flagged.** An earlier file for this subject exists as `aaron_the_levite.journey.json` / `aaron_the_levite.report.md`, cited by the pool's interlock lens. This file is written under the slug `aaron` as instructed; whether to merge or retire one is left for review.

---

## Sources

**Primary text (used directly)**
- Hebrew Bible: Exodus 1-40; Leviticus 8-10; Numbers 1-4, 12-20, 26, 33; Deuteronomy 9-10, 34. KJV for all quoted matter except Numbers 20:12 (NRSV, as supplied by the pool). Hebrews 9:4 for the rod in the ark. Quran 19:53 for Harun the prophet.

**Rabbinic and post-biblical (via the research pool, not independently collated)**
- Mishnah, Pirkei Avot 1:12; Avot de-Rabbi Natan; Exodus Rabbah 1:13; Seder Olam Rabbah chs. 9 and passim.
- Babylonian Talmud: Sotah 12a (Pharaoh's decree); Bava Batra 17a (death by the kiss); Taanit 9a (clouds of glory); Gittin 68a (the Shamir).
- Rashi on Exodus and Leviticus, including Leviticus 9:1 on the Adar ordination. Josephus, Jewish Antiquities IV.4.7.

**Archaeology and topography**
- Petra Papyri, document of 573 CE naming "the House of our Lord the Saint High-Priest Aaron."
- Finnish Jabal Harun Project, Petra: The Mountain of Aaron (Societas Scientiarum Fennica), Fiema and Frosen et al.
- Wikipedia, "Mount Hor," "Jabal Harun," "Land of Goshen," "Kadesh-barnea," for coordinate verification against the pool.
- Johann Ludwig Burckhardt, Travels in Syria and the Holy Land (1822).

**Named but not reachable, or reachable only at second hand (honest gaps)**
- **The Mamluk building inscription on Jabal Harun.** Reported to exist; not seen. Without it the 1458-59 date and any patron attribution stay unverified.
- **Finnish Jabal Harun Project volumes I-III**: reached through summaries only. The pool's excavation end-date of 2013 is unconfirmed against the project's own publication record.
- **Anchor Bible Dictionary, "Hor, Mount"**: not read directly, so the survey of alternative Mount Hor candidates is reported at second hand.
- **Antoninus of Piacenza, Itinerarium (c. 570 CE)**: not read; invoked only to state that the 573 formula does not come from it.
- **Thomas Römer on Pentateuchal source tensions**: not read directly; the Priestly-source attribution is given as the general position of critical scholarship, without a page citation.
- **Reallexikon zur Deutschen Kunstgeschichte**, or any study of Aaron's iconography: not consulted.
- **Any extra-biblical attestation of Aaron as a person**: searched for, none exists. The largest gap here, and not fillable.
