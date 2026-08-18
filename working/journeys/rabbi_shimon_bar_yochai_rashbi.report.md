# Rabbi Shimon bar Yochai (Rashbi): research report
*2026-08-18. Second-century Palestinian tanna; student of Rabbi Akiva; the figure to whom the Zohar, a millennium later, ascribes itself. Slug: `rabbi_shimon_bar_yochai_rashbi`.*

**Method note.** Nothing here is autograph. Every item belongs to one of five layers, never allowed to collapse into each other:

1. Tannaitic material (Mishnah, Tosefta, halakhic midrash) transmitting sayings in his name.
2. School attribution (Sifre "stam", the Mekhilta bearing his name): the school, not the hand.
3. Palestinian amoraic narrative (Yerushalmi Sheviit 9:1, Genesis Rabbah 79:6), redacted c. 4th-5th c.
4. Babylonian narrative (Shabbat 33b-34a, Meilah 17b, Sukkah 45b), redacted c. 5th-7th c.
5. Explicit pseudepigraphy (Nistarot, 7th-8th c.; the Zoharic corpus, late 13th-early 14th c.).

Legend: **[A]** = attested, source named · **[R]** = reconstruction, tradition, hypothesis, or scholarly reading.

---

## 1. What is not known

- **Birth year and birthplace: unknown, not merely uncertain.** No tannaitic, amoraic, or contemporary source gives either **[A, from absence]**. Popular reference works print "c. 90 CE"; that is a modern back-calculation, not a source-based date, and it is nowhere used. The birth stop carries a placeholder date whose `date_confidence` says so.
- **Death year and cause: unknown.** No talmudic source narrates his death **[A, from absence]**. The only death-scene in the whole record is the Idra Zuta's, a 13th/14th-century literary construction **[A: Zohar, Idra Zuta; dating per Scholem, Liebes, Huss, Meroz]**.
- **No contemporary inscription or independently datable document names him** **[R: standard historical caution for tannaitic figures]**. A corpus-wide grep of `working/journeys/*.journey.json` found no independently attesting 2nd-century document either.
- **His father Yochai: almost nothing.** The patronymic, and one further trace: at Pesachim 112a Rashbi presses the imprisoned Akiva with "if you do not teach me, I will tell Yochai my father and he will hand you over to the government," implying paternal access to the Roman authorities **[A]**. That implication is itself a Babylonian narrative touch, not a datum about a 2nd-century household.
- **His wife: never named.** She brings him bread and water in the study hall (Shabbat 33b) and vanishes from the record **[A]**.

## 2. The school of Akiva

- Counted among Akiva's students; the discipleship is transmitted rabbinic memory **[A: Mishnah and Tosefta passim]**.
- **Yevamot 62b**: after Akiva's earlier twelve thousand pairs of students die in one season (Rav Nahman attributes it in the sugya to diphtheria, not to the revolt, though later tradition conflates the two), Akiva goes to the sages **in the South** and teaches five: R. Meir, R. Yehuda b. Ilai, R. Yose b. Halafta, R. Shimon bar Yochai, R. Elazar b. Shammua **[A]**.
- **A conflict inside the research pool, resolved by splitting rather than by choosing.** The pool's geography lens placed the discipleship at Bnei Brak (32.0807 / 34.8338), Akiva's base in a *different* sugya (Sanhedrin 32b), while Yevamot 62b says "the South" (darom). The file therefore carries **two** stops, Bnei Brak by inference and the South by the cited verse. Neither is dressed up as the other.
- **Pesachim 112a, corrected against the pool's first summary.** Rashbi does not enter "surreptitiously," and he is not one of a group. He asks; Akiva **refuses**, citing danger; Rashbi presses with the threat about his father; Akiva answers with the calf and the cow; Rashbi argues the risk is his own, since Akiva is already imprisoned; only then does Akiva teach him **[A]**. The text names **no location**. Caesarea is the later tradition of Akiva's imprisonment, wholly extra-textual, and the file's `date_confidence` says so at the pin.
- **Independence within discipleship**: he disputes four of Akiva's own interpretations and argues his readings are better **[R: Tosefta Sotah 6:6; Sifre Devarim 31:8]**.

## 3. The Bar Kokhba backdrop

- The revolt (132) and its suppression (135) are securely dated from Cassius Dio and confirmed archaeologically at Battir / Khirbet el-Yahud **[A]**. Hadrian's own file carries the war, the fall of Beitar, the renaming of Judaea to Syria Palaestina, and the barring of Jews from Jerusalem.
- **Yerushalmi Ta'anit 4:5**: Rashbi is the transmitter of Akiva's messianic reading of Numbers 24:17, "a star shall go forth from Jacob," applied to Bar Koziba **[A]**.
- **What this is not.** It is not evidence that Rashbi fought in, endorsed, or was present at the revolt. It is also not licence to identify Hadrian as the unnamed Caesar of Shabbat 33b. Both inferences are refused throughout, in the report and in the file.

## 4. The sentence of death (Shabbat 33b)

- The sugya lists exactly three Roman works: **marketplaces, bridges, bathhouses**. R. Yehuda calls them fine; R. Yose is silent; Rashbi answers that Rome built them for its own needs: markets for prostitutes, baths for their own bodies, bridges to collect tolls **[A]**.
- Yehuda **ben Gerim** reports the remark. Sefaria renders him "Yehuda, son of converts"; the pool's first pass called him "a convert," which is wrong **[A, corrected]**.
- The government elevates R. Yehuda as "head of the speakers in every place," exiles R. Yose to Tzippori, and sentences Rashbi to death **[A]**. **No emperor is named in the passage.** Assigning it to Hadrian is a later inference, flagged and not made.
- Father and son first hide in the beit midrash, his wife bringing bread and water; when the decree intensifies they flee to the cave **[A]**.

## 5. The cave: two narratives, not one story

These are materially different narratives and the file refuses to merge them.

**Palestinian (Yerushalmi Sheviit 9:1; Genesis Rabbah 79:6) [A]**
- **Thirteen continuous years.** No return trip.
- Sustained by carobs: Genesis Rabbah 79:6 says they ate withered carobs "until they broke out in sores." The spring is a Bavli emphasis.
- **One fowler**, not "a pair of providential birds" as the pool's first pass had it. After the thirteen years Rashbi watches a bird-catcher spread nets while a heavenly voice calls *dimus* (acquitted, the bird escapes) or *spekula* (killing, it is caught), and concludes that no bird is adjudicated without Heaven, so much less a human. A providence lesson that prompts him to leave, **not** an all-clear signal about officials.
- Emerging, he purifies **Tiberias** of corpse impurity, floating cut lupines to find the graves.
- The **Samaritan** who reburies a corpse to discredit him, and the **scribe of Magdala** turned into a heap of bones, are **Palestinian**, not Babylonian. The pool's first pass had misattributed both to Shabbat 34a.

**Babylonian (Shabbat 33b-34a) [A]**
- **Twelve years, then a further twelve months.** Miraculous carob tree **and** spring; they strip and sit buried in sand to the neck to save their clothes, studying all day.
- **Elijah** announces at the cave mouth that the decreeing emperor has died and the decree is annulled.
- On first emerging, scandalized at men plowing and sowing, whatever they look at burns; a Divine Voice: "Did you emerge from the cave in order to destroy My world? Return to your cave."
- After the twelve months, Eleazar's gaze still burns and Rashbi heals what his son burns. An old man runs at Sabbath eve with two bundles of myrtle, one for "Remember" and one for "Observe."
- The Bavli's Tiberias scene is its own: hard ground judged pure, soft ground marked; an anonymous elder mocks "ben Yochai has purified a cemetery" and dies from his gaze; and it is **Yehuda ben Gerim** whom he turns into a pile of bones.

**Contradiction, flagged and left standing:** duration (13 vs 12+12 months), sustaining miracle, mechanism of departure, identity of the mocker, and recension of the Samaritan episode all differ. Nothing here is adjudicated.

**Historical-kernel reading [R].** Lee I. Levine treats the Tiberias purification as the one point in the cycle where a real sage doing real civic and purity work may underlie the legend.

**Modern literary readings [R].** Ofra Meir and Jeffrey Rubenstein read the Palestinian-to-Babylonian development as redactional transformation across centuries; Charlotte Fonrobert reads the cave against Plato's allegory; Michal Bar-Asher Siegal compares the ascetic retreat to late-antique Christian monastic literature. These sit in `suggested_refs` and `date_confidence`, never staged as scenes.

## 6. The teaching circle, the household, the sayings

- **Tekoa [A: Shabbat 147b; Eruvin 91a; Menachot 72a]**. Judah ha-Nasi recalls: "When we would study Torah with Rabbi Shimon in Tekoa, we would carry oil and towels from the courtyard to the roof and from the roof into an enclosure similar to a courtyard until we reached the spring in which we would bathe, without passing through a public domain." The Eruvin 91a parallel is a genuinely different wording, not the same sentence. **Correction applied:** Graetz established that this Tekoa was **Galilean**, not the biblical Judean one; the studying happened in Rashbi's lifetime, only the recollection is later.
- **R. Eleazar b. R. Shimon**, his son: the one family relation with no contradiction anywhere, companion in every version of the cave **[A]**.
- **R. Pinhas b. Yair**: Shabbat 33b states outright, with חַתְנֵיהּ, "his son-in-law"; a later Zoharic tradition makes Pinhas his **father-in-law** **[A for the Bavli, A for the Zoharic reversal]**. The two traditions place Pinhas in opposite generations. Left unresolved.
- **Sukkah 45b [A]**, corrected against the pool's flattening. The claim is graduated: alone, "from the day **I** was created until now"; with his son, "from the day **the world** was created until now"; with Yotam ben Uzziah added, "from the day the world was created **until its end**." The separate saying is the bnei-aliyah one: "if they number two, I and my son are they." The pool also carried "had he and his son stood at Sinai"; **Sinai does not appear anywhere in the passage**, and that phrase is dropped as an invention or conflation.
- **Berakhot 35b [A]**: Torah study as exclusive occupation, against R. Ishmael's derekh eretz. Abaye's coda, restored to full wording: many acted in accordance with the opinion of R. Yishmael and were successful; many acted in accordance with the opinion of R. Shimon ben Yohai and were not successful in their Torah study.

## 7. Rome and Ben Temalion (Meilah 17b)

Chosen for the embassy "as he is accustomed to experiencing miracles," with R. Eleazar b. Yose **[A]**. A demon, Ben Temalion, offers to possess the emperor's daughter so Rashbi can cast it out; he accepts, wanting the miracle for Israel's sake even through a demon. He calls "ben Temalion, emerge!" **three** times (not twice, as the pool had it); she is cured; the grateful emperor takes them to his treasury, where they find the letter of decrees against the Jews **and tear it up** **[A, corrected]**. Hagiographic, layer 4. No independent Roman record of any such embassy or decree exists.

**Tag inconsistency noted in the pool:** the episode was tagged [A] in the chronology lens and [R] in the afterlife lens. The convention adopted here: the **text** is attested [A]; the **historicity** is not, and that is stated in prose and in `date_confidence` rather than by flipping the tag.

## 8. The texts that carry his name

Three categories, never the same thing:
1. **Sayings transmitted in his name** across the tannaitic and talmudic corpus **[A]**.
2. **School texts bearing his name.** Sanhedrin 86a: an anonymous Sifre follows R. Shimon **[A]**. That is a retrospective redactional attribution, not personal composition. The **Mekhilta de-Rabbi Shimon bar Yochai** did not survive as an independent medieval manuscript; it was reconstructed from citations (notably Midrash ha-Gadol) and geniza fragments by David Zvi Hoffmann (1905), then by Epstein and Melamed, and translated critically by W. David Nelson (JPS, 2006) **[A]**.
3. **Pseudepigraphy.** The **Nistarot de-Rabbi Shimon ben Yochai**, an apocalypse presenting itself as a vision revealed to him in the cave, is early-Islamic in composition (7th-8th c.) and reflects that era's politics **[R]**. The **Zoharic corpus** is dated by the prevailing critical current to late 13th / early 14th century **Castile**, on Scholem's philological case (Aramaic grammatical errors, Arabic and Spanish loanwords, unfamiliarity with the geography of the Land of Israel), refined by Liebes, Huss, and Meroz **[A]**. Scholem concluded by 1938 that Moses de León was the most likely primary author, writing roughly 1280-1286.

## 9. The name after the man

- **The tomb at Meron.** No tannaitic or talmudic source attests a tomb of Rashbi anywhere **[A, from absence; noted in Reiner's work on the Meron cult]**. The tradition is medieval and early modern.
- **Lag BaOmer.** The association of 18 Iyyar with his death anniversary, and the bonfire pilgrimage to Meron, is decisively shaped by 16th-century Safed Kabbalah, the circle of Isaac Luria and Hayyim Vital **[A]**. Some bibliographic tradition suggests the date-attribution may partly trace to a **printing variant** in Vital's Pri Etz Chadash rather than an unbroken older custom **[R]**.
- **Reiner's hypothesis [R, explicitly a hypothesis]:** the Meron date-and-site complex may have migrated from earlier local traditions concerning Joshua and an earthquake.
- **Doubt from inside.** Jacob Emden's **Mitpachat Sefarim** already questions the Zohar's authenticity and its attribution to Rashbi, on internal anachronisms, from within observant rabbinic scholarship. **Correction applied:** not a single 1768 publication; it appeared at **Altona over 1761-68** from Emden's own press.
- **Ben-Zion Rosenfeld [R]** synthesizes the image across four registers at once (wonder-worker, magician-adjacent figure, halakhic scholar, saddiq) as cumulative literary personae rather than facets of one known biography.

## 10. Interlocks

**Named in a campa (direct, one-directional relation to Rashbi himself):**
- `moses_de_leon`. He circulated the Zohar as an ancient book composed by Rashbi in the cave with his son Eleazar, swore to Isaac of Acre at Valladolid that the manuscript was in his house at Ávila, and died at Arévalo before producing it. His widow's later testimony (via Isaac of Acre and Zacut) says he wrote it himself and put Rashbi's name on it to raise the price; two of his students swore the opposite. The relation is to Rashbi's **name and authority**, cited at Rashbi's own Meron pin, never staged as a Castile scene here.
- `adriano`. Hadrian, named once, only as the securely dated war whose messianic oracle Rashbi transmitted. The file states in the same breath that no source places Rashbi in the revolt and that the Caesar of Shabbat 33b is unnamed.

**Found and deliberately NOT named in any campa** (shared geography or third-party reception only, per the standing rule):
- `maimonides`, `saadia_gaon`, `martin_buber`: all three are Tiberias references, a millennium or more apart, with no relation to Rashbi as a person.
- `arthur_edward_waite`, `giovanni_pico_della_mirandola`, `borges`: reception of the **Zoharic corpus**, not engagement with Rashbi. Those are their own files' stops, recorded here so the operator can see they were found and weighed.

## 11. Apparatus relations for the operator

Rashbi is **not** listed in `EXCEPTIONS.md`. Two classes of material were kept rather than silently deleted, and both are flagged here for the operator's ruling:

1. **Forward-reaching material inside the file (segment "The Name After the Man").** The Nistarot, the Zoharic attribution, the Idras, the Meron tomb tradition, the Lurianic hillula, and Emden's critique all postdate Rashbi. By the block rule in EXCEPTIONS.md this is a **forward** direction, which the exception does not license in general. It is kept because the brief and QUEUE.md both require the layered-attribution material, and because it is not a *framework* applied forward but the posthumous career of the subject's own name and grave, the same shape as the 1966 repatriation stop on `abdelkader.journey.json`. Every such stop sits at Rashbi's **own** pins and declares its status in `date_confidence`. **Direction caught: forward. Operator to rule.**
2. **Third-party reception deliberately withheld** (Waite, Pico, Borges, and the modern academic readers Fonrobert, Rubenstein, Meir, Bar-Asher Siegal, Levine, Reiner, Rosenfeld). Not deleted: they are carried in `sources` and `suggested_refs` on Rashbi's own stops. No scene is staged for any of them. **Direction caught: forward, and declined.**

## 12. Coordinate corrections applied

The verified pool flagged eight coordinate errors. All are applied.

- **Peki'in, the cave**: pool gave 32.9897 / 35.3283 and, in the afterlife lens, 33.0175 / 35.3378. Used: **32.9742 / 35.3314**.
- **Meron**: pool gave 32.9878 / 35.4442 and 32.9847 / 35.4386. Used: **32.9819 / 35.4403**, standardized across every Meron stop.
- **Akiva's prison**: the afterlife lens pinned Tiberias (32.794 / 35.5312) against the geography lens's Caesarea. Used: **32.5 / 34.8913**, with the text's silence about place stated at the pin.
- **Tekoa**: the pool's 31.6539 / 35.2239 is Judea; Graetz's Galilean Tekoa is unlocated. Used: an Upper Galilee regional approximation, declared unidentified.
- **Usha** (32.7897 / 35.103, itself 4 km off) and the **Zohar composition** pin (40.4168 / -3.7038, which is Madrid): both dropped. No source places Rashbi at Usha, and the Castile material belongs to de León's own file.
- **Guadalajara**: inherited byte-identical from `moses_de_leon.journey.json`, **40.6333 / -3.1669**, not the pool's rounded -3.167. **Beitar** and **Jerusalem** from `adriano.journey.json`, as context only; no Rashbi stop is staged at either.

## 13. Sources

**Primary, reachable and used**
All via Sefaria unless noted.
- **Shabbat 33b-34a** (three Roman works; Yehuda ben Gerim; study hall; cave; sand; Divine Voice; myrtles; Tiberias; Pinhas ben Yair as חַתְנֵיהּ)
- **Pesachim 112a** (prison exchange; threat about Yochai; calf and cow; maxims)
- **Yevamot 62b** (five disciples in the South) · **Sukkah 45b** (graduated absolution; bnei aliyah)
- **Berakhot 35b** (Abaye's coda) · **Meilah 17b** (Rome; ben Temalion; the torn letter)
- **Shabbat 147b**, **Eruvin 91a**, **Menachot 72a** (Tekoa) · **Sanhedrin 86a** (stam Sifre)
- **Jerusalem Talmud Sheviit 9:1** (thirteen years; fowler; lupines; Samaritan; Magdala)
- **Bereshit Rabbah 79:6** (thirteen years; withered carobs and sores; the hunter; the Tiberias exchange; the gratitude maxim at the head of the section)
- **Yerushalmi Ta'anit 4:5** (the star oracle) · **Tosefta Sotah 6:6**, **Sifre Devarim 31:8** (the four disputes)

**Secondary**
- Gershom Scholem (Zohar philology and the de León attribution); Yehuda Liebes; Boaz Huss; Ronit Meroz
- Lee I. Levine (Roman Tiberias; the historical kernel)
- Ben-Zion Rosenfeld (the four-register image)
- Elchanan Reiner (Meron sacred geography; the Joshua/earthquake hypothesis)
- Jeffrey L. Rubenstein, *Talmudic Stories*; Ofra Meir; Charlotte Fonrobert; Michal Bar-Asher Siegal
- D. Z. Hoffmann, *Mechilta de-Rabbi Simon b. Jochai* (1905); J. N. Epstein and E. Z. Melamed, critical edition; W. D. Nelson, *Mekhilta de-Rabbi Shimon bar Yohai* (JPS, 2006)
- Jacob Emden, *Mitpachat Sefarim* (Altona, 1761-68)
- Wikipedia, "Peki'in," "Meron, Israel," "Usha (city)," "Simeon bar Yochai," "Jacob Emden," "Zohar," "Moses de León" (used for coordinates and for the Graetz citation on Galilean Tekoa)

**Named as gaps, not filled**
- No manuscript, inscription, or documentary record of any kind from the 2nd century names him.
- The **Mekhilta de-Rabbi Shimon bar Yochai** has no continuous medieval witness; what exists is reconstruction from citation and fragment.
- The **Nistarot** dating rests on internal reference to early Islamic politics, not on a colophon. Given as [R].
- The **printing-variant hypothesis** for 18 Iyyar in Vital's Pri Etz Chadash is a proposal in secondary literature; the primary printing history was not independently checked here. Given as [R].
- No independent Roman source records the Meilah 17b embassy or the decree it annuls.
