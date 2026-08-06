# Mao Zedong (1893-1976): research report for the atlas journey

*2026-08-06. Slug `mao_zedong`. Artifact: `mao_zedong.journey.json`, 7 segments, 45 stops, register "national mythology: the canon is true".*

**Legend.** **[A]** = attested, source named on the line. **[R]** = reconstruction, tradition, or a claim the reachable sourcing does not carry. Contradictions are flagged and left standing; none is adjudicated.

The journey is written in the canon: the Luding chains, the eighty-six thousand who left Jiangxi and the eight thousand who arrived, the swim at Wuhan. The hedging does not live in the prose; it lives in each stop's `date_confidence` field and in this document.

---

## A. Corrections applied to the research pool

Every row is an error in the pool that the journey does not reproduce. "Lens" names which of the pool's two geographic lenses carried the bad value.

| Item | Pool value | Corrected value | Reason **[A unless marked]** |
|---|---|---|---|
| May Fourth 1919 | Beijing (chron.) | Changsha 28.198, 112.97 | Wikipedia "Mao Zedong": his Beijing time "ended in the spring of 1919". He worked the movement from Hunan, editing the *Xiang River Review* from July [Short] |
| Nanchang Uprising | "Zhu De leads" (chron.) | Zhou Enlai directing, He Long commander in chief, Ye Ting the main force, Zhu De a subordinate unit | the Mao article says only that "a battalion led by General Zhu De was ordered to take the city" [Wikipedia] |
| Wenjiashi | 28.1608, 113.6486 (geo.) | 28.0487, 113.9252 | pool value is Liuyang city centre, 30 km northwest of the town [Chinese Wikipedia] |
| Jinggangshan | 26.6167, 114.2833 (chron.) | 26.5678, 114.1636 (Ciping) | pool value matches nothing; the base is Ciping |
| Xiang River | 25.0833, 110.6667 (chron.); 25.4833, 110.9833 (geo.) | 25.75, 110.63 (Jieshou ferry) | crossings were in Xing'an, Quanzhou and Guanyang. Chronology value is 60 km south near Guilin city, outside the battle area; geography value 30 km southeast of Xing'an |
| Jinsha crossing | 26.5, 101.7 (chron.) | 26.4833, 102.9167 (Jiaopingdu) | pool value 120 km west near Panzhihua; crossing was between Luquan and Huili. Lenses disagreed by over a degree of longitude: recorded, not averaged. Still approximate |
| Zoige / Maoergai | 33.28, 102.92 as one place | Zoige 33.575, 102.962; Maoergai near 32.6, 103.4 | two places 100 km apart; the August 1935 conference was at Maoergai, Songpan county. Pool value is neither. Stop cut, recorded for whoever restores it |
| Lazikou | 34.0333, 104.4833 (geo.) | 34.2, 103.6 (approximate) | pool longitude over 100 km east of Diebu (Tewo) county, Gansu, where the pass is |
| End of the March | "arrives in Yan'an" (chron.) | Wuqizhen 36.9167, 108.1667 | Wuqizhen is 145 km from Yan'an, not in Communist hands until December 1936 |
| Wayaobao | 37, 109 (geo.) | 37.1427, 109.6752 | rounded placeholder, 65 km off; Wayaobao is Wayaobu, Zichang |
| Xi'an Incident | dated 1937 with the united front (chron.) | Incident 12-25 Dec 1936; united front Sept 1937 | two events conflated |
| Xibaipo | 38.4667, 113.9167 (geo.) | 38.3176, 114.0127 | 18 km off; Pingshan county, Hebei |
| Span of office | "twenty-seven years as head of the state he founded" (afterlife) | thirty-three years as party chairman, from 1943 | head of state only 1949-1959, then Liu Shaoqi |
| Korea stop | 40.3399, 127.5101 (chron., generic) | Pyongyang 39.0392, 125.7625 | canonical pin inherited byte-identical from `isabel_peron.journey.json` |

## B. Contradictions flagged and left standing

1. **The first marriage.** Wikipedia "Mao Zedong": age 13, Luo aged 17. Wikipedia "Luo Yixiu" (b. 20 October 1889): 1908, Mao 14, Luo 18. The pool asserted "1907" with "age 14", which neither supports. Dated 1907-01-01, window 1907-1908 open in `date_confidence`; the campa says only "some four years his elder", which both allow.
2. **Graduation from Hunan First Normal.** The pool gave 1912-1919. Enrolment was spring 1913, as the pool's geography lens agrees. "June 1919" is an internal inconsistency in Wikipedia's "Mao Zedong", which elsewhere puts him in Beijing from autumn 1918; Short, Spence, and Pantsov and Levine give June 1918. **The journey does not date the graduation.**
3. **Zunyi Conference date.** Traditionally 7-9 January 1935; Wikipedia adopts Fei Peiru's revision to 15-17 January, used here with the older dating in `date_confidence`.
4. **Scale of Luding Bridge.** **[A for the crossing: Wikipedia "Battle of Luding Bridge"]** **[R for the scale: Sun Shuyun's field interviews found local memory of no battle at the bridge.]** The campa states the canon and then names Sun Shuyun: the only contradiction carried in prose as well as in the hedge.
5. **"It is right to rebel."** See section 6.

---

## 1. Shaoshan and the schools, 1893-1918

Born 26 December 1893 at Shaoshan, Xiangtan county, Hunan, to Mao Yichang, a grain dealer who worked up from debt to roughly twenty-two mou, and Wen Qimei, a Buddhist **[A: Wikipedia "Mao Zedong", "Shaoshan"; Snow, *Red Star Over China* (1937); Short, *Mao: A Life* (1999)]**. Pin 27.9136, 112.5309, the farmhouse; the chronology lens gave 27.9167, 112.5333, a few hundred metres off. Married by arrangement to Luo Yixiu, refuses to recognize it, never lives with her; she dies at twenty in 1910 **[A]**: see contradiction 1.

Leaves for the Dongshan Higher Primary School at Xiangxiang in 1910 against his father's wishes **[A: Snow, from Mao's own account]**; the pamphlet that made him weep is an old man's memory of a boy's reading forty years later, attested to Snow and not to 1910. At Changsha in 1911 he cuts his queue after the Wuchang rising and serves about six months as a private in the Hunan revolutionary army **[A: Snow]**; the month of enlistment is fixed nowhere reachable, and the stop says so. At Hunan First Normal from spring 1913 **[A: Short]**: see contradiction 2. First article in *New Youth* on physical education, 1917; Renovation of the People Study Society with Cai Hesen, 1918 **[A: Wikipedia "Mao Zedong"]**.

---

## 2. Beijing, May Fourth, the party, 1918-1921

Assistant to Li Dazhao in the Peking University library from autumn 1918 **[A: Snow; Spence, *Mao Zedong* (1999)]**, pin 39.9163, 116.4074 (old Shatan campus). May Fourth is corrected in table A; the December 1919 strike and the removal of governor Zhang Jingyao **[A]** fold into the Xiang River Review stop. Marries Yang Kaihui in 1920, month conventional and marked "traditional"; headmaster of the junior section of First Normal **[A: Wikipedia "Mao Zedong"]**. Her execution at Changsha in 1930, after refusing a public renunciation, is attested in the standard biographies and carried as forward narration.

First Congress, Shanghai, 23 July 1921, then South Lake at Jiaxing on the 31st: thirteen delegates, two Comintern agents, a girls' school in the French Concession, the congress finished on a hired boat after a stranger walks into the room **[A: Wikipedia "1st National Congress of the CCP"; CCP official history]**. The stranger, the lookout on deck and the mahjong tiles come from the official account: not independently verifiable, since the party is the source for the party's founding legend. **[R on those details; A on the relocation]**

---

## 3. United front and break, 1922-1927

Alternate member of the KMT Central Executive Committee, 1924, and the sixth term of the Peasant Movement Training Institute, 1926, both at Guangzhou **[A: Wikipedia "Mao Zedong"; Short]**, on one pin at 23.1291, 113.2644. The Central Land Committee at Wuhan, April 1927 **[A]**, is **CUT**: an event omitted, not doubted. The Hunan peasant report, March 1927, thirty-two days on foot in five counties, is verified by direct fetch of marxists.org and supplies the journey's only pre-Yan'an quote **[A: *Selected Works* vol. I]**; pin 27.6, 111.7 is a provincial centroid, the pool's own value. Nanchang is corrected in table A: the journey names all four commanders in the right relation and states that Mao was not present, which is why the stop exists.

---

## 4. The mountain and the soviet, 1927-1934

Wenjiashi and Jinggangshan are corrected in table A. Sanwan, 29 September 1927: party branches at company level, soldiers' committees, officers forbidden to beat the men, travelling money for anyone leaving **[A: Short; CCP official history]**; the six hundred remaining is the party's figure, **[R]** as a precise count. The campa closes on the survival of the company-level party branch in current PLA regulation **[A: the political work regulations of the People's Liberation Army retain the company branch and its secretary]**. At Jinggangshan the force of about eighteen hundred built partly by absorbing the bands of Yuan Wencai and Wang Zuo, and the April 1928 junction with Zhu De and Lin Biao forming the Fourth Red Army, share one stop **[A: Wikipedia "Mao Zedong"; Snow]**. Chinese Soviet Republic proclaimed at Ruijin, 7 November 1931, Mao chairman, real military authority passing to the Moscow-trained leadership and Otto Braun **[A: Wikipedia; Short]**, pin 25.8794, 116.0286.

**[R] flagged.** The pool's one reconstructed chronology entry holds that the turn toward the Jinggang Mountains was improvised on the retreat rather than planned: a historiographical reading, not a documented decision. The campa states the vote in the room and does not say when the idea formed.

---

## 5. The Long March, October 1934 to December 1935

Coordinates for Xiang River, Jinsha, Zoige, Lazikou, Wuqizhen and Wayaobao are corrected in table A; Zunyi and Luding are contradictions 3 and 4. Departure from Yudu, 16 October 1934, around 86,000 **[A: Wikipedia "Long March"]**, pin 25.9506, 115.4139; Xiang River casualties confirmed at 86,000 down to 36,000 **[A]**. The geography lens called that crossing a "Nationalist air and artillery attack", overstating the air component: the fighting was against Guangxi and Hunan ground forces. At Zunyi, Bo Gu and Otto Braun are removed from military command, Mao goes onto the standing committee as Zhou Enlai's assistant in military affairs, and Zhou remains the senior figure **[A: Wikipedia "Long March", "Zunyi Conference"]**; party history dates Mao's leadership from that room and the campa says so in those terms, reporting the claim as the canon's claim. Lazikou dates per Chinese Wikipedia: vanguard 16 September, main assault 17th, cleared 18th **[A]**. The 8,000 survivor figure at Wuqizhen is confirmed **[A]**, though the journey says "between six and eight thousand" because the range in the literature is real; the nine thousand kilometres, eighteen ranges and twenty-four rivers are canonical, **[R]** as measurements. Wayaobao, 17-25 December 1935, adopts the anti-Japanese national united front line **[A: CCP party history]**.

**Cut for budget:** Anshunchang, 24 May 1935 **[A]**, the Luding campa carrying the gorge without it; Jiajin Mountain, June 1935; Zoige, August 1935.

---

## 6. Yan'an, 1936-1947

Xi'an Incident dated in table A. He Zizhen leaves Yan'an in autumn 1937, that marriage never formally dissolved; Mao marries Jiang Qing on 28 November 1938, the Politburo consenting on condition she stay out of public political life **[A: Wikipedia "Jiang Qing"]**. The "twenty years" term of that condition is widely repeated and **[R]** here; the pool gives the restriction without a number.

Chairman of the party from 20 March 1943, and the Rectification Movement **[A: Wikipedia "Mao Zedong"; Short]**; Kang Sheng's security apparatus and the suicides among interrogated cadres are standard in Short and Spence. Pinned at Zaoyuan. Seventh Congress, Yangjialing, 23 April to 11 June 1945, Mao Zedong Thought into the party constitution **[A: CCP party history]**; the 1.2 million members and near-million army are the congress's own figures, **[R]** as independent counts. Chongqing, 28 August to 10 October 1945, the poem *Snow* published during the visit **[A: Short; Spence]**.

**Quotes.** Five of the journey's six were verified by direct fetch of marxists.org, and each stop's `quote_source` names the work and date: *On Contradiction*, *Problems of War and Strategy*, *Serve the People*, the Hunan peasant report, and *On the Correct Handling of Contradictions Among the People*. **[A]**

**The sixth is weaker, and is flagged in the file itself.** "It is right to rebel against reactionaries" is a Cultural Revolution slogan, not an original Mao sentence. The traceable original is his speech at the Yan'an rally for Stalin's sixtieth birthday, 20 December 1939: "Marxism comprises many principles, but in the final analysis they can all be brought back to a single sentence: it is right to rebel." The only source located is Wikiquote: tertiary, not on marxists.org, not confirmed against a scholarly edition. The journey uses the 1939 wording on the Red Guard rally stop and says so in `quote_source`. **[R on the sourcing; A on the slogan's currency in 1966-1967 Red Guard literature]**

---

## 7. The People's Republic, 1949-1976

Xibaipo corrected in table A: Central Committee there May 1948 to March 1949, Second Plenary Session held there **[A]**. The imperial-examinations remark on leaving for Beijing is party lore, **[R]** as verbatim quotation, so the campa paraphrases it. Fragrant Hills **[A: Short]** is **CUT**.

Tiananmen, 1 October 1949 **[A: widely attested; Spence]**. The journey's five Beijing pins are deliberately distinct: inherited city pin, rostrum, Zhongnanhai, mausoleum, old university. Korea from October 1950 **[A]**, pin corrected in table A; Mao Anying's death by napalm in November 1950 and his burial in Korea are attested **[A: Short]**, while the claim that Mao refused repatriation is widely reported and **[R]**.

Two Moscow journeys, December 1949 to February 1950 and November 1957 **[A: Short; Chinese and Soviet archival accounts]**, Kremlin pin 55.752, 37.6175. The 300 million dollars at one per cent over five years is the treaty's figure **[A]**; the remark about losing three hundred million people in a nuclear war is attested in several accounts of the 1957 conference, **[R]** as wording.

Hundred Flowers 1956, Anti-Rightist 1957, Great Leap Forward 1958, famine from 1959 **[A: Wikipedia "Mao Zedong"]**. The half a million sent to camps or the countryside is the standard estimate, **[R]** as a precise count; "tens of millions" for the famine is the pool's range, repeated as a range. Shaoshan in June 1959 **[A: Short]**, then Lushan in July, the Peng Dehuai letter and his dismissal **[A: Short; Spence]**, sequenced Shaoshan first. Beidaihe is **CUT**: the pool flags it as **[R]**, with no attested visit dates. Yangtze swim, 16 July 1966 **[A: contemporary press; Short]**; the Eleventh Plenum of the Eighth Central Committee, 1-12 August 1966, which dropped Liu Shaoqi from second to eighth in the standing committee ranking, closes that campa in place of an interpretive line **[A: Wikipedia "Liu Shaoqi", "Cultural Revolution"]**; eight Red Guard rallies, August to November 1966 **[A: Short]**. The Song Binbin armband exchange is documented in outline **[A]**, but Mao's exact reply is remembered variously, so the campa renders it indirectly.

Death, 9 September 1976, 00:10, Beijing, age 82 **[A: Wikipedia "Death and state funeral of Mao Zedong"]**. He had signed a pledge favouring cremation in line with party policy; the leadership chose preservation, and no reliable record survives of how or by whom that was decided. Wang Dongxing is credited with the embalming. **[A on the pledge and Wang's role; the decision process is an honest gap]**

---

## 8. Afterlife, and what the journey omits

Body to 305 Hospital, 17 September 1976, organs removed and kept in formaldehyde **[A]**. Mausoleum on the razed site of the Gate of China, 24 November 1976 to 24 May 1977, body in a crystal case; closed nine months in 1997, reopened 6 January 1998; Xi Jinping and the Politburo Standing Committee visit 29 September 2019. **[A: Wikipedia "Mausoleum of Mao Zedong"]** The wax-replica rumour is carried in the journey's last sentence as what people in the queue say, which is exactly its evidentiary status. **[R: mainstream sources neither confirm nor deny it]**

*Quotations from Chairman Mao Tse-tung* compiled 5 January 1964 by the *People's Liberation Army Daily*; over 50 languages and 117 countries by May 1967; printings past a billion 1966-1969, lifetime totals cited as high as 6.5 billion; publication halted February 1979 as a distortion of Mao Zedong Thought; a 1964 first edition sold at Sotheby's for 15,000 dollars, no date in the pool. **[A: Wikipedia]**

**Named omissions:** the Sotheby's sale and the 1979 halt; Liu Chunhua's 1967 *Chairman Mao Goes to Anyuan*, over 900 million copies and probably the most reproduced painting in history, which Mao is said to have disliked because it showed no workers **[A: Wikipedia]**; Shaoshan as a red-tourism economy **[A]**; Mao amulets on taxi mirrors **[R: journalism on post-Mao nostalgia, no primary citation located]**. An afterlife segment would be a legitimate eighth; the budget went to places Mao stood.

---

## 9. Interlocks

Named in campa:

| Stop | Slug | Basis |
|---|---|---|
| Changsha 1911 | `keyserling` | lands at Canton weeks after the empire falls, then sits with the exiled mandarin Ku Hung-ming at Tsingtao while Mao soldiers in the same revolution **[A on whereabouts, R on the pairing]** |
| Peking library 1918; Tiananmen 1949 | `marco_polo`, `matteo_ricci` | Khanbaliq; Ricci's grave at Zhalan **[A]** |
| Guangzhou 1926 | `ibn_battuta` | Canton's Muslim quarter, mosque and potters **[A]** |
| Xi'an 1936 | `kircher` | the Nestorian stele in *China Illustrata* (1667) **[A]** |
| Tiananmen 1949 | `genghis_khan` | Zhongdu burned in the winter of 1215 **[A]** |
| Pyongyang 1950 | `isabel_peron` | her May 1973 Beijing to Pyongyang mission, Kim Il-sung on 15 May **[A]** |
| Moscow 1957 | `che_guevara` | his 1965 Algiers attack on Soviet trade terms **[R on the pairing]** |

**Canonical pins inherited exactly:** Pyongyang 39.0392, 125.7625 (`isabel_peron`); Beijing 39.9042, 116.4074 (`isabel_peron`, `marco_polo`), at the Hundred Flowers stop. The Kaaba pin 21.4225, 39.8262 and the Paris pin 48.8566, 2.3522 are unused: no Mao overlap, and he stayed in China through the 1919-1920 work-study wave that took Zhou Enlai and Deng Xiaoping to France.

**Not named in campa:** `mikhail_bakunin`, whose quarrel with Marx in the First International is the founding schism Mao's party descends from the winning side of; real genealogy, no shared ground or date **[R]**. A future `madame_chiang_kai_shek` journey will intersect this one at Chongqing and Nanjing. **[A: QUEUE.md; census_real_persons_2026-08-02.md]**

**Genuine corpus gap:** no existing journey file places any subject at Yan'an, Shaoshan, Jinggangshan, or on the Long March route. That geography is built fresh. **[A: grep across all `*.journey.json` returned no hits]**

---

## Sources

**Reachable and used.** The English Wikipedia articles cited by name in the sections above; Chinese Wikipedia for Wenjiashi town and the Lazikou campaign. marxists.org, *Selected Works* vols. I-V: every journey quote except the 1939 rebel line was verified by direct fetch. Edgar Snow, *Red Star Over China* (1937); Philip Short, *Mao: A Life* (1999); Jonathan Spence, *Mao Zedong* (1999); Pantsov and Levine at second hand for the 1918 graduation. CCP official history and the site museums at Jinggangshan, Yan'an, Xibaipo and Xintiandi. Corpus: the `isabel_peron`, `marco_polo`, `matteo_ricci`, `genghis_khan`, `ibn_battuta`, `keyserling`, `kircher`, `che_guevara` and `mikhail_bakunin` journeys, `QUEUE.md`, `census_real_persons_2026-08-02.md`.

**Not reachable, and why.** Wikiquote is the only source found for the 20 December 1939 Stalin-birthday speech: tertiary, not cross-checked, flagged in `quote_source`. The upstream research session exhausted its web search budget before it could establish the Shaoshan bronze statue's unveiling date and dimensions, other major Mao statues including Chengdu Tianfu Square, Mao badge production totals, and the chronology of the formaldehyde-damage legends: unverified gaps, not resolved claims. No primary confirmation was found for the wax-replica rumour in either direction, nor for the taxi-mirror amulet practice. Short, Spence, and Pantsov and Levine were used at second hand through the research pool.

**Deliberately not consulted.** Nothing in Chinese state historiography beyond the museum and party-history material already in the pool, and nothing in the Chinese-language scholarly literature. For a subject whose national canon is the register of this file, that is a real limitation and it is named as one.
