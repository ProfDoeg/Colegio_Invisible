# Edward Burne-Jones (1833-1898): research report

*Compiled 2026-08-11. Slug `edward_burne_jones`. Companion: `edward_burne_jones.journey.json`.*

Legend: **[A]** attested, source named on the line · **[R]** reconstruction or this compiler's inference · **CONTRADICTION** sources disagree; recorded, not adjudicated.

The research pool arrived pre-audited. Corrections from the verification pass are reproduced where they bite; the corrected values, not the original claims, went into the journey file. Wrong dates and coordinates are named as well as replaced, so a later reader can tell which version a downstream file inherited.

---

## 1. Birmingham, 1833-1852

**[A Wikipedia, Edward Burne-Jones]** Edward Coley Burne Jones is born in Birmingham on 28 August 1833, son of a frame-maker; his mother dies days later. The surname is unhyphenated at birth, the hyphen being a legal act of 1894 (§8). He attends King Edward VI grammar school from 1844 and the Birmingham School of Art from 1848.

**[A Georgiana Burne-Jones, *Memorials of Edward Burne-Jones*, Vol. I (1904), Ch. I]** "I was always drawing. Unmothered, with a sad papa, without sister or brother, always alone, I was never unhappy, because I was always drawing."

- **Correction:** the pool dropped the word "was" ("I never unhappy"), restored here. Provenance, not upgraded: Georgiana (Vol. I, Ch. I, roughly p. 8) relays "his own words recorded by a friend, an artist," spoken during a talk about *David Copperfield*. Speech, then a friend's note, then the widow's book, not a memoir.

**[A Memorials Vol. I, Chs. I-III]** Further attested testimony, quoted in full in the journey file: his father as "a very poetical little fellow ... quite unfit for the world into which he was pitched"; Canon Richard Watson Dixon on the crossing from the Commercial to the Classical School at about fifteen; a schoolfellow on his drawing, "always without faltering or pausing." **Correction, the last two:** the pool cited Ch. II for each; Dixon's words open Vol. I, **Ch. III** ("DOMUS SAPIENTIAE, 1849-1851"), the schoolfellow's stand at roughly p. 38 of it. Speaker attributions are correct.

**[A Memorials Vol. I, Ch. III]** Of a drawing of a young priest before an altar, shown to Dixon: "That is what I hope to be one day." **[R]** Dated only "c. 1849-1851," the span of Ch. III; the journey file pins 1850, hedged in `date_confidence`.

**Gaps.** Nothing reachable documents the mother's death beyond "days after his birth," and no source consulted names her. No street address was confirmed beyond "born and baptised near Bennett's Hill" (**[A** Wikipedia, St Philip's Cathedral, Birmingham**]**); the birth pin is an approximation, flagged as one.

---

## 2. Oxford, 1853-1856

**[A Wikipedia]** He enters Exeter College in 1853 to read theology, intending ordination, and meets William Morris there. **[A `william_morris.journey.json`, stop "Exeter College, Oxford, the meeting with Burne-Jones"]** That file places the meeting on his first day and supplies the pin 51.7548, -1.2554, inherited byte-identical. **[A J. Comyns Carr, *Coasting Bohemia*, Project Gutenberg ebook #66838]** From conversation, undated: "I think Morris's friendship began everything for me ... He taught me practically all I ever learnt; afterwards I made a method for myself to suit my nature." Full text at the Exeter College stop of the journey file.

**CONTRADICTION, the date of the Brotherhood.** The pool back-dated it to 1853, as though the society existed on arrival; it was formed by Burne-Jones, Morris and the Birmingham Set in **1856**. The journey file splits the events, 1853 for the meeting, 1856 for the Brotherhood.

**CONTRADICTION, the date of the Ruskin reading.** Two canonical atlas files disagree and this compiler does not resolve it. `william_morris.journey.json` (stop "The Nature of Gothic, Ruskin read at Oxford") gives **1853-1856**, a span; `marcel_proust.journey.json` (stop "The Ruskin translation appears with a long preface"), citing that same file, dates the reading **1856**. The journey file pins 1853 and states the disagreement in `date_confidence`.

**[R]** The turn from the Church to art: the pool tags the discovery of Rossetti and of Malory's *Morte d'Arthur* as **[R]**, "exact date of the shift not firmly documented," notionally 1855. Kept as **[R]**; the Comyns Carr quotation confirms the sequence without dating it. **[A Wikipedia]** In 1856 he makes his first sketch in oils, becomes engaged to Georgiana MacDonald, and leaves Oxford without a degree, encouraged by Rossetti.

---

## 3. Red Lion Square, the Union, Italy, 1856-1859

**[A `william_morris.journey.json`, stop "Street's office and Red Lion Square"]** Morris takes rooms with Burne-Jones at 17 Red Lion Square on leaving Street's office. Dated 1856-01-21, pin 51.5183, -0.1178, inherited byte-identical. **[A Wikipedia]** In 1857 he joins Rossetti's scheme, with Morris and others, to paint Arthurian murals on the Oxford Union debating hall.

**CONTRADICTION resolved upstream, the first Italian journey.** The pool dated it **1857**; the verification pass called this "WRONG BY TWO YEARS," quoting the source: "In 1859 Burne-Jones made his first journey to Italy. He saw Florence, Pisa, Siena, Venice and other places." The 1857 date appears to be a collision with the Oxford Union murals. The journey file uses **1859**; the wrong value is recorded so any downstream file carrying 1857 can be traced here.

**Gap.** No month is attested for any leg, and no route order beyond the source's own list. The journey file follows that order and says so in `date_confidence`, without claiming the list is an itinerary.

---

## 4. The Firm, 1860-1864

**[A Wikipedia]** He marries Georgiana MacDonald on 9 June 1860; the pool gives the place only as "England." **Gap flagged:** no church and no town confirmed, so the journey file pins generic London coordinates and calls the pin a default. Also 1860: "Sidonia von Bork" and "Clara von Bork." 1861: his son Philip is born.

**[A `william_morris.journey.json`, stops "Red House, Bexleyheath" and "8 Red Lion Square, the founding of the Firm"]** At Red House he paints wall murals for the newly married Morris, and Georgiana records his verdict, "the beautifullest place on earth" (pin 51.4556, 0.1303, dated 1860-06-01, inherited). He is then a founding partner of the Firm with Ford Madox Brown, Charles Faulkner, Rossetti, P. P. Marshall and Philip Webb, the prospectus going out 11 April 1861 from 8 Red Lion Square (pin 51.5183, -0.1178, inherited). **[A Wikipedia, Morris, Marshall, Faulkner & Co.]** In 1862 he designs the Tristram and Isoude glass panels, and the Firm's showing at the London International Exhibition draws wide notice.

**[A `william_morris.journey.json`, stop "The stained glass, light through leaded saints"]** He draws the figures while Morris leads the colours; windows go into Jesus College and Christ Church, Oxford, and churches across England. **Flag:** that stop's place string is "Oxford / England (churches)" but its pin, **51.5225, -0.1235**, is in Bloomsbury, London. Canonical pins are inherited byte-identical, so the coordinate stands and the stop here is named for the London drawing office, not the Oxford installation. The mismatch inside the Morris file is flagged, not repaired.

**CONTRADICTION, The Merciful Knight.** The pool dates the painting 1863; the cited source anchors it to 1864 ("In 1864 ... exhibited, among other works, The Merciful Knight"). The journey file merges picture and exhibition into one 1864 stop and asserts no standalone 1863 event.

**[A Wikipedia]** In 1864 he is elected an associate of the Society of Painters in Water-Colours; in the same year, during Georgiana's grave illness with scarlet fever, a son, Christopher, is born and dies soon after.

---

## 5. Kensington, Fulham, the years out of sight, 1866-1876

**[A Wikipedia]** Margaret Burne-Jones is born at 41 Kensington Square in 1866; in the same year he begins an affair with his model and pupil Maria Zambaco, a public scandal that nearly ends the marriage. In 1867 the family settles at the Grange, North End, Fulham, his home for the rest of his life, and he designs the Green Dining Room at the South Kensington Museum for the Firm. In 1868 he begins the first Pygmalion series. In 1870, after controversy over the nudity in "Phyllis and Demophoön," he resigns from the Society of Painters in Water-Colours and enters roughly seven years of minimal public exhibition.

**CONTRADICTION, the 1874 entry.** The pool dated "The Beguiling of Merlin" and "Pan and Psyche" to 1874, called by the verification pass "a false single anchor": *Merlin* was painted 1872-1877 and first exhibited May 1877; *Pan and Psyche* is c. 1872-74, exhibited 1878. The journey file states the spans, not the anchor.

**[A Wikipedia, Morris, Marshall, Faulkner & Co.]** On 31 March 1875 the firm is dissolved amid partner disputes over share returns and reorganised under Morris's sole ownership.

**Quotations of this period, all [A] from Memorials Vol. II, Ch. XVI, full texts in the journey file. Every date the pool attached to them was rejected: the chapter spans 1868-1871 and Georgiana dates none of these utterances.** "You can tell the life of those who have fought and won and been beaten ..." (1868 dropped); "a savage passion for work," marked "he once exclaimed" (1868 dropped); "I want big things to do and vast spaces ... Oh! -- only Oh!", a recurring saying (1870 dropped, lowercase "only" and the dash restored). Only the tribute to Morris, "The like of him doesn't exist for dearness and goodness and simplicity," is dated in the chapter, to 1871.

**NOT A BURNE-JONES QUOTATION.** "Nothing ever interrupted the intimacy with Morris; that friendship was like one of the forces of nature." Verbatim in the same chapter, but **Georgiana's own narration**, introducing a quotation from Edward's notes. It must not be given as his utterance; the journey file attributes it to her. Its pool date of 1868 is also unsupported (the adjacent letter is February 1869).

**[A Comyns Carr]** A further undated recollection, on quarrelling with Morris about Art and wishing to travel backwards to Botticelli's Florence. Full text at the Florence stop.

---

## 6. The Grosvenor Gallery and fame, 1877-1885

**[A Wikipedia]** In May 1877 he breaks through publicly at the Grosvenor Gallery's opening, showing eight oils including "The Beguiling of Merlin."

**CONTRADICTION, the 1878 entry.** The pool placed "The Annunciation" and the second Pygmalion series in 1878. Neither is supported: *The Annunciation* was painted 1876-79 and exhibited at the Grosvenor in **1879**; the second Pygmalion series is 1875-78; what the source places in **1878** is the exhibition of *Laus Veneris*, *Chant d'Amour* and *Pan and Psyche*.

**[A Wikipedia]** 1880: he buys Prospect House, Rottingdean, and paints "The Golden Stairs." **[A Wikipedia, St Margaret's Church, Rottingdean]** He kept a house on the green for eighteen years until his death, which checks: 1880 + 18 = 1898. Honorary Oxford degree 1881, Honorary Fellow 1882, "The Wheel of Fortune" 1883, "King Cophetua and the Beggar Maid" 1884. In 1885 he becomes president of the Birmingham Society of Artists and an Associate of the Royal Academy.

---

## 7. The late work, 1890-1897

**[A `william_morris.journey.json`, stop "The tapestry loom, the Adoration and the Holy Grail"]** At Merton Abbey Works he supplies the cartoons for the Firm's tapestries, *The Adoration of the Magi* and *The Quest of the Holy Grail*; Morris and Dearle do the foregrounds. Dated 1890-01-01, pin 51.4158, -0.1772, inherited.

**CONTRADICTION, the 1890 entry.** The pool put the second Briar Rose series and "The Star of Bethlehem" in one year. They split: 1890 for the second Briar Rose series, exhibited by itself; *The Star of Bethlehem*, painted for the corporation of Birmingham, worked 1887-91 and **exhibited 1891**. Two entries in the journey file.

**[A Wikipedia]** Elected to the Art Workers' Guild 1891; resigns his Royal Academy Associateship 1893; approached in November 1893 about a baronetcy. **[A Wikipedia, St Margaret's Church, Rottingdean]** Three lancet windows at St Margaret's, installed 1893, showing Gabriel, Michael and Raphael, commemorate his daughter Margaret's marriage and predate his burial there by five years.

**[A Wikipedia, Kelmscott Chaucer]** In 1896 the Kelmscott Press completes the Chaucer with eighty-seven wood engravings by Burne-Jones, who left the base stories unillustrated and avoided comical situations, believing "that pictures are too good to be funny." The edition runs to 425 paper copies at twenty pounds and thirteen vellum at 120 guineas; Yeats called it the finest printed book of the era, though it lost money.

- **Correction, coordinate.** The pool pinned the press at 51.4915, -0.2242, some 800 m east near Furnivall Gardens. It stood at No. 14 Upper Mall, Hammersmith. The journey file uses **51.4903, -0.2345**.

**[A Wikipedia, St Philip's Cathedral, Birmingham]** He designs the west window of St Philip's, dedicated 1897 in memory of Henry Bowlby, plus three further windows at the east end. **Gap, unresolved:** the subjects of those three could not be confirmed, the cathedral article being silent on them. Nothing is inferred.

**Correction, the Belgian election.** The 1897 election to the Royal Academy of Science, Letters and Fine Arts of Belgium is attested, but the pool's place field, "Belgium (honorary, in absentia)," is not: no consulted source calls the election honorary or him absent. The journey file drops the parenthetical.

---

## 8. The name, the title, the death, 1894-1898

**[A Wikipedia]** February 1894: surname changed by law to the hyphenated Burne-Jones. 3 May 1894: created a baronet, of Rottingdean in the County of Sussex and of the Grange, Fulham. "The Last Sleep of Arthur in Avalon," pursued since around 1881, is unfinished at his death on 17 June 1898, aged 64, after influenza and a second sudden collapse.

- **Correction, coordinate.** The pool pinned the death at 51.5074, -0.1278, the generic Charing Cross pin for "London." He died at the Grange, North End, Fulham: **51.4908, -0.2069**, about 6.5 km west, which the journey file uses so the death pin does not land in Trafalgar Square.

**[A Wikipedia]** On 23 June 1898 a memorial service is held at Westminster Abbey at the intervention of the Prince of Wales; sources describe it as the first time an artist had been so honoured. **[A Wikipedia, St Margaret's Church, Rottingdean]** His ashes are interred not in the Abbey but at St Margaret's, Rottingdean, where the ashes of Georgiana and of their granddaughter, the novelist Angela Thirkell, join his.

- **Correction, coordinate, applied to four pool entries.** The pool gave St Margaret's as 50.8058, -0.0521, roughly 400 m east-southeast of the church, off the green and toward the seafront. The church stands at 50 deg 48'24"N, 0 deg 03'27"W = **50.8068, -0.0575**, used here for the burial and the archangel windows. The Kipling entry carried the same drift (50.806, -0.0526); the village-green stop is aligned at approximately 50.8065, -0.0570.

---

## 9. Afterlife

**[A Wikipedia, St Philip's Cathedral, Birmingham]** In the Second World War the Birmingham Civic Society removes his cathedral windows before the building is bombed on 7 November 1940; they are reinstated undamaged in the 1948 restoration.

**[A Wikipedia]** On 16 June 1933, the centenary of his birth, his nephew Stanley Baldwin, then Prime Minister, opens an exhibition at the Tate Gallery, recorded as poorly attended. Interest revives after Harrison and Waters's 1973 monograph and Fitzgerald's 1975 biography; a 1989 Barbican exhibition traces his influence on later artists.

**CONTRADICTION resolved upstream, the 1998 tour.** The pool claimed a retrospective travelling 1997-1998 to Tate Britain, the Metropolitan Museum, Birmingham and the Musee d'Orsay. Rejected on two counts: the tour **opened in New York**, not London, and Tate was not a venue on it (the conflated 1997 London show is a separate exhibition on British Aestheticism and Symbolism); and "Tate Britain" did not exist under that name until 2000. Corrected itinerary: 1998, Metropolitan Museum of Art, then Birmingham Museum and Art Gallery, then the Orsay.

Rudyard Kipling, his nephew by marriage through Georgiana MacDonald, moves to The Elms on Rottingdean green in 1897 and writes many of the *Just So Stories* there **[A]**. That local memory folds the two households into one mythology of the village is **[R]**, this compiler's inference.

---

## 10. Interlock with the existing atlas

Genuine crossings, named in the journey file's `campa` text:

- **`william_morris` [A]**, six stops there: Exeter College 1853, Red Lion Square 1856, Red House 1860, the Firm 1861, the stained glass, the Merton Abbey tapestries. Four coordinates inherited byte-identical.
- **`lancelot` [A]**, suggested_refs near line 334: Grail painting by Rossetti and Burne-Jones as the visual tradition for the Siege Perilous, naming him directly.
- **`guinevere` [R]**: that file near line 119 names **Rossetti only**; Burne-Jones is inferred from the tradition documented in the Morris tapestry stop.
- **`marcel_proust` [A]**, stop "The Ruskin translation appears with a long preface": Ruskin as shared master, the Oxford reading with Burne-Jones at Morris's side.
- **`mahatma_gandhi` [R]**: *Unto This Last* on the Natal train in 1904, the same Ruskin whose *Nature of Gothic* converted Morris and Burne-Jones. Inferred, not stated there.

Examined and **not** used: `dante`, `edward_bellamy`, `jules_verne`. In each the link runs through Rossetti, Morris or Ruskin rather than through any Burne-Jones event, and the pool tags the Verne one **[R]**.

Canonical geography pins checked and **rejected for want of evidence**, recorded so the check is not repeated. **Kaaba, Mecca (21.4225, 39.8262)** and **Temple Mount, Jerusalem (31.778, 35.2354)**: nothing links him to either, and the pool's Holy Land iconography suggestion is unattested speculation. **Buenos Aires (-34.6037, -58.3816)**: no connection of any kind. **Paris (48.8566, 2.3522)**: no Burne-Jones-specific Paris stop in the searched files, and the "great Exhibition" medals in the Morris file are most likely the **London** Exhibition of 1862, a misassignment risk the pool flags. Paris enters once only, in 1998, at the Orsay.

---

## Sources

**Reachable and used.** Wikipedia: "Edward Burne-Jones" (spine of the chronology and afterlife); "Morris, Marshall, Faulkner & Co."; "Kelmscott Chaucer"; "St Margaret's Church, Rottingdean"; "St Philip's Cathedral, Birmingham"; "Kelmscott Press", "Kelmscott House" and "North End, Fulham" (coordinates only). Georgiana Burne-Jones, *Memorials of Edward Burne-Jones*, 2 vols., Macmillan, 1904: Vol. I, Chs. I-III for childhood and school, Vol. II, Ch. XVI for the Grange years; two chapter attributions in the pool were wrong and are corrected against the text. J. Comyns Carr, *Coasting Bohemia*, Gutenberg #66838: two undated conversational recollections. Atlas files: `william_morris`, `dante`, `lancelot`, `guinevere`, `marcel_proust`, `mahatma_gandhi`, `edward_bellamy`, `jules_verne`, and `QUEUE.md` line 269.

**Named but not reached this session.** Penelope Fitzgerald's 1975 biography and Harrison and Waters's 1973 monograph: known only through the encyclopaedia notice of the revival they caused, and nothing here rests on either. The Kelmscott Chaucer itself: the claim that he omitted the coarser tales rests on a paraphrase of his own remark, not a leaf-by-leaf check. The 1998 Metropolitan Museum catalogue: the itinerary correction rests on the encyclopaedia's sentence. Parish records for the 1860 marriage, which would settle the church and town left blank above.

**Known unknowns.** The wedding place, 9 June 1860; the subjects of the three eastern windows at St Philip's; any month or route order for the 1859 Italian journey; the date of the Oxford Ruskin reading, where two canonical files disagree; the Birmingham address of the shop and the birth.
