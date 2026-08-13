# Bjarne Stroustrup: research report
*2026-08-13. Born Aarhus, Denmark, 30 December 1950; living at the date of research. Prepared for the atlas computing wing.*

**Method.** Four lenses (chronology, geography, quotations, atlas interlock) were gathered, then each re-checked adversarially against its own cited sources. This report carries the verified state including the corrections that pass forced. Contradictions that cannot be settled from reachable material are left open.

**Legend.** **[A]** = attested, source named. **[R]** = reconstruction, tradition, or inference, including anything resting on a single uncorroborated secondary summary. **(corr.)** marks a correction to the gathering pass.

**Source hygiene, first.** He maintains `stroustrup.com/bio.html`, plus his own FAQ and quotations pages: primary self-report, better than Wikipedia on dates of his own titles, which it overturns three times below. His framing of his work was treated as testimony, not fact.

---

## 1. Aarhus, 1950 to 1975

- **[A]** Born 30 December 1950 in Aarhus, Denmark's second city, into a working-class family (Wikipedia; Britannica corroborates the year alone). No source names hospital, street, or district; the pin is the historic centre and claims nothing narrower.
- **[A, bio.html]** Schooling at Laessoeesgade Skole, then Marselisborg Gymnasium. **[R]** The enrolment years (c. 1957-1966, c. 1966-1969) are arithmetic from the birth date and published nowhere reachable.
- **(corr., two pins.)** Laessoeesgade Skole was pinned at 56.1487, 10.2065; Nominatim gives Langenaes / Frederiksbjerg, Aarhus 8000 at **56.1461, 10.1876**, 1.2 km west. Marselisborg Gymnasium was pinned at 56.1425, 10.1971; Nominatim gives Taarbaekvej, Rosenvaenget at **56.1395, 10.2012**. A trap for re-checkers: English Wikipedia's infobox coordinate for that school reads 56.822 N, some 75 km north of Aarhus. It is corrupt; discard it.
- **[A]** Mathematics with a computer science focus at Aarhus University from 1969; cand.scient. 1975 (Wikipedia, Britannica). **[A, HOPL-II]** He meets Simula there and names the encounter as decisive for C++.
- **(corr., label and pin.)** The stop was labelled "Department of Computer Science (DAIMI)" at 56.1717, 10.1975. Label and coordinate disagree with each other and with the period: the modern department sits in the Katrinebjerg research park, where it was not in 1969-1975. Relabelled to the main campus, moved to Wikipedia's **56.1706, 10.2011**.
- **[A]** Marries Marian Tinson, 1975 (Wikipedia). No further detail reachable.

## 2. Cambridge, 1975 to 1979

- **[A]** Doctoral research at Cambridge on distributed computer systems, supervised by David Wheeler; PhD 1979; dissertation "Communication and control in distributed computer systems" (Wikipedia; Britannica corroborates). **[A, HOPL-II and bio.html]** The work uses the Cambridge CAP capability computer; he writes his simulator in Simula, finds it too slow, rewrites it in BCPL, and later calls that rewrite formative.
- **[A]** Member of Churchill College during the doctorate (Wikipedia, notable alumni). **(corr., pin.)** Churchill was pinned at 52.2181, 0.0986, some 600 m north-northwest of the college in open ground. Wikipedia gives Storey's Way, **52.213, 0.101**. The afterlife lens had given 52.2138, 0.1024; reconciled to the Wikipedia value, not averaged.
- **Site note.** In 1975-1979 the Computing Laboratory was on the New Museums Site (52.2036, 0.1188); it moved to the William Gates Building only in 2001, so his doctoral and 2012 pins differ correctly.

## 3. Murray Hill, 1979 to 1983

- **[A, HOPL-II 2.2]** Joins the Computing Science Research Center at Bell Labs, Murray Hill, April 1979, analysing how the Unix kernel might be distributed across a network. Working preprocessor Cpre by October 1979; in production on sixteen systems by March 1980 as "C with Classes". **[A, HOPL-II 2.3]** Internal technical report, April 1980.
- **(corr., two errors in one item.)** The geography pass attached "Adding Classes to the C Language: An Exercise in Language Evolution" to the April 1982 SIGPLAN Notices paper and called the language "by now known as C++". HOPL-II 2.3: the April 1982 SIGPLAN Notices paper is **"Classes: An Abstract Data Type Facility for the C Language"**, "followed by a more detailed Bell Labs technical report Adding Classes to the C Language... later published in Software: Practice and Experience." And in April 1982 the language was still C with Classes; the other name did not exist.
- **[A, bs_faq.html]** First internal version in use inside AT&T, August 1983.
- **(corr., hedge removed, date refined.)** The naming was tagged as widely repeated in secondary sources and unverified. The source already cited states it in his own words: "The name C++ was suggested by Rick Mascitti. It was first used in December of 1983." **[A], December 1983.**

## 4. The language goes out, 1985 to 1996

- **[A, bs_faq.html, HOPL-II]** First commercial release of C++ and first edition of "The C++ Programming Language", October 1985.
- **(corr., a significant one.)** Release 2.0 was reported as shipping "between 1985 and 1988". HOPL-II: it "introduced multiple inheritance (Sec 4.2) in **June 1989**", and readers had to "wait until June 1989 for release 2.0". The 1985-1988 span is HOPL's section heading for the design period, not a ship date. For the same reason: templates arrived with Release 3.0, 1991.
- **(corr., tag upgraded, pin moved.)** The ANSI committee founding was tagged [R] because "the exact city of the first meeting is not established here". The cited source establishes it. HOPL-II 6.5: "The organizational meeting of the ANSI C++ committee, X3J16 took place in December of 1989 in Washington, D.C." Now **[A], December 1989, Washington D.C. (38.90, -77.04)**, off the Murray Hill pin it had. The 1991 shift to a joint ISO project is supported separately by HOPL's June 1991 Lund meeting.
- **[A, Britannica]** Second edition 1991; third edition 1997. **[A]** Active in ANSI/ISO standardisation from 1989.
- **[A, HOPL-II proceedings]** April 1993: presents "A History of C++: 1979-1991" at HOPL-II, Cambridge, Massachusetts. It becomes the canonical origin account and the backbone of this file.
- **[A]** March 1996: ISO/ANSI committee meeting at Santa Cruz, documented in surviving photographs, one of many quarterly meetings.

## 5. Honors of the 1990s, and the AT&T split

- **[A, bio.html]** Hopper Award 1993; Bell Labs Fellow 1993; "The Design and Evolution of C++" 1994; AT&T Fellow 1996. **[A, Britannica]** Named by Fortune one of America's twelve top young scientists, 1990.
- **(corr., in two lenses.)** Chronology and afterlife both put the ACM Fellowship in 1993, "the same year" as the Hopper Award. Wikipedia's "List of fellows of the ACM", mirroring the society's roster, places him in the **1994** class. bio.html files "ACM fellow" under 1993, but that is his page grouping the two honors; the roster is authoritative. Split: Hopper 1993, ACM Fellow 1994.
- **Contradiction, adjudicated but recorded.** Wikipedia dates the IEEE Fellowship 1994; Britannica 2005; the gathering pass declared it unresolvable. bio.html reads "2005: IEEE Fellow", agreeing with Britannica. The atlas takes **2005** and notes that Wikipedia still says otherwise.
- **(corr., three problems in one item.)** It was written that he headed Large-Scale Programming Research at AT&T Labs Research from 1995, "the successor to Bell Labs after the 1996 AT&T divestiture, continuing work from the same Murray Hill campus." (1) The 1995 start year is unsourced; bio.html says only "from its creation". (2) Murray Hill continuity is very likely wrong: in the 1996 split, Bell Labs and Murray Hill went to Lucent, while AT&T kept AT&T Labs, with research sites at Florham Park, Bedminster, and Middletown. bio.html calls him a member of "AT&T Labs - Research, the half of Bell Labs Information Sciences Research that AT&T kept". (3) 1996 is the trivestiture; "divestiture" names the 1984 breakup. The atlas pins Florham Park, marks the site open, claims no start year.
- **[A]** Steps down as department head, 2002 (Wikipedia).

## 6. Texas A&M, 2002 to 2014

- **[A]** 2002: College of Engineering Chair Professor in Computer Science, Texas A&M (Wikipedia, Britannica).
- **(corr., tag upgraded.)** The Xi'an Jiao Tong honorary professorship, 2002-2006, was tagged [R] and sourced to a "Wikipedia biographical summary". bio.html states it directly: "2002-2006: Honorary Professor at Xi'an Jiao Tong University." **[A]** for appointment and span; what remains unknown, and is kept as a hedge, is whether he travelled there.
- **[A]** 2004: elected to the National Academy of Engineering; IEEE Computer Entrepreneur Award.
- **(corr., superlative dropped.)** The 2005 William Procter Prize (Sigma Xi) is confirmed; the attached claim that he was its first computer scientist is false. Herbert A. Simon received it in 1980 (Wikipedia list of recipients). No source prints the claim, so it is removed rather than re-attributed.
- **[A]** 2008: Dr. Dobb's Excellence in Programming Award; first edition of "Programming: Principles and Practice Using C++" (later editions 2014, 2024).
- **(corr., two honors disentangled.)** Chronology put University Distinguished Professor and the Aarhus honors both in 2010. bio.html separates "2010: Promotion to Distinguished Professor (the university's highest academic rank)" from "2011: University Distinguished Professor (honorable title, bestowed in perpetuity)". So 2010 = Distinguished Professor plus Aarhus; **University Distinguished Professor is 2011**. Geography already had this right; the lenses are reconciled to bio.html.
- **(corr., related over-claim.)** The afterlife pass folded the 2010 Aarhus honor into "a run of honorary doctorates". It was not a doctorate: bio.html gives Honorary Professor in Object-Oriented Programming Languages plus the Rigmor og Carl Holst-Knudsens Videnskabspris.

- **[A, bio.html]** Autumn 2011: sabbatical at Princeton, still on the A&M faculty. Spring 2012: sabbatical at the Cambridge Computer Laboratory, and Overseas Fellow of Churchill. **(corr., pin)** the William Gates Building is at **52.211, 0.092** (Wikipedia), not 52.2138, 0.0917.
- **[R]** 2013 ITMO University honorary doctorate. The afterlife pass cited bio.html, but the honor does not appear there in the fetched text, so the citation does not support it. Held as unconfirmed, neither dropped nor promoted.
- **[A]** May 2013: fourth edition of the book, covering C++11.

## 7. New York, 2014 to 2022

- **(corr., a title moved five years.)** He was reported as joining Morgan Stanley in January 2014 as "Technical Fellow and Managing Director". bio.html: "From January 2014 to April 2022, Bjarne was a Managing Director in the technology division of Morgan Stanley... In 2019, he was promoted to be Morgan Stanley's first Technical Fellow." 2014 is **Managing Director only**; Technical Fellow is **2019**.
- **[A, bio.html]** January 2014: also Visiting Professor at Columbia, until July 2022. **[A, bs_faq.html]** He lives in New York City, where his family is based, and explains the move partly as wanting to be in "the North-East".
- **[A]** "A Tour of C++": 2014, 2018, 2022. **[A]** 2015: Dahl-Nygaard Senior Prize; Fellow of the Computer History Museum, "for inventing C++". **[A]** 2017: IET Faraday Medal (Savoy Place, London) and Honorary Fellow of Churchill College, the second step after Overseas Fellow in 2012.
- **[A]** 2018: Charles Stark Draper Prize (NAE), IEEE Computer Society Computer Pioneer Award, John Scott Legacy Medal (Franklin Institute). **(corr.)** The Draper is not "the Academy's highest honor" in NAE's framing; Wikipedia describes the Draper, Russ, and Gordon Prizes together as its three major prizes. **[R]** The February ceremony date is inferred from NAE's usual calendar.
- **[A, bio.html]** 2019: honorary doctorate, Universidad Carlos III de Madrid. **Two lenses disagreed on campus**: geography said Leganes, afterlife said Getafe while pinning a coordinate that falls in Leganes. UC3M's engineering school is at Leganes; both are reconciled to **Leganes, c. 40.333, -3.766**. The geography coordinate 40.3287, -3.7623 sat 500 m southeast of the campus.
- **(corr., two dates uncollapsed.)** Chronology put the Morgan Stanley retirement and the Columbia full professorship both at April 2022. bio.html: Morgan Stanley "to April 2022"; visiting professorship "to July 2022"; "As of July 2022, Bjarne is a Professor of Computer Science at Columbia University." **Retirement April 2022, full professorship July 2022.** The geography lens had July right; reconciled to bio.html.

## 8. Living reputation: the tomb section that cannot be written

**The subject is alive.** No tomb, gravesite, or memorial monument exists, and the brief's funerary frame does not apply. Stated as a gap rather than filled with substitutes dressed as monuments.

- **[A, bio.html]** "The C++ Programming Language" runs to four main editions plus a Special Edition (2000), translated into at least nineteen languages.
- **[A, bio.html]** 2021: Technical Advisor to Metaspex; his page also lists YetiWare (February 2026) and Susquehanna International (June 2026), current only as of the fetch.
- **(corr., tag upgraded.)** The 2025 Kraks Blaa Bog entry was marked "not independently corroborated"; the cited source states it verbatim, "Entered into Kraks Blaa Bog 2025 (The Danish equivalent for the British Who's Who)", so it is **[A]**. Only the gloss about late homeland canonization is [R].

## 9. Quotations

All quotations used were checked against `stroustrup.com/quotes.html`, the HOPL-II PDF text, or `bs_faq.html`.

- **(corr., a misquote inside an item about misquotation.)** The afterlife pass rendered the famous line as "...it blows away your whole leg." The source reads: **"C makes it easy to shoot yourself in the foot; C++ makes it harder, but when you do it blows your whole leg off."** The variant is the meme drift the item was written to describe. The cited URL was wrong too: stroustrup.com/quotes.html, not bjarnestroustrup.com/quotes. He dates the line to "1986 or so".
- **(corr., attribution narrowed.)** "An organization that treats its programmers as morons..." was attributed to the second and third editions. The quotes page gives TC++PL3 only, a deliberate distinction: neighbouring quotes there are explicitly marked "TC++PL2 and TC++PL3", this one is not.
- **[A]** The indirection aphorism is not his. He attributes it to David J. Wheeler, his advisor, and asks not to be credited; the journey file preserves that in quote_source.

## 10. Atlas interlocks

- **[A]** Murray Hill is already canonical. `claude_shannon.journey.json` carries **40.6852, -74.396**; `bob_kahn.journey.json` places Kahn on the technical staff c. 1960-62. Stroustrup's Bell Labs stops inherit that coordinate byte-identically, not the 40.687, -74.3986 and 40.687, -74.3999 values his own lenses generated. Shannon works there from 1948, marries Betty Shannon in 1949, and builds Theseus with her.
- **[A]** `linus_torvalds.journey.json` narrates Unix as begun at Murray Hill by Ken Thompson and Dennis Ritchie in 1969. Stroustrup arrives in the same building ten years later and extends Ritchie's C. That file does not mention him; the tie is institutional and written as such.
- **[R]** `alan_turing.journey.json` carries the Cambridge precinct pin **52.2043, 0.1149**. Stroustrup takes his doctorate in the same university four decades later, at Churchill under Wheeler. No atlas file yet asserts his Cambridge years, and the two never met: shared institution, not encounter.
- **[A]** `guido_van_rossum.journey.json` narrates a European computer scientist relocating permanently to the US (NIST Gaithersburg, 1994; permanent 1995). Stroustrup runs the same arc fifteen years earlier, Denmark to New Jersey: structural parallel, not meeting. One genuine mutual reference exists, his quotes page contrasting his aims with van Rossum's, and it is used in the journey file.
- **[R]** `john_von_neumann.journey.json` and `alan_turing.journey.json` supply the lineage device the atlas already uses for Python and Linux: hardware descending from the stored-program architecture. Applied once here, at Princeton, as descent rather than encounter.
- **House-style flag.** `bob_kahn.journey.json` places Kahn's 1964 MIT professorship at Cambridge, **Massachusetts** (42.3736, -71.1097). Stroustrup's doctoral Cambridge is **England**; the two must stay distinct on the globe. His 1993 HOPL-II stop is the Massachusetts one and deliberately inherits the Kahn pin.
- **Gap.** Denmark has no existing pin or traveler in the reachable atlas files. The nearest Danish presence is Soren Kierkegaard, queued for the philosophy wing (QUEUE.md line 643), unresearched. No crossing between the two Danes is attested and none is invented.
- **Negative search.** Kaaba, Temple Mount, Paris, and Buenos Aires pins were searched for a tie to any computing-wing traveler; none found, none inherited. Of his decades of WG21 travel, only Santa Cruz 1996 is documented here.
- **Coordinate discipline.** `alan_turing.journey.json` leaves its few-hundred-metre disagreement with `claude_shannon.journey.json` over the 1943 tea unresolved rather than averaging; same rule here.

## 11. Contradictions and gaps, not resolved

1. **IEEE Fellow year.** Wikipedia 1994 vs Britannica 2005; adjudicated to 2005 on bio.html, and Wikipedia is uncorrected.
2. **ACM Fellow year.** ACM roster 1994 vs his own page's 1993 grouping; adjudicated to 1994.
3. **AT&T Labs Research.** Neither his work site after 1996 nor the department's creation year is published; the Florham Park pin is inference, the weakest geographic claim here, and the unsourced 1995 figure is not used.
5. **ITMO 2013.** Reported but absent from the cited source. Held at [R].
6. **Aarhus school enrolment years.** Estimated, never published.
7. **Draper ceremony date.** February 2018 inferred, not attested.
8. **Birth location within Aarhus.** No hospital or district named anywhere reachable.
9. **Xi'an.** Whether the 2002-2006 appointment involved travel is not established.

## Sources

**Primary self-report (fetched directly)**
- stroustrup.com/bio.html: dated career chronology, schools, sabbaticals, honors, Morgan Stanley and Columbia dates, Kraks Blaa Bog, advisory roles. Controlling source for dated titles.
- stroustrup.com/bs_faq.html: the Mascitti naming and December 1983, August 1983 first internal version, October 1985 first commercial release, the "North-East" remark.
- stroustrup.com/quotes.html: all quotations, his glosses, the Wheeler attribution.
- Stroustrup, "A History of C++: 1979-1991" (HOPL-II 1993), PDF text from stroustrup.com/hopl2.pdf: April 1979 arrival, Cpre, sixteen systems, the April 1982 papers, Release 2.0 June 1989, X3J16 December 1989, the June 1991 Lund meeting.

**Reference works**
- Wikipedia: "Bjarne Stroustrup" (birth date, marriage, dissertation, most honors; wrong on the IEEE Fellow year); "List of fellows of the ACM" (1994 class); "William Procter Prize for Scientific Achievement" (Simon, 1980); "Bell Labs" and "AT&T Labs" (1996 trivestiture, Murray Hill to Lucent, research sites); "Charles Stark Draper Prize"; "Churchill College, Cambridge"; "William Gates Building".
- Encyclopaedia Britannica, "Bjarne Stroustrup": birth year, degrees, Bell Labs, Fortune 1990, edition years, IEEE Fellow 2005, Texas A&M, Morgan Stanley.
- OpenStreetMap / Nominatim: corrected coordinates for the two Aarhus schools.

**Atlas files consulted for interlock**
claude_shannon.journey.json (canonical Murray Hill pin), betty_shannon.journey.json, bob_kahn.journey.json, alan_turing.journey.json, linus_torvalds.journey.json, guido_van_rossum.journey.json, john_von_neumann.journey.json, QUEUE.md lines 335 and 643.

**Checked and negative, or not reachable**
- No atlas file contains any Danish pin; Aarhus enters the corpus with this journey.
- ITMO's own announcement of the 2013 honorary doctorate was not reached; the claim rests on one secondary summary and stays [R].
- No source names the hospital or district of the 1950 birth, the creation year of the Large-Scale Programming Research department, or his work site after the 1996 AT&T split.
- English Wikipedia's infobox coordinate for Marselisborg Gymnasium (56.822 N) is corrupt and was discarded.
