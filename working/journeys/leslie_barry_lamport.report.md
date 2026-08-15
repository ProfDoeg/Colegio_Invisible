# Leslie Barry Lamport (b. 1941) - research report

*Atlas of Journeys, working file, compiled from the verified research pool for slug `leslie_barry_lamport`. The subject is living and retired as of January 2025: there is no tomb section, and the absence is stated rather than filled.*

**Legend.** **[A]** = attested, source named inline. **[R]** = reconstruction or secondary aggregation not corroborated against a primary record. Contradictions between the pool's four lenses (chronology, geography, quotes, afterlife) are printed and left standing wherever they could not be settled against a document.

The richest primary source in this pass is Lamport's own annotated publications list at `lamport.azurewebsites.net/pubs/pubs.html`, in which he introduces each paper with a retrospective note. Where a quote below is credited to "the annotated publications page," the raw HTML was downloaded and grepped rather than read through a summarising fetch.

---

## 1. Brooklyn and the mathematics years, 1941 to 1972

**Birth. [A]** Born 7 February 1941 in Brooklyn to Benjamin Lamport, an immigrant from Volkovysk in the Russian Empire (now Belarus), and Hannah Lasser, whose family came from the Austro-Hungarian lands. Jewish household, first generation on both sides (Wikipedia, "Leslie Lamport," Early life). The afterlife lens pinned the birth at 40.7128, -74.006, which is Lower Manhattan; the journey uses the geography figure, **40.6782, -73.9442**.

**CONTRADICTION 1: the Bronx Science years. Corrected, and the correction is itself a reconstruction.** Wikipedia records only "a graduate of Bronx High School of Science," with no attendance years. The geography lens supplied "c. 1955-1958," impossible against the pool's own MIT entry: a 1960 bachelor's degree means matriculation around 1956, so he cannot still have been in high school in 1958. Roughly 1952 to 1956 is the only range that fits, and no source states it. The journey dates the stop 1952-09-01 and carries the problem in `date_confidence`. The two lenses give 40.8781, -73.8916 and 40.8768, -73.8917, both on the school at 75 West 205th Street; the journey uses the first.

**MIT. [A]** B.S. in mathematics, 1960 (Wikipedia). Not computer science: no such degree existed to take. The journey inherits the canonical MIT campus pin **42.3598, -71.0921** byte-identical from `ron_rivest.journey.json` rather than the pool's 42.3601, -71.0942.

**Brandeis. [A]** M.A. 1963, Ph.D. 1972, the doctorate supervised by Richard Palais and titled *The Analytic Cauchy Problem with Singular Data* (Wikipedia; the afterlife lens adds the Brandeis mathematics genealogy record). Twelve years separate the two degrees.

**CONTRADICTION 2: what filled the twelve years. Corrected against Lamport's own account.** The geography lens wrote that "the years at Brandeis run alongside a day job; he is not yet a full-time graduate student when the decade turns," placing the overlap from 1960. Per Lamport's own account he worked part time at **the Mitre Corporation from 1962 to 1965** and then **taught mathematics at Marlboro College from 1965 to 1969**. The overlap begins in 1962, and the Vermont interlude is the actual reason the doctorate took until 1972. Both employments are missing entirely from the chronology and afterlife lenses, which begin his working life in 1970.

**Gap, stated as a gap.** Neither the Mitre office nor the nature of the Mitre work is named in any source reached here. The journey pins Mitre at the Bedford, Massachusetts site (42.4956, -71.2733) and flags the site as a reconstruction; Mitre also ran a Washington-area operation in those years. The Marlboro pin (42.8564, -72.7297) is the Potash Hill campus, likewise a placement.

## 2. Wakefield: Massachusetts Computer Associates, 1970 to 1977

**Employment. [A]** Massachusetts Computer Associates, Inc., 1970 to 1977 (Wikipedia, career section). The address, **Lakeside Office Park, Wakefield, MA 01880**, comes from the author's-address footnote of his own 1974 paper.

**CONTRADICTION 3: the bakery algorithm. Corrected; load-bearing for the whole first act.** The chronology lens tagged the bakery algorithm **[R]**, gave it no date, and placed it at **SRI International, Menlo Park**. All three are wrong. The paper is *A New Solution of Dijkstra's Concurrent Programming Problem*, **CACM 17(8), August 1974, pp. 453-455**, read directly at `lamport.azurewebsites.net/pubs/bakery.pdf`; the byline reads "Leslie Lamport, Massachusetts Computer Associates, Inc." and the footnote gives the Wakefield address. He did not join SRI until 1977. The claim is fully **[A]** and belongs in Massachusetts.

This matters beyond bibliography: the mutual-exclusion work predates the move west by three years, and the founding insight of his career, that correctness can be got out of shared memory with no hardware guarantee of atomicity, was worked out at a software contractor in a Boston office park while the dissertation was still unfinished.

**Quote. [A]** From the annotated publications page, on the bakery paper: "I have invented many concurrent algorithms. I feel that I did not invent the bakery algorithm, I discovered it."

## 3. Menlo Park: SRI International, 1977 to 1985

**Employment. [A]** SRI International, 1977 to 1985 (Wikipedia). The journey inherits the atlas's canonical SRI pin **37.453, -122.1817** byte-identical from `bob_kahn.journey.json` and `vint_cerf.journey.json`. The afterlife lens pinned SRI three times at 37.4419, -122.143, which is downtown Palo Alto, about 3.5 km east of 333 Ravenswood Avenue.

**SIFT. [A]** Software Implemented Fault Tolerance, a NASA-funded project to build a fault-tolerant flight-control computer from redundant processors that vote on results; the pool dates his involvement 1977 to 1980. The Byzantine agreement problem was formulated by the SIFT engineers, not by Lamport.

**CONTRADICTION 4: the attribution of a famous quote. Corrected.** The quotes lens credited "I am often unfairly credited with inventing the Byzantine agreement problem. The problem was formulated by people working on SIFT before I arrived at SRI" to the publications page's entry on *The Byzantine Generals Problem*, dated 1982-07. The raw HTML (line 1954) puts this annotation under the anchor `#reaching`, that is, under **Reaching Agreement in the Presence of Faults (1980)**; the same annotation adds "The term Byzantine didn't appear until [46]," [46] being the Byzantine Generals paper, which settles it. The correct date is 1980. The quote as circulated also drops an internal citation without an ellipsis: the original reads "people working on SIFT (see [30]) before I arrived at SRI." The journey prints it as the pool did but attributes it to the 1980 entry.

**Time, Clocks. [A]** *Time, Clocks, and the Ordering of Events in a Distributed System*, **CACM 21(7), July 1978, pp. 558-565**, PDF read directly. Abstract: "The concept of one event happening before another in a distributed system is examined, and is shown to define a partial ordering of the events." Page 559 carries the formal definition of happened-before in three clauses.

**Reaching Agreement. [A]** *Reaching Agreement in the Presence of Faults*, **JACM 27(2), April 1980, pp. 228-234**.

**CONTRADICTION 5: byline order and the formula. Both corrected.** The geography lens wrote "With Marshall Pease and Robert Shostak, Lamport publishes," putting Lamport first; the byline is **Pease, Shostak, Lamport**. The same entry garbled the central result as "at least three times the number of faulty processors plus one, 3n+1," reusing *n* for both the total and the faulty count. The result is that more than 3m processors are required to tolerate m faulty ones, **n >= 3m+1**. The journey states it in words rather than symbols to avoid re-importing the error.

**Byzantine Generals. [A]** *The Byzantine Generals Problem*, **ACM TOPLAS 4(3), July 1982, pp. 382-401**, PDF read directly. The byline order differs between the two papers (Pease-Shostak-Lamport in JACM 1980, Lamport-Shostak-Pease in TOPLAS 1982), and the pool's chronology lens gives a third ordering again. The journey follows the papers.

## 4. TeX and LaTeX, 1982 to 1994, with a coda in 2018

**Origin. [A, primary and in his own words]** From the annotated publications page: "In the early 80s, I was planning to write the Great American Concurrency Book. I was a TeX user, so I would need a set of macros... Don Knuth had begun issuing early releases of the current version of TeX, and I figured I could write what would become its standard macro package. That was the beginning of LaTeX." (Full text on the journey stop; the ellipsis here stands for two intervening sentences.)

This is the documented Knuth interlock, in Lamport's own sentence, one-directional in the way the atlas allows: LaTeX is built on TeX, Lamport writes about Knuth, the reverse dependency does not exist. The Stanford pin **37.4275, -122.1697** is inherited byte-identical.

**Releases. [R as to version strings and months]** Wikipedia says only that Lamport released versions of his macros "in 1984 and 1985." The strings carried by the pool, "LaTeX 2.06a in September 1984" and "LaTeX 2.09 in August 1985," could not be sourced: the LaTeX Project history page returns 404. The pool's geography lens tagged both **[R]**, correctly. The journey keeps the years, keeps the version numbers out of the prose, and flags the months in `date_confidence`.

**The manual. [A]** *LaTeX: A Document Preparation System*, Addison-Wesley, 1986. Sales in the hundreds of thousands (Wikipedia, LaTeX).

**The handoff. [A]** 21 August 1989, at a TeX Users Group meeting at Stanford, to Frank Mittelbach, who with Chris Rowley and Rainer Schöpf forms the LaTeX3 team. LaTeX2e follows in 1994 and remains the standard; in 2018 LaTeX3 is folded in as a programming layer inside LaTeX2e rather than replacing it (Wikipedia, LaTeX).

## 5. Palo Alto: DEC and Compaq, 1985 to 2001

**Employment. [A]** DEC's Systems Research Center, Palo Alto, from 1985; Compaq from its 1998 acquisition of DEC; the office does not move. Pin 37.4443, -122.1598.

**CONTRADICTION 6, unresolved and flagged.** The interlock lens, in its "no canonical pin intersects" entry, describes his track as running "to Maynard, Massachusetts (Digital Equipment Corporation) to Redmond (Microsoft Research)." Maynard was DEC's corporate headquarters, not the Systems Research Center, and Redmond is not where he worked. Every other lens places him at Palo Alto and then Mountain View. The journey follows the majority and prints the discrepancy rather than dropping it.

**Paxos. [A]** *The Part-Time Parliament* is submitted in 1989 and published in **ACM TOCS 16(2), May 1998, p. 133ff**, PDF read directly. Abstract: "Recent archaeological discoveries on the island of Paxos reveal that the parliament functioned despite the peripatetic propensity of its part-time legislators." Keith Marzullo's editorial note in front of it reads: "This submission was recently discovered behind a filing cabinet in the TOCS editorial office. Despite its age, the editor-in-chief felt that it was worth publishing."

**Note on the rejection story. [R]** The pool says the paper was "initially rejected/shelved for years reportedly for its unusual allegorical presentation." That "reportedly" is doing real work: no rejection letter, referee report, or contemporary account was reached here. What is documented is a nine-year gap and a joke printed by the editor. The journey says the manuscript sat, and does not assert why.

**TLA. [A]** Successive versions of the Temporal Logic of Actions published 1990 and 1994, growing into TLA+. **Paxos Made Simple. [A]** ACM SIGACT News, 2001.

## 6. Mountain View: Microsoft Research, 2001 to 2025

**Employment. [A]** Microsoft Research Silicon Valley, Mountain View, from 2001.

**CONTRADICTION 7: two errors in one sentence. Both corrected.** The geography lens pinned the lab at 37.4224, -122.1131, which falls in the Palo Alto baylands about 3.5 km northwest of the building, and said he "continues developing TLA+ and formal-methods tooling there for the next two decades." The lab at **1065 La Avenida Street** opened in August 2001 and **closed in September 2014**: thirteen years, not two decades. He remained with Microsoft Research after the closure. The journey uses the afterlife coordinate **37.4043, -122.0748**, and flags on the retirement stop that the pin marks an institution rather than a room.

**Specifying Systems. [A]** *Specifying Systems: The TLA+ Language and Tools for Hardware and Software Engineers*, 2002.

**Retirement, and a corrected count. [A]** January 2025, aged 83 (born 7 February 1941; his 84th birthday falls a few weeks later). The chronology lens says this closes "a research career spanning SRI International, Digital Equipment Corporation/Compaq, and Microsoft," and the geography lens calls Microsoft his "fourth industrial home." Both undercount: Mitre (1962-1965) and Marlboro College (1965-1969) precede Massachusetts Computer Associates, and the journey names all seven employers in the retirement campa.

## 7. Honors, and one anachronism

**CONTRADICTION 8: the name of the 2000 prize. Corrected.** The chronology lens says Lamport received "the Edsger W. Dijkstra Prize in Distributed Computing for the first time" in 2000. Year and paper are right per the official podc.org/dijkstra list, but in 2000 the award was called the **PODC Influential-Paper Award**; that name held through 2002. His three wins are confirmed as **2000, 2005, 2014**.

**PODC 2000 host city. [A, upgraded from R]** The geography lens tagged Portland, Oregon as inferred. It is confirmed: podc.org/podc2000/ includes a Portland visitor page (`pdx.html`). Pin 45.5152, -122.6784, tag lifted to attested.

**Honorary doctorates. [A]** Rennes (2003), Kiel (2003), EPFL Lausanne (2004), Lugano (2006), Nancy-Université (2007). Five, all European, none involving relocation.

**IEEE Emanuel R. Piore Award (2004) and IEEE John von Neumann Medal (2008). [A as awards, R as to venue]** Both years attested; neither presentation venue is recorded in any source reached here. The pool invented a geocode for the von Neumann Medal (38.8951, -77.0364, downtown Washington, D.C., which corresponds to no IEEE facility) and a New York geocode for the Piore Award. **Neither is given a pin.** The Piore Award is folded into the Lausanne 2004 stop; the von Neumann Medal is recorded here only.

**ACM SIGOPS Hall of Fame. [A as to years, no pin]** The clocks paper inducted **2007**, the parliament paper **2012**, both confirmed via sigops.org. The pool's Seattle coordinate is wrong: SOSP 2007 was at Skamania Lodge in Stevenson, Washington, and the even-year awards are given at OSDI rather than SOSP, so 2012 is a different conference again. Following the pool's own recommendation, **the geocode is dropped rather than guessed**; both inductions sit inside the Nancy 2007 campa without a pin.

**National Academy of Sciences, 2011. [A]** Pin 38.8931, -77.0469. Election to the National Academy of Engineering in 1991 appears in the afterlife lens only, uncorroborated, and is left out of the journey.

**Jean-Claude Laprie Award, 2013. [A as award, R as to city]** Inaugural award, to the Byzantine Generals paper. The Budapest host city (47.4979, 19.0402) is the pool's inference for that year's DSN conference and was not independently confirmed; carried with the hedge in `date_confidence`.

**Turing Award. [A at one remove]** The 2013 A.M. Turing Award, announced March 2014. The citation is verified only through Wikipedia's quotation of it: `amturing.acm.org` returned HTTP 403 to direct fetch, as did acm.org. The ACM pin 40.7484, -73.9857 is a Midtown Manhattan placement standing for the institution, not a verified headquarters address, and is labelled as such.

**Turing banquet, June 2014. [R]** San Francisco follows the reported pattern for the year; the venue was not confirmed. One detail in the pool's claim is plainly wrong: "eighty miles south of the ceremony." Mountain View is about **thirty-five** miles from San Francisco.

**ACM Fellow, 2014. [A]** **The lamport. [A]** Solana names its smallest currency subunit, one billionth of a SOL, the "lamport," 2020.

## 8. Interlocks

**Donald Ervin Knuth. [A, direct, one-directional]** The only interlock named in a campa. Lamport built LaTeX as a macro package on Knuth's TeX and says so himself above. QUEUE.md line 442 anticipates it: "the TeX typesetting system... joins Lamport (TeX begets LaTeX)." Knuth is queued with no journey file yet, so this is a forward interlock rather than an inherited one.

**Deliberately not named. [R, all of them]** The interlock lens offered a list of Bay Area co-locations: SRI as the second ARPANET node (`bob_kahn`, `vint_cerf`), Whitfield Diffie at Sun in Menlo Park, Ron Rivest at MIT fourteen years after Lamport's degree, Guido van Rossum on a Microsoft payroll in another division and decade, Adi Shamir's ciphers "deployed to Redmond." None is a relation between people; each is a shared address or employer, and the map already shows co-location.

**The eponymous cases. [R]** Lamport holds the A.M. Turing Award and the IEEE John von Neumann Medal, and both `alan_turing` and `john_von_neumann` are travelers here. Receiving a prize named for a dead man is not a relation to him. The awards are named in campas because that is what they are called; the men are not.

**A documented non-connection, recorded so nobody forces it later. [A]** Lamport never worked at Bell Labs; the Murray Hill pin carrying `claude_shannon` and `bjarne_stroustrup` has no Lamport link.

## 9. Gaps

- Nothing survives of his Bronx Science years: no course, no teacher, no dated attendance.
- The Mitre work (1962-1965) is named by Lamport and by nobody else; no office, no project, no publication. The four Marlboro College years are a hole in the technical record entirely, and Massachusetts Computer Associates left almost no public trace beyond the address on his papers.
- No primary account of the Paxos rejection was found; only the nine-year gap and the editor's joke.
- Presentation venues for the Piore Award, the von Neumann Medal, the SIGOPS inductions, and the Turing banquet are all unrecorded or unconfirmed.
- Where he worked between the 2014 lab closure and the 2025 retirement is stated nowhere reached here.

## 10. Sources

**Read directly as PDF or raw HTML** (all at lamport.azurewebsites.net/pubs/)
- *A New Solution of Dijkstra's Concurrent Programming Problem*, CACM 17(8), Aug 1974, 453-455: `bakery.pdf` (byline and Wakefield address footnote both read)
- *Time, Clocks, and the Ordering of Events in a Distributed System*, CACM 21(7), Jul 1978, 558-565: `time-clocks.pdf`
- Lamport, Shostak, Pease, *The Byzantine Generals Problem*, ACM TOPLAS 4(3), Jul 1982, 382-401: `byz.pdf`
- *The Part-Time Parliament*, ACM TOCS 16(2), May 1998, with Marzullo's note: `lamport-paxos.pdf`
- The annotated publications page, raw HTML downloaded and grepped: `pubs.html` (source of the bakery, clocks, Byzantine-agreement and LaTeX annotations quoted above)

**Reached through a fetch tool rather than raw**
- Wikipedia, "Leslie Lamport"; "LaTeX"; "Paxos (computer science)"; "TeX"; "Turing Award"
- podc.org/dijkstra (winners list); podc.org/podc2000/ (Portland host city); sigops.org (Hall of Fame years 2007 and 2012)

**Named and not reachable**
- amturing.acm.org, the primary Turing citation page: HTTP 403. The citation is carried at one remove through Wikipedia and labelled so on the stop. acm.org generally: HTTP 403, which is why the banquet venue stays a reconstruction.
- latex-project.org history page, cited by the afterlife lens for the 2.06a and 2.09 version strings: HTTP 404. Those strings are consequently unsupported.

**Fabricated citation found in the pool and struck**
- The afterlife lens cited "Chang & Fischer, Google Chubby paper, 2006." No such paper exists: Chubby is Mike Burrows, *The Chubby lock service for loosely-coupled distributed systems*, OSDI 2006, single-authored; Chang et al. is Bigtable; the Paxos-in-production paper is Chandra, Griesemer and Redstone, *Paxos Made Live*, PODC 2007. The underlying claim, that Paxos-derived consensus runs in production at Google, Amazon and Microsoft, survives; the citation does not, and no Chubby claim is made in the journey.
