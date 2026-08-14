# Guido van Rossum, research report
*2026-08-13. Atlas of Journeys, computing wing. Subject living; the file has no terminal date.*

Legend: **[A]** = attested, source named · **[R]** = reconstruction, inference, or tradition · *contradiction* = two reachable sources disagree, recorded rather than adjudicated.

The most useful source here is his own posted resume at `gvanrossum.github.io/Resume.html`, granular to the month for every employer from 1977 to 2026. It is self-authored: treated as attested for dates and titles, uncorroborated where it stands alone. Next comes his retrospective writing, the `python-history.blogspot.com` essays of January 2009, the Artima post on the origin of BDFL, and *A Brief Timeline of Python*. Where his timeline and Wikipedia disagree on a release date, this report follows his timeline and flags the disagreement. Fifteen corrections against the research pool are itemised at the end.

---

## 1. The Hague and Haarlem, 1956-1974

**Birth [A].** Born in The Hague, 31 January 1956 (Wikipedia). Nothing more specific than the city is recorded anywhere reachable: no hospital, no clinic, no street, no parish. The file pins the city centre (52.0705, 4.3007) and says so in `date_confidence`.

**Upbringing in Haarlem [R].** Dutch Wikipedia places the childhood in Haarlem. Neither the year of the move nor any school is named, and English Wikipedia does not carry the claim at all. The stop's date (1963) is a placeholder inside the schooling years, labelled as such.

**Nederlandse Jeugdbond voor Natuurstudie [A, undated].** Dutch Wikipedia attests teenage membership in the Dutch youth nature-study league. No source gives dates; the file dates the stop 1971 with `date_confidence` reading "the membership is attested, the years are not."

**International Mathematical Olympiad, bronze, 1974 [A medal / R venue].** Wikipedia attests the medal and the year but not the host city. Erfurt and the July dating come from the IMO's published host history for the 16th olympiad, not from any biography of van Rossum; the split basis is preserved in `date_confidence`.

**Gap, stated as a gap:** nothing reachable describes his parents, their occupations, or the household. His brother Just is documented only as a type designer and as the hand behind the Python Powered logotype (Wikipedia). No childhood anecdote exists in the corpus, and none has been supplied.

---

## 2. Amsterdam: SARA, the university, CWI, 1974-1991

**University of Amsterdam, master's in mathematics and computer science, 1982 [A].** Both Wikipedia and the resume give the degree and the year. **The 1974 matriculation is [R]**, an inference from the 1982 degree; no source states when he began, and the stop's `date_confidence` says so.

*Coordinate correction.* The pool gave Roeterseiland as 52.3557, 4.9151, near the Amsteldijk about a kilometre southeast of the campus. Corrected to **52.3632, 4.9093**.

**SARA, 1977-1982 [A].** Part-time systems programming at the Stichting Academisch Rekencentrum Amsterdam on the Kruislaan, while still a student (resume). No month.

**CWI, ABC group, 1982-1986 [A].** He joins Centrum Wiskunde & Informatica at Kruislaan 413, on the design and implementation of ABC (resume; Wikipedia, 'History of Python'). ABC's indentation-delimited block structure is Python's direct ancestor, a genealogy he states himself in the 2009 essay.

**CWI, Amoeba, 1986-1991 [A].** Distributed operating system project (resume). The `glob()` routine adopted into BSD Unix is dated 1986 by Wikipedia. **Multimedia group, 1991-1995 [A]:** hypermedia and network synchronisation (resume).

All four CWI phases share one address and one coordinate (52.3563, 4.9528), used for five stops without variation because the man did not move: eighteen years inside a few hundred metres of the Kruislaan.

---

## 3. The Christmas interpreter, 1989-1994

**Started late December 1989, at home, on a Macintosh [A].** Two self-accounts converge: the 2009 CWI essay ("I started working on Python in late December 1989, and had a working version in the first months of 1990") and the 1998 *Linux Journal* interview ("I had a two-week Christmas holiday with nothing to do. So, I wrote the first bits of the Python interpreter on my Mac"). No day is given; the file dates the stop 1989-12-24 and marks the day unattested.

**The name [A].** From Monty Python's Flying Circus, "the first thing that came to mind" (2009 essay). Not the snake. Undated; the file dates it 1989-12-31 and labels it inferred.

**First public release, February 1991, *contradiction recorded, not silently resolved*.** *A Brief Timeline of Python* reads "February 20, 1991 | 0.9.0 (released to alt.sources)." Wikipedia's 'History of Python' gives 0.9.1, and the research pool carried *both readings in one document*. The file follows the author's timeline **and records the Wikipedia reading in `date_confidence`**.

**Python 1.0, 26 January 1994, *place corrected* [A].** The date is right in the pool and in his timeline. The pool's **place was wrong**: it said USA. He did not leave the Netherlands until April 1995 (resume), so 1.0 was released from CWI in Amsterdam. The file pins it at Kruislaan 413 and says so in `date_confidence`.

**"Python was open source before the term was even invented" [A, truncated in the pool].** The full 2009 sentence reads: "So, like almost everything I've written, Python was open source before the term was even invented by Eric Raymond and Bruce Perens in late 1997." The pool cut it at "invented" with no ellipsis; the file quotes it whole.

---

## 4. Reston, Virginia: CNRI, 1994-2000

**NIST Gaithersburg, October-December 1994, *date corrected* [A].** The resume gives mid-October to mid-December 1994. The pool dated this stint "c. 1995," conflating it with the April 1995 arrangement, a NIST-funded appointment *based at CNRI in Reston*. Both are separately attested and are separate stops. The pool's Gaithersburg coordinates (39.1329, -77.2148) fall on the NIST campus and are retained.

**CNRI from April 1995 [A].** Guest researcher on NIST money, April 1995 to February 1998; direct CNRI employee March 1998 to May 2000 (resume). The popular summary, "worked at CNRI 1995-2000," elides a real distinction.

*Coordinate decision.* The pool's Reston pin (38.9586, -77.3570) sits about 3 km north of CNRI's address at 1895 Preston White Drive. **The file instead inherits the atlas's canonical Reston coordinate from `bob_kahn.journey.json`, 38.9558, -77.355, byte-identical**, preferring consistency with the wing over a third guess.

**Grail, *date range corrected* [A].** The pool gave "c. 1996-1999." Wikipedia gives August 1995 for the start, November 1995 for the first release, 0.6 in 1999 for the last.

**BDFL, *tag and origin corrected*.** The pool's chronology tagged the title [R], "exact coinage date not documented," while its afterlife section called it "self-adopted": the two contradict each other inside one pool, and the second is wrong. The Artima post of 31 July 2008 says: "I believe I've tracked down the origin of the term Benevolent Dictator For Life (BDFL) to a Python meeting in 1995." Conferred by the community, not taken. Dated 1995-04-18 with the hedge in `date_confidence`.

**Python 1.5, *date corrected* [A].** The pool said December 1997; his timeline reads "January 3, 1998 | 1.5," corroborated by Wikipedia. The pool's "nearly three decades" of BDFL is likewise wrong: mid-1990s to July 2018 is about twenty-three years.

---

## 5. The corporate custodians, 2000-2005

**BeOpen.com, May 2000 [A employer, R location].** He and three other core developers leave CNRI; he directs PythonLabs (Wikipedia; resume). The **Fremont office coordinate (37.5485, -121.9886) is a reconstruction**, unconfirmed, and labelled so in both the pool and the file.

**Python 2.0, October 2000 [A].** List comprehensions and a cycle-detecting garbage collector (Wikipedia), no day in the pool, released while its custodian company was collapsing.

**Zope Corporation, Fredericksburg, October 2000 - July 2003 [A].** Director of PythonLabs, team transferred intact (resume).

**Python Software Foundation, 2001 [A].** Incorporated to hold the language's intellectual property, van Rossum a founding member. The Wilmington pin (39.7447, -75.5484) reflects incorporation, not any place he stood. The **FSF Award** (for 2001, presented 2002) is folded into this stop, no source supplying a venue.

**First PyCon, Washington D.C., March 2003 [A].** Roughly two hundred attendees (Wikipedia, 'PyCon').

**NLUUG Award, May 2003 [A, no usable coordinate].** The pool gives the award and the month but only "Netherlands" as a place. Rather than pin a national centroid, which this atlas's practice rejects, the award is recorded inside the campa of the 2019 CWI Dijkstra Fellowship stop, where both Dutch honours sit at an attested address.

**Elemental Security, July 2003 - December 2005 [A role, R location].** Senior language architect, custom security-policy language; San Mateo coordinate reconstructed to the town.

---

## 6. Google, December 2005 - December 2012

**Joined December 2005, left 7 December 2012 [A].** Permitted to spend part of his working time on Python. Author of Mondrian, from which Rietveld descends (resume; Wikipedia).

*Coordinate.* **The Googleplex pin is inherited byte-identical from `vint_cerf.journey.json`: 37.422, -122.084**, rather than the pool's one-digit-longer 37.422, -122.0841, so the two travelers occupy one point.

**ACM Distinguished Engineer, 2006 [A]. App Engine, NDB, Appstats, 2008 [A]. Python 3.0, December 2008 [A].**

---

## 7. Dropbox, January 2013 - October 2019

**Joined January 2013 [A].** mypy, and involvement in the Python 2-to-3 work (resume; Wikipedia).

*Coordinate correction.* The pool pinned "Dropbox headquarters" at 37.7825, -122.3927, near Rincon Hill and on no Dropbox site at any date. The company was at **185 Berry Street (37.7761, -122.3919)** in 2013, **333 Brannan Street (37.7785, -122.3924)** from 2014, **1800 Owens Street (37.7683, -122.3960)** from 2019. The file follows the buildings by year.

**PEP 484, accepted May 2015 [A].** Optional static type hints, authored and shepherded by him (peps.python.org).

**The five-million-line claim, *corrected and downgraded*.** The pool asserted that "under van Rossum's direction Dropbox migrates more than five million lines of server code from Python 2 to Python 3." Dropbox's engineering blog supports neither figure nor attribution: the migration post describes "over 1 million Python LOCs" and is by Max Bélanger and Damien DeVille, who thank van Rossum in acknowledgements only; the separate type-checking effort reached "almost 4 million lines of statically typed code."

---

## 8. The transfer of power, 2018-2020

**12 July 2018, python-committers, "Transfer of Power" [A].** He steps down as BDFL after the PEP 572 fight over the assignment expression, `:=`, shipped in Python 3.8.

**The quotation, *corrected twice over*.** The pool's chronology invented the phrase "work forever," and its afterlife section printed a paraphrase as verbatim ("I don't ever want to have to fight so hard for a decision again... I am giving myself a permanent vacation from the BDFL life"), with a note claiming the phrasing could not be verified. It can: the actual text reads

> Now that PEP 572 is done, I don't ever want to have to fight so hard for a PEP and find that so many people despise my decisions.

> I'm basically giving myself a permanent vacation from being BDFL, and you all will be on your own.

Note "for a PEP," not "for a decision"; "from being BDFL," not "from the BDFL life." The file quotes only verified text from this post, in four places.

**Steering Council election, *date corrected* [A].** The pool said January 2019; PEP 8100 gives nominations 7-20 January and voting from 21 January to **4 February 2019**. Van Rossum was among the five elected, with Barry Warsaw, Brett Cannon, Carol Willing and Alyssa Coghlan. He withdrew from the 2020 election (Wikipedia).

**CWI Dijkstra Fellow, 2019 [A]. Computer History Museum Fellow, 2018 [A].** The museum stop is the one place here where a coordinate was supplied by neither the pool nor a source it names; the Shoreline Boulevard address (37.4144, -122.0774) is used and `date_confidence` says so.

**Dropbox retirement, October 2019, *day and phrase corrected* [A].** The pool gave 30 October 2019; the resume gives only "October 2019," and the day appears nowhere reachable. The pool also attached "the start of a permanent vacation" to this event; the phrase belongs to the July 2018 post, fifteen months earlier. Removed, and the conflation named in the campa.

**2019-2020 sabbatical [R as to place].** The gap is attested from the resume; that it was spent at Belmont is inference.

---

## 9. Microsoft and after, 2020-2026

**Announced 12 November 2020 [A].** Microsoft Developer Division, Distinguished Engineer. **Faster CPython [A]**, a return to interpreter engineering. **Office of the CTO, c. 2021-2026 [A]. NEC C&C Prize, 2023 [A].**

*Coordinate decision.* The pool pinned this on the Redmond campus (47.6423, -122.1390) while its own note conceded he announced he would work remotely and did not relocate. **The file pins the appointment at Belmont**, his residence, and uses the Redmond coordinate only for the two stops about the Redmond-based teams, with `date_confidence` stating that the pin is the employer's campus and not his place of work.

**GitHub, 2024 [A], *the TIOBE half dropped*.** Octoverse 2024 states verbatim that "Python becomes the most used language on GitHub, overtaking JavaScript after a 10-year run as the most used language." The pool bolted onto this a set of TIOBE claims (top ten since 2004, number one October 2021) sourced to the Wikipedia article on van Rossum, which contains no TIOBE data. Dropped rather than re-sourced.

**Retirement from Microsoft, May 2026 [A, single source].** The resume gives Microsoft as November 2020 through May 2026 and his current status as retired. **Not cross-confirmed by any second source**, and the file says so in `date_confidence`.

**No tomb.** He is living, retired, and resident in Belmont with his wife Kim Knapp and their son. The atlas's standard afterlife question, the tomb and its fate, has no referent, and the file records that as a gap rather than inventing a memorial.

**The Zen of Python [A authorship / R attribution].** PEP 20 is by Tim Peters; the attribution to van Rossum is folk tradition, and the closing stop makes the misattribution its subject rather than repeating it.

---

## Interlocks with the existing atlas

Four existing travelers are named in campa, where the paths cross or where the descent is real and labelled as descent:

| Slug | Where | Basis |
|---|---|---|
| `bob_kahn` | Reston, CNRI, 1995 | **[A]** Kahn founded CNRI in 1986 and chaired it; van Rossum worked there 1995-2000, same institution and building. Reston pin inherited byte-identical. |
| `vint_cerf` | Reston 1995 | **[A]** Kahn and Cerf's shared CNRI years, same institution, same corridor, stated in the Reston 1998 stop. **[cut 2026-08-14]** The Mountain View 2005 mention (Cerf joining Google two months before van Rossum, working from Reston) was struck from campa: same employer, different building, and the campa itself said "no source says the two men ever met here" — a same-coordinate coincidence with zero citation, not a genuine relation under house style. Googleplex pin still inherited byte-identical from `vint_cerf.journey.json`, unaffected. |
| `alan_turing` | — | **[cut 2026-08-14]** Was named at Belmont 2024 as disciplinary lineage only ('On Computable Numbers' to the machines Python runs on), explicitly disclaimed as "neither ever met van Rossum." Struck under house style: a generic technical lineage true of all modern software is a thematic echo, not a documented relation. |
| `john_von_neumann` | — | **[cut 2026-08-14]**, same stop and same reasoning as Turing above. |

The PEP-as-descendant-of-RFC connection to the Cerf/Kahn standards culture is stated in the Reston 1998 stop with both files cited: van Rossum's own documented claim, not an inference from adjacent files.

**Canonical pins checked and declined**, per the interlock lens's request: the Kaaba (21.4225, 39.8262), the Temple Mount (31.778, 35.2354), the Buenos Aires anchor (-34.6037, -58.3816) and the Paris centroid (48.8566, 2.3522). No source attests any connection, so none is inherited, following the discipline already set by `arthur_bispo_do_rosario`, `cecilia_vicuna`, `fritz_lang` and `johan_palmstruch`.

**A gap the atlas fills for the first time.** No file in `working/journeys` previously mentioned Amsterdam or CWI in any computing connection; the eleven Amsterdam stops here establish that node.

**Queue context [A].** `QUEUE.md` lines 333-335 frame van Rossum, Linus Torvalds and Bjarne Stroustrup as a trio entering the wing after Turing, Cerf and Kahn. Neither of the other two has a `journey.json` yet, so neither is named in campa.

---

## Corrections applied to the research pool

1. Coordinates: Roeterseiland → **52.3632, 4.9093**; Reston → **Kahn's canonical 38.9558, -77.355**; Googleplex → **Cerf's 37.422, -122.084**; Dropbox → **Berry / Brannan / Owens by year**; Microsoft appointment → **Belmont**, not Redmond.
2. Dates: Python 1.5 → **3 January 1998**; first release → **0.9.0, 20 February 1991** (minority 0.9.1 kept in `date_confidence`); NIST Gaithersburg → **Oct-Dec 1994**; Grail → **1995-1999**; Steering Council → **concluded 4 February 2019**.
3. Python 1.0 place USA → **Amsterdam, CWI**.
4. "Five million lines migrated under his direction" → **~4 million type-annotated; migration led by others**.
5. BDFL "self-adopted," "nearly three decades" → **conferred by the community; twenty-three years**.
6. 2018 resignation: invented quote and paraphrase-as-verbatim → **actual text from the post**; "permanent vacation" moved back off the October 2019 retirement onto it.
7. TIOBE claims → **dropped**, unsupported by the cited source.
8. "Employed at Microsoft" → **retired May 2026** per his resume.

---

## Sources

**Self-authored, primary for this life**
- `gvanrossum.github.io/Resume.html`: employment, months, titles, 1977 to May 2026. Single-source for the 2026 retirement.
- *A Brief Timeline of Python*: release dates (0.9.0 1991-02-20; 1.0.0 1994-01-26; 1.5 1998-01-03).
- "Personal History, Part 1: CWI," python-history.blogspot.com, January 2009: Amoeba motivation, ABC, the naming, open source before the term.
- "Origin of BDFL," Artima weblog, 31 July 2008; "Transfer of Power," python-committers, 12 July 2018; interview, *Linux Journal*, 1998.

**Institutional**
- PEP 8, PEP 20, PEP 484, PEP 545, PEP 8100, peps.python.org. GitHub Octoverse 2024.
- Dropbox engineering blog: the Python 3 migration post (Bélanger, DeVille) and the type-checking-at-scale post.
- PSF incorporation records; Computer History Museum Fellow citations; IMO results archive.

**Encyclopaedic**
- Wikipedia: 'Guido van Rossum', 'Python (programming language)', 'History of Python', 'Grail (web browser)', 'PyCon'.
- Dutch Wikipedia: 'Guido van Rossum', sole source for Haarlem and the NJN membership, neither in the English article.

**Named as unreachable or unsupplied**
- **No archival source for the birth beyond the city**, and **no Haarlem school named**; the upbringing rests on Dutch Wikipedia alone.
- **No coordinate for the NLUUG award (May 2003)**, only "Netherlands"; a national centroid was declined rather than invented. **None supplied for the Computer History Museum** either; the Shoreline Boulevard address was used and flagged.
- **BeOpen's Fremont office and Elemental Security's San Mateo office** are reconstructions in the pool and remain so here; neither address was confirmed.
- **The BeOpen and Zope stops share the month October 2000**, with no finer dating for either; the sequence is ordered by narrative logic, not by an attested day.
- The interlock lens located `john_von_neumann.journey.json`, `ada_lovelace.journey.json` and `charles_babbage.journey.json` but did not read them in full. The von Neumann claim is therefore [R], resting on the Fine Hall co-presence attested in `alan_turing.journey.json`; Lovelace and Babbage are not named in campa, no read stop supporting a crossing.
