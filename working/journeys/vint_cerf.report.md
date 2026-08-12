# Vint Cerf: research report

*Prepared 2026-08-12 for the Atlas of Journeys. Subject: Vinton Gray Cerf, b. 23 June 1943, New Haven, Connecticut; living at the time of writing. Co-designer, with Robert E. Kahn, of the TCP/IP protocol suite.*

**Legend.** **[A]** = attested, source named. **[R]** = reconstruction. Contradictions are printed as contradictions and left standing.

**Method.** Worked from a verified research pool in five lenses (chronology, geography, quotes, interlock, afterlife), each entry checked and, where wrong, corrected in place; the corrections are printed, not absorbed. Where two lenses disagree, the disagreement is recorded rather than resolved by preference.

---

## 1. New Haven and the Valley (1943 to 1961)

- Born **23 June 1943, New Haven, Connecticut** **[A: Internet Hall of Fame biography; standard biographies]**. The family moves west while he is small; New Haven never reappears in his working life.
- Grows up in **Van Nuys**, San Fernando Valley **[A: Internet Hall of Fame; PBS and Computer History Museum oral histories]**. Partial hearing loss from birth, hearing aid from age thirteen. He and his wife Sigrid both have hearing loss and **met through a hearing-aid provider** **[A: Wikipedia, "Vint Cerf"]**.
- Attends **Van Nuys High School** in the same years as **Steve Crocker** and **Jon Postel** **[A: Wikipedia, "Steve Crocker": "Steve Crocker attended Van Nuys High School, as did Vint Cerf and Jon Postel"]**.
  - *Correction:* the pool's school coordinates (34.1878, -118.4491) are wrong by roughly 600 m, landing in residential blocks northwest of the campus. Van Nuys High is at 6535 Cedros Avenue, approximately **34.1856, -118.4437**; the journey uses the corrected pair.
  - *Correction:* RFC 1 was written by **Crocker**. Postel's domain was the assignment of numbers and names (IANA), not "the standards process that governs the internet's addresses" as the pool phrased it.
- **Rocketdyne, six months on the Apollo program**, writing statistical-analysis software for F-1 engine tests **[A: Wikipedia]**.
  - *Correction:* the pool framed this as a pre-college job. Wikipedia reads "**While in high school**, Cerf worked at Rocketdyne on the Apollo program for six months"; 1961 is a vicinity, not a documented start. **[R]** on place: the pool gives only "Los Angeles area," and Rocketdyne's principal plant was at Canoga Park, which the journey pins and flags.

## 2. Stanford, IBM, and the return to school (1965 to 1972)

- **B.S. in mathematics, Stanford, 1965** **[A: Wikipedia]**.
- **About two years as an IBM systems engineer in Los Angeles**, on the **QUIKTRAN** time-sharing system **[A: Wikipedia; Internet Hall of Fame]**. **[R]** on the office: the building "is not confirmed in the public sources," and 34.0522, -118.2437 is the downtown centroid.
- **Graduate study at UCLA from 1967** in **Leonard Kleinrock's** group; **M.S. 1970**; **PhD 1972**, dissertation *Multiprocessors, Semaphores, and a Graph Model of Computation*, advised by **Gerald Estrin** **[A: Wikipedia]**.
- **The first ARPANET node**, an Interface Message Processor wired to Kleinrock's host, is installed in **room 3420 of Boelter Hall on 2 September 1969**, the room now preserved and marked; Cerf works in the Network Measurement Center **[A: UCLA CS department history; Kleinrock's accounts]**.
- **RFC 20, "ASCII format for Network Interchange," 16 October 1969**, Cerf at UCLA **[A: RFC 20, read directly]**.
- **SRI International, Menlo Park**, second node **[A: SRI institutional history; ARPANET timelines]**.
- **University of Utah**, fourth node: **[R]**. The node is documented; **no source confirms Cerf's presence at Salt Lake City in this window**.

## 3. Stanford again, and the protocol (1972 to 1976)

- **Assistant professor of computer science and electrical engineering, Stanford, 1972 to 1976** **[A: Stanford faculty records; Wikipedia; Cerf's own accounts]**.
- **September 1973: International Network Working Group meeting, University of Sussex**, where Cerf puts the internetworking problem to an international audience **[A: Cerf's ACM oral history; INWG records]**.
- **Autumn 1973: the hotel sketch. [R], doubly.** The anecdote of a diagram on hotel paper (host, gateway, destination network) is widely repeated; sources differ on hotel, month, and medium (napkin, envelope, stationery).
  - *Correction to the pool:* it asserted the story "is not corroborated by either man's own detailed published account." That overreaches. **Cerf has himself repeatedly described sketching the architecture on the back of an envelope in a hotel lobby in 1973.**
  - *Coordinate contradiction, not resolved:* geography pins 37.4419, -122.143 (central Palo Alto) while labelling it "Hyatt House, El Camino Real"; the El Camino Hyatt properties (Rickeys / Cabana, c. 4200-4290) sit near **37.405-37.410, -122.125**, 4 km southeast, and the afterlife lens repeats the wrong pair. The journey takes the El Camino strip.
- **May 1974: Cerf and Kahn, "A Protocol for Packet Network Intercommunication," IEEE Transactions on Communications, vol. COM-22, no. 5** **[A: original IEEE-reprinted PDF fetched and read]**, quoted verbatim in the journey, including the sentence naming the GATEWAY.
- **December 1974: RFC 675, "Specification of Internet Transmission Control Program," Cerf, Dalal, Sunshine** **[A: RFC 675]**, the first detailed TCP specification, acknowledging Ray Tomlinson for the three-way handshake and initial sequence number selection.
- **Xerox PARC and Ethernet: [R].** Metcalfe's Ethernet work overlaps Cerf's Stanford years, but **no documentation of Cerf's own visits to the PARC building was found**.

## 4. DARPA (1976 to 1982)

**The pool's worst error sits here.** The chronology lens claimed Cerf **left Stanford for DARPA in 1973**. **Wrong by three years**, and contradicted by two other entries in the same pool: he was a Stanford assistant professor **1972 to 1976** **[A: Wikipedia; Stanford records]**, and the **Internet Hall of Fame** reads "During his tenure from 1976-1982 with the U.S. Department of Defense's Advanced Research Projects Agency (DARPA), Cerf played a key role leading the development of Internet" **[A]**. The likely source of the error is Wikipedia's loose "From 1973 to 1982, Cerf worked at DARPA," which describes DARPA-*funded* work begun at Stanford, not employment. **Correct date: 1976.**

- Program manager for the Internetting project under Kahn: packet radio, packet satellite, TCP/IP, network security **[A: DARPA program history]**. *Coordinate correction:* DARPA sat at **1400 Wilson Boulevard, Arlington (c. 38.8951, -77.0722)**; the pool's 38.8903, -77.0908 is 1.7 km southwest near Fort Myer, neither the 1970s address nor the present one.
- **22 November 1977: the three-network demonstration.** A van on the **Bayshore Freeway (US 101) near Menlo Park** sends packets through a packet radio net, an ARPANET gateway, and a satellite link to Europe and back **[A: DARPA and internet-history accounts; Cerf's retrospectives]**. **University College London** (Peter Kirstein's group) is the far leg **[A: Kirstein's published accounts]**.
- **The satellite leg: tag lowered from [A] to [R], and the country changed.** The pool named **Kjeller, Norway (NORSAR)**. Wikipedia ("Internet protocol suite") routes the test "via England, Boston, and **Sweden**." NORSAR's own article says it "was the first non-US site included in ARPANET in June 1973," its link running "via the **Tanum Earth Station in Sweden** to the Seismic Data Analysis Center (SDAC) in Virginia," and **makes no mention of the November 1977 demonstration**. The journey keeps Kjeller as an early-node marker, prints Tanum, and tags the stop [R].
- **BBN, Cambridge, Massachusetts: [R]** on Cerf's presence at any specific meeting. *Coordinate correction:* BBN at 10 Moulton Street is approximately **42.3906, -71.1418**; the pool's 42.3875, -71.119 is 2.1 km east, near Harvard.
- **1 January 1983, Flag Day:** the Network Control Program is switched off and TCP/IP becomes the network's only protocol **[A]**. **There is no ceremonial site.** The journey repeats the gap rather than inventing a room.

## 5. MCI, CNRI, and the Internet Society (1982 to 1999)

- **1982: leaves DARPA for MCI**, vice president of MCI Digital Information Services, leading engineering of **MCI Mail** **[A]**, which launches 1983 and in **1989 becomes the first commercial email service connected to the Internet** **[A: Wikipedia]**. **1988: begins publicly advocating privatization and commercialization** **[R]**, a claim the pool tags itself and documents nowhere.
- **1986: leaves MCI for the Corporation for National Research Initiatives (CNRI), Reston**, as vice president, working again with Kahn **[A: CNRI institutional history; Internet Hall of Fame]**. Digital library work and the first groundwork of the Interplanetary Internet belong here. *Note, not a contradiction:* the CNRI move precedes the 1989 MCI Mail milestone, which is a fact about the service, not his employer.
- **1992: co-founds the Internet Society, founding president** **[A: Internet Hall of Fame; Wikipedia]**.
- **1994: rejoins MCI as senior vice president of *Technology Strategy*** **[A: Internet Hall of Fame: "From 1994 to 2005, Cerf served as the senior vice president of Technology Strategy for MCI"]**.
  - *Correction:* the geography lens gave "senior vice president for Internet architecture and technology," contradicting the chronology lens. **Use "Technology Strategy."** **[R]** on the Ashburn office: title and dates are documented, the address is not.
- **Interop: the pool's founding attribution is wrong.** Wikipedia ("Interop"): the conference "was founded by **Dan Lynch**," and "In August 1986 the Internet Architecture Board (IAB) held the first TCP/IP Vendors Workshop in **Monterey, California**. This event later became Interop." **Cerf's role there is not attested.** The journey names Lynch and the IAB, pins Monterey 1986, and drops the unverified Santa Clara 1988 venue.

## 6. ICANN, and the medals (1997 to 2008)

- **December 1997: President Bill Clinton presents Cerf and Kahn with the National Medal of Technology** **[A]**. *Citation correction:* the official citation reads **"For creating and sustaining development of Internet Protocols."** "For founding and developing the Internet" is Wikipedia's paraphrase and must not sit in quotation marks. *Contradiction, not resolved:* chronology dates the ceremony **December 1997**, geography **October 1997**, with an East Room detail attested nowhere consulted. The journey uses December, on Wikipedia, and prints both. The afterlife entry also **omits Kahn**, who received it jointly.
- **1997: joins the board of trustees of Gallaudet University**, and receives the **IEEE Alexander Graham Bell Medal** **[A]**.
- **1999: joins the ICANN board.** *Correction, twice over:* the pool called him **"founding board member"** and **"founding chairman"**. Both false. ICANN's article: it "was officially incorporated in the state of California on September 30, 1998, with ... **Esther Dyson** as founding chairwoman." Cerf joined a year later, after the initial board was seated.
- **November 2000 to November 2007: chairman of the ICANN board** **[A: Internet Hall of Fame]**. Early offices at 4676 Admiralty Way, Marina del Rey; the pool's 33.9749, -118.4457 is 750 m southwest of that. The journey inherits the atlas's canonical Marina del Rey pin (33.98, -118.44) from `diffie.journey.json`.
- **1998: Marconi Prize**; **2002: Prince of Asturias Award**; **2004: ACM A. M. Turing Award with Kahn** **[A: ACM citation]**. **[R]** on the ceremony venues of the first and the third, which the pool declines to confirm.
- **9 November 2005: Presidential Medal of Freedom from President George W. Bush** **[A: White House press records]**.
- **May 2006: National Inventors Hall of Fame, with Kahn** **[A: Wikipedia awards list, matching the pool's chronology entry]**. Geography hedged this as "c.2006"; the year is not uncertain. **[R]** stays on the Akron venue.
- **January 2008: Japan Prize with Kahn** **[A]**.

## 7. Google, the Interplanetary Internet, and after (1998 to 2026)

- **1998: distinguished visiting scientist at NASA's Jet Propulsion Laboratory**; the Interplanetary Internet study is "started by a team of scientists at JPL led by internet pioneer Vinton Cerf and the late Adrian Hooke" **[A: Wikipedia, "Interplanetary Internet"]**. *Coordinate correction:* the afterlife lens gave 34.1808, -118.1712, about 2.3 km south of JPL in Pasadena proper; **JPL is at approximately 34.2013, -118.1712**, as the geography lens has it.
- **October 2005: joins Google as vice president and Chief Internet Evangelist** **[A]**, working from Reston (1875 Explorer Street; the pool's 38.9497, -77.354 sits within about 100 m) and travelling to Mountain View, **[R]** on any dated visit. *Correction:* the pool wrote the tenure "2005-present" in three places. **Wikipedia: "Cerf worked for Google as a vice president and Chief Internet Evangelist from October 2005 to July 2026."** The range closes, and the journey carries a closing stop.
- **February 2006: testifies before Congress on network neutrality** **[R]**, the pool citing Senate Commerce Committee records and press coverage without a confirmed date. **2006: Computer History Museum oral history**, treated by historians as a primary archival record **[A]**.
- **23 April 2012: inducted into the inaugural Internet Hall of Fame, Pioneers, announced at the Internet Society's Global INET in Geneva** **[A: Wikipedia; Internet Society records]**. *Correction and contradiction:* **no source consulted names Palexpo as the venue.** Geography labelled it Palexpo at 46.2381, 6.1092; afterlife pinned central Geneva at 46.2044, 6.1432 for the same day. **Not resolved.** The journey reduces the label to Geneva and Global INET and takes the central pair.
- **May 2012: elected president of the ACM**, serving into 2014 **[A]**; **[R]** on location, the pool giving only "USA." **16 January 2013: President Barack Obama announces his intent to appoint Cerf to the National Science Board** **[A]**; **Cerf's own whereabouts that day are unrecorded**, and the journey pins the White House with that hedge.
- **2013: Queen Elizabeth Prize for Engineering**, Buckingham Palace **[A: QEPrize records]**.
- **February 2015: the "digital dark age" warning**, AAAS remarks and coverage **[A]**.
- **June 2016: NASA installs delay-tolerant networking aboard the International Space Station** **[A]**. The station has **no fixed terrestrial coordinate**; the journey pins the ground segment and says so.
- **2016: Foreign Member of the Royal Society** **[A]**. **2023: IEEE Medal of Honor** **[A]**, **[R]** on venue. **2024: California Hall of Fame** **[A]**.
- **Alive at the time of writing.** No tomb, no monument, no statue **[A: absence of record across monument and memorial databases consulted]**. The corpus's usual frame of grave and posthumous fate does not apply, and that is stated as the gap it is.

---

## Contradictions, printed and left standing

1. **DARPA start.** 1973 (chronology) against 1976 (Internet Hall of Fame, and the pool's own Stanford entries).
2. **National Medal of Technology month.** December 1997 (chronology) against October 1997 (geography).
3. **Internet Hall of Fame venue.** Palexpo, 46.2381, 6.1092 (geography) against central Geneva, 46.2044, 6.1432 (afterlife), same event, same day.
4. **MCI title 1994-2005.** "Technology Strategy" (sourced) against "Internet architecture and technology" (unsourced).
5. **ICANN founding role.** Two founding claims, both contradicted by ICANN's record of Esther Dyson as founding chairwoman, 1998.
6. **The hotel sketch.** Coordinates disagree between lenses; hotel, month, and medium disagree between sources.
7. **The 1977 satellite leg.** Norway (pool) against Sweden (Wikipedia; NORSAR).

## Honest gaps

- No hospital or street for the birth; no IBM office address, 1965-1967; no documented presence at Utah, at Xerox PARC, or at any specific BBN meeting.
- No ceremonial site for Flag Day, 1 January 1983. The transition happened everywhere at once.
- No ceremony venue for the Marconi Prize, the Turing Award, the Inventors Hall of Fame induction, or the IEEE Medal of Honor.
- **No atlas anchor for DARPA, ARPANET, IPTO, or packet switching.** A grep of `working/journeys/*.journey.json` for those terms returned no hits before this file.
- **No prior textual trace of Cerf in the corpus** but one: the EFF Pioneer Award recipient list inside `phil_zimmermann.journey.json`. (The Editions du Cerf hits in `falconetti.journey.json` are a French publisher, not the man.)
- **The Kaaba, Temple Mount, Paris, and Buenos Aires canonical pins do not connect.** No ICANN meeting, IFIP conference, or governance event at those coordinates appears in the corpus or in Cerf's record. Stated as a gap rather than forced.

## Interlocks with the existing atlas

- **Stanford, 37.4275, -122.1697**, canonical, shared byte-identically with `diffie.journey.json`, `hellman.journey.json`, `ralph_merkle.journey.json`, and `nick_szabo.journey.json`. Cerf held his professorship there 1972-1976, the exact years of the TCP design. Pin inherited unchanged.
- **Marina del Rey, 33.98, -118.44**, inherited from `diffie.journey.json`, where Diffie is ICANN's Vice President for Information Security and Cryptography, 2010 to 2012. Cerf chaired the same institution 2000-2007.
- **San Francisco, 37.7749, -122.4194**, the EFF pin from `phil_zimmermann.journey.json`, whose 1995 Pioneer Award stop **names Cerf** among prior recipients with Engelbart, Kahn, and Baran.
- **The White House, 38.8977, -77.0365**, canonical, shared with `bill_clinton.journey.json` and `george_w_bush.journey.json`. Clinton gives the National Medal of Technology in 1997, Bush the Presidential Medal of Freedom in 2005.
- **`alexander_graham_bell`**: the Bell Medal, 1997, in the same year Cerf joins the board of a university for the deaf that Bell spent his life arguing with over how deaf children should be taught.
- **`claude_shannon`**: the information-theory lineage the cipher wing inherits; Cerf's sequencing and error control run on the same ground. **`alan_turing`**: the link is the award carrying his name, 2004. **`bob_kahn`** is queued beside Cerf in `QUEUE.md` (line 332), a forward link with no file yet.

## Sources

**Reached and read directly**
- Cerf and Kahn, "A Protocol for Packet Network Intercommunication," *IEEE Transactions on Communications* COM-22 no. 5, May 1974 (IEEE-reprinted PDF, quoted verbatim)
- RFC 675 (Cerf, Dalal, Sunshine, December 1974); RFC 20 (Cerf, UCLA, 16 October 1969); RFC 3271 (Cerf, April 2002), all quoted verbatim
- Internet Hall of Fame inductee page for Vint Cerf (source of the 1976-1982 DARPA correction and the MCI title correction)
- Wikipedia: "Vint Cerf", "Steve Crocker", "ICANN", "Interop", "Internet Hall of Fame", "Internet protocol suite", "Interplanetary Internet", "NORSAR"
- Perry, "Meet Mr. Internet: Vint Cerf," *IEEE Spectrum*, 30 April 2023; "Your Life: Vinton Cerf," *AARP Bulletin* 57 no. 10, December 2016

**Consulted at second hand, through the pool**
- UCLA CS department history and the Boelter Hall markers; Kleinrock; SRI, CNRI, NORSAR, and Internet Society institutional histories; Kirstein on UCL's ARPANET and SATNET links; Hafner and Lyon, *Where Wizards Stay Up Late*; White House press records 1997 and 2005; ACM, QEPrize, and National Inventors Hall of Fame records; NASA JPL documentation

**Not reached, and why**
- **The Computer History Museum oral history transcript**: not opened, cited through the pool. [A] for its existence, [R] for anything attributed to its interior.
- **The official National Medal of Technology ceremony program**, which would settle October against December 1997: not located.
- **ICANN board minutes for 1999**: not consulted; the correction rests on the incorporation record and ICANN's published board history.
- **Any primary document naming the 1973 hotel**: not found by any lens. The room stays unlocated.
- **Senate Commerce Committee records, February 2006**: not opened.
- **NORSAR records of the November 1977 test**: no such record found, which is itself the evidence for the Sweden correction.
