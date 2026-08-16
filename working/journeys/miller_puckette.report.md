# Miller Smith Puckette, research report
*2026-08-16. Born Chattanooga, Tennessee, 1959; living. Mathematician (Putnam Fellow, two IMO medals, Harvard PhD), author of Max and of Pure Data, professor emeritus of computer music at UC San Diego.*

Legend: **[A]** = attested, source named · **[R]** = reconstruction, inference, or single-sourced claim not independently confirmed. Contradictions are flagged and left open; unreachable sources are named with the reason.

A note on the subject's shape first. Puckette lives in four places (Tennessee, Cambridge Massachusetts, Paris, La Jolla) and visits a handful more to collect prizes. The movement in his life is not his own; it is his software's. That creates the discipline problem addressed in section 4: a great many events in the Max/Pd story happen in rooms Puckette was never in.

---

## 1. Tennessee and the Olympiads (1959 - 1976)

- **Born Miller Smith Puckette, 1959, Chattanooga, Tennessee.** **[A: Wikipedia, "Miller Puckette"]** Month and day are not given in any source reached; the journey file defaults to 01-01 and says so in `date_confidence`.
- **Attends St. Andrew's-Sewanee School, Sewanee, Tennessee, before university.** **[A: Wikipedia, "Miller Puckette"]** The *years* are **[R]**: no source reached gives them, and 1974 in the journey is a placement, not a claim. **Coordinate correction applied:** the pool's 35.2065, -85.9219 lands near the University of the South, ~3 km off campus; the school at 290 Quintard Road is at **35.2172, -85.8914** (Wikipedia, "St. Andrew's-Sewanee School").
- **Gold Medal, International Mathematical Olympiad, 1975.** **[A: Wikipedia, "Miller Puckette"]** The *host city* is a cross-reference, not from the Puckette article: the 17th IMO was in Bulgaria, Burgas and Sofia (Wikipedia, "List of International Mathematical Olympiads"). Pinned at Burgas, 42.5048, 27.4626.
- **Silver Medal, IMO, 1976.** **[A]** 18th IMO, Lienz, Austria, 46.825, 12.7639. Same cross-reference structure.

*Gap:* nothing is reachable about his family, his parents' occupations, or why a Chattanooga boy ended up at an Episcopal school on the plateau.

---

## 2. Cambridge: mathematics and the Experimental Music Studio (c. 1976 - 1987)

- **Undergraduate at MIT; introduced to computer music through Barry Vercoe, director of MIT's Experimental Music Studio.** **[A: Wikipedia, "Miller Puckette"; Wikipedia, "Barry Vercoe"]** Enrollment dates are **[R]**, inferred from the 1979 Putnam and the 1975-76 Olympiads.
- **Putnam Fellow, 1979.** **[A]** for the fellowship and year; **[R]** for the venue, since the Putnam is sat at the candidate's own institution and MIT is therefore an inference from his known enrollment. Stated in `date_confidence`.
- **Member of the MIT Media Lab from its 1985 opening until 1987.** **[A]** The Wiesner Building (E15) pin 42.3601, -71.0882 is used; the general MIT pin 42.3601, -71.0942 for the undergraduate and Putnam stops.
- **PhD in mathematics, Harvard University, 1986.** **[A: Wikipedia, "Miller Puckette"]** Worth stating plainly because it is routinely misreported: the doctorate is in **mathematics**, not music and not computer science. The pool tagged this [R] in one lens and [A] in another; the discrepancy is internal to the pool, not to the sources, and it is treated as attested. *Gap:* dissertation title, advisor, and subject not found; Harvard's records were not consulted.

---

## 3. IRCAM: The Patcher, Max, and the Manoury cycle (1985/1987 - c. 1991)

### The unresolved inception date, flagged, not adjudicated

This is the single most important contradiction in the file and it is **not resolved**.

| Source | Claim |
|---|---|
| Wikipedia, "Max (software)" | Puckette begins **The Patcher** at IRCAM in **1985**; it is the direct ancestor of Max. |
| Wikipedia, "Miller Puckette" | Puckette is a member of the **MIT Media Lab in Cambridge, Massachusetts, from 1985 to 1987**, and develops "the first version of Max" at IRCAM in **1988** with Philippe Manoury. |
| Wikipedia, "Max (software)" | Manoury's **Pluton (1988)** is the earliest widely recognized use of what becomes Max. |

The three cannot all be read at face value. He cannot be resident in Paris in 1985 and on the Media Lab staff in Cambridge in 1985. And 1988 cannot be both the year Max was "first developed" and the year of the first *composition* using an already-working system.

The journey file handles this by dating the IRCAM arrival stop to **1987**, the attested end of his Media Lab membership, carrying the contradiction in that stop's `date_confidence`, and describing Pluton (1988) as the first *composition* to use Max rather than as the year of Max's invention. **No source reached settles when The Patcher was begun, or by what arrangement he could have been at IRCAM before 1987.** Left open.

### The stops themselves

- **The Patcher at IRCAM, Place Igor-Stravinsky.** **[A for the program; date contested as above, Wikipedia, "Max (software)"]**
  - **Coordinate note.** The pool offered 48.8606, 2.3522; IRCAM's own geotag is 48.8598, 2.3513, ~120 m away. The precise pin is used.
  - **Canonical-pin decision, stated openly.** The interlock lens proposed inheriting the canonical *Paris* pin 48.8566, 2.3522 (from `andre_breton.journey.json`), "pending direct sourcing." Direct sourcing now exists, and IRCAM is a building rather than a city, so the venue pin is used. A deliberate departure, recorded here so it can be reversed if house policy prefers the city pin.
- **Control software for the Sogitec 4X.** **[R]** The 4X's role at IRCAM is general computer-music history; **no source reached confirms Puckette wrote control software for it.** The stop is dated 1987 rather than the pool's c.1985-1986, since the earlier date compounds the Media Lab contradiction.
- **The Manoury cycle, Sonus ex machina.** Jupiter, 1987 (rev. 1992), flute and live electronics; **Pluton**, 1988 (rev. 1989), piano and live electronics, the first composition to use Max; La Partition du Ciel et de l'Enfer, 1989; Neptune, 1991, three percussionists. **[A: Wikipedia, "Philippe Manoury"; Wikipedia, "Max (software)" for Pluton's priority]**
- **Max/FTS ("Faster Than Sound") for the NeXT computer, 1989**, with a dedicated DSP board, precursor of MSP. **[A: Wikipedia, "Max (software)"]**
- **jMax, IRCAM, 1998**, open-source Java-over-C descendant for SGI and then Linux; **NATO.0+55+3d**, the Netochka Nezvanova fork, 1999, video, development ends 2001. **[A]** Puckette has left IRCAM by then; the stop is explicit that it records the fate of the line, not his presence.

*Gap:* the date Puckette left IRCAM is not established by any source reached; the 1994 UCSD hire is the only anchor.

---

## 4. The commercial line, and the stop-attribution problem

Everything in this section happened in rooms Miller Puckette was not in. Per the standing house rule (**a stop belongs to whoever was actually there**), none of it is staged as a scene in a Californian or New York location:

- **IRCAM licenses Max for US distribution to Intelligent Computer Music Systems** (Joel Chadabe, Ben Austin); the firm fails. **[A for the licensing and failure: Wikipedia, "Max (software)"]**; **[R] for the Albany, New York base**, inferred by the pool from Chadabe's known base and not confirmed. **No Albany stop is created**: the licensing is recorded at IRCAM, which is the licensor and where Puckette was.
- **Opcode Systems publishes Max for the Macintosh, 1990**, developed and extended by David Zicarelli. **[A: Wikipedia, "Max (software)"]** Two pool corrections, neither becoming a stop: Opcode's HQ was **Palo Alto**, not Menlo Park (approx. 37.4419, -122.1430); and Gibson acquired Opcode in **1998** while Opcode **ceased operations in 1999**, two years the pool conflated.
- **Zicarelli acquires the Max publishing rights and founds Cycling '74, 1997; Max/MSP launches** without dedicated hardware. **[A]** Recorded as a La Jolla stop, not a San Francisco scene.
- **Jitter and Max 4, 2003** (video, OpenGL, Windows compatibility). **[A]** **Omitted from the journey**: a Cycling '74 product event with no Puckette involvement attested.
- **Ableton announces its acquisition of Cycling '74, 6 June 2017**; Max keeps its name and leadership. **[A]** Recorded as a La Jolla stop contrasting the two lineages, not as a Berlin scene.

---

## 5. La Jolla: UC San Diego and Pure Data (1994 - present)

### The UCSD hire date, flagged, not adjudicated

| Source | Claim |
|---|---|
| French Wikipedia, "Miller Puckette" | "Depuis **1994**, il est directeur associé du centre de recherche pour les arts et l'informatique de l'UCSD." |
| Wikipedia (English), "Miller Puckette" | Associate director of CRCA **2000-2011**. |
| Research pool, geography lens | "late 1990s" for the faculty appointment. |

The pool's own two lenses disagreed with each other (chronology: 1994; geography: late 1990s). **1994 is used** as the earlier and more specific claim, with the contradiction stated in `date_confidence`. Note that French Wikipedia attaches 1994 to the *CRCA associate directorship*, not to the faculty appointment, which sharpens rather than softens the disagreement: one of the two articles is six years wrong about the same post. Not resolved.

### Pure Data

- **Pd conceived in the 1990s as an open-source successor to Max**, running real-time audio on standard CPUs without dedicated DSP boards; **first public release 1996**. **[A: Wikipedia, "Pure Data"]** The pool's geography lens flagged the *development site* as unconfirmed and used UCSD coordinates as a proxy inferred from the timing of the appointment. That inference is retained and labelled.
- **License and hosting: BSD-3-Clause, source on GitHub.** **[A]** With a correction: **the GitHub repository publishes no tagged releases**; releases ship from msp.ucsd.edu.
- **Current version.** Wikipedia's infobox is **stale at 0.55-2 (18 November 2024)**. repology.org shows **0.56.5** packaged across Arch, Debian and Ubuntu as of August 2026. The later figure is used, sourced to repology.
- **Platform list corrected.** The pool's "Linux, macOS, iOS, Android, Windows, FreeBSD and IRIX" overstates the infobox, which gives macOS / Windows / Linux with ports for FreeBSD and IRIX. Corrected in the journey.

### Quoted material, provenance corrected

Nine quotes were offered in the pool. Eight are genuine primary text from the software's own distribution, though most are maintainer prose in the current manual rather than demonstrably Puckette's own hand. Eight are used across the journey, each cited to the file it lives in.

The ninth, the **graphical data structures** passage, needed three corrections, all applied:

1. **Citation.** The pool cited Wikipedia, "Pure Data," which reproduces only the *first sentence*. The full passage is in the Pd manual itself, `doc/1.manual/x2.htm`, section 2.9 "Data structures," in Pd 0.52-2 and earlier. The manual is cited, not Wikipedia.
2. **Text.** The original reads "Pd is designed **to to** offer," a doubled word present in every version. The pool's quote silently repaired it. Rather than publish a silently altered quotation, the journey quotes a different, typo-free sentence from the same passage: *"The data itself can be edited from scratch or can be imported from files, generated algorithmically, or derived from analyses of incoming sounds or other data streams."*
3. **Section number.** In current master (`doc/1.manual/2.theory.of.operation.htm`) this is section **2.10**, and the modern rewrite drops "he or she wants to." The older section 2.9 is cited for the older wording.

The chapter flags itself as "an adapted and updated version of an article submitted to ICMC 2002," which is why the corresponding journey stop is dated 2002 and why this passage, unlike the introduction quotes, is treated as Puckette's own prose.

### CRCA

- **Associate director, CRCA, 2000-2011.** **[A: Wikipedia, "Miller Puckette"]**, single-sourced, contradicted by French Wikipedia as above.
- **CRCA founded 1972 as the Center for Music Experiment by Roger Reynolds; ceased operations 1 July 2012; functions, support and facilities folded into Calit2.** **[A: Wikipedia, "Center for Research in Computing and the Arts"]** **Correction applied:** the pool welded these into one event ("CRCA closes in 2011, ending Puckette's tenure"). They are two events a year apart and the journey keeps them as two stops; the Puckette article's "until its closure" is wrong about the closure date.

---

## 6. Honors, later years, and afterlife of the software

- **SEAMUS award, 2008.** **[A: Wikipedia, "Miller Puckette"; seamusonline.org lists 2008: Miller Puckette]**
  - **Coordinate correction applied.** The pool supplied **0, 0** with a note not to plot it. 0,0 is a live coordinate in the Gulf of Guinea and would plot. The 2008 SEAMUS conference host city **could not be determined** (the society's past-conferences page returned 404), so the stop is pinned at his own campus, with the gap stated in `date_confidence`.
- **Honorary doctorate, University of Mons, Belgium, 11 May 2011.** **[A]**
- **Honorary degree, Bath Spa University, 21 July 2012.** **[A]** **Coordinate correction applied:** the pool gave 51.36, -2.398, open country ~3.6 km south of the campus. Newton Park is at 51°22'32"N 2°26'18"W = **51.37556, -2.43833** (Wikipedia, "Bath Spa University"), at Newton St Loe outside Bath proper; the stop is named accordingly.
- **Silver Lion in music, Venice Biennale, 2023.** **[A for the award, Wikipedia, "Miller Puckette"]**; **[R] for the venue.**
  - **Venue correction applied.** The pool pinned the Giardini (45.4279, 12.3556), which per labiennale.org is an Art/Architecture site. Biennale Musica's performance spaces are **Teatro alle Tese and Teatro Piccolo Arsenale at the Arsenale**, approximately **45.4335, 12.3517**. labiennale.org confirms a ceremony at noon on **19 October 2023** but does not name the room, so the Arsenale pin is used and the tag downgraded to reconstruction.
- **Professor emeritus of computer music, UCSD.** **[R]** The title is attested; **no source reached gives a date for it**, and UCSD's own pages could not be loaded. The journey places the stop at 2020 as a placement and says so.
- **The Theory and Technique of Electronic Music, 2007.** **[A]** Whether translated editions exist is **not established**: msp.ucsd.edu failed with a TLS certificate error.
- **Pd embedded in third-party products** (the Reactable, EA's internal EAPd build used in Spore, the discontinued RjDj app). **[R: Wikipedia, "Pure Data"]** Not staged as stops; carried in `suggested_refs`.
- **Interlanguage coverage.** Wikipedia hosts Max articles in roughly a dozen languages. **[R]** Breadth of encyclopedia coverage, not evidence of localized official documentation; not used in the journey.
- **Subject is living.** No tomb, no grave, no burial stop. The "afterlife" the file tracks is the software's.

---

## 7. Interlocks: a negative finding, stated as such

**No traveler already in the corpus is named in any campa of this file, and the returned interlock list is empty.**

The interlock lens found no attested intersection: no journey file in the corpus mentions Puckette, Max Mathews, IRCAM, Barry Vercoe, or Pure Data by name. Every candidate it surfaced is geographic or institutional coincidence, which the house rule excludes:

- **Richard Dawkins** at Scripps (2009): same La Jolla neighborhood, different institution, no meeting. **Rejected.**
- **Leonard Adleman, Adi Shamir, Ron Rivest, Donald Knuth**: 2002 Turing Award ceremony, San Diego, 2003-06-07. **Rejected**, shared city only. Knuth's San Diego pin is additionally flagged in its own file as an unverified reconstruction.
- **Ken Thompson**: San Diego schooling c.1957-1960, USENIX Winter 1993. **Rejected**, shared city only.
- **Merce Cunningham**: BIPED and real-time motion-capture performance. **Rejected**, thematic resonance is not an interlock.
- **Claude Shannon, Dennis Ritchie, Bjarne Stroustrup, Bob Kahn**: Bell Labs Murray Hill and Cambridge, Massachusetts. **Rejected**, institutional parallel only.
- **Pierre Boulez**, reachable only through `andre_breton.journey.json`, founded and directed IRCAM. The closest thing to a real link: Puckette worked at an institute Boulez founded and led. But Boulez has no journey file, so there is no slug to interlock, and naming Breton or Kahlo in a Puckette campa would be pure geographic name-dropping. **Rejected.**

**One claim needing explicit rejection:** the interlock lens reported that "Miller Puckette also worked at Bell Labs (Max Mathews's computer music group) in the 1980s before IRCAM," tagged [R] and flagged as unverified. **No source reached supports it** and it appears in none of the other lenses, so **it is not used in the journey file.** If true it would create a genuine Bell Labs interlock with Ken Thompson, Dennis Ritchie, and Claude Shannon at the canonical Murray Hill pin 40.6852, -74.396, and a direct link to Max Mathews. Worth verifying properly, and worth not asserting until someone has.

Genuine relations that would be legitimate interlocks if the other party had a file: **Philippe Manoury** (four named collaborations), **Barry Vercoe** (teacher), **David Zicarelli** (successor publisher of his software). None has one. Recorded here for whoever builds them.

---

## 8. Journey file: shape

6 segments, 34 stops, chronological within and across segments: *The Plateau and the Olympiads* (4), *Cambridge: Mathematics and the Experimental Music Studio* (5), *IRCAM: The Patcher* (5), *Faster Than Sound* (4), *La Jolla: Pure Data* (8), *The Honors and the Emeritus Years* (8).

Eight stops carry quotes, all from the Pd README and manual. The pool contains no quoted speech or writing from Puckette outside the software's own documentation, and none at all from before 1996.

---

## Sources

**Reached and used**
- Wikipedia, "Miller Puckette": the spine of the biography, and single-sourced for most of it
- Wikipedia, "Max (software)": inception, Max/FTS, the US commercial line, jMax, NATO, Ableton
- Wikipedia, "Pure Data": 1996 release, license, hosting, embedded uses
- Wikipedia, "Philippe Manoury": Jupiter, Pluton, La Partition du Ciel et de l'Enfer, Neptune
- Wikipedia, "Center for Research in Computing and the Arts": 1972 founding under Roger Reynolds, closure 1 July 2012 into Calit2
- Wikipedia, "Opcode Systems": Palo Alto HQ, Gibson acquisition 1998, operations cease 1999
- Wikipedia, "St. Andrew's-Sewanee School" and "Bath Spa University": campus coordinates
- Wikipedia, "List of International Mathematical Olympiads": 1975 and 1976 host cities
- French Wikipedia, "Miller Puckette": the 1994 CRCA date contradicting the English article
- Pd Documentation, `doc/1.manual/1.introduction.htm`, `doc/1.manual/2.theory.of.operation.htm`, `doc/1.manual/x2.htm` at tag 0.52-2, and `README.txt`: all quoted text
- repology.org: Pd 0.56.5 packaged across Arch, Debian, Ubuntu, August 2026
- ircam.fr, labiennale.org (venues page and 19 October 2023 ceremony), seamusonline.org (2008 award)

**Reached and negative, or not reached (gaps)**
- **msp.ucsd.edu**, Puckette's own faculty and release site, and **UCSD department pages**: **TLS certificate verification error**, could not be loaded. This blocks the emeritus date, the translated editions of the 2007 textbook, and the authoritative release history.
- **seamusonline.org past-conferences page**: HTTP 404. The 2008 host city is therefore unknown.
- **labiennale.org Silver Lion citation page**: 404. The venues page and ceremony time were reachable, the room was not.
- **Harvard dissertation records**: not consulted; thesis title, advisor, and subject are a gap.
- **IRCAM internal reports and Puckette's own IRCAM-era papers**: not consulted. These would settle the 1985/1987/1988 contradiction and the 4X question, and are the obvious next step for anyone revising this file.
- **The claimed Bell Labs period**: no source found. See section 7.
