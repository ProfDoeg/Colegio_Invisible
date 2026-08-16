# Ken Thompson (b. 1943): research report
*Compiled 2026-08-16 from the verified research pool (chronology, geography, quotes, interlock, and afterlife lenses). Legend: **[A]** = attested, source named · **[R]** = reconstruction, tradition, or reported-but-unverified. Contradictions between lenses are flagged where they occur and are NOT adjudicated.*

Subject: Kenneth Lane Thompson, born New Orleans 1943, still living at the time of writing. Co-author of Unix, author of B, of the first practical regular-expression engine, of the chess machine Belle, of UTF-8 (with Rob Pike), co-designer of Go. The unusual feature of this file among atlas subjects is that it has **no death, no tomb, and no posthumous reception**: the "afterlife" is entirely institutional, and the subject can still contradict it.

---

## 1. Origins and education, 1943-1966

- **Born New Orleans, Louisiana, 4 February 1943 [A, source: Wikipedia, "Ken Thompson"].** The city is recorded; hospital, street, and ward are not. The geography lens explicitly notes that its coordinates (29.9511, -90.0715) are a downtown stand-in for an unrecorded birth site. Kept as such in the journey file.
- **Air Force childhood; high school in San Diego, California [R].** The chronology lens tags this **[R]** and gives no year. The "1960" in the journey file is a *placement* before the attested 1965 degree, and `date_confidence` says so. **Gap:** no school named, no teachers, no early-genius anecdote in anything reachable.
- **BS in electrical engineering and computer sciences, UC Berkeley, 1965 [A].**
- **MS, same department, 1966, thesis advisor Elwyn Berlekamp [A].** **Gap, and a real one:** no source reached names the thesis title or subject. It is Thompson's only piece of formal academic work; he never took a doctorate.
- **Coordinate correction applied.** The geography lens gave 37.8756, -122.2585 for "Cory Hall"; its verifier flags that this is **Soda Hall**, which did not open until 1994. Corrected to **37.8751, -122.2573** (OpenStreetMap relation 18935).

## 2. Bell Labs: arrival, Multics, and the spare machine, 1966-1971

- **Hired by Bell Telephone Laboratories, Murray Hill, New Jersey, 1966 [A].**
  **CONTRADICTION, not resolved:** the chronology lens and the Ken Thompson article give **1966**; the interlock lens, quoting `claude_shannon.journey.json`, says "Thompson joins the same Murray Hill Computing Science Research Center in **1967**". (The Ritchie file's own 1967 Murray Hill stop is Ritchie's arrival, which may be the source of the confusion.) The journey file uses 1966 and records the disagreement in `date_confidence`.
- **Multics work with Ritchie; Bell Labs withdraws, 1969 [A].**
- **Space Travel, and the port to the PDP-7, 1969 [A].** The chronology lens originally said the game ran on a "GE-635"; its own verifier corrects this: Multics ran on a **GE 645**, and the GE 635 (GECOS) was the machine used to *cross-compile* the PDP-7 code. Both facts are kept in the journey campa in their corrected form.
- **The month alone, 1969 [A, source: Wikipedia, "History of Unix", quoting Thompson].** Wife and infant son away for a month; a week each to the operating system, shell, editor, and assembler. **The month of 1969 is not fixed by any source reached**, the quotation says "the month she was gone" and nothing more. `date_confidence` states this.
- **B, 1969 [A].** Chronology lens says 1969; geography lens says "1969-1970". Minor, flagged, left open.
- **The name Unix, coined by Brian Kernighan, 1970 [A].**
- **PDP-11 and the Unix Room, 1970 [A, via `dennis_ritchie.journey.json`].**
- **Chess program bundled with the first PDP-11 Unix, 1971 [A].**

### The regex problem, a contradiction carried into the file
The chronology lens claim reads "Thompson develops the **ed** text editor's regular-expression search algorithm... 1968". Its own verifier corrects this: the 1968 work is **QED** (the CTSS editor), and ed arrives with Unix c.1969-1971. The geography lens dates a combined "QED then ed then Thompson's construction" claim to **c.1970**. The 1968 CACM paper is firm. The journey stop is pinned at **1968**, names QED, and says in `date_confidence` that whether ed precedes or follows is contradicted and not resolved here.

## 3. Unix goes public, 1973-1974

- **"The UNIX Time-Sharing System", 4th ACM Symposium on Operating Systems Principles, IBM Watson Research Center, Yorktown Heights, 15-17 October 1973 [A, `dennis_ritchie.journey.json`].** The interlock lens is the only source that supplies the venue and the fact that Ritchie and Thompson travelled there together; the chronology lens gives only "USA". Coordinates inherited byte-identical from the Ritchie file: **41.2098, -73.8043**.
- **Kernel rewritten in C, November 1973 [A].** Interlock supplies the precise month; the chronology lens gives only the year.
- **Version 4 tape sent to the University of Utah, 31 May 1974 [A, source: Wikipedia, "History of Unix", citing the CHM archive item "Utah Unix v4 raw"].** Sole surviving Version 4 witness as of 2025. This is placed as a Murray Hill stop (Thompson mailing the tape), not as a Utah or Mountain View stop: **the traveling was done by the tape, not by the man.**

## 4. Berkeley again, 1975-1976

- **Sabbatical as visiting professor; V6 installed on a PDP-11/70; Bill Joy and the seed of BSD [A].**
- **First version of Berkeley Pascal, early 1976 [A].** The chronology lens called it "Unix Pascal"; its verifier corrects the name to **Berkeley Pascal** and the date to *early* 1976, with Joy, Charles Haley, and Susan Graham extending it later that year. Corrected form used.
- **Coordinate correction applied.** The geography lens gave 37.8752, -122.2578 for "Evans Hall"; its verifier notes Evans Hall is at **37.8736, -122.2578** and that the given pin lands near Cory Hall instead. Corrected value used for both sabbatical stops.

## 5. Belle, 1972-1986

- **Summer 1972: Thompson alone begins a chess program for the PDP-11 [A, source: Wikipedia, "Belle"].** The chronology lens originally credited Joe Condon from 1972; its verifier corrects this. **Condon enters in 1976** with the hardware move generator. The journey file follows the correction and says so inside the campa.
- **1978: Belle wins the ACM Computer Chess Championship, four wins in four games [A].** **Dropped from the journey file** as a stop: no source reached gives the tournament city, so there is no defensible place to pin it and no evidence of where Thompson was.
- **1980: World Computer Chess Championship, Linz, Austria [A for the machine; R for Thompson's presence].** The geography lens tags this **[R]** precisely because Thompson's own attendance is not confirmed. Kept, with the hedge in `date_confidence`.
- **1983: U.S. Open, 8.5/12, performance rating 2363; USCF master rating 2250; Fredkin Prize milestone award [A for the result and rating; venue NOT verified].** The host city is unconfirmed and the Pasadena-area coordinates (34.1478, -118.1445) are the geography lens's own acknowledged placeholder. Carried forward **labelled as a placeholder** in `date_confidence`; the weakest pin in the file.
- **1986: last ACM championship win; Belle donated to the Smithsonian [A].** The transfer date is not given.

## 6. Honors and "Reflections on Trusting Trust", 1980-1990

- **1980: elected to the National Academy of Engineering [A].** Citation verbatim: "designing UNIX, an operating system whose efficiency, breadth, power, and style have guided a generation's exploitation of minicomputers." Used as the stop's quote.
- **1982: IEEE Emanuel R. Piore Award [A].** Folded into the Turing Award campa rather than given its own stop; no venue in any source.
- **1983: ACM A. M. Turing Award, jointly with Ritchie [A].** Ceremony venue unconfirmed; the pin marks Murray Hill, where the honored work and the lecture text originated, and the `date_confidence` says exactly that.
- **1984 (August): "Reflections on Trusting Trust", CACM 27(8), 761-763 [A, source: verified by direct PDF extraction of the CACM text].** The lecture was delivered for the 1983 award; the chronology lens dates the item 1984, which is the publication.
- **1985: elected to the National Academy of Sciences [A, source: nasonline.org].**
- **1990: IEEE Richard W. Hamming Medal, jointly with Ritchie [A, source: interlock].**
- **Coordinate correction applied.** Both academy pins were given as 38.8913, -77.0472, which the verifier places on the National Mall near the Vietnam Veterans Memorial. Corrected to the NAS/NAE building at 2101 Constitution Avenue NW: **38.8925, -77.0490**.

### Quote-set notes
The pool's Trusting Trust quotations were verified by direct PDF extraction. Two problems were flagged by the verifier and are handled here:
1. The "whiz kids" quotation is **clipped** in the pool: it orphans "On the other hand" by dropping "There is an explosive situation brewing. On the one hand, ...". **Not used as a quote in the journey file** for that reason; the sense is paraphrased in the campa instead.
2. The published CACM scan reads "**heros**"; the Wikiquote and aeb.win.tue.nl transcriptions read "heroes". The pool's note calls this an OCR dropped letter, which the verifier says is unproven. Since the passage is not quoted verbatim in the journey file, the disagreement does not propagate, but it is recorded here.

## 7. Plan 9, UTF-8, Inferno, 1985-1997

- **Plan 9 [A as to existence and Thompson's leading role; date NOT attested].** The chronology lens asserts 1985; its own verifier says no source gives a year, only "mid-1980s", with first public release in 1992. The journey stop uses 1985-01-01 with `date_confidence` stating plainly that this is a placement within the decade and not a date.
- **C++ trials, c.1985-1990 [A for the trials; R for the quotation].** The "garbage heap of ideas that are mutually exclusive" line is attributed to *Coders at Work* (Apress, 2009), p. 475, but the researcher could not fetch the book text; the quotes lens tags it **[R]**. Used as a quote with the failure to verify stated in `quote_source`.
- **UTF-8 designed on a placemat in a New Jersey diner, 2 September 1992, with Rob Pike [A, source: Wikipedia, "UTF-8"].** **Gap, permanent so far:** the diner is unnamed in every source, and the placemat is not known to survive. Coordinates default to Bell Labs Murray Hill as the nearest fixed point, as the geography lens itself proposes.
- **UTF-8 presented at USENIX, San Diego, 25 January 1993; accepted by X/Open as FSS-UTF [A, source: afterlife lens].**
- **1994: IEEE Computer Pioneer Award [A].** Folded into the Inferno campa; no venue.
- **1995: Inferno [A].**
- **1997: Fellow of the Computer History Museum, with Ritchie [A].** **Anachronism flagged in the stop itself:** the pin (37.4143, -122.0776) is the museum's current Mountain View building, which did not open as such until 2002-2003; in 1997 the institution was the Computer Museum History Center at Moffett Field. The `date_confidence` field carries this warning rather than silently moving the pin.

## 8. The medal, the retirement, and Google, 1998-2024

- **National Medal of Technology, with Ritchie.** **CONTRADICTION, not resolved:** the chronology and geography lenses give the presentation as **27 April 1999**; `dennis_ritchie.journey.json` gives **21 April 1999**; the afterlife lens dates the item **December 1998**, which its own verifier identifies as the *announcement* (8 December 1998) of the 1998 award year, presented by Clinton in 1999. The journey file uses **1999-04-27** and states the 21 vs 27 April conflict in `date_confidence`. White House coordinates 38.8977, -77.0365 are identical across the geography, interlock, and afterlife lenses and are inherited unchanged.
- **1999: Tsutomu Kanai Award [A].** Folded into the retirement campa.
- **Retirement from Bell Labs, late 2000 [A].** The chronology lens's parenthetical "(by then part of Lucent/Avaya's successor entities)" is **wrong** per its verifier: in 2000 Bell Labs was Lucent's R&D arm, and Avaya was a separate Lucent spinoff that did not include Bell Labs. Dropped. The month within "late 2000" is not given; the stop defaults to 2000-01-01 and says so.
- **2003: Harold Pender Award [R for the presenting institution].** The geography lens notes that the award being a University of Pennsylvania prize is general knowledge, not re-confirmed in the research pass.
- **2006: joins Google as Distinguished Engineer, after a stint at Entrisphere [A].**
- **2007: Go design begins with Robert Griesemer and Rob Pike [A]; November 2009 public release [A]; March 2012 version 1.0 [A].** The "we hated C++" quotation is **[R]**: drdobbs.com no longer resolves and the text comes from a secondary transcription. Stated in `quote_source`.
- **2011: Japan Prize, with Ritchie [A for the award; R for everything else].** The geography lens's National Theatre coordinates (35.6939, 139.7454) are ~1.4 km off the real National Theatre of Japan (35.6814, 139.7431), *and* the venue attribution for 2011 is itself unsupported: Wikipedia documents the National Theatre only for 2014, and japanprize.jp's 2011 page gives no date, venue, or attendance. The ceremony also fell weeks after the 11 March Tohoku earthquake, and no source says whether it was held as scheduled. **Resolution used:** the journey inherits the canonical Tokyo pin from `dennis_ritchie.journey.json` (**35.6852, 139.7454**) rather than either disputed venue coordinate, and `date_confidence` carries the caveat. Ritchie died that October.
- **c.2023: switches from Apple hardware to Raspberry Pi OS.** **CONTRADICTION between lenses, resolved in favour of [A]:** the chronology lens tags this **[R]** with "exact date unspecified"; the geography lens tags it **[A]**; the verifier sides with [A], since Wikipedia states it directly and cites Thompson's own SCaLE 20x closing keynote (March 2023, 57:48-58:55). **Weakness carried:** no source reached names the conference city; the Pasadena coordinates follow SCaLE's generally reported venue and are labelled not-checked.
- **Title drift [A]:** Wikipedia (as of 2024) says Thompson worked at Google "first as a Distinguished Engineer and later as a Google Advisor". The geography lens's "Still working at Google as a Distinguished Engineer" in the 2020s is out of date and is not repeated.
- **2024: Computer History Museum oral history [A].**

---

## Interlocks used, and interlocks deliberately refused

**Used** (each a real relation of Thompson's own, not shared geography):
- **`dennis_ritchie`**, collaborator across every phase; the Ritchie file supplied the canonical Murray Hill pin, the SOSP venue and dates, the November 1973 kernel month, the Hamming Medal citation, and the White House stop.
- **`bjarne_stroustrup`**, Stroustrup built C++ in the same laboratory from 1979; Thompson tried it and publicly rejected it. A documented, direct, if one-sided, engagement.
- **`linus_torvalds`**, one-directional: Torvalds's kernel is a reimplementation of the system Thompson wrote. Named once, in the retirement campa, as an offspring of the work rather than as a person Thompson met.

**Refused:**
- **`claude_shannon`**, the interlock lens itself tags the connection **[R]** and says "same building/institution, generations apart; **not a documented meeting**". Shannon's 1950 chess paper and Thompson's Belle share an institution and a subject, but nothing reached here shows Thompson engaging with Shannon's work by name. Shared geography is not an interlock, so Shannon is not named in any campa.
- **`guido_van_rossum`**, the interlock lens tags the glob/BSD link **[R]** and marks it "inferred lineage, not stated directly in the van Rossum file". Not used.

**Stops that belong to other people, and were therefore not staged here:** McIlroy's 2011 Murray Hill remarks for Ritchie (cited as a quote source on the Tokyo stop, not given a scene); David A. Wheeler's diverse double-compiling work (2005 ACSAC paper, 2009 GMU dissertation) and the 2023 publication of the annotated backdoor source, other people's engagements with the 1984 lecture, which appear only in that stop's `suggested_refs`.

## Honest gaps

1. **The 1966 master's thesis**, title and subject not found. The only formal academic artifact of his life.
2. **The diner**, name and address of the New Jersey diner where UTF-8 was designed: unrecorded everywhere. The placemat is not known to survive.
3. **The 1983 U.S. Open host city**, unverified; the pin is an acknowledged placeholder.
4. **Award ceremony venues**, Turing (1983), Piore (1982), Kanai (1999), Computer Pioneer (1994), Hamming (1990), NAE (1980), NAS (1985): none confirmed. Pins mark either the workplace or the awarding body's building, and each stop says which.
5. **The San Diego school years**, no institution, no dates.
6. **The month in 1969**, attested as a month, never as a date.
7. **Bonnie Thompson**, named in the sources only as "his wife" in the 1969 anecdote; no independent material about her, their son, or their marriage was reachable in this pass. A large biographical hole in an otherwise densely documented life.
8. **"Ken Thompson facts" folklore**, the afterlife lens tags this **[R]** and admits no citable primary source was found. Not used anywhere in the journey file.

## Sources

**Reachable and used**
- Wikipedia, "Ken Thompson" (biography, honors, personal life; the personal-life claim cites Thompson's own SCaLE 20x keynote)
- Wikipedia, "History of Unix" (the month-alone quotation; the Utah Version 4 tape, citing the Computer History Museum archive item "Utah Unix v4 raw")
- Wikipedia, "Space Travel (video game)" (GE 645 vs GE 635; the cross-compiler and paper tape)
- Wikipedia, "Belle (chess machine)" (1972 start, 1976 Condon move generator, 1978/1980/1983/1986, Smithsonian)
- Wikipedia, "Go (programming language)" (2007 design, November 2009 release, March 2012 v1.0)
- Wikipedia, "UTF-8" (2 September 1992 placemat; 25 January 1993 USENIX San Diego; FSS-UTF)
- Wikipedia, "Bell Labs" (600 Mountain Avenue, built 1941-1945, now Nokia; the December 1998 medal announcement)
- Ken Thompson, "Reflections on Trusting Trust", *Communications of the ACM* 27(8), August 1984, pp. 761-763, **verified by direct PDF extraction**
- Ken Thompson, "Regular Expression Search Algorithm", *CACM* 11(6), June 1968, cited, not re-read
- M. Douglas McIlroy, remarks for the Japan Prize award ceremony for Dennis Ritchie, Murray Hill, 19 May 2011 (PDF, cs.dartmouth.edu)
- dwheeler.com/trusting-trust (for the correct 2005 ACSAC citation and the 2009 dissertation date)
- OpenStreetMap relation 18935 (Cory Hall); Wikipedia geotags for Evans Hall, the NAS building, the National Theatre of Japan, and Bell Labs Murray Hill
- Atlas files: `dennis_ritchie.journey.json`, `linus_torvalds.journey.json`, `bjarne_stroustrup.journey.json`, `claude_shannon.journey.json`, `guido_van_rossum.journey.json`

**Named and NOT reachable (recorded as gaps, not worked around)**
- Peter Seibel, *Coders at Work* (Apress, 2009), p. 475, book text not fetched; the C++ quotation rests on secondary transcription (Wikiquote)
- "Interview with Ken Thompson", *Dr. Dobb's*, 18 May 2011, **drdobbs.com no longer resolves**; the Go quotation is from Wikiquote's transcription
- Kernighan and Pike, *The UNIX Programming Environment* (Prentice-Hall, 1984), p. 204, source of the "I'd spell creat with an e" line; page not verified, so the line is **[R]** and is not used in the journey file
- japanprize.jp 2011 laureate page, reachable but silent: no ceremony date, no venue, no attendance
- The 1983 U.S. Open tournament record (host city), not located
- UC Berkeley thesis records, 1966, not consulted
- Louisiana birth records, February 1943, not consulted

**Coordinate policy for this file.** Where the interlock lens supplied a canonical pin already in use in the atlas, it was inherited byte-identical rather than re-derived: Murray Hill **40.6852, -74.396** (all Bell Labs stops, including the unlocated diner), Yorktown Heights **41.2098, -73.8043**, the White House **38.8977, -77.0365**, Tokyo **35.6852, 139.7454**. The Murray Hill pin therefore differs deliberately from the geography lens's corrected 40.6833, -74.4003 (600 Mountain Avenue), a discrepancy of about 250 metres, recorded here rather than silently reconciled. Where no canonical pin existed, the verifier's corrections were applied (Cory Hall, Evans Hall, the Academy building).
