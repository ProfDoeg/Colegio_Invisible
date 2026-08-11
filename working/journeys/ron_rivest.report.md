# Ronald Linn Rivest (b. 1947) - research report
*Atlas of Journeys, working file. Compiled 2026-08-11 from the verified research pool for slug `ron_rivest`. The subject is living: there is no tomb section, and the absence is stated rather than filled.*

**Legend.** **[A]** = attested, source named inline · **[R]** = reconstruction, tradition, or secondary aggregation not corroborated against a primary record. Contradictions are flagged and left standing; where the pool contradicts itself, both readings are printed. Page numbers with no other citation refer to the *Oral History of Ronald L. Rivest*, Roy Levin interviewer, ACM Turing Award Winners Project, 6 December 2016 (CHM Ref X8019.2017), 48 pp., the only document in this pass in which Rivest speaks for himself at length.

---

## 1. Schenectady and Niskayuna, 1947 to 1965

**Birth. [A]** Born 6 May 1947 in Schenectady, New York (Wikipedia; Britannica). His father is an electrical engineer at the General Electric Research Laboratories; the family lives in Niskayuna, which Rivest calls "sort of a high-tech suburb of Schenectady" (p.2).

**A rejected specific: the hospital. [R, rejected]** The pool placed the birth at Ellis Hospital, tagged [A], at 42.8074, -73.9265. Neither cited source names any hospital: Wikipedia says only Schenectady, and "Ellis" and "hospital" appear nowhere in the transcript. The coordinates were wrong for Ellis Hospital anyway, since 1101 Nott Street geocodes near 42.8202, -73.9165. The journey uses a generic Schenectady pin (42.8142, -73.9396).

**The programming class. [A as fact, R as to year]** A high school computer programming class turns him toward computing; the year 1964 comes from the History Tools biography, not from Rivest. He graduates from Niskayuna High School in 1965.

**A rejected embellishment. [R, demoted]** That the Niskayuna faculty was "unusually stocked with PhD holders" is carried only by Grokipedia and HandWiki. Rivest says the school "had a lot of interesting classes, both within the school and after school" and that "it was just a strong math program." Coordinates corrected: the school at 1626 Balltown Road is near 42.8183, -73.8894, where the pool's 42.7962, -73.8891 was about 2.4 km too far south.

## 2. Yale and Stanford, 1965 to 1973

**Yale. [A]** BA in mathematics, 1969 (Wikipedia; oral history).

**Stanford. [A]** Rivest enters the computer science PhD programme directly from Yale under Robert W. Floyd. From his own mouth: Donald Knuth and Zohar Manna on the faculty, David Klarner and Vasek Chvatal as visiting combinatorialists, Bob Tarjan and Vaughan Pratt as fellow students.

**The selection algorithm. [A]** In 1973 Rivest publishes, with coauthors, the first linear-time selection algorithm, the median-of-medians method (Wikipedia). **Gap:** the pool does not itemise the coauthors and this pass did not verify the author list, so the campa names none.

**CONTRADICTION 1: the year of the doctorate. Not resolved.** Wikipedia and the amturing.acm.org chronology give **1974**. The oral history has Levin asking "you graduated from Stanford in '73?" and Rivest answering "'73, yeah" **[A, primary]**. The 1973 reading is what makes the decade coherent, since a full postdoctoral year in France stands between the degree and the MIT appointment of autumn 1974. The journey dates the stop 1973-06-01 and carries the disagreement in `date_confidence`.

## 3. Rocquencourt, 1973 to 1974

**CONTRADICTION 2, internal to the pool. Resolved for the primary source, resolution shown.** The pool's chronology tagged the French postdoctoral year **[R]** at **1974** and called it uncorroborated against Rivest's CV; the pool's own geography section tagged the same year **[A]** at **1973-1974**. Geography is right: the oral history has Rivest reporting the invitation in direct speech, naming Gilles Kahn and Jean Vuillemin as the colleagues who said "Ron, when you're finished with your PhD, why don't you come work with us at INRIA?", placing the institute "just north of Versailles," and saying he went with his wife for a year. Pin 48.8447, 2.0964.

## 4. MIT and the open problem, 1974 to 1977

**The appointment. [A]** "When the postdoc was over in the fall of '74, I joined the MIT faculty." EECS; he never works anywhere else. Early published work: partial-match retrieval and self-organising lists, 1976.

**CONTRADICTION 3: when he met Shamir and Adleman. Corrected; load-bearing.** The pool said Rivest "joins the faculty at MIT, where he meets Leonard Adleman and, soon after, Adi Shamir," dated 1974, tagged [A]. Wrong by two to four years: Adleman took an MIT assistant professorship in 1976, and Shamir arrived on MIT research staff in 1977-78.

**The Diffie-Hellman paper. [A]** "the crypto work started in '76, when the Diffie-Hellman paper was published" (p.11-12); on reading it, "there's a nice, open problem here... lays out the ideas of public-key cryptography, but doesn't have implementations" (p.12). The journey inherits the Stanford pin **37.4275, -122.1697** byte-identical from `diffie.journey.json` and `hellman.journey.json`, which already carry the 1976-11-01 stop.

**The corridor. [A]** To Shamir and Adleman, whose offices were near his: "Hey guys, now this is an interesting problem, shall we talk about this a bit?" (p.12). On the method: "Adi and I spent some time devising initial approaches, which Len was quick to show us didn't work" (p.12). They also tried to prove the thing impossible, "But we failed at that, and ended up coming up with a proposal that still stands today" (p.12-13).

## 5. The seder and the trapdoor, April 1977

**CONTRADICTION 4: two accounts of the invention. Not resolved.**
- **[R]** The secondary literature (Robinson, 'Still Guarding Secrets', Northeastern, and many repetitions) has the three at a Passover seder at a student's house, Manischewitz wine, Rivest home near midnight unable to sleep, on the couch with a mathematics textbook, most of the paper drafted by daybreak. No primary account of that night was located and the house is named nowhere; the pin 42.3736, -71.1097 is a reconstruction.
- **[A]** The oral history makes the invention the terminus of months of proposal and refutation, dated only to the year: "the Diffie-Hellman paper appeared in '76, the invention of RSA and sort of the... figuring out the details was '77" (p.13). The journey carries both, and the seder stop says Rivest tells it differently.

**The canonical pin. [A, inherited]** The atlas's anchor for the whole RSA lineage is **545 Technology Square, 42.3626, -71.0913, dated 1977-04-02**, established in `phil_zimmermann.journey.json`, inherited by `nick_szabo.journey.json`, referenced in `hal_finney.journey.json`. Reproduced byte-identical.

## 6. Publication and the crypto wars, 1977 to 1978

**Gardner's column. [A]** *Scientific American*, August 1977: the scheme announced to the public a year before any journal printed it, with the RSA-129 challenge ciphertext, a hundred-dollar prize, and the offer of the MIT memo to any reader mailing a stamped addressed envelope. Rivest's estimate of the factoring work ran to quadrillions of years.

**The memo held. [A, primary]** "we were told that maybe there would be a violation of some law, if we were to ship this memo around... and finally in December of '77 they said, 'It's okay to mail it out now'" (p.13-14). The April memo sat eight months while the envelopes accumulated.

**The legal weather. [A]** Joseph A. Meyer's July 1977 NSA warning letter, and the October 1977 IEEE Symposium at Cornell where Merkle and Hellman's paper was read aloud by students rather than faculty, are already in the corpus: `phil_zimmermann.journey.json` (1977-07-01) and `ralph_merkle.journey.json` (1977-10-01). The Cornell pin **42.4534, -76.4735** is inherited byte-identical. Rivest: "the crypto wars were the questions as to whether... working in cryptography in academia was in the national interest or not... Or was it illegal?" (p.13).

**The paper. [A]** *Communications of the ACM* 21:2 (February 1978), 120-126. `ralph_merkle.journey.json` (1978-04-01) states that when Merkle's delayed paper reached the same journal that April, "the paper by Rivest, Shamir and Adleman is a year old."

## 7. The company and the patent, 1982 to 1983

**[R]** The venture beginning in Leonard Adleman's apartment near USC, 1982, rests on FundingUniverse's compiled corporate history. Not corroborated. Pin 34.0224, -118.2851, marked reconstruction.

**[A]** RSA Data Security Inc. incorporated at Redwood City, 1983. US Patent 4,405,829 granted 20 September 1983, assigned to MIT, licensed exclusively to the company. The number 4405829 is itself prime; the fact is repeated in most retellings and is checkable, but no source says whether anyone noticed at the time. The canonical Washington pin **38.9186, -77.0367** is used, the same `ralph_merkle.journey.json` uses for US 4,200,770.

## 8. Hashes, textbook, ossifrage, 1988 to 1996

**[A]** GMR provably secure signatures with Shafi Goldwasser and Silvio Micali, 1988, pinned to **42.3592, -71.0921**, the shared MIT pin used by `betty_shannon.journey.json` and `claude_shannon.journey.json`. MD4 (1990); MD5 (1992), later broken; RC5 published 1994; RC2 as RFC 2268 in 1998.

**CONTRADICTION 5: authorship of the first edition of *Introduction to Algorithms*. Corrected.** The pool credited the 1990 first edition to Cormen, Leiserson, Rivest **and Stein**. It is CLR: Cormen, Leiserson, Rivest. Clifford Stein joins with the second edition in 2001, after which the book is CLRS.

**CONTRADICTION 6: the fall of RSA-129. Internal to the pool, flagged in `date_confidence`.** The pool's chronology dates the factoring to **1993**; its afterlife section to **1994-04**. The campaign launched in August 1993 and finished in April 1994, roughly 600 volunteers on about 1,600 machines, coordinated by Atkins, Graff, Lenstra and Leyland.

**The plaintext, and what it is not. [A]** "The magic words are squeamish ossifrage." Fully citable: it is the title of Atkins, Graff, Lenstra and Leyland, ASIACRYPT'94, LNCS 917 (Springer, 1995), 261-277. The pool's hedge cited the CHM oral history; the transcript was searched for "squeamish ossifrage" and "ossifrage" with zero hits, so that source is dropped. **Caveat carried into the journey:** this is the decrypted plaintext of a challenge co-authored by Rivest, not anything Rivest said, and the `quote_source` field says so.

**[A, inherited]** ACM Paris Kanellakis Theory and Practice Award, 1996, jointly to Adleman, Diffie, Hellman, Merkle, Rivest, Shamir. Already in `ralph_merkle.journey.json` (1996-01-01) at **40.7519, -73.9686**; inherited byte-identical.

## 9. The older secret, 1997

**[A]** The British government declassifies work done at GCHQ: Clifford Cocks devised something close to RSA in 1973, four years before the CACM paper, and called it nonsecret encryption. Rivest: "It wasn't quite the same... but it's essentially the same idea" (p.22-23); "they never did anything with any of those things... put them back in the drawer" (p.23).

**CONTRADICTION 7: what "first" means. Left open. [R]** The pool notes, as a pattern rather than a sourced claim, that trade press and textbooks still call RSA the first practical public-key cryptosystem while footnoting Cocks's precedence in the same volumes. No source states this as a named legend; it is an inference across HandWiki, Academic Kids and History Tools.

## 10. AES, expiry, Turing, 1999 to 2004

**[A]** Second AES Candidate Conference, Rome, 22-23 March 1999: RC6 presented, designed with Matt Robshaw, Ray Sidney and Yiqun Lisa Yin, one of five finalists, not the winner. IEEE Koji Kobayashi Award, 2000, jointly with Shamir and Adleman; the same year the RSA Conference gives Ralph Merkle its award for excellence in mathematics, a stop the atlas carries at **37.3305, -121.8893** in `ralph_merkle.journey.json`, inherited here. Ring signatures with Adi Shamir and Yael Tauman Kalai, 2001.

**[A]** RSA Security releases the patent into the public domain about two weeks before its September 2000 expiry (Computerworld). `hal_finney.journey.json` (1992-09-01) states that PGP did its public-key work with RSA, "licensed and litigated"; the release ends that dispute.

**CONTRADICTION 8: when Peppercoin was founded. Corrected, co-founder restored.** The pool gave 2003 and named Rivest alone. Peppercoin, Inc. was founded in late 2001 by Rivest **and Silvio Micali**, at Waltham. The system was presented at the RSA Conference in 2002; 2003 is the commercial launch. Chockstone bought it in 2007.

**CONTRADICTION 9: the rice. The event is real; the explanation is invented.** MIT News (April 2003) describes a surprise party on Wednesday 23 April 2003: about thirty colleagues invited by LCS director Victor Zue burst into the first session of Rivest's 6.045 class in Room 37-212 wearing party hats and shrieking, and "peppered Rivest with rice." **No source gives any reason for the rice.** The pool's gloss, "a jab at the algorithm's dependence on large prime numbers," appears in no account and connects to nothing.

**[A]** Turing Award (for 2002) at the ACM banquet during the Federated Computing Research Conference, San Diego, 7 June 2003; Turing lecture the next day, 'The Early Days of RSA: History and Lessons'. **[A]** CSAIL moves from Technology Square to the Stata Center, 2004.

## 11. Election security, 2005 to 2020

**[A]** Purdue lecture on voting systems, Krannert Auditorium, 5 December 2005. ThreeBallot, 2006. Marconi Prize, Menlo Circus Club, Atherton, 28 September 2007. Chesley Lecture, Carleton College, 29 May 2008. **[R]** EAC Technical Guidelines Development Committee work and Scantegrity, given in the sources as a period rather than a dated event; the journey places it at 2009-01-01 and calls the year a placement.

**CONTRADICTION 10: where the 2020 testimony happened. Corrected; the pool's own open question resolves.** The pool anchored the 17 July 2020 testimony to the Rayburn House Office Building and asked whether Rivest appeared in person or remotely. Both fail. The hearing was the Committee on House Administration's first fully virtual full-committee hearing, over WebEx under House Resolution 965; the chair states this on the record and witnesses joined remotely (Newt Gingrich appeared from Rome). The committee's hearing room is in **Longworth**, not Rayburn. Content confirmed: remote congressional voting is feasible and can be made adequately secure, because House votes are not secret.

## 12. Late honours, and the absence of a tomb

**[A]** Institute Professor, MIT, June 2015. BBVA Frontiers of Knowledge Award, 2017. USENIX Enigma speaker, 2016 (in the pool; dropped from the journey for length, not for doubt). Oral history recorded at the Computer History Museum, 6 December 2016; the museum pin **37.4143, -122.0775** is the one `ralph_merkle.journey.json` uses for the 2011 Fellows, inherited byte-identical over the pool's -122.0776.

**CONTRADICTION 11: the Hall of Fame year. Internal to the pool. Reconciled to 2018.** The pool's afterlife section says 2011; its own chronology (item 33) and geography (items 23-24) say 2018, with illumination at USPTO Alexandria on 2 May and induction at the National Building Museum on 3 May, which is what the Hall of Fame's announcement records. The 2011 date belongs to Diffie, Hellman and Merkle, whose induction the atlas carries in `ralph_merkle.journey.json`.

**CONTRADICTION 12: the 2021 Cryptographers' Panel. Real event, wrong place.** Rivest and Shamir did sit on the panel; Rivest likened NFTs to seventeenth-century Dutch tulip mania and Shamir floated auctioning an NFT of the signed first page of the 1977 MIT technical report. But RSA Conference 2021 ran entirely online, 17-20 May, so the pool's San Francisco anchor at 37.7749, -122.4194 does not apply. The journey uses the standing RSA Conference pin and says the coordinates are an address, not a room.

**Family and tomb. [A]** Married to Gail Rivest; two sons, Alex (a filmmaker) and Chris (an entrepreneur and co-founder); residence in Arlington, Massachusetts, undated in the sources, so the final stop carries a placement date and says so. Rivest is alive: the brief's frame of "afterlife and tomb" does not apply, and the journey states that absence instead of manufacturing a monument.

---

## Negative findings and honest gaps

1. **No canonical global pins apply.** An atlas-wide grep found no file placing Rivest at the Kaaba, Temple Mount, Paris, or Buenos Aires pins. His corpus geography is Cambridge, Stanford, Cornell, Washington, New York, and Silicon Valley.
2. **CRYPTO at UC Santa Barbara.** `diffie.journey.json` (1985-08-01) and `ralph_merkle.journey.json` (1987-08-01) treat the August CRYPTO conference at UCSB as the field's central convening. Rivest is a founding-generation figure and a historical participant, but no corpus file and no pool source places him there on a date, so no CRYPTO stop was written.
3. **The 1973 selection paper's coauthors** are not itemised in the pool and were not verified here.
4. **The Sapienza honorary doctorate (2002)** rests on a Prabook entry; no Sapienza record was checked, and the journey says so.
5. **The seder house** is unidentified in every source consulted; the pin is a reconstruction near campus.
6. **`rivest_shamir_adleman.journey.json`** is referenced by filename in the corpus but does not exist.
7. **Recency.** No confirmed public appearance later than the 2021 panel was surfaced. 2024 and 2025 are a gap, not an assertion of absence.

## Sources

**Primary, reached and read**
- *Oral History of Ronald L. Rivest*, Roy Levin interviewer, ACM Turing Award Winners Project / Computer History Museum, 6 December 2016 (CHM Ref X8019.2017), 48 pp. Pages cited: 2, 11-14, 22-23, 33, 35. Two pool citations are corrected here: "Yeah, that was a joke" is the last Rivest utterance on p.12, not p.13; the Dr. Dobb's credit-card passage is on p.33, not p.34, and is read aloud by Levin quoting the 2008 interview rather than spoken fresh in 2016.
- Rivest, Shamir, Adleman, *Communications of the ACM* 21:2 (Feb 1978), 120-126, doi:10.1145/359340.359342. US Patent 4,405,829. Atkins, Graff, Lenstra, Leyland, ASIACRYPT'94, LNCS 917 (1995), 261-277, doi:10.1007/BFb0000440. Written testimony HHRG-116-HA00-Wstate-RivestR-20200717, 17 July 2020.

**Institutional and press**
- MIT News: 'Rivest pelted with rice at Turing tribute' (2003); 'MIT leaves behind a rich history in Tech Square' (2004); 'Rivest wins Marconi Prize' (2007). MIT CSAIL News, 'Ron Rivest named Institute Professor' (2015).
- amturing.acm.org chronology and the 2003 Turing announcement; AMS *Notices* (July 2003); NIST Second AES Candidate Conference report (Rome, 1999); National Inventors Hall of Fame 2018 coverage and invent.org; BBVA laureate page; Carleton Chesley listing (2008); Purdue News (2005); USENIX Enigma 2016 listing; RSA Conference speaker pages and BankInfoSecurity 2021 coverage; Computerworld, 'RSA encryption patent released'.

**Secondary and compiled, carrying [R] where they are the only support**
- Wikipedia, 'Ron Rivest', 'RSA (cryptosystem)', 'RSA Security'; Britannica; FundingUniverse, 'History of RSA Security Inc.' (Adleman's apartment, the Redwood City incorporation); History Tools; Grokipedia / HandWiki (high-school details, demoted); Prabook (Sapienza doctorate, unverified); Robinson, 'Still Guarding Secrets', Northeastern, and cognate retellings of the seder.

**In-corpus journey files consulted for interlock and pin inheritance**
`phil_zimmermann`, `nick_szabo`, `hal_finney`, `ralph_merkle`, `diffie`, `hellman`, `claude_shannon`, `betty_shannon`.

**Not reached in this pass, with the reason**
- The August 1977 *Scientific American* issue itself; the Gardner column comes wholly through retrospectives.
- Rivest's CV or MIT publication list, which would settle the 1973/1974 doctorate question and itemise the 1973 selection paper's coauthors.
- Any Sapienza record of the 2002 honorary doctorate; any primary account of the April 1977 seder; the RSA Conference 2021 panel transcript.
