# Sergio Demian Lerner: research report

*Compiled 2026-09-09 for `sergio_demian_lerner.journey.json`. Buenos Aires cryptographer; Bitcoin vulnerability researcher; author of the extraNonce/Patoshi analysis; co-inventor of ASICBoost; co-founder and chief scientist of RSK/Rootstock; since 2024 identified with Fairgate and BitVMX.*

Legend: **[A]** attested, source named. **[R]** reconstruction, tradition, or self-report no independent record confirms. Contradictions are flagged and **not adjudicated**. Unreachable sources are named with the reason.

**One caution governs the whole file.** The richest source on this life is his own About page, `bitslog.com/about/`, which supplies most of the early life, the talk list, the company foundings and the Casares meeting, almost none of it independently corroborated. Each such item is **[A]** as a statement he makes about himself and **[R]** as a fact about the world. The journey file says so item by item in `date_confidence`; this report says it once, here.

---

## 1. Origins, and the gap where a biography should be

**No reliable public source establishes his birth date or birthplace. [A, negative finding]** A commercial biography site gives 1972; it conflicts with the documented UBA record and is corroborated nowhere. No parents, schooling, siblings or birth city appear in anything reachable. The gap is stated twice inside the journey file.

**c. 1990, Applied Cryptography. [R]** He credits Schneier's *Applied Cryptography* as his entry into the field and dates the purchase to 1990. **Contradiction, unresolved:** that book's first edition appeared in **1994**. Either the year is wrong or the book is; the file presents the recollection as his and says the year cannot be right as stated.

**1994, a branch of the Argentine government. [R]** "by 1994 I was working on information security... in order to protect the networks of a branch of Argentina's government." **No source names the agency**, and his own sentence stops where a name would go.

**Undated, Core Security Technologies. [R for his role, A for the firm]** He reports consulting there, "designing and programming high-performance cryptographic servers," with no year, office or project. Core Security was founded in Buenos Aires in **1996** by Emiliano Kargieman, Iván Arce, Ariel Futoransky and Gerardo Richarte, file-attested in `emiliano_kargieman.journey.json`, which **never mentions Lerner**. The crossing is institutional; **no personal meeting is documented**. The stop's 1998 date merely sits after the founding.

**Undated, Pentatek / ATI-Medical. [R]** Neurological and medical equipment, about fifteen employees, more than ten years. **No incorporation record, dissolution date, equity or co-founder beyond himself was located.** The stop's year 2000 is an ordering device.

## 2. Mental poker, 2009 to 2010

**13 October 2009, patent priority. [A]** Google Patents US8677128B2: priority 13 October 2009, filed 13 October 2010, granted 18 March 2014, assignee an individual. **Correction:** a common version folds **US8862879B2** into this family; it carries its own priority of **13 April 2011** and does not belong there. The file names only US8677128B2.

**2010, Certimix at Incubacén. [A]** `incubacen.exactas.uba.ar/?p=284`: Certimix, marketing the CertifiedPlay card-game library, in pre-incubation at the Exactas-UBA incubator, Ciudad Universitaria, Pabellón II.

**15 November 2010, licenciatura thesis. [A as to existence and supervisor, R as to date]** *MPF: A New Family of Practical and Secure Mental Poker Protocols*, FCEN-UBA, supervised by **Hugo Scolnik**, dedicated to his wife **Alush** and son **Ariel**. Indexed via academia.edu and dblp. **The submission date could not be verified against any reachable primary UBA record.** That dedication is the **only appearance of a family anywhere in the reachable record of his life**.

**December 2010, Empretec / Banco Nación third prize. [A as to prize, R as to money]** The Incubacén post of 6 December 2010 confirms third place in the *Idea-proyecto* category. **The repeated ARS 10,000 figure could not be checked**: `empretec.org.ar` and `comercioyjusticia.info` both returned **HTTP 403**. No source places the ceremony inside the bank; the pin is the Bartolomé Mitre 326 headquarters and asserts nothing about the room.

## 3. The bug reports, 2011 to 2013

**Late 2011, first reading. [R]** "It was not until late 2011, when I first read the Bitcoin paper and I rushed to analyze the source code." **Contradiction, left standing:** a **2024 Criptonoticias interview** dates his encounter to **2012**, as does the December 2014 Foundation announcement ("voluntario desde 2012"). The discrepancy is his own and the file does not choose. He separately places himself on a cryptography mailing list in **2010** discussing anonymous payments, adding "I don't remember having read about Bitcoin during 2010." **[R]**

**Four disclosures. [A]** **25 June 2012, CVE-2012-3789**, CPU exhaustion, fixed in Bitcoin Core 0.6.3, release notes crediting him. **24 to 26 August 2012, CVE-2012-4684**, alert-system signature malleability, discussed privately with **Gavin Andresen** and **Gregory Maxwell**, fixed in 0.7.0 on 17 September 2012, disclosed 1 March 2013. **9 January 2013, CVE-2013-2293**, continuous disk seek: the wiki records the report on the **9th**, not the 8th as often given, Andresen confirming 0.8 unaffected the same day, rc1 on 9 February, disclosure 14 February; the formerly cited `bitcoinwiki.org` page returns **HTTP 404** and was replaced. **30 January 2013, CVE-2013-2292**, OP_CHECKSIG cost, "a transaction that takes at least 3 minutes to verify," per the en.bitcoin.it CVE table; its commonly cited **NVD publication date of 12 March 2013 is dropped**, since nvd.nist.gov and cve.org failed to return the record and `en.bitcoin.it/wiki/CVE-2013-2292` returns **HTTP 404**.

**19 to 21 September 2012, Ekoparty, MavePay. [A as to talk, venue contested]** `seclists.org/fulldisclosure/2012/Sep/30` gives the **eighth** edition, conference 19 to 21 September, listing "Bitcoin, MavePay and the future of cryptocurrencies." The MAVEPAY PDF carries a creation date of 17 April 2012, single author.

> **Two corrections and one open contradiction.** (1) **Not a tenth anniversary**: Spanish Wikipedia dates the conference's founding to 2005 and calls 2012 "su octava edición consecutiva." (2) **Venue unresolved**: the only primary program reached gives "Ciudad Autónoma de Buenos Aires" with no address, while one tradition places the 2012 edition at **Aeroparque Jorge Newbery** and another places this same talk at **Ciudad Cultural Konex**. Neither is sourced to a primary document, and **the two lenses of this pool contradicted each other here.** Rather than let one talk occupy two buildings, the stop pins to the city centroid and states the contradiction.

**A stop deliberately not written: CVE-2013-2272.** Proposed by the geography lens (remote discovery of a node's wallet addresses), dated February 2013. The CVE table dates it to **11 January 2013**, `en.bitcoin.it/wiki/CVE-2013-2272` returns **HTTP 404**, and **no reachable source names Lerner as its reporter**, so it was dropped rather than written on an assumption.

## 4. Patoshi, 2013

**17 April 2013, "The Well Deserved Fortune of Satoshi Nakamoto." [A, fetched directly]** Tracking the extraNonce field across the first fifty thousand blocks yields straight-line segments that occasionally restart: a single dominant early miner that never spent. Verbatim: "**I estimate at eyesight that Satoshi fortune is around 1M Bitcoins**, or 100M USD at current exchange rate," and "I can't assure with 100% certainty that the all the black dots are owned by Satoshi, but almost all are owned by a single entity."

> **Correction carried into the file.** A widely repeated summary has this post estimating "980,000 to 1.1 million BTC" and using the nickname **Patoshi**. Fetched directly, **it does neither.** Both belong to the **2019** work; the file moves them there.

**The critical position. [R]** Analysts including BitMEX Research argue that slopes and nonce-byte clustering establish **one implementation or coordinated system**, not one identifiable person, and that block-level attribution produces false positives. This is a **synthesized critical consensus**, not a single dated primary statement; the nearest reachable anchor is the PLOS ONE "strangely mined bitcoins" study. Rendered as a live dispute, neither debunking nor vindication.

**2013, Wences Casares' office. [A as self-report]** "In 2013, Wences Casares, the founder of Xapo, visited Argentina... he invited me to his offices in Buenos Aires, and after a really enthusiastic talk he convinced me to go to the 2013 Bitcoin conference, in San Jose." Address given nowhere; the pin approximates Retiro and says so. **This is the direct, attested, personal relation that licenses naming `wences_casares` in a campa.**

**17 to 19 May 2013, Bitcoin 2013, San Jose. [A as to conference, R as to content]** He reports pitching Appecoin and a Turing-complete contract platform to general indifference, **Timo Hanke** the exception. Not independently corroborated. The same holds for his **2013 Ekoparty Satoshi talk [R as to venue and month]**, recorded as "A mystery trip to the origin of Bitcoin": Konex is Ekoparty's customary venue in these years but **is not pinned to the 2013 edition by any primary program reached**.

**7 to 8 December 2013, first LaBitConf. [A as to conference, R as to Lerner]** `blog.portinos.com` confirms verbatim "7 y 8 de diciembre de 2013... en el Meliá Buenos Aires Hotel, Reconquista 945." **Correction:** that source names **Jeff Garzik** and **Tony Gallippi** as headline foreign speakers, while **Andreas Antonopoulos and Erik Voorhees**, widely attached to this edition, could not be verified and are **not asserted**. **Caution:** **no primary source places Lerner in the hall**; he is documented only as belonging to the circle the conference gathered.

## 5. ASICBoost and the auditor's chair, 2014 to 2015

**2014, ASICBoost with Timo Hanke. [A with a dating conflict]** "During 2014 I collaborated with Timo Hanke in creating ASICBoost." **Contradiction, unresolved:** **US11113676B2**, inventors Timo Tobias Hanke and Sergio Demian Lerner, carries a **priority date of 19 November 2013**, filed 28 April 2016, granted 7 September 2021, assignee **Circle Line International Limited**. His "during 2014" sits after the priority; January 2014 orders the segment and does not adjudicate. **Also dropped:** the claim that the patent gives Lerner a Buenos Aires residence does not appear on the Google Patents record reached, and `patents.justia.com` returned **HTTP 403**.

**ASICBoost and SegWit. [R]** Covert deployment by mining-hardware manufacturers became a central charge in the 2017 scaling war, alleged of manufacturers and **not of Lerner**; the retrospective account rests on the Malicious Life podcast, unverified against a primary transcript. The file alludes to the fight in one clause and asserts nothing about his conduct.

**Undated, CoinFabrik and Coinspect. [A as to partners, R as to dates]** "I co-founded Coinfabrik with Pablo Yabo and Sebastian Wain. Coinfabrik used to employ more than 40 engineers"; Coinspect with **Juliano Rizzo**. **The circa-2014 dating in circulation is attested by no source reached.** The Rizzo partnership matters because he signs the Vot.Ar report months later.

**5 December 2014, Bitcoin Foundation security auditor. [A]** CoinDesk dates Gavin Andresen's announcement to 5 December 2014. **Two things to keep straight:** the **8 December** date frequently given is the publication date of the Spanish reprint at `oroyfinanzas.com`, which is the article actually carrying the quotes; and several outlets described a full-time hire where Andresen's own text makes it **on demand** ("No es realista poner las expectativas de un empleado a tiempo completo en un voluntario"). That reprint says "voluntario desde 2012" with **no month**; "since March 2012" comes from other reporting.

**3 July 2015, the Vot.Ar report. [A, PDF read directly]** **Two material corrections.** (1) **Signatory, not co-author**: the closing page lists nine names under **"Adhieren:"** (Ortega, Barrera Oro, Chaparro, Russ, Amato, Smaldone, Rizzo, Waisman, Lerner), followed by "Y gente de la Internet." (2) **Not presented at Ekoparty**: the document is headed "Julio 3, 2015" and was released through **Fundación Vía Libre** two days before the 5 July 2015 CABA election, so that scrutineers would be alert during the count. Ekoparty 2015 ran in **October**. The file dates the stop 3 July and drops the Ekoparty framing.

## 6. RSK / Rootstock, 2015 to 2020

**2015, RSK Labs founded. [A]** Lerner (chief scientist), **Diego Gutiérrez Zaldívar** (CEO), **Adrián Eidelman**, **Gabriel Kurman**, **Rubén Altman**, in Buenos Aires. Crunchbase dates Gutiérrez Zaldívar's tenure from **November 2015**, the only month-level anchor found. His own account: "I designed Rootstock, including its merge-mining subsystem and its bridge with Bitcoin, and I wrote its whitepaper."

**Three talks resting on his own list alone. [R]** LaBitConf Mexico 2015 (the Mexican city is stated nowhere reachable; pin defaults to Mexico City), MIT Bitcoin Expo 2016 (undated within the year; campus centroid), Off the Chain workshop, Berlin 2018 (Shrinking-Chain Scaling; no venue, no month).

**March 2016 and 22 May 2017, the funding. [R]** FinSMEs: about **US$1M** from Bitmain, Coinsilium and Digital Currency Group, after a seed near **US$350,000**. CoinDesk, 22 May 2017: **US$3.5M** with Bitmain, Bitfury and Anthony Di Iorio among participants, alongside the Ginger testnet. Trade press only; **no corporate filing was reached for any figure.**

**November 2017, Devcon 3, Cancún. [A]** "The Blockchain Virus: Can a Blockchain Pay to Replicate?" **Coordinate correction:** the hotel-zone coordinates commonly given (21.0752, -86.8747) are about **11 km north** of the site. Devcon 3 was at the **Moon Palace** resort, Nominatim **20.9870, -86.8386**, which the file uses.

**4 January 2018, Bamboo mainnet genesis. [A by concordant trade press]** Mined at approximately 01:41 CST; about 100 transactions per second; 21 smartbitcoins among some 100 companies. **The block hash and timestamp were not pulled from a chain explorer in this pass.**

**3 to 4 July 2018, Building on Bitcoin, Lisbon. [R]** Bitcoin Magazine confirms the Lisbon dates, but its **confirmed-speaker list (Paul Sztorc, Nicolas Dorier, Adam Ficsor, Bryan Bishop) does not include Lerner**. The slide PDF formerly cited returns **HTTP 404** and `building-on-bitcoin.com` is dead. His participation rests on his own listing alone.

**16 April 2019, "The Return of the Deniers and the Revenge of Patoshi." [A, fetched directly]** The independent nonce-byte fingerprint: "There is a single PC clock whose time is stamped in the Patoshi blocks... A single miner." In fairness to his critics, from the same post: "**I'm open to consider other explanations**, but for me this can only mean one thing." He publishes the classification as satoshiblocks.info the same year **[R as to month]**; it is his own dataset and confirms nothing independently.

**27 September 2019, IOV Labs acquires Taringa!. [A]** Rootstock Labs' own announcement, dated **27 September** rather than merely "September": 30 million users, over 1,000 active communities. Taringa declined and **closed in 2024**. **No public source isolates Lerner's individual responsibility** for the decision or the outcome.

**30 January 2020, Advantek S.R.L., Boletín Oficial. [A as document, R as kinship]** Notice 34.297, p. 34: Lerner resigns as manager; **Daniel Lerner, born 16 October 1945**, is appointed managing partner. Seat at **Manuel Ricardo Trelles 2040** (-34.6046, -58.4659); Daniel Lerner's domicile **Camarones 2307**, four blocks away. **Tagging correction:** the document is squarely **[A]** and only the **father-son inference is [R]**, made by no source and made nowhere in the file.

**26 May 2020, the Wright address list. [R]** bitcoinblog.de reports addresses from a Wright-associated early-block list being used to sign a message calling Wright "a liar and a fraud." Lerner's separate warning about false positives is documented but **not tied to that date or message by any source reached**.

**December 2020, the Powpeg. [R]** "I co-designed the Powpeg two-way-peg bridge, that the RSK sidechain implemented in December, 2020." Co-designers unnamed there and not found elsewhere.

## 7. Fairgate, 2023 to 2026

**24 January 2023, Flyover. [A]** `eprint.iacr.org/2023/086`, submitted 24 January, revised 26 January. **Billing correction:** the author order is **Javier Alvarez Cid-Fuentes, Diego Angel Masini, Sergio Demian Lerner**, all at IOV Labs, with **Lerner third**. "Lerner co-authors with X and Y" inverts it; the campa states the real order.

**22 to 24 February 2024, Bitcoin++ Buenos Aires. [A]** `btcpp.dev/ba24`; Área Tres Workplace, Palermo Soho; keynote on two-way pegs and Bitcoin scaling; identified with **Fairgate** and BitVMX.

**20 May 2024, COPA v Wright. [A as to ruling, absent as to Lerner]**

> **Venue sharpened, then abandoned.** The **written judgment** was handed down **20 May 2024** by **Mr Justice Mellor**, Chancery Division, in the Business and Property Courts at the **Rolls Building, Fetter Lane** (about 51.5176, -0.1093), not the Royal Courts of Justice on the Strand (51.5138, -0.1136), which one lens of this pool had wrong. But Lerner was **not a party**, **no source reached shows him testifying**, and none confirms his research being cited **in the courtroom** as opposed to in the press around it. Under the rule that a stop belongs to whoever was actually there, staging him at the Rolls Building would be false, so the file places this at **his own Buenos Aires pin** and asserts nothing about London.

**2024, Criptonoticias interview at LaBitConf. [A]** **Quote correction, material:** the sentence circulating as "La emoción que sentí al conocer Bitcoin en 2012 sigue intacta, o incluso más potenciada" **appears nowhere in the source**, splicing the headline with the body. The body reads "la emoción que sentí el día que conocí Bitcoin en 2012 sigue intacta, o incluso más potenciada," and the file quotes **his words, not the headline**. Also drawn on: "mis primeras conferencias sobre Bitcoin, en 2012, eran bastante críticas" and "Para mí, Rootstock es la solución ideal de escalabilidad para Bitcoin."

**7 October 2025, BATTLE for Bitcoin. [A]** `arxiv.org/abs/2510.06468`, with **Ariel Futoransky**. That this is the Core Security co-founder is stated in the dossier and consistent with the record but **was not independently reconfirmed**; the file calls the thirty-year loop probable, not proven.

**2026, APoW. [R, the weakest item in the file]** *APoW: Auditable Proof-of-Work Against Block Withholding Attacks* appears in the dossier's works bibliography and fits Fairgate's programme, but **no primary record of its publication was reached** and no month is attested. It closes the file, labelled a reconstruction.

## 8. Claims examined and deliberately not written

- **The Vitalik Buterin legend. [R, unconfirmed]** The tradition that Lerner personally introduced Buterin to smart contracts during Buenos Aires visits circulates in secondary profiles; `criptodinero.es` separately credits him with collaborating on Ethereum's early design. **No primary correspondence, dated meeting, interview or joint statement from either man was found**, and there is **no `vitalik_buterin.journey.json`** to anchor it against. Written as **no stop**, and recorded here so it is not silently lost.
- **CVE-2013-2272.** See section 3, dropped for lack of any source naming him as reporter.
- **Hal Finney and Nick Szabo.** Their files fix, respectively, the genesis-era corpus the Patoshi work analyses and the Bit Gold/Ethereum lineage behind RSK's EVM compatibility. Both are **corpus overlap or lineage, not relations**: no source places Lerner in a room or in correspondence with either man, and **neither is named in any campa**. The same rule bars name-dropping travelers who merely share his Buenos Aires pins.

## Apparatus relations for the operator

**None found, in either direction.** Nothing in this pool applies Lerner's framework backward to events he never treated, and nothing applies a dead theorist's framework forward onto him. He is **not** listed in `EXCEPTIONS.md`, and no stop needed the exception. The nearest boundary case was COPA v Wright, not an apparatus relation but a placement question, resolved by moving the stop to his own pin rather than by deletion.

## Interlocks written into the journey file

| named in a campa | basis | strength |
|---|---|---|
| **Wences Casares** (`wences_casares.journey.json`) | his own account of the 2013 office invitation and the San Jose trip | **[A]** direct, personal, self-attested |
| **Emiliano Kargieman** (`emiliano_kargieman.journey.json`) | Lerner consulted for Core Security, the firm Kargieman co-founded | **[R]** institutional; no personal meeting documented |
| **Ariel Futoransky** (no file yet) | Core Security co-founder; co-author on BATTLE for Bitcoin, 7 Oct 2025 | **[A]** co-authorship; **[R]** that the two Futoranskys are one man |
| **Diego Gutiérrez Zaldívar** (no file yet, queued) | RSK co-founder with Lerner, 2015; organizer of the first LaBitConf | **[A]** direct professional partnership |

`wences_casares.journey.json` **does not mention Lerner**; the relation is one-directional and written only on Lerner's file, per the standing rule. Nothing was added to any other traveler's file. Gutiérrez Zaldívar and Futoransky are named in prose as real co-workers and carried in `suggested_refs` against the day their own files land.

**Negative finding.** Grepping the journey files for Lerner, Bitslog, RSK, Rootstock, Certimix, CoinFabrik, Coinspect, ASICBoost, Patoshi, Ekoparty and LaBitConf returns nothing, and the 2026-08-02 census has zero hits for "Lerner." **This subject enters the corpus cold.**

## Sources

**Reached and used.** Every source is carried per stop in the journey file's own `sources` arrays and is not re-listed here. Fetched directly rather than by search: `bitslog.com/about/`, the 2013-04-17 and 2019-04-16 Bitslog posts, and the Vot.Ar PDF at vialibre.org.ar. One item deserves separate note: Open Library full-text search of Dominic Frisby, *Bitcoin: The future of money?* (OL39827629M), confirms the sentence about Lerner with "blockchain" as one word, correcting the Goodreads-relayed "block chain" variant and upgrading that quote from [R] to [A]. In-corpus reading: `emiliano_kargieman.journey.json`, `wences_casares.journey.json`, `QUEUE.md`, `EXCEPTIONS.md`.

**Not reached, with the reason.** **HTTP 403**: `empretec.org.ar`, `comercioyjusticia.info` (ARS 10,000 prize figure unverified), `patents.justia.com/patent/11113676` (ASICBoost residence line unasserted). **HTTP 404**: `bitcoinwiki.org/wiki/cve-2013-2293` (replaced), `en.bitcoin.it/wiki/CVE-2013-2292` and `.../CVE-2013-2272`, `building-on-bitcoin.com` and its slide PDF (domain dead). **Record not returned**: nvd.nist.gov and cve.org for CVE-2013-2292. **Not found at all**: a primary program for LaBitConf Mexico 2015 or Ekoparty 2013; a chain-explorer record of the RSK Bamboo genesis hash; a primary record of APoW (2026); and any birth record whatsoever for Sergio Demian Lerner.
