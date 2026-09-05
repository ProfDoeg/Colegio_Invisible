# Adi Shamir: Research Dossier

## Scope and evidentiary note

This dossier reconstructs the publicly documented life and work of Israeli cryptographer Adi Shamir through September 2, 2026. Shamir is living.

The surviving public record is exceptionally rich regarding his research, appointments, collaborators, honors, patents, and commercial applications, but sparse regarding his childhood household, ancestry, military service, private finances, and family life. Those absences are stated rather than supplemented by inference.

Evidentiary labels used below:

- **Documented fact:** supported by an institutional record, original publication, patent, official award record, or other primary document.
- **Reported fact:** stated by reputable contemporaneous journalism, an interview, or a credible secondary source but not independently documented here.
- **Allegation:** a claim made in an investigation, legal proceeding, or attributed accusation that did not necessarily result in a finding.
- **Disputed claim:** competing accounts exist or the available evidence does not establish one version conclusively.
- **Rumor or myth:** a repeated narrative unsupported by adequate evidence, or a simplified story whose historical significance exceeds its literal accuracy.
- **Unresolved:** available sources do not establish the answer.

---

## Basic Identifying Information

- **Full name:** Adi Shamir.
- **Hebrew:** עדי שמיר.
- **Common professional forms:** Adi Shamir; A. Shamir; Professor Adi Shamir; Dr. Adi Shamir.
- **Birth:** July 6, 1952.
- **Birthplace:** Tel Aviv, Israel.
- **Nationality:** Israeli.
- **Present status:** Living as of September 2, 2026.
- **Principal field:** Computer science, especially mathematical cryptography and cryptanalysis.
- **Other fields:** Computational complexity, algorithms, machine learning, hardware-security analysis, side-channel analysis, and computational geometry.
- **Long-term institutional base:** Weizmann Institute of Science, Rehovot, Israel.
- **Named chair:** Paul and Marlene Borman Professor of Applied Mathematics; later institutional descriptions call him the Borman Professor of Computer Science or Applied Mathematics.
- **Current institutional status:** Weizmann’s research portal identifies him as a full professor emeritus in Computer Science and Applied Mathematics while continuing to list research through 2026.
- **Residence:** A Hebrew biographical summary reports that Shamir lives in Rehovot. No property record or exact address was consulted or is reproduced.
- **Most familiar public identification:** “the S in RSA,” referring to the Rivest–Shamir–Adleman cryptosystem.
- **Pseudonyms or pen names:** None documented.
- **Titles of nobility, political office, or religious office:** None documented.

Shamir should not be confused with the unrelated Russian-Israeli-Swedish writer who uses the name Israel Shamir, former Israeli prime minister Yitzhak Shamir, mathematician Eli Shamir, or other persons sharing the surname.

---

## Family and Ancestry

### Parents, ancestry, and siblings

No sufficiently reliable source consulted for this dossier identifies Shamir’s parents, their occupations, his ancestry beyond his Israeli birth, or any siblings.

The Wolf Foundation states that he showed an early interest in science and attended youth academic programs and science summer camps at the Weizmann Institute. This provides evidence of an intellectually formative childhood but not of his family’s social or economic circumstances.

### Marriage and children

A Hebrew secondary biographical compilation reports that:

- Shamir is married to a woman named **Leah**;
- they have **two daughters and one son**;
- the family resides in **Rehovot**.

This is best labeled **reported fact**, because no direct interview, family statement, or official biography consulted here supplies the same information. Names, birth dates, occupations, and biographies of the children were not established.

There is no reliable public evidence in the consulted record of other marriages, partners, or children.

---

## Childhood and Early Life, 1952–1970

Shamir was born in Tel Aviv on July 6, 1952, four years after the establishment of the State of Israel.

The detailed circumstances of his childhood—neighborhood, schools, parents’ occupations, religious observance, family migrations, and economic background—are absent from the principal institutional biographies. No reliable source consulted establishes whether he was born into an immigrant or locally born family.

The Wolf Foundation records two formative elements:

1. He exhibited an interest in science from an early age.
2. He participated in academic programs for young people and summer science camps at the Weizmann Institute.

These programs supplied an early institutional connection to Weizmann, where he would later take his graduate degrees and spend most of his career.

No childhood illness, accident, psychological crisis, disciplinary problem, political activism, or juvenile employment was documented.

---

## Education and Formation, circa 1970–1977

### Tel Aviv University

Shamir studied mathematics at Tel Aviv University and received a **Bachelor of Science in mathematics in 1973**. The Wolf Foundation states that he graduated with highest distinction.

His undergraduate teachers and thesis, if any, have not been established from the consulted sources.

### Weizmann Institute of Science

Shamir moved into computer science at the Weizmann Institute:

- **M.Sc. in computer science, 1975**
- **Ph.D. in computer science, 1977**

His doctoral dissertation was titled **“The Fixedpoints of Recursive Definitions.”** Bibliographic records sometimes date the thesis manuscript to October 1976, while institutional biographies give 1977 as the degree year. These are compatible: manuscript completion or submission in 1976, degree award in 1977.

His doctoral adviser was **Zohar Manna**, a prominent researcher in the mathematical theory of computation and program verification. Manna was therefore Shamir’s most clearly documented formal mentor.

Shamir’s dissertation belonged to theoretical computer science rather than cryptography. His early publications addressed semantics, recursion, data types, and algorithms. This background helps explain the breadth of his later work: he did not enter research as a narrowly trained intelligence cryptographer but as a mathematical computer scientist.

### Intellectual formation

Three currents became especially important:

- mathematical logic and computation, represented by his dissertation work with Manna;
- algorithms and complexity theory;
- the emerging public literature on public-key cryptography, especially the 1976 work of Whitfield Diffie and Martin Hellman.

There is no evidence that Shamir received classified cryptographic training before RSA. Accounts of the RSA work instead portray him as a theorist attracted by the newly published public-key problem.

---

## Early Career: Warwick and MIT, 1976–1980

### University of Warwick

Institutional biographies report a one-year postdoctoral appointment at the **University of Warwick** in England, normally dated 1976–1977.

A 1977 paper with William W. Wadge, “Data Types as Objects,” belongs to this early theoretical-computer-science period.

### Massachusetts Institute of Technology

Shamir moved to the United States and joined MIT’s Department of Mathematics:

- **Instructor, 1977–1978**
- **Assistant professor, 1978–1980**

He was also associated with MIT’s Laboratory for Computer Science.

This move placed him near Ronald L. Rivest and Leonard M. Adleman at the moment when Diffie and Hellman’s public-key proposal had made construction of a practical one-way trapdoor function an urgent research problem.

No evidence consulted indicates that the move was an exile or politically compelled migration. It was an academic appointment. Shamir returned voluntarily to Israel in 1980.

---

## The Creation of RSA, 1976–1978

### The public-key problem

Whitfield Diffie and Martin Hellman publicly described the idea of public-key cryptography and digital signatures in 1976. Their work made possible a system in which an encryption key could be made public while the corresponding decryption key remained secret, but it did not provide the RSA construction.

At MIT, Rivest, Shamir, and Adleman began looking for a practical realization.

### Division of labor

The best detailed account comes from Leonard Adleman’s ACM oral history:

- Rivest and Shamir repeatedly proposed candidate systems.
- Adleman, whose background included number theory, attempted to break them.
- The team went through dozens of proposals.
- Adleman recalled approximately forty-two failed candidates before the successful one.

The “42 failed systems” count is a participant’s retrospective recollection, not a surviving numbered laboratory register, but the basic pattern is consistently reported.

### The Passover-night story

Adleman recalled that after a Passover dinner in 1977, Rivest telephoned him around midnight or later with the core construction now called RSA. Adleman immediately thought it looked sound. Rivest then stayed awake and drafted a paper by hand.

The first draft reportedly listed the authors alphabetically as Adleman, Rivest, Shamir—“ARS.” Adleman initially asked to be removed because he regarded the decisive construction as Rivest’s idea. Rivest argued that the failed proposals and Adleman’s attacks had made the result a team achievement. Adleman agreed to remain if placed last; Shamir agreed that Rivest should be first. Hence **Rivest–Shamir–Adleman**, or RSA.

This story is **reported fact based on participant testimony**. Rivest’s own oral history confirms the general 1977 development period and collaborative process. The precise hour, quantity of wine, and sequence of conversations vary in popular retellings.

### Publication

The principal paper was:

> Ronald L. Rivest, Adi Shamir, and Leonard M. Adleman, “A Method for Obtaining Digital Signatures and Public-Key Cryptosystems,” *Communications of the ACM* 21, no. 2 (February 1978), pp. 120–126.

The system used modular exponentiation and a modulus formed from two large primes. Its public and private exponents permit encryption, decryption, and digital signatures. Its practical security became associated with the difficulty of factoring the public modulus, although the exact equivalence of breaking every RSA configuration and factoring is not established.

### Patent

MIT obtained U.S. Patent **4,405,829**, “Cryptographic Communications System and Method,” naming Rivest, Shamir, and Adleman as inventors. It was filed December 14, 1977, and granted September 20, 1983.

Because the work was done at MIT, the patent was assigned to MIT, not simply owned personally by the three inventors. RSA Data Security later received an exclusive license. The patent had no equivalent controlling force over use outside the United States and expired in September 2000; RSA Security released the algorithm from its remaining U.S. patent restrictions shortly before formal expiration.

### Government pressure and export controls

Contemporaneous and retrospective accounts report that the U.S. National Security Agency warned the MIT researchers about dissemination of cryptographic material and the possible application of arms-export rules. Adleman recalled receiving warnings that cryptography was treated as a munition and that overseas distribution could lead to prosecution.

No consulted source establishes that Shamir was prosecuted, formally charged, imprisoned, or sanctioned over RSA publication. The episode belongs to the broader late-twentieth-century conflict over U.S. cryptographic export controls.

---

## Chronological Life History and Research

## 1979: Secret sharing and algorithms

Shamir published **“How to Share a Secret”** in *Communications of the ACM*.

The scheme divides a secret into multiple shares so that any authorized threshold number can reconstruct it, while fewer shares disclose no information. Its construction uses polynomial interpolation over a finite field.

The method became foundational in:

- distributed key custody;
- disaster recovery;
- certificate-authority protection;
- multiparty computation;
- cryptocurrency wallet recovery;
- institutional controls designed to prevent any one person from holding a complete secret.

In theoretical computer science, Shamir also produced an early linear-time algorithm for **2-satisfiability**, an important special case of Boolean satisfiability.

## 1980: Return to Israel

Shamir returned to the Weizmann Institute:

- **Associate professor, 1980–1984**
- **Professor, 1984 onward**

His principal professional residence thereafter was Rehovot. He continued extensive international travel for conferences, prizes, and visiting appointments.

## 1982: Breaking the Merkle–Hellman knapsack cryptosystem

Shamir published a polynomial-time attack against the basic Merkle–Hellman knapsack cryptosystem, an early public-key system proposed by Ralph Merkle and Martin Hellman.

This was a major cryptanalytic success because it showed that the apparent hardness of the general subset-sum problem did not automatically protect a cryptosystem built from a specially structured instance. It helped establish a recurring principle of Shamir’s career: a hard mathematical problem can be undermined by the structure added to make it usable.

## 1983–1984: Recognition and identity-based cryptography

Shamir received the Israel Mathematical Union’s **Erdős Prize in 1983**.

At CRYPTO 1984 he proposed **identity-based cryptosystems and signature schemes**. In an identity-based system, a public identifier such as a name or email address can function as a public key, while a trusted authority generates the corresponding private key.

Shamir’s 1984 paper proposed the paradigm and provided an identity-based signature construction, but not a fully practical identity-based encryption system. Practical pairings-based identity-based encryption arrived much later. Popular summaries sometimes blur this distinction.

## 1980s: Computational complexity

Shamir remained active outside cryptography. His work included algorithms, complexity theory, and the relationship between interactive proof systems and conventional complexity classes.

A particularly important result was his 1992 theorem **IP = PSPACE**, showing that the problems possessing polynomial-time interactive proofs are exactly those solvable in polynomial space. This was a central result in complexity theory and demonstrated that interaction and randomness dramatically enlarge what a computationally limited verifier can check.

## 1986–1988: Fiat–Shamir identification and signatures

With **Amos Fiat** and **Uriel Feige**, Shamir developed practical zero-knowledge identification protocols.

Major publications included:

- “How to Prove Yourself: Practical Solutions to Identification and Signature Problems”;
- “Zero-Knowledge Proofs of Identity.”

These protocols allow a claimant to demonstrate possession of secret information without revealing that information.

The associated **Fiat–Shamir heuristic or transform** converts certain interactive public-coin proof protocols into noninteractive signatures by replacing the verifier’s random challenge with a cryptographic hash of the transcript. It became central to modern proof systems, digital signatures, and blockchain protocols.

Its security was later formalized under models such as the random-oracle model. It is not a universal theorem that every interactive proof remains secure under this transformation; the applicability conditions matter.

### Students and mentoring

Shamir’s documented students include:

- Amos Fiat;
- Uriel Feige;
- Eli Biham.

Later collaborators and younger researchers associated with his work include Eran Tromer, Itai Dinur, Orr Dunkelman, Nathan Keller, Daniel Genkin, Eyal Ronen, Yuval Elovici, Ben Nassi, and others.

## 1987–1988: News Datacom and pay-television security

In 1987–1988, the commercial arm of Weizmann, **Yeda Research and Development**, and Rupert Murdoch’s News Corporation organized a venture commonly called **News Datacom** or **News Data Security Products**, with Israeli research conducted through News Datacom Research and Development.

A June 1988 Israeli high-technology report stated:

- News Corporation and Yeda were major stockholders;
- Murdoch’s side was investing approximately **US$5 million**;
- products would initially use inventions by Shamir and other Weizmann scientists;
- the Fiat–Shamir algorithm was patented by Yeda and exclusively licensed to the venture;
- intended applications included identification, authentication, digital signatures, and secure access.

Later descriptions connect the company with smart-card and conditional-access technology for pay television. News Datacom evolved into **NDS**, later a major provider of television encryption and conditional-access systems.

Sources disagree on Shamir’s exact corporate position:

- some popular Israeli accounts call him a co-founder;
- a scholarly account of Israeli high technology describes him as a consultant rather than an employee;
- contemporaneous material clearly establishes that his inventions and Weizmann’s commercialization arm were foundational to the venture.

No reliable source consulted establishes the size of Shamir’s equity, royalties, consulting income, or later proceeds. It would be unsafe to infer personal wealth from NDS’s eventual valuation.

## Late 1980s–1993: Differential cryptanalysis

Shamir and his student **Eli Biham** developed and publicly disclosed **differential cryptanalysis**, a general chosen-plaintext method for analyzing block ciphers by tracing how input differences affect output differences.

They applied it to DES-like structures and ultimately to the full Data Encryption Standard. Their book, *Differential Cryptanalysis of the Data Encryption Standard*, appeared in 1993.

The work transformed public cryptanalysis and influenced cipher design, including the later AES competition.

### IBM and NSA prior knowledge

After Biham and Shamir’s public discovery, it became clear that researchers involved in DES at IBM had known related techniques in the 1970s and that the NSA knew of them as well. IBM’s S-box design had been strengthened against the attack.

Therefore:

- **Documented fact:** Biham and Shamir independently developed and publicly introduced differential cryptanalysis to the open research community.
- **Documented fact:** related knowledge predated their publication inside IBM/NSA.
- **Incorrect simplification:** that they were necessarily the first humans ever to discover the method.
- **Equally incorrect simplification:** that their work was merely derivative. No evidence consulted shows access to the classified prior work.

## 1990s: Recognition and commercial expansion

Shamir received:

- **UAP Scientific Prize**, France, 1990;
- **Pius XI Gold Medal**, Pontifical Academy of Sciences, 1992;
- **ACM Paris Kanellakis Theory and Practice Award**, 1996, jointly recognizing RSA’s theoretical and practical importance.

RSA Data Security, founded by Rivest, Shamir, and Adleman in 1982, developed into a commercial security company. James Bidzos became its decisive business executive after the founders’ early management proved less successful.

Security Dynamics acquired RSA Data Security in 1996. The available record establishes Shamir as a founder and early shareholder but does not disclose his eventual personal proceeds.

## 1994: Visual cryptography

With **Moni Naor**, Shamir introduced visual cryptography.

An image is divided into transparencies or shares that look random individually. When the required shares are physically superimposed, the image becomes visible to the human eye without ordinary decryption computation.

The work extended secret sharing from numerical secrets to directly perceptible images and stimulated research on graphical authentication and physical cryptographic interfaces.

## 1996: Differential fault analysis

Shamir and Biham announced **differential fault analysis**, extending the principle that deliberately induced computational errors can reveal secret keys.

This followed independent Bellcore work by Dan Boneh, Richard DeMillo, and Richard Lipton on fault attacks against public-key systems. Biham and Shamir emphasized applicability to secret-key ciphers such as DES.

The episode illustrates parallel discovery rather than a substantiated plagiarism dispute.

## 1996–1997: News Datacom tax investigation

This is the most substantial documented legal controversy touching Shamir personally.

On October 20, 1996, Israeli tax investigators raided News Datacom Research’s Jerusalem offices and related professional offices. A warrant referred to suspected tax offenses, tax evasion, and assistance to others in evading taxes between 1989 and 1996. Contemporary reports placed the overall disputed transactions or alleged evasion at very large amounts, with figures varying by report.

Shamir, identified as a senior technical figure or head of a computer center associated with the company’s work, was questioned.

The evidentiary distinctions are important:

- **Documented fact:** News Datacom was investigated and its offices were searched.
- **Documented fact:** Shamir was interrogated or questioned.
- **Documented fact:** later reporting specifically said Shamir and general manager Abe Peled/Feld were **not arrested**, correcting early reports that loosely described persons as detained or “held.”
- **Allegation at the time:** company-related tax evasion and improper transfers or sales of intellectual property.
- **Company position:** News Datacom denied wrongdoing and said it had filed required returns and paid applicable taxes.
- **Resolution reported in 1998:** News Datacom agreed to pay the Israeli tax authority a **NIS 15 million forfeiture**.
- **No established personal finding against Shamir:** the consulted record disclosed no indictment, conviction, civil judgment, or individual monetary penalty against him.

One 1996 business report mentioned approximately NIS 500,000 in unpaid taxes in the larger drama, but the accessible text does not establish that this was Shamir’s personal liability. It should not be represented as such.

## 1998–2000: Academies, side channels, and RSA patent expiration

Shamir was elected to the **Israel Academy of Sciences and Humanities** in 1998.

He received the **IEEE Koji Kobayashi Computers and Communications Award** in 2000.

In the late 1990s and early 2000s, he became prominent in the study of implementation attacks. These attacks do not necessarily defeat a cipher’s mathematics; they exploit information leaked by the device performing it, including:

- timing;
- power consumption;
- cache behavior;
- faulty calculations;
- electromagnetic or acoustic emissions.

The U.S. RSA patent expired in September 2000.

## 1999–2003: TWINKLE and TWIRL

Shamir proposed **TWINKLE**—The Weizmann Institute Key Locating Engine—a conceptual optoelectronic device intended to accelerate the sieving stage of integer factorization.

With Eran Tromer, he later designed **TWIRL**, a hardware architecture for the number-field sieve.

These projects did not constitute a demonstrated break of properly sized RSA keys. They explored the economics and engineering of factoring, helping estimate which key sizes were defensible against specialized machines.

## 2001: Ring signatures

With Ronald Rivest and Yael Tauman, Shamir published **“How to Leak a Secret,”** introducing ring signatures.

A ring signature lets a signer prove that one member of an ad hoc group signed a message without revealing which member. Unlike traditional group signatures, the construction does not require a group manager or prior group formation.

The paper framed the concept through the example of anonymously leaking a cabinet secret while proving that the source belonged to a group of officials.

## 2002: Turing Award

The Association for Computing Machinery awarded its 2002 A.M. Turing Award jointly to:

- Ronald L. Rivest;
- Adi Shamir;
- Leonard M. Adleman.

The official citation recognized their “ingenious contribution to making public-key cryptography useful in practice.”

The award refers principally to RSA rather than to the entirety of Shamir’s independent work.

## 2003–2009: International appointments and honors

Shamir received an honorary doctorate from the **École Normale Supérieure** in 2003. Institutional biographies report that he became an invited professor there beginning in 2006.

He was named an **IACR Fellow** in 2004 and elected a foreign associate of the **U.S. National Academy of Sciences** in 2005.

The French Academy of Sciences also describes him as having held visiting professorships at MIT, the University of Chicago, and ENS.

In 2008 he received:

- the **Israel Prize** in computer science;
- the **Okawa Prize**;
- the **NEC C&C Prize**.

He received an honorary doctorate from the **University of Waterloo** in 2009.

## 2005–2006: Commercial advising and RFID attack

A Hebrew secondary source reports that Shamir advised the Israeli online-security company **Cyota**, which was acquired by RSA Security in 2005. The exact dates, contractual terms, and compensation were not established.

At the 2006 RSA Conference, Shamir described how reflected power-consumption behavior could help attack password-protected RFID tags. He used a directional antenna and oscilloscope to infer whether guessed password bits were being accepted.

The demonstration extended his longstanding emphasis on physical leakage from nominally secure systems.

## 2008–2013: Cube attacks and acoustic cryptanalysis

With **Itai Dinur**, Shamir developed **cube attacks**, a method for extracting low-degree algebraic structure from black-box cryptographic functions. The work affected analysis of stream ciphers and related constructions.

With **Daniel Genkin** and **Eran Tromer**, he developed acoustic cryptanalysis against computers. Their experiments showed that sounds emitted by a machine during cryptographic computation could contain information sufficient, under controlled conditions, to recover RSA keys.

This research was sometimes sensationalized as “stealing keys by listening to a laptop.” The actual attacks required carefully designed signal processing, chosen inputs or interaction, suitable hardware, and vulnerable implementations. They demonstrated a real attack class, not effortless universal eavesdropping.

## 2009: Israeli biometric-database debate

A Hebrew biographical source reports that Shamir proposed adding controlled ambiguity or cryptographic protection to Israel’s planned biometric database so it could detect duplicate identities without exposing a straightforward centralized biometric repository. The government reportedly did not adopt his proposal.

This indicates participation in a specific public-policy debate, but not party affiliation or elected political activity.

## 2012: Grand Medal and NDS acquisition

The French Academy of Sciences awarded Shamir its **Grande Médaille** in 2012.

Cisco acquired NDS in 2012 in a transaction commonly valued at approximately **US$5 billion**. Shamir’s technology was historically connected to the company, but the evidence consulted does not establish that he retained a material shareholding at the time or received a calculable portion of the sale.

Claims that the acquisition made him a billionaire or produced a specified personal fortune are unsupported by the consulted evidence.

## 2013–2019: Visa difficulties and security-policy interventions

### U.S. visas

Reports state that Shamir was unable to obtain a U.S. visa in time to attend the 2019 RSA Conference, where he ordinarily appeared on the cryptographers’ panel. Conference reporting described this as particularly incongruous because he was the “S” in RSA.

A Hebrew secondary source states that he also encountered a U.S. visa refusal or failure in 2013. The precise administrative grounds in either episode were not made public.

There is no evidence in the consulted sources that the visa problem resulted from a criminal conviction, espionage finding, or formal security accusation. Speculation to that effect is unverified.

### NSA, privacy, and key escrow

After the Snowden disclosures, Shamir publicly described the U.S. government as an “advanced persistent threat” in the context of data security. He warned against centralized cloud services and rejected government key-escrow proposals. He argued that calling privileged access a “front door” instead of a back door did not alter the security problem.

These statements show skepticism toward generalized state or corporate access to encrypted data.

### Apple–FBI dispute

At the 2016 RSA Conference, Shamir criticized Apple’s handling of the dispute over the iPhone used by a perpetrator of the San Bernardino attack. He argued that Apple had selected a strategically poor case in which to resist the FBI and should have complied there while choosing a less emotionally and legally unfavorable case to contest broader access demands.

This did not amount to endorsement of universal backdoors. His position distinguished the litigation strategy of that case from his opposition to systemic key escrow.

## 2015–2019: Academy elections

- **Foreign associate, French Academy of Sciences:** elected November 17, 2015.
- **Foreign Member of the Royal Society:** elected 2018.
- **Member, American Philosophical Society:** reported in 2019.

The Royal Society’s biographical statement identifies him as a founder of modern cryptography and lists his contributions to RSA, secret sharing, identity-based cryptography, zero-knowledge identification, ring signatures, differential cryptanalysis, and side-channel attacks.

## 2017: Japan Prize

Shamir received the **2017 Japan Prize** in Electronics, Information and Communication for “contribution to information security through pioneering research on cryptography.”

The prize for the field carried **50 million Japanese yen**. This was the prize allocation for the field; the consulted official source does not establish taxes, subsequent disposition, or Shamir’s total wealth.

## 2018–2023: Drones, scanners, COVID exposure notification, and quantum caution

Shamir co-authored applied-security work showing:

- how encrypted drone video traffic could leak whether a particular object or location was being filmed;
- how light directed at a flatbed scanner could provide a route for injecting data into an isolated organization;
- privacy-preserving methods for automated COVID-19 exposure notification.

He remained skeptical of claims that practical, cryptographically decisive quantum computers were imminent. At a 2023 discussion he reportedly suggested that quantum computers capable of breaking major public-key systems could remain decades away.

Such forecasts are expert judgments, not proven technical results. They have been disputed by those expecting faster progress, and Shamir’s estimate should not be treated as a guarantee that present RSA deployments are indefinitely safe.

## 2024: Wolf Prize

Shamir and mathematician Noga Alon shared the **2024 Wolf Prize in Mathematics**, with Shamir cited for fundamental contributions to mathematical cryptography.

The Wolf Foundation emphasized that his work helped transform cryptography into a mathematically grounded scientific discipline.

## 2024–2026: Continuing research

Weizmann’s publication portal records continuing collaborative research, including:

- privacy-preserving and verifiable screening of DNA-synthesis orders;
- cryptographic protocols involving secure oblivious exponentiation;
- attacks on Feistel structures;
- error-resilient geometric or space-partitioning methods;
- “Deep Neural Cryptography,” scheduled in the EUROCRYPT 2026 proceedings.

This record contradicts any suggestion that Shamir ceased research after becoming emeritus.

At the March 2026 RSAC Conference, he described agentic artificial intelligence as involving “very clever idiots”: systems capable of impressive behavior but vulnerable to manipulation and unsafe when entrusted with extensive permissions. This was criticism of current reliability and security, not opposition to all AI research.

---

## Companies, Institutions, Technologies, Projects, and Financial Interests

### RSA Data Security / RSA Security

- **Founded:** 1982.
- **Founders:** Rivest, Shamir, and Adleman.
- **Principal asset:** exclusive license from MIT to the RSA patent.
- **Early management:** Adleman initially served as president; later accounts say the academics were ineffective company managers.
- **Commercial leadership:** James Bidzos joined in the 1980s and built the firm.
- **1996 transaction:** acquired by Security Dynamics.
- **Later history:** became RSA Security and passed through further corporate ownership.

Shamir’s founding shareholding is documented in general terms. Exact holdings, dilution, dividends, sale proceeds, and taxes are not public in the consulted record.

### News Datacom / NDS

- **Organized:** 1987–1988.
- **Participants:** News Corporation, Yeda/Weizmann, and other investors.
- **Initial News Corporation investment:** reportedly about US$5 million.
- **Technology:** Fiat–Shamir-based authentication and later smart-card/conditional-access technology.
- **Shamir’s role:** foundational inventor, consultant, and—in some accounts—co-founder.
- **Later corporate identity:** NDS.
- **Cisco acquisition:** approximately US$5 billion in 2012.
- **Later disposition:** Cisco subsequently sold the business, which became associated with Synamedia.

No reliable source establishes Shamir’s personal proceeds from the Cisco transaction.

### Yeda Research and Development

Yeda is the Weizmann Institute’s commercialization arm. It patented and licensed technology associated with Shamir and his colleagues, including the Fiat–Shamir work used by News Datacom.

The precise division of licensing income among Yeda, Weizmann, Shamir, and co-inventors was not found.

### Patents

The consulted patent index attributes multiple patent filings to persons named Adi Shamir, but name disambiguation is necessary. The patents most securely connected to this Shamir include:

1. **U.S. Patent 4,405,829, “Cryptographic Communications System and Method.”**
   - Inventors: Ronald Rivest, Adi Shamir, Leonard Adleman.
   - Filed: December 14, 1977.
   - Granted: September 20, 1983.
   - Assignee: MIT.
   - Subject: RSA cryptography.

2. Patent families associated with the Fiat–Shamir identification/authentication work and commercialized through Yeda and News Datacom are reported in contemporaneous trade literature, although a complete verified family-level patent table was not reconstructed here.

A broad automated patent list should not be treated as conclusive because “Adi Shamir” citations often identify him as an author of prior art rather than as the inventor.

### Wealth and property

No reliable net-worth estimate, property portfolio, trust structure, investment company, offshore entity, securities filing, or financial disclosure for Shamir was found.

Documented potential sources of wealth include:

- academic salary;
- prize money;
- patent-related royalties;
- RSA Data Security founder equity;
- consulting;
- commercial licensing through Yeda;
- possible participation in News Datacom/NDS.

The amounts personally received remain unresolved.

---

## Political, Religious, Philosophical, and Intellectual Development

### Political activity

No party membership, candidacy, government office, diplomatic appointment, campaign-finance activity, or sustained ideological organization is documented.

His public-policy interventions were technical:

- opposition to systemic government-access mechanisms and key escrow;
- concern about cloud surveillance;
- commentary on the Apple–FBI litigation;
- advice concerning biometric databases;
- warnings about hardware sabotage, side channels, and AI agents.

These positions do not fit neatly into a single civil-libertarian or security-state category. He opposed generalized backdoors but thought Apple chose the wrong test case against the FBI.

### Religion

No reliable source consulted documents Shamir’s religious beliefs, observance, denomination, conversion, atheism, or theological writing.

Receipt of the Vatican’s Pius XI Gold Medal was a scientific honor and is not evidence of Catholic affiliation.

### Intellectual orientation

His published work shows recurring methodological commitments:

- construct systems with precise mathematical security goals;
- attack those systems through overlooked structure;
- distinguish mathematical security from implementation security;
- treat cryptography as an adversarial empirical discipline as well as a theorem-driven one;
- seek simple formulations with large practical consequences.

This description is derived from his research record, not from a personal philosophical manifesto.

---

## Important Relationships and Networks

### Ronald L. Rivest

Shamir’s central early collaborator. Rivest and Shamir generated candidate public-key systems at MIT, while Adleman attacked them. They later co-founded RSA Data Security and reunited for ring signatures and other work.

### Leonard M. Adleman

RSA collaborator, adversarial tester of early candidate constructions, co-founder of RSA Data Security, and co-recipient of the Turing Award. Adleman’s oral history is the fullest public participant account of RSA’s creation.

### Zohar Manna

Doctoral adviser at Weizmann. Manna shaped Shamir’s formation in rigorous theoretical computer science and recursive definitions.

### Whitfield Diffie and Martin Hellman

Their 1976 public-key paper posed the central problem that led directly to the MIT search for RSA. They were intellectual predecessors, later professional peers, and recurring participants with Shamir in public discussions of cryptographic policy.

### Ralph Merkle

An intellectual predecessor in public-key cryptography and co-author of the knapsack cryptosystem that Shamir broke. The relationship was primarily scientific rather than documented as personally hostile.

### Eli Biham

Student and major collaborator. Their work on differential cryptanalysis and differential fault analysis became central to public cryptanalysis.

### Amos Fiat and Uriel Feige

Students/collaborators in identification, signatures, and zero-knowledge protocols. Their names form the Fiat–Shamir and Feige–Fiat–Shamir terminology.

### Moni Naor

Collaborator on visual cryptography.

### Eran Tromer and Daniel Genkin

Collaborators on specialized factoring hardware, cache or physical leakage, and acoustic cryptanalysis.

### Itai Dinur

Collaborator on cube attacks and later symmetric-cryptanalysis work.

### Yael Tauman

Co-author with Rivest and Shamir of the ring-signature paper.

### Rupert Murdoch, Yeda, and News Corporation

Commercial relationship through News Datacom. Murdoch’s company financed a venture using Shamir-associated cryptographic inventions. No evidence indicates a close private friendship or political alliance.

### James Bidzos

Business executive who commercialized RSA Data Security after the academic founders’ early efforts. Bidzos’s oral history places Shamir in both RSA and News Datacom’s late-1980s commercial network.

### Institutional network

Shamir’s major institutions include:

- Tel Aviv University;
- Weizmann Institute of Science;
- University of Warwick;
- MIT;
- École Normale Supérieure;
- French Academy of Sciences;
- Israel Academy of Sciences and Humanities;
- U.S. National Academy of Sciences;
- Royal Society;
- American Philosophical Society;
- International Association for Cryptologic Research;
- ACM;
- IEEE;
- RSAC Conference.

No documented personal enemies were found. Scientific targets such as Merkle–Hellman, DES, GSM-related ciphers, RFID systems, and RSA implementations should not be converted into personal rivalries without evidence.

---

## Controversies, Allegations, Investigations, and Contested Questions

## 1. News Datacom tax case

**Status: documented investigation; company-level financial settlement; no located personal charge or finding against Shamir.**

Shamir was questioned during the 1996 Israeli investigation into News Datacom’s tax affairs. Early reporting used ambiguous language suggesting that several figures had been “held”; later reporting clarified that Shamir was interrogated but not arrested.

The company eventually paid a NIS 15 million forfeiture. The sources consulted do not show that Shamir was indicted, convicted, fined individually, or found to have evaded taxes.

## 2. Who “invented RSA”?

**Status: independently repeated invention; popular priority dispute often oversimplified.**

The public RSA construction was developed independently by Rivest, Shamir, and Adleman in 1977 and published in 1978.

GCHQ later disclosed that:

- James Ellis conceived “non-secret encryption” around 1970;
- Clifford Cocks found a mathematically similar encryption construction in 1973;
- Malcolm Williamson independently found a Diffie–Hellman-like key-exchange method.

The GCHQ work remained classified and did not influence the MIT team according to the available record.

A careful priority statement is:

- Cocks discovered the underlying RSA-like encryption mathematics earlier in classified work.
- Rivest, Shamir, and Adleman independently produced the public construction, developed its signature implications, published it, analyzed it, patented it, and enabled its widespread scientific and commercial adoption.

Statements that “Shamir stole RSA from GCHQ” are unsupported. Statements that no one had discovered related mathematics before the MIT team are also false.

## 3. Authorship credit within RSA

**Status: participant account, not an accusation of misconduct.**

Adleman credited Rivest with the final decisive construction and initially wanted his own name removed. Rivest insisted the work was collaborative. Shamir supported placing Rivest first.

There is no documented claim by any of the three that Shamir fraudulently claimed authorship. The story concerns collective credit after a collaborative search.

## 4. Patenting fundamental cryptography

**Status: policy controversy, not legal wrongdoing.**

The RSA patent became part of the wider debate over software and algorithm patents. Critics argued that fundamental mathematical methods should not be privately controlled and noted that Cocks had independently found equivalent mathematics earlier. Defenders argued that RSA represented a practical engineered invention worthy of patent protection.

MIT was the assignee; RSA Data Security held an exclusive commercial license. No court finding of fraud in obtaining the patent was found.

## 5. Cryptographic export controls

**Status: documented policy conflict; no located prosecution of Shamir.**

The NSA and U.S. government treated strong cryptography as strategically sensitive and subject to export restrictions. Warnings surrounding the RSA publication contributed to the “crypto wars.”

No evidence establishes that Shamir acted as an intelligence agent, was charged with illegal export, or was convicted of an export offense.

## 6. NSA or Israeli intelligence connections

**Status: rumor or unsupported inference.**

Internet discussions sometimes infer intelligence connections from Shamir’s nationality, cryptographic expertise, military reserve service, or work on surveillance-resistant and surveillance-relevant technologies.

One Hebrew secondary source reports that he performed reserve service in **Lotem**, the Israeli military’s telecommunications and information-technology division. The precise dates and duties were not independently documented.

No source consulted establishes that he worked for Mossad, Shin Bet, Unit 8200, the NSA, GCHQ, or another intelligence service. Scientific contact with security agencies or research relevant to intelligence work is not proof of agency employment.

## 7. NDS piracy and corporate controversies

**Status: company controversies; personal involvement by Shamir not established.**

NDS later became embroiled in disputes concerning pay-TV piracy, smart-card security, competition, and allegations involving rivals. Shamir’s technology helped establish the company, but the consulted evidence does not connect him personally to later alleged hacking, piracy, market misconduct, or management decisions.

He should not be assigned responsibility merely because the company descended from a venture based on his research.

## 8. Differential cryptanalysis priority

**Status: corrected historical attribution.**

Biham and Shamir are properly credited with independent public discovery and systematic publication. IBM and NSA personnel had prior nonpublic knowledge. There is no evidence that Biham and Shamir misrepresented access to classified sources.

## 9. “Breaking RSA”

**Status: recurring media exaggeration.**

Shamir has repeatedly studied ways to attack RSA implementations and accelerate factoring. TWINKLE, TWIRL, fault analysis, cache analysis, and acoustic cryptanalysis are sometimes reported as if Shamir “broke RSA.”

The better distinction is:

- some attacks break weak parameters;
- some break faulty or leaking implementations;
- some estimate specialized factoring costs;
- none of the cited projects provides a general efficient classical algorithm for factoring arbitrary properly generated modern RSA moduli.

## 10. Quantum-computing forecasts

**Status: expert forecast, disputed and unresolved.**

Shamir’s skepticism about near-term cryptographically relevant quantum computers has attracted attention. The fact that large fault-tolerant systems do not yet exist supports caution about imminent claims, but no one can document a 30-year future timeline. His view is an informed prediction, not an established result.

## 11. AI criticism

**Status: documented public criticism, not scandal.**

In 2017 Shamir expressed doubt that then-current AI could reliably detect rare novel attacks. In 2026 he called AI agents “very clever idiots,” stressing the mismatch between capability and reliability.

These statements may prove prescient or overly conservative. They are technical judgments, not accusations of fraud against AI researchers.

## 12. Absence of other substantiated misconduct

The dedicated adversarial search conducted for this dossier found no credible evidence, through September 2, 2026, that Shamir had been:

- convicted of a crime;
- formally charged with fraud or corruption;
- found liable in a personal civil fraud judgment;
- accused by a named victim of sexual or workplace abuse;
- dismissed for misconduct;
- implicated in money laundering;
- identified in a substantiated espionage case;
- sanctioned for research fabrication or plagiarism.

This is a finding about the consulted public record, not proof that no unreported dispute ever existed.

---

## Myths, Legends, Rumors, and Propaganda

### “The S in RSA”

**Story:** Shamir is popularly reduced to being “the S in RSA.”

**Origin and circulation:** Technology journalism, conference introductions, institutional biographies, and RSA corporate publicity.

**Evidence:** Literally correct: RSA takes the initials of Rivest, Shamir, and Adleman.

**Distortion:** It obscures Shamir’s independent contributions to secret sharing, identity-based cryptography, zero knowledge, cryptanalysis, complexity theory, visual cryptography, and side-channel attacks.

**Effect:** It made him unusually recognizable for a theoretical computer scientist but narrowed popular understanding of his career.

### The solitary-eureka RSA myth

**Story:** Three mathematicians suddenly invented internet security in a single night.

**Evidence:** Rivest reached the successful construction during or after a long series of failed candidates, followed by a late-night call and handwritten draft. The work nevertheless depended on months of group effort and on Diffie and Hellman’s public-key framework.

**Effect:** The Passover-night anecdote became an invention legend emphasizing inspiration over cumulative collaborative work.

### “RSA was stolen from British intelligence”

**Story:** The MIT group took the construction from GCHQ.

**Appearance:** Popular histories following the 1997 declassification, anti-patent commentary, and online discussions.

**Evidence against:** The GCHQ result was classified, and no evidence has emerged that the MIT team had access to it.

**Underlying truth:** Cocks discovered equivalent core mathematics earlier.

**Effect:** The disclosure complicated priority narratives and supplied critics of the RSA patent with a powerful historical example.

### “Shamir can hear your encryption key”

**Story:** Shamir showed that anyone can recover a computer’s secrets merely by listening.

**Underlying evidence:** Acoustic leakage from particular implementations can disclose key-dependent information, and Genkin, Shamir, and Tromer demonstrated key recovery under controlled conditions.

**Against the exaggerated version:** The attack was not universal and required vulnerable implementations, interaction or chosen ciphertexts, suitable recordings, and signal analysis.

### “He broke RSA”

**Story:** Headlines periodically imply that Shamir defeated his own cryptosystem.

**Underlying evidence:** He helped develop implementation attacks and factoring hardware proposals.

**Against:** No general classical break of sound, properly sized RSA was demonstrated.

### “Visa denial proves a secret security case”

**Story:** Shamir’s inability to obtain U.S. entry documents proves that he was suspected of espionage or wrongdoing.

**Evidence:** The visa difficulty is documented; the reason is not publicly established.

**Assessment:** **Unverified speculation.** Administrative delay, vetting, or an undisclosed issue are all possible. No criminal or intelligence finding was located.

### Name-confusion narratives

Online material occasionally conflates Adi Shamir with unrelated people named Shamir, including polemicist Israel Shamir or political figures from the family of Yitzhak Shamir.

No family connection among these people was established. Claims transferred through surname confusion should be rejected unless separately documented.

---

## Awards, Honors, Memberships, and Appointments

Dates sometimes differ by one year between announcement and presentation.

- **1983:** Erdős Prize, Israel Mathematical Union.
- **1986:** IEEE W.R.G. Baker Award.
- **1987:** Weizmann Prize, reported in biographical compilations.
- **1990:** UAP Scientific Prize, France.
- **1992:** Pius XI Gold Medal, Pontifical Academy of Sciences.
- **1996/1997:** ACM Paris Kanellakis Theory and Practice Award, jointly for RSA.
- **1998:** Elected to the Israel Academy of Sciences and Humanities.
- **2000:** IEEE Koji Kobayashi Computers and Communications Award.
- **2002:** ACM A.M. Turing Award with Rivest and Adleman.
- **2003:** Honorary doctorate, École Normale Supérieure.
- **2004:** Fellow, International Association for Cryptologic Research.
- **2005:** Foreign associate, U.S. National Academy of Sciences.
- **2006 onward:** Invited professor, École Normale Supérieure.
- **2008:** Israel Prize in computer science.
- **2008:** Okawa Prize.
- **2008:** NEC C&C Prize.
- **2009:** Honorary doctorate, University of Waterloo.
- **2012:** Grande Médaille, French Academy of Sciences.
- **2015:** Foreign associate, French Academy of Sciences.
- **2017:** Japan Prize.
- **2018:** Foreign Member of the Royal Society.
- **2019:** Member, American Philosophical Society.
- **2024:** Wolf Prize in Mathematics, shared with Noga Alon.
- **2025:** A secondary source reports receipt of the Levchin Prize for Real-World Cryptography; this was not independently confirmed from the award organization in the present search.

Additional institutional memberships reported by the Royal Society include Academia Europaea.

---

## Health, Accidents, and Personal Crises

No reliable source consulted documents:

- a major illness;
- addiction;
- psychiatric hospitalization;
- suicide attempt;
- serious accident;
- disabling injury;
- prolonged medical leave.

No cause-of-death section applies because Shamir is living.

Absence of public documentation should not be interpreted as evidence of perfect health.

---

## Works by Adi Shamir

### Authorship notes

Shamir’s output consists primarily of technical papers rather than memoirs, political works, or general-audience books. DBLP and Weizmann together index roughly 180 research outputs through 2026. The following is a substantial chronological bibliography of the principal works and research lines; DBLP remains the most practical complete, updateable publication register.

No ghostwritten books, diaries, correspondence editions, autobiography, collected letters, artworks, films, or musical recordings under his name were identified.

### Dissertation and book

- **1976/1977.** *The Fixedpoints of Recursive Definitions.* Doctoral dissertation, Weizmann Institute of Science. Manuscript dated 1976; doctorate awarded 1977.
- **1993.** Eli Biham and Adi Shamir. *Differential Cryptanalysis of the Data Encryption Standard.* New York: Springer. Genuine co-authored monograph.

### Selected papers, chronological

- **1977.** Adi Shamir and William W. Wadge. “Data Types as Objects.” *ICALP 1977*, pp. 465–479.
- **1978.** Ronald L. Rivest, Adi Shamir, and Leonard M. Adleman. “A Method for Obtaining Digital Signatures and Public-Key Cryptosystems.” *Communications of the ACM* 21(2): 120–126.
- **1979.** Adi Shamir. “How to Share a Secret.” *Communications of the ACM* 22(11): 612–613.
- **1979.** Adi Shamir. Work on a linear-time algorithm for 2-satisfiability, generally cited under “A Linear Time Algorithm for Deciding 2-Satisfiability.”
- **1982.** Adi Shamir. “A Polynomial Time Algorithm for Breaking the Basic Merkle–Hellman Cryptosystem.” *FOCS 1982*.
- **1984.** Adi Shamir. “Identity-Based Cryptosystems and Signature Schemes.” *CRYPTO 1984*, pp. 47–53.
- **1986.** Amos Fiat and Adi Shamir. “How to Prove Yourself: Practical Solutions to Identification and Signature Problems.” *CRYPTO 1986*.
- **1988.** Uriel Feige, Amos Fiat, and Adi Shamir. “Zero-Knowledge Proofs of Identity.” *Journal of Cryptology* 1(2): 77–94.
- **1989.** Adi Shamir. “An Efficient Identification Scheme Based on Permuted Kernels.” *CRYPTO 1989*.
- **1990.** Eli Biham and Adi Shamir. Early conference publications introducing differential cryptanalysis of DES-like cryptosystems.
- **1991.** Eli Biham and Adi Shamir. “Differential Cryptanalysis of DES-like Cryptosystems.” *Journal of Cryptology* 4(1): 3–72.
- **1992.** Adi Shamir. “IP = PSPACE.” *Journal of the ACM* 39(4): 869–877.
- **1994.** Moni Naor and Adi Shamir. “Visual Cryptography.” *EUROCRYPT 1994*.
- **1996/1997.** Eli Biham and Adi Shamir. “Differential Fault Analysis of Secret Key Cryptosystems.”
- **1998.** Alex Biryukov and Adi Shamir. Work on structural cryptanalysis and time-memory tradeoffs.
- **1999.** Adi Shamir. “Factoring Large Numbers with the TWINKLE Device.”
- **2000.** Alex Biryukov, Adi Shamir, and David Wagner. “Real Time Cryptanalysis of A5/1 on a PC.” Work on GSM encryption.
- **2001.** Ronald L. Rivest, Adi Shamir, and Yael Tauman. “How to Leak a Secret.” *ASIACRYPT 2001*. Introduced ring signatures.
- **2001.** Adi Shamir. “New Directions in Cryptography”/“New Directions in Croptography.” CHES proceedings contain the latter typographical rendering.
- **2001.** Adi Shamir and Boaz Tsaban. “Guaranteeing the Diversity of Number Generators.”
- **2002.** Alexander Klimov, Anton Mityagin, and Adi Shamir. “Analysis of Neural Cryptography.” *ASIACRYPT 2002*.
- **2003.** Adi Shamir and Eran Tromer. “Factoring Large Numbers with the TWIRL Device.” *CRYPTO 2003*.
- **2004.** Daniel Page and Adi Shamir-related work on cache behavior and implementation attacks appears in the broader side-channel research program.
- **2005.** Eran Tromer, Dag Arne Osvik, and Adi Shamir. “Efficient Cache Attacks on AES, and Countermeasures.” Later published in the *Journal of Cryptology*.
- **2007.** Eli Biham, Yaniv Carmeli, and Adi Shamir. “Bug Attacks.”
- **2008.** Itai Dinur and Adi Shamir. “Cube Attacks on Tweakable Black Box Polynomials.”
- **2008.** Jonathan J. Hoch and Adi Shamir. “On the Strength of the Concatenated Hash Combiner When All the Hash Functions Are Weak.”
- **2009.** Itai Dinur and Adi Shamir. “Cube Attacks on Tweakable Black Box Polynomials.” Formal conference publication.
- **2010.** Orr Dunkelman, Nathan Keller, and Adi Shamir. “Improved Single-Key Attacks on 8-Round AES.”
- **2010.** Charles Bouillaguet, Chen-Mou Cheng, Tung Chou, Ruben Niederhagen, Adi Shamir, and Bo-Yin Yang. “Fast Exhaustive Search for Polynomial Systems in \(F_2\).”
- **2013/2014.** Daniel Genkin, Adi Shamir, and Eran Tromer. “RSA Key Extraction via Low-Bandwidth Acoustic Cryptanalysis.”
- **2014.** Daniel Genkin, Adi Shamir, and Eran Tromer. “Acoustic Cryptanalysis.” Subsequent journal version.
- **2015.** Eyal Ronen and Adi Shamir. “Critical Review of Imperfect Forward Secrecy: How Practical Are Common Attacks on Weak Cryptographic Parameters?”
- **2017.** Ben Nassi, Adi Shamir, and Yuval Elovici. “Oops!...I Think I Scanned a Malware.”
- **2018.** Ben Nassi, Raz Ben-Netanel, Adi Shamir, and Yuval Elovici. “Game of Drones—Detecting Streamed POI from Encrypted FPV Channel.”
- **2019.** Shamir participated in continuing symmetric-cryptanalysis and side-channel research recorded in DBLP and Weizmann’s institutional bibliography.
- **2020.** Ronald L. Rivest, Adi Shamir, Emily Shen, Ari Trachtenberg, Mayank Varia, and Daniel J. Weitzner. “Privacy-Preserving Automated Exposure Notification.”
- **2023.** Odelia Melamed, Gilad Yehudai, and Adi Shamir. Research on neural networks and cryptographic or computational structure.
- **2024.** Carsten Baum et al., including Ronald Rivest and Adi Shamir. “Efficient Maliciously Secure Oblivious Exponentiations.” IACR ePrint 2024/1613.
- **2024.** Carsten Baum et al., including Adi Shamir. “A System Capable of Verifiably and Privately Screening Global DNA Synthesis.” Preprint.
- **2025.** Adi Shamir and Eran Tromer. “TWIRL.” Entry in the third edition of the *Encyclopedia of Cryptography, Security and Privacy*.
- **2026.** Daniël Gerault, Alexander Hambitzer, Eyal Ronen, and Adi Shamir. “Deep Neural Cryptography.” *EUROCRYPT 2026*.
- **2026.** Orr Dunkelman, Oded Geyzel, Chaya Keller, Nathan Keller, Eyal Ronen, Adi Shamir, and Ran J. Tessler. “Error Resilient Space Partitioning.” *Discrete & Computational Geometry*.
- **2026.** Itai Dinur, Orr Dunkelman, Nathan Keller, David Ross, and Adi Shamir. “New Attacks on Feistel Structures with Improved Memory Complexities.” *Journal of Cryptology*.

### Speeches, lectures, and interviews

- **2002/2003:** ACM Turing Award lecture, commonly titled “Cryptography: State of the Science.”
- **2017:** Japan Prize lecture, “Cryptography: Past, Present, Future.”
- **Recurring:** RSAC Cryptographers’ Panel appearances, including recorded sessions in 2017, 2018, 2020–2026.
- **2023:** RSAC discussion on migration to post-quantum schemes.
- **2026:** RSAC Cryptographers’ Panel, including comments on agentic AI.

Shamir is described in Adleman’s oral history as reluctant to grant personal interviews. Consequently, the archival record contains fewer first-person biographical sources than his prominence might suggest.

---

## Books and Major Works About Shamir and His Field

There is no definitive full-length scholarly biography devoted solely to Shamir in the sources located. Important contextual works include:

- Steven Levy, *Crypto: How the Code Rebels Beat the Government—Saving Privacy in the Digital Age* (2001). Narrative history of public-key cryptography and the crypto-policy conflict; includes RSA’s development and commercialization.
- Simon Singh, *The Code Book* (1999). Popular history including public-key cryptography, RSA, and the later GCHQ disclosure.
- Whitfield Diffie and Susan Landau, *Privacy on the Line*. Policy and technical context for public cryptography.
- David Kahn, *The Codebreakers*, revised edition. Broad historical background rather than a Shamir biography.
- Eli Biham and Adi Shamir, *Differential Cryptanalysis of the Data Encryption Standard* (1993). Primary technical work and historical evidence for their research program.
- ACM Turing Award biographical and oral-history materials concerning Shamir, Rivest, Adleman, Diffie, Hellman, and Goldwasser.
- Ronald Rivest’s IEEE/ACM oral history. Participant account of RSA’s development.
- Leonard Adleman’s ACM oral history. The most detailed narrative of the collaboration and naming of RSA.
- James Bidzos’s Charles Babbage Institute oral history. Commercial history of RSA Data Security and News Datacom.
- “Gene Genie,” *Wired* (1995). Long-form profile of Adleman containing substantial RSA history.
- “The Open Secret,” *Wired* (1999). Long-form account of the classified British prehistory of public-key cryptography.
- Paul Van Oorschot, research on the history and societal impact of public-key cryptography. Useful for separating public, classified, technical, and commercial priority.
- Japan Prize Foundation’s 2017 laureate dossier. Concise institutional biography and technical assessment.
- Wolf Foundation’s 2024 laureate profile. Institutional retrospective of Shamir’s mathematical contributions.
- Royal Society’s Foreign Member profile. Authoritative professional summary.
- Weizmann Institute’s institutional research profile and publication database.
- DBLP’s Adi Shamir bibliography.

Hostile book-length biographies of Shamir were not located. Critical treatment is directed primarily at cryptographic patents, corporate commercialization, government policy, technical forecasts, or associated companies rather than at his private life.

---

## Films, Documentaries, Interviews, and Archival Material

### Recorded lectures and panels

- ACM recording of Shamir’s Turing Award lecture.
- Japan Prize lecture, “Cryptography: Past, Present, Future.”
- RSAC Cryptographers’ Panel archive, with numerous appearances by Shamir.
- Turing Centenary Celebration materials.
- Interviews and historical recordings featuring Rivest and Adleman, which discuss Shamir and RSA.
- Heidelberg Laureate Forum portrait/interview of Leonard Adleman, containing a detailed account of the RSA collaboration.

### Archival and documentary collections

- ACM A.M. Turing Award laureate archive.
- ACM oral-history transcripts for Adleman, Rivest, Diffie, and other cryptographers.
- Charles Babbage Institute oral history of James Bidzos.
- MIT institutional news archive.
- Weizmann Institute faculty and research-output archives.
- GCHQ biographical archive on James Ellis and the classified origin of public-key cryptography.
- NSA historical profile of Ellis, Cocks, and Williamson.
- U.S. Patent and Trademark Office record for the RSA patent.
- French Academy of Sciences membership and medal records.
- Japan Prize Foundation laureate archive.
- Wolf Foundation laureate archive.
- Royal Society fellowship archive.
- Contemporary Israeli high-technology reports on News Datacom.
- Contemporary international newspaper coverage of the 1996 News Datacom tax investigation.

No authorized theatrical biopic or feature-length documentary devoted solely to Shamir was located.

---

## Present Status and Later Life

Shamir is alive and professionally active as of September 2, 2026.

He is identified by Weizmann as an emeritus full professor but continues to publish with international collaborators. His recent work extends beyond classical cryptography into:

- neural cryptography;
- synthetic-biology screening;
- privacy-preserving computation;
- attacks on block-cipher structures;
- computational geometry;
- AI-agent security.

His public role combines research, award lectures, and recurring participation in the RSAC Cryptographers’ Panel.

No retirement date marking a complete withdrawal from research has been documented.

---

## Reputation and Legacy

### Cryptography

Shamir’s legacy rests on unusually broad work across both construction and attack:

- RSA made public-key encryption and digital signatures practical.
- Shamir secret sharing established threshold protection of information.
- Identity-based cryptography introduced a major key-management paradigm.
- Fiat–Shamir protocols connected zero knowledge, identification, and signatures.
- Ring signatures enabled ad hoc anonymous authentication.
- Differential cryptanalysis transformed block-cipher analysis.
- Fault, cache, acoustic, and other side-channel work shifted attention from mathematical primitives to real machines.

### Theoretical computer science

The theorem IP = PSPACE is independent evidence that his importance is not confined to applied cryptography. His early work on semantics, satisfiability, and algorithms also reflects a general theoretical career.

### Commercial and institutional influence

RSA and News Datacom/NDS translated academic cryptography into:

- secure network communication;
- digital signatures;
- authentication products;
- pay-television conditional access;
- commercial security companies;
- later internet trust infrastructure.

The financial value created was enormous, but the portion personally captured by Shamir cannot be reconstructed from the public evidence consulted.

### Historical reinterpretation

His reputation has undergone several refinements:

1. **Initial public narrative:** one of three inventors of the first practical public-key cryptosystem.
2. **After GCHQ disclosure:** independent public inventor and commercial/scientific disseminator of a construction whose core encryption mathematics Cocks had earlier found in secret.
3. **After disclosure of IBM/NSA differential knowledge:** independent public discoverer of a technique already known in classified or corporate settings.
4. **Later assessment:** not merely a co-inventor of RSA but a central architect of cryptography’s development as a mature mathematical and adversarial discipline.

No posthumous cult applies. During his lifetime, “the S in RSA” functions as a symbolic identity linking a person’s surname to the infrastructure of digital security.

---

## Atlas Connections

Only documented or directly supported intersections with the supplied atlas roster are included. Mere contemporaneity, common nationality, or appearance in the same broad field is excluded.

### Ronald Linn Rivest

- **Label:** Documented fact.
- **Nature:** MIT colleague; RSA co-inventor; co-founder of RSA Data Security; co-author on ring signatures and later privacy-preserving research; co-recipient of the 2002 Turing Award.
- **Dates and places:** MIT, Cambridge, Massachusetts, 1977–1980; continuing collaboration through at least 2024.

### Leonard Max Adleman

- **Label:** Documented fact.
- **Nature:** MIT colleague; adversarial tester of early candidate public-key systems; RSA co-inventor; co-founder of RSA Data Security; co-recipient of the 2002 Turing Award.
- **Dates and places:** MIT, Cambridge, Massachusetts, principally 1977–1980; company founding documents signed in Los Angeles in 1982 according to Adleman’s account.

### Bailey Whitfield Diffie

- **Label:** Documented intellectual influence and professional association.
- **Nature:** Diffie and Hellman’s public-key work directly motivated the RSA search. Diffie later appeared with Shamir on cryptographic panels and in the policy debates over encryption.
- **Dates and places:** Intellectual influence beginning with the 1976 Diffie–Hellman publication; later conference contacts, including RSAC events in the United States.

### Martin Edward Hellman

- **Label:** Documented intellectual influence and professional association.
- **Nature:** Co-author of the 1976 public-key paper that posed the construction problem addressed by RSA; co-inventor with Ralph Merkle of the knapsack cryptosystem Shamir broke.
- **Dates and places:** Intellectual connection from 1976; cryptanalytic connection from Shamir’s 1982 attack.

### Ralph Charles Merkle

- **Label:** Documented intellectual and cryptanalytic connection.
- **Nature:** Public-key pioneer; co-creator of the Merkle–Hellman knapsack cryptosystem; Shamir published a polynomial-time attack against its basic form in 1982.
- **Dates and places:** Scientific-literature connection, 1970s–1982; no specific private meeting established.

### Alan Mathison Turing

- **Label:** Documented institutional-symbolic connection, not a personal meeting.
- **Nature:** Shamir received the 2002 ACM award named for Turing. Turing died before Shamir was two years old; no personal connection existed.
- **Dates and places:** Award announced for 2002 and presented by ACM.

### Claude Elwood Shannon

- **Label:** Documented disciplinary influence at the field level; no personal relationship established.
- **Nature:** Shannon’s mathematical theory of secrecy formed part of the intellectual foundation of modern cryptography in which Shamir worked. No consulted source records a meeting or correspondence.
- **Dates and places:** Indirect influence through the cryptographic literature.

### Vinton Gray Cerf and Robert Elliot Kahn

- **Label:** Documented shared professional scene only.
- **Nature:** They appear with Shamir in ACM Turing laureate programs and belong to the networking infrastructure whose security RSA helped enable. No substantive collaboration or direct personal relationship was established.
- **Dates and places:** ACM Turing-centenary and laureate institutional settings.

### Yoshua Bengio and Geoffrey Everest Hinton

- **Label:** Documented shared ACM laureate network; no direct collaboration established.
- **Nature:** Fellow Turing laureates in later years. Shamir’s recent neural-cryptography research creates a topical overlap, but no source consulted documents a personal or research connection.
- **Assessment:** Not counted as a substantive life connection.

### Other roster members

No adequately sourced personal intersection was found with the overwhelming majority of the atlas roster. In particular, no evidence supports a personal relationship with Albert Einstein, David Ben-Gurion, Golda Meir, Benjamin Netanyahu, Sam Altman, Elon Musk, Bill Gates, Nick Szabo, Harold Finney, Philip Zimmermann, Alan Turing, John von Neumann, Norbert Wiener, or Claude Shannon beyond indirect historical, institutional, or disciplinary association where noted. Absence of a documented connection is the finding.

---

### Connection Tags

Machine-readable summary of this dossier's Atlas Connections, added 2026-09-05 during the connections-harmonization pass. Types: T1 wrote about a past figure, T2 prophecy/hyperstition, T3 discourse, T4 proximity/milieu, T5 friendship/meeting, T9 shared object or site. Sign + = this subject is the earlier/source figure, - = the later figure, blank = undirected. See the prose above (or the counterpart's own dossier) for the full claim.

- **Ronald Linn Rivest** [T5]
- **Leonard Max Adleman** [T5]
- **Bailey Whitfield Diffie** [T5]
- **Martin Edward Hellman** [T3]
- **Ralph Charles Merkle** [T3]
- **Alan Mathison Turing** [T9-]
- **Claude Elwood Shannon** [T9-]
- **Vinton Gray Cerf** [T4]
- **Robert Elliot Kahn** [T4]
- **Yoshua Bengio** [T9+]
- **Geoffrey Everest Hinton** [T9+]
- **Martin Edward Hellman** [T4] (mirrored from hellman.dossier.md)
- **Philip R. Zimmermann** [T9+] (mirrored from phil_zimmermann.dossier.md)
- **David Lee Chaum** [T1+] (mirrored from david_chaum.dossier.md)
- **Leslie Barry Lamport** [T9+] (mirrored from leslie_barry_lamport.dossier.md)
- **Bailey Whitfield Diffie** [T4] (mirrored from diffie.dossier.md)
- **Donald Ervin Knuth** [T9+] (mirrored from donald_ervin_knuth.dossier.md)
- **Max Rafailovich Levchin** [T1+] (mirrored from max_levchin.dossier.md)

## Compact Chronology

- **1952, July 6:** Born in Tel Aviv, Israel.
- **Childhood/teens:** Participates in youth science programs and Weizmann summer camps.
- **1973:** B.Sc. in mathematics, Tel Aviv University.
- **1975:** M.Sc. in computer science, Weizmann Institute.
- **1976:** Dissertation manuscript on fixed points of recursive definitions; postdoctoral period at Warwick begins.
- **1977:** Ph.D. awarded by Weizmann; moves to MIT; RSA developed with Rivest and Adleman.
- **1978:** RSA paper published; MIT instructor, then assistant professor.
- **1979:** Publishes Shamir secret sharing; linear-time 2-SAT work.
- **1980:** Returns to Weizmann as associate professor.
- **1982:** Breaks the basic Merkle–Hellman knapsack cryptosystem; co-founds RSA Data Security.
- **1983:** Erdős Prize; RSA patent granted.
- **1984:** Becomes professor at Weizmann; proposes identity-based cryptography.
- **1986–1988:** Develops Fiat–Shamir and Feige–Fiat–Shamir identification/signature protocols.
- **1987–1988:** Shamir/Weizmann technology commercialized through News Datacom.
- **Late 1980s:** Develops differential cryptanalysis with Eli Biham.
- **1990:** UAP Scientific Prize.
- **1991:** Major journal treatment of differential cryptanalysis.
- **1992:** Proves IP = PSPACE; receives Pius XI Gold Medal.
- **1993:** Publishes book on differential cryptanalysis of DES.
- **1994:** Introduces visual cryptography with Moni Naor.
- **1996:** Kanellakis Award; differential fault analysis; questioned in News Datacom tax investigation.
- **1998:** News Datacom pays NIS 15 million forfeiture; Shamir elected to Israel Academy.
- **1999:** Proposes TWINKLE factoring hardware.
- **2000:** Koji Kobayashi Award; RSA patent expires.
- **2001:** Introduces ring signatures with Rivest and Tauman.
- **2002:** Turing Award with Rivest and Adleman.
- **2003:** TWIRL paper with Tromer; ENS honorary doctorate.
- **2004:** IACR Fellow.
- **2005:** Elected foreign associate of U.S. National Academy of Sciences.
- **2006:** Invited professor at ENS; demonstrates RFID side-channel attack.
- **2008:** Israel Prize, Okawa Prize, and NEC C&C Prize; cube-attack research period.
- **2009:** Waterloo honorary doctorate; intervenes in Israeli biometric-database debate.
- **2012:** Grande Médaille of French Academy; Cisco acquires NDS.
- **2013–2014:** Acoustic RSA key-extraction research.
- **2015:** Elected foreign associate of French Academy.
- **2016:** Comments on Apple–FBI dispute.
- **2017:** Japan Prize.
- **2018:** Foreign Member of Royal Society; drone-traffic side-channel work.
- **2019:** Unable to secure timely U.S. visa for RSA Conference; American Philosophical Society membership reported.
- **2020:** Co-authors privacy-preserving exposure-notification research.
- **2023:** Warns that cryptographically decisive quantum computing may remain decades away.
- **2024:** Wolf Prize in Mathematics; research on private screening of DNA synthesis.
- **2025:** Continues RSAC participation and cryptographic publication.
- **2026:** Publishes or schedules work on neural cryptography, Feistel attacks, and error-resilient space partitioning; warns about unreliable agentic AI.
- **September 2, 2026:** Living; emeritus at Weizmann and continuing research.

## Sources

https://weizmann.elsevierpure.com/en/persons/adi-shamir/

https://www.wisdom.weizmann.ac.il/profile04/scientists/shamir-prof04.html

https://www.weizmann.ac.il/math/adi-shamir

https://amturing.acm.org/?pg=awards.html

https://ptacts.uspto.gov/ptacts/public-informations/petitions/1517535/download-documents?artifactId=XLyNR2I2YXepp4fa_4LH3A_5rJSjIlEtWsjS6ycZOiystd_nvQVT1QY

https://dblp.org/pid/s/AdiShamir.html

https://www2.cs.sfu.ca/~vaughan/teaching/431.2011-1/papers/citation.cfm.html

https://nakamotoinstitute.org/library/rsa-paper/

https://people.csail.mit.edu/rivest/pubs.html

https://news.mit.edu/1997/rsa

https://news.mit.edu/2011/rivest-unlocks-cryptographys-past-looks-toward-future

https://amturing.acm.org/pdf/AdlemanTuringTranscript.pdf

https://people.csail.mit.edu/rivest/pubs/Riv16q.pdf

https://www.wired.com/1995/08/molecular-2/

https://www.wired.com/1999/04/crypto/

https://www.gchq.gov.uk/person/james-ellis

https://www.nsa.gov/History/Cryptologic-History/Historical-Figures/Historical-Figures-View/Article/3006218/clifford-cocks-james-ellis-and-malcolm-williamson/

https://people.scs.carleton.ca/~paulv/papers/society-impact-of-pkc-v3.pdf

https://patents.justia.com/inventor/adi-shamir

https://www.invent.org/inductees/adi-shamir

https://www.rsa.com/company/rsa-cryptography/

https://wolffund.org.il/adi-shamir/

https://www.japanprize.jp/en/prize_prof_2017_shamir.html

https://www.japanprize.jp/data/foundation/2017jpnews57_e.pdf

https://www.japanprize.jp/press_releases20170202.html

https://www.academie-sciences.fr/adi-shamir

https://royalsociety.org/people/adi-shamir-13842/

https://royalsociety.org/news/2018/05/distinguished-scientists-elected-fellows-royal-society-2018/

https://awards.acm.org/award_winners/?172=

https://www.acm.org/binaries/content/assets/awards/about-the-acm-a.m.-turing-award-fact-sheet.pdf

https://turing100.acm.org/final_program/tcc_final_program.pdf

https://www.acm.org/binaries/content/assets/awards/turing50-program.pdf

https://www.rsaconference.com/experts/adi-shamir

https://www.weizmann-usa.org/news-media/in-the-news/rsa-panel-calls-nsa-access-to-encryption-keys-a-bad-idea/

https://iapp.org/news/a/cryptographers-at-rsa-users-seem-to-now-mind-giving-up-privacy

https://www.networkworld.com/article/725807/cloud-computing-former-nsa-tech-chief-i-dont-trust-the-cloud.html

https://www.pcworld.com/article/419883/apple-goofed-in-several-ways-in-fight-with-fbi-over-data-encryption-renowned-cryptographer-says.html

https://www.scworld.com/news/cryptography-experts-cast-doubt-on-ais-role-in-cybersecurity

https://www.pcworld.com/article/3099195/security-experts-at-rsac-keep-calling-ai-stupid.html

https://www.theregister.com/security/2019/03/05/adi_shamir_visa_snub/

https://www.washingtonpost.com/archive/politics/1996/10/21/israeli-tax-agents-raid-murdoch-owned-firm/31c6726a-8712-43fa-bef2-b2f81306e05d/

https://www.independent.co.uk/news/business/noheadline-5595173.html

https://en.globes.co.il/en/article-366620

https://en.globes.co.il/en/article-350338

https://www.irishtimes.com/business/report-of-israeli-warrant-for-murdoch-is-untrue-1.102412

https://www.ishitech.co.il/0688.pdf

https://conservancy.umn.edu/bitstreams/70b76bf7-b025-4938-a634-7ec2379eb24c/download

https://jr.co.il/only-in-israel/innovation-israel-aug2018.pdf

https://berlin.ccc.de/~andy/CCC/TRON/material/nds/20020415-afr.html

https://www.eetimes.com/cellphone-could-crack-rfid-tags-says-cryptographer/

https://www.heise.de/news/RFID-Passwortraten-leicht-gemacht-176334.html

https://cryptome.wikileaks.org/jya/dfa.htm

https://cryptome.wikileaks.org/jya/aes2-day1.htm

https://weizmann.elsevierpure.com/en/publications/bug-attacks/

https://arxiv.org/abs/cs/0112014

https://arxiv.org/abs/1703.07751

https://arxiv.org/abs/1801.03074

https://arxiv.org/abs/2403.14023

https://fr.timesofisrael.com/a-71-ans-israel-peut-etre-fier-des-entreprises-technologiques-quil-a-creees/

https://he.hamichlol.org.il/%D7%A2%D7%93%D7%99_%D7%A9%D7%9E%D7%99%D7%A8
