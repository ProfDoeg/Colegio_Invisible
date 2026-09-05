# David Chaum: Research Dossier

**Prepared:** 24 August 2026  
**Scope:** Reconstructable life and career of David Lee Chaum, with special attention to blind signatures, DigiCash/eCash, anonymous communications, voting systems, and the pre-Satoshi digital-money lineage.  
**Method:** Documentary synthesis emphasizing Chaum's original papers and dissertation, patents, institutional records, contemporary company material and reporting, and later technical-historical scholarship. Where the public record is silent—especially family and private finances—the absence is stated rather than filled by inference.

## Basic Identifying Information

- **Full name:** David Lee Chaum; technical publications commonly use **David L. Chaum** or **D. Chaum**.
- **Birth:** 1955, Los Angeles, California, United States. No reliable public source consulted gives a month or day.
- **Status:** Living as of 24 August 2026.
- **Nationality:** American.
- **Fields:** Computer science, cryptography, privacy-enhancing technologies, electronic payments, anonymous communications, distributed systems, and verifiable voting.
- **Occupations:** Researcher, university teacher, inventor, editor, institution builder, company founder and technology executive.
- **Frequently applied titles:** “inventor/father of digital cash,” “father of online anonymity,” and “godfather of cryptocurrency/crypto.” These are honorific media formulations, not offices.
- **Principal known locations:** Los Angeles; Berkeley; Santa Barbara; New York; Amsterdam; Palo Alto/Silicon Valley; and later Southern California. Public biographies place him in Sherman Oaks, Los Angeles, but no present residential address is reproduced here.
- **Known institutional affiliations:** University of California, Berkeley; University of California, Santa Barbara; New York University Graduate School of Business Administration; Centrum Wiskunde & Informatica (CWI), Amsterdam; International Association for Cryptologic Research (IACR); DigiCash; Voting Systems Institute/Perspectiva; Elixxir; Praxxis; xx network.

## Family and Ancestry

The recoverable public record is unusually sparse. Reliable institutional profiles identify Chaum as born in Los Angeles in 1955; secondary profiles describe a Jewish family background, but the primary and institutional sources consulted do not name his parents, grandparents, siblings, spouse, partners, or children. No dependable public documentation was found for ancestry, inherited wealth, family businesses, or family political connections.

This silence should not be converted into a claim that no such relations exist. It means only that Chaum has kept his private household largely outside the professional record and that the available sources are insufficient for responsible identification.

## Childhood and Early Life

Chaum's most detailed public account of childhood appears in a 2020 CWI interview. He said that he grew up in Los Angeles, first programmed a computer by punching pre-perforated Hollerith cards with toothpicks, and waited about a week for each batch result. While still in high school he taught programming at a local junior college. He also said that he “kind of dropped out” of high school so he could slip into computer-science courses at UCLA. The interview does not name the high school, junior college, UCLA instructors, or the computer system.

These details establish early access to institutional computing and an unusually precocious teaching role, but they remain autobiographical recollections rather than independently documented school records. No evidence was found of military service, arrest, imprisonment, exile, addiction, major illness, or formative accident.

## Education and Formation

Chaum attended the University of California, Berkeley and received a Ph.D. in computer science in 1982. His dissertation was **“Computer Systems Established, Maintained, and Trusted by Mutually Suspicious Groups.”** ProQuest identifies him as David Lee Chaum; later bibliographies date the dissertation to June or April 1982, while the underlying Berkeley technical report, UCB/ERL M79/10, is dated 22 February 1979. The safest reconstruction is that the research existed as a 1979 report and was incorporated into the 1982 dissertation.

Secondary catalogues name Bernard Marcel Mont-Reynaud as doctoral adviser. Chaum’s early intellectual setting included the emergence of public-key cryptography after Whitfield Diffie and Martin Hellman, RSA signatures, cryptographic hash functions, fault-tolerant distributed computing, smart cards, and growing anxiety about computerized dossiers and transaction surveillance. His work differed from cryptography used only for secrecy: it asked how cryptographic protocols could change institutional power by minimizing what banks, governments, network operators, and counterparties learned.

Chaum told CWI that he created the organization that became IACR when the U.S. National Security Agency was trying to block or constrain open cryptography conferences. The exact characterization of NSA conduct is his retrospective account; the broader conflict over open cryptographic publication is well documented in histories of the period. CRYPTO ’81 and the edited CRYPTO proceedings helped turn a dispersed subject into an international academic community.

## Early Career

### Berkeley, the vault system, and mix networks (1979–1982)

The 1979 report/1982 dissertation specified a system of physically secured “vaults” operated by mutually suspicious groups. Vaults signed, recorded, and broadcast transactions; cryptographic checksums chained a compressed history of consensus states. A 2019 scholarly history by Sherman and colleagues argues that the design embodied many elements later associated with permissioned blockchains: replicated public records, chained history, signed state transitions, consensus among distrusting operators, and private computation. It did **not** supply Bitcoin’s permissionless proof-of-work/Sybil-resistance mechanism or Bitcoin’s monetary design. Calling it “the first blockchain” is therefore a retrospective classification, not terminology Chaum used in 1979–82, and scholars qualify the comparison.

In February 1981, *Communications of the ACM* published **“Untraceable Electronic Mail, Return Addresses, and Digital Pseudonyms.”** Chaum proposed “mixes”: servers that collect encrypted messages, transform and reorder them, then pass them onward so that traffic analysis cannot readily connect sender to recipient. A chain remains private unless every relevant mix is compromised or conspires. The paper became a foundational ancestor of anonymous remailers, onion routing, Tor, and later mixnets, though Tor is not simply Chaum’s original batch-mix design.

### Blind signatures and anonymous payment (1982–1985)

At CRYPTO ’82 Chaum presented **“Blind Signatures for Untraceable Payments,”** published in the 1983 proceedings. A customer blinds a digital coin, a bank signs the obscured value, and the customer unblinds it. The bank’s valid signature remains, but the bank cannot link the coin it later receives from a merchant to the withdrawal that created it. This is the central cryptographic invention behind Chaumian cash.

The model was neither a free-floating commodity nor a permissionless currency. In its classic online form:

1. a customer deposits conventional bank money;
2. the issuing bank signs blinded serial-numbered tokens;
3. the customer unblinds and spends them;
4. the merchant sends tokens to the bank for validation and redemption;
5. the bank rejects a serial number already spent.

The result protects the payer–purchase link while retaining an issuer, redemption, and conventional currency backing. The merchant generally remains identifiable to its bank; this asymmetry also allowed tax and anti-fraud functions that fully anonymous bilateral cash might frustrate.

Chaum’s 1985 CACM article **“Security Without Identification: Transaction Systems to Make Big Brother Obsolete”** widened the program beyond cash. It described personal “card computers,” unlinkable pseudonyms, selective credentials, payments, transit, and other transactions designed to disclose only the minimum needed. The political content was explicit but not party-political: computerized organizations were accumulating detailed personal histories; cryptographic architecture could prevent those histories from being assembled in the first place.

## Chronological Life History

### 1980s: academic cryptography and Amsterdam

After Berkeley, Chaum taught at the University of California, Santa Barbara and at New York University’s Graduate School of Business Administration. Exact appointment dates and ranks are inconsistently reported in short biographies and were not located in authoritative personnel archives.

He moved to the Netherlands and created a cryptography research group at CWI in Amsterdam. CWI later described his arrival as foundational for its cryptology work. Amsterdam became the base for a dense network of collaborators including Jan-Hendrik Evertse, Jan Camenisch, Ronald Cramer, Ivan Damgård, Bert den Boer, Torben Pryds Pedersen, Hans van Antwerpen, Eugène van Heyst, Amos Fiat, and Moni Naor.

Important research from this period included:

- the Dining Cryptographers/DC-net protocol for unconditional sender anonymity (1988);
- minimum-disclosure proofs with Claude Crépeau (1988);
- offline untraceable cash with Amos Fiat and Moni Naor (1988), in which double spending can expose identifying information;
- undeniable signatures with Hans van Antwerpen (1989), requiring the signer’s participation to verify or disavow;
- multiparty-computation and credential protocols;
- group signatures with Eugène van Heyst (1991), allowing a group member to sign anonymously subject to an opening authority.

### 1989/1990–1994: founding DigiCash and building eCash

Sources give both 1989 and 1990 for DigiCash’s founding. The most defensible formulation is that Chaum organized the venture in Amsterdam in 1989–90; the company’s later U.S. corporate chronology sometimes begins in 1994. Those dates should not be collapsed.

DigiCash sought to commercialize Chaum’s research as licensed payment software for banks. Product names included **eCash/ecash**, while **CyberBucks** were demonstration tokens without sovereign-money value. DigiCash also worked on smart-card systems for point-of-sale use.

On 27 May 1994 DigiCash’s team made what the company described as the first electronic cash payment over computer networks. A public CyberBucks trial followed in October 1994. Contemporary EFF archives preserve DigiCash announcements, brochures, a 1994 Chaum bibliography, and competing digital-cash proposals, useful evidence that DigiCash was one project in a fast-moving ecosystem rather than an isolated apparition.

### 1995–1997: bank deployments, recognition, and capitalization

Mark Twain Bank of St. Louis launched U.S.-dollar eCash in October 1995, the best-known live deployment. Deutsche Bank announced a German trial; other licensees or pilots included Bank Austria, Credit Suisse, Finland’s Merita Bank/EUnet, Norway’s Den norske Bank, Sweden’s Posten, Australia’s Advance Bank and St.George Bank, and Japan’s Nomura Research Institute. The arrangements differed—commercial service, pilot, or marketing license—and should not all be counted as mass public adoption.

Chaum and DigiCash received the 1995 European Information Technology Award. Chaum’s own award archive describes a $250,000 prize. Contemporary coverage emphasized privacy-protecting payments, toll systems, and online commerce.

The company nevertheless struggled with the two-sided-market problem: consumers had little reason to install software without merchants, and merchants had little reason without consumers. Credit cards were already familiar, reversible, and bundled with bank relationships. eCash also depended on participating banks, national regulation, currency backing, wallet software, and customer education.

A 28 April 1997 company release announced outside investment, a new Palo Alto headquarters, Nicholas Negroponte as chairman, and Michael Nash—formerly of American Express and Visa—as chief executive. Chaum became chief technology officer. Venture capitalist David Marquardt was among the outside investors. This reorganization is evidence of an attempt to professionalize commercial management after the Amsterdam phase.

### 1998–1999: DigiCash collapse

Mercantile Bank, which had acquired Mark Twain Bank, ended the only U.S. bank trial in September 1998. DigiCash filed for Chapter 11 protection in California in November. Contemporary *Wired* reporting placed debt at about **$4 million** and noted layoffs and the shrinking perceived market for micropayments as consumers accepted credit cards online.

In a 1999 *First Monday* interview, Chaum described the failure as a timing and chicken-and-egg problem. Former employees and Julie Pitta’s 1999 *Forbes* reconstruction added a less flattering management account: slow or rejected deals, excessive secrecy and control, and difficulty converting strong technology into a bank/merchant ecosystem. These are attributed assessments, not court findings of misconduct.

The most repeated lost-opportunity story says Bill Gates/Microsoft proposed bundling eCash with Windows 95 and that Chaum rejected an offer often inflated online to $100 million or $180 million. A European Commission retrospective repeats that a Windows 95 deal was turned down, and Pitta’s reporting is the source behind many later versions. No executed term sheet, Microsoft corporate record, or independently verified dollar offer was found in the consulted record. The existence of discussions is plausible and widely reported; the exact price and Chaum’s precise reasons remain unverified.

DigiCash’s assets and patents passed to eCash Technologies; Chaum ended his involvement by 1999. InfoSpace acquired eCash Technologies in 2002. A later trademark lawsuit involving eCash Technologies and ecash.com concerned the successor, not a criminal or fraud finding against Chaum.

### 2000s–2010s: voting, privacy architecture, and renewed recognition

Chaum redirected much of his public work toward end-to-end verifiable elections. His earlier mix paper had already described secret ballots with publicly checkable tallying. Later systems included SureVote/code voting, a 2004 voter-verifiable scheme, Punchscan, Scantegrity, and Remotegrity. Collaborators included Josh Benaloh, Ronald Rivest, Peter Ryan, Poorvi Vora, Aleks Essex, Jeremy Clark, Richard Carback, Stefan Popoveniuc, and Alan Sherman.

Punchscan won the 2007 VoComp competition. Scantegrity used invisible-ink confirmation codes on optical-scan ballots: voters could later verify that a code appeared on a public bulletin board while cryptographic audits checked the tally without publishing the vote. Takoma Park, Maryland used Scantegrity in its municipal election on 3 November 2009, described by MIT and contemporary reporting as the first binding governmental election using an end-to-end cryptographically verifiable voting system. It was a small municipal deployment, not a nationwide adoption.

Chaum founded or led the Voting Systems Institute and Perspectiva/Perspectiva Fund. He also proposed **Random Sample Elections**, in which a cryptographically selected, representative sample deliberates and votes for the larger population. This remained a political-technical proposal rather than an adopted constitutional system.

In 2004 Chaum became an IACR Fellow. He received the RSA Conference Award for Excellence in Mathematics in 2010.

### 2016: PrivaTegrity and the “nine-padlock backdoor” controversy

At Real World Cryptography in January 2016 Chaum and collaborators introduced **cMix**, designed to precompute expensive cryptographic operations and permit high-throughput mix networking. The proposed application, **PrivaTegrity**, distributed trust across nine servers in different jurisdictions.

Chaum also proposed that unanimous cooperation of all nine server operators could remove a targeted user’s anonymity for conduct “generally recognized as evil.” He framed it as an alternative to universal exceptional-access mandates: no single company or government would hold a master key. Critics—including privacy and security writers—called it a backdoor, argued that unanimity could be coerced or compromised, questioned governance and the undefined “evil” standard, and noted that the prototype initially contemplated servers on Amazon infrastructure. This was a documented design dispute, not an allegation that Chaum secretly supplied intelligence access. No evidence was found that PrivaTegrity became a deployed surveillance system or that Chaum had an intelligence-agency relationship.

### 2018–present: Elixxir, Praxxis, and xx network

Chaum returned to cryptocurrency entrepreneurship with **Elixxir** (announced 2018), a high-speed privacy-messaging and transaction project using cMix; **Praxxis** (announced 2019), promoted as a quantum-resistant consensus/currency design; and their combination as the **xx network** and **xx coin**. Public releases locate parts of Praxxis development in the Cayman Islands and the venture’s public organization in several jurisdictions. A reported 2020 xx coin presale raised approximately $9.7 million, but audited cap tables, Chaum’s personal stake, compensation, and net proceeds were not found.

The xx network’s claims—metadata shredding, quantum resistance, speed, scale, and decentralized governance—are project claims. They should not be treated as independently established merely because the underlying inventor is prominent. The network and token launched; neither has achieved Bitcoin-scale use. Token-price performance and circulating-supply figures change continuously and are omitted from this historical dossier.

Chaum continued publishing on user discovery, cryptocurrency-wallet fallback signatures, sleeve constructions, and VoteXX through at least 2024. His publications page also lists a July 2026 draft title, **“Toward a Graph Theory of Civilization: Commons, Chokepoints, and Ciphers,”** with a placeholder-like arXiv identifier; until a stable record exists, it should be treated as announced/unverified rather than a confirmed publication.

## Companies, Institutions, Technologies, Projects, and Financial Interests

| Entity/project | Dates | Chaum’s role | Documentary status and result |
|---|---:|---|---|
| Berkeley vault system | 1979–1982 | Designer/dissertation author | Detailed research design; retrospectively compared with permissioned blockchain; not a deployed cryptocurrency. |
| IACR/CRYPTO | 1981–1982 onward | Founding organizer/editor | Durable international professional association and conference series. |
| CWI cryptography group | 1980s onward | Founder/research leader | Major Amsterdam research network; institutional legacy continued after Chaum. |
| DigiCash | 1989/90–1999 | Founder, CEO/chairman; later CTO | Commercialized eCash; bank pilots; Chapter 11 in 1998; assets sold. |
| eCash/ecash | 1980s research; 1994–98 deployment | Inventor/product architect | Bank-issued, redeemable, privacy-preserving digital bearer tokens; technically demonstrated, limited adoption. |
| CyberBucks | 1994 | Trial currency | Demonstration tokens, not bank money and not a decentralized commodity. |
| Voting Systems Institute/Perspectiva | 2000s | Founder/leader | Research and advocacy for verifiable elections and public decision systems. |
| Punchscan/Scantegrity/Remotegrity | 2000s–2010s | Inventor/co-inventor | Research systems; Scantegrity used in binding Takoma Park elections. |
| PrivaTegrity/cMix | 2016 | Lead inventor/co-author | Prototype/proposal; sparked exceptional-access governance controversy. |
| Elixxir | 2018 onward | Founder | Privacy communications and transaction technology; folded into xx network. |
| Praxxis | 2019 onward | Founder | Consensus/currency project promoted as quantum resistant; folded into xx network. |
| xx network/xx coin | 2019 onward | Founder/technical leader | Operating network/token; presale reportedly about $9.7 million; ultimate adoption unresolved. |

### Patents and intellectual property

Chaum filed a substantial patent family around blind signatures, credentials, cash, and communications. Representative records include:

- **US 4,759,063**, *Blind signature systems* (filed 1985; granted 1988).
- **US 4,991,210**, *Unpredictable blind signature systems* (filed 1989; granted 1991).
- **WO 1990/004892**, *Returned-value blind signature systems* (priority 1988).
- **US 5,005,200** and related international family, public-key/signature systems with enhanced certification (priority 1988).
- **US application 2006/0218636**, distributed communication security/man-in-the-middle detection. The USPTO rejected its claims and the application became abandoned after no response in 2008. Later academic analysis argued the idea may have been misunderstood but confirms the prosecution outcome.

Patent titles and assignees changed across jurisdictions, and DigiCash/successor companies owned or acquired parts of the portfolio. A precise patent-by-patent ownership history would require paid assignment and bankruptcy records not available in the consulted sources.

### Wealth, property, and financial relationships

No credible audited estimate of Chaum’s net worth was found. Crypto biography pages that claim “millions” do not disclose a method and are not evidence. Known financial facts are limited to DigiCash’s fundraising, the $250,000 1995 prize, roughly $4 million in company debt at bankruptcy, later asset sales, and a reported $9.7 million xx presale. None of these amounts equals Chaum’s personal wealth. No reliable source established significant real property, offshore holdings, money laundering, tax proceedings, or bankruptcy by Chaum personally.

## Political / Religious / Intellectual Development

Chaum’s public program is best described as **privacy through system design**. His 1980s work assumed that identification should not be the default price of participation. Instead of merely promising legal restraint after data collection, systems should use unlinkable pseudonyms, selective credentials, blind signatures, distributed trust, and public verification to prevent unnecessary data aggregation.

This positioned him upstream of the cypherpunks. Timothy C. May’s *Cyphernomicon* explicitly directed readers to Chaum’s 1985 “Big Brother” article; Eric Hughes, John Gilmore, Hal Finney, Nick Szabo, Wei Dai, Adam Back, and others inherited a landscape in which private digital cash and anonymous communications were already technically imaginable. Chaum himself, however, worked heavily through banks, research institutes, patents, and venture-backed firms. His approach was not identical to the later cypherpunk preference for permissionless software and distrust of institutional issuers.

No reliable evidence was found for formal party membership, candidacy, government office, organized religion, or a complete philosophical self-identification. His verifiable political interventions concern informational self-determination, open cryptographic research, election integrity, decentralization, and a later willingness to consider distributed exceptional access under stringent multi-party control.

## Important Relationships and Networks

### Academic and technical collaborators

- **Ronald Rivest and Alan T. Sherman:** co-editors with Chaum of the CRYPTO ’82 proceedings; Sherman later analyzed Chaum’s early vault system and voting work.
- **Amos Fiat and Moni Naor:** co-authors of the 1988 offline untraceable-cash protocol.
- **Claude Crépeau:** co-author on minimum-disclosure proofs.
- **Hans van Antwerpen:** co-inventor of undeniable signatures.
- **Eugène van Heyst:** co-inventor of group signatures.
- **Torben Pryds Pedersen, Ivan Damgård, Bert den Boer, Jan Camenisch, Ronald Cramer:** part of the broader European/CWI cryptographic network around credentials, signatures, proofs, wallets, and cash.
- **Josh Benaloh, Ronald Rivest, Peter Ryan, Poorvi Vora, Alan Sherman, Richard Carback, Jeremy Clark, Aleks Essex, Stefan Popoveniuc:** collaborators and adjacent researchers in verifiable voting.
- **Aggelos Kiayias and later cMix co-authors:** reviewers/collaborators in high-performance mix networking.

### DigiCash business network

- **Nicholas Negroponte:** appointed DigiCash chairman in the 1997 restructuring.
- **Michael Nash:** recruited as CEO in 1997; Chaum shifted to CTO.
- **David Marquardt/August Capital:** outside venture backing.
- **Mark Twain Bank/Mercantile Bank, Deutsche Bank, and other licensed institutions:** distribution and trial partners.
- **Bill Gates/Microsoft:** reported negotiations over Windows distribution; details disputed and not documented by an available contract.

### Nick Szabo

Nick Szabo belongs in Chaum’s intellectual lineage, but claims that he was a core DigiCash employee or direct co-inventor require care. Szabo’s 1996 **“Smart Contracts: Building Blocks for Digital Markets”** linked readers to Chaum’s “Security Without Identification,” “Achieving Electronic Privacy,” and DigiCash. In a 2017 interview he explicitly credited Chaum with inventing mixes and applying blinding to money. Later accounts sometimes say Szabo worked at or with DigiCash, but no authoritative personnel record consulted establishes a title, dates, or employment contract. The secure conclusion is strong documented intellectual influence and ecosystem proximity; a formal employment relationship remains insufficiently documented here.

Szabo’s **bit gold** differed structurally from eCash. It sought scarce digital objects through costly computation and a distributed ownership registry, reducing dependence on a redeeming bank. Wei Dai’s **b-money** proposed anonymous distributed money; Adam Back’s **Hashcash** supplied reusable proof-of-work ideas; Hal Finney’s **RPOW** created transferable proof-of-work tokens using trusted hardware. Bitcoin combined proof of work, peer-to-peer timestamping, economic incentives, and a capped native unit. Chaumian blind-signature cash instead optimized payment privacy around an issuer.

### Satoshi Nakamoto and Bitcoin

Bitcoin’s 2008 white paper did **not** cite Chaum. It cited Adam Back, Wei Dai, Ralph Merkle, Haber and Stornetta, and others. Absence from the reference list does not imply no historical influence: Chaum’s work shaped the field, the cypherpunk conversation, digital-cash vocabulary, and privacy techniques. But direct influence on a particular Bitcoin design choice should not be asserted without evidence.

Chaum has occasionally been proposed online as Satoshi because of his skills, early digital cash, vault dissertation, and privacy commitments. CoinMarketCap circulated one such candidate narrative in 2023; video interviewers have teased the question. No cryptographic proof, contemporaneous correspondence, code provenance, stylometric consensus, or financial evidence connects Chaum to the Nakamoto identity. The proposition is speculation. Chaum’s public post-Bitcoin systems also differ materially from Bitcoin.

## Controversies, Allegations, Investigations, and Financial Questions

### DigiCash management

**Documented facts:** DigiCash missed broad adoption, changed leadership, moved to California, lost its U.S. bank partner, carried about $4 million in debt, and entered Chapter 11 in 1998.

**Attributed criticism:** Pitta’s *Forbes* article and retrospective employee accounts portrayed Chaum as technically brilliant but commercially controlling, secretive, slow to close deals, and unwilling to relinquish authority until late. Some accounts blame refusal of Microsoft/Netscape/card-network opportunities.

**Chaum’s account:** the Internet commerce market and privacy awareness were too immature; banks and merchants faced a chicken-and-egg problem.

**Assessment:** market timing, network effects, bank conservatism, credit-card convenience, product complexity, and management decisions can all have contributed. No consulted source establishes fraud, embezzlement, or criminal conduct by Chaum in DigiCash’s failure.

### Patents versus open cryptographic culture

DigiCash’s proprietary licensing and patent strategy created tension with later open-source, permissionless ideals. Patents can finance deployment and publish inventions, but they can also restrict independent implementation. The record supports a business-model conflict, not a finding that Chaum stole others’ inventions.

### PrivaTegrity exceptional access

The nine-party tracing mechanism was openly proposed, not secretly discovered. Critics’ “backdoor” label accurately describes an intentional exceptional-access capability in ordinary security vocabulary; Chaum emphasized distributed control and the need to trace severe abuse. Governance, coercion, server compromise, due process, and mission creep remained unresolved. No evidence shows a production deployment or abuse.

### xx-network financial and promotional questions

The projects marketed strong claims about speed, privacy, scalability, and quantum resistance and sold tokens to fund development/reward supporters. Public promotional releases are not audited performance evidence. No consulted regulator, court, or law-enforcement source reported an indictment, enforcement action, conviction, money laundering, or proven investor fraud by Chaum. Conversely, absence of such a record does not validate every technical or investment claim.

### Intelligence connections and political violence

No credible evidence was found that Chaum worked for an intelligence service, participated in political violence, or facilitated abuse. His account of NSA pressure on cryptographic conferences concerns publication policy, not an employment or covert relationship. Anonymous payment and communication systems can be used for crime as physical cash and encrypted networks can; capability is not evidence of the inventor’s criminal participation.

## Myths, Legends, Rumors, Propaganda, and Disputed Narratives

### “Chaum invented cryptocurrency”

1. **Story:** Chaum invented the first cryptocurrency or all modern crypto.
2. **Appearance/circulators:** later cryptocurrency media, conference biographies, Chaum-associated project publicity, and institutional retrospectives.
3. **Evidence for:** he published the foundational blind-signature cash protocol and DigiCash implemented bank-issued anonymous digital cash before Bitcoin.
4. **Evidence against/qualification:** eCash had an issuer, bank redemption, conventional currency backing, and online double-spend checking. It lacked Bitcoin’s permissionless consensus, native scarce asset, and proof-of-work issuance.
5. **Effect:** the label restored Chaum to cryptocurrency prehistory but often erased the centralization/decentralization distinction.

### “The 1982 dissertation was Bitcoin/blockchain”

1. **Story:** Chaum designed blockchain or Bitcoin in 1982.
2. **Appearance:** a 2019 scholarly paper cautiously said “many elements” of blockchains appeared in the vault design; popular retellings strengthened this to “first blockchain.”
3. **Evidence for:** signed records, broadcast transactions, replicated consensus state, and a chained checksum over history.
4. **Against/qualification:** permissioned physical vaults, no Nakamoto proof of work, no open Sybil resistance, no Bitcoin monetary unit, and no direct publication impact on Nakamoto shown.
5. **Effect:** expanded Chaum’s reputation from digital-cash pioneer to blockchain precursor, sometimes anachronistically.

### “Microsoft offered $100/$180 million and Chaum simply said no”

1. **Story:** Bill Gates offered an enormous sum to place eCash in every Windows 95 copy; Chaum refused and doomed DigiCash.
2. **Appearance:** Pitta’s 1999 corporate postmortem and many later crypto histories; dollar figures vary.
3. **Evidence for:** multiple retrospective accounts report Microsoft discussions; an EU institutional article repeats that a bundling deal was rejected.
4. **Against/qualification:** no term sheet, exact amount, deal structure, board record, or Microsoft confirmation was located. Divergent dollar figures signal story inflation.
5. **Effect:** became a morality tale about the brilliant inventor who could not commercialize his invention.

### “DigiCash was decentralized”

1. **Story:** DigiCash was a decentralized predecessor identical in principle to Bitcoin.
2. **Appearance:** simplified Web3 timelines and even an EU page.
3. **Evidence:** user privacy reduced an issuer’s observational power; multiple banks could theoretically issue.
4. **Against:** each coin depended on an issuer/signature and redemption; the online system checked spent serial numbers at a bank. The company licensed central infrastructure.
5. **Effect:** makes a neat straight line to Bitcoin at the cost of technical accuracy.

### “Chaum is Satoshi Nakamoto”

1. **Story:** Chaum secretly wrote Bitcoin under the Nakamoto name.
2. **Appearance:** candidate listicles, video teasers, social media, especially after renewed attention to his dissertation.
3. **Evidence for:** capability, privacy expertise, digital-cash history, and chronological possibility.
4. **Against:** no direct evidence; Bitcoin does not cite him; Bitcoin’s architecture departed from his bank-issued cash; Chaum has maintained an open professional identity.
5. **Effect:** attaches Bitcoin’s central origin myth to an acknowledged precursor and enhances interest in Chaum’s older work.

### “Blind signatures make money totally untraceable and crime-proof”

The first half overstates privacy; the second is false. Correctly implemented Chaumian cash can break the withdrawal-to-payment link, but endpoints, malware, merchant records, network metadata, denomination patterns, compromised randomness, issuer policy, or double-spend procedures can reveal information. Cryptography does not prevent theft, extortion, fraudulent merchants, or institutional failure.

## Works by David Chaum

Chaum’s maintained publications page is the most complete available master bibliography and includes journal articles, proceedings papers, books edited, technical reports, patents-linked material, and unpublished manuscripts. The following is a substantial chronological selection; co-authorship is preserved. “Unpublished” means listed by Chaum but not established as formally published.

### Dissertation, reports, and major articles

- **1979:** *Computer Systems Established, Maintained, and Trusted by Mutually Suspicious Groups*, UCB/ERL M79/10 (technical report).
- **1981:** “Untraceable Electronic Mail, Return Addresses, and Digital Pseudonyms,” *Communications of the ACM* 24(2):84–90.
- **1981:** “Trust Relationships and Information Security,” *Proceedings of the National Electronics Conference*.
- **1982:** *Computer Systems Established, Maintained, and Trusted by Mutually Suspicious Groups*, Ph.D. dissertation, UC Berkeley.
- **1982/1983:** “Blind Signatures for Untraceable Payments,” CRYPTO ’82 proceedings.
- **1982:** “Verification by Anonymous Monitors (‘Silo Watching’),” report on CRYPTO ’81.
- **1984:** “A New Paradigm for Individuals in the Information Age,” IEEE Symposium on Security and Privacy.
- **1985:** “Security Without Identification: Transaction Systems to Make Big Brother Obsolete,” *Communications of the ACM* 28(10):1030–1044.
- **1985:** “Showing Credentials Without Identification: Signatures Transferred Between Unconditionally Unlinkable Pseudonyms,” EUROCRYPT ’85.
- **1985:** “Attacks on Some RSA Signatures,” CRYPTO ’85.
- **1986:** with W. de Jonge, “Some Variations on RSA Signatures and Their Security,” CRYPTO ’86.
- **1987:** “Blinding for Unanticipated Signatures,” EUROCRYPT ’87.
- **1988:** “The Dining Cryptographers Problem: Unconditional Sender and Recipient Untraceability,” *Journal of Cryptology* 1(1):65–75.
- **1988:** with Claude Crépeau, “Minimum Disclosure Proofs of Knowledge,” *Journal of Computer and System Sciences* 37(2):156–189.
- **1988:** with Amos Fiat and Moni Naor, “Untraceable Electronic Cash,” CRYPTO ’88.
- **1989:** with Hans van Antwerpen, “Undeniable Signatures,” CRYPTO ’89.
- **1989:** “The Spymasters Double-Agent Problem,” CRYPTO ’89.
- **1990:** with Jan Bos, “Smart Cash: A Practical Electronic Payment System,” CWI report CS-R9035.
- **1990:** with Sandra Roijakkers, “Unconditionally-Secure Digital Signatures,” CRYPTO ’90.
- **1990:** “Zero-Knowledge Undeniable Signatures,” EUROCRYPT ’90.
- **1991:** with Eugène van Heyst, “Group Signatures,” EUROCRYPT ’91.
- **1991:** with collaborators, “Undeniable Signatures: Applications and Theory,” technical report.
- **1992:** “Achieving Electronic Privacy,” *Scientific American*.
- **1992:** with Torben Pryds Pedersen, “Wallet Databases with Observers” and “Transferred Cash Grows in Size.”
- **2001:** *SureVote: Technical Overview*, Workshop on Trustworthy Elections.
- **2004/2005:** “Secret-Ballot Receipts: True Voter-Verifiable Elections” / “A Practical Voter-Verifiable Election Scheme.”
- **2008–2013:** multiple co-authored papers on Punchscan, Scantegrity, accessible verification, and Remotegrity.
- **2016:** with D. Das, F. Javani, A. Kate, A. Krasnova, J. de Ruiter, and A. T. Sherman, “cMix: Anonymization by High-Performance Scalable Mixing,” IACR ePrint 2016/008; revised ACNS publication in 2017.
- **2017:** “Random-Sample Voting,” with co-authors; related writings on random-sample elections.
- **2021:** with M. Larangeira, M. Yaksetig, and W. Carter, “W-OTS+ Up My Sleeve! A Hidden Secure Fallback for Cryptocurrency Wallets,” ACNS.
- **2022:** with M. Yaksetig, A. T. Sherman, and J. de Ruiter, “UDM: Private User Discovery with Minimal Information Disclosure,” *Cryptologia*.
- **2022:** with collaborators, “VoteXX: A Solution to Improper Influence in Voter-Verifiable Elections,” IACR ePrint 2022/1212.
- **2024:** with collaborators, “VoteXX: Extreme Coercion Resistance,” IACR ePrint 2024/1354.
- **Undated/unpublished on author list:** “7th Estate: Grassroots Democracy”; “Combining Secrets in Most Concealing Ways”; “Zero Information Circuits with DES.”
- **Announced/listed for 2026 but not independently verified:** “Toward a Graph Theory of Civilization: Commons, Chokepoints, and Ciphers.”

### Books and edited volumes

- Chaum, Rivest, and Sherman, eds., *Advances in Cryptology: Proceedings of CRYPTO ’82* (Plenum, 1983).
- Chaum, ed., *Advances in Cryptology: Proceedings of CRYPTO ’83* (Plenum, 1984).
- Chaum and W. L. Price, eds., *Advances in Cryptology—EUROCRYPT ’87* (Springer, 1988).
- Chaum and Ingrid Schaumüller-Bichl, eds., *Smart Card 2000: The Future of IC Cards* (North-Holland, 1988).
- Chaum, ed., *Smart Card 2000: Second International Smart Card 2000 Conference, Amsterdam 1989* (Elsevier, 1991).
- Chaum, Jakobsson, Rivest, Ryan, Benaloh, Kutyłowski, and Adida, eds., *Towards Trustworthy Elections: New Directions in Electronic Voting* (Springer, 2010).

No memoir, diary, collected correspondence, or conventional autobiography by Chaum was located. Later interviews are primary testimony but are edited journalistic products, not authored memoirs.

## Books and Major Works About David Chaum

No full-length scholarly biography devoted solely to Chaum was located. The major treatments are histories of cryptography, digital money, privacy, and Bitcoin:

- Steven Levy, *Crypto: How the Code Rebels Beat the Government—Saving Privacy in the Digital Age* (2001; later editions). Substantial narrative on open cryptography and DigiCash.
- Jean-François Blanchette, *Burdens of Proof: Cryptographic Culture and Evidence Law in the Age of Electronic Documents* (MIT Press, 2012). Academic context for signatures, evidence, and cryptographic culture.
- Finn Brunton, *Digital Cash: The Unknown History of the Anarchists, Utopians, and Technologists Who Created Cryptocurrency* (Princeton University Press, 2019). Broad history placing Chaum among monetary experiments.
- Arvind Narayanan, “What Happened to the Crypto Dream?,” *IEEE Security & Privacy* 11(2), 2013. Retrospective on the privacy program.
- Alan T. Sherman, Farid Javani, Haibin Zhang, and Enis Golaszewski, “On the Origins and Variations of Blockchain Technologies,” *IEEE Security & Privacy* (2019). Technical-historical reassessment of Chaum’s vaults.
- Julie Pitta, “Requiem for a Bright Idea,” *Forbes*, 1 November 1999. The principal corporate postmortem; influential but dependent on interviews and retrospective attribution.
- Jens-Ingo Brodesser, “First Monday Interviews: David Chaum,” *First Monday* 4(7), 1999. Primary interview immediately after DigiCash’s collapse.
- Marc Rotenberg, “Eurocrats Do Good Privacy,” *Wired*, May 1996. Contemporary European policy context.
- Andy Greenberg, “The Father of Online Anonymity Has a Plan to End the Crypto War,” *Wired*, January 2016. PrivaTegrity profile and controversy.
- Aaron van Wirdum, *The Genesis Book: The Story of the People and Projects That Inspired Bitcoin* (Bitcoin Magazine Books, 2024). Narrative history of DigiCash and pre-Bitcoin projects; useful but written within Bitcoin media.
- David Birch, *Before Babylon, Beyond Bitcoin* (London Publishing Partnership, 2017). Payments-history context.
- Nathaniel Popper, *Digital Gold* (Harper, 2015), and Paul Vigna and Michael J. Casey, *The Age of Cryptocurrency* (St. Martin’s, 2015). Bitcoin histories that situate precursor work.

## Films, Documentaries, Interviews, and Archival Material

- **BBC News/Horizon segment:** “David Chaum, ‘Godfather of Anonymous Communication’” (video, c. 2014).
- **CWI interviews:** “Blockchain Will Decentralize Power” (2019) and “Interview with Dijkstra Fellow David Chaum” (2020); the latter contains his clearest brief childhood recollections.
- **First Monday interview** (1999): contemporary discussion of DigiCash’s Chapter 11 and deployment problem.
- **Unchained, episode 186:** “Why Bitcoin Now: David Chaum and Adam Back Reflect on the Crypto Wars” (2020); retrospective by two pre-Bitcoin researchers.
- **Bloomberg Odd Lots:** “Meet the Godfather of Cryptocurrency” (2019).
- **Epicenter:** “David Chaum: The Forefather of Cryptocurrencies and Online Privacy” (2019).
- **CoinDesk Devcon interview** (2019) and later CoinDesk video interviews on xx network, quantum resistance, and Satoshi speculation.
- **Tim Ferriss Show #244 with Nick Szabo** (recorded 2017; transcript published 2018): Szabo’s explicit acknowledgment of Chaum’s work.
- **Chaum.com archives:** publications, awards, eCash timeline, DigiCash press releases and photographs. These are first-party curated archives and require corroboration for evaluative claims.
- **EFF digital-money archive:** contemporaneous 1990s DigiCash announcements, brochures, bibliographies, and competing cash proposals.
- **CWI institutional archive/repository:** Chaum papers and institutional history.
- **UC Berkeley/ProQuest:** dissertation catalogue and text.
- **Google Patents/USPTO records:** patent texts, priority chains, assignments where indexed, and prosecution status.

No major authorized theatrical biopic or feature documentary centered exclusively on Chaum was located.

## Awards, Honors, Offices, and Appointments

- Founding organizer of IACR/CRYPTO community, early 1980s.
- European Information Technology Award, 1995, for DigiCash eCash; Chaum archive states $250,000.
- IACR Fellow, 2004.
- RSA Conference Award for Excellence in Mathematics, 2010.
- Dijkstra Fellowship, CWI, 2019, shared in that cycle with Guido van Rossum.
- Honorary doctorate, Faculty of Informatics, Università della Svizzera italiana (USI), 2021.
- Honorary Consensus MetaGala Award, 2022, according to Chaum’s awards archive.

His 1997 move from DigiCash chief executive leadership to CTO was a corporate reassignment during recapitalization, not documented as a dismissal. No academic dismissal was found.

## Illness, Accidents, and Present Status

No reliable public documentation was found of major illnesses, addictions, psychological crises, serious accidents, or disabling injuries. Chaum remains alive and professionally active as of the dossier date. Because he is living, there is no cause of death or posthumous estate.

## Reputation and Legacy

Chaum’s legacy divides into four technically distinct lines:

1. **Communication anonymity:** mixes and DC-nets established basic ways to resist traffic analysis. Later remailers, onion routing, Tor, mixnets, and privacy cryptocurrencies adapted rather than simply copied them.
2. **Privacy-preserving credentials and signatures:** blind signatures, minimum-disclosure proofs, group signatures, undeniable signatures, and unlinkable pseudonyms became foundational research areas.
3. **Digital cash:** DigiCash proved that software could issue and redeem cryptographic bearer value with strong payer privacy. It also demonstrated the fragility of a system dependent on banks, merchant adoption, proprietary clients, and a venture-funded intermediary.
4. **Verifiable collective systems:** voting research pursued a recurring Chaum theme—publicly verifiable outcomes without exposing private individual actions.

The post-Bitcoin reinterpretation emphasizes continuity: Chaum made digital cash thinkable and buildable. The discontinuity is equally important: Bitcoin abandoned the redeeming bank and blind-signature model in favor of a public ledger, proof-of-work consensus, pseudonymous addresses, and a native asset. Bitcoin is often less private than Chaumian cash at the transaction layer even while being more permissionless at the issuance/consensus layer.

## Chronology

| Date/year | Event |
|---|---|
| 1955 | Born in Los Angeles, California; exact date not reliably public. |
| c. late 1960s–early 1970s | Programs with punched Hollerith cards; teaches programming at a junior college while in high school; informally attends UCLA computer-science courses (Chaum’s recollection). |
| 22 Feb. 1979 | Berkeley report UCB/ERL M79/10 on computer systems trusted by mutually suspicious groups. |
| Feb. 1981 | Mix-network paper published in *Communications of the ACM*. |
| 1981–82 | Helps organize CRYPTO/IACR during conflict over open cryptographic research. |
| 1982 | Receives UC Berkeley Ph.D.; presents blind signatures at CRYPTO ’82. |
| 1983 | CRYPTO ’82 proceedings publish “Blind Signatures for Untraceable Payments.” |
| 1984–85 | Publishes new privacy paradigm and “Security Without Identification.” |
| 1980s | Teaches at UCSB and NYU; relocates to Amsterdam; establishes CWI cryptography group. |
| 1988 | Publishes Dining Cryptographers, minimum-disclosure proofs, and offline untraceable cash work. |
| 1989 | Undeniable signatures; DigiCash organization begins (sources also give 1990). |
| 1990 | DigiCash established in Amsterdam; “Smart Cash” CWI report. |
| 1991 | Group signatures with Eugène van Heyst. |
| Aug. 1992 | “Achieving Electronic Privacy” in *Scientific American*. |
| 27 May 1994 | DigiCash records first networked eCash payment. |
| Oct. 1994 | Public CyberBucks trial announced. |
| 23 Oct. 1995 | Mark Twain Bank launches U.S.-dollar eCash. |
| Nov. 1995 | Receives European Information Technology Award. |
| 1996 | Deutsche Bank and other institutional pilots/licenses expand. |
| 28 Apr. 1997 | DigiCash announces investment, Negroponte chairmanship, Michael Nash as CEO, and move to Palo Alto; Chaum becomes CTO. |
| Sept. 1998 | Mercantile Bank ends U.S. eCash trial. |
| Nov. 1998 | DigiCash files Chapter 11 with reported debt near $4 million. |
| 1999 | First Monday interview; assets/involvement transition; Pitta publishes major postmortem. |
| 2002 | InfoSpace acquires successor eCash Technologies. |
| 2004 | Named IACR Fellow; voter-verifiable election research gains public visibility. |
| 2007 | Punchscan wins VoComp. |
| 3 Nov. 2009 | Takoma Park uses Scantegrity in a binding municipal election. |
| 2010 | Receives RSA Award for Excellence in Mathematics; co-edits *Towards Trustworthy Elections*. |
| 2011–12 | Promotes Random Sample Elections. |
| Jan. 2016 | Presents cMix/PrivaTegrity; exceptional-access design draws criticism. |
| 2018 | Announces Elixxir. |
| Aug.–Nov. 2019 | Announces Praxxis and combined xx network/xx coin; receives CWI Dijkstra Fellowship. |
| 2020 | Reported $9.7 million xx coin presale; CWI publishes extended interview. |
| 2021 | Receives USI honorary doctorate; xx network/coin launch period. |
| 2022 | Consensus MetaGala honor; UDM/VoteXX and wallet-security research continues. |
| 2024 | VoteXX extreme-coercion-resistance paper listed. |
| 24 Aug. 2026 | Living; later publications/project activity continues, with some announced work not yet independently verified. |

## Atlas Connections

### Whitfield Diffie

- **[T1-]** **Documented fact:** Chaum discussed Diffie’s earlier work in “Security Without Identification” (1985), identifying the 1976 Diffie–Hellman paper as the source of the digital-signature concept on which Chaum’s privacy architecture built. [Chaum text and references](https://chaum.com/security-without-identification/)

### Martin Hellman

- **[T1-]** **Documented fact:** In “Security Without Identification” (1985), Chaum credited Hellman jointly with Diffie for proposing digital signatures and cited their 1976 paper “New Directions in Cryptography.” [Chaum text and references](https://chaum.com/security-without-identification/)

### Ronald Rivest

- **[T3]** **Documented fact:** Chaum and Rivest worked together as co-editors—with Alan T. Sherman—of *Advances in Cryptology: Proceedings of CRYPTO ’82*, arising from the conference held in Santa Barbara, California, on 23–25 August 1982. Chaum was general chair and Rivest program chair. [Springer proceedings record](https://link.springer.com/book/10.1007/978-1-4757-0602-4), [Chaum’s IACR archive](https://chaum.com/iacr/)
- **[T1-]** **Documented fact:** Chaum’s 1985 treatment of digital signatures discussed and cited the earlier RSA construction by Rivest, Adi Shamir, and Leonard Adleman. [Chaum text and references](https://chaum.com/security-without-identification/)

### Adi Shamir

- **[T1-]** **Documented fact:** Chaum discussed public-key digital signatures in “Security Without Identification” and cited the 1978 Rivest–Shamir–Adleman paper as a foundational construction underlying the protocols he presented. [Chaum text and references](https://chaum.com/security-without-identification/)

### Leonard Adleman

- **[T1-]** **Documented fact:** Chaum’s “Security Without Identification” cited and built its explanation of practical digital signatures partly around the earlier RSA work of Rivest, Shamir, and Adleman. [Chaum text and references](https://chaum.com/security-without-identification/)

### Bill Gates

- **[T3]** **Reported fact:** Retrospective accounts report negotiations or communications in the mid-1990s between Chaum/DigiCash and Gates’s Microsoft concerning possible eCash integration with Windows 95. The talks reportedly produced no agreement. Claims that Gates personally offered Chaum exactly $100 million or $180 million remain unverified because no term sheet, correspondence, or Microsoft record establishing those figures has surfaced. [Contemporary corporate postmortem](https://www.forbes.com/forbes/1999/1101/6411390a.html), [Chaum’s later interview discussing Microsoft’s interest](https://unchainedcrypto.com/why-bitcoin-now-david-chaum-and-adam-back-reflect-on-the-crypto-wars/)

### Hal Finney

- **[T1+]** **Documented fact:** Finney wrote a detailed exposition of Chaum, Amos Fiat, and Moni Naor’s offline electronic-cash protocol. Dated 15 October 1993 and revised 13 March 1996, “Detecting Double-Spending” explicitly explained Chaum’s anonymity, blind-signature, and double-spender-identification mechanisms. [Finney’s essay](https://fennetic.net/irc/finney.org/~hal/chcash2.html)

### Nick Szabo

- **[T1+]** **Documented fact:** Szabo repeatedly treated Chaum as an earlier intellectual and technical precursor. His writings linked readers to Chaum’s privacy and digital-cash work, and in a 2017 interview he explicitly credited Chaum with inventing mixes and applying blinding techniques to money. This establishes written and public intellectual engagement, but not, by itself, employment at DigiCash or a personal collaboration. [Szabo interview transcript](https://tim.blog/2018/06/01/the-tim-ferriss-show-transcripts-nick-szabo/), [Szabo’s “Smart Contracts” bibliography](https://nakamotoinstitute.org/library/smart-contracts-building-blocks-for-digital-markets/)

### Guido van Rossum

- **[T4]** **Documented fact:** Chaum and van Rossum were jointly honored as CWI’s first Dijkstra Fellows in Amsterdam in November 2019. CWI scheduled both recipients for the 21 November award soirée at the Scheepvaartmuseum and associated CWI Lectures on 21–22 November, placing them in the same institutional event and milieu without establishing a deeper personal relationship. [CWI announcement](https://www.cwi.nl/en/news/david-chaum-and-guido-van-rossum-awarded-dijkstra-fellowship/), [CWI retrospective record](https://ir.cwi.nl/pub/29131)

No other roster crossing was included where the available evidence showed only broad intellectual lineage, shared subject matter, overlapping geography, a namesake institution—such as Mark Twain Bank—or unsupported speculation.

### Connection Tags

Machine-readable summary of this dossier's Atlas Connections, added 2026-09-05 during the connections-harmonization pass. Types: T1 wrote about a past figure, T2 prophecy/hyperstition, T3 discourse, T4 proximity/milieu, T5 friendship/meeting, T9 shared object or site. Sign + = this subject is the earlier/source figure, - = the later figure, blank = undirected. See the prose above (or the counterpart's own dossier) for the full claim.

- **Bailey Whitfield Diffie** [T1-]
- **Martin Edward Hellman** [T1-]
- **Ronald Linn Rivest** [T3]
- **Ronald Linn Rivest** [T1-]
- **Adi Shamir** [T1-]
- **Leonard Max Adleman** [T1-]
- **William Henry Gates III** [T3]
- **Harold Thomas Finney II** [T1+]
- **Nick Szabo** [T1+]
- **Guido van Rossum** [T4]
- **Martin Edward Hellman** [T3] (mirrored from hellman.dossier.md)
- **Nick Szabo** [T3] (mirrored from nick_szabo.dossier.md)
- **Brock Jeffrey Pierce** [T4] (mirrored from brock_pierce.dossier.md)
- **Philip R. Zimmermann** [T4] (mirrored from phil_zimmermann.dossier.md)
- **Bailey Whitfield Diffie** [T4] (mirrored from diffie.dossier.md)
- **Ronald Linn Rivest** [T5] (mirrored from ron_rivest.dossier.md)

## Sources

https://chaum.com/publications/
https://chaum.com/ecash/
https://chaum.com/awards/
https://chaum.com/security-without-identification/
https://chaum.com/wp-content/uploads/2022/02/techrep.pdf
https://chaum.com/wp-content/uploads/2022/01/04-28-1997-DigiCash-Appoints-CEO-Increases-Outside-Investment-and-Moves-Headquarters-To-California.pdf
https://dl.acm.org/doi/10.1145/358549.358563
https://dl.acm.org/doi/10.1145/4372.4373
https://link.springer.com/chapter/10.1007/978-1-4757-0602-4_18
https://link.springer.com/article/10.1007/BF00206326
https://nakamotoinstitute.org/library/computer-systems-by-mutually-suspicious-groups/
https://nakamotoinstitute.org/library/untraceable-electronic-mail/
https://nakamotoinstitute.org/library/blind-signatures/
https://nakamotoinstitute.org/authors/david-chaum/
https://cdn.arenafi.org/papers/arxiv/1810.06130.pdf
https://www.proquest.com/docview/303061992
https://www.cwi.nl/en/stories/interview-with-dijkstra-fellow-david-chaum/
https://www.cwi.nl/en/stories/interview-david-chaum-201cblockchain-will-decentralize-power201d/
https://firstmonday.org/ojs/index.php/fm/article/view/683/593
https://www.forbes.com/forbes/1999/1101/6411390a.html
https://www.wired.com/1998/11/digicash-outta-cash/
https://www.americanbanker.com/news/electronic-commerce-bankrupt-digicash-to-seek-financing-new-allies
https://ec.europa.eu/newsroom/cef/items/658303
https://w2.eff.org/Privacy/Digital_money/?f=online_cash_chaum.paper.txt
https://patents.google.com/patent/US4759063A/en
https://patents.google.com/patent/US5005200A/en
https://patents.google.com/patent/US5839119A/en
https://patents.google.com/patent/EP0542298B1/en
https://www.wired.com/2007/07/us-team-wins-vo/
https://www.wired.com/2009/11/scantegrity/
https://www.wired.com/2016/01/david-chaum-father-of-online-anonymity-plan-to-end-the-crypto-wars/
https://bford.info/2016/03/08/backdoors/
https://www.securityweek.com/privategrity-david-chaums-anonymous-communications-project/
https://tim.blog/2018/06/01/the-tim-ferriss-show-transcripts-nick-szabo/
https://nakamotoinstitute.org/library/smart-contracts-building-blocks-for-digital-markets/
https://cdn.nakamotoinstitute.org/docs/cyphernomicon.txt
https://www.youtube.com/watch?v=ZVZxRMAeIdo
https://www.youtube.com/watch?v=IXr_6jqBTj0
https://podcasts.apple.com/us/podcast/meet-the-godfather-of-cryptocurrency/id1056200096?i=1000439442488
https://podcasts.apple.com/ca/podcast/david-chaum-the-forefather-of/id792338939?i=1000449315022
https://www.prnewswire.co.uk/news-releases/david-chaum-announces-the-xx-coin-supporting-decentralized-messaging-payments-and-dapps-on-the-xx-network-834748051.html
https://www.fintechfutures.com/quantum-computing/david-chaum-announces-quantum-resistant-digital-currency
https://epic.org/people/david-chaum/
