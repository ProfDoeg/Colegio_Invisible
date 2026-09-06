# ARPANET: Network Dossier

**Network:** Advanced Research Projects Agency Network  
**Common name:** ARPANET; historically also **ARPA Network**, **ARPA Computer Network**, and, informally, **the Net**  
**Bounded period:** 1969–1990  
**Document status:** Source-critical synthesis  
**Filename:** `arpanet_network_dossier.md`

---

## Evidentiary conventions

This dossier uses the following labels:

- **Documented:** established by contemporary technical reports, RFCs, directories, maps, contracts, government publications, logs, or mutually consistent participant testimony.
- **Retrospective testimony:** a participant’s later recollection; valuable but vulnerable to memory, institutional perspective, and priority disputes.
- **Scholarly inference:** a conclusion drawn by historians from documented circumstances rather than stated contemporaneously.
- **Disputed:** responsible sources give materially different accounts.
- **Unverified:** widely repeated but not traceable here to a satisfactory primary source.
- **Myth or legend:** a simplified story that conflicts with, or substantially exceeds, the documentary evidence.

The surviving record is unusually extensive but institutionally uneven. ARPA/DARPA, Bolt Beranek and Newman, the Stanford Research Institute Network Information Center, and the RFC series are strongly represented; routine users, junior operators, secretaries, equipment installers, telephone-company workers, and rejected prospective users are less visible.

---

## 1. Identification and Definition

### 1.1 What ARPANET was

ARPANET was a United States Department of Defense–funded, geographically distributed, packet-switched computer network. It joined heterogeneous host computers through a standardized subnet of dedicated packet switches called **Interface Message Processors** (IMPs), interconnected principally by leased telecommunications circuits. A host did not need to reproduce every other host’s hardware or operating system. It communicated with its local IMP through a defined interface; the IMP subnet accepted, routed, acknowledged, retransmitted when necessary, and delivered units of data toward the destination host. This separation between heterogeneous hosts and a relatively homogeneous communication subnet was one of the system’s foundational architectural decisions. [BBN, *A History of the ARPANET: The First Decade*](https://upload.wikimedia.org/wikipedia/commons/9/94/A_History_of_the_ARPANET%2C_The_First_Decade%2C_BBN_Report_4799%2C_April_1981.pdf)

ARPANET carried no physical goods or people. It carried digital information:

- interactive terminal keystrokes and responses;
- remote-login sessions;
- program source and executable files;
- scientific data and results;
- remote jobs and their output;
- electronic mail;
- administrative notices;
- host-name and protocol documentation;
- mailing-list discussions;
- network measurements and diagnostic traffic;
- demonstrations of graphics, speech, database, and collaborative-computing applications;
- traffic associated with defense-funded research and, later, operational government communication.

The network was neither identical with the Internet nor merely an early name for it. Before 1983, ARPANET was principally a single packet-switching network using the IMP subnet and the ARPANET Network Control Program/Protocol family. The Internet was the later internetworking system in which ARPANET became one component alongside packet-radio, satellite, local-area, federal, academic, and eventually commercial networks. DARPA itself describes ARPANET as becoming subsumed within a much larger “network of networks.” [DARPA, “ARPANET”](https://www.darpa.mil/news/features/arpanet)

### 1.2 Names

The documented English forms include:

- **Advanced Research Projects Agency Network** — the usual expansion of ARPANET.
- **ARPANET** and **ARPAnet** — both historical typographies occur; later usage overwhelmingly favors ARPANET.
- **ARPA Network** — common in early technical papers and contemporary discussion.
- **ARPA Computer Network** — used in technical and administrative descriptions.
- **Resource Sharing Computer Networks** — the title of the fiscal-year 1969 DARPA program under which the work began; it described the program more than it supplied the network’s permanent proper name. [BBN history](https://upload.wikimedia.org/wikipedia/commons/9/94/A_History_of_the_ARPANET%2C_The_First_Decade%2C_BBN_Report_4799%2C_April_1981.pdf)
- **Defense Research Internet** — a later designation for the research-oriented Internet environment descended from ARPANET, not a simple synonym for ARPANET throughout 1969–1990.
- **DDN ARPANET** — an administrative expression after incorporation into the Defense Data Network framework.

ARPA was renamed the **Defense Advanced Research Projects Agency** in 1972, returned to **ARPA** in 1993, and became DARPA again in 1996. The network nevertheless retained the established name **ARPANET** rather than becoming “DARPANET.”

Because ARPANET was created, administered, and technically documented in the United States, its operative name and standards language were English. Other-language forms—French *réseau ARPANET*, Spanish *red ARPANET*, German *ARPANET-Netz*, Japanese アーパネット, Russian АРПАНЕТ, and Arabic أربانت—are later transliterations or descriptive translations, not separately chartered historical names. Japanese-language historical material, for example, calls it ARPANET and expands the English acronym. [JPNIC Japanese timeline](https://web.nic.ad.jp/timeline/index.html)

### 1.3 Boundary dates

**1969** is justified as the beginning because:

1. the “Resource Sharing Computer Networks” program began in fiscal year 1969;
2. RFC 1 appeared on 7 April 1969;
3. the first IMP was delivered to UCLA at the end of August/beginning of September;
4. the first UCLA–SRI host-to-host experiment occurred on 29 October;
5. the four-node network existed by December.

The beginning can therefore be dated differently depending on the criterion:

- **1966:** Bob Taylor initiated the project inside ARPA and recruited Lawrence Roberts.
- **1967:** Roberts publicly presented the networking plan.
- **1968:** ARPA issued the IMP request for quotations and awarded BBN the contract.
- **7 April 1969:** Steve Crocker issued RFC 1, *Host Software*.
- **29 October 1969:** the first recorded host-to-host message attempt ran from UCLA to SRI.
- **December 1969:** UCLA, SRI, UCSB, and Utah formed the first four-node network.

Calling any one of these the unique “birth of the Internet” is retrospective shorthand. They concern different objects: a program, a design, a contract, a documentary community, a working link, and a multi-node network.

**1990** is the appropriate terminal year because the remaining ARPANET packet-switching backbone was decommissioned in early 1990. Sources differ on precision. Contemporary and institutional histories generally say **February 1990**, **28 February 1990**, or **March 1990**. NSFNET’s historical timeline uses March; DARPA states that formal decommissioning occurred in 1990 without fixing a day on its feature page. The difference is probably between shutdown activity and administrative recognition, but an authoritative shutdown order establishing one exclusive date has not been located in the sources used here. [NSFNET timeline](https://nsf.net/timeline), [DARPA](https://www.darpa.mil/news/features/arpanet)

ARPANET did not “turn into the Internet” at the instant it was switched off. Its institutional transformation occurred in stages: operational transfer to the Defense Communications Agency in 1975; internetworking experiments during the 1970s; TCP/IP conversion in 1983; removal of most military nodes to MILNET in 1983–84; displacement as a research backbone by NSFNET and regional networks in the later 1980s; final retirement in 1990.

### 1.4 What counts as inside

Strictly inside ARPANET were:

- IMPs, Terminal IMPs (TIPs), and later Pluribus switches operating as its packet-switching subnet;
- leased lines and satellite circuits treated as ARPANET links;
- hosts directly attached to an ARPANET IMP;
- terminals entering through ARPANET TIPs or authorized terminal-access controllers;
- the Network Control Center and Network Information Center insofar as they administered ARPANET;
- host protocols and services actually operating across this subnet.

Related but analytically distinct were:

- ALOHAnet and the Packet Radio Network;
- SATNET/Atlantic Packet Satellite Network;
- Ethernet local networks;
- Tymnet, Telenet, Datapac, Cyclades, NPL, EIN, CSNET, BITNET, Usenet, NSFNET, and commercial packet networks;
- MILNET after its separation;
- the Internet as the encompassing TCP/IP internetwork.

A machine reachable through a gateway could be “on the Internet” without being a directly attached ARPANET host. Conversely, an ARPANET host after 1983 was both on ARPANET physically and on the Internet logically.

---

## 2. Formation

### 2.1 Institutional setting

ARPA was established in 1958 after Sputnik to fund advanced research whose urgency or uncertainty did not fit ordinary military procurement. Its Information Processing Techniques Office funded leading American centers in time-sharing, artificial intelligence, graphics, command-and-control research, and human–computer interaction.

By the mid-1960s IPTO managers faced several related conditions:

- expensive, incompatible computers were distributed among different contractors;
- researchers wanted access to specialized machines, software, and datasets elsewhere;
- ARPA was paying for overlapping computing capacity;
- time-sharing had demonstrated interactive multi-user computing;
- communications research had begun to make packet switching credible;
- defense planners had a continuing interest in robust command, control, and information systems.

J.C.R. Licklider, IPTO’s first director, circulated 1962–63 memoranda describing a “Galactic Network” of interactive computers and communities. These memoranda were visionary programmatic statements, not an engineering plan for ARPANET. Ivan Sutherland succeeded him; Bob Taylor, who became IPTO director in 1966, converted the general desire to link the contractor community into a program. [Internet Society, “A Brief History of the Internet”](https://www.internetsociety.org/internet/history-internet/brief-history-internet/)

Taylor later recalled that his office contained three terminals used to reach three incompatible remote systems and that the practical absurdity suggested one network terminal. He also recalled repeatedly pressing Lawrence Roberts to join ARPA and asking ARPA director Charles Herzfeld to use ARPA’s funding leverage over MIT Lincoln Laboratory. Taylor jokingly called this “blackmail.” This is **retrospective testimony**, corroborative of recruitment pressure but not a literal criminal allegation. [Computer History Museum, Robert Taylor oral history](https://archive.computerhistory.org/resources/text/Oral_History/Taylor_Robert/102702015.05.01.acc.pdf)

### 2.2 Technical predecessors and parallel inventions

Several developments fed ARPANET:

- **Time-sharing:** MIT’s Compatible Time-Sharing System, Project MAC/Multics, SDC’s systems, and other interactive-computing projects established the idea of many remote users sharing computation.
- **Kleinrock’s queueing research:** Leonard Kleinrock analyzed communication nets and packet-like store-and-forward traffic mathematically.
- **Roberts–Merrill experiment, 1965:** a TX-2 at Lincoln Laboratory in Massachusetts communicated with the Q-32 at System Development Corporation in California over a dial-up line. Remote operation worked, but conventional circuit switching was judged inefficient for bursty computer traffic.
- **RAND distributed communications:** Paul Baran and colleagues developed a redundant digital network concept for survivable military communications and published an eleven-part 1964 series.
- **NPL packet switching:** Donald Davies’s group at Britain’s National Physical Laboratory independently developed packet switching, coined the term **packet**, and built an experimental network.
- **Other networking experiments:** experimental host-linked networks and airline-reservation, banking, and teleprocessing systems demonstrated remote data communication but did not share ARPANET’s architecture and research purpose.

The BBN retrospective history states that Roberts learned of NPL work from Roger Scantlebury at the 1967 Gatlinburg conference and that the proposed line rate rose from 2.4 to 50 kilobits per second. The Internet Society account, co-authored by major participants, gives the same broad sequence. This does not justify assigning packet switching to a single inventor: Baran, Davies, Kleinrock, Roberts, and others addressed different theoretical, architectural, terminology, and implementation questions. [BBN history](https://upload.wikimedia.org/wikipedia/commons/9/94/A_History_of_the_ARPANET%2C_The_First_Decade%2C_BBN_Report_4799%2C_April_1981.pdf), [Internet Society](https://www.internetsociety.org/internet/history-internet/brief-history-internet/)

### 2.3 Approval, design, and procurement

In 1966 Taylor obtained approval from Charles Herzfeld for a networking program. Roberts joined ARPA late that year and developed the plan. In 1967 he presented it at the ACM Symposium on Operating System Principles.

ARPA initially considered making every participating host perform network switching. Wesley Clark advocated interposing small, standardized computers between hosts and the communications network. The idea became the IMP subnet. Its advantages included insulating the subnet from host diversity and centralizing routing, error control, statistics, and switching software. Its disadvantage was the cost of placing another computer at each node. [BBN history](https://upload.wikimedia.org/wikipedia/commons/9/94/A_History_of_the_ARPANET%2C_The_First_Decade%2C_BBN_Report_4799%2C_April_1981.pdf)

ARPA issued the IMP request for quotations in August 1968. Bolt Beranek and Newman of Cambridge, Massachusetts, received the contract in December. Frank Heart led the BBN team; important members included Robert Kahn, Severo Ornstein, William Crowther, David Walden, Ben Barker, Bernie Cosell, and Hawley Rising. BBN selected a ruggedized Honeywell DDP-516 minicomputer, supplemented it with custom interfaces and error-control hardware, and wrote the IMP software largely in assembly language.

Network Analysis Corporation, associated particularly with Howard Frank, helped optimize topology and line placement. UCLA’s Network Measurement Center under Kleinrock prepared to measure network behavior. Each host institution remained responsible for writing its own host-to-IMP interface software and higher-level host protocols, a division of labor that created delays but also encouraged inter-site collaboration.

### 2.4 Purpose: resource sharing and defense

The 1981 BBN history describes the program’s immediate rationale as reducing duplication among IPTO-funded centers, improving scientific exchange, and developing techniques needed by the military. It calls the project wholly unclassified and says network service was initially supplied to government contractors as a “free good.” [BBN history](https://upload.wikimedia.org/wikipedia/commons/9/94/A_History_of_the_ARPANET%2C_The_First_Decade%2C_BBN_Report_4799%2C_April_1981.pdf)

The defense rationale is **disputed in emphasis, not wholly absent**:

- Taylor, Herzfeld, and many engineering histories emphasize interactive resource sharing and reject the simplified proposition that ARPANET was specifically built as a post-nuclear-war command network.
- Stephen Lukasik, ARPA deputy director and later director, wrote retrospectively that the higher-level justification included command and control under nuclear threat and survivable control of nuclear forces.
- Baran’s RAND system explicitly addressed survivability, but ARPANET did not simply implement Baran’s proposed nuclear-command network.
- BBN’s report said packet switching had direct command-and-control applications and that ARPANET-developed technology could be transferred to military experiments.

The strongest reconstruction is therefore: **documented** resource sharing was the immediate project and engineering objective; **documented** defense command-and-control utility formed part of ARPA’s institutional rationale; the claim that ARPANET itself was designed as an operational nuclear-war command network is false or at least unsupported; the claim that nuclear survivability played no part at any sponsoring-policy level is contradicted by Lukasik’s testimony. [Stephen Lukasik, “Why the Arpanet Was Built”](https://castig.org/wp-content/uploads/2022/06/1f84f-why-the-arpanet-was-built-.pdf)

---

## 3. Constituent Nodes

### 3.1 Meaning of “node”

Historical counts are often incompatible because **node**, **IMP**, **TIP**, **host**, **site**, **terminal**, and, after 1983, **network** are not synonyms.

- An **IMP node** was a packet switch.
- A **TIP** was an IMP-derived switch with direct terminal ports.
- A **host** was a computer attached to an IMP; several hosts could share one IMP.
- A **site** was an institution or physical location, sometimes containing several hosts and switches.
- A **terminal** was not ordinarily counted as a host.
- A gateway could connect an entire external network, making many machines reachable without making each one an ARPANET host.

Contemporary maps sometimes label IMP names rather than host names. The June 1977 government map explicitly warns of this. [Government ARPANET map, June 1977](https://www.govinfo.gov/content/pkg/GOVPUB-C60-PURL-gpo5575/pdf/GOVPUB-C60-PURL-gpo5575.pdf)

### 3.2 The original four nodes

| Order | Site and location | IMP/host | Network role | Date |
|---|---|---|---|---|
| 1 | UCLA, Boelter Hall, Los Angeles | Honeywell 516 IMP; SDS Sigma 7 | Network Measurement Center; first IMP and first host | IMP delivered late Aug./early Sept. 1969 |
| 2 | Stanford Research Institute, Menlo Park | IMP; SDS 940 running NLS | Engelbart’s Augmentation Research Center; later Network Information Center | October 1969 |
| 3 | University of California, Santa Barbara | IMP; IBM 360/75 | Culler–Fried interactive mathematics and display research | November 1969 |
| 4 | University of Utah, Salt Lake City | IMP; DEC PDP-10 | Graphics research associated with Ivan Sutherland and collaborators | December 1969 |

The first hosts’ diversity—SDS Sigma 7, SDS 940, IBM 360/75, and DEC PDP-10—was deliberate evidence that the network was not a vendor-homogeneous system. [BBN history](https://upload.wikimedia.org/wikipedia/commons/9/94/A_History_of_the_ARPANET%2C_The_First_Decade%2C_BBN_Report_4799%2C_April_1981.pdf)

### 3.3 Early expansion, 1970–72

By June 1970 three East Coast nodes and two additional West Coast nodes had been added, together with two transcontinental lines. Thirteen IMPs existed by late 1970. By September 1971 the network had eighteen switching nodes and about twenty-three hosts in commonly cited contemporary counts; exact totals depend on whether TIPs and incompletely commissioned hosts are included. BBN says IMPs were initially delivered at approximately one per month. [BBN history](https://upload.wikimedia.org/wikipedia/commons/9/94/A_History_of_the_ARPANET%2C_The_First_Decade%2C_BBN_Report_4799%2C_April_1981.pdf)

Important additions included:

- **BBN, Cambridge:** IMP development, Network Control Center, experimental and service hosts.
- **MIT Project MAC:** Multics and other computing resources; major protocol work.
- **MIT Lincoln Laboratory, Lexington:** advanced computing and earlier Roberts networking work.
- **Harvard University, Cambridge:** research host and northeastern topology.
- **Carnegie Mellon University, Pittsburgh:** computing and artificial-intelligence research.
- **Case Western Reserve University, Cleveland:** computing research.
- **University of Illinois, Urbana:** ILLIAC and Center for Advanced Computation work.
- **RAND Corporation, Santa Monica:** defense research and computing.
- **System Development Corporation, Santa Monica:** time-sharing and defense-computing work.
- **NASA Ames Research Center, Moffett Field:** aerospace computing; later TIP access.
- **MITRE, Bedford/McLean-associated operations:** defense systems research and early TIP use.
- **Stanford University:** separate from SRI, with important computer-science and later internetworking work.
- **USC/Information Sciences Institute, Marina del Rey:** protocol development, RFC editing, naming, and service hosts.
- **ARPA headquarters and Pentagon-area facilities, Washington region:** sponsor and administrative users.

RFC 254, issued in October 1971, gives concrete remote-login scenarios for UCLA’s Sigma and IBM 360/91, SRI’s NIC and AI machines, UCSB, Utah, BBN, MIT, Multics, Harvard, and other systems. It demonstrates that the nominal topology corresponded to practical, if sometimes awkward, remote resource use. [RFC 254](https://www.rfc-editor.org/info/rfc254/)

### 3.4 Geographic clusters

By August 1972 the subnet had recognizable clusters around:

- Boston/Cambridge;
- Washington, D.C., northern Virginia, and Maryland;
- San Francisco Bay;
- Los Angeles/Santa Monica.

Intermediate nodes reduced dependence on a few transcontinental circuits. Other sites appeared in Utah, Illinois, Ohio, Pennsylvania, New York, Alabama, Florida, Texas, New Mexico, and elsewhere. BBN topology maps document growth from four nodes in December 1969 through the denser 1977 structure. [BBN history](https://upload.wikimedia.org/wikipedia/commons/9/94/A_History_of_the_ARPANET%2C_The_First_Decade%2C_BBN_Report_4799%2C_April_1981.pdf)

### 3.5 International reach

The first permanent overseas extensions appeared in 1973:

- **NORSAR**, the Norwegian Seismic Array near Kjeller, Norway, connected through a satellite arrangement involving the Tanum earth station in Sweden and the Seismic Data Analysis Center in Virginia.
- **University College London**, directed in networking work by Peter Kirstein, connected through the same general transatlantic infrastructure and became a major site for internetworking experiments.

Hawaii appeared through links associated with seismic and packet-radio work. The 1977 map shows NORSAR, London, and Hawaii connected by satellite circuits, but warns that experimental satellite connections were omitted. Thus a line on an ARPANET map can represent an administrative or dedicated circuit, not the full experimental SATNET topology. [Government map, June 1977](https://www.govinfo.gov/content/pkg/GOVPUB-C60-PURL-gpo5575/pdf/GOVPUB-C60-PURL-gpo5575.pdf)

Overseas reach did not make ARPANET a generally open international public network. Foreign sites were selected research or defense-related partners, and access remained sponsor-controlled.

### 3.6 Specialized and administrative nodes

#### BBN Network Control Center

The NCC in Cambridge monitored IMP status, loaded software, collected statistics, diagnosed failures, coordinated repairs, and could use the network to observe remote nodes. When conventional Honeywell field maintenance proved insufficient, BBN combined central expertise with specialized field personnel. [ARPANET Completion Report](https://nobbyville.com/ARAPNET-completion-report.pdf)

#### SRI Network Information Center

Douglas Engelbart’s Augmentation Research Center received the NIC role; Elizabeth “Jake” Feinler became its central long-term operator. The NIC:

- registered host names and addresses;
- maintained host tables;
- published directories and resource handbooks;
- distributed RFCs;
- recorded network liaisons;
- answered user queries;
- maintained online information in NLS/AUGMENT;
- later managed domains and Defense Data Network information.

The December 1978 directory was produced at SRI using the SRI-KL machine and Tymshare’s AUGMENT system. Its contents include individuals, network sponsors, liaison officers, host acronyms, addresses, computer configurations, and logical and geographic maps. [ARPANET Directory, December 1978](https://vtda.org/docs/computing/DefenceCommsAgency/ARAPNET_Directory_Dec78.pdf)

#### USC Information Sciences Institute

ISI became a central protocol and administrative node. Jon Postel edited RFCs, maintained assigned-number records, and coordinated protocol specifications. The transition of RFC editing from SRI toward ISI is visible around RFC 690 in 1975. [RFC 8700](https://www.rfc-editor.org/info/rfc8700/)

#### Terminal IMP sites

TIPs placed a Honeywell 316-based IMP and terminal concentrator at locations that did not require, or could not justify, a full host. Users connected terminals—locally or by dial-up—to the TIP and selected a remote host. The 316-based TIP cost about half as much as the original 516 IMP according to BBN’s retrospective. By the mid-1970s, TIPs widened practical access far beyond the number of formally attached host computers. [BBN history](https://upload.wikimedia.org/wikipedia/commons/9/94/A_History_of_the_ARPANET%2C_The_First_Decade%2C_BBN_Report_4799%2C_April_1981.pdf)

### 3.7 Representative 1977 node inventory

The June 1977 official map securely attests the following IMP/TIP labels, grouped geographically and functionally. A label does not necessarily identify one host:

- **West Coast and Pacific:** UCLA, RAND, USC, ISI-22, ISI-52, UCSD/NOSC, SRI-2, SRI-51, Stanford, Xerox, Tymshare, SUMEX, Ames-15, Ames-16, Moffett, Lawrence Berkeley Laboratory, Lawrence Livermore Laboratory, Utah, Hawaii, Fleet Numerical Weather Central and related sites.
- **Central and Southwest:** Illinois, Argonne, Texas, Air Force Weapons Laboratory, Wright-Patterson AFB, Scott AFB, Gunter AFB, Eglin AFB.
- **Northeast:** BBN-30, BBN-40, MIT-6, MIT-44, Lincoln Laboratory, Harvard, CCA, Carnegie Mellon, Rutgers, NYU, DEC, Rome Air Development Center.
- **Washington/Mid-Atlantic:** ARPA, Pentagon, NSA, National Bureau of Standards, Naval Research Laboratory, MITRE, Fort Belvoir, Aberdeen, and defense computer/communications establishments.
- **International:** NORSAR and London/UCL.

This is a representative physical-switch inventory, not a complete host list. Contemporary directories, rather than modern redrawn maps, are the appropriate authority for exact host affiliations at a given date. [Government map, June 1977](https://www.govinfo.gov/content/pkg/GOVPUB-C60-PURL-gpo5575/pdf/GOVPUB-C60-PURL-gpo5575.pdf)

### 3.8 What survives

Documented surviving materials include:

- IMP hardware in museums and institutional collections;
- UCLA’s 29 October 1969 IMP log;
- BBN engineering reports, code listings, maps, and oral histories;
- SRI ARC/NIC paper records and nine-track tapes;
- RFCs;
- host tables and directories;
- Network Working Group notes;
- films and photographs;
- participant papers at the Computer History Museum and universities.

The Computer History Museum’s SRI ARC/NIC collection covers design, administration, protocol development, naming, working groups, and participant lists. Some computer manuals, physical artifacts, and DEC-20 dump tapes were separated and catalogued individually. [CHM SRI ARC/NIC finding aid](https://archive.computerhistory.org/resources/access/text/finding-aids/102706170-SRI/102706170-SRI.pdf)

---

## 4. Connections

### 4.1 Physical links

Most early IMP-to-IMP connections were dedicated **50-kilobit-per-second** leased circuits. The Defense Commercial Communications Office arranged most through AT&T Long Lines; a smaller number came from other carriers such as General Telephone. ARPA created a dedicated point of contact at AT&T to coordinate carrier, contractor, and government work. [BBN history](https://upload.wikimedia.org/wikipedia/commons/9/94/A_History_of_the_ARPANET%2C_The_First_Decade%2C_BBN_Report_4799%2C_April_1981.pdf)

The lines formed a changing partial mesh, not one linear route. BBN and Network Analysis Corporation selected edges according to cost, expected traffic, delay, reliability, geographic growth, and the need for alternate paths. A famous map line is therefore not analogous to a road used by every packet between its endpoints: adaptive routing could send traffic through different sequences of IMPs as conditions changed.

Satellite circuits extended the system to Hawaii, Norway, and London. Experimental packet satellite traffic belonged partly to SATNET and internetworking research rather than solely to the production ARPANET.

### 4.2 Host-to-IMP connections

A host used a hardware interface defined in BBN Report 1822. It supplied a message and destination to the local IMP. The IMP accepted messages of bounded size, broke them into packets where required, added control information, and transmitted them. Standardizing this boundary reduced—but did not eliminate—the work each site had to perform.

Hosts initially varied in word size, character encoding, operating system, and terminal conventions. Considerable engineering was required to connect 8-, 16-, 24-, 32-, 36-, and 60-bit machines to an 8-bit-oriented communication environment.

### 4.3 IMP-to-IMP forwarding

At the packet-switching layer:

1. A source IMP chose a next hop according to its routing information.
2. It transmitted a packet over a leased line.
3. A 24-bit cyclic checksum protected the transmission.
4. The adjacent IMP recomputed the checksum.
5. Correct reception produced an acknowledgment.
6. Absence of acknowledgment caused retransmission.
7. The packet was stored and forwarded until it reached the destination IMP.
8. The destination IMP reassembled the host message and delivered it to the destination host.

The original subnet attempted reliable delivery for the hosts. This later mattered because NCP assumed a single reliable network, while TCP/IP was designed for heterogeneous component networks that could lose, duplicate, or reorder datagrams. [BBN history](https://upload.wikimedia.org/wikipedia/commons/9/94/A_History_of_the_ARPANET%2C_The_First_Decade%2C_BBN_Report_4799%2C_April_1981.pdf)

### 4.4 Major logical connections

#### Remote login

TELNET created a network virtual terminal abstraction. A user at one machine could interact with a program on another, but differences in echoing, character sets, line discipline, control characters, and interrupt handling produced prolonged debate. A broadly usable early TELNET was implemented by late 1972. [BBN history](https://upload.wikimedia.org/wikipedia/commons/9/94/A_History_of_the_ARPANET%2C_The_First_Decade%2C_BBN_Report_4799%2C_April_1981.pdf)

#### File transfer

FTP established control and data connections through which users moved files between unlike systems. It had to negotiate representations and commands across operating systems. Electronic mail initially rode on file-transfer mechanisms before SMTP became a distinct TCP-based transfer protocol.

#### Remote job entry

RJE allowed a user to submit a batch job to a distant host and recover output. It embodied the original resource-sharing conception but proved less socially dominant than interactive login and mail.

#### Electronic mail

Mail connected named user mailboxes on hosts. Ray Tomlinson at BBN adapted SNDMSG and CPYNET to send between machines and selected `@` to divide local user from host. Abhay Bhushan and others incorporated mail transfer into ARPANET FTP specifications. Larry Roberts wrote an influential mail-management program with listing, reading, replying, forwarding, and filing functions.

The famous claim that email constituted **75 percent of ARPANET traffic by 1973** is not securely documented in the form usually repeated. Later accounts variously identify a 1973 ARPA study or a 1974 MITRE study, but the original measurement report is elusive. The figure should be treated as **plausible but inadequately sourced**, not a precise audited statistic. Historians discussing the issue have traced it primarily to participant recollection. [SIGCIS discussion of the 75-percent claim](https://lists.sigcis.org/archives/list/members%40lists.sigcis.org/message/ZHE7PTQNSLKAITT3IRQLI4CE73IKLBRO/)

#### Mailing lists and discussion groups

Network mail rapidly supported group communication. Notable lists included MsgGroup, human-factors and protocol discussions, and SF-Lovers, a science-fiction list. These carried technical work, announcements, jokes, arguments, popular culture, and community formation. They reveal that the network moved social relationships and organizational authority as well as machine-readable data.

### 4.5 Frequency, speed, cost, and risk

Traffic was bursty and statistically multiplexed. Unlike a telephone call, a user did not reserve an end-to-end circuit for the session. Many users’ packets shared the same physical links.

No universal per-message charge existed for early authorized users. ARPA paid network development and line costs; participating projects paid for local hosts, interfaces, staff, and sometimes sponsor-assessed network costs. This “free good” at point of authorized use promoted experimentation but concealed substantial public expenditure and institutional cross-subsidy.

Transmission delay depended on packet length, hop count, congestion, host response, and retransmission. On a 50-kilobit line, a 1,000-bit packet requires roughly 20 milliseconds merely to serialize, excluding propagation, switching, acknowledgment, queuing, and host delay. This is a calculation from line rate, not a measured universal ARPANET transit time.

Risks included:

- telephone-circuit outage or noise;
- switch hardware and software failure;
- routing instability;
- congestion and reassembly-resource exhaustion;
- incompatible host implementations;
- weak passwords and unauthorized remote login;
- disclosure through shared hosts;
- incorrect or stale host tables;
- administrative disconnection;
- satellite-link delay and loss.

---

## 5. Agents and Operators

### 5.1 Government sponsors and managers

- **J.C.R. Licklider:** IPTO director, 1962–64; articulated interactive-computing and “Galactic Network” ideas.
- **Ivan Sutherland:** succeeding IPTO director; continued advanced computing programs.
- **Robert W. Taylor:** IPTO director from 1966; initiated the network project and recruited Roberts.
- **Charles M. Herzfeld:** ARPA director who authorized the project.
- **Lawrence G. Roberts:** ARPA program manager and principal planner; managed topology, procurement, demonstrations, and early applications.
- **Stephen J. Lukasik:** ARPA deputy director and director during deployment and expansion; emphasized defense command-and-control justification.
- **Robert Kahn:** BBN system architect and later ARPA program manager; organized the 1972 public demonstration and initiated internetworking architecture.
- **Vinton Cerf:** UCLA/Stanford researcher and later ARPA program manager; co-designed TCP with Kahn and managed Internet development.
- **Barry Wessler and later DCA/DDN personnel:** participated in security, transition, and operational management.
- **Jon Postel:** protocol editor, assigned-numbers administrator, implementer, and coordination authority—mostly through trusted service rather than statutory office.
- **Elizabeth Feinler:** led NIC operations and supervised directories, host registration, name service, and user support.

### 5.2 BBN builders and maintainers

Frank Heart’s IMP group included Severo Ornstein, Will Crowther, Dave Walden, Bob Kahn, Bernie Cosell, Ben Barker, Hawley Rising, Alex McKenzie, John McQuillan, and others. Their collective work included:

- switch hardware selection and modification;
- assembly-language routing and packet software;
- host interfaces;
- TIP and Pluribus development;
- network measurements;
- central monitoring;
- field installation;
- maintenance;
- reports and operational coordination.

Attributing the IMP or ARPANET to one engineer erases the distributed production process. BBN’s own history identifies overlapping architecture, software, hardware, installation, maintenance, and management contributions.

### 5.3 Host implementers and Network Working Group

The host protocol was not supplied completely by BBN. Graduate students and programmers at UCLA, SRI, UCSB, Utah, MIT, BBN, and later sites formed the Network Working Group. Important names included:

- Steve Crocker;
- Jon Postel;
- Vint Cerf;
- Bill Duvall;
- Jeff Rulifson;
- Abhay Bhushan;
- Alex McKenzie;
- Joel Winett;
- Richard Kalin;
- Dave Crocker;
- Ray Tomlinson.

The RFC process began because the group needed a quick, informal way to circulate uncertain proposals. RFC 1, *Host Software*, was dated 7 April 1969. The phrase **Request for Comments** was intentionally non-imperial: participants lacked both complete knowledge and a settled formal authority. [RFC history](https://www.rfc-editor.org/info/rfc8700/)

### 5.4 Local labor

Every site required labor that is less visible in heroic histories:

- host programmers;
- system administrators;
- operators;
- electrical and telecommunications technicians;
- network liaison officers;
- clerical and directory staff;
- carrier installers;
- security officers;
- maintenance engineers;
- researchers who wrote user programs and documentation.

No evidence indicates that enslaved labor was involved. The network was, however, a product of military appropriation, defense contracting, hierarchical employment, university research labor, and Cold War state power. Some graduate students performed essential implementation work while possessing far less institutional authority than government managers and principal investigators. Statements that they worked specifically to avoid Vietnam-era conscription are biographically true for some individuals but cannot safely be generalized to the entire workforce.

### 5.5 Users

Authorized users included:

- ARPA program managers;
- university and contractor researchers;
- military and civilian government personnel;
- computer scientists and engineers;
- artificial-intelligence, graphics, mathematics, seismic, weather, and biomedical researchers;
- visiting users holding accounts on remote machines;
- students and staff admitted under local site rules.

The network was not open to the general public. Access depended on a participating institution, sponsor approval, a host account, or an authorized terminal facility. Some hosts offered guest or demonstration accounts, but this was local generosity rather than a universal public right.

### 5.6 Commercial participants

Private firms occupied several roles:

- **BBN:** prime network contractor and operator.
- **Honeywell:** supplied the 516 and 316 processor base and initially field maintenance.
- **AT&T Long Lines and other carriers:** leased circuits.
- **Network Analysis Corporation:** topology consulting.
- **Tymshare, Xerox, DEC, CCA, and others:** hosts, research sites, vendors, or users.
- **Telenet:** founded by Larry Roberts and others as a commercial packet-switched network influenced by ARPANET; it was separate from ARPANET.

Commercial participation did not make ARPANET itself a public commercial service.

---

## 6. Operation and Mechanism

### 6.1 Governance

ARPANET combined centralized and decentralized authority.

Centralized functions included:

- federal sponsorship and admission;
- BBN control of IMP software releases;
- topology and circuit procurement;
- NCC monitoring;
- NIC naming and directory publication;
- sponsor policy;
- DCA/DDN operational administration after 1975.

Decentralized functions included:

- host ownership and operating systems;
- local account authorization;
- host protocol implementation;
- application creation;
- informal RFC discussion;
- site-level security;
- research use.

This distribution created innovation but also chronic compatibility and security problems. A correctly operating subnet could not force a host to implement TELNET, FTP, mail, or TCP correctly.

### 6.2 Financing and ownership

During development, DARPA paid BBN, line costs, network design work, NIC functions, and research contracts. Host institutions generally controlled their large computers while the federal government funded many of them wholly or partly.

A memorandum transferred management to the Defense Communications Agency effective **1 July 1975**, followed by a six-month transition ending 31 December. Sponsor organizations retained ownership of equipment assigned to them. DCA financed operations and maintenance through its Communications Industrial Fund and recovered costs through prorated allocations to sponsors based on equipment use. DCA initially continued contracts with BBN for operation and maintenance, SRI for NIC services, and potentially Network Analysis Corporation for topology work. The network was declared an operational DoD facility for government business. [BBN history](https://upload.wikimedia.org/wikipedia/commons/9/94/A_History_of_the_ARPANET%2C_The_First_Decade%2C_BBN_Report_4799%2C_April_1981.pdf)

A complete year-by-year expenditure ledger has not been reconstructed here. Frequently repeated single figures for “the cost of ARPANET” mix initial IMP procurement, research grants, leased circuits, host computers, and later operations and should not be treated as comparable without accounting definitions.

### 6.3 Routing and reliability

Original IMP routing was distributed and adaptive. Each IMP derived estimates of path delay and exchanged routing information with neighbors. Messages could follow alternate paths when links or nodes failed. Routing algorithms changed when early designs exhibited oscillation or poor behavior under load.

Reliability mechanisms included:

- checksums;
- link acknowledgments and retransmission;
- sequence information;
- store-and-forward buffering;
- duplicate suppression;
- status reports;
- automatic routing around failed components;
- centrally observed switch statistics;
- software release control;
- field maintenance.

Redundancy was real but not absolute. A site with a single IMP, one host interface, or a single local circuit could still be cut off. Multiple paths in the national topology did not make every endpoint indestructible.

### 6.4 Network Control Program

NCP was the host-to-host communication system used operationally from roughly 1971 through 1982. Its Initial Connection Protocol established communication sockets; flow-control commands allocated message and bit capacity; application protocols operated above it.

“NCP” has been expanded both as **Network Control Program** and, retrospectively, **Network Control Protocol**. Contemporary usage often meant the host software implementing a family of protocols rather than one monolithic protocol. RFC 60, for example, explicitly calls for an NCP process and describes duplex links, sockets, buffers, and flow control. [RFC 60](https://www.rfc-editor.org/rfc/rfc60.html)

NCP relied upon the ARPANET subnet to provide reliable delivery to a destination host on the same network. It had no general means to address an arbitrary host behind another packet network. This architectural limit was central to TCP’s development.

### 6.5 TCP/IP

Kahn’s internetworking principles included:

- each component network would stand independently;
- component networks would not require internal redesign to join;
- communication would be best effort;
- hosts would retransmit lost data;
- gateways would connect networks without keeping per-flow state;
- there would be no single global operational controller.

Cerf and Kahn published an initial Transmission Control Program design in 1974. Later experimentation separated internetwork packet delivery into IP and reliable end-to-end transport into TCP. Production standards included IPv4 in RFC 791 and TCP in RFC 793.

Jon Postel’s November 1981 transition plan ordered implementation work, temporary dual-protocol and relay services, completion during 1982, and full TCP/IP service on **1 January 1983**. Mail relays were especially important; TELNET and FTP relays were used less. [RFC 801](https://www.rfc-editor.org/info/rfc801/), [RFC 942](https://www.rfc-editor.org/info/rfc942/)

### 6.6 Naming and directories

At first, users and programs depended on centrally distributed host tables. A site supplied its host information to the NIC; the NIC maintained an authoritative file; hosts periodically fetched updated copies. As the Internet expanded, this process became operationally unwieldy and was replaced by the hierarchical Domain Name System.

ARPANET subsequently appeared as the top-level domain `.ARPA`/`ARPANET` in transitional naming schemes. RFC 830 described `user@host` as the ARPANET naming convention and treated host names as a flat subdomain during transition. [RFC 830](https://www.rfc-editor.org/rfc/rfc830.html)

### 6.7 Maintenance

Honeywell initially maintained IMP hardware using its national field organization. BBN concluded this general-purpose arrangement did not meet the subnet’s reliability needs. BBN then took maintenance more directly in hand:

1. the NCC observed anomalous behavior remotely;
2. central specialists diagnosed probable hardware, software, or line causes;
3. local field personnel performed physical tests or replacement;
4. BBN tracked configuration and released controlled software;
5. carriers were contacted when evidence indicated circuit trouble.

The network was therefore both the object and instrument of maintenance: engineers used ARPANET to monitor ARPANET. [ARPANET Completion Report](https://nobbyville.com/ARAPNET-completion-report.pdf)

### 6.8 Worked example: the first UCLA–SRI message

The best-documented emblematic transaction occurred on **29 October 1969 at approximately 22:30 Pacific time**.

1. **Source:** UCLA’s SDS Sigma 7 in Boelter Hall 3420.
2. **Source operator:** student programmer Charles Kline, working with Leonard Kleinrock’s group.
3. **Destination:** SRI’s SDS 940 in Menlo Park, running Engelbart’s NLS environment.
4. **Coordination:** Kline and SRI programmer Bill Duvall communicated by telephone while testing the connection.
5. **Intended application action:** type `LOGIN`.
6. **First transfer:** UCLA sent `L`; SRI confirmed receipt.
7. **Second transfer:** UCLA sent `O`; SRI confirmed receipt.
8. **Failure:** the SRI host crashed as the third character was attempted.
9. **Recorded result:** the first attempt therefore delivered `LO`, not a deliberately composed message “lo.”
10. **Recovery:** the systems were repaired and a complete login succeeded later that night.

The UCLA IMP log is the principal contemporary artifact. DARPA reproduces it and fixes the time at 22:30. The familiar story that “LO” prophetically meant “lo and behold” is a retrospective joke, not the sender’s intended content. [DARPA, “ARPANET”](https://www.darpa.mil/news/features/arpanet)

End to end, the keystrokes passed from UCLA’s terminal/application environment into host software, across the Sigma 7–IMP interface, through UCLA’s IMP, along the leased circuit, into SRI’s IMP and host interface, and finally to the login process on the SDS 940. The telephone voice call used to coordinate the experiment remained an indispensable out-of-band control channel.

### 6.9 Worked example: an early electronic mail transfer

A typical early NCP/FTP mail transfer proceeded as follows:

1. A user composed text with a local program such as SNDMSG.
2. The program parsed an address of the form `user@host`.
3. The local host table translated the host name into an ARPANET address.
4. NCP opened a logical connection to the destination host’s file-transfer/mail service.
5. FTP mail commands supplied sender and recipient information.
6. The source host passed message data to its IMP.
7. IMPs routed packets across shared 50-kilobit links.
8. The destination IMP reassembled and delivered the message to its host.
9. The receiving program appended or deposited the message in the recipient’s mailbox file.
10. The recipient later read it with a local mail program.

The procedure was not universally seamless: mail programs differed, host tables became stale, mailbox formats varied, machines went down, and NCP-era mail initially used FTP rather than a cleanly separated SMTP service. During the NCP/TCP transition, relay hosts accepted mail in one protocol environment and forwarded it into the other. [RFC 771](https://www.rfc-editor.org/rfc/pdfrfc/rfc771.txt.pdf), [RFC 773](https://www.rfc-editor.org/info/rfc773/)

---

## 7. Change over the Lifespan

### Phase I: conception and construction, 1966–69

Taylor organized the program; Roberts planned it; the packet-switching proposal absorbed lessons from Kleinrock, Davies/NPL, Baran/RAND, and prior remote-computing experiments. BBN won the IMP contract and built the first switches. Host sites formed the Network Working Group. Four nodes operated by the end of 1969.

### Phase II: basic subnet and protocols, 1970–71

The network expanded across the United States. IMP software, routing, measurement, host interfaces, and NCP stabilized unevenly. The first years exposed the difference between installing switches and producing useful host services. RFCs became the system’s working documentary memory.

By September 1971, commonly cited counts give eighteen nodes and twenty-three hosts, though contemporary readiness varied. Remote-login scenarios document which systems could actually be tried. [RFC 254](https://www.rfc-editor.org/info/rfc254/)

### Phase III: public demonstration and social utility, 1972–74

Robert Kahn organized the October 1972 International Conference on Computer Communications demonstration in Washington. Terminals accessed geographically dispersed machines, presenting the network to a wider professional public.

Electronic mail became the most socially consequential application. Mailing lists and asynchronous coordination changed the network from a remote-computer utility into a community infrastructure. International connections to Norway and London appeared in 1973.

Cerf and Kahn’s internetworking work distinguished a network of heterogeneous networks from ARPANET itself. Packet-radio and packet-satellite experiments tested conditions—loss, mobile nodes, long delays—for which NCP was inadequate.

### Phase IV: operationalization under DCA, 1975–79

Management transferred from DARPA to DCA beginning 1 July 1975. This was a major legal-administrative reorganization:

- ARPANET became an operational DoD facility;
- sponsor categories and cost recovery were formalized;
- equipment ownership remained distributed;
- BBN and SRI continued contracted operational roles;
- research continued on and around the operational system.

The Pluribus multiprocessor switch provided additional capacity at selected nodes. TIPs expanded terminal access. By 1977 maps showed a dense national subnet with satellite connections to Europe and Hawaii.

The December 1978 directory’s hundreds of pages demonstrate a mature socio-technical bureaucracy: sponsors, liaisons, addresses, host configurations, individuals, maps, and operating instructions. [ARPANET Directory](https://vtda.org/docs/computing/DefenceCommsAgency/ARAPNET_Directory_Dec78.pdf)

### Phase V: transition to Internet protocols, 1980–82

The coexistence of ARPANET, packet-radio, satellite, Ethernet, and other networks made internetworking operationally necessary. TCP/IP implementations existed on several operating systems, but conversion required every host organization to rewrite or acquire software.

The transition plan created:

- dual-protocol hosts;
- TCP-only and NCP-only hosts;
- relay systems;
- new mail procedures;
- revised host tables;
- implementation deadlines;
- a coordinated flag day.

RFC 801’s milestones called for final NCP conversion during 1982 and removal of NCP service on 1 January 1983. This was an administratively enforced technological reconstitution, not spontaneous adoption. [RFC 801](https://www.rfc-editor.org/info/rfc801/)

### Phase VI: TCP/IP and MILNET split, 1983–84

On **1 January 1983**, ARPANET’s production service changed from NCP to TCP/IP. Some nonconforming systems were temporarily isolated or required conversion assistance. Later assessment found mail relays heavily used and reported NIC readiness and performance-tuning problems. [RFC 942](https://www.rfc-editor.org/info/rfc942/)

On **4 October 1983**, ARPANET and MILNET were logically separated. Physical restructuring continued into 1984. Roughly sixty-eight of 113 switching nodes are frequently reported as moving to MILNET; the count is credible but should be understood as a count of network nodes under the split plan, not of every attached computer or user.

MILNET took most routine unclassified military operational traffic. ARPANET retained research sites. Controlled gateways joined them, with provisions for stronger separation in emergency. A contemporary UPI report described the October logical division and a later physical split. [UPI archive, 4 October 1983](https://www.upi.com/Archives/1983/10/04/The-Defense-Department-electronically-separated-its-nationwide-computer-network/8814434088000/)

### Phase VII: declining backbone role, 1985–89

ARPANET remained useful but no longer defined the scale or architecture of the Internet. The Defense Data Network supplied military networking; NSF funded CSNET and then NSFNET; universities deployed campus Ethernets and regional networks; other federal agencies operated discipline-specific systems.

NSFNET began in 1986 and connected a far broader academic constituency through regional networks. Its backbone rose from 56-kilobit circuits to T1 service in 1988. ARPANET increasingly duplicated routes available through the Internet and NSFNET. [NSF, “Birth of the Commercial Internet”](https://www.nsf.gov/impacts/internet)

The 1988 Morris worm affected the wider TCP/IP Internet, including research systems descended from the ARPANET environment. It was not simply an “ARPANET worm,” but it exposed weaknesses—trusted hosts, vulnerable network services, homogeneous software populations, and insufficient incident coordination—within the system ARPANET had helped produce. RFC 1087, issued in January 1989, declared unauthorized access, disruption, resource wasting, destruction of information integrity, and privacy compromise unacceptable. [RFC 1087](https://www.rfc-editor.org/info/rfc1087/)

### Phase VIII: retirement, 1990

By 1990, traffic could use NSFNET, regional, DDN, and other Internet infrastructure. The remaining ARPANET IMP subnet was shut down. Hosts did not lose the conceptual protocols or necessarily lose connectivity; they migrated to successor networks.

---

## 8. End or Transformation

### 8.1 Proximate causes

ARPANET was retired because:

- its original switching equipment was aging;
- TCP/IP had made the particular IMP subnet only one possible carrier;
- MILNET had absorbed most operational military nodes;
- NSFNET and regional networks provided broader and faster research connectivity;
- modern routers and local-area networks displaced direct dependence on IMPs;
- maintaining a redundant legacy backbone no longer justified its cost.

There was no enemy destruction, judicial suppression, bankruptcy, or single catastrophic failure.

### 8.2 Structural causes

ARPANET succeeded itself out of existence. Its most consequential innovation was not one permanent network but a set of practices allowing unlike networks and machines to interoperate. Once IP could run over Ethernet, satellite, radio, leased lines, NSFNET, DDN, and commercial networks, the original ARPANET subnet ceased to be indispensable.

### 8.3 What happened to the assets

- IMP and TIP machines were powered down, scrapped, stored, transferred, or preserved.
- Hosts migrated to other gateways and networks.
- BBN’s operational expertise flowed into commercial networking and router development.
- NIC functions continued within the DDN/Internet naming and registration system.
- RFC publication continued.
- MILNET and later defense networks inherited operational military functions.
- NSFNET and regional networks inherited much of the American academic-backbone role.
- TCP/IP, DNS, email, FTP, TELNET, routing research, and distributed administrative practices survived independently of ARPANET.

### 8.4 Records

Records survive principally at:

- the Computer History Museum;
- SRI International–related collections;
- DARPA and Defense Technical Information Center holdings;
- the RFC Editor archive;
- UCLA;
- BBN/Raytheon-related and private collections;
- university archives;
- Internet Society oral-history projects;
- the National Archives and federal technical-report repositories.

Not everything survives. Operational email was not comprehensively archived; many host files and informal discussions disappeared; classified adjacent programs remain unevenly available; software exists in incomplete versions; and institutional archives preserve managerial actors better than routine users.

### 8.5 Successors

No single system “replaced” ARPANET:

- **MILNET/DDN** succeeded its operational defense component.
- **NSFNET** became the principal American academic Internet backbone.
- **Regional and campus networks** absorbed endpoint connectivity.
- **Commercial Internet service providers** later supplied general-purpose connectivity.
- **The Internet** inherited and generalized its protocol culture and interconnection function.

---

## 9. Failures, Abuse, Security Incidents, and Controversies

### 9.1 Technical failures

Early problems included:

- late or incomplete host protocol implementations;
- hosts that technically attached but supplied little useful service;
- line errors and outages;
- IMP crashes;
- routing oscillations and congestion;
- reassembly-buffer exhaustion;
- terminal incompatibility;
- inadequate automated resource discovery;
- poor coordination between independent host administrators.

The first message itself ended in a host crash after two characters. This is documented failure, not evidence that the network as a whole failed.

### 9.2 Resource sharing fell short of its strongest claims

The founding rationale emphasized access to specialized remote computing. Remote login and file transfer did become important, but automatic program-to-program resource sharing developed more slowly. BBN later acknowledged that ambitious NIC resource-discovery plans were reduced and that users often needed to contact a site directly for detailed information. Email and interpersonal collaboration became more important than planners initially expected. [BBN history](https://upload.wikimedia.org/wikipedia/commons/9/94/A_History_of_the_ARPANET%2C_The_First_Decade%2C_BBN_Report_4799%2C_April_1981.pdf)

### 9.3 Security weaknesses

ARPANET was unclassified, but attached hosts could contain valuable research, account privileges, or connections to sensitive institutions. Its early community assumed a relatively small, identifiable, cooperative user population. Authentication and isolation were largely host responsibilities. Password guessing, shared accounts, excessive trust, experimental software, and inconsistent logging created vulnerabilities.

The Ware task force, created under ARPA auspices in 1967 and published in classified form in 1970, analyzed threats to multi-access computer systems. Its concern extended beyond ARPANET but directly described the security environment in which networked time-sharing developed. The declassified 1979 report discussed unauthorized disclosure, Trojan horses, access control, physical protection, and management responsibility. [Ware report](https://cryptome.wikileaks.org/sccs.htm)

A 1977 General Accounting Office investigation found continuing vulnerabilities in telecommunications and computer systems. It should not be read as proof that every listed weakness was exploited on ARPANET, but it establishes official concern that remote access expanded opportunities for unauthorized use. [GAO, *Vulnerabilities of Telecommunications Systems to Unauthorized Use*](https://www.gao.gov/products/lcd-77-102)

### 9.4 The 1978 DEC mass mailing

On 3 May 1978, Gary Thuerk of Digital Equipment Corporation sent an unsolicited announcement for DEC computer demonstrations to several hundred West Coast ARPANET addresses. The message was commercial promotion transmitted through a government-funded research network and generated complaints from administrators and users.

It is often called “the first spam.” That label is retrospective: the word *spam* was not then used in its modern email sense, and earlier unwanted mass messages may have existed. It is securely documented as an early notorious unsolicited commercial mass email, not necessarily the first unwanted message of every kind.

### 9.5 Social and administrative abuse

Mailing lists sometimes generated off-topic traffic, personal disputes, excessive distribution, and sponsor concern over government resources. Science-fiction and recreational lists were periodically defended as community-building and criticized as inappropriate use. These disputes illustrate that “use” was negotiated rather than mechanically determined by the network’s technical design.

### 9.6 Worms and malicious code

Bob Thomas’s early-1970s **Creeper** experiment and Ray Tomlinson’s **Reaper** are often called the first computer worm and antivirus program. Terminology is retrospective, and surviving technical documentation is thinner than popular retellings. Creeper was an experimental self-relocating program on TENEX systems, not a criminal attack comparable to later malware.

The 1988 Morris worm was a documented disruptive event on the larger Internet. Its estimated affected-host counts vary widely, commonly around several thousand; contemporary counting was imprecise. ARPANET was then one backbone among several and should not be presented as the sole attacked network.

### 9.7 Espionage and surveillance

Defense and intelligence institutions, including NSA-labelled facilities, appeared as ARPANET nodes or sponsors. This establishes institutional participation, not that ARPANET was itself a comprehensive surveillance system. Network Control Center measurements and logs permitted operational observation of traffic volume and faults; host systems could log sessions. Evidence used here does not establish routine centralized reading of all user content.

The network’s unclassified status barred it from carrying classified operational material as such. Separate secure systems and later classified defense networks served other functions. Unauthorized transmission of classified information may have been possible as a rule violation, but no comprehensive incident ledger has been established here.

### 9.8 Monopoly and extraction

AT&T’s regulated long-distance infrastructure supplied most early circuits. ARPA’s dependence on a dominant common carrier affected cost and provisioning, but ARPANET did not exercise monopoly violence in the historical sense associated with territorial trade networks. Its exclusions arose from federal sponsorship, contractor status, institutional admission, and scarce computing resources.

No documented role for slavery, forced labor, pilgrim traffic, tribute, or religious coercion applies to this network. Their absence should be stated rather than analogically manufactured.

---

## 10. Contested and Legendary Aspects

### 10.1 “Built to survive nuclear war”

**Story:** ARPANET was deliberately created so American command could survive a Soviet nuclear attack.

**Evidence for a qualified version:**

- Baran’s distributed communications research explicitly concerned survivable military communication.
- ARPA existed within the Defense Department.
- Lukasik later stated that command and control under nuclear threat and survivable control of nuclear forces helped justify the expenditure.
- Adaptive routing and distributed switching had obvious military survivability value.

**Evidence against the popular strong version:**

- ARPANET’s project documents emphasize resource sharing among research computers.
- It was unclassified, initially small, and connected vulnerable university and contractor sites.
- It lacked the hardened terminals, protected transmission, security, redundancy at every site, and assured command procedures necessary for an operational nuclear-command system.
- Taylor and Herzfeld rejected the simple nuclear-survival origin story.
- ARPANET did not directly reproduce Baran’s proposed network.

**Finding:** The statement is **false as a literal engineering description**, **partly grounded as a higher-level defense rationale**, and **disputed among participants according to institutional vantage point**. [Lukasik](https://castig.org/wp-content/uploads/2022/06/1f84f-why-the-arpanet-was-built-.pdf), [Taylor oral history](https://archive.computerhistory.org/resources/text/Oral_History/Taylor_Robert/102702015.05.01.acc.pdf)

### 10.2 “The first message was LO”

**Story:** The first Internet message was the meaningful word “LO.”

**Documented core:** `L` and `O` reached SRI before the remote host crashed.

**Correction:** The intended command was `LOGIN`; “LO” acquired symbolic meaning afterward. Calling it the first **Internet** message is anachronistic if Internet is reserved for the later internetwork, but it was the first recorded ARPANET host-to-host message attempt. [DARPA](https://www.darpa.mil/news/features/arpanet)

### 10.3 “One person invented the Internet”

Claims favoring Licklider, Kleinrock, Baran, Davies, Roberts, Taylor, Kahn, Cerf, Postel, or Berners-Lee generally collapse different inventions:

- vision of interactive networked computing;
- queueing analysis;
- distributed survivable networks;
- packet terminology;
- IMP architecture;
- operational packet networking;
- host protocols;
- internetworking;
- TCP/IP;
- administration and naming;
- the World Wide Web.

ARPANET’s record supports a distributed invention involving state sponsorship, contractors, university groups, standards authors, telecommunications carriers, and users.

### 10.4 “ARPANET was the Internet”

This is useful shorthand but historically imprecise. ARPANET was a predecessor and later component of the Internet. The conceptual distinction became concrete when gateways joined ARPANET to packet radio, satellite, and other networks. On 1 January 1983 ARPANET adopted the Internet protocol suite; it did not thereby encompass every Internet network.

### 10.5 “Email was 75 percent of traffic in 1973”

The statistic is widely repeated. Later testimony attributes it variously to a 1973 ARPA study or 1974 MITRE study, but the underlying report and measurement definitions have not been securely recovered here.

Questions include:

- bytes, packets, messages, or connection time?
- internode traffic only?
- representative week or annual total?
- mail data alone or FTP sessions used to move mail?
- whether administrative and mailing-list traffic were included?

**Finding:** email’s rapid dominance is documented qualitatively; **75 percent** is an **inadequately verified retrospective statistic**. [SIGCIS source discussion](https://lists.sigcis.org/archives/list/members%40lists.sigcis.org/message/ZHE7PTQNSLKAITT3IRQLI4CE73IKLBRO/)

### 10.6 “The network was decentralized and ungoverned”

Routing was distributed, host administration was local, and RFC collaboration was comparatively informal. Nevertheless:

- ARPA selected and funded participants;
- BBN controlled IMP software;
- central offices procured circuits;
- the NCC monitored the subnet;
- the NIC controlled authoritative tables and registrations;
- DCA imposed operational policy;
- sponsors could deny or withdraw access;
- the 1983 protocol conversion was centrally scheduled.

The legend confuses distributed packet forwarding with absence of institutional power.

### 10.7 “ARPANET was public and egalitarian”

Within its contractor community it often encouraged unusually open technical exchange. It was not public infrastructure available on equal terms to all citizens. Access required institutional position, sponsor approval, an account, or cooperation from an authorized user. Universities outside favored disciplines often could not join, one reason CSNET and NSFNET became important.

### 10.8 “ARPANET ended in 1983”

The 1983 transition is sometimes called its end because NCP disappeared and the Internet protocol suite took over. This is a defensible **architectural periodization**, not a physical or administrative shutdown date. The ARPANET subnet retained its name and operated until 1990.

### 10.9 “ARPANET ended in 1989”

DARPA’s visual timeline labels 1989 as the end, whereas other institutional sources use 1990. This may refer to the decision or practical completion of migration rather than the final formal decommissioning. With the sources used here, **1990 is better supported for formal retirement**, while late 1989 may mark effective obsolescence or staged shutdown. [DARPA innovation timeline](https://www.darpa.mil/about/innovation-timeline/arpanet), [NSFNET timeline](https://nsf.net/timeline)

---

## 11. Historiography and Representations

### 11.1 Foundational technical histories

#### BBN, *ARPANET Completion Report* and *A History of the ARPANET: The First Decade*

These are indispensable insider technical histories. They reconstruct design choices, topology, protocol evolution, maintenance, handover to DCA, and lessons learned. Their strength is proximity to the IMP contractor record. Their limitation is institutional: BBN’s subnet work receives greater resolution than users, excluded institutions, competing networks, or political economy.

#### RFC archive

RFCs provide a serial documentary record from 1969 onward. They preserve provisional ideas, rejected proposals, transition plans, protocol specifications, operational complaints, host tables, etiquette, and jokes. They are primary evidence but not transcripts of all decisions: meetings, private correspondence, code, and implementation practice frequently diverged from an RFC.

#### SRI/NIC records

These illuminate naming, directories, documentation, resource discovery, working groups, user support, and the labor of making a network legible. The archive corrects histories focused solely on switching and protocol invention. [CHM finding aid](https://archive.computerhistory.org/resources/access/text/finding-aids/102706170-SRI/102706170-SRI.pdf)

### 11.2 Participant histories

Participant accounts by Taylor, Roberts, Kahn, Cerf, Kleinrock, Feinler, Crocker, Heart, Walden, Lukasik, and others preserve otherwise lost details. They also generate priority disputes:

- whose idea the network was;
- who first recognized packet switching;
- who selected particular speeds or architectures;
- whether defense command and control or research resource sharing was primary;
- what counts as the “first” message, protocol, email, router, or Internet demonstration.

Responsible historiography treats these testimonies as situated evidence rather than combining them into a frictionless heroic narrative.

### 11.3 Major scholarly interpretations

- **Janet Abbate, *Inventing the Internet*** emphasizes the transformation from military research network to international, civilian, standards-based infrastructure and gives proper weight to packet switching outside the United States.
- **Katie Hafner and Matthew Lyon, *Where Wizards Stay Up Late*** offers a vivid participant-centered narrative, especially of BBN and the original nodes; it sometimes reinforces a “great men and memorable moments” frame.
- **Arthur Norberg and Judy O’Neill, *Transforming Computer Technology*** situates IPTO and ARPA institutional policy.
- **Martin Campbell-Kelly and Daniel Garcia-Swartz** place ARPANET within the commercial history of computer communication.
- **Valérie Schafer and international networking historians** broaden the account beyond an exclusively American genealogy.
- **Joy Lisi Rankin, *A People’s History of Computing in the United States*** and **Claire L. Evans, *Broad Band*** redirect attention toward users, communities, and women’s work, though their scopes are broader than ARPANET.
- **Andrew Russell, *Open Standards and the Digital Age*** situates consensus standards and openness within longer institutional histories.
- **Paul Edwards, *The Closed World*** relates computing to Cold War command-and-control culture.

### 11.4 Archival biases and unresolved questions

Still incompletely reconstructable are:

- a precise, consistently defined annual cost series;
- total active users for each year;
- complete traffic composition by application;
- every host’s actual service dates;
- comprehensive records of unauthorized use;
- deleted or unpreserved personal email;
- the full contribution of technicians and junior staff;
- exact boundary between production ARPANET, DDN service, SATNET experiments, and the Internet at certain gateways;
- the final shutdown sequence for every IMP;
- the provenance of the “75 percent email” statistic.

### 11.5 Filmography, exhibitions, and popular representations

#### *Computer Networks: The Heralds of Resource Sharing* (1972)

This documentary recorded contemporary researchers explaining resource sharing and networked computing. Its value is temporal proximity. It reflects the program’s public self-presentation and predates the mature Internet.

#### DARPA anniversary exhibitions and timelines

DARPA’s online materials reproduce the UCLA log, early maps, IMP imagery, and a simplified four-node-to-Internet narrative. They are reliable for agency memory and selected artifacts but compress disputes and administrative complexity. [DARPA](https://www.darpa.mil/news/features/arpanet)

#### Computer History Museum exhibitions

CHM preserves oral histories, finding aids, artifacts, and timeline presentations. Its collections expose disagreements absent from celebratory timelines. [CHM Internet History](https://www.computerhistory.org/internethistory/1960s/)

#### *Where Wizards Stay Up Late*

The book remains the best-known narrative history. It popularized the BBN engineering story and the failed `LOGIN` episode. It should be supplemented by institutional, international, labor, and policy histories.

#### Television and web retellings

Popular accounts frequently:

- call ARPANET “the Internet” from 1969;
- treat `LO` as an intentional message;
- say nuclear-war survival was the sole purpose;
- credit one inventor;
- move the invention of email to a single precise instant;
- omit NPL, Cyclades, packet radio, SATNET, DCA, NIC labor, and the military/civil split.

#### Games and fictional depictions

Cold War and hacking fiction commonly represents ARPANET as a universally connected military supercomputer containing secret weapons data. The real system was a heterogeneous unclassified network whose hosts retained their own files, authorization, and security. It had no single master database.

---

## 12. Chronology

| Date | Event | Evidentiary note |
|---|---|---|
| 1958 | ARPA established after Sputnik | Institutional predecessor |
| 1961 | Kleinrock publishes early queueing/network paper | Theoretical precursor |
| 1962 | Licklider circulates “Galactic Network” ideas | Visionary precursor, not ARPANET design |
| 1963 | Licklider addresses the ARPA computing community as a networked group | Documented conceptual continuity |
| 1964 | RAND publishes Baran distributed-communications reports | Parallel military-survivability work |
| 1965 | Roberts and Thomas Merrill connect TX-2 and Q-32 over a dial-up circuit | Pre-ARPANET wide-area experiment |
| 1965–66 | Davies’s NPL group develops packet-switching concept and terminology | Independent British work |
| Feb.–late 1966 | Taylor organizes ARPA networking initiative and recruits Roberts | Date details rely partly on Taylor’s retrospective testimony |
| 1967 | Roberts presents ARPA network plan; Scantlebury communicates NPL work | Documented convergence |
| Aug. 1968 | ARPA issues IMP RFQ | Formal procurement |
| Dec. 1968 | BBN receives IMP contract | Formal founding contract |
| 7 Apr. 1969 | RFC 1 issued by Steve Crocker | Beginning of RFC series |
| Aug./Sept. 1969 | First IMP delivered to UCLA | Sources vary slightly on delivery wording/date |
| 29 Oct. 1969 | UCLA sends `LO` to SRI before host crash; complete login follows | Contemporary log survives |
| Nov. 1969 | UCSB attached | Third node |
| Dec. 1969 | Utah attached; four-node network exists | Conventional operational beginning |
| 1970 | Transcontinental growth; thirteen IMPs by late year | BBN count |
| Dec. 1970 | Initial host-to-host protocol substantially completed | Implementations continued afterward |
| 1971 | NCP and TELNET deployment broadens; about eighteen nodes and twenty-three hosts by September | Counts depend on definitions |
| Oct. 1971 | Final major NWG implementation meeting at MIT | BBN history |
| Jan. 1972 | Definitive host-to-host protocol description published | Operational stabilization |
| 1971–72 | Tomlinson develops inter-host mail and selects `@` separator | Exact “first email” date not securely recoverable |
| Oct. 1972 | ICCC public demonstration in Washington | Major public milestone |
| 1973 | NORSAR and UCL international links; Cerf–Kahn internetwork design work | Securely documented |
| 1973–74 | Email and mailing lists become dominant social uses | Exact traffic percentage disputed |
| 1974 | Cerf and Kahn publish internetwork protocol paper | Internet architecture milestone |
| 1 Jul. 1975 | Management formally begins transfer from DARPA to DCA | Six-month phase-over |
| 31 Dec. 1975 | Planned DCA transition phase ends | Administrative milestone |
| 1975–77 | TIP, satellite, gateway, Pluribus, and topology expansion | Continuous rather than single event |
| Jun. 1977 | Official geographic map shows mature U.S. and transatlantic network | Secure primary cartographic source |
| 1977 | GAO reports telecommunications/computer security weaknesses | Broader than ARPANET alone |
| 3 May 1978 | Gary Thuerk sends DEC commercial mass email | Early “spam,” retrospective label |
| 1978 | Major ARPANET directory and resource documentation published | Mature administrative system |
| 1979 | Ware report publicly reissued after prior classification | Security-policy milestone |
| 1980 | NCP/TCP mail-transition planning intensifies | RFC 771/773 |
| Nov. 1981 | RFC 801 sets TCP/IP transition plan | Primary operational directive |
| 1982 | Dual-protocol deployment and relays | Transition period |
| 1 Jan. 1983 | ARPANET changes from NCP to TCP/IP | “Flag day” |
| 4 Oct. 1983 | Logical ARPANET/MILNET split | Physical restructuring continued |
| 1984 | MILNET separation substantially completed; DNS deployment begins | Transformation into Internet component |
| 1985 | DCA issues ARPANET information brochure; NSFNET initiated | Mature but declining backbone |
| 1986 | NSFNET service expands academic connectivity | Successor growth |
| 1988 | T1 NSFNET backbone; Morris worm disrupts wider Internet | ARPANET no longer sole backbone |
| Jan. 1989 | RFC 1087 states Internet-use ethics after disruptive incidents | Policy response |
| 1989 | Some DARPA summaries label ARPANET ended | Likely migration/decision boundary |
| Feb.–Mar. 1990 | Remaining ARPANET backbone decommissioned | Exact formal date varies by source |
| Jul. 1990 | RFC 1167 refers to the “deceased ARPANET” | Contemporary confirmation that retirement was complete |

---

## 13. Quantitative Summary and Reliability

| Measure | Figure | Date | Reliability |
|---|---:|---|---|
| Original switching nodes | 4 | Dec. 1969 | High; consistent maps and reports |
| Line rate | 50 kbit/s | 1969 onward for principal early trunks | High; BBN documentation |
| IMPs | 13 | Late 1970 | High; BBN retrospective based on contractor records |
| Nodes | 18 | Sept. 1971 | Moderate–high; depends on IMP/TIP counting |
| Hosts | 23 | Sept. 1971 | Moderate; commissioning definitions vary |
| IMP delivery pace | approximately one/month | 1969–70 | Moderate; BBN retrospective |
| First host hardware types | 4 mutually unlike systems | 1969 | High |
| TIPs | 23 | June 1977 context | High for BBN’s defined count |
| Node count before MILNET split | approximately 113 | 1983 | Moderate–high; node definition required |
| Nodes moved to MILNET | approximately 68 | 1983–84 | Moderate–high; widely reported from split documentation |
| Email share | about 75% | 1973 or 1974 | Low–moderate; original study not established |
| People in 1984 DDN directory | approximately 14,000 | 1984 | Moderate; contemporary directory-owner count, includes broader DDN environment |
| Host entries in 1984 DDN directory | approximately 440 | 1984 | Moderate; broader than strict post-split ARPANET |
| Early packet checksum | 24 bits | 1969– | High; BBN technical report |
| TCP/IP flag day | 1 Jan. 1983 | 1983 | High |
| Formal retirement | Feb.–Mar. 1990 | 1990 | High for year; moderate for exact day |

Node-count series should never be plotted as though the terms were uniform. The 1969 “four nodes,” 1971 “twenty-three hosts,” 1983 “113 nodes,” and 1984 “440 hosts” count different things and, in the last case, may cover the broader Defense Data Network.

---

## 14. Assessment of the Network as a System

ARPANET’s physical biography began as four expensive computers connected indirectly through four purpose-built packet switches and leased telephone circuits. Its administrative biography began as an ARPA research program, became a contractor-operated experimental service, passed into DCA operational management, split its military and research constituencies, and ended as an obsolescent subnet inside the Internet it had helped make possible.

Its characteristic system relationships were:

- **host ↔ IMP:** standardized boundary between heterogeneous computation and communication;
- **IMP ↔ IMP:** adaptive packet forwarding across shared leased lines;
- **site ↔ sponsor:** access and funding through federal research or government mission;
- **host group ↔ RFC community:** negotiated protocol implementation;
- **NCC ↔ field equipment:** centralized observation of distributed machinery;
- **NIC ↔ users and hosts:** naming, directories, documentation, and institutional memory;
- **ARPANET ↔ other networks:** first through bespoke gateways, later through TCP/IP;
- **research network ↔ military state:** open unclassified experimentation financed for both research productivity and anticipated defense utility.

The network’s main cargo changed. Remote access to scarce computers justified construction. File transfer and remote job entry demonstrated resource sharing. Email became the most socially transformative application. Internetwork packets eventually became the decisive cargo: by carrying IP, ARPANET supplied transit for communications whose endpoints and applications no longer belonged uniquely to it.

Its end was therefore a transformation rather than a disappearance. Almost none of today’s ordinary Internet traffic traverses an ARPANET IMP, but contemporary networking retains concepts and institutions developed or consolidated there: packet switching, layered protocols, adaptive routing, host-independent communication, remote login, network mail, open technical memoranda, assigned identifiers, network operations centers, decentralized implementation, gateways, TCP/IP, and communities coordinated through the network they maintain.

---

## 15. Sources

### Primary and near-primary technical sources

- Bolt Beranek and Newman, *A History of the ARPANET: The First Decade*, Report 4799, April 1981.
- Frank Heart, Alex McKenzie, John McQuillan, and David Walden, *ARPANET Completion Report*, 1978.
- SRI Network Information Center and Defense Communications Agency, *ARPANET Directory*, December 1978.
- Steve Crocker, RFC 1, *Host Software*, 1969.
- Richard Kalin, RFC 60, *A Simplified NCP Protocol*, 1970.
- Abhay Bhushan, RFC 254, *Scenarios for Using ARPANET Computers*, 1971.
- Vinton Cerf, RFC 771, *Mail Transition Plan*, 1980.
- David Clark, RFC 773, *Comments on NCP/TCP Mail Service Transition Strategy*, 1980.
- Jon Postel, RFC 801, *NCP/TCP Transition Plan*, 1981.
- RFC 830, transitional Internet naming specification, 1982.
- National Research Council, RFC 942, *Transport Protocols for Department of Defense Data Networks*, 1985.
- Internet Activities Board, RFC 1087, *Ethics and the Internet*, 1989.
- Willis Ware, ed., *Security Controls for Computer Systems*, RAND R-609-1.
- U.S. General Accounting Office, *Vulnerabilities of Telecommunications Systems to Unauthorized Use*, 1977.
- Official June 1977 ARPANET geographic map.
- UCLA IMP log as reproduced by DARPA.

### Oral histories and archival guides

- Robert W. Taylor oral history, Computer History Museum.
- Elizabeth J. Feinler oral history, Computer History Museum.
- Computer History Museum, SRI ARC/NIC records finding aid.
- Computer History Museum Internet history collection.
- Stephen J. Lukasik, “Why the Arpanet Was Built,” *IEEE Annals of the History of Computing*.

### Institutional syntheses

- DARPA, “ARPANET.”
- Internet Society, “A Brief History of the Internet.”
- National Science Foundation, “Birth of the Commercial Internet.”
- NSFNET historical timeline.
- JPNIC Internet history timeline.

### Selected secondary bibliography

- Janet Abbate, *Inventing the Internet*. MIT Press, 1999.
- Katie Hafner and Matthew Lyon, *Where Wizards Stay Up Late: The Origins of the Internet*. Simon & Schuster, 1996.
- Arthur L. Norberg and Judy E. O’Neill, *Transforming Computer Technology: Information Processing for the Pentagon, 1962–1986*. Johns Hopkins University Press, 1996.
- Andrew L. Russell, *Open Standards and the Digital Age*. Cambridge University Press, 2014.
- Paul N. Edwards, *The Closed World: Computers and the Politics of Discourse in Cold War America*. MIT Press, 1996.
- Martin Campbell-Kelly and Daniel D. Garcia-Swartz, *From Mainframes to Smartphones: A History of the International Computer Industry*. Harvard University Press, 2015.
- Roy Rosenzweig, “Wizards, Bureaucrats, Warriors, and Hackers: Writing the History of the Internet,” *American Historical Review*, 1998.
- Joy Lisi Rankin, *A People’s History of Computing in the United States*. Harvard University Press, 2018.
- Claire L. Evans, *Broad Band: The Untold Story of the Women Who Made the Internet*. Portfolio, 2018.
- Thomas Haigh, Andrew L. Russell, and William H. Dutton, “Histories of the Internet,” historical and communications scholarship.
- Valérie Schafer, works on European networking, Cyclades, and international Internet history.

---

## Deduplicated URL list

https://archive.computerhistory.org/resources/access/text/finding-aids/102706170-SRI/102706170-SRI.pdf  
https://archive.computerhistory.org/resources/access/text/2013/05/102702199-05-01-acc.pdf  
https://archive.computerhistory.org/resources/text/Oral_History/Taylor_Robert/102702015.05.01.acc.pdf  
https://castig.org/wp-content/uploads/2022/06/1f84f-why-the-arpanet-was-built-.pdf  
https://cryptome.wikileaks.org/sccs.htm  
https://lists.sigcis.org/archives/list/members%40lists.sigcis.org/message/ZHE7PTQNSLKAITT3IRQLI4CE73IKLBRO/  
https://nobbyville.com/ARAPNET-completion-report.pdf  
https://nsf.net/timeline  
https://upload.wikimedia.org/wikipedia/commons/9/94/A_History_of_the_ARPANET%2C_The_First_Decade%2C_BBN_Report_4799%2C_April_1981.pdf  
https://vtda.org/docs/computing/DefenceCommsAgency/ARAPNET_Directory_Dec78.pdf  
https://web.nic.ad.jp/timeline/index.html  
https://www.computerhistory.org/internethistory/1960s/  
https://www.darpa.mil/about/innovation-timeline/arpanet  
https://www.darpa.mil/news/features/arpanet  
https://www.gao.gov/products/lcd-77-102  
https://www.govinfo.gov/content/pkg/GOVPUB-C60-PURL-gpo5575/pdf/GOVPUB-C60-PURL-gpo5575.pdf  
https://www.internetsociety.org/internet/history-internet/brief-history-internet/  
https://www.nsf.gov/impacts/internet  
https://www.rfc-editor.org/info/rfc254/  
https://www.rfc-editor.org/info/rfc773/  
https://www.rfc-editor.org/info/rfc801/  
https://www.rfc-editor.org/info/rfc8700/  
https://www.rfc-editor.org/info/rfc942/  
https://www.rfc-editor.org/info/rfc1087/  
https://www.rfc-editor.org/rfc/pdfrfc/rfc771.txt.pdf  
https://www.rfc-editor.org/rfc/rfc60.html  
https://www.rfc-editor.org/rfc/rfc830.html  
https://www.upi.com/Archives/1983/10/04/The-Defense-Department-electronically-separated-its-nationwide-computer-network/8814434088000/
