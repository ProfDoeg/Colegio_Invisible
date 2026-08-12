# Laura Renée Maier: research report

*Compiled 2026-08-12 for the Atlas of Journeys. Embroidery artist, born Seattle 1991, living and working in Bogotá; named in the corpus as an embroiderer collaborator of the author and maker of the 2022 diptych "Encoded Threads."*

Legend: **[A]** = attested, source named on the same line · **[R]** = reconstruction, tradition, inference, or the corpus's mythic register. Contradictions are flagged and **not adjudicated**.

A structural note first. This subject has **two archives that do not know about each other**. The **essay corpus** knows her diptych, nimbi, hash, handle, and one studio visit in Belgrano, and records no birth, nationality, training, gallery, or exhibition. The **artist's own site** knows her birth year and city, a nonprofit, nineteen exhibitions in five countries, and four collaborations, and records nothing about a blockchain, a certificate, a hash, or Hayagriva. They touch at one point, the section title `ENCODED THREADS`, and neither cites the other. The journey is built from both.

---

## Phase 0: origin (1991)

- Born 1991 in Seattle, Washington. **[A: laurareneemaier.art/bio and /curriculumvitae, both carrying "LAURA RENÉE MAIER / 1991 SEATTLE, WASHINGTON, UNITED STATES"]** No day or month anywhere; the journey defaults to 1991-01-01 with the hedge in `date_confidence`.
- No parents, no schooling, no training, no first teacher. **A gap, stated as a gap.** Nothing in the research pool located any biographical material between the birth line and the first CV entry of 2017, a twenty-six-year hole.

**Contradiction flagged (internal to the research passes, not to the sources).** The chronology pass called the origin an absolute gap "anywhere in the corpus." That is true of the essay corpus only, and false of the CV the geography pass was using for this very line. The journey states the corpus's silence and the CV's birth line side by side rather than choosing one.

---

## Phase 1: Portland, New York, Mexico City (2017-2019)

- **2017, Wild Woman founded** in Portland with the couturier Myriam Marcela: a registered nonprofit pairing her embroidery with wearable art, touring as installation and auctioned at the end. Her co-founding runs 2017 to 2024. **[A: /wildwoman and /curriculumvitae, "2017 - 2024 WILD WOMAN ... CO-FOUNDER"]**
- **Beneficiary structure, corrected.** An earlier pass gave two parallel beneficiaries. The site says "to benefit Fondo Semillas (Mexican Society for Women's Rights, A.C.) in partnership with Global Fund for Women": one beneficiary, one partner. **[A: /wildwoman, verbatim]**
- **2017, FASHIONXT, Portland**, under the Wild Woman banner; **2017, Critical Conception II** and **2018, Portray-T, New York**, both with Forvll Collective, her first documented New York showings. **[A: CV]** No addresses. **[gap]**
- **2019, Casa Rivas Mercado, Mexico City**, and **2019, Roche Bobois showroom, Portland**, both Wild Woman installations. **[A: CV]** The Roche Bobois address is unconfirmed. **[gap]**
  - **Correction applied.** An earlier pass placed Casa Rivas Mercado in Colonia San Rafael at 19.4436 / -99.1547, about a kilometre WNW of the building and in the wrong colonia. Its own site gives Calle Héroes 45, Colonia Guerrero, C.P. 06300, roughly 19.4415 / -99.1450, which the journey uses. **[A: casarivasmercado.com]**
- **2019, A New Cross**, Bogotá design brand, collaboration begins and is listed as ongoing. **[A: CV; /anewcross]** Earliest Colombian item in her record, predating her documented residence there.

---

## Phase 2: Bogotá (2020-2021)

- **She lives and works in Bogotá.** **[A: /bio, "Laura Renée currently lives and works in Bogotá, Colombia"]** The start year is stated nowhere: "2020-present" is inferred from the first Bogotá exhibition on the CV, carried in `date_confidence`, and no arrival is asserted. **[R]**
- **2020, Mujeres, Escena Villegas, Bogotá.** **[A: CV]** Address unconfirmed.
- **Carne de Mi Carne**, a continuing series, exists as a named section of her site. **[A: /carnedemicarne]** An earlier pass described it as "thread on linen tracing shared homeotic structure between plant and human anatomy"; the verification pass could not match that to the site text, so the journey states only that the series exists. **[R for the description]**
- **Desapariciones**, in thread, digital painting, and encoded textile, addressing Colombia's disappeared, exists as a named section. **[A: /desapariciones]** The dating to 2021-2022 and the link to the pandemic and civil unrest is **[R]**: no date is on the site.
- **2021, Hilos Silencios, Montenegro Art Projects, Bogotá.** **[A: CV]** The gallery becomes her most repeated venue: 2021, 2023-2024, 2024, 2025, all three Pinta years, and the 2024 Collector's House.
- **2021, Pinta Miami Art Fair, digital edition**, Montenegro Art Projects. **[A: CV, "2021 PINTA MIAMI ART FAIR - DIGITAL ... MIAMI, FLORIDA"]**
  - **Correction applied.** An earlier pass pinned the digital edition at 25.7907 / -80.13, a Miami Beach coordinate, and the 2022 and 2023 editions at 25.7887 / -80.1998. The CV says Miami in all three cases. The journey uses **one** Miami placeholder, 25.7887 / -80.1998, for all three Pinta years and The Collector's House.

---

## Phase 3: the diptych and the Certificate Authority (2022)

The phase the essay corpus knows and the CV does not.

**Exhibitions on the CV for 2022**, none of which mention the diptych: WTF at Galería La Cometa, Bogotá; Dechado at Casa Hoffmann, Bogotá; Mexican Modernism at the Portland Art Museum; Pinta Miami in person. **[A: CV]**

**MAGDALENA, 2022**, thread on silk, garment, 70 x 42 in / 178 x 107 cm, described as "Commission for the Portland Art Museum." **[A: laurareneemaier.art/wildwoman, verbatim]** An earlier pass wrote that it "enters the museum's collection"; the source states a commission and says nothing about accession, so ownership stays off the record. **[gap]**

**The diptych "Encoded Threads," 2022:**
- Two canvas panels, black thread. One: nude, four-armed, horse-headed feminized Hayagriva facing right, 114 x 102 cm. Two: nude, dog-headed feminized Anubis / cynocephalic San Cristóbal, gazing and gesturing left, 72 x 102 cm. Each nimbus is bordered with hexadecimal characters of a 32-byte SHA256 hash (3370...1ba0), first 16 bytes on the Hayagriva panel and last 16 on the Anubis panel, so the hash is verifiable only across the pair. Each panel carries a gilded fold secured by overlay stitches, said to conceal the private-key counterparts of the certificate's keys. **[A: augury.md 4]**
- The on-chain certificate (SHA256 3370...1ba0, header c1dd0001ccff0001, Invisible College standard v0.1) carries an "Artista" field valued "Laura Renee Maier" beside three secp256k1 public keys named Hayagriva, Christophia, and Anthony, published via a 3-of-3 address 9xth...7yqs. **[A: augury.md, paragraph 3]**
- **12 December 2022:** two digital images, "Laura's Hayagriva" and "Laura's Christophia," created simultaneously, 512x512 px, black and white, 64 quipu strands, same header, published via two 2-of-2 addresses: AD28...ozuw (Hayagriva + Anthony) and A7pf...aefV (Christophia + Anthony). **[A: augury.md 5, "Ambas imágenes fueron creadas simultáneamente el 12 de diciembre de 2022"]**
- **13 December 2022:** the full proof of the hidden certificate presented to Andréa and Tomás of Mochuelos at the Taller de Rumpelstiltskin. **[A: augury.md 5, verbatim]**

### Contradictions and corrections in this phase

1. **Where the diptych was made is unstated, and one pass asserted Buenos Aires.** `augury.md` names no city. The CV and bio place her in Bogotá across 2020-2025, with Bogotá shows either side of December 2022. The journey pins the making at her attested residence and declares the gap. **Not resolved.** **[R for the pin; A for the residence]**
2. **The Taller de Rumpelstiltskin has no recorded location**, not in `augury.md`, `INDEX.md`, or any post. An earlier pass placed it in Buenos Aires while conceding the address was missing. The journey uses the canonical Buenos Aires pin as a declared placeholder. **Not resolved.**
3. **The 1ec0 transaction was misattributed.** An earlier pass tied it to the certificate anchoring Maier's diptych. `augury.md` ties the 1ec0 reference to the Certificate Authority field inside **Katrin Vates's Domrémy inscription**. The journey does not carry 1ec0. **[A: augury.md, lines 13 and 30]**
4. **"The day after the panels were inscribed" is a misreading.** `augury.md` dates the *creation of the two images* to 12 December and never dates the inscription. The 13 December presentation is the day after the images were made, which is the journey's wording. **[A: augury.md]**
5. **Her name is spelled two ways and the corpus does not resolve it.** With the accent in 208, 210, and most Instagram posts; without it in augury.md's certificate paragraphs and in the on-chain Artista field. Her own site uses the accent. **Flagged, not resolved.**
6. **"Christophia" names two things**: one of the three secp256k1 keys, and her embroidered Anubis panel ("obra titulada Christophia"). Wordplay or coincidence is not stated. **Flagged, not resolved.** **[R]**
7. **Nothing here is verified on-chain.** No pass queried a Dogecoin node for any address or hash. Every cryptographic detail is attested **to the essay, not to the ledger**. **[gap]**

---

## Phase 4: Belgrano and the Gordian knot (2023)

- **27 January 2023:** an essay on "nimbus" (Latin, from PIE *nebh-*, linked to the Mesopotamian god Nabu) reads her use of gold, halo, areola, and inscription as making her embroideries function as "portals," tagging @laurareneemaier. **[A: instagram/2023-01-27-nimbus-...md]**
- **30 January 2023:** the narrator visits the knit designer Matías Carbone's studio in **Belgrano**, after an anonymous invitation, and ends the conversation looking at her embroidered Anubis, "la obra titulada Christophia," calling it a Gordian knot he cannot untangle while feeling a deep and ancient mystery in it. Posted 31 January, tagging @laurareneemaier and @matiascarbone. **[A: instagram/2023-01-31-ayer-fui-al-estudio-de-matias.md, line 5: "Ayer fui al estudio de Matias Carbone en Belgrano después de recibir una invitación anónima."]**
  - **Worst error in the earlier passes, corrected.** One pass gave "Av. Alvear 1807" at -34.5875 / -58.3925, a Recoleta address absent from the corpus and about 9 km from Belgrano. The journey uses Belgrano, -34.5631 / -58.4547. Quote and visit date were correct and are kept.
- **2023, Pinta Miami**, third consecutive year with Montenegro, and **2023-2024, La Fibra del Tiempo** at the same gallery in Bogotá. **[A: CV]** No months for either end of the run. **[gap]**

---

## Phase 5: the corpus reads the work back (2024)

- **28 April 2024:** essay 208 and its counterpart call "the encoded nimbus above Laura Renée Maier's threaded cynocephalus" a highly connected node, part of a "semantic sun-dog" mimicking the radial ceque diagram of the Qorikancha at Cuzco. **[A: 208_saint_christopher.md; instagram/2024-04-28-san-cristobal-es-un-nodo-altamente.md]** She is not recorded in Cuzco; the stop records a comparison, not a journey.
- **5 June 2024:** essay 210 states that Hayagriva "appears in a feminized form, donning an embroidered nimbus, in Laura Renée Maier's Encoded Threads," linking the work to the Ashvashala of Hayagriva at San Isidro, where a hechicera is said to invoke that figure when she lifts a volume from the Kshira Sahara. **[A for the statement; R for the ritual claim]**
  - **Coordinate disagreement flagged.** The geography pass gave -34.4708 / -58.5069 for the Ashvashala, the afterlife pass -34.4708 / -58.5205 for the same site. The corpus gives no coordinate; the atlas's existing San Isidro pin (Villa Ocampo) is -34.45806 / -58.51833, a different place in the district. The journey uses the first value as a declared placeholder. **Not resolved.**
- **2024, ARTBO, Corferias, Bogotá**, Montenegro Art Projects. **[A: CV; es.wikipedia.org "Corferias"]** An earlier pass gave 4.6304 / -74.0972, about 780 m west of the fairgrounds; Corferias is at Carrera 37 N° 24-67, 4.6297 / -74.0902, which the journey uses.
- **2024, The Collector's House, Miami Art Week**, Montenegro Art Projects. **[A: CV, "MIAMI, FLORIDA"]** An earlier pass titled and pinned it Miami Beach; no source places it there. Corrected to the single Miami placeholder.
- **2024, Eichholtz Miami**, Design District collaboration; **VAREC** (ongoing) and **Faride Ramos**, Bogotá design brands. **[A: CV]** No addresses. **[gap]**

---

## Phase 6: Komorebi, and the last dated mention (2025-2026)

- **2025, Komorebi. Latido de Luz y Agua, Montenegro Art Projects**, and a **fundraiser exhibition at the Museo de Arte Moderno de Bogotá**. **[A: CV]** No piece is named for the fundraiser. **[gap]**
- **3 October 2025:** an essay on textile provenance and the question "De dónde sos?" names her with Katy Troja and Katrin Vates as artists who "cargan con historias de viaje," set against Rachel's Tomb, the Bethlehem checkpoint, and the narrator's father interrogated at the Berlin Wall. **[A: instagram/2025-10-03-interrogo-la-puntada...md]**
  - **That she personally has a migration history is inference from the grouping, not documentation.** **[R]**
  - **Correction applied.** An earlier pass built an "ESCVDO thread workshop lineage" stop pinned at Cusco, -13.532 / -71.9675. The post names no Peruvian place, its textile author is named only "una artesana peruana," and ESCVDO is a Lima brand: the coordinate was invented and is dropped. The cones of algodón, alpaca, merino and seda are handed in the post to "Yuki, Chary, Henrik y Anna," not to Maier.
- **27 October 2025:** an Instagram carousel (posts 3, 4, 5) republishes the whole 2022 account verbatim in essay form. **[A: instagram/2025-10-27-3, -4, -5]** Last dated appearance of her name in the corpus.
- **INDEX.md** files the augury material under "THE CERTIFICATE AUTHORITY," cataloguing "Laura Renee Maier's Encoded Threads diptych" as chain-and-cloth mutual certification beside Katrin Vates's Domrémy embroidery. **[A: INDEX.md 72, 133]**
- **2026, LGM Galería, Bogotá**, solo listed as upcoming. **[R: forthcoming, not verifiable at the time of research]**
- **No death, cessation, or biographical event after 27 October 2025 appears in any source.** She is treated as living and working. **[gap, not an assertion of activity beyond the last citation]**

---

## Interlocks with the atlas

- **San Cristóbal**, whose cynocephalic form she feminizes on panel two: most-named real person in the census (38 documents), completed journey, birth pin Marmarica 31.3525 / 27.2373, inherited byte-identical. **[A: census 8; san_cristobal.journey.json]**
- **Hayagriva** (2nd, 20 documents) and **Anubis** (4th, 17), both named in her nimbi and her hash. **[A: census 9, 11]**
- **Katrin Vates** (Ekaterina Sirchinova), 3rd with 20 documents, the corpus's other embroiderer-collaborator; INDEX.md pairs her Domrémy embroidery with the diptych. **[A: census 10, 19, 441; INDEX.md 72, 133]**
- **Duwenavue Sante' Johnson** holds the canonical Temple Mount pin, 31.778 / 35.2354, curating the Masonic apron and the embroidered girdle of the Kohanim. Inherited byte-identical. **[A: duwenavue_sante_johnson.journey.json line 378]**
- **Leo Chiachio** holds the canonical Buenos Aires pin, -34.6037 / -58.3816, and the canonical Paris pin, 48.8566 / 2.3522. Both inherited byte-identical. **[A: leo_chiachio.journey.json lines 90-91, 167-168]**
- **Daniel Giannone** and **Arthur Bispo do Rosário**, completed journeys, grouped with her by QUEUE.md as one textile-art lineage; **Matías Carbone** and **Ekaterina Sinchinova**, queued and unresearched, her nearest siblings in that block. **[A for the adjacency: QUEUE.md 259, 261, 301, 305; leo_chiachio.report.md 137, 140. R for what the grouping means.]**

### Interlock contradictions and non-interlocks

1. **The 203 problem, unresolved.** QUEUE.md line 300 says she is "named in essay 203_masonic_embroidery.md," and the interlock pass built a Johnson-Maier bridge on it. The chronology pass checked 203 directly, English and Spanish, and **found no occurrence of her name**; her documented essay appearances are 208, 210, and augury.md. The journey records the discrepancy at the Temple Mount stop. **Not adjudicated.**
2. **Document count discrepancy.** QUEUE.md line 300 carries a docs count of 2; the census counts 11 (3 essays, 8 Instagram posts). **Flagged, not resolved.** **[A: QUEUE.md 300; census 19]**
3. **Michael Maier** (alchemist, d. 1622) and **Meyer Lansky** (born Maier Suchowljansky) are surname coincidences with completed travelers. **No atlas source connects either to her.** Flagged as surface confusion only. **[R]**
4. **"Anthony" and "Christophia"** in her hash are the author-and-persona names the atlas is itself built under (git identity "Christophia Hayagriva"), not travelers with journey files. Her work encodes the atlas's own authorship. **[R]**
5. **The Kaaba pin** (21.4225 / 39.8262) was checked and confirmed present via adnan_khashoggi.journey.json. **No Maier connection exists in any file**, so it is unused here. **[A for the pin; gap for any link]**
6. **The cryptography thread QUEUE.md claims she interlocks with is not locatable** in any completed journey or census entry besides augury.md itself. **[gap]**

---

## Standing gaps

- Everything between birth (1991) and the first CV entry (2017). Twenty-six years, nothing.
- Any street address for any venue on the CV except Corferias and Casa Rivas Mercado; the city where the diptych was embroidered; the location of the Taller de Rumpelstiltskin.
- The present location, owner, or exhibition history of the two "Encoded Threads" panels. Her site carries an `ENCODED THREADS` section, so the work is publicly presented by her, but no gallery, acquisition, or location appears in either archive. The earlier "no source names it" phrasing is narrowed to "no exhibition history or location is recorded."
- Whether the gilded folds have ever been opened; on-chain verification of anything; whether she has a migration history of her own; which piece went to the MAMBO fundraiser.

---

## Sources

**Reached and used**

- `laurareneemaier.art`: `/bio`, `/curriculumvitae` (with the "CV SEP 2025" image), `/wildwoman`, `/carnedemicarne`, `/desapariciones`, `/anewcross`, and the navigation carrying `ENCODED THREADS`.
- `casarivasmercado.com` (address and colonia); `es.wikipedia.org` "Corferias" (ARTBO, fairground address).
- `~/essays/augury.md` paragraphs 3, 4, 5 and lines 13, 30; `208_saint_christopher.md`; `210_hayagriva.md`; `INDEX.md` lines 72, 133; `203_masonic_embroidery.md` (checked for her name, **no hits**).
- `~/essays/instagram/`: 2023-01-27 (nimbus), 2023-01-31 (Carbone studio), 2024-04-28 (San Cristóbal node), 2024-06-05 (Hayagriva expedition), 2025-10-03 ("de dónde sos"), 2025-10-27 posts 3, 4, 5.
- Atlas files: `QUEUE.md` 259, 261, 299-301, 305; `census_real_persons_2026-08-02.md` 8-11, 19, 441; `san_cristobal`, `duwenavue_sante_johnson`, `leo_chiachio` journeys; `leo_chiachio.report.md`; `victoria_ocampo.journey.json` (San Isidro pin); `adnan_khashoggi.journey.json` (Kaaba check).

**Not reached, with the reason**

- **The Dogecoin blockchain itself.** No node query against 9xth...7yqs, AD28...ozuw, A7pf...aefV, or the hash 3370...1ba0. All chain claims rest on augury.md alone.
- **@laurareneemaier on Instagram.** The handle is attested by two posts that tag it; the account's own posts were not fetched, so nothing dated by her enters this file.
- **Gallery and fair pages** (Montenegro Art Projects, La Cometa, Casa Hoffmann, Escena Villegas, LGM, Pinta Miami, ARTBO exhibitor lists): not fetched, so every exhibition here is single-sourced to her CV.
- **Portland Art Museum records**: not fetched, which is why MAGDALENA stays a commission and not an accession.
- **ESCVDO**: identified as Lima-based, no workshop location, no page fetched; the Cusco coordinate an earlier pass supplied was fabricated and is dropped.
- **Any birth, education, or immigration record.** None attempted; none appropriate for a living private person beyond what she publishes herself.

**Recorded as a negative result:** `203_masonic_embroidery.md` does not contain her name, against QUEUE.md's claim that it does.
