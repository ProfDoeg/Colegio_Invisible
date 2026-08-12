# Luis Federico Leloir (1906-1987): research report
*Atlas of Journeys. Compiled 2026-08-11 for `luis_federico_leloir.journey.json`.*

Argentina's second science Nobel laureate and the first Ibero-American laureate in Chemistry. Born in Paris by accident of travel, raised on a coastal estancia, trained as a physician, converted to biochemistry by Bernardo Houssay, and responsible for the identification of sugar nucleotides in a Palermo house funded by a textile fortune.

**Legend.** **[A]** = attested, source named. **[R]** = reconstruction, tradition, or a claim whose only support is repetition. Contradictions are flagged and left standing. Where a widely circulated date or coordinate is corrected, the arithmetic is shown.

**A caution about the source base.** English and Spanish Wikipedia carry nearly the whole biographical spine and disagree in several places. The nobelprize.org biographical pages and the Britannica biography returned **HTTP 403**. The Nobel lecture and banquet speech were reached and are the only true primary documents here; everything else is secondary at best.

## 1. Birth and the pampa childhood (1906 to c.1922)

- **Born 6 September 1906, 81 Avenue Victor Hugo, 16th arrondissement, Paris [A: en.wiki, es.wiki].** Both articles give the street number. Nominatim geocodes the address to **48.87020, 2.28706**; a working figure of 2.2823 sits about 350 m west of the building and is not used.
- **Parents Argentine, of Basque descent [A].** No source names a town of origin, so the regional coordinate that circulates for this family (43.263, -2.935) is **[R]** and is dropped from the journey as too weak to carry a stop.
- **The family returns to Argentina in 1908 [A for the year].** The two-year-old comes ashore at the Port of Buenos Aires. **Neither ship nor pier is named by any source [R].**
- **Childhood on the Estancia El Tuyú [A]**, a holding between San Clemente del Tuyú and Mar de Ajó measured in tens of thousands of hectares.
  - *Coordinate correction.* The circulating **-36.5 / -58.5** is wrong by roughly 160 km, landing on the open pampa near Las Flores and Rauch. San Clemente geocodes to -36.3561, -56.7194 and Mar de Ajó to -36.7213, -56.6776, giving a centre near **-36.55 / -56.70**, the figure used.

## 2. Schooling on two continents (c.1912 to c.1926)

- **Escuela General San Martín, then Colegio Lacordaire (Dominican), then Colegio del Salvador (Jesuit, Avenida Callao) [A: es.wiki].** No source gives addresses or years for the first two, so their pins are **[R]**.
- **A period at Beaumont College, Old Windsor, England [A: en.wiki].** The school operated 1861 to 1967, so attendance in the early 1920s is chronologically clean. *Coordinate correction:* 51.4667 / -0.6183 is about 3.6 km northwest of the site; English Wikipedia's Beaumont College article gives **51.449 / -0.575**, by the Thames near Runnymede.
- **Architecture studies in Paris, abandoned.** The file's sharpest source conflict, not resolved here. en.wikipedia says **École Polytechnique**; es.wikipedia says **Institut Polytechnique**; and **neither institution taught architecture**, the École being an engineering grande école with no architecture faculty. The claim as normally written is attested by no source and contradicted between two, so it is tagged **[R]** throughout, including in `date_confidence`. The rue Descartes campus (48.8462, 2.3486), occupied by the École until 1976, is a labelled stand-in pin.

## 3. Medicine, and the turn to the bench (1932 to 1935)

- **Medical degree, Facultad de Medicina, Universidad de Buenos Aires, 1932 [A: both].** **Reportedly four attempts to pass anatomy [R: en.wiki, no document behind it].**
- **Residencies at Hospital de Clínicas José de San Martín and Hospital Ramos Mejía [A: es.wiki].**
  - *A false claim removed.* "The building still stands" is wrong for the building Leloir trained in: the nineteenth-century Hospital de Clínicas on Avenida Córdoba was demolished and its site is now **Plaza Houssay**. The journey says the institution continues and the walls do not, taking the canonical Plaza Houssay pin (-34.59889 / -58.39806) from `bernardo_houssay`.
  - *Coordinate correction, Ramos Mejía.* -34.6103 / -58.3986 lands about 1.4 km northeast, outside Balvanera. Nominatim gives **-34.61804 / -58.41018** for General Urquiza 609.
- **Meets Bernardo Houssay in 1933 and begins doctoral work on the adrenal glands and carbohydrate metabolism under him [A for the mentorship, R for the year and the route].** es.wikipedia reports the introduction came through a family connection to his cousin **Victoria Ocampo** and offers no document; tagged **[R]**.
  - *Coordinate correction.* Houssay's Instituto de Fisiología sat inside the UBA Facultad de Medicina building, not at a separate downtown address; -34.6008 / -58.3838 points to Callao and Corrientes, another neighbourhood. The journey inherits **-34.5989 / -58.3974**, byte-identical from `bernardo_houssay`.
- **Doctoral thesis judged the best of the medical department that year [A: both].**
  - *Date correction: 1935 becomes 1934.* The 1935 date is supported by neither source. en.wikipedia: diploma 1932, thesis completed "after only two years." es.wikipedia: "Su tesis, completada en solo dos años..." The arithmetic gives 1934, the year standard biographies carry.
- **Courses at the Facultad de Ciencias Exactas y Naturales, then in the Manzana de las Luces at Perú 222 [A: en.wiki].** Coordinate corrected from -34.6086 / -58.3728 to **-34.6105 / -58.3747**, about 275 m.

## 4. Cambridge, and the 1943 rupture

This is where the sources fail hardest, and the failure has propagated widely.

- **Cambridge under Frederick Gowland Hopkins, from 1936 [A: both]**, at the Sir William Dunn Institute on Tennis Court Road, on enzymatic effects including cyanide and pyrophosphate.
- **The 1936 to 1943 Cambridge span is an infobox artefact and is rejected here.** en.wikipedia's own prose reads: *"Leloir returned to Buenos Aires in 1937 after his brief stay at Cambridge."* The reconstruction adopted is **Cambridge 1936-1937, Buenos Aires under Houssay 1937-1943 [A, same article's body text].**
  - The pool called this a discrepancy between the two Wikipedias. That framing is itself wrong: es.wikipedia never claims a continuous Cambridge decade, and en.wikipedia contradicts its own infobox in its own prose. The correction also kills two circulating sentences: that he left Cambridge for the United States (he left it for Buenos Aires), and that his 1943 marriage fell in the year he left Cambridge (six years earlier).
  - *Coordinate note.* 52.2007 / 0.1247 is about 200 m east of the Dunn Institute. **52.2007 / 0.1216** is used.
- **4 June 1943, the GOU coup at the Casa Rosada [A]**, pin inherited byte-identical from `juan_peron.journey.json` (-34.6081 / -58.3702). Within months the new government purged professors who had signed an anti-Nazi declaration, and Houssay lost his chair.
- **Leloir resigns his own UBA post in solidarity with Houssay [A: es.wiki]**, under the Pedro Pablo Ramírez government. Month not given; the journey places the resignation after the mid-year purge and says so in `date_confidence`.
- **Marries Amelia Zuberbühler, 1943 [A for the year: both].** Venue unnamed by any source **[R]**. *Unresolved contradiction, left standing:* en.wikipedia names **one daughter**, also Amelia; es.wikipedia says **"cuatro hijos."** The journey states the conflict rather than picking a side.

## 5. The American interlude (1943 to 1945)

- **Washington University School of Medicine, St. Louis, 1943-44, in the pharmacology department and the laboratory of Carl and Gerty Cori [A: both].** *Rank downgraded:* "associate professor of pharmacology" is supported by neither source, both of which describe him only as working in the department. The journey calls him a visiting researcher and names the inflated title as inflated.
- **Columbia University College of Physicians and Surgeons, New York, from 1944, as a research assistant in enzyme research [A: en.wiki].**
- **Returns to Buenos Aires in 1945 to resume work with Houssay [A: both].**

## 6. The Instituto Campomar, and the discovery (1947 to 1958)

- **Founded 1947 at Houssay's initiative, funded by the industrialist Jaime Campomar at 100,000 pesos a month; Leloir directs it forty years [A: both].**
- **Address conflict, unresolved.** en.wikipedia gives **"1719 Julián Alvarez Street"**, the Spanish article on the institute **"Julián Álvarez 1917"**, and nothing reached reconciles them. The journey uses the geocode of 1719, **-34.5914 / -58.4220** (a working figure of -34.5893 / -58.4243 is about 310 m off), and flags the conflict in the campa.
- **Sugar nucleotides identified; the pathway that carries his name [A: both].** *Date correction:* UDP-glucose was not isolated "in 1947 and 1948" but in **1949-1950**, and the journey dates the discovery stop 1949.
- **Prize from the Sociedad Científica Argentina for the sugar nucleotide work [R: es.wiki, year unspecified]**, placed loosely in the late 1940s. **Titular professor at the biochemical institute of the UBA, 1949 [R: en.wiki only].**
- **Through the 1950s: galactose metabolism (the Leloir pathway), glycoproteins, and the biochemical basis of galactosemia [A: both, years not pinned].**
- **1957: after Campomar's death the institute faces a funding crisis. Leloir declines offers from the Rockefeller Foundation and Massachusetts General Hospital and secures NIH and Rockefeller grants to keep the laboratory in Argentina [R: es.wiki only].** A load-bearing claim on a single source.
- **1958: the institute moves into a former girls' school donated by the Argentine government, at Vuelta de Obligado and Monroe, under an agreement with Dean Rolando García of the Facultad de Ciencias Exactas y Naturales [A: both].**
  - *Consequence: the "four decades at one Palermo address" story is false.* The institute stood on Julián Álvarez **1947-1958 only**, at Vuelta de Obligado 1958-1983, near Parque Centenario from 1983. A forty-year daily Fiat 600 commute to a single Palermo door did not happen; the Fiat 600 is attested **[A: en.wiki]**, the address is not.
  - *Pin.* No survey of the 1958 building was reached, so the journey uses the canonical Belgrano coordinate **-34.5579 / -58.4588** from `bernardo_houssay` (IBYME, a few blocks along the same street), and says so in the campa.

## 7. Honours and Stockholm (1967 to 1972)

- **Louisa Gross Horwitz Prize, Columbia University, 1967 [A: en.wiki]. 1968 cluster: Premio Benito Juárez (Mexico), honorary doctorate from the Universidad Nacional de Córdoba, election to the Pontifical Academy of Sciences [A: es.wiki].** The Benito Juárez venue is named by no source **[R]**; Mexico City stands in, labelled as reconstruction.
- **Nobel Prize in Chemistry, 10 December 1970, sole laureate, "for his discovery of sugar nucleotides and their role in the biosynthesis of carbohydrates" [A: official prize motivation].** First Ibero-American laureate in Chemistry; second Argentine science laureate after Houssay in 1947.
  - *Pins.* Konserthuset **59.333 / 18.064** is inherited byte-identical from `fermi` and `dirac`, in preference to the standalone geocode 59.33506 / 18.06318; the Stadshuset banquet **59.3273 / 18.054** and the Royal Society **51.5074 / -0.1339** come from `bernardo_houssay`.
- **Nobel lecture, 12 December 1970 [A: Nobel Foundation PDF, retrieved].** The hall is named in nothing reached, so the pin stands for the city and is flagged.
- **Donates the prize money, about $80,000, to the institute; the team drinks champagne from laboratory test tubes [A: both].**
- **Foreign Member of the Royal Society, 1972 [A: en.wiki].**

## 8. Late honours, death, afterlife (1971 to 2001)

- **Orden de Andrés Bello (Venezuela) 1971; Gran Cruz de la Orden de Bernardo O'Higgins (Chile) 1976; Légion d'honneur (France) 1982 [A: es.wiki].** The Légion d'honneur venue is unconfirmed, Paris or the French embassy in Buenos Aires **[R]**; the journey uses the embassy as the likelier site for a man of seventy-six settled in the city.
- **Premio Konex de Brillante 1983; Ciudadano Ilustre de la Ciudad de Buenos Aires 1984 [A: es.wiki].** The conferral chamber is unconfirmed **[R]**; the Legislatura's seat on Perú stands in.
- **Co-founder of the Third World Academy of Sciences, Trieste, 1983 [A: en.wiki]. The institute's third move, to a purpose-built facility near Parque Centenario, 1983 [A: es.wiki]**, later expanded from 6,900 to 10,900 square metres.
- **Address "Comentarios sobre la investigación científica en la Argentina," 19 June 1985**, published 1986 by the Instituto de Teoría, Organización de la Investigación e Historia de la Ciencia **[A for the citation, R for the text]**: quoted on Wikiquote with full bibliographic detail, but the 1986 printing was not retrieved.
- **Dies of a heart attack in Buenos Aires, 2 December 1987, aged 81, shortly after returning from his laboratory. National mourning declared. Buried in the Leloir family mausoleum at La Recoleta [A: both agree on date and cause].** Plot number given nowhere. **Asteroid 2548 Leloir [R: undated].**
- **Konex Platinum Prize to the institute 1988; the Fundación Instituto Campomar renamed Fundación Instituto Leloir in 2001; today 24 research groups and 170+ staff, recruited by open international competition since 1999 [A: es.wiki].** *Coordinate correction, repeated five times in the working pool:* -34.6086 / -58.4372 is about 550 m off, and **-34.60426 / -58.43428** (Patricias Argentinas 435, Caballito) is used everywhere.

## 9. The quotations

Ten quotes are carried into the journey; their provenance varies enormously.

**Solid primary text [A].** The banquet speech and Nobel lecture PDF (10 and 12 December 1970), both retrieved. Four lines are used: the Churchill paraphrase, the origin of the work, the Houssay dedication, and the Paleolithic sentence.

- Two pool errors fixed: the Paleolithic line was circulating truncated (it ends "...but fortunately there are also some very recent and exciting advances in the field", quoted whole here), and "Fortunately even after two decades our field of investigation has not become dull or too fashionable" is **not** the lecture's closing line but the opening of its acknowledgements paragraph.

**Traceable but not his own words [R].**

- **"Descubrí (no yo: mi equipo)..."** Traced to the Comodoro Rivadavia page at elchenque.com.ar (Wayback capture, 28 February 2007), credited there to **Revista Gente**. The circulating English ("a much larger project") is a loose translation of "una larga investigación", so the journey quotes the Spanish.
- **"Si hubiera patentado esa salsa..."** The citation everyone repeats is wrong: the archived Tesone / Sociedad Argentina de Diabetes page was retrieved and mentions neither Leloir nor salsa golf nor patents. The wording appears in **Infobae, 5 September 2017**, introduced as "Dijo algo así como", so the outlet does not vouch for it. Kept **[R]** and re-sourced.
- **"No existen problemas agotados, solo hay hombres agotados por los problemas."** Verbatim in a real source but not documented as his coinage. La Prensa, "Houssay, Leloir y Milstein: vivir para la ciencia" (URL 404, via the Wayback Machine), quoting Federico Pérgola, *Historia de la Medicina argentina*: it is the phrase **Leloir posted at the institute's entrance**, and is presented that way. Checked against Ramón y Cajal's Wikiquote page and absent there.
- **"we could do little for our patients..."** Leloir, "Far Away and Long Ago," *Annual Review of Biochemistry* 52 (1983), known only through a secondary excerpt; the original is paywalled. **[R]**
- **The salsa golf anecdote.** A quote cannot carry a higher tag than the event it depends on, so the patent joke drops from **[A]** to **[R]**. es.wikipedia sets the invention at the **Mar del Plata Golf Club**, en.wikipedia at **the Ocean Club**; the conflict is stated, not smoothed. Coordinate corrected from -37.9695 / -57.5508 (about 6.8 km north of the city) to **-38.0293 / -57.5330**.

## 10. Atlas intersections

| Traveler | Crossing, checked against the committed journey file | Tag |
|---|---|---|
| `bernardo_houssay` | Doctoral supervisor from 1933; the purge of his chair is why Leloir resigned in 1943; he initiated the Campomar foundation; named in the Nobel lecture as the one influence on Leloir's career. Five pins inherited. | **[A]** |
| `juan_peron` | The 4 June 1943 GOU coup at the Casa Rosada, pin inherited byte-identical, is the rupture that purged the UBA. | **[A]** event, **[R]** chain |
| `borges` | The 1946 library dismissal belongs to the same purge climate in which Leloir left state science. Adjacency, not contact. | **[R]** |
| `victoria_ocampo` | es.wikipedia reports Leloir met Houssay through his cousin Victoria Ocampo. No document. | **[R]** |
| `eva_peron` | The Rainbow Tour reached Paris in 1947; Leloir was born there in 1906. A coincidence and nothing else. | **[R]** |
| `fermi` / `dirac` | Same Konserthuset stage, 10 December 1938 and 10 December 1933. Canonical pin shared. | **[A]** |
| `cesar_milstein` | Argentina's third science Nobel, 1984, taken as an emigrant in Cambridge, one year before Leloir's 1985 address telling Argentina to have faith in its future. | **[A]** juxtaposition |

**Negative results, recorded rather than omitted.** The Kaaba (21.4225, 39.8262) and Temple Mount (31.778, 35.2354) pins were checked for reuse and do not apply here. The Kirchner and Milei files both contain "Instituto", but neither was confirmed to name CONICET or the Instituto Leloir; that lead stays unpromoted. `adi_shamir` was checked for a Cambridge pin and is unrelated.

## Sources

**Reached and used**

- Nobel Foundation: **banquet speech** and **Nobel Lecture PDF**, 10 and 12 December 1970; **official prize motivation**, Royal Swedish Academy of Sciences, 1970.
- **English Wikipedia**: "Luis Federico Leloir"; "Beaumont College." **Spanish Wikipedia**: "Luis Federico Leloir"; "Instituto Leloir"; "Salsa golf." **Spanish Wikiquote**: "Luis Federico Leloir."
- **Infobae**, 5 September 2017, "Salsa golf: la historia del invento gastronómico de un Premio Nobel argentino."
- **La Prensa** (Buenos Aires), "Houssay, Leloir y Milstein: vivir para la ciencia", quoting Federico Pérgola, *Historia de la Medicina argentina* (Eudeba). URL 404, via the Wayback Machine.
- **Revista Gente**, via the archived Comodoro Rivadavia page at elchenque.com.ar (Wayback capture, 28 February 2007).
- **Nominatim** geocodes for 81 Avenue Victor Hugo, San Clemente del Tuyú, Mar de Ajó, Ramos Mejía, the Manzana de las Luces, Julián Álvarez 1719, Konserthuset, the Mar del Plata Golf Club, and Patricias Argentinas 435.
- Committed atlas files: `bernardo_houssay`, `juan_peron`, `borges`, `eva_peron`, `victoria_ocampo`, `fermi`, `dirac`, `cesar_milstein`.

**Attempted and unreachable, recorded as gaps**

- **nobelprize.org biographical and facts pages: HTTP 403** on both URLs, so the Foundation's own biography was never read. **britannica.com biography: HTTP 403.** **leloir.org.ar**: no historical content on the founder at the time of access.
- **Leloir, "Far Away and Long Ago," *Annual Review of Biochemistry* 52 (1983)**: paywalled, used only through a secondary excerpt, which is why the quotation from it is **[R]**.
- **"Comentarios sobre la investigación científica en la Argentina" (1986 printing)**: not retrieved; the quotation rests on Wikiquote's citation alone.
- **The archived Tesone / Sociedad Argentina de Diabetes page**: retrieved, and found **not to support** the salsa golf quotation attributed to it across the literature.

**Standing contradictions, not adjudicated:** the number of children (one daughter in en.wiki, four in es.wiki); the Paris school (École against Institut Polytechnique, neither teaching architecture); the Campomar street number (Julián Álvarez 1719 against 1917); the salsa golf venue (Mar del Plata Golf Club against the Ocean Club); and the Légion d'honneur ceremony (Paris or the Buenos Aires embassy, no source says).
