# Report: Domingo Faustino Sarmiento (sarmiento.journey.json)

**Span:** 1811–1888, gregorian, 9 segments, 45 stops, 16 direct quotes (all Spanish, all transcribed from a primary text).

## Sources

Two primary texts were read directly rather than through commentary:

- **Facundo** (1845), full Spanish text, biblioteca-antologica.org PDF — searched, not skimmed.
- **Viajes en Europa, África i América, 1845-1847**, the 1886 *Obras* tomo V scan on the Internet Archive (`viajeseneuropaa00sarmgoog`), full OCR. This is the volume carrying the African letter to Juan Thompson. Every Viajes quotation in the dataset is transcribed from that scan's own text, in Sarmiento's period orthography (`i` for *y*, `j` for *g*, `arjentino`, `relijion`) — that is genuinely what the page says, not a stylisation.
- **De la educación popular** (1849), Cervantes Virtual PDF, for the Paris *salas de asilo*.
- Secondary spine for chronology and coordinates: es.wikipedia, Museo Histórico Sarmiento, Casa Natal de Sarmiento, Archivo General de la Nación (the Sarmiento–Mary Mann epistolary), sobrecartas.com for the Alsina and Mitre letters.

**Orthography note:** the Facundo quotations are given in the modernised spelling of the edition actually consulted; the Viajes quotations in the 1886 original spelling. Neither was converted into the other, and nothing was back-translated from English.

---

## VERDICT on the Abd-el-Kader question

**The hypothesis holds, and holds harder than expected. Both texts name him, and the gaucho/Bedouin analogy is explicitly Sarmiento's own, in his own words, before he ever saw Africa.** Three independent findings:

**1. Facundo names Abd-el-Kader directly — once.** Chapter XIV (*Gobierno unitario*), on the French blockade and Rosas's appetite for international fame:

> «Sus anticipaciones han ido más allá de lo que él podía prometerse, y sin duda que Mehemet-Alí ni **Abdel-Kader** gozan hoy en la tierra de una nombradía más sonada que la suya.»

The emir appears there as the world's other famous non-European insurgent chief — the yardstick for Rosas's notoriety. It is a single sentence, and it is not the gaucho analogy; I have not encoded it as a stop, but it is the proof that the name was already in Sarmiento's head in 1845.

**2. The gaucho-as-Bedouin analogy is explicit, systematic, and Sarmiento's, not a scholar's later reading.** It runs through Facundo from chapter I onward and is stated in so many words. Chapter I:

> «La vida primitiva de los pueblos, la vida eminentemente bárbara y estacionaria, la vida de Abraham, que es la del **beduino** de hoy, asoma en los campos argentinos.»

and, of the mule-train raiders, «estos **beduinos americanos**»; and of the gauchos' faces, «semblantes graves y serios, **como los de los árabes asiáticos**»; and of the caudillo, «El caudillo argentino es un **Mahoma** que pudiera, a su antojo, cambiar la religión dominante.» The decisive one is chapter IV, which names Algeria itself:

> «Las **hordas beduinas** que hoy importunan con su algazara y depredaciones **las fronteras de la Argelia** dan una idea exacta de la **montonera argentina**... La misma lucha de civilización y barbarie, de la ciudad y el desierto, existe hoy en África; los mismos personajes, el mismo espíritu, la misma estrategia indisciplinada, entre la horda y la montonera.»

That was written in Santiago in 1845 by a man who had never left the Southern Cone. The orientalised pampa is not imposed on Sarmiento by Said-influenced criticism; it is the load-bearing structure of his own argument, and he says so.

**3. The Viajes then puts him physically on Abd-el-Kader's ground, and he names the emir repeatedly.** Sarmiento reached Orán on 2 January 1847 — eleven months before the surrender — as an official guest of the French army. In the African letter he:

- explains the emir's faith as the engine of his war: «La palabra incredulidad no existe todavía entre los árabes, i **Abd-El-Kader** no fuera tan grande guerrero, si no creyera i esperara firmemente»;
- transcribes the Mahdist prophecies then circulating, and glosses the emir's name («*el Servidor del Poderoso*»);
- and, riding out of Mascara with General Arnault, crosses **the plain of Eghris**: «En aquella llanura está la casa paterna de **Abd-El-Kader**, hijo de un gran marabut, a quien en una peregrinación a la Meka le fueron revelados en sueños los altos destinos que estaban reservados a su hijo. Mas tarde en aquella misma llanura cinco mil jinetes árabes se reunieron para proclamar Emir a Abd-El-Kader.»

That is the same plain, the same event, that `abdelkader.journey.json` pins at **35.25 / 0.1424** as "Plain of Eghris, near Mascara — proclaimed Amir al-Mu'minin, 22 November 1832". Sarmiento's stop is pinned to the identical coordinate. **The edge is a shared physical pin, fifteen years apart, and it is textual, not inferential.**

Two further confirmations from the same letter: he interviews **Marshal Bugeaud** (who also appears in the Abdelkader dataset, at Tafna and Isly) and the two men compare the Algerian razzia with Argentine counter-montonera warfare — Bugeaud «comprendió mui bien que los franceses parodiarían a los **gauchos árabes**». And in the tent of a *duar*, taking the ritual *diffa*, the metaphor closes on itself: «¡Tate! me dije para mí, yo conozco todo esto, i las tiendas patriarcales de los descendientes de Abrahan no están mas avanzadas que los toldos de nuestros salvajes de las Pampas.»

**What I did *not* find, and have not encoded:** no meeting, no correspondence, no attempt at contact between the two men; Sarmiento never mentions the emir's later Damascus fame (he died in 1888, five years after Abdelkader, but the 1860 rescue does not appear in his writing that I located); and Facundo's single naming of Abd-el-Kader is *not* part of the Bedouin argument — the two things sit in different chapters and do different work. The dataset says exactly that much and no more.

---

## Judgment calls

- **The Bedouin analogy gets its own stop** ("Santiago, the gaucho written as a Bedouin", 1845) placed *before* the voyage, so that the Africa segment reads as what it was: a man travelling to check his own metaphor against the ground, and finding it confirmed. That sequence is the spine of the whole file.
- **The Chacho is included, undebunked and unsoftened.** The 1861 letter to Mitre — «No trate de economizar sangre de gauchos. Este es un abono que es preciso hacer útil al país» — is quoted at the Olta stop, verbatim and without cushioning. The register says the canon is true; the Argentine canon carries this sentence, and the file would be dishonest without it. It is placed deliberately as the dark answer to the Facundo stop: the book that read the caudillo as a desert chieftain became a government that treated him as one.
- **Froebel is a *late and mediated* edge, and the file says so.** Sarmiento's 1849 model for early childhood is the French *salle d'asile*, not the kindergarten — I searched *De la educación popular* and found neither Pestalozzi nor Froebel named in the text consulted. The Froebel connection is real but arrives forty years later and by way of Boston: Mary Peabody Mann and the Peabody sisters → Sarmiento → Sara Chamberlain de Eccleston → the Paraná kindergarten of 4 August 1884 and the Sociedad Froebeliana Argentina. Both the Paris *salas de asilo* stop and the 1884 Paraná stop carry the edge; neither claims he read Froebel in 1847.
- **Pestalozzi is an ancestral, not a personal, edge.** I found no evidence Sarmiento visited Yverdon, Burgdorf or Hofwyl, and did not invent one. The Pestalozzi link runs through the Prussian and Massachusetts systems he *did* study; the edge lives in the sources fields of the education stops rather than in a fabricated pin.
- **The 1886 *Obras* OCR is imperfect**, so quotations were chosen from passages where the scan is clean and unambiguous; obvious single-character scanner artefacts were not "corrected" into new wording, they were avoided by picking other sentences.

## Gaps and time-folds

- The Chilean decade 1841–1845 (journalism, the romanticism polemic with Bello's circle, four newspapers) is compressed into four stops. The El Progreso language quarrel is folded into the orthography and Facundo stops.
- The European itinerary is thinned hard: Le Havre, Belgium, Holland, Germany, Switzerland and England are represented by nothing at all, and Italy by one stop. This is deliberate — Sarmiento's Europe is a *disappointment*, and the letters that matter are Grand Bourg, Paris, Madrid, Africa. Africa gets seven stops, more than Europe.
- **The duar stop (35.55 / -0.45) is an approximation.** Sarmiento names no village; he rode out from Orán with an escort to a tent camp. The pin is a nearest-plausible placement on the Oran hinterland, not a located site.
- The presidency's works (railways, telegraph, census, navy, military college, meteorological office) are summarised inside campas rather than given stops; only the schools, the fever, and the observatory are pinned.
- Family is thin: Benita Martínez Pastoriza, Ana Faustina, and Aurelia Vélez appear barely or not at all. Dominguito appears through his death, which is how the canon carries him.

## Five richest episodes

1. **Baños del Zonda, November 1840** — a beaten schoolmaster writes a French sentence in charcoal on a bathhouse wall so his pursuers can't read it, and the government sends a commission to decipher the hieroglyph. Five years later it is the epigraph of the founding book of Argentine literature.
2. **Grand Bourg, 24 May 1846** — a whole day alone with San Martín, in which Sarmiento deliberately plucks strings until the *campagnard* vanishes and the young general of the Andes reappears in the room; then they name Rosas and the vision collapses. Direct shared pin with `san_martin.journey.json`.
3. **The duar and the diffa, January 1847** — sitting cross-legged in an Arab tent expecting Rebecca and Jael, getting cramp, hauling one knee up under his chin *the way a gaucho does*, and realising he has been here his whole life.
4. **The plain of Eghris, February 1847** — riding across the field where Abd-el-Kader was proclaimed emir, past the emir's father's house; and that evening a French general in the middle of Africa hands him a *Revue des Deux Mondes* and points at the words *Civilisation et Barbarie* — his own book, reviewed, found at the far end of the earth.
5. **West Newton, October 1847** — Horace Mann with no Spanish, Sarmiento with no English, and Mary Peabody Mann sitting between them translating for hours. Everything downstream — the sixty-five North American teachers, Paraná, the 1884 kindergarten — begins in that parlour.

## Connections to the atlas

- **abdelkader** — the key edge, and it is a *shared physical pin* at the plain of Eghris (35.25 / 0.1424), plus a shared antagonist in Marshal Bugeaud. The two files now read against each other: the emir's war seen from inside by its leader, and seen from the French guest tent by an Argentine writer who had already invented the same country in his head. Sarmiento is, so far as I can find, the only Latin American in the atlas who was physically inside the Algerian war.
- **san_martin** — shared pin at Grand Bourg, 24 May 1846, from the visitor's side; `san_martin.journey.json` should carry the same date from the host's.
- **pestalozzi** and **froebel** — the method's downstream terminus. Froebel by way of Boston in 1884; Pestalozzi ancestrally through Prussia and Massachusetts. Both edges are named honestly as mediated.
- **humboldt** — the other great reader of American nature as text, and the direct precedent for Sarmiento's Córdoba observatory / Burmeister academy programme: European instruments turned on the southern hemisphere.
- **che_guevara**, **lautaro**, **juan_peron**, **eva_peron**, **borges** — the Argentine counter-tradition. Facundo's orientalised pampa is the thesis every later Argentine writer in the atlas has to answer; Borges answers it directly, Perón and Che from the side Sarmiento wrote against, Lautaro from the side he wrote out.
- **bolivar**, **belgrano**, **sucre**, **miranda**, **ohiggins**, **alvear** — the libertador generation he arrives one beat too late for, and interviews in its old age.
- **dihya** — the other Algerian in the atlas; the desert Sarmiento reads as barbarism is her country.

---

# Verification pass — 2026-07-20

Independent verify stage, run against `joan_of_arc.journey.json` as the schema and register reference. `json_check.py` passed before and after: 9 segments, 45 stops, 16 quotes, no schema or field defects. **No stop was added, removed or reordered** — every repair is in place, so the Spanish twin stays positionally aligned (though six stops now carry corrected field values).

## Quotes — 16 of 16 checked, all in the original Spanish, none invented

Every quotation in the file was traced to its source text. Nothing was nulled and nothing was rewritten, because nothing was fabricated.

**Facundo (2 quotes)** — verified against the full Spanish text (educ.ar / elaleph edition, extracted whole and searched):
- cap. I, "Hay algo en las soledades argentinas… entre el Tigris y el Eúfrates" — **verbatim**, including the `Eúfrates` accent of the edition.
- cap. IV *Revolución de 1810*, "Las hordas beduinas… las fronteras de la Argelia… la misma lucha de civilización y barbarie" — **verbatim**. Chapter attribution confirmed correct. Note some editions read `algaradas` where this one reads `algazara`; the file follows the edition consulted.

**Viajes (9 quotes)** — verified line by line against the 1886 *Obras* tomo V scan (`viajeseneuropaa00sarmgoog`), the same volume the research stage used. All nine are **verbatim** in period orthography, allowing for OCR damage in the scan itself:
Grand Bourg / San Martín (`momentos sublimes… el campagnard de Grandbourg`); Madrid (`la villa de Madrid`); Orán departure (`Ahora parto para África`); Mitidja (`el velado horizonte árabe`); Abd-el-Kader's faith (`La palabra incredulidad no existe todavía entre los árabes`); Bugeaud (`parodiarían a los gauchos árabes`); the diffa (`¡Tate! me dije para mí`); the plain of Eghris (`la casa paterna de Abd-El-Kader`); the Arab trackers (`los baqueanos árabes… huelen la tierra para orientarse`).

The Eghris passage is confirmed as the report claimed, and the scan spells the plain **Eghrees** — the dataset's "Eghris" is a normalisation to match `abdelkader.journey.json`, not a misreading.

**Alsina letter, 12 Nov 1847 (2 quotes)** — this volume's OCR stops before the American letters, so both were verified against an independent transcription of the letter: "Los Estados Unidos son una cosa sin modelo anterior, una especie de disparate que choca a la primera vista" and "Un hombre no llega a la plenitud de su desenvolvimiento moral e inteligente sino por la educación: luego la sociedad debe completar al padre en la crianza de su hijo." Both **verbatim**; both genuinely from that letter, as the `quote_source` states.

**Mitre letter (1 quote)** — "No trate de economizar sangre de gauchos. Este es un abono que es preciso hacer útil al país." **Verbatim**, and the date and place in `quote_source` (Buenos Aires, 20 September 1861) are **confirmed exactly**. Left undebunked and uncushioned, per the register.

**De la educación popular (1 quote)** — the *salas de asilo* sentence confirmed present in the 1849 text.

**Baños del Zonda (1 quote)** — `On ne tue point les idées` confirmed both as the Zonda wall inscription and as the epigraph of Facundo, and the attribution to Fortoul that the campa calls out is confirmed as the attribution Sarmiento himself made.

### One quote repaired
- **Mitidja**: the quotation silently elided `la resignación que no desespera,` between `en su humildad aparente,` and `la enerjia que no se somete`. An ellipsis was inserted. Wording otherwise untouched.

## Coordinates — 16 spot-checked, 5 corrected

Confirmed correct and left alone: San Francisco del Monte de Oro (−32.60/−66.13, exact); Casa Natal de Sarmiento (Sarmiento 21 Sur, San Juan); Mascara (35.39664/0.14027 — the file's 35.3968/0.1400 is essentially exact); the plain of Eghris (Ghriss, just south of Mascara, and identical to the `abdelkader` pin as intended); Córdoba Observatory (Laprida 854, Barrio Observatorio); Escuela Normal de Paraná (Monte Caseros y Urquiza); Diamante (Punta Gorda crossing, pin sits correctly on the river); Orán; Pocuro (Calle Larga commune confirmed); Recoleta.

**Corrected:**

| Stop | Was | Now | Why |
|---|---|---|---|
| Baños del Zonda | −31.5250 / −68.7333 | **−31.5558 / −68.6928** | ~5 km off. The Quebrada de Zonda is in Rivadavia dept, at 31°33′21″S 68°41′34″O; the old pin sat north-west of the gorge. |
| West Newton | 42.3487 / −71.2270 | **42.3455 / −71.2260** | Old pin was West Newton square; the Mann house stood at 155 Chestnut St, corner of Highland (now Crocker Circle), a quarter-mile south of the railroad. |
| Caseros | −34.5900 / −58.5700 | **−34.6028 / −58.6122** | ~4 km off. Battlefield is 34°36′10″S 58°36′44″O, under the Colegio Militar and the Palomar de Caseros. |
| Olta | −30.6333 / −66.2500 | **−30.6167 / −66.2667** | ~2.5 km off the town. (Peñaloza was actually run down at Loma Blanca, ~2.5 km from the plaza; the head went on the pike in the plaza, which is what the stop pins.) |
| Asunción, the death | −25.2637 / −57.5759 | **−25.2881 / −57.6159** | **~5.5 km off** — the old value was a database centroid for greater Asunción, out east near the botanical garden. Sarmiento died on calle De la Residenta between Saltos del Guayrá y Washington, barrio San Roque, beside what is now the Gran Hotel del Paraguay (De la Residenta 902, −25.28808/−57.61594). The worst error in the file. |

## Dates — one corrected

Chronology is strictly ascending within every segment, before and after. Confidences are honest: `attested` is used for documented public acts, `traditional` for canonical episodes without a fixed day, `inferred` for the Africa itinerary where Sarmiento gives no dates — that grading is sound.

Confirmed exactly as dated: Facundo's first folletín in *El Progreso* (2 May 1845); the Grand Bourg visit (24 May 1846); the Chacho's death (12 Nov 1863); the Córdoba observatory (24 Oct 1871); the first jardín de infantes at Paraná (4 Aug 1884); the death (11 Sept 1888); the return of the body (21 Sept 1888).

**Corrected:** the Escuela Normal de Paraná stop was dated **1870-08-13**, which is neither of the two real dates. The founding decree Sarmiento and Avellaneda signed is **13 June 1870**; classes began 16 August 1871. Set to **1870-06-13**, and the campa's opening clause was rewritten from "The first national normal school of Argentina opens at Paraná" to name the decree and note that the doors open the August after next — so the stop no longer collapses the two events. Campa now 104 words, still in range and in present tense.

## Campas and register

All 45 campas fall between 81 and 108 words (spec: 60–110), all present tense, all in the mythic register. The great episodes are not flat: the charcoal on the bathhouse wall, the day alone with San Martín, the diffa in the tent, the plain of Eghris, the West Newton parlour, and the head on the pike all carry their full weight. No campa needed rewriting for register.

Stop count (45) is well above the 30 threshold, so no stops were added.

## Not confirmed

- **The duar (−35.55/−0.45)** remains the approximation the research report already flagged. Sarmiento names no village; the pin is a plausible placement on the Oran hinterland. Left as is, honestly labelled `inferred`.
- **Grand Bourg (48.6206/2.4297)**: the house is confirmed at 1 rue du Général San Martín, Évry-Courcouronnes (Grand Bourg sector), but no source gives a coordinate. The existing pin is consistent with that address and was left alone.
- **Facundo `algazara`/`algaradas`**: editions differ; not resolvable without collating originals, and immaterial.
- **Orthography is deliberately mixed** — Facundo and *De la educación popular* in modernised spelling, Viajes in the 1886 original (`i`, `arjentino`, `relijion`). This follows the editions actually consulted and is documented above; it was not "normalised", since normalising would mean altering quotations.
