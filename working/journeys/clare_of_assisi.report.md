# Clare of Assisi: research report

*Chiara di Favarone di Offreduccio, c. 1194 to 11 August 1253. Assisi, Umbria. Calendar: Julian throughout, here and in `clare_of_assisi.journey.json`.*

Legend: **[A]** attested, source named · **[R]** reconstruction, tradition, hagiography or inference · **[C]** sources contradict, flagged and not adjudicated.

Journey file: `clare_of_assisi.journey.json`, 8 segments, 41 stops.

## 0. Evidential shape of the subject

Clare has an unusually good body of witness testimony and an unusually bad body of narrative. The 1253 canonisation depositions are the best thing in the dossier: fifteen sisters plus relatives and townspeople, questioned within four months of her death. The *Legend of Saint Clare* (c. 1255-56) is the worst: written for the cult, forty years after the events it describes most vividly, and the sole authority for the famous scenes. Neither was reachable in a primary edition, so anything tracing to either is **[R]** on that ground alone, even where the underlying fact is almost certainly true. Her own writings (Rule, Testament, Blessing, four letters to Agnes of Prague) were reachable in English and Italian renderings; the Latin critical text was not.

## 1. Assisi, 1194-1212

**Birth** to Favarone di Offreduccio and Ortolana, into the knightly *maiores*, in a fortified house beside the campanile of San Rufino. **[A**: Wikipedia, 'Clare of Assisi' and 'Cathedral of San Rufino, Assisi', the latter identifying that structure as the family home.**]** The date **16 July 1194** is **[R]**: the Catholic Encyclopedia and Wikipedia both carry it while noting it is not established by contemporary evidence, and Fortini, where it should be checked against the notarial record, was not reachable. Age fifty-nine at death is consistent with 1194 but does not fix the day.

**Baptism at the San Rufino font. [A**: Wikipedia, 'Cathedral of San Rufino, Assisi'.**]** Two atlas files carry the claim from the other side, `saint_francis.journey.json` ("the same font will later christen Clare di Favarone") and `pica_bourlemont.journey.json`, which adds Frederick II to the same basin. Three files agreeing is not three sources; all descend from the cathedral's tradition, and the Frederick II detail stays tradition here.

**1198 revolt, the Rocca Maggiore razed. [A**: Wikipedia, 'Rocca Maggiore'**]** for the uprising and the destruction. That the Offreduccio were among the dispossessed is **[R]**: no fetched source names them.

**Refuge in Perugia, c. 1198-1202. [R]**, standard in the biographies, unconfirmed in anything fetched; Clare's movements as a small child are undocumented.

**Marriage refused at about twelve. [R]**, Wikipedia citing hagiographic tradition. The year 1206 is computed from the traditional birth date and inherits its weakness.

**Hearing Francis preach. [C].** Wikipedia's 'Clare of Assisi' puts a Lenten sermon at **San Giorgio**, 1212; Wikipedia's 'Cathedral of San Rufino' puts the vocation-forming sermon at **San Rufino**, c. 1209-1211. Conflict on venue and year, not resolved. One stop is staged, at the San Rufino pin, stating the conflict in `date_confidence`.

**Secret meetings via Brother Philip, chaperoned by Bona di Guelfuccio. [R]**, from the depositions, not fetched.

## 2. March 1212, the flight

**The pool's date is wrong and has been corrected.** It gives "On Palm Sunday evening... 1212-03-20," which is self-contradictory. Julian Easter 1212 fell on 25 March, so Palm Sunday was **18 March**; 20 March was a Tuesday. Wikipedia's "20 March 1212" is a propagated error. Corrected throughout to **the night of 18-19 March 1212**.

**[C]** on the year: Fortini and part of the scholarship prefer **Palm Sunday 1211, that is 27 March 1211**, also a Sunday. Both years are defensible, 20 March under neither. The file uses 1212, names the 1211 alternative in `date_confidence`, and splits the departure (18 March) from the tonsure (19 March). `saint_francis.journey.json` independently dates the same scene 1212-03-18.

**The door of the dead. [R]**, and weaker than the pool suggested. it.wikipedia, 'Chiara d'Assisi', states flatly that *"Il racconto della Domenica delle Palme è presente solo nella leggenda di Chiara"*: the **whole** Palm Sunday narrative, not merely the door, is Legend-only. The stop says so.

**Tonsure at the Porziuncola. [A]** (Catholic Encyclopedia: "St. Francis, having cut off her hair, clothed her in a rough tunic"). Aunt Bianca and one companion, **[R]**.

**San Paolo delle Abbadesse, Bastia Umbra. [A]** for the 1212 reception. Altar-clinging and the shorn head shown to the kinsmen are Legend material, **[R]**.

**Sant'Angelo di Panzo. [A]**, Wikipedia, 'Clare of Assisi'.

**Agnes.** Sister Caterina follows sixteen days after the flight, renamed Agnes. **[A]**. The family's violent attempt to seize her is **[A]** from the depositions as summarised; the dead weight of her body and Monaldo's withered arm are faith claims, **[R]**, and the campa says so.

### Coordinate corrections carried out

Pool value, then value used, then error and authority.

- **San Paolo delle Abbadesse**: 43.087, 12.572 to **43.0766, 12.5528**, ~1.9 km. OSM Nominatim, matching it.wikipedia's siting at the Tescio-Chiascio confluence by the 1862 cemetery.
- **Sant'Angelo di Panzo**: 43.087, 12.652 to **43.0577, 12.6399**, ~3.4 km. OSM Nominatim; the pool's point sat on Subasio's north flank, the hermitage is southeast of Assisi.
- **San Giorgio** and **Santa Chiara** (afterlife lens): 43.0713, 12.6133 and 43.067, 12.612 to **43.0689, 12.6172**, ~400 m and ~455 m. The first lands near Piazza del Comune; corrected value inherited from `saint_francis.journey.json`.
- **San Damiano** (afterlife lens): 43.0592, 12.6183 to **43.0631, 12.6197**, ~275 m. Canonical atlas pin, §6.
- **Clare's family house** (afterlife lens): 43.0707, 12.6144 to **43.0717, 12.6187**, ~250 m. The pool's point is nearer the Chiesa Nuova, which tradition assigns to *Francis's* family.

## 3. San Damiano, 1212-1226

**Settlement at San Damiano. [C]** on the year: Wikipedia 'San Damiano, Assisi' gives c. 1212, 'Poor Clares' gives 1216. Not resolved; 1212 used for ordering and declared as such.

**Abbess. [C]**, three ways: Catholic Encyclopedia 1215 (made superior by Francis), Wikipedia 1216, Franciscan Media "age 21." Flagged, not resolved.

**Fourth Lateran Council, 1215. [A]**: new communities must adopt an already-approved rule. Clare was not at Rome; the stop stands at San Damiano and is explicit that what is dated is the constraint arriving, not a journey.

**Expansion from 1218**, Perugia then Florence, Venice, Mantua, Padua. **[A]**. Clare travelled to none of them and no stop is staged in any.

**Ugolino's *forma vitae*, c. 1219. [A]**, Catholic Encyclopedia. Its content characterised as Benedictine with Franciscan trimming: standard in the literature, **not** checked against the Latin.

**Francis at San Damiano, 1225, and the Canticle. [R]**. Clare's proximity is secure; the nursing attributed to her is not confirmed. Date inherited from `saint_francis.journey.json` (1225-04-15) so the files agree.

**The coffin at the window, 4 October 1226. [R]**, recorded in the Legend decades later. Staged from Francis's side in his own file at the same date.

**The long illness. [A]** for twenty-seven years (Franciscan Media: "serious illness for the last 27 years of her life"), counting back from 1253 to **1226**. The pool's geography lens inflated this to "roughly three decades" from "c. 1224/25"; that reading is **rejected** and the lenses are aligned on 1226. This corrects the pool, not a source.

## 4. 1228-1253, the argument with Rome

**The Privilege of Poverty. [C]** on shape. Catholic Encyclopedia: "1228 - September 17: Received the Privilegium Paupertatis," a single grant from Gregory IX. Wikipedia frames the pursuit as running roughly 1228-1240 through successive popes. Not reconciled; the file uses the dated bull and states the broader framing in `date_confidence`. A **1216 privilege attributed to Innocent III** is traditional, no original survives, historicity debated: not a stop, mentioned in the 1228 campa with its status stated.

**Clare's reply to Gregory IX. [R]**, and textually unstable: the Catholic Encyclopedia and Wikipedia give two English renderings that do not agree, neither traced to a primary edition. Both are flagged in the stop's quote source field.

**Agnes of Prague.** First surviving letter 1234 **[A]**; correspondence over two decades, four surviving letters, the women never met **[A**, Wikipedia, 'Agnes of Bohemia'**]**. Second and third letters c. 1235-36 and 1238, read as resistance to curial pressure on Agnes to accept an endowment: **[R]**.

**The attack on San Damiano. [A]**, **September 1240**. The pool's contradiction is **resolved and closed rather than carried**. The Catholic Encyclopedia's 1234 is an error refutable on external grounds: in 1234 Frederick II was reconciled with Gregory IX, who that July excommunicated Frederick's own son Henry at the emperor's request, and was not campaigning in Umbria; imperial war in the Papal States follows the March 1239 excommunication. en.wikipedia and it.wikipedia independently give September 1240 for San Damiano and June 1241 for Assisi. The rejected 1234 is named in the stop's `sources`, so the decision is auditable. The vessel: earliest testimony describes a small ivory or silver pyx, not the sunburst monstrance of later painting, **[A]** as an iconographic development.

**Siege of Assisi, 22 June 1241. [A]** for the episode; **[R]** for Clare's prayer as its cause, the community's own reading.

**1247 rule of Innocent IV; 1250 instruction; 16 September 1252 approval by Cardinal Rainaldo of Ostia.** All **[A]** from the general record, **no primary text fetched**. The exact days for 1247 and 1252 are the weakest dates in the journey.

***Solet annuere*, 9 August 1253. [A]** to the day. The pool's "one day before her death" is **wrong: it was two days.** Bull dated 9 August, death 11 August. en.wikipedia's 'Poor Clares' repeats the error, it.wikipedia has it right. The separate tradition that the sealed bull reached her hands on **10 August** is staged as its own stop, not conflated with the bull's date.

**Death, 11 August 1253, age fifty-nine. [A]**. Last words **[R]**, traced only to catholicsaints.info and Wikipedia, never to the Acts of the Process. "I am speaking to my soul" is **[R]** and doubly weak: franciscanmedia.org calls it secondhand from Sisters Benvenuta and Anastasia, and summarises rather than quotes.

## 5. Afterlife

- Burial at **San Giorgio**, inside the walls, against theft of the body. **[A]**
- **28-29 November 1253**, canonisation inquiry under Bishop Bartolomeo of Spoleto. **[A]** as an event; the surviving Latin is a later translation of a lost vernacular original; transcript not fetched, a gap.
- **26 September 1255**, canonised by Alexander IV at **Anagni**, bull *Clara claris praeclara*. **[A]**. en.wikipedia's 'Clare of Assisi' wrongly says **Rome**, its own 'Anagni Cathedral' article and it.wikipedia say Anagni; the pool picked correctly. No stop staged at Anagni, §7.
- **1257**, the community leaves San Damiano for the city with the crucifix, now in the basilica, a replica left in the original church. **[A]**
- **3 October 1260**, translation to the basilica, buried under the high altar, grave then deliberately lost. **[A]**
- **1263**, Urban IV names the order for her and permits corporate ownership, the Urbanist observance. **[A]**. Folded into the 1257 campa; a Roman act after her death, so no stop.
- **23 September 1850**, coffin located and opened; flesh and clothing decayed to dust, skeleton intact. **[A]**. This contradicts the popular "incorrupt visible body"; what is displayed is a wax effigy over the relics.
- **29 September 1872**, Archbishop Gioacchino Pecci (later Leo XIII) translates the bones to the crypt. **[C]**: it.wikipedia dates the crypt's neo-Gothic restyling to **1935** and does not mention 1872. Flagged, not resolved.
- **1958**, Pius XII names her patroness of television on the strength of the Legend's Christmas vision. **[A]** for the act, year only. **[R]** for the vision.

## 6. Canonical pins inherited

Assisi's core geography is already fixed in `saint_francis.journey.json`, inspected directly. These are used byte-identical, not re-geocoded: San Rufino / Offreduccio house **43.0717, 12.6187** · San Damiano **43.0631, 12.6197** · Porziuncola **43.0578, 12.5804** · Assisi city **43.0707, 12.6176** · Perugia **43.1119, 12.389** · San Giorgio / Santa Chiara **43.0689, 12.6172**.

**One discrepancy inside the interlock lens, flagged.** Its summary gives San Giorgio / Santa Chiara as **43.0705, 12.616**. Direct inspection shows that is the pin of a *different* stop, "the stall of San Francesco il Piccolino"; the actual San Giorgio **burial** stop is **43.0689, 12.6172**, matching en.wikipedia for the Basilica of Saint Clare and the geography lens. The burial pin is used; whoever maintains the canonical list may want to correct the summary. The lens likewise gave "Perugia / Collestrada" as 43.0856, 12.481, which is Collestrada, not Perugia.

Other pins used: San Paolo delle Abbadesse 43.0766, 12.5528; Sant'Angelo di Panzo 43.0577, 12.6399; Rocca Maggiore 43.073, 12.6151. Prague and Anagni were corrected in the pool but are **not used**, since no stop is staged at either.

**Canonical world pins checked, all negative:** neither the Kaaba, the Temple Mount, Paris nor Buenos Aires has any documented claim on this subject. Reported as a negative, not invented into one.

## 7. Stop-ownership decisions

Four candidate scenes were dropped as stops because Clare was not there. Recorded so nothing is silently lost.

1. **Collestrada, November 1202.** Francis's battle and captivity. Clare was eight and her presence is undocumented. Kept as one sentence of background in the Perugia campa; the scenes stay on `saint_francis.journey.json`.
2. **Prague, the Convent of Saint Agnes.** Agnes of Prague's own geography. Clare never crossed the Alps and the two never met. The correspondence is staged where Clare wrote it, at San Damiano; Prague is in `suggested_refs` only.
3. **Anagni, 26 September 1255.** Alexander IV's act, two years after her death, in a city she never visited and to which her body was never brought. Stated inside the 1260 translation campa, at Assisi.
4. **Rome: Fourth Lateran 1215, Urban IV 1263.** Curial acts that shaped and then unmade her settlement. Folded into San Damiano and Assisi campas; Clare is not recorded outside the Assisi basin at any point in her life.

One borderline case **kept**: the November 1253 depositions at San Damiano. Clare was dead and the deponents are the sisters. Retained because it happens at her own house and is the evidentiary floor under every other stop in the file. Flagged for the operator.

## Apparatus relations for the operator

Clare is **not** listed in `EXCEPTIONS.md`, so no backward apparatus stops are licensed and none were written. Two items are recorded here rather than deleted, for the operator to rule on.

1. **Pius XII, 1958, Clare as patroness of television.** *Direction: forward.* A twentieth-century reinterpretation of a Legend episode, reaching 705 years past her death, and the reinterpretation is what the papal act consists of. Retained as a stop because it is an attested act **about Clare and her cult**, at her own pin, and because relic-and-cult afterlife stops are ordinary atlas practice. It is **not** an apparatus stop: no framework of Clare's is applied to anything later. If the operator reads the "remote vision" framing as apparatus-applied-forward, the stop should be cut, not softened.
2. **Modern scholarship reframing Clare's agency.** *Direction: forward.* Bartoli (*Chiara d'Assisi*, 1989) and Mooney (*Clare of Assisi and the Thirteenth-Century Church*, 2016) recast Clare from a reflection of Francis into an independent author and legal negotiator. Handled as sources per the standing one-directional rule, in `suggested_refs`, never staged. No ruling needed unless the operator wants the historiography given a stop, which would require the exception.

Nothing was found running the other way. No relation was deleted.

## Interlocks with existing atlas files

- **`saint_francis.journey.json`**: the only traveller named in a campa, named repeatedly, on the strongest grounds. He preaches the sermon she hears, cuts her hair, gives her San Damiano, makes her abbess over her objection, writes the Canticle beside her wall, and his coffin is brought to her window. Six of his stops overlap her geography and were checked for collisions; the two files stage the shared events from opposite sides (tonsure, Canticle, funeral procession) with matching dates.
- **`pica_bourlemont.journey.json`**: Francis's mother is **not** named in any campa. Her file carries the same San Rufino font claim and two San Damiano scenes, but no relation between Pica and Clare is attested. Shared geography is not a reason to name-drop. Her file is cited in `sources` where its claims are load-bearing.
- **`margery_kempe.journey.json`**: an Assisi stop for the Lammas Day Porziuncola pardon, c. 1414, connected to the indulgence, not to Clare, two centuries later. Not named, not staged.
- **Absence check, a gap:** no atlas file names Agnes of Prague, Innocent IV, Alexander IV / Cardinal Rainaldo, Thomas of Celano, or Jacques de Vitry. Clare's whole curial network, 1230s to 1253, is unattested in the atlas outside her own file. Nothing to inherit, nothing to write into anyone else's file.

`QUEUE.md` line 151 lists Clare with the note "already done." No `clare_of_assisi.journey.json` or slug variant existed before this pass; the directory was listed and grepped for *clare*, *chiara*, *agnes*. The note appears stale.

## Sources

**Reachable and used.** Wikipedia: 'Clare of Assisi', 'Poor Clares', 'Cathedral of San Rufino, Assisi', 'Rocca Maggiore', 'San Damiano, Assisi', 'San Damiano Cross', 'Basilica of Saint Clare, Assisi', 'Agnes of Bohemia', 'Anagni Cathedral'. it.wikipedia: 'Chiara d'Assisi' (independent on the 1240/1241 dating, on *Solet annuere*, and on the Legend-only status of the Palm Sunday narrative), 'Bastia Umbra', 'Basilica di Santa Chiara'. Catholic Encyclopedia, 'Saint Clare of Assisi' · Franciscan Media, two articles · porziuncolaproject.com, Rule chs. 1, 6, 8 · assisisantachiara.it, 'Gli scritti di S. Chiara' · ora-et-labora.net · catholicsaints.info · OSM Nominatim. Atlas-internal: `saint_francis.journey.json`, `pica_bourlemont.journey.json`, `margery_kempe.journey.json`, `EXCEPTIONS.md`, `QUEUE.md`.

**Named, not reachable, and what each gap costs.**

- **Acts of the Process of Canonisation, 1253.** The most consequential gap: primary authority for the depositions, the last words, "I am speaking to my soul," the Bastia altar scene, the Agnes abduction. Everything from it is [R] for that reason alone.
- **The *Legend of Saint Clare*, c. 1255-56**, no Latin text. Same consequence for the door of the dead and the Christmas vision.
- **Fortini's documentary biography and the Assisi archive**, so the 1194 / 16 July birth date and the 1211-versus-1212 flight year could not be checked against notarial record.
- **Armstrong, ed., *Clare of Assisi: Early Documents. The Lady* (2006)**, the standard critical edition. All quoted texts of Rule, Testament, Blessing and letters therefore come from devotional sites, one of which carries an OCR error corrected in the pool ("let the confidently" to "let them confidently").
- **Latin texts of the bulls and acts**: *Sicut manifestum*, the 1247 rule, the 1250 instruction, Rainaldo's 1252 approval, *Solet annuere*, *Clara claris praeclara*. Carried from encyclopedia and general record.
- **Bartoli (1989) and Mooney (2016)**, carried on the pool's framing.
- The pool notes **WebSearch was unavailable** for part of the geography pass, hence several coordinates at three decimals needing correction.

**Rejected** (each argued where it arises above): the Catholic Encyclopedia's **1234** for the attack on San Damiano, §4 · **20 March 1212** for the flight, §2 · **"one day before her death"** for *Solet annuere*, §4 · the **canonisation at Rome**, §5 · the **"incorrupt visible body"**, §5 · **"roughly three decades" of illness from c. 1224/25**, §3.
