# Lorenzo di Piero de' Medici, "il Magnifico" (1449-1492): research report

*Compiled 2026-08-24 for `lorenzo_de_medici_il_magnifico.journey.json`. 42 stops, 8 segments, calendar `julian`.*

**Legend.** **[A]** = attested, source named. **[R]** = reconstruction, tradition, or a claim from the crawled dossier with no re-fetched primary behind it. Where sources disagree, the disagreement is printed and left standing.

**Caution about the pool.** The verified research pool arrived with its own corrections attached, several severe: a poem attributed to the wrong tournament, a causal sequence reversed, a death staged at the wrong villa, and ten coordinates out by between 80 m and 4.1 km (casa vecchia, Baptistery, Cafaggiolo, the Apostolic Palace on two stops, Piazza Santa Croce, Bagnolo, Sarzanello, Poggio a Caiano, Fiesole, San Marco). All are applied; each stop's `date_confidence` carries the old value, the new value, the distance and the authority, and the reasons are given by phase below. Where the pool says "not independently re-verified against a primary source in this pass", that wording is carried forward, not quietly upgraded.

---

## 1. Birth and boyhood, 1449-1464

**[A]** Born 1 January 1449 in Florence to Piero di Cosimo de' Medici and Lucrezia Tornabuoni (Wikipedia, 'Lorenzo de' Medici'; corroborated by Ingeborg Walter's *Dizionario Biografico degli Italiani* entry per the dossier).

**[A, pin corrected]** The birthplace is the *casa vecchia*, not the Palazzo Medici Riccardi. The pool's prose said "the old Medici house" while its pin pointed at the new palace, occupied only from about 1458; Wikipedia, 'Palazzo Medici Riccardi', puts the old house "some 50 metres north, on the same street".

**[R] Baptism, 6 January 1449.** The Epiphany date is inferred from Florentine practice; no fetched source states it. The pool tagged it [A]; it is **downgraded to [R]** on the pool's own correction note. Its pin was byte-identical to its Cathedral pin, which would have put the baptism and the Pazzi attack on one dot.

**[R] Cafaggiolo.** The dossier does not name it; the entry is reconstruction from standard accounts of Medici villa use (F. W. Kent). The pool's pin fell 4.1 km away in open countryside.

**[A, year only] Cosimo dies, 1464.** The pool carries the year alone; the stop is dated 1464-01-01 with the default stated. The 1 August date was not imported from memory.

---

## 2. The diplomatic circuit, 1465-1466

**[A]** Piero sent the teenage Lorenzo to Milan, Ferrara, Venice, Bologna, Rome and Naples (Wikipedia; dossier, 'Early Career and Journeys, 1465-1469').

**Honest gap.** The circuit is attested as a list of cities. Not one leg is separately dated, and nothing survives in the reached sources about what was said at any of them. All six stops are dated `1465-01-01`, with `date_confidence` stating that the order follows the itinerary as listed and is not documented. The Bologna campa says outright that the record gives the city and nothing of its content.

**[A, pin corrected] Rome.** The pool's Vatican pin sits on St Peter's, 215 m from the Apostolic Palace, and it reused that wrong point twice, so the error was doubled.

**[A, year only] The 1466 coup** by Luca Pitti, Dietisalvi Neroni and Niccolò Soderini, with Venetian backing; it failed.

---

## 3. Inheritance, 1469-1472

**[A] The giostra, 1469, with a major misattribution stripped.** Lorenzo won first prize at twenty; Verrocchio painted the banner; the horse was Morello di Vento (Wikipedia). **Poliziano's *Stanze per la giostra* are removed from this event entirely.** Per Wikipedia, 'Angelo Poliziano', they were written on **Giuliano's** tournament of **1475** and left unfinished when the 1478 conspiracy killed their protagonist. The poem for Lorenzo's giostra is Luigi Pulci's *La Giostra*, which the file names. The pool carried the error twice, at `chronology[4]` and `geography[9]`; both are corrected. Date flagged: Wikipedia attaches 7 February 1469 to the **betrothal**, not the joust, so the file keeps that date at low confidence. The pool also presented a middle clause of the *Ricordi* quote as a freestanding sentence and altered its punctuation; the file uses an ellipsed excerpt of the verified verbatim text.

**[A]** Marriage to Clarice Orsini, 4 June 1469, four days of celebration (Wikipedia, 'Clarice Orsini'); the 6,000-florin dowry is **[R]**, dossier only. **[A]** Piero dies and the succession is asked for on 2 December 1469; the famous *Ricordi* line about not being able to be rich in Florence without the state was **not** used, being absent from the verified pool. **[A]** The 663,755-florin reckoning of Medici outlay 1434-1471 is quoted verbatim from Brucker (ed.), *The Society of Renaissance Florence* (1971), p. 27.

**[R] Prato, 1470.** Nardi's rising, marked by the pool "independently unconfirmed by a fetched primary source in this pass". Carried at that strength.

**[R] Rome, 1471.** Embassy after the election of Sixtus IV, honours, antiquities. Dossier summary. The election fell on 9 August 1471, placing the embassy in the autumn, but the pool carries only the year, so the stop is dated 1471-01-01.

**[A, responsibility contested] Volterra, 18 June 1472.** Siege dates and sack attested (Wikipedia, 'Volterra'). Not resolved: the pool states Lorenzo "did not personally conduct the sack" and that "a direct order to pillage is not established", while his regime pressed the intervention and profited by it.

---

## 4. The Pazzi conspiracy and after, 1474-1479

**[R] Pisa and the Salviati appointment, 1474-1478.** Dossier summary, dated 1474-01-01 as the opening of the quarrel.

**[A, with a myth removed] 26 April 1478.** Attack during High Mass; Giuliano and Francesco Nori stabbed to death; Lorenzo wounded in the neck, escaping into the sacristy (Wikipedia, 'Pazzi conspiracy'; it.wikipedia, hour about 13:30). **"Easter Sunday" is struck.** Easter 1478 fell on 22 March; 26 April was an ordinary Sunday. The pool's geography lens carried the Easter claim; its own note contradicts it.

Three well-known details absent from the pool were declined: nineteen wounds on Giuliano, Poliziano at the sacristy doors, Botticelli's defamatory fresco of the hanged men. They may be true; they are not in the verified material.

**[A, date range extended] The hangings.** Salviati and Francesco de' Pazzi from the palace windows within hours on 26 April; **Jacopo de' Pazzi on 28 April at the twenty-third hour** (it.wikipedia). The pool compressed all three into "1478-04-26/27". Bodies thrown into the Arno is confirmed; **"dragged through the streets" is tradition only**, and lives in `date_confidence`.

**[A]** Bull of excommunication, 1 June 1478. Interdict on Florence, 20 June 1478. About eighty executions between 26 April and 20 October, a total the pool cautions mixes formal trial, mob killing and summary execution; the campa says so and does not present eighty as a judicial number.

**[A]** Bandini Baroncelli hanged from a window of the Palazzo del Capitano del Popolo, 29 December 1479, after extradition from Constantinople. Leonardo's sketch of the corpse is from the dossier. Lorenzo was in Naples that day, which `date_confidence` states.

---

## 5. Naples and the narrowed constitution, 1479-1480

**Contradiction flagged, not resolved.** Wikipedia calls Lorenzo "a prisoner of the king for several months"; the dossier frames the same three months as a voluntary, calculated risk. Both agree on the duration (December 1479 to March 1480) and the outcome. The campa states the disagreement rather than choosing and ends on it as an open question. The pool's separate warning against the myth that Lorenzo alone saved Italy by eloquence is in `date_confidence`.

**[R] The Council of Seventy, 1480.** Dossier summary of constitutional history, not re-verified.

**[R] Otranto and the reconciliation, 1480.** Dossier summary. A placement problem is flagged rather than invented around: the pool assigns the ceremony to Florence but says nothing about where the envoys stood. The pin follows the pool, and `date_confidence` says so.

---

## 6. The balance of Italy, 1484-1489

**[A, causal sequence corrected] Peace of Bagnolo, 7 August 1484.** The pool had the war ending "shortly after Sixtus IV's death". The reverse is true: the treaty was signed 7 August and Sixtus died **five days later**, reportedly enraged at terms he had not wanted (Wikipedia, 'War of Ferrara (1482-1484)'; it.wikipedia, 'Pace di Bagnolo'). The venue is Bagnolo Mella near Brescia, not Bagnolo San Vito. The corrected pin is nonetheless **not used**; see the relocation section.

**[A, presence upgraded] Sarzana, 22 June 1487.** it.wikipedia, 'Sarzana', gives the Genoese surrender as 22 June after a siege begun in May, noting the garrison may have yielded "forse avendo avuto notizia dell'imminente arrivo di Lorenzo de' Medici". That is stronger than the pool's "presence unconfirmed". The pin is the named Fortezza di Sarzanello, not the town.

**[A, place corrected] Clarice Orsini dies 30 July 1488 in Florence**, of tuberculosis, buried two days later (Wikipedia, 'Clarice Orsini'). The pool's geography lens staged this at Careggi, contradicting its own chronology and the source. The stop is moved to Florence: Careggi is where Lorenzo died in 1492. Luisa's death in May 1488 is from the same source.

**[A] Giovanni made cardinal at thirteen, 9 March 1489**, barred from insignia and deliberations for three years (Wikipedia, 'Pope Leo X'). Created at Rome; the stop sits at Via Larga, where Lorenzo pressed for it and the boy went on living.

---

## 7. Villas, garden, friar, 1470s-1492

**[A, date corrected] Poggio a Caiano.** The pool said "late 1480s"; it.wikipedia puts the purchase and the Sangallo commission **between 1470 and 1474**, with the villa a third built at Lorenzo's death. Redated to 1474.

**[A, caveat kept] Fiesole.** The villa was built for Giovanni de' Medici in 1451-1457 and **inherited**, not built or redirected, by Lorenzo. Rather than write a weak "he continued work here" stop, the pin was repurposed to its documented Lorenzo content: the villa lent to Pico from 1488, attested on Pico's own file.

**[A, intercession corrected] Pico della Mirandola.** The pool twice named **Innocent VIII** as the object of Lorenzo's intercession. Per Wikipedia, 'Giovanni Pico della Mirandola', the documented intervention was with **Charles VIII of France**, who released Pico from Vincennes after Lorenzo instigated several Italian princes to petition him. Innocent VIII permitted residence in Florence under Lorenzo's protection but **never lifted the censures**, which stood until 1493. Pico's own file corroborates this; the pool's interlock lens flagged the conflict itself. Pico settled in Florence in **1488**, not 1490, and the Careggi placement is dropped.

**[R] The sculpture garden and Michelangelo.** Kept at the pool's strength and no stronger. Vasari (1550/1568) and Condivi (1553) are late and interested; the safest reconstruction is roughly two years of late-adolescent patronage under Bertoldo, not adoption of a child. Michelangelo was seventeen when Lorenzo died.

**[A] Savonarola brought to San Marco, May or June 1490**, as lector, Pico having persuaded Lorenzo that the friar would bring prestige to the convent (Wikipedia, 'Girolamo Savonarola'). **His refusal to pay court on Via Larga is Savonarolan tradition, not documented**, and is marked so in `date_confidence` as well as attributed in-line.

**[R] Careggi and the "Platonic Academy".** The pool follows Hankins in warning against the myth of a nightly academy with fixed membership. The campa says the academy was invented afterwards and names only Ficino, Poliziano and Pico. Landino and other names in circulation are not in the pool and are not used.

---

## 8. Death and afterlife

**[A]** Died in the late night of 8 April 1492 at Careggi, aged 43.

**[R] The deathbed, contradiction printed.** Savonarolan biography (Burlamacchi and after) has the dying Lorenzo demand the friar, who exacts faith and restitution and withholds absolution over the restoration of Florentine liberty. Poliziano, a contemporary, gives a quieter, more pious account with no three conditions. The Savonarola article fetched for this file **mentions no such meeting at all**. The stop says a visit is plausible and the scripted dialogue is not established. It does not choose.

**[R] The portents** (lightning on the dome, ghosts, the Medici lions fighting) are Florentine chronicle tradition and are narrated as such. **[R] Acromegaly**, proposed by some modern medical historians from symptoms, skeleton and death mask, is explicitly speculative; kept in `date_confidence`, not narrated.

**[A]** First burial with Giuliano in the porphyry and bronze chest Verrocchio made for Piero and Giovanni, Old Sacristy. The day of burial is nowhere in the fetched sources; 9 April is a stated placeholder.

**[A]** 1559 translation into the New Sacristy, to an unmarked tomb beneath Michelangelo's Madonna and Child. **Attribution corrected:** the sculptures were installed by Niccolò Tribolo in 1545 and finished by Vasari and Ammannati by 1555 (Wikipedia, 'Medici Chapels'), not by Vasari alone. The monumental tombs for the brothers were never begun; the confusion with the seated Duke of Urbino, Lorenzo's grandson and namesake, is stated in the campa.

**[A]** Poliziano's *Quis dabit capiti meo aquam*, set by Heinrich Isaac within the year. A detail of the burial stop and a `suggested_ref`, **not** a scene: the lament is Poliziano's act.

---

## Apparatus relations for the operator

Lorenzo is **not** listed in `EXCEPTIONS.md`, so no framework may be applied backward or forward on his file. Nothing was silently deleted. Four relations not rooted in his own travelling life were caught; each is recorded with its direction.

1. **Forward.** The **1975 discovery and 2023 opening of the charcoal-drawing corridor beneath the New Sacristy**, physically under his tomb. Kept as a `suggested_ref` only: no scene, no campa sentence, no stop title.
2. **Forward.** The **retrospective acromegaly diagnosis** from his skeleton and death mask. Kept in `date_confidence` as explicitly speculative.
3. **Forward.** **Reumont's 1876 archival biography** and the modern editions of Lorenzo's works. Bibliography, not travel; no stop.
4. **His own body, after his own death.** The 1559 reburial and the mid-sixteenth-century installation campaign involve his remains and his tomb, so they are carried as his resting place, with `date_confidence` stating that the stop postdates his life by sixty-seven years.

For items 1 to 3 to become scenes rather than references, Lorenzo would need adding to `EXCEPTIONS.md` with a forward grant, which no agent may assume.

## Stops relocated on the who-was-there rule

Three pins in the pool name places Lorenzo did not stand in. None was deleted; each moved to a pin where he was, with the absent place kept in `sources` and `suggested_refs`.

- **Bagnolo Mella.** The pool's own note flags that he was not present and that the peace was directed from Florence. The stop sits at the Palazzo Medici and says outright that he never saw the ground.
- **Otranto.** He never went. The Ottoman landing is folded into the Florence reconciliation stop as the cause it was.
- **Rome, 9 March 1489.** The creation was made at the curia; he was in Florence pressing for it. The stop sits at Via Larga.

The Rome pins that **are** kept (1465, 1471, 1 June 1478) are two embassies he attended in person, plus one bull issued against him where `date_confidence` says the pin marks the issuing curia, not a place he stood.

## Interlocks named in campa

Three, each on a documented personal relation, never on shared geography alone.

- **`michelangelo`**: Lorenzo asked Ghirlandaio for his best apprentices, took the boy into the San Marco garden under Bertoldo and fed him at the Via Larga table; Michelangelo later built the room Lorenzo's bones were moved into. Both directions are in Michelangelo's file.
- **`giovanni_pico_della_mirandola`**: Lorenzo petitioned Charles VIII to free Pico from Vincennes, housed him at Fiesole, received the *Heptaplus* dedication, and brought Savonarola to San Marco at Pico's urging. All four are in Pico's file.
- **`leonardo_da_vinci`**: Leonardo drew the corpse of Bandini Baroncelli, his brother's killer, hanged by his regime. A one-directional engagement with an act of Lorenzo's government, cited on Lorenzo's stop for that execution and given no scene of its own.

**Not named, deliberately.** Cosimo de' Medici is QUEUE.md row 143 with no journey file yet, so no cross-file corroboration exists; he appears only as Lorenzo's grandfather. No canonical pin (Kaaba, Temple Mount, Paris, Buenos Aires) intersects Lorenzo's attested itinerary, so none is inherited; Paris touches this life only through Pico's Vincennes imprisonment, which is Pico's stop.

## Honest gaps

- **Education and tutors.** Nothing in the pool. Absent from the file.
- **The bank's decline.** The pool's section heading refers to "banking strain" but supplies no figures, branch closures or dates. The file does not narrate a collapse it cannot source.
- **Lucrezia Donati.** The pool states the nature and duration of the relationship are unproven. Not written.
- **Poetry.** Only *Ambra*, the *Canzona di Bacco*, the *Comento* and the *Ricordi* are used.
- **Presence at Bagnolo, and in person at Volterra.** Unestablished in both cases; handled by relocation and by explicit hedging respectively.
- **The 1471 antiquities.** The pool says "acquiring antiquities" with no inventory; the campa names nothing specific.

## Sources

**Reached and used**
- Wikipedia: Lorenzo de' Medici, Clarice Orsini, Pazzi conspiracy, Pope Leo X, Pope Sixtus IV, Girolamo Savonarola, Giovanni Pico della Mirandola, Angelo Poliziano, Volterra, Florence Baptistery, Palazzo Medici Riccardi, Sassetti Chapel, Sagrestia Vecchia, New Sacristy, Medici Chapels, Basilica of San Lorenzo, War of Ferrara (1482-1484), Trionfo di Bacco e Arianna
- it.wikipedia: Congiura dei Pazzi, Pace di Bagnolo, Sarzana, Fortezza di Sarzanello, and the villa articles for Poggio a Caiano, Fiesole and Cafaggiolo
- it.wikisource: Guicciardini, *Elogio di Lorenzo de' Medici*, in *Scritti politici e ricordi*, ed. Palmarocchi (Laterza, 1933), p. 229
- Wikiquote, 'Lorenzo de' Medici' (the *Ricordi* joust passage via Del Lungo, tr. Steegmann, 1907; and the motto)
- G. Brucker (ed.), *The Society of Renaissance Florence* (1971), p. 27
- Janet Ross, *Florentine Palaces & Their Stories* (1905), p. 250, verified verbatim inside Internet Archive item `florentinepalace00ross`, scan leaf 272 (printed page number plausible but unverified)
- Machiavelli, *The Florentine History*, vol. 2 (1906 ed.), p. 169; Williamson, *Lorenzo the Magnificent* (1974), pp. 268-269; brians.wsu.edu on Poliziano's lament and Isaac's setting; Project Gutenberg text 50625 (Reumont, tr. Harrison, 1876)
- Atlas cross-files: `michelangelo`, `giovanni_pico_della_mirandola`, `leonardo_da_vinci`

**Carried from the crawled dossier without independent re-fetch (all [R] or hedged above)**: Prato 1470; Rome 1471 and the antiquities; Volterra's political framing; the 1476 Sforza assassination; the Council of Seventy; Otranto and the reconciliation; the War of Ferrara narrative; the Sarzana framing; the Pisa/Salviati dispute; the Michelangelo garden years; the Savonarola deathbed tradition; the Careggi gatherings.

**Named and not reached**
- Ingeborg Walter in the *Dizionario Biografico degli Italiani*; F. W. Kent on the villas; Nicolai Rubinstein on the 1465-66 missions. Cited in the dossier, none fetched.
- Burlamacchi's life of Savonarola, and Poliziano's letter on Lorenzo's death: known only through the dossier's summary of the dispute between them. Neither was read.
- Simioni (ed.), *Opere* (Laterza, 1913-14); Orvieto (ed.), *Tutte le opere* (Salerno, 1992); Thiem's English selection (Penn State UP, 1991). The pool could not confirm any of the three in a catalogue before its search budget ran out. Two quotes in the journey file carry the Simioni citation on the pool's authority alone. **A verifier should check these against WorldCat before the file is promoted to canon.**
- No published English translator was traced for the *Canzona di Bacco* refrain, so it stands in Italian, as do the Guicciardini *Ricordi* C 75 saying and the two *Comento* fragments.
