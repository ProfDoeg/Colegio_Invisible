# Louis XIV: research report

*Slug `louis_xiv`. Compiled 2026-08-09 from the verified research pool (chronology, geography, quotes, interlock, afterlife lenses). Nothing gathered fresh. Where verification overturned a gathering claim, the correction is carried forward and the overturned version printed beside it.*

**Legend.** **[A]** attested, source named. **[R]** reconstruction or attribution. Contradictions are flagged, not resolved. Gaps are stated as gaps.

**Register note.** The house register "national mythology: the canon is true" governs campa prose only. Every hedge the campa suppresses lives in the `date_confidence` field of its stop. Routine attested dates are named once here and carried per stop in the journey's `sources` arrays.

---

## 1. The God-given child, and a regency (1638-1653)

- **[A: Wikipedia, "Louis XIV"; "Fronde"]** Born 5 September 1638 at Saint-Germain-en-Laye after twenty-three years of marriage without an heir, named Louis Dieudonné; king at four on 14 May 1643, Anne of Austria regent, Mazarin chief minister; the will annulled 18 May 1643; majority at thirteen 7 September 1651; re-entry into Paris 21 October 1652; Mazarin back unopposed February 1653.
- **COORDINATE CORRECTION. [A: Wikipedia, "Château de Saint-Germain-en-Laye"]** Gathering gave 48.8947, 2.0947, roughly 390 m off; Wikipedia gives **48.89806, 2.09639**. Verification adds a point that matters more: Louis was born in the **Château Neuf, demolished after the Revolution**, not the surviving Château Vieux any modern coordinate points at. No Château Neuf coordinate exists in the pool, so the journey uses the corrected pin and the campa says it falls on the wrong building.
- **MAJOR CORRECTION, the opening of the Fronde.** Gathering produced: *"1648-10-22. The Parlement of Paris's uprising forces the royal family to flee Paris, the opening episode of the Fronde."* Verification rejected it as wrong on **both date and event**, two things collapsed into one that never happened. **[A: Wikipedia, "Fronde"]** The Fronde opens with the **Day of the Barricades, 26 to 28 August 1648**, after Mazarin arrests the parlement's leaders; the **night flight is 5 to 6 January 1649**. **[R]** Nothing attaches to 22 October 1648; the verifier's diagnosis, a misreading of the 24 October 1648 entry for the Peace of Westphalia, is recorded as reconstruction. Both real events get stops; the rejected date appears nowhere in the journey.
- **ELEVEN ATTESTED PLACES HAVE NO COORDINATES IN THE POOL**, carried in campa text rather than pinned: Rueil (1649), Fuenterrabía (1660), Aix-la-Chapelle (1668), Nijmegen (1678), Pignerol and Châlons-sur-Marne (1680), Meudon (1711), Utrecht (1713), Saint-Cyr (1719), Philippsburg, and the bare "France" of the Code Noir and Colbert's appointment. Inventing coordinates would put unsourced numbers into the atlas.
- **Gap.** The court sleeping on straw at Saint-Germain in January 1649 is credited by the pool to "standard biographies (Bluche; Voltaire)" with no page, edition, or fetched text. Those books were **not reachable**; the detail reaches the journey through a campa, and the stop's `sources` array says so.

---

## 2. The anointing and the bride (1654-1661)

- **[A: Wikipedia, per stop]** Coronation at Reims 7 June 1654; Arras August 1654, Louis present but not commanding, day defaulted to 01, resting on general military histories the pool names but did not fetch; Treaty of the Pyrenees 7 November 1659; proxy marriage at Fuenterrabía 2 June 1660, marriage at Saint-Jean-de-Luz 9 June; entry into Paris 26 August 1660; Mazarin dead at Vincennes 9 March 1661. The bricked-up door at Saint-Jean-de-Luz is a local tradition about a real walled door, and is written as tradition.
- **PIN DISCREPANCY, Reims.** The interlock lens reported the corpus pin as **49.2528, 4.0347**. `louis_xvi.journey.json` line 118 shows it is **49.2533, 4.0347**, which the geography lens also gave. The journey inherits the value really in the file. Flagged because the lens's coordinates cannot be trusted unchecked.
- **CORRECTION, the first sight of the bride.** Gathering wrote that Louis "first glimpses his bride here," attached to the 1659 signing. Verification: **he was not present.** The family interview was on the same island in **June 1660**, seven months later. **[A: Wikipedia, "Treaty of the Pyrenees"; "Maria Theresa of Spain"]** One stop, dated to the treaty, correction explicit in campa and `date_confidence`.
- **Two lenses, no contradiction.** The chronology lens gives only "1661-03" for Mazarin's death, the geography lens 9 March at Vincennes; the journey takes the specific date.
- **Dropped, both [R].** Metz 1657 and Charleroi 1667, tagged R by the pool itself, cut for stop budget. Recorded so the absence is deliberate.

---

## 3. THE QUOTE PROBLEM (the 1661 address)

Gathering produced the address to the secretaries of state, *"Up to this moment I have been pleased to entrust the government of my affairs to the late Cardinal,"* sourced to Wikipedia's "Louis XIV" footnote 31, with a note claiming that footnote "traces this to standard biographical sources." Verification fetched `en.wikipedia.org/wiki/Louis_XIV?action=raw`:

- **Wording CONFIRMED verbatim [A]**, section "Coming of age and early reforms."
- **The provenance claim is FALSE [A].** Reference 31 is `{{Cite web |title=Louis XIV - the Sun King: Absolutism |url=http://www.louis-xiv.de/index.php?id=30}}`, a hobbyist site archived 28 October 2013. It cannot carry the weight put on it.
- **[R]** The underlying address, to the secretaries of state on 10 March 1661, is well attested in the scholarly literature through Brienne's account, so the quotation is not invented. Nothing in this pool traces the English wording to a primary edition.

The journey's `quote_source` says exactly that and withdraws the "standard biographical sources" claim. **A future pass should substitute a real biography (Bluche) once one is reachable.** Same caveat for the "first knots" passage, also seen only on the live Wikipedia page (footnote 9).

**Quotes used, nine of forty-five stops:**

| Quote (opening) | Stop | Status |
|---|---|---|
| "Nature was responsible for the first knots..." | king at four | [A] wording, [R] provenance |
| "Up to this moment I have been pleased..." | Vincennes | [A] wording, provenance corrected above |
| "Toutes les fois que je donne une place vacante..." | Marly | **[R]** Voltaire ch. 26, Wikiquote |
| "L'Etat, c'est moi." | court arrives | **[R]** flagged in the artifact as apocryphal |
| "Since I have been Queen..." | queen's death | **[R]** reported last words of Maria Theresa |
| "Je mettrais plutôt toute l'Europe d'accord..." | secret marriage | **[R]** Mirabeau, Wikiquote |
| Edict of Fontainebleau, opening | Fontainebleau | **[A]** Louis's own edict, Fordham, fetched |
| "Il n'y a plus de Pyrénées." | Compiègne | **[R]** Voltaire ch. 28, Wikiquote |
| "Je m'en vais, mais l'Etat demeurera toujours." | death | **[R]** Dangeau, Wikiquote, not fetched |

**Not used. [R]** *"Is there not a son?"* (Saint-Simon, Gutenberg 3875), retrieved only in fragments, with no stop it belongs to without inventing an occasion; and *"J'ai failli attendre,"* flagged apocryphal by Fournier, one apocryphal saying being enough.

---

## 4. Fouquet, Colbert, the first conquests (1661-1668)

- **[A: Wikipedia, per stop]** The fête at Vaux-le-Vicomte 17 August 1661, premiere of *Les Fâcheux*, Vatel in the kitchens; Fouquet taken at Nantes 5 September 1661 by d'Artagnan; the packed court voting banishment 20 December 1664 and Louis overruling his own tribunal for life imprisonment; Fouquet dead at Pignerol 23 March 1680; Colbert Controller-General from 1665; the Grand Dauphin born 1 November 1661; Dunkirk bought from Charles II for five million livres in 1662; the War of Devolution opened 1667, Tournai June, Douai July, Lille in nine days in August, Franche-Comté February 1668 under Condé, Aix-la-Chapelle in May. Douai, Dunkirk and the 1664 verdict fold into neighbouring campa for budget.
- **COORDINATE CORRECTION, Vaux-le-Vicomte. [A: Wikipedia]** Gathering gave 48.5697, 2.7136, roughly 530 m north; corrected to **48.564851, 2.714**.
- **VAGUE DATE, marked as one. [A: Wikipedia, "Louvre Palace"]** Bernini commissioned then set aside, Perrault's colonnade built. **The pool dates this only "the 1660s."** The stop is dated 1665-01-01, and `date_confidence` says a decade was given and 1665 chosen for Bernini's visit and Colbert's appointment.
- **PIN INHERITED, Tournai.** `clovis.journey.json` pins Childeric's hall at **50.6069, 3.3893**; the geography lens gave the cathedral at 50.6067, 3.3888. The corpus pin wins, the interlock being the point of the stop.

---

## 5. Versailles rising, and the Dutch War (1670-1678)

- **[A: Wikipedia, per stop]** Chambord premiere of *Le Bourgeois Gentilhomme* 14 October 1670; Le Vau's enveloppe 1671, month and day defaulted to 01; Vatel's death at Chantilly 24 April 1671, resting on Sévigné's letters, which the pool cites with no edition or letter number and the stop's `sources` array says so; the Rhine crossing at Lobith 12 June 1672; Maastricht June 1673, Vauban's first full parallel-trench siege, d'Artagnan killed; Ghent March 1678; Nijmegen 1678, the peak of French power, uncoordinated in the pool and carried in the Ghent campa; the Hall of Mirrors 1678-81, folded into the 1682 stop.
- **MAJOR CORRECTION, Valenciennes.** Gathering wrote that the winter dawn assault went in **"against Vauban's own advice on timing."** Verification: **the claim reverses Vauban's role.** **[A: Wikipedia, "Siege of Valenciennes (1677)"]** The siege ran 28 February to 17 March 1677 with Louis present, and **the daylight assault was Vauban's own proposal**, argued from surprise and coordination, and approved. Corrected in the campa, reversal printed in `date_confidence`.
- **Dropped for budget, all [A].** Besançon (May 1674), carried in the Dole campa; Condé-sur-l'Escaut (April 1676); Cambrai (April 1677), named in the Valenciennes campa.

---

## 6. The court becomes the state (1679-1687)

- **[A: Wikipedia, per stop]** Strasbourg entered 23 October 1681 after annexation without a shot under the Chambers of Reunion, the organ playing in his honour given by the pool as "said to have" and written that way; court and government permanently at Versailles 6 May 1682, the Duke of Burgundy born there that August; the queen dead 30 July 1683, aged 44; the Edict of Nantes revoked 18 October 1685; Bernini's marble shipped 1685, the king reportedly outraged, recarved by Girardon in 1687 as Marcus Curtius at 48.804389, 2.123139.
- **TWO CORRECTIONS, Marly. [A: Wikipedia, "Château de Marly"]** The gathering coordinate 48.8697, 2.0897 is a kilometre off, against **48.86389, 2.10000**; the dates are **22 May 1679 to 1684**, not 1679-1686.
- **CONTRADICTION LEFT STANDING. [A: Wikipedia, "Marquise de Maintenon"]** The secret marriage is dated by historians **either 9 October 1683 or January 1684**. The pool gives both and chooses neither. The journey dates the stop to the earlier and prints the disagreement in `date_confidence` without adjudicating: a real historiographical split, and resolving it here would be inventing a consensus.
- **Code Noir. [A]** 1685, with **no month and no place beyond "France"** in the pool, so it is carried in the Fontainebleau campa rather than pinned to an invented location. It is not a footnote to the revocation; it shares a stop only because both are 1685 acts of one signature and neither has a place of its own here. A future pass with a real date and place should give it a stop.

---

## 7. The Rhine, the failed succession, the end (1688-1715)

- **THE POOL'S LARGEST HOLE, filled from the corpus. [A: `joseph_oppenheimer.journey.json`; `samuel_oppenheimer.journey.json`]** Joseph Süss Oppenheimer is born in Heidelberg "in the ruined Palatinate lately burned by the armies of Louis XIV" (the 1689 devastation under Louvois); Samuel Oppenheimer's son Emanuel is seized as a hostage against faster deliveries to Philippsburg. **Neither event appears in the chronology, geography, or afterlife lenses.** Without the interlock lens this reign would run from Strasbourg in 1681 to Utrecht in 1713 with a thirty-year hole where two of its wars were.
- **PIN DISCREPANCY, Heidelberg.** The lens reported **49.3988, 8.6724**, a value that **occurs in no journey file**. The pin actually in `joseph_oppenheimer.journey.json` is **49.4094, 8.6946**, the Judengasse, which the journey inherits. With the Reims case above, **the lens's coordinates are approximations and must be checked against the files.**
- **[A: Wikipedia, per stop]** Compiègne 1698, review and mock siege before ambassadors, year only in the pool; Girardon's Vendôme bronze cast 1699; Burgundy married at Versailles 7 December 1697 at fifteen, folded into the 1712 Marly campa; the chapel completed 1710; Philip V renouncing the French throne 10 July 1712 and the Utrecht treaties signed 11 April 1713, that stop pinned at Versailles because Utrecht has no coordinate; death 1 September 1715, after 72 years.
- **The succession collapses. [A: Wikipedia, "Louis, Grand Dauphin"; "Louis, Duke of Burgundy"]** Grand Dauphin dead of smallpox at Meudon 14 April 1711, aged 49. Burgundy, having nursed his wife through fatal measles, dies of it six days after her, 18 February 1712 at Marly; the pool's "six days" puts her death at 12 February, which is standard. **[R]** The death of their elder son in March 1712 is **not in this pool**; the campa says only that the direct line is reduced to a boy of two, which the pool does support.
- **[R], deliberately omitted.** The deathbed scene as usually told, the farewell in the great gallery and the advice to the five-year-old against building and war, is universally reported but **not in this pool in any form**. The campa keeps the gangrene, the refusal of amputation and the leave-taking in general terms, and puts none of those sentences in his mouth.

---

## 8. Afterlife (1715-2006)

- **[A: Wikipedia, per stop]** Buried at Saint-Denis 9 September 1715, heart interred separately at Saint-Louis in Paris; Girardon's Vendôme bronze destroyed 1792-93, a small version preserved in the Louvre; Desjardins's gilt bronze at the Place des Victoires, Louis crowned by Victory and treading Cerberus, demolished 1792, a wooden pyramid there in 1793, a nude Desaix in 1810, Bosio's twelve-metre replacement in 1828; Versailles emptied 1789, stripped for the Louvre 1792, furnishings auctioned 1793-94, apartments open to visitors from 1793; museum inaugurated 30 June 1837; Rockefeller giving roughly $2,166,000 in 1925-28; Opera reopened 1957; UNESCO 1979; Hall of Mirrors complete again 2006 after the 1999 cyclone.
- **PIN INHERITED, Saint-Denis.** The pool gives 48.9354, 2.3597 and 48.9354, 2.3596 for one building; `saint_denis.journey.json` uses **48.9355, 2.3597**, which the journey takes.
- **HONEST LIMIT, the desecration. [A: Wikipedia, "Basilica of Saint-Denis"]** The Convention orders the tombs violated in 1793, two waves in August and October, bodies into trenches covered with lime; the account **does not name Louis XIV specifically** among the disturbed remains, though he was interred there, and the campa does not claim his body was identified. Remains still in the graves at the 1806 reopening; an 1817 investigation finds three bodies with any shape left, and fragments of roughly 158 people go into one ossuary with marble plates naming each.
- **The eaten heart. [R: Wikipedia, "William Buckland," citing Hawthorne 1863 and Hare 1900]** Widely repeated and **disputed**: alleged 1848, first printed 1863, veracity questioned by the source itself. Given a stop, hedge in `date_confidence`, campa ending on the fact that nobody at the table wrote it down. The coordinate 51.7, -1.15 is the pool's, a village-level approximation.

---

## 9. Corpus interlocks used, and those refused

Named in campa and reported as interlocks:

| Slug | Crossing | Tag |
|---|---|---|
| clovis | the Sainte Ampoule at Reims; Childeric's grave opened at Tournai 27 May 1653, inside Louis's minority | [A] |
| louis_xvi | Reims as shared consecration site; the 1787 edict naming the ancestor who revoked the Edict of Nantes | [A] |
| saint_denis | the necropolis is his abbey; the burial campa names the beheaded bishop | [A] |
| samuel_oppenheimer | victuals the Habsburg army against Louis in the Dutch War; the hostage-taking over Philippsburg | [A] |
| joseph_oppenheimer | born in the Heidelberg Judengasse in the Palatinate burned by Louis's armies | [A] |
| napoleon | Childeric's bees on the coronation mantle; the 1806 reopening of Saint-Denis, kings still in the trenches | [A] |
| mesmer | rooms at Versailles in 1801, a site inheritance rather than a meeting | [R] |
| marcel_proust | five months in 1905 a few hundred metres from the palace without going to look at it | [A] |

**Refused. [R]** The lens offered pins for the Kaaba (21.4225, 39.8262), the Temple Mount (31.778, 35.2354) and Buenos Aires (-34.6037, -58.3816) as "inheritable geography," while noting **no Louis XIV connection to those sites was found**. A reusable pin is not a reason to visit a place.

**Too weak. [R]** `michel_foucault.journey.json` (a 1971 shooting in the town the palace created), `jean_jacques_rousseau.journey.json`, `madame_de_lafayette.journey.json` (later people passing through Versailles): naming any would be a pun on a place-name. `QUEUE.md`'s entry is the brief, not a source, and the lens says so.

---

## 10. Gaps, stated as gaps

1. **The Nine Years' War (1688-1697) is absent from the topic research**, reaching the journey only through the Oppenheimer interlocks. The League of Augsburg, La Hougue, Namur and Ryswick are all missing.
2. **The War of the Spanish Succession has no battles.** Blenheim, Ramillies, Oudenarde and Malplaquet occur nowhere in the pool; the reign's last and most ruinous war reaches this atlas as a treaty signature.
3. **No mistresses.** La Vallière, Montespan and the Affair of the Poisons are absent from every lens; Maintenon appears only as governess and secret wife.
4. **Almost nothing in his own words**, only the two Wikipedia-sourced passages. The *Mémoires* written for the Dauphin are not in the pool in any form.
5. **No colonial material except the Code Noir.** New France, the Compagnie des Indes, Saint-Domingue: absent.
6. **Bluche and Voltaire are cited by the pool and were never fetched**, so every claim resting on "standard biographies" is **[R]** in substance whatever tag it carries.
7. **Eleven attested places have no coordinates in the pool**, listed in section 1.

---

## Sources

**Reachable and used (fetched by the pool):**

- **English Wikipedia**, roughly forty articles, named per stop in the journey's `sources` arrays. The load-bearing one is "Louis XIV", read as article and as raw wikitext at `?action=raw`, which is how the footnote-31 error was caught.
- **Fordham University, Internet Modern History Sourcebook**: the Edict of Fontainebleau in translation, the only primary document in the pool.
- **Wikiquote, "Louis XIV"**: the vehicle for five of the nine quotes, each tagged **[R]** on that account.
- **Project Gutenberg 3875**, Saint-Simon, *Memoirs*, trans. St. John: fetched, passage in fragments, quote unused.
- **Madame de Sévigné, *Letters***, cited for the Vatel scene with no edition or letter number.
- **Corpus files** read for pin inheritance and interlock text: `abdelkader.journey.json`, `bourlemont_roster.md`, `clovis.journey.json`, `louis_xvi.journey.json`, `saint_denis.journey.json`, `joseph_oppenheimer.journey.json`.

**Named in the pool but NOT reachable, with the reason:**

- **François Bluche, *Louis XIV*.** Cited repeatedly as "standard biographies," never fetched, no edition or page. The most consequential absence: it is the citation the 1661 quote should have and does not.
- **Voltaire, *Le Siècle de Louis XIV*** chs. 26 and 28, **Dangeau, *Mémoire sur la mort de Louis XIV***, **Mirabeau, *Esprit de Mirabeau* vol. 1**: four quotations, every one reached through Wikiquote rather than the book.
- **`louis-xiv.de`**, the actual footnote behind the 1661 address. Technically reachable and deliberately not used: naming it would launder a dead-link personal homepage into scholarship.
- **Any primary edition of the *Mémoires*.** Not attempted in the pool.
