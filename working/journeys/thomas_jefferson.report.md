# Thomas Jefferson (1743-1826): research report

*Atlas of Journeys. Slug `thomas_jefferson`. Compiled 2026-08-10 from the verified research pool (chronology, geography, quotes, interlock, afterlife lenses), with that pool's adversarial corrections folded in.*

Legend: **[A]** attested, source named · **[R]** reconstruction or tradition · **[C]** the pool's lenses contradict each other; recorded, not adjudicated.

Journey file: `thomas_jefferson.journey.json`, 9 segments, 45 stops, calendar `gregorian`, register `national mythology: the canon is true`.

---

## 1. Piedmont origins, 1743-1760

**Birth. [A / C on coordinates]** Born at Shadwell on the Rivanna, Albemarle County, 13 April 1743 New Style, third of ten children of Peter Jefferson, planter and surveyor, and Jane Randolph Jefferson (History.com; Wikipedia; Autobiography and the family Bible record). Old Style the date is 2 April; the file uses New Style and flags the double dating in `date_confidence`.

**The Shadwell coordinate is the worst data problem in this pool. [C]** Three pins for one plantation:

| Lens | Pin | Where it lands |
|---|---|---|
| chronology (birth; and the 1768 mountaintop) | 38.0033, -78.4508 | the Monticello ridge, ~3 km SW |
| geography (birth; Peter Jefferson's death) | 38.0234, -78.4453 | open country NW of the site |
| Wikipedia, 'Shadwell, Virginia' (the pool's own correction) | 38.0124, -78.4178 | the village of Shadwell |

The file adopts **38.0124, -78.4178** for both Shadwell stops and says so in `date_confidence`. No reachable authority settles it; the foundation's Shadwell excavation coordinates would, and were not reachable here.

**Tuckahoe. [A, coordinate corrected]** After William Randolph III's death the family moves to Tuckahoe on the James, 1745-1752 (Autobiography; Malone, vol. 1). The pool's pin (37.6247, -77.6864) is ~6.7 km off, north of the James near Short Pump; corrected to **37.5705, -77.6532**. The estate straddles Goochland and Henrico, which the pool's label gets half right.

**The first schoolmaster's denomination. [R, downgraded]** The pool said Jefferson began school in 1752 under "a Presbyterian minister". The date is right, the denomination contested: the teacher was the Rev. William Douglas, a Scottish-born clergyman holding the Anglican parish of St. James Northam, and "Presbyterian" is a repeated gloss on Jefferson's own phrase "a clergyman from Scotland". The campa says only "a clergyman his own autobiography calls a Scotsman".

**Peter Jefferson's death, 1757. [A, year only]** Thomas, fourteen, inherits roughly 5,000 acres including the future Monticello site. No month or day in the pool; the file defaults to `1757-01-01` and says so.

**James Maury's school, 1758. [A]** Two years near Gordonsville. No lens supplied a coordinate, so it is folded into the 1757 campa rather than pinned on a guess.

## 2. Williamsburg, 1760-1769

**The college. [A, one correction]** Enters in 1760 under William Small. The pool said he "graduates" in 1762; Encyclopedia Virginia is explicit that he "left William and Mary in 1762 **without graduating**", the college not routinely conferring degrees on gentry students. The campa follows Encyclopedia Virginia.

**The law. [A, chronology inverted in the pool]** The pool dated 1762 as the year Jefferson *concluded* study of law under Wythe. It is the year he *began*; he read with Wythe roughly five years, to his admission to the bar in 1767.

**Coordinates corrected in the historic district.** Williamsburg is a dense reconstruction and the pool's pins were off by enough to land on the wrong block:

- George Wythe House: pool 37.2724, -76.6994 → **37.27167, -76.70333** (~350 m)
- Capitol at Williamsburg: pool 37.2707, -76.6975 → **37.27126, -76.69329** (~375 m)
- Governor's Palace: pool 37.2735, -76.6947 → **37.27425, -76.70211** (~660 m; the pool's pin fell off Palace Green onto Duke of Gloucester Street)

**House of Burgesses, 11 May 1769. [A]** Takes his seat for Albemarle, sits until the Crown ends the house in 1775. The campa deliberately omits the 1769 dissolution and the Raleigh Tavern resolves, textbook matter that appears nowhere in the pool.

## 3. Monticello, marriage, and the Declaration, 1768-1776

**The mountaintop, 1768. [A on year, place label wrong in the pool]** The pool filed the leveling under "Shadwell" with a coordinate on the Monticello ridge. The site is Monticello, on inherited land ~3 km southwest of Shadwell. The file uses the geography lens's pin **38.0092, -78.4536** for every Monticello stop.

**Marriage, 1 January 1772. [A; coordinate approximate]** Martha Wayles Skelton, widow, aged 23, at The Forest, Charles City County. The house no longer stands and the pin is approximate, carried as given with the caveat in `date_confidence`. The snowstorm arrival at Monticello is **[R]**, family tradition, and marked as such.

**Congress and the Declaration. [A]** Delegate to the Second Continental Congress, 1775; committee of five named 11 June 1776; drafted at the Graff house; adopted 4 July 1776. The Franklin-telling-a-story detail during the excisions is **[R]** and flagged as tradition. Quotes are verbatim from the National Archives transcript and from the Autobiography via Wikisource; the struck slave-trade clause is quoted at the adoption stop, where Congress removed it.

## 4. The war in Virginia, 1777-1783

**Religious freedom. [A, date corrected]** The pool dated the authorship 1779. He drafted the bill in **1777**; 1779 is the year of introduction; enactment is 16 January 1786, carried by Madison while Jefferson was in Paris. The stop is dated 1777 and the sequence stated in campa and `date_confidence`.

**Governor, 1779-1781. [A, one day corrected]** Elected June 1779; capital to Richmond in 1780; second term expires **2 June 1781**, not 3 June as the pool had it (Encyclopedia Virginia). Virginia then had no governor until the Assembly elected Thomas Nelson Jr. on 12 June.

**Arnold's raid, 5 January 1781; Tarleton's raid, 4 June 1781. [A]** The chronology lens gave only "1781" for Tarleton; the geography lens gives the day, which the file uses. The inquiry that cleared Jefferson is attested in the pool and stated in the Richmond campa.

**Elk Hill: dropped. [R, unverifiable]** The geography lens placed Cornwallis's destruction of Elk Hill at 37.759, -78.21 and attributed the account to *Notes on the State of Virginia*. Both fail: the account is in Jefferson's letter to Dr. William Gordon of 16 July 1788, and the coordinate matches no authority, looking too far north for a James River seat opposite Elk Island.

**Poplar Forest, 1781 refuge. [A, coordinate corrected]** Pool 37.3735, -79.3253 falls in the Lynchburg outskirts, ~6 km northwest of the house; corrected to **37.3483, -79.2649**. The same correction applies to the 1806 octagon stop.

**Martha's death, 6 September 1782. [A]** Aged 33, ten years married. The promise not to remarry is **[R]**, family tradition, and is flagged as such.

**Confederation Congress, 1783-1784. [A, place corrected]** The pool said "Annapolis/Philadelphia". Congress was not in Philadelphia during his term: it left in June 1783 after the Pennsylvania Mutiny, sat at Princeton, then at Annapolis from November 1783.

*Deliberate omission:* the 1784 ordinance clause barring slavery from the western territories after 1800, famous and lost by one vote, is **not in the verified pool** and is not asserted in the campa.

## 5. Europe, 1784-1789

**The crossing. [A, two errors corrected]** Sails from Boston aboard the *Ceres*, 5 July 1784. The geography lens said he "lands at Le Havre after crossing the Atlantic" in August. The crossing in fact ended **in England**: the *Ceres* put in at West Cowes, Isle of Wight, on 26 July; he crossed the Channel and landed at Le Havre on **31 July**, reaching Paris 6 August. No West Cowes stop was made: no lens gave a coordinate and I declined to invent one.

**Minister to France, 1785-1789. [A]** Succeeds Franklin; leases the Hôtel de Langeac on the Champs-Élysées (lease records). Pin **48.8721, 2.305** as given. **London, March 1786. [A]** Grosvenor Square, presented at court by Adams; George III turning his back is **[R]**, remembered afterwards by the two Americans.

**The southern tour, 1787. [A, causal order corrected]** Aix, Nîmes, Nice, Turin, Milan, and Genoa are attested from the 1787 travel journal. The pool's claim that the Maison Carrée "becomes his model for the Virginia State Capitol" **inverts the causation**: the design was made with Clérisseau in 1785-86 from engravings and the model shipped to Richmond in 1786, and Jefferson first saw the building in March 1787. The campa states the inversion plainly. For space, Aix, Nice, Milan, and Genoa are folded into the Nîmes and Turin stops. The Milanese rice-smuggling story is **[R]** in the pool itself and is written as what tradition adds and the journal does not.

**Sally Hemings arrives in Paris, 1787. [R]** Attested: Hemings, about fourteen and enslaved at Monticello, accompanies Jefferson's younger daughter to Paris and stays about two years. Inference: that a sexual relationship began in this period, the position of historians reading the foundation's documentary and DNA findings. The campa attributes it to them rather than asserting it as event.

**Amsterdam and the Rhine, 1788. [A]** Dutch loan negotiations with Adams in March, then the Rhine journey through Frankfurt and re-entry at Strasbourg in April, folded into the Amsterdam campa.

**Lafayette's Declaration of the Rights of Man, 11 July 1789. [A, interlock]** From `marques_de_lafayette.journey.json`: Lafayette lays the draft, written with Jefferson's help, before the National Assembly, and the paper survives with Jefferson's marginal corrections.

## 6. Interlocks with existing atlas travelers

**Named in campa (mutual gaze):**

1. **`humboldt`**: Humboldt at the President's House, June 1804, days of talk on the Louisiana border and New Spain, Humboldt supplying maps and mining figures, the correspondence running unbroken to Jefferson's death (`humboldt.journey.json`, stop 'Washington, the President's House, and Jefferson'; his letter of 24 May 1804 is cited there).
2. **`marques_de_lafayette`**, twice: the 11 July 1789 draft declaration with Jefferson's marginal corrections, and Lafayette at Jefferson's table in Washington in the 1804 season (`marques_de_lafayette.journey.json:661`).

**Canonical pins inherited byte-identical:**

- President's House, Washington **38.8977, -77.0365** from `humboldt.journey.json:463-464`, used for the Danbury and Humboldt stops as the lens instructs.
- Versailles **48.8049, 2.1204**, carried by both the geography lens and `marques_de_lafayette.journey.json`, used for 11 July 1789.

**Pins offered and deliberately not used:**

- Hôtel de Noailles, Paris **48.8658, 2.33**. The lens suggests Jefferson's Paris stops reuse this neighbourhood pin for consistency with the Lafayette files. He has no attested stop there, and his own address (Hôtel de Langeac, 48.8721, 2.305) rests on lease records. Using Noailles would import a false address for the sake of consistency. A deliberate divergence.
- Mount Vernon **38.7075, -77.0861**. The lens's two Mount Vernon items (the Bastille key, 1790; Lafayette in Washington's tomb, 1824) do not place **Jefferson** there on a datable occasion.

**Interlocks recorded but not used:**

- **George Washington**, census subject #159, has no journey file. Jefferson crosses him at nearly every stop from 1775 to 1793. QUEUE.md groups Washington, Jefferson, Jackson, and Franklin as the anchor for a planned Tocqueville journey. When Washington gets a file, segments 6 and 7 here are the seam.
- **John Locke**, queued as a direct intellectual source for the Declaration. No file yet.
- **Adrienne de Lafayette** (`madame_de_lafayette.journey.json:520`): her château in the Brie hosts "Jefferson's correspondents" among the international liberal opposition, a milieu rather than a crossing at a place and date. That file also **debunks** the tradition that Jefferson suggested the name "Virginie" for Lafayette's daughter, born 1782: he did not reach France until 1784. Kept out entirely.
- `bolivar`, `mark_twain`, `francis_bellamy` matched a text search for "Washington" and are tagged **[R]** as unverified grep hits. None was opened here; none is used.

## 7. Presidency and retirement, 1790-1826

- **Secretary of State. [A, conflation corrected; C, minor]** The pool dated the appointment 1790-03-22. He was nominated and confirmed in **September 1789**, accepted 14 February 1790, and took office at New York in **March 1790**. Encyclopedia Virginia gives 21 March, Wikipedia 22; the file uses 21 and records the disagreement.
- **Philadelphia. [A, coordinate and substance corrected]** The pool put a "President's House, Philadelphia" waypoint at 39.95, -75.155 and said Jefferson "works" there. He did not: as Secretary of State he kept his own lodgings and offices on Market Street. Pin corrected to the President's House site at Sixth and Market (**39.9494, -75.1500**), stop rewritten as Philadelphia the federal capital.
- **Germantown. [A, date corrected]** The pool dated the fever removal September 1793, which is when officials scattered; the cabinet reconvened at Germantown in **November 1793**. The pool's pin is also ~1.4 km west of historic Germantown. Cut for space, folded into the resignation campa.
- **Vice presidency, 1797-1801. [A]** Sworn 4 March 1797 in Philadelphia. Cut for space, carried in the 1801 inauguration campa.
- **Louisiana and Lewis and Clark. [A, split date]** The pool dated the expedition's commission to 1804. Congress funded it in January and February **1803**, Lewis got his instructions that June, and the Corps left Camp Dubois 14 May 1804. The purchase treaty is 30 April 1803. Combined in one stop dated 1803-04-30.
- **Embargo. [A on year only]** The pool gives 1807 with no month or day; the Act was signed 22 December 1807, which the pool does not carry, so the stop is dated 1807-01-01 and says the year alone is attested. The weakest date in the file.
- **Library sold to Congress, 1815. [A, count corrected]** The pool said "roughly 6,700 volumes". He **offered** 6,707; **6,487 were received** for the 23,950 dollars voted in January 1815.
- **Warm Springs, 1818. [A, cut for space]** A course of bathing in Bath County that Jefferson later blamed for worsening his health.
- **University of Virginia. [A]** First classes 1825. Rotunda pin 38.0356, -78.5034 (geography lens); the chronology lens gives a Charlottesville pin ~250 m away, a town-versus-building difference, not a contradiction.
- **Death, 4 July 1826. [A]** At Monticello, aged 83, hours before John Adams. Adams's last words invoking Jefferson are **[R]** in the pool's own framing ("reported as").

## 8. Afterlife, 1826-2018

**The grave. [A / C on coordinates]** Buried 5 July 1826 under an obelisk he designed, naming only the Declaration, the Virginia Statute for Religious Freedom, and the university. **Contradiction:** the geography lens gives 38.0079, -78.4555 and the afterlife lens 38.0083, -78.4531 for the same cemetery, ~210 m apart. The file uses the geography value and records the disagreement. Not adjudicated.

**The chipped stone. [A, funding misattributed]** Relic hunters reduced the original to a stub by the 1870s. The pool said "descendants and Congress fund a larger replacement". In fact **Congress appropriated 10,000 dollars in 1882** and the enlarged obelisk went up in 1883; the descendants' part was giving the original away. It went to the University of Missouri in July 1883 as the first university founded in Louisiana Purchase territory, dedicated on the Francis Quadrangle **4 June 1885**. Pin 38.9453, -92.3277.

**The Memorial, 13 April 1943. [A]** Pope's domed rotunda, dedicated by Roosevelt on the two hundredth birthday. The Commission of Fine Arts never approved the site, holding it broke L'Enfant's plan; protesters chained themselves to the cherry trees in November 1938; the opening statue was plaster for want of wartime bronze, replaced in 1947; the site now subsides and floods.

**Hemings. [A]** The 1998 Foster et al. study; the foundation's 2000 report and definitive 2018 position; the 2017 identification of the room under the south terrace, next to Jefferson's bedchamber, as Sally Hemings's quarters.

**Cut for space, both attested:** Mount Rushmore (the first Jefferson head dynamited off the rock and re-carved to Washington's left, 1936); the nickel and two-dollar bill, where the Monticello reverse ran 1938-2003, lapsed for the 2004-2005 Westward Journey designs, and returned in 2006 with a new obverse, correcting the pool's "circulates continuously".

## 9. Honest gaps

- **No coordinate for the Maury school** near Gordonsville, and none for West Cowes; both are narrated inside adjacent campas rather than pinned.
- **Elk Hill** has no verifiable coordinate and its pool source attribution was wrong; dropped rather than guessed.
- **founders.archives.gov would not render for this session.** Two quotes therefore rest on a secondary compilation and are tagged **[R]** in the pool: "a little rebellion, now and then, is a good thing" (Madison, 30 Jan 1787) and "The tree of liberty must be refreshed..." (William Stephens Smith, 13 Nov 1787). Both are used, and each `quote_source` says in-line that the text is unconfirmed against Founders Online. Re-verify before promotion to canon.
- **Shadwell has three candidate coordinates and the Monticello graveyard two.** Neither is settled here.
- **No Masonic claim is made.** The pool notes Jefferson's Masonic status is debated and unattested while flagging the Philadelphia Masonic-memorabilia network as a possible interlock via `madame_de_lafayette`.
- **The enslaved community of Monticello appears at four points** (the adoption, Hemings in Paris, the 1826 dispersal, the 2017 room). No pool entry gives population figures, names beyond the Hemings family, or the sale records, so nothing beyond the pool is asserted.

## 10. Sources

**Reachable and used**

- National Archives, transcript of the engrossed Declaration of Independence (fetched directly per the pool's note): the three Declaration quotes.
- Wikisource: First Inaugural Address (1801); Danbury Baptist letter (1802); Virginia Statute for Religious Freedom; Autobiography (1821).
- Wikipedia: 'Thomas Jefferson'; 'Early life and career of Thomas Jefferson'; 'Shadwell, Virginia'; 'Tuckahoe (plantation)'; 'Monticello'; 'Poplar Forest'; 'Notes on the State of Virginia'; 'The Jefferson Bible'; 'Thomas Jefferson Memorial'; 'Mount Rushmore'; 'Sally Hemings'; 'Library of Congress'; 'Francis Quadrangle'; 'Louisiana Purchase'; 'Lewis and Clark Expedition'.
- Encyclopedia Virginia, 'Thomas Jefferson': non-graduation, the Wythe chronology, the 2 June 1781 term expiry, the March 1790 assumption of office.
- History.com, 'Thomas Jefferson': the spine of the chronology lens.
- Jefferson's Autobiography, Memorandum Books, Farm Book, and the 1787 and 1788 travel journals, as cited by the geography lens.
- Thomas Jefferson Foundation statements on the Hemings question, 2000 and 2018; Foster et al., *Nature*, 1998.
- Atlas files via the interlock lens: `humboldt.journey.json`, `marques_de_lafayette.journey.json`, `madame_de_lafayette.journey.json`, `census_real_persons_2026-08-02.md`, `QUEUE.md`.

**Named and not reachable**

- **founders.archives.gov**, which would not render in this session. The largest gap: it is the authority for the two [R] quotes, the Gordon letter of 16 July 1788 on Elk Hill, the June 1803 instructions to Lewis, and Humboldt's letter of 24 May 1804.
- **Malone, *Jefferson and His Time***, cited through the geography lens for Tuckahoe; not consulted directly.
- **The Thomas Jefferson Foundation's Shadwell excavation reports**, which is why the three-way Shadwell coordinate disagreement stands open.
- `bolivar.journey.json`, `mark_twain.journey.json`, `francis_bellamy.journey.json`, unverified grep hits on "Washington", not opened here.

---

*Written for review, not for the globe. New journey files in `working/journeys` are not canon until approved.*
