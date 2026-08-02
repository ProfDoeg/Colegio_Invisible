# Gilles de Rais: research report
*2026-08-02. Marshal of France, companion-in-arms of Joan of Arc, hanged and burned at Nantes 26 October 1440. Slug: `gilles_de_rais`.*

Legend: **[A]** = attested, source named · **[R]** = reconstruction, tradition, or inference · contradictions are flagged and left open, never adjudicated silently.

Several dates and ten coordinates carried in the gathering pass were wrong. They were corrected against the encyclopaedia article for each place, and the corrections are listed in section 9 rather than buried, because the journey uses the corrected figures.

---

## 1. Origin and wardship (c. 1404 to 1422)

**Birth [A, disputed].** Born at the Château de Champtocé in Anjou and baptised in the castle chapel, whose ruins are listed *monument historique*, 16 June 1926 (FR Wikipedia). The **date is not settled**: Britannica gives September/October 1404, a chronology relayed by EN Wikipedia gives 10 September 1404, other biographers run as late as 1407–1408, and the broadest range in circulation is 1396–1406. The journey carries `1405-01-01` with the dispute in `date_confidence`. **No birth record survives.**

**Parents and wardship [A].** Father Guy de Rais (de Laval), mother Marie de Craon. Guy dies at Machecoul in **October 1415** (day not given in anything reached); Gilles and his brother René pass to their maternal grandfather **Jean de Craon**. The wardship is run as a marriage market: betrothals to **Jeanne Paynel** (1417, dissolved) and **Béatrice de Rohan** (1418, contract never fulfilled), both [A] per EN Wikipedia. Neither has a place attached in the pool, and neither gets a stop.

**Marriage [A, contradiction flagged].** Gilles abducts and marries his cousin **Catherine de Thouars**, bringing Tiffauges and Pouzauges into his hands. **Two datings stand unreconciled**: (a) abduction and marriage in 1420 without dispensation, papal validation in 1422 after her father's death (FR Wikipedia; medievalmatt.substack.com); (b) the ceremony itself at Chalonnes-sur-Loire on **26 June 1422** (EN Wikipedia). Both may be true of different acts. The journey pins Chalonnes, 1422-06-26, with the contradiction in `date_confidence`.

**Champtoceaux [R].** Two errors in the pool. (1) The dates (February–May 1420) are wrong: February is when Marguerite de Clisson captured Duke Jean V, which *triggered* the siege, which then ran May–July and capitulated "avec les honneurs le 5 juillet 1420" (FR Wikipedia). (2) **The FR Wikipedia article on Champtoceaux never mentions Gilles at the siege**, so his presence is a biographer's placement, **[R]**, not [A].

---

## 2. The soldier (1427 to 1432)

**Service dates [A, imprecise].** EN Wikipedia gives "1427 (or 1420?) – 1435", FR Wikipedia approximately 1420–1436. The pool's withdrawal from military affairs in 1433 is **too early as stated**, corrected to a gradual disengagement across the mid-1430s. His last documented field action is Lagny, 1432.

**Maine frontier [A].** Raiding English-held garrisons with the captain **Ambroise de Loré** from 1427 (EN Wikipedia). No engagement is named; the journey anchors the frontier at Le Mans (48.0061, 0.1996), an **editorial placement, not an attested location**.

**The relief of Orléans [A, date corrected].** Gilles escorts the supply convoy mustering at Blois. The pool dated the departure **25 April 1429**; EN Wikipedia's *Siege of Orléans (1428–1429)* states the convoy "finally left Blois on 27 or 28 April". The journey uses **1429-04-27**.

**Saint-Loup [A, date corrected].** The pool gives 6 May 1429, following the EN Wikipedia article on Rais. That article is wrong: the *Siege of Orléans* article states "At midday on 4 May Dunois launched the attack on this easterly English fortification", and 6 May was the assault on Saint-Jean-le-Blanc and Les Augustins. The journey uses **1429-05-04**. **Two Wikipedia articles contradict each other; the one treating the siege directly is preferred, in the open.**

**Loire campaign [A, tags corrected upward].** The pool tagged Meung (15 June) and Beaugency (16–17 June) **[R]**, reasoning that no source names Gilles individually. **Over-cautious.** EN Wikipedia's *Loire Campaign (1429)* names him among the captains under Joan of Arc and Alençon at both. Both are **[A]**. Jargeau and Patay were already [A].

**Reims [A].** 17 July 1429: raised to **Marshal of France**, and by tradition among the four lords escorting the Sainte Ampoule at the coronation. `joan_of_arc.journey.json` describes "four knights on horseback" **without naming them**; identifying Gilles as one is external history. [A] for the marshalcy, [R] for the identification.

**Then [A].** Les Tourelles, 7 May 1429, attested in EN Wikipedia's chronology of places. Montépilloy, 15 August 1429, the inconclusive day facing Bedford near Senlis, coordinates corrected in section 9. Paris, 8 September 1429, the failed assault on the Porte Saint-Honoré where Joan is wounded in the thigh. Lagny, 1432 (month not fixed; the geography lens says August), counted by his biographers among his best feats of arms and the last of them. Jean de Craon dies in November 1432, day not given, and Gilles inherits.

---

## 3. The interlock with Joan of Arc

**[A] Corpus metadata states the connection directly.** `census_real_persons_2026-08-02.md` line 36 identifies "Rais" as "French marshal, companion of Joan of Arc"; `QUEUE.md` line 47 logs him with 8 corpus documents naming him as "companion-in-arms of Joan of Arc."

**[A] But no journey file names him.** A grep across all `*.journey.json` for "Gilles", "Rais", "Nantes", "Machecoul", "Tiffauges", and "Bluebeard" returns **zero mentions**; every "Rais" match in `joan_of_arc.journey.json` is the verb *to raise*. **A gap, stated as a gap:** the interlock is real in history and absent from the atlas until now.

**Fourteen canonical pins are inherited byte-identical from `joan_of_arc.journey.json`:** Blois 47.5866/1.3288; Orléans Burgundy gate 47.8995/1.9184; Bastille Saint-Loup 47.9103/1.941; Les Tourelles 47.8963/1.9077; Orléans siege lifted 47.9005/1.9039; Jargeau 47.865/2.1211; Meung-sur-Loire 47.8253/1.6953; Beaugency 47.7794/1.63; Patay 48.048/1.695; Reims 49.2539/4.0349; Porte Saint-Honoré 48.8632/2.3336; Lagny-sur-Marne 48.8737/2.71; Chinon 47.1682/0.2367; Paris city pin 48.8566/2.3522.

The geography lens gave different figures for several (Blois 47.5861/1.3359; Patay 48.0558/1.6939; Lagny 48.8756/2.7047). **The corpus pin wins every time**, so that the two travellers stand on one point.

**Second interlock, conceptual only [R].** `jesus.journey.json` pins the Massacre of the Innocents at Bethlehem (31.7042, 35.2075). Gilles founds a chapel at Machecoul **dedicated to the Holy Innocents** while, by his own servants' testimony, children are killed on the same ground. The dedication is documented; the resonance is thematic, **not evidentiary**, with no shared time, place, or persons. Named in that one campa and nowhere else.

---

## 4. Ruin (1432 to 1439)

**Onset of the killings [R, disputed].** The indictment-derived chronology begins the child-murders about **1432**, with his withdrawal from soldiering; other accounts say **late 1433**. Nothing contemporary fixes it, and neither figure is chosen.

**Loss of patronage [A].** Georges de La Trémoille, his kinsman and patron, falls from favour in **June 1433**. His daughter **Marie** is born that year.

**La Suze [R].** His brother René is granted the La Suze inheritance on **25 January 1434**, part of the family's property fights as the finances collapse. *Cut from the journey for length; the coordinate correction is in section 9.*

**The Mystère du siège d'Orléans [R].** A theatrical reconstruction of the siege staged at Orléans, hundreds of costumed actors, repeated free performances, financed by Gilles, dated 1435 in the pool and cited among the causes of his ruin.

**Royal interdict [A].** In **July 1435** Charles VII forbids further alienation of his lands, alarmed by spending on alchemy, ritual, and the Mystère. Duke Jean V's refusal to publish the edict in Brittany and his continued buying is standard in the literature but **is not in the verified pool**; it is in the journey campa, flagged **[R], general history.**

**Sales [A].** Ingrandes among the Angevin seigneuries sold off c. 1435–1437 (FR Wikipedia). **Chapel of the Holy Innocents [R]:** founded and richly endowed at Machecoul c. 1435–1436, with a college of canons and choristers.

**Tiffauges and Prelati [A/R].** The alchemical and demon-summoning work is attested by trial testimony; the **dating is uncertain**. Two corrections: (1) **Prelati was not Florentine.** EN and FR Wikipedia give his birth about 1417 at **Montecatini Terme, diocese of Lucca**; he styled himself "François de Montcatin". (2) **The arrival date of 14 May 1439 is uncorroborated**, appearing in one chronology and in neither Wikipedia article. Tagged **[R]**.

---

## 5. The fall and the two trials (1440)

**Saint-Étienne-de-Mer-Morte [A].** On **15 May 1440** Gilles seizes the tonsured clerk **Jean Le Ferron** during high mass in the parish church and takes the neighbouring castle by force. Confirmed by the commemorative plaque quoted in FR Wikipedia. Coordinates corrected, see section 9.

**Ducal recapture [R, mis-filed in the pool].** The recapture and freeing of Le Ferron, **24 August 1440**, is filed in the pool under "Château de Machecoul" **at Machecoul's coordinates**, a mismatch: it happened at Saint-Étienne. The date rests solely on famous-trials.com, **404 during verification**. Folded into the Saint-Étienne campa.

**Arrest [A].** 15 September 1440 at Machecoul, with the servants **Henriet Griart** and **Etienne Corrillaut, called Poitou**. The secular inquest opens on **18 September**, the date of the innkeepers' deposition about Peronne Loessart's son, Bataille pp. 253–255.

**Indictment and confession [A, dates corrected].** The bill of **forty-nine articles** is read **13 October 1440**, not 13 September, which is the date of a general first indictment; four quotes were moved. The in-court confession is of **22 October** (Bataille pp. 195–203), not the 21st, which was the separate out-of-court interrogation; four more quotes were moved.

**Sentencing [A, attribution corrected].** Two ecclesiastical sentences on **25 October 1440**, one for apostasy and demon-invocation, one for sodomy on children of both sexes (Bataille pp. 207–208). The pool called the sodomy sentence "the secular court's verdict". **Wrong**: both are ecclesiastical. The secular sentence, by Pierre de l'Hôpital at Le Bouffay, **does not appear in the document** and is known only from narrative accounts.

**Execution [A].** 26 October 1440, hanged and burned in a meadow beyond the Loire with Henriet and Poitou. The Île de la Grande Biesse no longer exists as an island and the two lenses disagree about where it was; see section 9, **contradiction not resolved**. The claim that he heard mass at the Cathedral of Saint-Pierre-et-Saint-Paul that morning is **[R] and uncorroborated by anything reachable** (patrimonia.nantes.fr and famous-trials.com both 404), and is dropped.

**Burial [A, coordinate contradiction].** Buried the same evening in the Carmelite church of Notre-Dame des Carmes (EN Wikipedia). The two lenses disagree by 360 m about the vanished convent and **neither figure is sourced**; see section 9.

---

## 6. Quotations: what survived checking

Fourteen quotations were carried in the pool from the Bataille dossier. **Thirteen are verbatim.** One is not, and it matters:

**Failed [A].** "the child had been well chosen, and that he was as beautiful as an angel" is a **stitched and reworded composite**. The page reads: "the said Lord told Poitou that the child *was* well chosen; Poitou responded that there had been no one but himself to choose, and the said Lord told him that he had not been mistaken and that *the child* was as beautiful as an angel." The tense was changed, "the child" became "he", and an intervening clause was closed over. The journey uses only **"the child was as beautiful as an angel"**. The speech is also **reported by the innkeeper witnesses, not spoken by Peronne Loessart**, and dated **18 September 1440**.

**Unverified [R].** "We have sinned, all three of us, but as soon as our souls depart our bodies we shall all see God in His glory in Heaven" is attributed to Gilles at the scaffold and appears in narrative accounts only. **It is not in the primary confession or sentencing documents**, and the journey says so in `quote_source`.

All other quotes were checked word for word against the famous-trials.com transcriptions, which print the Bataille source line, and are used unaltered.

---

## 7. Afterlife

- **Bluebeard [A].** Tradition since the early nineteenth century identifies Rais with Perrault's *La Barbe bleue* (1697); the 1911 Britannica already notes it. **Modern scholarship treats it as speculative, with no evidence Perrault knew his history.**
- **Carmelite convent and Crée-Lait [R].** The convent and the tomb monument are destroyed in the Revolution. An expiatory monument near the execution ground, Notre-Dame-de-Crée-Lait, a pilgrimage point for pregnant and nursing women, disappears in **1867**, fragments at the Musée Dobrée. Both rest on patrimonia.nantes.fr alone, **404 at verification time**.
- **Là-bas [A, tag corrected upward].** The pool tagged Huysmans's novel [R] because the excerpts fetched did not surface it. **It is fully attested**: EN Wikipedia records serialisation from **15 February 1891** in *L'Écho de Paris*, book form in April, and Durtal "begins to research the life of the notorious 15th-century child-murderer and torturer Gilles de Rais".
- **Bataille [A, date contradiction].** *Le Procès de Gilles de Rais*, Pauvert, **1965**, Latin minutes into French by **Pierre Klossowski**. Robinson's English translation is dated **1991** by Open Library and **2004** by booksellers, **left open in `date_confidence`**; the pool's flat "2004" is at best a reprint.
- **The 1992 rehabilitation [A, characterisation corrected].** The staged trial happened, but calling it "formal" misleads. **Gilbert Prouteau**, who organised it and published *Gilles de Rais ou la Gueule du loup* (Éditions du Rocher, 1992), called it "une farce monumentale montée avec des comparses de haute volée" and was still laughing about it years later (FR Wikipedia).
- **Reinach [R, dating rejected].** **Salomon Reinach died 4 November 1932**, so the pool's "commonly dated to the 1930s" is at best the very end of his life and probably wrong; his writing on Rais belongs to the earlier *Cultes, mythes et religions*. **No date is printed in the journey**, and Reinach is separated from the 1992 event, which he cannot have been associated with.
- **Scholarship [A].** Jacques Chiffoleau and Claude Gauvard examine the trial records without seeking to exonerate him, treating the rehabilitation literature as a separate, largely non-scholarly tradition (FR Wikipedia).
- **No statue [R].** No public monument to Rais is recorded at Nantes or the Loire sites. **A negative inferred from the sources consulted; no monument inventory was checked.**

---

## 8. Honest gaps

1. **The victim count is not knowable.** The ecclesiastical court cites 140; his own servants say the number could not be counted; no register of the missing survives. The journey states the court's figure as the court's figure and does not adopt it.
2. **Catherine de Thouars is a blank.** Never charged, never questioned in the surviving record, nothing she said has come down. Marie de Rais, born 1433, appears in the pool once and never again.
3. **No place of issue for the July 1435 royal edict.** The pool says only "France"; the journey attaches it to Ingrandes, where the sales were happening. **An editorial placement.**
4. **The Maine campaigning has no named site.** Le Mans is a proxy chosen by the writer.
5. **The Hôtel de la Suze cannot be located.** The building is gone; the pool gives 47.216, -1.555 as "the old town of Nantes generally", used as such.
6. **famous-trials.com narrative pages were 404 during verification.** They carry the 24 August 1440 recapture, the execution-day detail, and the scaffold quotation. Its *document* transcriptions were reachable and were checked word for word.
7. **No monograph was consulted.** No Chiffoleau or Gauvard text was read directly; both are known only through the FR Wikipedia sentence citing them.
8. **The corpus itself is silent** (section 3): the Joan of Arc interlock had to be built from shared campaign chronology, not from anything already written into a stop.

---

## 9. Coordinate corrections applied

The authority is the encyclopaedia article for the place, except in the last two, where **no figure is sourced at all**. The journey uses the bold figure.

- Champtocé-sur-Loire **47.4125, -0.8619** (pool 47.3833, -0.7667, ~8 km)
- Champtoceaux **47.3378, -1.2656** (pool 47.3717, -1.1875, ~7.7 km)
- Montépilloy **49.2100, 2.6989** (pool 49.2394, 2.5453, 11 to 12 km)
- La Suze-sur-Sarthe **47.8906, 0.0261** (pool 47.8969, 0.1075, ~6 km)
- Bourgneuf-en-Retz **47.0439, -1.9514** (pool 46.9575, -1.9636, ~10 km, in the marsh)
- Saint-Étienne-de-Mer-Morte **46.9306, -1.7414** (pool 46.9767, -1.7833, ~6 km)
- Château de Tiffauges **47.0167, -1.1147** (pool 46.9989, -1.0967 and 47.0083, -0.9704, up to ~11 km, **the two lenses contradicted each other**)
- Machecoul **46.9939, -1.8217** (pool 46.9967, -1.8258, under 1 km)
- Execution ground, Nantes **47.2093, -1.5423** (pool 47.2079, -1.5462, ~400 m, **not resolved**)
- Notre-Dame des Carmes **47.2145, -1.5535** (pool 47.2151, -1.5583, ~360 m, **not resolved**)

La Suze, Bourgneuf-en-Retz, and Pornic were cut from the journey for length; their corrections are kept here.

---

## Sources

**Reachable and used**
- EN Wikipedia: *Gilles de Rais* (biography, chronology of places); *Siege of Orléans (1428-1429)* (corrected the Blois departure and the Saint-Loup date); *Loire Campaign (1429)* (named Rais at Meung and Beaugency, upgrading both to [A]); *Château de Tiffauges* (corrected coordinates against two conflicting lens figures); *Là-bas (novel)*; *Bluebeard*; *Salomon Reinach*
- FR Wikipedia: *Gilles de Rais*; *Champtocé-sur-Loire*; *Champtoceaux*; *Montépilloy*; *La Suze-sur-Sarthe*; *Bourgneuf-en-Retz*; *Saint-Étienne-de-Mer-Morte*; *François Prelati*; *Gilbert Prouteau*
- Encyclopaedia Britannica, *Gilles de Rais*, and 1911 Britannica, *Rais, Gilles de* (Wikisource), earliest Bluebeard attestation reached
- famous-trials.com document transcriptions, all from Georges Bataille, *The Trial of Gilles de Rais*, Amok Books, trans. Richard Robinson: *Indictment* (pp. 169–180); *Confession of Gilles de Rais* (pp. 195–203); *Sentencing* (pp. 207–208); *Confession of Henriet* (pp. 275–279); *Confession of Poitou* (pp. 279–282); *Testimony concerning a missing child* (pp. 253–255)
- Open Library, entry for Bataille, *Le Procès de Gilles de Rais*, J.-J. Pauvert 1965; Amok Books English edition dated 1991
- medievalmatt.substack.com, "Have You Heard of Gilles de Rais?": used only where it agrees with an encyclopaedia
- Corpus: `joan_of_arc.journey.json` (all inherited pins), `jesus.journey.json` (Bethlehem), `census_real_persons_2026-08-02.md` line 36, `QUEUE.md` line 47

**Named as unreachable**
- **famous-trials.com narrative pages** ("An Account"; "A Chronology"): **HTTP 404 at verification**. Everything resting on them alone is [R]: the 24 August 1440 recapture, the scaffold quotation, the execution-morning detail.
- **patrimonia.nantes.fr**: **404**. The convent's Revolutionary destruction, the Crée-Lait monument, and the Musée Dobrée fragments rest on it alone and are [R].
- **Bataille, *Le Procès de Gilles de Rais*, printed volume**: not held; reached only through the transcriptions, which do print the page ranges and translator.
- **Jacques Chiffoleau and Claude Gauvard**: no text of either read.
- **Salomon Reinach's essay on Rais**: not located, neither title nor date established.
- **No monument inventory for Nantes or the Vendée** was checked, so the claim that no statue exists remains an unverified negative.
