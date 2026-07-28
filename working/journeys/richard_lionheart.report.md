# Richard the Lionheart — report

**Sources.** Primary-adjacent: Ambroise's *L'Estoire de la Guerre Sainte* and the Latin *Itinerarium Peregrinorum* (crusade eyewitness/near-eyewitness verse and prose); Baha ad-Din ibn Shaddad, *The Rare and Excellent History of Saladin* (Ayyubid eyewitness at Acre and Arsuf); Roger of Howden's *Gesta Regis Ricardi*; Ralph of Coggeshall's *Chronicon Anglicanum*; William the Breton's *Philippide*. Modern synthesis: John Gillingham, *Richard I* (Yale, 1999) — the standard biography — plus Jean Flori, Peter Edbury (*The Kingdom of Cyprus and the Crusades*), and Marjorie Reeves on Joachim of Fiore. Richard's own surviving poem, "Ja nus hons pris" (RS 1891), is quoted from the standard Old French text. Web verification of dates, itinerary, and the al-Kamil episode used current secondary sources (see individual `sources` fields per stop).

**Judgment calls.** (1) The al-Kamil knighting — the curator's centerpiece — has no primary-source passage I could pin to a page in Baha ad-Din's text via search; multiple modern secondary accounts converge on 29 March 1192 at Acre, with al-Kamil aged eleven or twelve, and I've marked it `traditional` rather than `attested` accordingly. (2) The "shield before Jerusalem" refusal-to-look is explicitly a later legend built on Ambroise's plainer report that Richard saw the city from a hilltop near Beit Nuba; I kept the legend (with its resonant quote) but marked it `traditional`. (3) Blondel de Nesle's song-search for Dürnstein is flagged in its own campa text as a legend layered onto a captivity whose location was, historically, no secret at all — true to the "canon is true" register while being honest that this is the *later* canon, first attested in the 1260s. (4) Richard's entrails: Châlus and Charroux both claim them; I named Châlus as primary with Charroux as alternate tradition rather than pick one falsely.

**Time-folds / gaps.** The 1191–92 Holy Land campaign is compressed hardest — eighteen months of maneuvering, two Beit Nuba advances, the Jaffa/Joan marriage-proposal comedy, and the Ascalon rebuilding are represented by seven stops rather than the dozens of skirmishes the chronicles record. Richard's youth (1157–79) likewise skips the 1173–74 great rebellion against his father in which he was a chief actor, folding it into the Taillebourg and investiture stops instead, to keep the crusade and captivity — the curator's real interest — proportionally dominant.

**Five richest episodes.** (1) The investiture as Duke of Aquitaine at fourteen — ring of St. Valerie, lance and banner at Saint-Hilaire — the moment Eleanor's country becomes his. (2) The knighting of the boy al-Kamil at Acre, 29 March 1192 — the hinge the curator asked for, and the scene that (per the memory index) should let a future `al_kamil.journey.json` open from the other side of the same morning. (3) The massacre at Ayyadieh, 20 August 1191 — narrated as the canon narrates it, Christian chroniclers calling it retribution, without softening what it plainly also was. (4) The capture at Erdberg — the spit-turning kitchen detail, the boy-interpreter who gives him away buying provisions too freely. (5) "Ja nus hons pris" at Trifels — Richard's own words, the only stop in the whole journey where the traveler's voice is not reported by a chronicler but composed by the man himself.

**Connections to the atlas.** Shares Chinon with Joan of Arc (his father dies where she will later be recognized by a king 250 years on) and Westminster Abbey coronation-ground with any future English-crown journey. The al-Kamil knighting is built explicitly as a shared pin awaiting `al_kamil.journey.json` — same date, same city, same event, different point of view, in the house style already used for Joan/Bourlemont shared pins. Eleanor of Aquitaine appears throughout as regent, ransom-bearer, and kingmaker without yet having her own journey file — a clear next-candidate. The crusade segments sit adjacent in theme (not yet in the corpus) to any future Saladin or Third Crusade dataset; Joachim of Fiore's Antichrist prophecy at Messina is a loose thread toward apocalyptic/esoteric register journeys already in the atlas's orbit.

---

## Verification pass — 2026-07-20

Independent structural and canon-fidelity review. `json_check.py`: **OK, 0 WARN, 9 segments, 43 stops, 6 quoted** (before and after repair). Schema matches `joan_of_arc.journey.json` exactly (top-level `traveler / title / years / calendar / register / segments`; per-stop `name / lat / lng / date / date_confidence / campa / quote / quote_source / suggested_refs / sources`).

### Confirmed sound

- **Chronology.** All 9 segments internally ordered; no cross-segment inversions. Stop count 43 sits inside the 30–45 target, so no additions were made.
- **Dates spot-checked against the canon and found correct:** birth 8 Sep 1157; Young King's death 11 Jun 1183; Henry II's death at Chinon 6 Jul 1189; coronation 3 Sep 1189; departure from Vézelay 4 Jul 1190; storming of Messina 4 Oct 1190; fleet sails 10 Apr 1191; Limassol 6 May 1191; marriage 12 May 1191; Richard at Acre 8 Jun 1191; fall of Acre 12 Jul 1191; Ayyadieh 20 Aug 1191; Arsuf 7 Sep 1191; Treaty of Jaffa 2 Sep 1192; departure from Acre 9 Oct 1192; Corfu 11 Nov 1192; capture at Erdberg 21 Dec 1192; **Speyer 28 Mar 1193 (verified — the Diet was summoned for Palm Sunday 21 March, but Richard was handed to Henry VI on the 28th, so the file's date is right)**; Worms ransom terms 29 Jun 1193; release at Mainz 4 Feb 1194; Sandwich 13 Mar 1194; Fréteval 3 Jul 1194; wounding at Châlus 26 Mar 1199, death 6 Apr, burial 11 Apr.
- **Confidences honest.** Legend-layered material is correctly marked `traditional`, not `attested`: the shield before Jerusalem, the Blondel song-search (whose campa already states plainly that the Emperor had announced the capture — the correction is inside the narration, and the legend is kept, as it should be), the al-Kamil knighting, the Château Gaillard boast.
- **Register.** Present tense throughout, all campas in-band. The great episodes are not flat: Taillebourg, Ayyadieh, Arsuf, the Erdberg kitchen spit, the Trifels song, and the divided burial all carry their weight.
- **Coordinates verified correct as given:** Oxford/Beaumont, Poitiers, Limoges, Martel, Tours, Chinon, Westminster, Vézelay, Marseille, Messina, Acre, Arsuf, Jaffa, Beit Nuba, Corfu, Aquileia, Erdberg, Dürnstein, Speyer, Worms, Mainz, Sandwich, Winchester, Fréteval, Château Gaillard, Châlus, Fontevraud.

### Repaired in place

**1. Cyprus — place/narrative mismatch (substantive).** The stop was named *"Kyrenia, the submission and the silver chains"* at Kyrenia's coordinates (35.3417, 33.3192), while its campa placed the surrender at Kantara. Neither is where Isaac Komnenos actually yielded: after his army broke near Tremithousa he fled to Kantara and was run down at **Cape Apostolos Andreas**, the tip of the Karpass peninsula. Renamed the stop, moved it to 35.6873 / 34.5814, rewrote the opening clause to trace the real flight (Tremithousa → Kantara → the cape), and retargeted the `suggested_refs` entry. Campa trimmed back to 110 words after the rewrite.

**2. Coordinates corrected.**
- Taillebourg: 45.849 / -0.635 → **45.8317 / -0.6339**
- Limassol landing: 34.7071 / 33.0226 (modern city centre) → **34.6753 / 33.0413** (the castle/old-harbour ground)
- Limassol, Chapel of Saint George: 34.707 / 33.0225 → **34.6739 / 33.0424** (inside Limassol Castle, where the wedding is sited)
- Friesach: 46.951 / **14.501 → 14.4058** (the longitude was ~7 km east of the town)
- Trifels: 49.2075 / 7.9522 → **49.1928 / 7.9789** (the castle rock, not the valley)

**3. Quotes — two failed the carry test, two were misattributed.**

- **Treaty of Jaffa.** *"I commend to God's protection this land and this Holy City, which I have not been able to deliver."* — could not be traced to Ambroise, Baha ad-Din, or the *Itinerarium*; it reads as composed. Rather than null the stop and lose the episode's voice, it was **replaced with the genuinely carried line from the same moment**: Saladin's reply to Richard's request for a three-year truce, from the *Itinerarium Peregrinorum et Gesta Regis Ricardi* — that if the land were to be lost in his time, he would rather it pass to Richard's power than to any other prince he had ever seen. Attribution now names the speaker and the source explicitly.
- **Speyer.** Wording restored to the received form — *"I am born in a rank which recognizes no superior but God, to whom alone I am responsible for my actions"* (was "born **of** a rank… **answerable for my conduct**"). The `quote_source` credited **William the Breton's *Philippide***, which does not carry it; the line descends through later English tradition (printed in Duncan, *The Dukes of Normandy*, 1839). Source line rewritten to say so plainly instead of naming a chronicle that does not hold it.
- **Château Gaillard.** The quote opened with an invented French tag, *"Ma belle fille d'un an —"*. The canon here is **Latin**: William of Newburgh, *"Quam pulchra est filia mea unius anni!"* Quote reduced to the standard English rendering, source corrected to Newburgh with the Latin given.
- **"Ja nus hons pris."** Text confirmed against the RS 1891 critical edition; the file's reading (`par confort`, not the KNOX variant `par effort`) is the preferable one, so the text stands. But the attribution asserted Trifels flatly — the composition place is given variously as Dürnstein or Trifels, and the printed text is a normalization of the chansonnier tradition. `quote_source` now states both. The stop itself stays at Trifels.
- **Beit Nuba / the shield** and **Châlus / the pardon** both verified and left as they stand. The shield-raising is later legend and the file already says so in `quote_source`; the Châlus mercy ("Live on, and by my bounty behold the light of day") is carried by Howden and correctly attributed.

**4. Factual detail.** Châlus-Chabrol's `suggested_refs` placed the keep "above the Vienne" — it stands above the **Tardoire**. Corrected.

### Noted, not changed

- The Châlus campa names the crossbowman "Bertrand de Gourdon." This is Howden's name (Bertram de Gurdun); Ralph of Coggeshall and Bernard Itier call him Pierre Basile. The campa already hedges with *"a boy some chroniclers name"*, which is the honest form, and the file cites Howden — left as is.
- The al-Kamil knighting at Acre (29 Mar 1192) remains a `traditional`-marked shared-pin hook awaiting `al_kamil.journey.json`, per the curator's brief. Its `suggested_refs` forward-link to the 1219 meeting with Francis is the intended cross-journey seam and was left intact.
- Ayyadieh (32.96 / 35.1) is an approximation of Tell al-'Ayyadiya east of Acre. Within a couple of kilometres of the traditional mound; left rather than invent false precision.

Final state: **43 stops, 9 segments, 6 quotes, 0 WARN.**

---

## Verification pass — 2026-07-20

Independent structure and canon-fidelity check. Reference schema/register: `joan_of_arc.journey.json`.
Repaired in place. **No stop was added, removed, or reordered** — 9 segments, 43 stops, order untouched, so the Spanish twin at `es/richard_lionheart.journey.json` stays positionally aligned.

Final state: **43 stops, 9 segments, 4 quotes, 0 WARN.**

### 1. Structure

`json_check.py` clean before and after. All ten per-stop keys present on all 43 stops; campa word-counts all inside 60–110; `quote`/`quote_source` both-or-neither holds. Against Joan: same top-level key set, same stop key set, same present-tense mythic register. The only cosmetic divergence is the `register` separator (em-dash here, colon in Joan) — eleven files in the fleet already use the em-dash form, so it was left alone.

Dates re-walked segment by segment: chronological throughout, no inversions.

### 2. Coordinates — 12 sites web-checked, 11 moved

Every fix is a same-place refinement; none of them moved a stop to a different town, and only Beit Nuba was wrong by enough to matter on a globe.

| Stop | was | now | error |
|---|---|---|---|
| Beit Nuba (×2 stops) | 31.854 / 34.983 | **31.8533 / 35.0325** | ~4.6 km — the worst on the file; the pin sat west of the Latrun salient instead of on the village |
| Vienna, Erdberg | 48.1986 / 16.4079 | **48.2007 / 16.398** | ~0.8 km; now on Erdbergstraße 41, the plaque site of the Rüdenhof inn |
| Speyer | 49.3167 / 8.4333 | **49.3172 / 8.4424** | ~0.7 km; `suggested_refs` names the cathedral, so the pin is now on it |
| Château Gaillard | 49.2333 / 1.4104 | **49.238 / 1.4031** | ~0.75 km; was off the chalk spur |
| Châlus-Chabrol | 45.6667 / 0.9833 | **45.6576 / 0.9793** | ~1.1 km; now the castle, not the town centroid |
| Fréteval | 47.899 / 1.198 | **47.888 / 1.211** | ~1.5 km |
| Martel | 44.944 / 1.619 | **44.9361 / 1.6061** | ~1.3 km |
| Limassol, the wedding | 34.6739 / 33.0424 | **34.6725 / 33.0417** | ~0.2 km; onto the castle proper |
| Vézelay | 47.4638 / 3.7469 | **47.4664 / 3.749** | ~0.34 km; onto the basilica |
| Fontevraud | 47.1817 / 0.0567 | **47.1814 / 0.0517** | ~0.38 km; onto the abbey |
| Oxford, Beaumont Palace | 51.754 / -1.26 | **51.7551 / -1.2621** | ~0.2 km; onto SP51030652, the marked palace site |

Checked and left standing: Poitiers, Limoges, Taillebourg, Tours, Chinon, Westminster Abbey, Marseille, Messina, Limassol (the landing), Cape Apostolos Andreas, Acre, Arsuf, Jaffa, Corfu, Aquileia, Friesach, Dürnstein, Trifels, Worms, Mainz, Sandwich, Winchester.

### 3. Quotes — six checked, two nulled

- **Speyer, "I am born in a rank which recognizes no superior but God…" — NULLED.** The previous pass restored this line's wording and honestly flagged it as "received English tradition." It is worse than that: the line traces no further back than Jonathan Duncan, *The Dukes of Normandy* (London, 1839), which gives no earlier source, and it is most likely Duncan's own composition placed in Richard's mouth. Howden, Coggeshall and William the Breton do not carry it. **The trial stays.** The campa still has him defending himself alone, unbroken, moving hardened enemies — only the invented sentence is gone.
- **Beit Nuba, "Ha! Lord God, I pray that I may never see Jerusalem…" — NULLED.** Ambroise carries only that Richard rode to a hilltop from which Jerusalem was visible. The shield-raising is later legend, and no medieval text bearing these words could be found in Ambroise, the *Itinerarium*, or the Old French continuations. **The episode stays** — the campa still raises the shield and still says he is not worthy to see the city he cannot deliver. The myth is untouched; only the manufactured wording is.
- **Saladin's reply, "If the land were to be lost in his time…" — CONFIRMED, attribution tightened.** Wording matches the *Itinerarium Peregrinorum et Gesta Regis Ricardi* essentially verbatim. But the reply belongs to the truce embassy of **late July 1192**, not to the September signing; `quote_source` now says so while keeping the stop on the treaty.
- **Château Gaillard, "Behold, how fair is this year-old daughter of mine!" — KEPT, attribution corrected.** The saying is genuinely carried by the Anglo-Norman chronicle tradition. The Latin the previous pass supplied — *"Quam pulchra est filia mea unius anni!"* attributed to William of Newburgh — could not be located in Newburgh or any other chronicle text. The Latin and the flat attribution are removed; the source line now says plainly that this is the received English rendering with no single chronicle fixable as its origin.
- **"Ja nus hons pris" — CONFIRMED.** The file's stanza collates with the standard normalized text. Its readings (`Assez ai d'amis`, `par confort`) are attested chansonnier variants against the fr.wikipedia base text (`Pro ai d'amis`, `par confort`). `quote_source` already declares the normalization and the Dürnstein/Trifels ambiguity. Left exactly as it stands.
- **Châlus, "Live on, and by my bounty behold the light of day." — CONFIRMED.** Carried by Roger of Howden as Richard's pardon of the crossbowman. Left as it stands.

### 4. Dates

- **Beit Nuba, second advance: 1192-06-04 → 1192-06-11.** The army reached Beit Nuba on 11 June 1192; the council's decision to turn back came in early July. Still `traditional`, still in order.
- **Beit Nuba, first turning back: `attested` → `traditional`.** The retreat was resolved on 13 January 1192; the file's 8 January is the arrival window, not a fixed attested date. Date left, confidence honest.
- **Aquileia shipwreck: `attested` → `traditional`.** Chroniclers place the wreck in the first half of December 1192 without agreeing a day; 3 December is one reading among several.

Spot-confirmed and left: birth 8 Sep 1157; Martel 11 Jun 1183; Chinon 6 Jul 1189; Westminster 3 Sep 1189; Vézelay 4 Jul 1190; Messina 4 Oct 1190; sailing 10 Apr 1191; Limassol 6 May 1191; wedding 12 May 1191; Acre 8 Jun and 12 Jul 1191; Ayyadieh 20 Aug 1191; Arsuf 7 Sep 1191; Jaffa treaty 2 Sep 1192; departure 9 Oct 1192; Corfu 11 Nov 1192; capture 21 Dec 1192; Speyer 28 Mar 1193; Mainz 4 Feb 1194; Sandwich 13 Mar 1194; Winchester 17 Apr 1194; Fréteval 3 Jul 1194; the bolt 26 Mar 1199; Fontevraud 11 Apr 1199.

### 5. Stop count

43 stops is well clear of the 30-stop floor and the arc is complete — birth, Aquitaine, the crusade vow, Sicily, Cyprus, Acre, the two turnings-back, Jaffa, the capture, the song, the ransom, the return, Châlus, the divided burial. **Nothing added.**

### Could not confirm

- **Ayyadieh, 32.96 / 35.1.** No published coordinate for Tell al-'Ayyadiya could be found. The value is an approximation of the mound a few kilometres east of Acre and is consistent with the accounts; left rather than fabricate precision. Flagged again here because it is the one crusade coordinate still unverified.
- **The Château Gaillard saying's origin.** Universally repeated, nowhere traceable to a specific chronicle passage. Kept as tradition, labelled as tradition.
- **The exact day of the Aquileia wreck**, and **the exact day the council at Beit Nuba resolved the second retreat** — both left inside their traditional windows.
