# Al-Malik al-Kamil — Cairo to Damascus: the Sultan Who Gave Away Jerusalem Twice (1180–1238)

**Shape:** 34 stops in 8 named segments (Cairo-Born Acre-Knighted, the Viceroy of Egypt, the Sultan Under Siege, the Trap at Mansura, Brothers and Rivals, the Emperor's Questions, the Treaty of Jaffa, the Last Years). Calendar julian. Register: national mythology — the canon (Ibn Wasil's *Mufarrij al-Kurub*, Oliver of Paderborn's *Historia Damiatina*, the Franciscan *Legenda Maior*, Ibn al-Athir) is TRUE and narrated as event. 3 of 34 stops carry a quote; the rest are honestly null — al-Kamil is known to us almost entirely through others' chronicles, not his own first-person voice, so nulls dominate by design rather than neglect.

## Sources
- **Ibn Wasil, *Mufarrij al-Kurub fi Akhbar Bani Ayyub*** — the Ayyubid court chronicle, the closest thing to al-Kamil's own perspective on the al-Mashtub conspiracy, the Fifth Crusade offers, the Treaty of Jaffa's terms, and the muezzin anecdote at Jerusalem.
- **Oliver of Paderborn, *Historia Damiatina*** — the crusader eyewitness account of the siege, the Nile-flood trap at Mansura, and his own testimony to al-Kamil's clemency in feeding the surrendered army.
- **Bonaventure, *Legenda Maior*, and Jacques de Vitry's Letter VI (1220)** — the Franciscan canon for the Fariskur encounter, cross-checked against `saint_francis.journey.json`'s own Fariskur stop for exact wording of the farewell quote.
- Wikipedia (Al-Kamil, Fifth Crusade, Siege of Damietta, Treaty of Jaffa, Al-Mu'azzam Isa, Ayyubid dynasty, As-Salih Ayyub), Grokipedia (Al-Kamil, Battle of Mansurah), kurdish-history.com and sultanandthesaintfilm.com for consolidated biography, Paul Moses's *The Saint and the Sultan* for the Acre knighting, medievalists.net and researchgate.net for the Frederick II correspondence, Archnet/Wikipedia for the Madrasa al-Kamiliyya's foundation date.

## Judgment calls
- **The Acre knighting (1191)**: the curator's brief names it explicitly. Primary Ayyubid/Ricardian chronicles (Baha al-Din) document the Richard–al-Adil marriage negotiations at length but the knighting of the boy specifically is attested through Paul Moses's synthesis rather than a chronicle I could verify word-for-word; dated `traditional` and placed in the autumn 1191 truce-talk window.
- **Birth year**: sources split 1177/1180; I followed the majority (Sultan-and-Saint, kurdish-history) and used c. 1180, `traditional`.
- **The muezzin anecdote**: strictly an exchange between Frederick and the qadi Shams al-Din inside Jerusalem, not something al-Kamil witnessed firsthand — he was besieging Damascus at the time. I placed the stop at Jerusalem (the event's site) but wrote the campa as the report *reaching* the sultan's camp, keeping the traveler's actual location honest.
- **Jerusalem's walls thrown down (1219-1220)**: al-Mu'azzam's demolition, not al-Kamil's own act — included because it is the hinge that makes the later Jaffa cession militarily cheap; the campa is explicit that this was the brother's decision, not the sultan's.
- **Time-fold**: the "Emperor's Questions" segment compresses a correspondence that ran 1226–1230s into three anchored stops (1226, 1227, 1228) since individual letters are not reliably dated in the sources consulted.

## Gaps
No verbatim al-Kamil quote survives for the Fifth Crusade offers, the al-Mashtub conspiracy, or his own reaction to Frederick's coronation — all left null rather than invented. The philosophical content of the Frederick correspondence (often conflated in popular sources with the later "Sicilian Questions" Frederick posed to Ibn Sab'in, a different and later exchange) is described generically to avoid that conflation.

## The five richest episodes
1. **The friar from Assisi at Fariskur** (1219) — the counter-shot to `saint_francis.journey.json`: same tent, same farewell quote ("Pray for me, that God may reveal to me the law most pleasing to Him"), told from the sultan's side of the chains.
2. **The Nile dams opened at Mansura** (1221) — the Fifth Crusade's actual hinge: a river released, not a battle won, ending an invasion that three refused peace offers could not.
3. **The Treaty of Jaffa, negotiated entirely by letter** (1229) — two rulers who never meet, trading Jerusalem for a decade of peace so al-Kamil's real war, against his own nephew in Damascus, can be won.
4. **The gift of the star-tent** (c. 1228) — an early planetarium sent to Frederick, emblem of a friendship conducted wholly on parchment between a sultan and an excommunicate emperor.
5. **The sermon against the treaty in the Umayyad Mosque** (1229) — Sibt ibn al-Jawzi's public grief that Saladin's nephew gave away in an afternoon what his uncle spent a war winning.

## Connection to the atlas
This is the deliberate **counter-shot to `saint_francis.journey.json`**: the Fariskur stop shares coordinates, date, and the sultan's own farewell quote with Francis's telling of the same tent. It also runs alongside the crusader-era geography already staked out by `joan_of_arc.journey.json` (a different century, same Christian-mythic register applied here to the Muslim side of a shared frontier) and sits in direct historical sequence with any future Frederick II or Richard the Lionheart journey — the Acre knighting (1191) and the Jaffa treaty (1229) are both hinge-points that would anchor those itineraries too. Where Joan's canon narrates voices and a sword drawn from the earth as fact, al-Kamil's canon narrates diplomacy and clemency as the equivalent marvels: a sultan who wins wars by opening a river and loses none of his glory by feeding the men he starved.

---

## Verification pass — 2026-07-20

`json_check.py`: **OK**, no WARN lines, before and after repair.
Tally moved **34 → 38 stops**, 8 segments, 3 quoted.
Schema compared field-by-field against `joan_of_arc.journey.json` — identical top-level and per-stop key set, no drift.

### Coordinates — 14 spot-checked, all good

Cairo (30.0444, 31.2357), Cairo Citadel (30.0287, 31.2599), Kamiliyya/Jamaliyya quarter (30.0511, 31.2622), Acre (32.9281, 35.0818), Harran (36.8628, 39.0327), Damietta (31.4165, 31.8133) and the siege camp (31.42, 31.805), Fariskur (31.3297, 31.7146), al-Mansurah (31.0409, 31.3785), Jerusalem (31.7683, 35.2137), Jaffa (32.0533, 34.75), Damascus (33.5138, 36.2765), Umayyad Mosque (33.5117, 36.3053), Jazira frontier (36.2, 40.0 — deliberately generic). **No corrections needed.** The two new eastern stops were placed at Amid/Diyarbakır (37.9144, 40.2306) and Harran.

The Fariskur stop still shares coordinates and date with the Fariskur stop in `saint_francis.journey.json`, per the curator's brief. Confirmed intact.

### Quotes — 3 checked, 3 repaired

1. **The sultan's farewell to Francis.** The file carried a shortened paraphrase attributed to *Bonaventure, Legenda Maior* IX.9. The carried canonical form is **Jacques de Vitry**'s (*Historia occidentalis*, 1221 — the earliest witness, retold later by Bonaventure). Restored to the canon's wording: "Pray for me, that God may deign to reveal to me that law and faith which is most pleasing to Him," and re-sourced.
   ⚠️ **Divergence flagged for the curator:** `saint_francis.journey.json` carries the old short paraphrase inside its Fariskur *campa* (prose, not a `quote` field). Coordinates and date still match; only the wording now differs. Align that file if the twin should be verbatim.
2. **Oliver of Paderborn on the provisioning of the beaten army.** The file carried a different translation truncated with an ellipsis. Restored to the widely carried wording ("...revived us with their own food when we were dying of hunger and showered us with kindness even when we were in their power"). The mercy stands; only the translation changed.
3. **Ibn Wasil on the Jaffa terms.** Wording verified. Attribution corrected — these are **al-Kamil's own words of self-justification** as reported by Ibn Wasil, not Ibn Wasil's description of the clauses. That is a stronger and more accurate citation.

Quoted count stays at 3 and this is honest, not a gap: the Arabic chronicle tradition records al-Kamil's *acts* far more than his speech. A candidate fourth quote (Sibt ibn al-Jawzi's pulpit lines) was found only in modern secondary retelling, not in a primary translation, so it was **left null** rather than introduced.

### Factual corrections

- **"grandson of al-Adil" → "son of al-Adil"** in the Damascus sermon *campa*. Al-Kamil is al-Adil's eldest son; Saladin's nephew. Plain genealogical error.
- **The Damascus sermon re-dated 1229-07-01 → 1229-05-01** and re-ordered before the surrender stop. Sibt ibn al-Jawzi preached it *at al-Nasir Dawud's command while the city braced for the siege* — it was a weapon of the defence, not a lament after the fall. The old framing ("even as the city passes into his family's hands") inverted its meaning. Confidence lowered to `inferred` for the month.
- **"three crusades that came against Egypt"** → two. The Fifth came against Egypt; the Sixth did not land there at all.
- **"the last of Salah al-Din's nephews still holding real power"** (at 1229) → "the eldest". Al-Ashraf held Damascus and outlived that date by eight years.
- **"sixty years old" at death** → "in his sixtieth year or near it." The file dates his birth c.1180 (traditional), which would make him 58; sources split 1177/1180. The softened phrasing removes the internal contradiction without pretending the split is settled.
- Retitled the 1229 stop "the sultan of two crowns governs on" → **"the arbiter of the house governs on."** He held no second crown in 1229 — Damascus went to al-Ashraf. "Two crowns" now belongs to the January 1238 stop, where it is literally true.

### Four stops added (34 → 38)

The canon plainly offered more, and the old file had an unexplained eight-year hole between 1230 and a death in Damascus that was never accounted for — the reader was never told *why* he was in Damascus.

- **Amid, 18 Oct 1232** — the Artuqid conquest of Diyar Bakr, Hisn Kayfa in November, the whole principality handed to as-Salih Ayyub.
- **Harran, 1234** — routed by Kayqubad I; Siverek, Urfa, Harran and Raqqa lost. The plainest military defeat of the reign, kept in rather than smoothed away, and it rings against his first campaign on the same ground.
- **Damascus, Oct 1237** — al-Ashraf dies, as-Salih Ismail seizes the city, and the failed siege: Ismail razes the suburbs so no Egyptian can forage. The arbiter refused by his own house.
- **Damascus, Jan 1238** — the city opens, Ismail bought off with Baalbek and Bosra, the two crowns held at last. He holds them nine weeks.

The death *campa* was rewritten to land on that nine weeks, which now closes the arc instead of dangling.

### Canon fidelity

Nothing mythic was removed. The trial by fire, the sultan's refusal to harm Francis, the farewell prayer, the star-tent planetarium sent to Frederick, the muezzin anecdote at Jerusalem (still framed as a report reaching his camp, per the earlier honest gap), and the opening of the Nile dams all stand as the canon carries them. Only dates, attributions, genealogy and arithmetic were touched.

---

## Second verification pass — 2026-07-20 (independent re-check)

The first pass above was re-checked from sources rather than trusted. `json_check.py`: **OK**, no WARN, after repair. **38 stops, 8 segments, unchanged in count and order.** Quoted count **3 → 4**.

### Structural

**No stop added, removed or reordered.** Nine stops repaired in place (name / coords / date / campa / quote). The Spanish twin remains positionally aligned, but its text is now stale for those nine stops — see the list at the end.

### Dates corrected

- **The Acre knighting: 1191-11-01 → 1192-03-29.** Richard girded al-Adil's son with the belt of knighthood at **Easter 1192, back at Acre**, not in the autumn 1191 window the first pass guessed. The "eleven-year-old" stands on the 1180 birth year, which the Arabic tradition confirms (576–635 AH).
- **Al-Mu'azzam's ride, 1219-03-01 → 1219-02-12, `attested` → `inferred`.** He arrived within days of al-Kamil abandoning his camp on 4/5 February; a March date contradicted the campa's own "the moment word reaches him." The day is inferred, and now says so.
- **Death of al-Mu'azzam Isa: 1227-11-11 → 1227-11-12.**
- **Burial: 1238-03-10 → 1238-03-07.** The Arabic tradition is explicit that he was buried **the day after** his death.

### Coordinates — 14 spot-checked, 6 corrected

The serious error: **al-Kamil was never near Damascus in the winter of 1229.** He held his camp at **Tall al-Ajul** on the Wadi Ghazza, south of Gaza, from November 1228 until **late April 1229**; al-Ashraf opened the Damascus attack in March, and al-Kamil only reached the city on 6 May. The file placed him in Syria for the whole Jaffa negotiation — roughly 370 km and a border out.

| stop | was | now | why |
|---|---|---|---|
| the Jan 1229 stop | 33.4, 36.1 ("Near Damascus") | 31.4669, 34.4064 | he was at Tall al-Ajul; renamed and rewritten |
| Treaty of Jaffa | 32.0533, 34.75 (Jaffa) | 31.4669, 34.4064 | Jaffa was *Frederick's* camp; the two never met |
| Frederick's coronation | 31.7683, 35.2137 (generic) | 31.7784, 35.2296 | the Church of the Holy Sepulchre itself |
| the sultan's death | 33.5138, 36.2765 (generic) | 33.5111, 36.3014 | he died inside the citadel |
| the burial | 33.5117, 36.3053 (Umayyad Mosque) | 33.5111, 36.3014 | he was buried **in the citadel**, not the mosque |
| both Acre stops | 32.9281, 35.0818 | 32.9236, 35.0686 | old city / port, not modern Acre inland |

Verified and left alone: Cairo, Cairo Citadel, Kamiliyya (Jamaliyya quarter), Harran, Damietta and the siege camp, Fariskur (31°19′51″N 31°42′58″E), al-Mansurah, Jerusalem (walls stop), Damascus, Umayyad Mosque (nudged to 33.5114/36.3067), Amid/Diyarbakır, Jazira frontier (deliberately generic, and 36.2/40.0 does sit inside the Jazira).

### Quotes — 4 checked, 2 repaired, 1 added

1. **Francis's farewell.** Restored to the canon's actual wording: *"Pray for me, that God may deign to reveal to me the law and the faith which is more pleasing to Him"* (Jacques de Vitry, *Historia occidentalis*, the earliest witness). The file carried "that law and faith which is most pleasing."
2. **Oliver of Paderborn on the provisioning.** Verified **verbatim**, no change.
3. **Ibn Wasil on the Jaffa terms.** Verified against the Gabrieli translation; wording and the attribution to al-Kamil's own self-justification both stand.
4. **Added, and it is the find of this pass.** Ibn Wasil carries Frederick's rebuke to the qadi in direct speech, and the coronation stop was sitting on it with a null quote: *"You committed an error in what you did. By God, the greatest of my aims in staying overnight in Jerusalem was to hear the muezzins making the call to prayer and glorifying God in the night."* Checked against the Arabic-chronicle tradition — the qadi silenced the muezzins **of his own esteem for his guest**, which is what the campa already said and what Ibn Wasil actually reports.

### Other factual corrections

- **The 1234 Kayqubad campaign.** The campa claimed he answered the rout "not with a second army but with envoys." Not so: he had taken Kharput first, and he **recovered Urfa within four months** before the envoys. Both added; the defeat is not softened.
- **The Jaffa terms.** "Off-limits to Frankish worship" overstated the clause; the Haram stayed under Muslim law, garrison and qadi, which is what the treaty says.
- **The death campa** was thin ("the ordinary exhaustion of long rule"). The canon is far better and was simply unused: the cough, the flux, the old gout, and above all that he was carried to a small room of the **Dar al-Qasaba — the same room in which Salah al-Din had died forty-five years before.** That is now the stop's hinge.

### Could not confirm

- **The exact death date.** Latin/English scholarship gives **6 March 1238**; the Arabic tradition gives the night of Thursday **22 Rajab 635**, which converts nearer 8–10 March. Kept 6 March as the widely carried date, with the burial the day after. Flagged, not resolved.
- **The star-tent.** Frederick's celebrated "planetarium" tent is the one place this file risks a conflation: a magnificent planetarium bearing sun and moon was sent by **al-Ashraf in 1232**, and Frederick's star-tent is elsewhere dated to his 1229 return. The stop stays at 1228 with `traditional` confidence, which is the honest register for a gift the chronicles remember better than they date. Not corrected — flagged.
- **Al-Kamil's tomb today.** The chronicle says buried in the citadel; no surviving marked tomb was confirmed.

### Canon fidelity

Nothing mythic removed. The trial by fire, the refusal to harm Francis, the farewell prayer, the star-tent, the muezzin anecdote, the opening of the Nile dams, and the sultan dying in Saladin's room all stand as the canon carries them. Only geography, dates and one over-reaching sentence were touched.

### Stops whose Spanish twin is now stale (positions preserved, text changed)

Segment 1 stop 2 (Acre knighting); segment 3 stop 3 (al-Mu'azzam's ride); segment 5 stop 3 (death of al-Mu'azzam); segment 6 stop 4 (Frederick at Acre); segment 7 stops 1, 2, 3 (Tall al-Ajul ×2, the coronation — **name, coords and campa all changed; stop 3 gains a quote**); segment 7 stop 4 (sermon, coords only); segment 8 stop 4 (Harran/Kayqubad), stops 7 and 8 (death and burial).
