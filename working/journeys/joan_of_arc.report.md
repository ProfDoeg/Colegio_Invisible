# Joan of Arc — Domrémy to Rouen: research report

**Dataset:** `joan_of_arc.journey.json` — 8 segments, 54 stops, 1424-08-15 to 1431-05-30 (Julian), 45 stops carrying her attested words.

## Sources
Primary canon: the **trial of condemnation** (Rouen, Feb–May 1431; notaries' minute, ed. Quicherat/Champion, trans. Barrett) and the **rehabilitation trial** (1456; testimonies of Dunois, Alençon, d'Aulon, Pasquerel, Jean de Metz, Poulengy, Marguerite La Touroulde, Massieu, Ladvenu, Isambart, the Domrémy villagers). Chronicles: *Journal du siège d'Orléans*, Perceval de Cagny, Gruel's *Chronique de Richemont*, Wavrin, the *Bourgeois de Paris*. Her surviving letters (to the English, Tournai, Riom, Reims, the Hussites). Modern scaffolding for dates/geography: Pernoud & Clin, jeanne-darc.info chronology, famous-trials.com, stejeannedarc.net, Société Historique de Compiègne, and French local-heritage pages for the captivity castles (all cross-checked by web search).

## Judgment calls
- **First voice dated 1424** per the brief; the trial says "when I was thirteen," which strict reckoning from a January 1412 birth puts in 1425 — marked *traditional*, placed at a summer noon per her own testimony.
- **Departure from Vaucouleurs 23 Feb / arrival Chinon 6 March**: sources split between 12/13, 22 and 23 February; I follow the majority modern chronology (23 Feb → 6 Mar, eleven nights).
- **Beaurevoir leap dated 1430-08-15, *inferred***: scholarship splits between "shortly after arrival" (July) and "when she learned of the sale/threat to Compiègne" (autumn); I placed it mid-stay and flagged it.
- **Compiègne "sold and betrayed" speech to the children of Saint-Jacques** comes from a 1498 local inquiry, not 1431/1456 records — kept in the campa as the town's memory, not as her quote; the quote used is Cagny's rearguard cry.
- Trial cell/chapel/robing-room stops share the castle site with jittered coordinates so they render as distinct stops.
- Segment count forced one merge: captivity route and trial share the final segment, "The Captivity Road and the Fire."

## Gaps in the canon
Exact ride-route stops between Saint-Urbain and Auxerre (nights unrecorded); the Poitiers register itself is lost (only the Conclusions survive); precise dates at Tours/Blois, Bourges arrival, Arras and Le Crotoy are itinerary reconstructions; nothing survives of her words at Meung, Le Crotoy, or the Rouen arrival — those quotes are honestly null.

## Five richest episodes
1. **Chinon, 6 March 1429** — the recognition through the crowd of 300 and the secret sign.
2. **Les Tourelles, 7 May 1429** — the foretold wound, the vineyard prayer, the standard touching the wall.
3. **Melun, Easter week 1430** — the voices announce the capture before St. John's Day; she rides north anyway.
4. **Beaurevoir** — the three Jeannes of Luxembourg and the sixty-foot leap survived unbroken.
5. **Rouen, 24 Feb & 30 May 1431** — the grace-of-God answer that stupefied the court, and the stake with the unburned heart.

## verification

Verified 2026-07-04 (structure and canon-fidelity pass; the canon stands, only placement/dating/form checked).

**Structure.** JSON parses; all 54 stops carry the exact 10-key shape (name, lat, lng, date, date_confidence, campa, quote, quote_source, sources, suggested_refs); quote/quote_source always null together (9 honest nulls confirmed); calendar `julian`; dates strictly increasing across all 8 segments, 1424-08-15 → 1431-05-30. Stop count 54 sits inside the 35-55 target — no additions needed.

**Coordinates.** Ten sites spot-checked against the web (Domrémy garden, Saint-Urbain, Fierbois, Les Tourelles, Patay, Margny, Beaulieu-lès-Fontaines, Beaurevoir, Le Crotoy, Vieux-Marché). Four fixed in place:
- Abbey of Saint-Urbain: 48.465,5.096 → 48.4014,5.1831 (was ~10 km off; abbey is at Saint-Urbain-Maconcourt, Haute-Marne)
- Sainte-Catherine-de-Fierbois: 47.1494,0.655 → 47.157,0.6545 (village/church center, was ~0.9 km south)
- Beaulieu-lès-Fontaines: 49.639,2.92 → 49.6608,2.9133 (village with the castle keep, was ~2.5 km off)
- Beaurevoir: 49.998,3.309 → 49.9927,3.3019 (the surviving Tour Jeanne d'Arc southwest of the village — the tower of the leap, not the village center)
All others confirmed correct (Margny at the bridgehead, Tourelles at the south bank of the old bridge, Rouen trial stops on the Bouvreuil site, Vieux-Marché at the pyre garden).

**Quotes.** Six verified verbatim-faithful against the canon by web check: the grace-of-God answer (condemnation trial, 24 Feb 1431); Jean de Metz's "wear my legs down to the knees / rather spin beside my poor mother" (1456); Alençon's Patay "though they hung from the clouds" (1456); Dunois's Crépy "here is a good people... buried in this soil" (1456); the Melun Easter-week capture prophecy (trial, 10 March 1431); Massieu's "Ah, Rouen, I greatly fear you may have to suffer for my death." The remainder read as recognizable canon (trial minute, rehabilitation depositions, her letters, Cagny/Gruel); none needed moving to campa or nulling.

**campa.** All present tense, mythic-national register; the great episodes (Chinon recognition, Tourelles, the leap, the grace answer, the stake) carry their full weight. Six stops ran 111-116 words; trimmed surgically to ≤110 (Reims, Beaurevoir, first session, Saint-Ouen abjuration, relapse, the stake) without losing any canonical detail.

**Re-validation.** Full python pass after repairs: schema, ordering, word counts, coordinate types — zero problems.
