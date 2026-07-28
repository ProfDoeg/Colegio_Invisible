# Yolande of Aragon — Zaragoza to Saumur: research report

**Dataset:** `yolande_aragon.journey.json` — 8 segments, 35 stops, 1381-08-11 to 1471-01-01 (Julian), 1 stop carrying her attested words (the rest honestly null — almost nothing of Yolande's own voice survives outside one chronicled sentence).

## Sources
Primary modern biography: **Zita Eva Rohr, *Yolande of Aragon (1381–1442): Family and Power — The Reverse of the Tapestry*** (2016), the standard scholarly life. Cross-checked against Wikipedia/Grokipedia entries for Yolande, Louis II, Louis III, Marie of Anjou, René of Anjou, Charles IV of Anjou, the Compromise of Caspe, and the Cabochien Revolt; The Monstrous Regiment of Women and Unofficial Royalty (popular-scholarly blogs citing Rohr and the chronicle sources); *jeanne-darc.info* and Encyclopedia.com for the Marie Robine prophecy; the French Wikipedia and *lesportesdutemps.com* for the 1433 Chinon coup against La Trémoille. For the shared ground: `joan_of_arc.journey.json`, `pica_bourlemont.journey.json`, `pierre_bourlemont.journey.json`, `mary_magdalene.journey.json`, and `bourlemont_roster.md`.

## Judgment calls
- **The "we have not nurtured this one" refusal** is preserved only through the 16th-century Angevin chronicler Jehan de Bourdigné, not a contemporary document — used as the dataset's one quote, dated *traditional* to 1417 (after Louis II's death and Charles's elevation to dauphin), with the chronicle attribution stated plainly in `quote_source` rather than passed off as verbatim eyewitness record.
- **Louis XI's "a man's heart in a woman's body"** is a later remark *about* Yolande, not *by* her — kept out of the `quote` field on schema grounds (traveler's own words only) and narrated instead inside the Saumur/Margaret campa as reported fact.
- **The Poitiers vs. Tours location of the virginity examination**: scholarship is genuinely split (Poitiers Conclusions vs. a separate Tours physical exam). Per the curator's brief this dataset places it at Poitiers, pin-identical to `joan_of_arc`'s Poitiers stop, since the popular/mythic register (and several secondary sources) keep both examinations together there.
- **Several dates are necessarily approximate** ("traditional," month/day set to `-01-01` or a reasonable placeholder): the 1390 betrothal, the Aix court years, the Marie Robine "kept current" stop (no single dateable event — a standing practice rendered as one), and the Saumur retreat years. All marked accordingly.
- **Chronological folding**: the Bulgneville/captivity of René (1431) and the Chinon coup against La Trémoille (1433) are narrated as news reaching Yolande at Angers/Chinon rather than as her own travel, matching the established convention (seen in `joan_of_arc`'s Tournai letter, pinned at Gien) of anchoring a stop to the traveler's own location, not the event's.

## Gaps
No primary-source personal letters of Yolande's own survive in accessible translation beyond the Bourdigné-transmitted refusal; her interior life is reconstructed entirely through action (regencies, marriages arranged, armies funded, coups timed) rather than her own words — which is itself the argument of Rohr's subtitle, "the reverse of the tapestry."

## Five richest episodes
1. **Angers, 1417** — the refusal to Isabeau, the one line of her own voice the canon kept.
2. **Poitiers, March 1429** — the matrons' examination, the gate through the witchcraft charge.
3. **Chinon, 6 March 1429** — the audience her sixteen years of court-building made possible.
4. **Reims, 17 July 1429** — the coronation achieved entirely by proxy; she waits at Angers for the letter.
5. **Chinon, 3 June 1433** — the coup against La Trémoille, the kingmaker closing her own hand.

## Connections across the atlas
Pin-identical with `joan_of_arc.journey.json` at Chinon, Poitiers, Tours, and Blois (both datasets' matrons/audience/financing stops share exact coordinates). Pin-identical with `pica_bourlemont.journey.json` and `mary_magdalene.journey.json` at Tarascon (43.8058, 4.6548), tying the Anjou-Provence court's Sainte-Marthe cult to the Bourlémont Provençal branch. The Bar thread runs through `bourlemont_roster.md`'s 1334 aveu (Jean de Bourlémont to Édouard I, comte de Bar) into René's 1419 adoption as heir of Bar — the same county that held Domrémy in vassalage, closing a loop the curator asked for explicitly: Yolande's mother Violant de Bar, her son René's inheritance, and the ground under Joan's own childhood are one continuous fief.

## Verification pass — 2026-07-14

Structure and canon-fidelity check by a second agent. `json_check.py` clean before and after repairs: 8 segments, 35 stops, 1 quoted; chronology, key lint, campa word counts, and quote/quote_source pairing all pass. 35 stops sits inside the 30-45 target and the arc covers the canon fully, so no stops were added.

**Cross-pins re-verified.** Chinon (47.1682, 0.2367), Poitiers (46.5813, 0.3453), Tours (47.3936, 0.6892), and Blois (47.5866, 1.3288) are byte-identical — coordinates AND dates — with `joan_of_arc.journey.json`. Tarascon (43.8058, 4.6548) matches the Magdalene/Bourlémont pins.

**Coordinates spot-checked (13 sites) — 3 pins fixed:**
- Zaragoza/Aljafería (both stops): was 41.658, -0.915 (~1.5 km west of the palace); fixed to 41.6565, -0.8971 (the Aljafería itself).
- Foixà: was 41.968, 2.958 (~7 km south of the village); fixed to 42.0325, 2.9903 (the castle hill in the Baix Empordà).
- Verified good as-is: Arles/Saint-Trophime, Angers château, Aix, Paris, Bar-le-Duc, Saumur, and the five cross-pins above.

**Quote checked against canon.** The Bourdigné refusal-to-Isabeau matches the standard English rendering (Wikipedia / Monstrous Regiment of Women / Rohr-derived) except one stray comma; wording aligned exactly: "...make him die like his brothers or to go mad like his father, or to become English like you." Attribution honestly marked as chronicle-transmitted. Only one quote in the dataset, consistent with the researcher's finding that almost nothing of her voice survives.

**Confidence honesty — 2 downgrades.** The Provence-regency stop (1411-06-01) and the Bar adoption stop (1419-01-01) both carried placeholder month/days yet were marked `attested`; downgraded to `traditional` to match the file's own convention. All other placeholder-day stops were already `traditional`.

**Dates fact-checked, all sound:** birth 11 Aug 1381, Juan I's death at Foixà 19 May 1396, Arles marriage 2 Dec 1400, the five births (1403-1414), Caspe 28 Jun 1412, Cabochien seizure Apr 1413, betrothal Dec 1413, Louis II's death 29 Apr 1417, Richemont 7 Mar 1425, the 1429 sequence (pin-dated to Joan's file), Bulgnéville 2 Jul 1431, La Trémoille coup Jun 1433, death at Saumur 14 Nov 1442, René coda at Aix 1471 (traditional). Traveler deceased; journey correctly ends at death + coda, not the present.

**Canon fidelity.** The mythic register is intact: the Marie Robine / Bois Chenu prophecy stop stands as the court's living belief, the Tarasque and Sainte-Marthe lore carried without debunking, the "queen of four kingdoms" paradox threaded as the file's spine. Nothing was flattened.
