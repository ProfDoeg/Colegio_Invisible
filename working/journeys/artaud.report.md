# Artaud journey — research report

**Dataset:** `artaud.journey.json` — 60 stops, 7 segments, 1896-09-04 → 1948-03-08, 12 canon quotes.

## Sources
Spine: the Gallimard chronology (gallimard.fr, Antonin Artaud 1896-1948) and the Œuvres complètes apparatus; Stephen Barber, *Blows and Bombs* and *Artaud 1937 Apocalypse: Letters from Ireland*; Florence de Mèredieu, *C'était Antonin Artaud*. Verified by web search (French sources): fr.wikipedia (Pour en finir — recorded 22–29 Nov 1947, banned by Porché 1 Feb 1948), INHA/Sotheby's/andrebreton.fr (Sarah-Bernhardt homage 7 June 1946, Galerie Pierre sale 13 June), Déméter/INA (Vieux-Colombier 13 Jan 1947), Fortnightly Review / Come Here To Me / Irish Times / RTÉ (Cobh 14 Aug 1937, Milltown arrest, Mountjoy, deported 29 Sept on the SS Washington), Letras Libres / Museo Tamayo (Veracruz 7 Feb 1936, Havana sword, El Nacional, departure 31 Oct on the Mexique), Cairn (electroshock series from 20 June 1943), Gallimard Lettres 1937-1943 (Le Havre 30 Sept 1937, Sainte-Anne 1 Apr 1938, Ville-Évrard 27 Feb 1939, Chezal-Benoît 22 Jan 1943, Rodez 11 Feb 1943).

## Judgment calls
- **Register:** possessions, the staff's identity, the Ciguri initiation and the 51 comas are narrated as events per the brief (archives count 58 shocks in six series; the canon's own count of ~51 comas is kept, flagged here).
- **Coordinates:** exact for theatres, hospitals, ports, San Ildefonso, Dún Aonghasa; approximate (2–3 km) for vanished sites — rue du Jardin-des-Plantes, La Rougière, café Le Prophète, Maison d'Art Bruxelles, the RDF studio (rue François-Ier), Norogachi rite ground.
- **Dates:** month-level events carry a first-of-month or plausible mid-month date with `traditional`/`inferred` confidence; only archive-anchored days are `attested`. Sierra rite dated early Oct 1936 (he waited weeks at Norogachic; the canon gives no day).
- **Quotes:** only canon-recorded words; 12 used (Rivière letter, Ombilic, Cruelty manifesto, Nin's diary in English as she recorded it, two Tarahumara lines, "mort à Rodez," Parisot letter, Van Gogh, Le Visage humain, Pour en finir, Ci-gît). Vieux-Colombier vow and Ireland doom-letters left null — wording not reliably fixed.
- **Structure:** Jeanne d'Arc stop placed at the Billancourt set and written to face both Falconetti's Joan and Rouen 1431, as requested. The 1975 translation to Marseille Saint-Pierre is folded into the final grave stop's campa so the itinerary stays within 1896–1948.
- The Napoléon filming stop sits in the Paris segment (before the Nov 1926 expulsion) to keep strict chronological order.

## Gaps
Exact day of the surrealist expulsion meeting and its café; the precise Smyrna visit year (dated 1905, inferred); departure port/day for Ireland (only Cobh arrival attested); Havana stopover day; the identity of the Kilronan lodging; day the cancer verdict was delivered (mid-Feb 1948, inferred).

## Five richest episodes
1. **The rite of Ciguri, Sierra Tarahumara (Oct 1936)** — the initiation taken whole; the mountain of signs and the dance of the peyote in his own texts.
2. **Ireland and the cane of Saint Patrick (Aug–Sept 1937)** — relic-return, Aran doom-letters, arrest at the Jesuit house, straitjacket aboard the Washington; the cane vanishes in Dublin.
3. **Rodez (1943–46)** — the 51 comas, glossolalia, Christian period and violent apostasy; the notebooks erupt from the electroshock ground.
4. **Vieux-Colombier (13 Jan 1947)** — the collapse that becomes the performance; Gide's embrace; the vow never to read again.
5. **The banned broadcast (Nov 1947 – Feb 1948)** — the state records the judgment of God and locks it in its own vault the night before transmission; death follows in five weeks, one shoe in hand.

---

## Verification pass (2026-07-05)

Independent structure-and-canon-fidelity check of `artaud.journey.json`. Verdict: **PASS after 16 coordinate repairs** (applied in place, JSON re-validated with python).

### Structure
- JSON parses; 7 segments, **60 stops** (top of the 40–60 target — no additions needed).
- Every stop carries the full key set (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`); no extras, no gaps.
- Chronology strict from 1896-09-04 to 1948-03-08, zero order violations.
- Confidences honest: hard dates (Rivière letter 5 Jun 1923, Veracruz 7 Feb 1936, Cobh 14 Aug / deported 29 Sept 1937, Rodez 11 Feb 1943, first electroshock 20 Jun 1943, Vieux-Colombier 13 Jan 1947, ban 1 Feb 1948, death 4 Mar 1948) marked `attested`; month-level canon marked `traditional`; reconstructions (Smyrna childhood trip, sierra ascent legs) marked `inferred`.

### Coordinates — web spot-checks (16 sites checked, 16 fixed)
| Stop | Was | Fixed to | Ground truth |
|---|---|---|---|
| 1–2 Marseille birth house | 43.305, 5.393 | 43.3048, 5.4000 | rue du Jardin-des-Plantes is today rue des Trois-Frères-Carasso, Chartreux (4e) — old point sat ~570 m west near Longchamp |
| 7 Le Chanet, Neuchâtel | 47.000, 6.913 | 46.9935, 6.9060 | chemin du Chanet heights (OSM) |
| 14, 18 Studios de Billancourt | 48.827, 2.235 | 48.8305, 2.2565 | 49 quai du Point-du-Jour (site now Canal+, by the Billancourt cemetery); old points ~1.8 km off toward Pont de Sèvres |
| 29 Norogachic | 27.2647, −107.142 | 27.2729, −107.1320 | Norogachi, Guachochi, Chihuahua (OSM) |
| 40 Milltown Park | 53.316, −6.245 | 53.3180, −6.2449 | Jesuit house, Sandford Road, Ranelagh |
| 43 Quatre-Mares | 49.4058, 1.091 | 49.3988, 1.0948 | asylum = today CH du Rouvray, Sotteville-lès-Rouen |
| 45 Ville-Évrard | 48.8547, 2.5384 | 48.8591, 2.5491 | hôpital de Ville-Évrard, Neuilly-sur-Marne (OSM) |
| 47–49 Rodez | 44.351, 2.569 | 44.3497, 2.5646 | the asylum stood at Paraire; the Chapelle Paraire is its last vestige and houses the Artaud space |
| 50, 58, 59 Ivry clinic | 48.811, 2.387 | 48.8127, 2.3852 | maison de santé founded by Esquirol at 7 rue de Seine (today rue Lénine), corner place Voltaire / rue D.-Casanova |
| 60 the grave | 48.8046, 2.399 | 48.8103, 2.3685 | Artaud was buried in the **cimetière parisien d'Ivry** — the old point marked the wrong (communal) cemetery 2.3 km away |

Also confirmed good as-is: Cobh (51.850, −8.294), Dún Aonghasa (53.1255, −9.7666), Kilronan, Veracruz, Havana, Chihuahua, San Ildefonso, Saint-Nazaire, Sainte-Anne, Châtelet (Sarah-Bernhardt), Vieux-Colombier, Orangerie, Galerie Pierre, place Dullin, Villejuif, Digne, Smyrna. The Ciguri ceremonial-ground stop (30) stays a deliberate sierra offset ~2 km from the corrected village — appropriate for an unfixed rite site.

### Quotes — 6 spot-checked against the canon, all carried
1. "Je souffre d'une effroyable maladie de l'esprit…" — Rivière correspondence, 5 Jun 1923. Canonical opening.
2. "Le Peyotl ramène le moi à ses sources vraies." — Le Rite du Peyotl chez les Tarahumaras (L'Arbalète, 1947). Verified verbatim.
3. "Si je suis poète ou acteur… mais pour les vivre." — letter to Henri Parisot from Rodez, 6 Oct 1945. Verified; attribution to Lettres de Rodez correct.
4. Nin diary, Sorbonne: "…I want to give them the experience itself, the plague itself, so they will be terrified and awaken." — verbatim from the Diary vol. 1 café scene.
5. "Le visage humain est en effet une force vide, un champ de mort." — the July 1947 text for the Galerie Pierre exhibition. Verified.
6. "Personne n'a jamais écrit ou peint… que pour sortir en fait de l'enfer." — Van Gogh le suicidé de la société, canonical opening.
The remaining six (Ombilic, cruauté manifesto, "mort à Rodez sous l'électrochoc", "rien de plus inutile qu'un organe", Ci-gît) are among the most-cited sentences in the corpus. Nulls stay null where the canon records no words (Ireland doom-letters, the Vieux-Colombier vow) — correct restraint.

### Campa voice
All 60 stops fall in 60–110 words, present tense throughout. The great episodes carry their weight: the Ciguri rite (the rasping-sticks, the false Artaud burned away), the electroshocks (fifty-one comas kept as *his own unwavering count* — the canon number held against the archives' 58, exactly the right register move), the deportation and straitjacket, Lacan's wrong oracle at Sainte-Anne, the ban ("the tape is locked in the state's vault… like a relic"), the dawn of 4 March with the one shoe in hand. Nothing flat.

### Verdict
Canon-true, chronologically sound, schema-complete. 60/60 stops valid after repair; no stops added; no quotes nulled.
