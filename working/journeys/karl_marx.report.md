# Karl Marx — report

**Dataset:** `karl_marx.journey.json` — 8 segments, 45 stops, 33 quoted. Calendar gregorian, 1818-1883.

## Sources
Spine: MECW/MEGA (letters, prefaces, trial speeches, the NRZ), Engels's memoirs and graveside speech, Jenny Marx's *Short Sketch of an Eventful Life*, and the standard biographies (Mehring, McLellan, Wheen, Gabriel's *Love and Capital*, Stedman Jones, Musto's *The Last Years*). Web verification in German/French/Dutch for the physical geography: the Brussels addresses (Persée's "Ixelles dans la vie et l'œuvre de Karl Marx", heritage.brussels, reflexcity.net — Bois Sauvage, rue de l'Alliance 5, rue d'Orléans 42/Jean d'Ardenne 50, the Amigo), rue Vaneau 23/38, the Hague Concordia and the Amsterdam Sarphatistraat hall (onsamsterdam.nl), Karlsbad's Hotel Germania (Kisch), Algiers' Pension Victoria (Musto, lesvraisvoyageurs), Ventnor's 1 St Boniface Gardens (town council), Hamburg/Meissner (marx200.org).

## Judgment calls
- **Curator's route honored**: Trier → Bonn/Berlin → Paris → Brussels → Cologne → London, with the real side-journeys that canon attests (Manchester 1845, Hamburg 1867, Hague/Amsterdam 1872, Karlsbad, Algiers, Ventnor). Dropped the real-but-peripheral Vienna/Berlin fundraising trip of Aug-Sep 1848 to stay inside 45 stops.
- The Jena doctorate arrived **in absentia**, so it is placed at Hippel's wine-cellar in Berlin (where the life actually happened), not in Jena.
- Quotes are Marx's own recorded words only; Engels's great lines ("agreement in all theoretical fields", "the Moor is dead", the graveside speech) are narrated in campa, never put in the quote field. The one soft quote is the attributed last words to Lenchen, sourced as "as the tradition tells it" — the register permits canon.
- Freddy Demuth is named at Dean Street without adjudicating paternity; the canon of the household records the birth and the carrying-away.

## Gaps and time-folds
- Ventnor stop folds the whole homeward arc of 1882 (Monte Carlo, Argenteuil, Enghien, Vevey) into its opening clause — four real waypoints compressed to keep the stop budget.
- Dean Street is one stop carrying six years and three children's deaths; Grafton Terrace similarly folds Grundrisse → 1859 *Critique*.
- Exact arrival days in Paris (Oct 1843) and Brussels (Feb 1845) are month-attested only; marked `inferred`.

## Five richest episodes
1. **Stralau, 1837** — the convalescent conversion to Hegel, told in the all-night letter to his father ("a curtain had fallen").
2. **Ixelles, January 1848** — the Manifesto written against the League's Feb-1 ultimatum, the book and the revolution appearing the same week; then the midnight arrest at the Bois Sauvage and Jenny's night in the Amigo.
3. **The red number, Cologne, 19 May 1849** — a newspaper dying in red ink, Freiligrath's farewell, 20,000 copies fought over at the press.
4. **Hamburg, April 1867** — the Book carried across a storm-whipped North Sea in his own hands to Meissner's door: "the most terrible missile."
5. **Algiers, April 1882** — the last photograph, then the prophet's beard offered "on the altar of an Algerian barber."

## Connections in the atlas
Marx is the atlas's great counter-pilgrim: his Italian Journey runs north, from vineyards to fog. He walks Goethe's Germany two generations on (the abitur essay is pure Bildung), shares the exile-editor's arc with the libertadores (Bolívar's Jamaica letter ↔ the Brussels pledge), the expulsion-chain itinerary with Blavatsky and Gurdjieff, and the reading-room-as-shrine with every scholar-saint in the corpus — his Bois Chenu is the Round Reading Room. Joan hears voices toward the church; Marx, at Stralau, hears the idea in the real itself. Highgate closes the loop as the corpus's other prophesied grave.

## Verification pass — 2026-07-12

Structure and canon-fidelity check against the Goethe schema (joan_of_arc.journey.json as reference). json_check.py clean before and after repair: 8 segments, 45 stops, 33 quoted; top-level and per-stop keys identical to the Joan reference; campa 93-104 words, all present tense, in register; chronology strictly ordered 1818-05-05 → 1883-03-17 (dead traveler ends at the grave); confidences honest (attested/traditional/inferred — the Westphalen walks, the Karzer/duel and the secret betrothal correctly carry `traditional`). Stop count 45 = top of target; nothing added.

### Quotes (6+ spot-checked against the canon)
- **Exact as attested**: Prometheus foreword; Becker "most terrible missile" (17 Apr 1867); Amsterdam 1872 "peaceful means" (La Liberté/MECW); free-press "ubiquitous vigilant eye"; plus the load-bearing famous ones (spectre, opium, eleventh thesis, emancipation-by-the-classes-themselves, hand-mill, frontier posts, curtain-fallen) all match MECW wording.
- **Restored to canon (2)**:
  - Westphalen dedication: "the living proof … the truth" → "were always a living argumentum ad oculos to me, that idealism is no figment of the imagination, but a truth" (dissertation dedication, 1841).
  - League split speech: paraphrase blend → the Revelations wording: "You will have to go through 15, 20, 50 years of civil wars and national struggles not only to bring about a change in society but also to change yourselves, and prepare yourselves for the exercise of political power"; quote_source now credits Revelations Concerning the Communist Trial in Cologne as the carrier (the bare 15 Sept 1850 minutes carry a shorter variant).
- The traditional last words ("Last words are for fools…") stay, flagged as tradition in quote_source — canon kept, not debunked.

### Coordinates (12+ web-spot-checked; 8 fixed)
Confirmed correct: Trier (Brückergasse, Porta Nigra, Gymnasium), Bonn, Unter den Linden, Stralau, Hippel's/Friedrichstraße, Cologne, rue Vaneau, Café de la Régence, Bois Sauvage/Ste-Gudule, Amigo, Chetham's, Grand-Place Cygne, Dean St, British Museum, Great Windmill St, St Martin's Hall, Hamburg Bergstraße, rue de Lille, Karlsbad Schlossberg, Algiers Mustapha Supérieur (within El Mouradia bbox), Highgate, Amsterdam Sarphatistraat (west end).

Fixed (geocoded via OSM/Nominatim):
| stop | was | now | error |
|---|---|---|---|
| Pauluskirche, Bad Kreuznach | 49.8444, 7.8654 | 49.8443, 7.8568 | ~620 m |
| rue de l'Alliance 5, St-Josse | 50.8530, 4.3688 | 50.8505, 4.3702 | ~290 m |
| rue d'Orléans 42 (Jean d'Ardenne 50), Ixelles | 50.8341, 4.3688 | 50.8320, 4.3622 | ~520 m |
| Ixelles — Manifesto | 50.8342, 4.3690 | 50.8321, 4.3624 | ~520 m |
| Anderson St, Chelsea | 51.4900, -0.1600 | 51.4906, -0.1624 | ~180 m |
| 9 Grafton Terrace | 51.5482, -0.1505 | 51.5497, -0.1551 | ~360 m |
| 1 Modena Villas / 41 Maitland Park Rd (×3 stops) | 51.5445-49, -0.1528/-0.1540 | 51.5479-82, -0.1553/-0.1556 | ~400 m |
| Concordia hall, Lombardstraat, The Hague | 52.0772, 4.3090 | 52.0753, 4.3038 | ~430 m |
| 1 St Boniface Gardens, Ventnor (PO38 1PW) | 50.5972, -1.2102 | 50.5982, -1.1974 | ~900 m |

Re-validated after repair: json_check.py OK, no WARNs. Dataset verified.
