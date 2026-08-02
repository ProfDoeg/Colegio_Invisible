# Atlas network survey - generated
*153 journeys | 6056 stops | 6056 located*

## A. Interlock: asymmetric gazes (A names B, B silent)
*1067 asymmetric pairs*

- **maimonides** names moses 35x, no return gaze
- **elsa_lindenberg** names reich 34x, no return gaze
- **zoroaster** names muhammad 27x, no return gaze
- **charlemagne** names alexander 24x, no return gaze
- **charlemagne** names cyrus 24x, no return gaze
- **marco_polo** names genghis_khan 20x, no return gaze
- **steiner** names goethe_full 19x, no return gaze
- **cortes** names lady-of-the-lake 18x, no return gaze
- **tolkien** names alexander 18x, no return gaze
- **tolkien** names cyrus 18x, no return gaze
- **jesus** names alexander 17x, no return gaze
- **jesus** names cyrus 17x, no return gaze

## B. Pin drift: same event, non-identical pins
*94 same-date pairs violating the byte-identical rule*

- 9m **eva_peron** (-34.6021,-58.3689) vs **juan_peron** (-34.6021,-58.369) [1944-01-22] - Luna Park, el festival, y el asiento junto a
- 9m **jesus** (31.7785,35.2295) vs **mary_magdalene** (31.7785,35.2296) [0033-04-05] - The Garden Tomb, the empty tomb, Easter morn
- 9m **jesus** (31.7785,35.2296) vs **mary_magdalene** (31.7785,35.2295) [0033-04-05] - The Garden, the risen Lord to Mary Magdalene
- 17m **heisenberg** (55.699,12.566) vs **niels_bohr** (55.6989,12.5658) [1927-02-01] - Copenhagen, the paper while Bohr is skiing
- 19m **al_kamil** (31.7784,35.2296) vs **joffrey_bourlemont** (31.7784,35.2298) [1229-03-18] - Jerusalem, Frederick crowns himself, word re
- 28m **nietzsche** (51.15,11.813) vs **steiner** (51.15,11.8126) [1896-01-25] - Naumburg, Steiner in the sickroom
- 30m **jesus** (31.7784,35.2298) vs **mary_magdalene** (31.7785,35.2295) [0033-04-03] - Golgotha, the Crucifixion
- 30m **jesus** (31.7785,35.2295) vs **mary_magdalene** (31.7784,35.2298) [0033-04-03] - The Tomb of Joseph of Arimathea, the burial
- 33m **alvear** (-34.608,-58.372) vs **san_martin** (-34.6083,-58.372) [1812-10-08] - Plaza de la Victoria: la revolución del 8 de
- 35m **aeneas** (36.8528,10.3233) vs **dido** (36.853,10.3236) [-1182-06-13] - Carthage rising, the murals of Troy on Juno'
- 35m **aeneas** (36.853,10.3236) vs **dido** (36.8528,10.3233) [-1182-06-13] - Dido's hall, the banquet and Cupid in Ascani
- 37m **arthur-lotharingia** (47.4818,7.6104) vs **parzival** (47.482,7.61) [0842-09-21] - Cundrie's Curse and the Call to Chastel Marv

## C. Canonical pins (3+ journeys, byte-exact) - inherit these
- `(48.8566, 2.3522)` 18 journeys: blavatsky, delsarte, emin_arslan, francis_bacon, giordano_bruno
- `(41.9028, 12.4964)` 13 journeys: aristotle, bolivar, freud, giulio_camillo, guido_keller
- `(52.52, 13.405)` 10 journeys: blavatsky, charlotte_bara, elsa_lindenberg, guido_keller, gurdjieff
- `(51.5074, -0.1278)` 9 journeys: annie_besant, braille, isadora_duncan, laban, merlin
- `(40.4168, -3.7038)` 9 journeys: bolivar, borges, einstein, humboldt, miranda
- `(21.4225, 39.8262)` 8 journeys: abdelkader, abraham, aishah, attar, ibn_arabi
- `(-34.6037, -58.3816)` 8 journeys: borges, charly_garcia, che_guevara, emin_arslan, eva_peron
- `(39.8628, -4.0273)` 6 journeys: aristotle, eva_peron, hannibal, kyot-willehalm, pedro_de_mendoza

## D. Chronology
- **BCE time-navigation quirk**: 273 adjacent same-year stop pairs across 15 journeys. `datekey` negates the whole fractional year, so months invert inside one BCE year. NOTE: journey paths and the traveler list are NOT affected - stops draw in file order and the traveler sort was verified correct. This touches only the time scrubber and next/prev-in-time navigation. Low priority.
  - hannibal: 36
  - moses: 32
  - alexander: 26
  - aeneas: 24
  - ulysses: 23
  - sheba: 20
- **Genuine regressions**: 1
  - juan_peron: 1960-01-26 -> 1957-01-01

## E. House style
- em dashes in authored text: **325** (rule: none)
- `register` variants: **4** (should be 1)
  -   63x `national mythology, the canon is true`
  -   63x `national mythology: the canon is true`
  -   25x `national mythology — the canon is true`  <- EM DASH
  -    2x `national mythology; the canon is true`
- curly quotes: **0** (rule: zero)
- campa outside 450-650 chars: 164 short, 124 long (5% of stops)

## F. Quote deserts (corpus median ~12/journey)
- salomon_oppenheim: 0 quotes / 25 stops
- samuel_oppenheimer: 0 quotes / 26 stops
- falconetti: 1 quotes / 32 stops
- joffrey_bourlemont: 1 quotes / 43 stops
- yolande_aragon: 1 quotes / 35 stops
- braille: 2 quotes / 31 stops
- matteo_ricci: 2 quotes / 43 stops
- reich: 2 quotes / 49 stops
- valientes: 2 quotes / 34 stops
- vera_skoronel: 2 quotes / 34 stops

## G. Temporal deserts (>=50 empty years)
- -1638 -> -1391: 247 empty years
- 90 -> 287: 197 empty years
- -814 -> -629: 185 empty years
- -1174 -> -990: 184 empty years
- -530 -> -427: 103 empty years
- -1271 -> -1185: 86 empty years
- -931 -> -850: 81 empty years
- -321 -> -247: 74 empty years

## H. Geographic deserts (10deg cells held by one journey)
- (-90, 0): serrano
- (-80, 0): maria_orsic
- (-70, -70): serrano
- (-70, -60): serrano
- (-60, -70): juan_peron
- (-50, -70): juan_peron
- (-40, -150): dante
- (-40, 10): matteo_ricci
- (-30, 20): tolkien
- (-20, -10): napoleon
