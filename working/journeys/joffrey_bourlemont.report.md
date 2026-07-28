# Joffrey de Bourlémont — The Fire Carried Home: research report

**Dataset:** `joffrey_bourlemont.journey.json` — 7 segments, 43 stops, 1211-01-06 to 1456-01-28 (Julian), 1 quote (the 1248 charter, his only recorded words).

## Sources
In-universe canon: the five instagram essays (birth amid the fairy tide 2022-12-22; Greccio with Pierre 2023-01-25; Jerusalem 1227/Treaty/fifth station 2023-01-25; the seraph told on the Bethlehem walk 2023-01-25; Lois de Conte 2022-12-26; the 1456 fairy testimony 2024-09-27). Documentary graft: `bourlemont_roster.md` Gen. 5 — the attested Joffroy (charter of 28 May 1248 to Mureau, Luce *Preuves* Suppl. I; Poull/fr.wiki: c. 1210–†1268, sénéchal de Navarre of Thibaut IV, Holy Land return, castle rebuilt, wife Sibylle de Saulxures). History scaffolding by web search: Treaty of Jaffa (18 Feb 1229; Frederick crowned at the Sepulchre 18 March), Barons' Crusade (Marseille Aug 1239, Acre 1 Sept, Gaza disaster 13 Nov, the 1240 treaties, the rose of Provins in the helmet), fall of Jerusalem 1244 (Tower of David 23 Aug; La Forbie 17–18 Oct), Thibaut crowned Pamplona May 1234 / †Pamplona 8 July 1253, Children's Crusade (Stephen of Cloyes at Saint-Denis, Lendit 1212), the Franciscan fifth-station chapel ("a small Franciscan church established in 1229" — an outside source landing exactly on the canon's sentence).

## Pins shared with the atlas (byte-identical)
Greccio 42.4619, 12.751 (saint_francis, same night 1223-12-24); the fairy tree 48.4302, 5.6706 and the well 48.4295, 5.6699 (joan_of_arc's Tree of Bourlemont and Fontaine des Fiévreux); Domrémy Saint-Rémy 48.4436, 5.6748 and Neufchâteau 48.3554, 5.6942 (joan_of_arc); Bethlehem 31.7042, 35.2075, Holy Sepulchre 31.7784, 35.2298, Via Dolorosa fifth station 31.7794, 35.232 (jesus). Château de Bourlémont set at 48.3901, 5.6623 (Monumentum/GPS sources for the standing castle at Frebécourt) — **this is the pin pierre_bourlemont/pica_bourlemont should share**. La Verna is deliberately NOT a stop: the canon has Joffrey *hear* the seraph, on the Bethlehem road, never climb the mountain.

## Judgment calls & time-folds
- **Birth 1211-01-06**: canon says only "~1211," but Lois born 6 January "200 years after Joffrey" fixes the feast of the Kings — the birthday shared down the chain to Joan.
- **Greccio nights**: canon reads arrival Nochebuena → communion "por la mañana" → cave "esa noche." I put the crib on the night of the 24th (tradition + saint_francis alignment) and communion the morning of the 25th — a one-night fold of the essay's sentence order.
- **The 1244 return**: attested history has Thibaut home by late 1240; the canon has Joffrey return "in 1244 when Jerusalem fell." Reconciled by keeping him as seneschal in Pamplona 1240–44, where the news of the fall (a stop) sends him home — the canon's grief made itinerary.
- **"El anciano"** telling stories at ~44: taken at canon value; grief ages a man into the storyteller's office.
- **1456 vs the essay's "1455"**: trial opened Nov 1455; the Domrémy depositions ran Jan–Feb 1456 — dated 1456-01-28, attested.
- Death **1268-11-02**: year from Poull, day chosen (All Souls); burial place unrecorded — left unsaid rather than invented (Gen. 9's Franciscan burial at Neufchâteau belongs to a later Pierre).

## Gaps
No source records his route in 1227 (Marseille inferred), his crusade itinerary beyond the host's, or a single spoken sentence outside the charter — every quote but one is honestly null. The seneschalcy's dates are Poull's reconstruction; Estella/Provins stops are texture, marked inferred.

## Five richest episodes
1. **Greccio, Christmas 1223** — the boy holding his father's hand while heat pours off the praying cousin; the magi wearing Nizami's faces.
2. **Bethlehem, Christmas 1229** — the friars in the robes of the magi of Zoroaster above the very grotto, the seraph story still warm from the walk, and the unconfirmed rumor of the Virgin's dress.
3. **Jaffa/Jerusalem, spring 1229** — an eighteen-year-old watching peace signed instead of fought, then an excommunicate crowning himself at the Sepulchre.
4. **Mureau, 28 May 1248** — the one parchment where he speaks: *laude et assensu Sibille uxoris mee* — the plough-dues of Joan's own villages given under prayer.
5. **The well and the tower, 1245–1255** — a crusader translating war into bedtime stories, building the exact apparatus (tree, well, tower) that Joan's voices will later inhabit.

## Connections in the atlas
This is the missing span of the bridge: **saint_francis** (Greccio/La Verna, same pins) → **pierre_bourlemont/pica_bourlemont** (father and the friar's mother; shared castle pin) → **nizami** (the magi/Khamsa inheritance, twice invoked) → and forward two hundred years to **joan_of_arc** (tree, well, Bois Chenu — Joffrey builds the stage her canon opens on), with **bernard_clairvaux** and **molay** holding the neighboring crusade panels. The fire goes east from Greccio to Bethlehem and comes home to a beech tree on the road to Vaucouleurs.

## Verification pass — 2026-07-13

Independent structure/canon-fidelity check of `joffrey_bourlemont.journey.json` (verifier, not the researcher).

**json_check**: OK, no WARN lines, before and after repair — 7 segments, 43 stops (within the 30–45 target), 1 quoted. Schema byte-compared against `joan_of_arc.journey.json`: identical top-level and per-stop key sets, identical confidence vocabulary (attested/inferred/traditional). Chronology strictly ordered within every segment; the traveler dies 1268 and the CODA is properly a separate segment, so no living-person issue.

**Coordinates spot-checked (14)**: Château de Bourlémont 48.3901,5.6623 (Monumentum/Wikidata: 48.39012,5.66235 — exact); Abbaye de Mureau 48.3678,5.5753 (Wikidata 48°22'4"N 5°34'31"E — exact); Chapel of Simon of Cyrene / fifth station 31.7794,35.232 (Wikipedia 31.77965,35.23240 — matches, and byte-identical to the jesus.journey.json Via Dolorosa pin as directed); Bethlehem Nativity 31.7042,35.2075 and Sepulchre 31.7784,35.2298 byte-match jesus.journey.json; fairy tree 48.4302,5.6706 and well 48.4295,5.6699 byte-match joan_of_arc.journey.json; Domrémy, Neufchâteau, Great St Bernard, Rieti, Acre, Jaffa, Pamplona cathedral all within town/site tolerance. Incidental canon confirmation from the fifth-station check: the spot "was the first home for the Franciscans when they came to Jerusalem in 1229" — the campa's claim exactly.

**One pin fixed**: "The road to Bethlehem — the seraph told on the walk" was 31.7226,35.2126 (~1.4 km south of the halt its own suggested_ref names); corrected to Mar Elias monastery 31.7348,35.2112 (BibleWalks/Wikidata 31°44'5.3"N 35°12'40.2"E).

**Quote verified against the source itself**: pulled Luce, *Jeanne d'Arc à Domremy*, Supplément aux Preuves, pièce I, p. 281 (archive.org PDF, leafs 604–620). The charter reads "Ego Jofridus, dominus de Borlenmont, notum facio universis presens scriptum inspecturis quod ego, laude et assensu Sibille uxoris mee et heredum meorum, contuli et concessi…" — the dataset's elided quote is verbatim. Luce's heading confirms 28 May 1248 (= Ascension Day 1248), the Domremy-sur-Meuse/Greux/Neuville arages, the Premonstratensian order (the "white canons"), and footnote 3 confirms Thibaud count of Bar sealed his confirmation the same month — all as the campa has it. Only 1 quote exists in the file; all other quote fields are honestly null (the canon carries no other speech). The 1456 fairy testimony (Jeanne widow of Thiesselin, the lord of Bourlémont and the lady Fée) is paraphrased in campa, not quoted — correct handling.

**Campa**: present tense throughout, register held (the canon's theophanies, the fairy portal, the dragons, and the time-folds all kept and marked by confidence, never debunked). One length repair: the birth stop ran 112 words, over the joan-reference ceiling of 110; trimmed to 109 with a three-word cut ("high", 2× "the") — no content lost. All 43 campas now 85–109 words.

**Not changed**: the 1240-vs-1244 reconciliation, the Greccio one-night fold, and the 1456 dating stand as the researcher argued them; La Verna correctly remains heard-of, not visited. No stops added — 43 is inside target and the canon is fully spent.

Verdict: dataset sound. Two repairs (Mar Elias pin, birth campa length), re-validated clean.
