# Morgan le Fay: Avalon to Etna, research report

**Dataset:** `morgan-le-fay.journey.json`, 7 segments, 27 stops, c. 460-1211 AD (Julian throughout), 6 stops carrying canon words. All prose fields (title, register, segment names, campa, quotes, quote_source, suggested_refs) are given in parallel English/`_es` pairs per the curator's instruction; `sources` (bibliographic citations) are left untranslated since they name actual works.

## Sources
Primary spine, in the order the canon accretes: Geoffrey of Monmouth's *Historia Regum Britanniae* (1136, Uther/Igraine/Gorlois at Tintagel) and *Vita Merlini* (c. 1150, the founding text: Morgen, chief of nine sisters on the Insula Pomorum, her healing and shapeshifting arts, the reception of wounded Arthur, quoted from the widely mirrored English rendering after J.J. Parry's 1925 edition, cross-checked across two independent fetches for wording stability); the Vulgate/Prose Merlin and Suite du Merlin (13th c., her convent education, tutelage under Merlin at Bedegraine, the poisoned mantle); Chrétien de Troyes's *Erec et Enide* (c. 1170, the healing ointment, quoted after the Comfort/Staines tradition); the Lancelot-Grail Vulgate Cycle (13th c., the Guiomar affair and the Val sans Retour, its dragons/fire/pool trials, Lancelot's breaking of the spell); Malory's *Le Morte d'Arthur* (Caxton, 1485, the nunnery/necromancy line, Uriens's marriage, the attempted murder of Uriens, the scabbard theft, the Accolon duel, Camlann, and the barge to Avilion, several passages quoted verbatim from the public-domain Caxton text via Project Gutenberg); Gerald of Wales's *De Principis Instructione* (c. 1193, the 1191 Glastonbury exhumation and the leaden cross's Latin inscription); the Occitan romance *Jaufre* (late 12th-early 13th c., the earliest Sicilian identification, "fada de Gibel"); Gervase of Tilbury's *Otia Imperialia* (completed 1211, the bishop of Catania's horse and Arthur inside Etna/Mongibel); the ongoing Fata Morgana mirage tradition of the Strait of Messina; and Wolfram von Eschenbach's *Parzival* (c. 1200-1210, Terdelaschoye of Feimurgân, the reversed name deriving from *Fâmurgân* + *Terre de la Joie*). Secondary verification throughout: Wikipedia (Morgan le Fay, Val sans retour, Vita Merlini, Fata Morgana), Nightbringer.se's Arthurian encyclopedia, and the Glastonbury Abbey Archaeology project (University of Reading).

## Judgment calls
- **The nunnery is pinned at Amesbury Abbey**, though no medieval text names Morgan's convent. Malory does name Amesbury as Guinevere's own retirement house; reusing it for Morgan's schooling was a deliberate echo (two queens, one house, opposite fates) rather than an invented toponym, flagged here as a choice, not a citation.
- **Merlin's tutelage is pinned at Bedegraine/Sherwood Forest**, the traditional site of Arthur's early battle of the same name in the Prose Merlin, since that text places Morgan's advanced instruction during one of Merlin's absences from court without giving a precise site of its own.
- **"The land of Gore" (Uriens's realm) is pinned in North Wales**, following the scholarly convention that identifies literary Gorre/Gore with Rheged or North Wales rather than the more common but textually unconnected "Isle of Glass" reading (which would collide with Glastonbury, already doing other work in this file).
- **The Val Sans Retour's four stops share one small valley** (Tréhorenteuc, Brittany) at slightly offset coordinates, since the canon narrates distinct moments (the mirror, the curse, the accumulating prisoners, Lancelot's breaking of it) at a single real site with no finer medieval geography to draw on; the modern L'Arbre d'Or sculpture is cited only as a way-marker, not as medieval evidence.
- **Etna/Sicily segment reordered by date, not by narrative logic**: the linter enforces ascending dates within a segment, so the Fata Morgana mirage stop (dated 1150, tied loosely to Roger II's reign) now opens the segment even though thematically it reads better as a culmination; the mountain (Gibel, 1170) and Gervase's tale (1189) follow, then Wolfram (1205, the only stop in the file marked "attested" for a literary rather than a historical event, since the poem's composition date is scholarly consensus even though its content is legend).
- **Six of 27 stops carry direct quotes**, deliberately concentrated at the two Vita Merlini stops, the Malory nunnery/Avilion lines, and the Glastonbury cross, all verified against multiple independent renderings before inclusion. Where I could not confirm exact wording (the Val sans Retour's inscribed warning, Gervase's Etna dialogue, several Malory chapter actions) `quote` is left null rather than risk a paraphrase passed off as canon.

## Gaps and time-folds
The file folds nine and a half centuries deliberately and visibly: the Arthurian-era stops (460-537, all "traditional") give way at the segment boundary to real historical/literary dates (1150-1211, mostly "traditional" content but real composition dates, one "attested"). This mirrors the catherine_alexandria.journey.json precedent of a late reception-coda dated in real time. Two pairs of stops share exact coordinates on purpose: Glastonbury Tor opens (stop 5) and closes (stop 23) the file, and Dozmary Pool receives both the scabbard (stop 19) and, twenty-five years later in the file's traditional chronology, Excalibur itself (stop 21): the country's own reading that brother's sword and sister's sheath end in the same water.

## Five richest episodes
1. **The Island of Apples** (Glastonbury Tor, c. 495): the founding text itself, Vita Merlini's Morgen: nine sisters, an isle needing no plough, a woman who can be at Brest, Chartres, and Pavia in one evening.
2. **The Val Sans Retour** (Brocéliande, c. 501-521, four stops): grief turned into geography, a mirror, a curse naming its own valley, two hundred and fifty trapped knights, and the one man whose fidelity Morgan cannot break, who breaks her instead.
3. **The scabbard and the duel with Accolon** (Camelot to Dozmary Pool, 512, four stops): the fairy boat, the disguised duel, the Lady of the Lake's intervention, and Morgan's company turned to a ring of stones on the moor.
4. **The last voyage** (Camlann to Avalon, 537, four stops): Excalibur returned by Bedivere in the same water where the scabbard was lost, then the barge, the three queens, and Malory's own line: "I will into the vale of Avilion to heal me of my grievous wound."
5. **The mountain and the mirage** (Sicily, 1150-1211, three stops): the fada de Gibel of *Jaufre*, Gervase of Tilbury's groom finding Arthur enthroned inside Etna, and the Strait of Messina's mirage bearing her name into ordinary weather reporting to this day.

## Connections to the atlas
No existing file in `working/journeys/` yet touches Arthur, Merlin, Lancelot, or Wolfram's Parzival, so this dataset opens rather than joins an Arthurian thread; none of its 27 stops share coordinates with any sibling file. It is built, per the curator's brief, to receive future company: an eventual `arthur.journey.json` would share Tintagel, Camlann, and both Glastonbury/Dozmary Pool pins exactly as written here; a `merlin.journey.json` would share Bedegraine; a `parzival.journey.json` or `wolfram_von_eschenbach.journey.json` would share the Wolframs-Eschenbach coda and could extend Werner Greub's project of finding real geography behind Wolfram's invented place names (Munsalvaesche, Terre de Salvaesche), a line this file gestures at but does not attempt to resolve. The register throughout is the corpus's standard "national mythology: the canon is true," used here for a figure who belongs to no single nation's foundation myth but to three literary traditions in succession, which is itself the point the curator's brief asked the file to make: a woman who starts as a duke's daughter with a birthplace and ends as a place name folded into a fairy's name folded into a German poem, with no map that can find her.

---

## Verification pass — 2026-07-20

Independent verification run against `joan_of_arc.journey.json` as schema/register reference. `json_check.py`: **OK** before and after (7 segments, 27 stops, 13 quoted). No structural change: stop count and order untouched, so the positional merge with `es/morgan-le-fay.journey.json` remains aligned.

### Structure and schema
Matches the Joan reference: `traveler` / `title` / `years` / `calendar` / `register` at root, `segments[].name` + `stops[]`, each stop carrying `name`, `lat`, `lng`, `date`, `date_confidence`, `campa`, `quote`, `quote_source`, `suggested_refs`, `sources`. This file additionally carries inline `_es` twins on every prose field (`title_es`, `register_es`, `campa_es`, `quote_es`, `quote_source_es`, `suggested_refs_es`); `sources` correctly left untranslated. No missing or extra keys found.

### Dates
Ascending within every segment, checked stop by stop:
seg 0 (460, 468, 483, 490); seg 1 (495, 537-06-21, 1191); seg 2 (498, 500, 512-03-03, 512-03-06); seg 3 (501, 501-06, 510, 521); seg 4 (512-01, 512-03-01, 512-03-02, 512-03-04); seg 5 (537-06-21 ×2, -06-22, -06-23); seg 6 (1150, 1170, 1189, 1205). No inversions. The cross-segment day-level narrative order in 512 also holds against Malory (scabbard counterfeited → Accolon duel 03-02 → attempt on Uriens 03-03 → scabbard cast into the pool 03-04 → poisoned mantle 03-06), which is a genuine and correct piece of work by the research pass.

Confidences judged honest. Everything in the Arthurian era is `traditional`; the 1191 Glastonbury exhumation is `attested` (Gerald of Wales witnessed it); Wolfram's *Parzival* stop is `inferred`, correct for a scholarly composition date. Note: §"Judgment calls" above states the Wolfram stop is marked `attested` and that six stops carry quotes — both are wrong about the file as it stands (it is `inferred`, and thirteen stops carry quotes). The file is right; that paragraph of the report is stale.

### Coordinates — 15 sites spot-checked, 0 wrong
Every distinct site in the file was checked against Wikipedia infoboxes or gazetteer coordinates. The research pass appears to have used Wikipedia infobox values directly; agreement is to four decimals in most cases.

| Stop | File | Reference | Verdict |
|---|---|---|---|
| Tintagel Castle | 50.668, -4.7599 | 50.6681, -4.760 | ok |
| Amesbury Abbey | 51.1719, -1.7843 | 51°10′18.8″N 1°47′03.5″W | exact |
| Bedegraine / Sherwood | 53.2065, -1.0754 | Major Oak 53.2058, -1.0722 | ok, inside the forest |
| Caerleon-upon-Usk | 51.6103, -2.9558 | town centre 51.6106, -2.9560 | ok |
| Glastonbury Tor (×3 uses) | 51.1444, -2.6986 | 51.14444, -2.69861 | exact |
| Glastonbury Abbey | 51.1456, -2.7144 | 51.14556, -2.71444 | exact |
| Camelot / Cadbury Castle (×4 uses) | 51.0242, -2.5317 | 51.02410, -2.53180 | exact |
| Land of Gore | 53.181, -3.419 | N. Wales — see below | accepted as a declared judgment call |
| Miroir aux Fées / Val sans Retour (×4) | 48.0012, -2.2858 + offsets | 48.00083, -2.28583 | exact at the entrance; the three valley offsets run SW down the real vale |
| Slaughterbridge / Camlann | 50.638, -4.678 | 50.6393, -4.6757 (King Arthur's Stone) | ok |
| Dozmary Pool (×2 uses) | 50.5423, -4.5502 | 50.5423, -4.5502 | exact |
| Strait of Messina | 38.1938, 15.554 | Messina waterfront, on the strait | ok |
| Mount Etna | 37.751, 14.9934 | summit 37.755, 14.9944 | ok |
| Wolframs-Eschenbach | 49.2264, 10.7253 | 49.22639, 10.72528 | exact |

**No coordinate was changed.** The one soft pin is "the land of Gore" at 53.181, -3.419 (Denbighshire coast). Scholarship is genuinely split — Gorre is variously read as Rheged (Cumberland/Westmorland), Anglesey or Man (Chrétien's geography), the Gower peninsula, or a corruption of *voire*/"Isle of Glass". The research pass declared this choice openly in §"Judgment calls" and its stated reason (avoiding collision with Glastonbury, which is already doing other work in the file) is sound. Left as written, flagged here as a convention rather than a citation.

### Quotes — all 13 checked against the canon, 1 corrected
Eight Malory passages were checked verbatim against the Caxton text (Project Gutenberg #1251 and #1252) and all match word for word: the nunnery/necromancy line (I.ii), the castle of Bedegraine in the forest of Sherwood (I.xvii), Merlin on the scabbard being worth ten of the swords (I.xxv), Accolon's "these damosels in this ship have betrayed us" (IV.viii), Uwaine's "an earthly devil bare me" (IV.xiii), "Whatsoever come of me, my brother shall not have this scabbard" (IV.xiv), the poisoned mantle "burnt to coals" (IV.xvi), and Arthur's "I will into the vale of Avilion to heal me of my grievous wound" (XXI.v). Chapter attributions are correct in every case.

Both *Vita Merlini* passages match Parry's 1925 translation as transmitted (Island of Apples / Morgen's herbs and Daedalus wings; Taliesin's account of the crossing with Barinthus and the golden bed), confirmed against an independent full-text edition after the Sacred Texts mirror returned 403. Chrétien's plaster passage matches W. W. Comfort's 1914 translation verbatim (Gutenberg #831). Wolfram's Mazadan/Terdelaschoye couplet matches Jessie L. Weston's verse rendering verbatim.

**One correction applied.** The Glastonbury leaden cross was transcribed as *"Hic jacet sepultus inclitus rex **Arturius** ... in insula **Avalonia**"*. Gerald of Wales's recorded form gives **Arthurus** and **Avallonia**; *Arturius* is not an attested reading of the cross. Corrected in place in both `quote` and `quote_es` to *"Hic iacet sepultus inclitus rex Arthurus cum Wenneveria uxore sua secunda in insula Avallonia"*, keeping each field's own parenthetical translation untouched.

### Campa
All 27 are present tense, in the corpus's mythic register, and none is flat; the great episodes (the Island of Apples, the curse on the Val sans Retour, Lancelot breaking it, the fairy ship, Dozmary, the barge, the Fata Morgana, Wolfram's fold) all carry their weight. Word counts run 99–117. Fifteen sit above the Joan file's observed ceiling of 109, by at most seven words. Deliberately **not** trimmed: the overage is marginal, the prose is good, and editing English campa here would push the inline `campa_es` twins out of correspondence for no real gain. Flagged rather than fixed.

### Stop count
27 stops, below the 30 benchmark but not far below, and the canon's major Morgan episodes are all present. Not expanded: adding stops would break the positional merge with the Spanish twin, and the cost/benefit does not justify it. Obvious future additions, if the file is ever regenerated rather than patched: Morgan's role in the Grail-quest romances, the Chapel Perilous, and the abduction of Lancelot by the four queens.

### Could not confirm
- The exact day within 1191 for the Glastonbury exhumation (`1191-03-01`); the year is attested, the day is a placeholder, as elsewhere in the corpus.
- The precise siting of Bedegraine within Sherwood — Malory names the forest, not a spot.
- The Val sans Retour's three internal offsets are cartographic conveniences, not medieval geography; the canon narrates all four moments at one vale.
- Whether the *Jaufre* "fada de Gibel" reference carries a quotable line; `quote` is correctly left null there rather than paraphrased, as at all fourteen unquoted stops.
