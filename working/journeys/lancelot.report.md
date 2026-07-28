# Lancelot — Brocéliande to Joyous Gard: research report

**Dataset:** `lancelot.journey.json` — 7 segments, 31 stops, c. 502-543 (Julian, all `traditional`), 6 stops carrying canon quotes. Spanish parallel: `lancelot.journey.es.json` (same shape, translated prose fields, quotes rendered with `(traducción)` noted on the quote_source, following the convention set by `lady-of-the-lake.journey.es.json`).

## Sources
Three source-systems, as the brief specified: Chrétien de Troyes' *Lancelot, le Chevalier de la Charrette* (trans. W. W. Comfort 1914 for prose citation; A. S. Kline's verse translation for the one exact quoted passage, the cart hesitation) for the Gorre material; the Vulgate/Lancelot-Grail Cycle (Prose Lancelot, Queste del Saint Graal) for the infancy, Galehaut, Elaine/Galahad, and madness episodes; and Malory's *Le Morte d'Arthur* (Caxton text, cross-checked via Wikisource, Owl Eyes, Gutenberg, and sacred-texts excerpts) for Joyous Gard's naming, the Grail-quest failure at Corbenic, the exile war, and the death. Secondary: Nightbringer.se and Grokipedia for King Ban/Benoic genealogy; R. S. Loomis and D. D. R. Owen on the real-world geography Chrétien himself supplies for Gorre (he names Bath as one of Bademagu's court cities); Dante's *Inferno* V and Duke University's Dante's Library page for the Galehaut kiss rubric; P. A. Karr's *Arthurian Companion* on Corbenic's unlocated status.

## Judgment calls
- **Camlann fixed at 537, matching the sibling file exactly.** `lady-of-the-lake.journey.json` already anchors this atlas's Arthurian chronology to the Annales Cambriae year for Camlann. This file reuses that same date (`0537-01-01`) for the same event rather than inventing a rival year, and shares the Comper coordinates (48.0706, -2.1723) byte-for-byte for the fostering scene both files narrate.
- **A deliberate, flagged time-fold.** The Vulgate's own internal clock puts roughly fifteen years between Galahad's conception and his arrival at the Siege Perilous (he is canonically ~15 at the Grail Quest). Squeezed against the fixed 537 Camlann anchor, that arithmetic doesn't fit — no full retelling reconciles it either. This file compresses the gap (Galahad conceived 523, the Quest opens 531) and says so here rather than padding invented incident to paper over it, exactly the corpus's own stated practice for genuine folds.
- **Gorre and Corbenic marked honestly unlocated, per the curator's brief.** Gorre is pinned at Bath because Chrétien's own text names Bath as one of Bademagu's court cities (a real textual anchor, not invention); Corbenic has no medieval consensus location at all, so its pin sits in the Welsh Marches where modern illustrators and gazetteers (Karr) most often guess, with the campa text saying outright that this is not a claimed real site.
- **Joyous Gard kept at one fixed pin (Bamburgh) across all four of its appearances** (conquest, siege, and burial), rather than alternating with Alnwick, since Malory himself never resolves which and the castle is one continuous place across the whole legend. Malory's own hedge ("some men say it was Alnwick, and some men say it was Bamborough") is quoted directly at its first appearance.
- **The Elaine/Galahad deception and madness kept in, though not named in the brief's waypoint list**, because the Corbenic failure is only fully legible against it: Lancelot's own son achieves, unveiled, what a trick of magic and his own sin keep permanently out of his father's reach.
- **Register kept at "national mythology: the canon is true,"** matching the Lady of the Lake file's exact formula rather than treating Chrétien's courtly-love material and Malory's tragedy as needing separate framing.

## Gaps
No episode from Chrétien's unfinished poem beyond the sword bridge and the year-later duel is dated with any real precision, since Godefroi de Leigni's completion gives no calendar markers at all; every date past infancy is a narrative construction, not a claim of history, and is marked `traditional` throughout (no stop is `attested`, since nothing in this canon is externally verifiable). The Perilous Bed and the lion/serpent gate-guardians of Gorre, and the second Round Table founding at Camelot, were left out as padding once the sword-bridge and Corbenic material already carried the weight the brief asked for.

## Five richest episodes
1. **The two steps of hesitation before the cart** (on the road, 521) — Reason against Love argued out in the open, and Guinevere's later verdict that the two-step delay, not the shame of the cart itself, was the true offense.
2. **The sword bridge at Bath** (521) — Chrétien's own text anchoring an otherworldly kingdom to a real English city while insisting no traveler returns from it, crossed on hands and knees over a blade.
3. **The rubric of the first kiss** (Sorelois, 519) — the scribal line Dante lifts whole into *Inferno* V, turning a Round Table romance into the book that damns Paolo and Francesca.
4. **Struck down before the Grail at Corbenic** (531) — twenty-four days unconscious, one for each year of sin, in the very castle where his own son was conceived by a deception he never chose.
5. **Sir Ector's eulogy at Glastonbury** (543) — the single most quoted passage of Malory's whole book, closing the map exactly where the curator's brief said it should: the best knight, with a hole where the grail should be.

## Connections to the atlas
This is the second Arthurian file after `lady-of-the-lake.journey.json`, and it was built to interlock with it deliberately: the Comper fostering (identical coordinates, cross-referenced in `sources`) and the fixed 537 Camlann date are shared anchors, not coincidences. Structurally it sits closest to `joan_of_arc.journey.json` among the non-Arthurian siblings: both are dense, quote-bearing itineraries of a single named canon (trial record there, Chrétien/Vulgate/Malory here) rather than the thinner constellation-of-sites shape of `lady-of-the-lake` or `catherine_alexandria`. It is also the atlas's first file to treat a mythical, deliberately unlocated geography (Gorre, Corbenic) as first-class stops rather than either forcing false coordinates or dropping the episodes, a pattern future Arthurian entries (Guinevere, Gawain, Galahad, Arthur himself) can now follow.

---

## Verification pass, 2026-07-20 (Opus)

First verification this dataset has ever received: the original research pass's verify agent died before running, so nothing had checked it until now. Both `lancelot.journey.json` and `es/lancelot.journey.json` were audited and repaired in place. Both now pass `json_check.py` clean, with no campa outside the enforced 55-120 word band, 7 segments / 31 stops / 9 quoted stops in each, byte-identical `lat`/`lng`/`date`/`date_confidence` across the pair, and positional quote parity on all 31 stops. No em-dash appears in either file.

### What was checked
Structure and key-shape against `joan_of_arc.journey.json`; chronological ordering within every segment; every `date_confidence` value (all `traditional`, which is correct for a wholly legendary subject); coordinates for 13 sites geocoded against OpenStreetMap; and quotes checked line by line against public-domain source texts, principally Caxton's Malory (Gutenberg 1251/1252) and W. W. Comfort's 1914 *Four Arthurian Romances* (Gutenberg 831).

### Coordinates fixed
- **Bamburgh Castle** (4 stops: 0519-03-10, 0536-06-01, 0536-09-01, 0543-01-15): 55.6089 / -1.708 was about 200 m off the castle. Now 55.6094 / -1.7113.
- **Glastonbury Abbey** (3 stops: 0542-11-01, 0543-01-01, and the queen's burial): 51.1489 / -2.7136 sat about 330 m north-east of the abbey precinct, which is the site the campas actually name (the grave of Arthur and Guinevere). Now 51.1464 / -2.7155.
- **Amesbury Abbey** (0537-01-05): 51.1719 / -1.777 was about 640 m off the abbey. Now 51.1745 / -1.7854.
- **Trèbe**: coordinate left at Bourges (47.081 / 2.3988, correct to 3 decimals) but the stop had been *named* "Trèbe on the Loire" while pinned 30 km from the Loire, on the Yèvre. Renamed "Trèbe in Benoic" and the campa now says plainly that later tradition sets Benoic in the Berry near Bourges, which is where this atlas pins it.
- Checked and left alone as already accurate: Comper (48.0706 / -2.1723, 70 m from the château), Bath (51.3811 / -2.359), Carlisle (54.8951 / -2.9382, town), Bayonne (43.4933 / -1.4748), Winchester (51.0632 / -1.3184, 110 m from the Great Hall, acceptable for a town pin), and the four deliberately unlocated pins (Sorelois, the roads of Logres, Corbenic, the wild country, the forest hermitage), which the campas already flag as guesses rather than claims.

### Quotes fixed
- **Sir Ector's lament** was a silent splice: it ran three clauses together while dropping "And thou were the truest friend to thy lover that ever bestrad horse" without ellipsis, and inserted commas the canon does not carry ("the truest lover, of a sinful man, that ever loved woman"). Restored to Malory's contiguous verbatim run, Book XXI Chapter XIII. It was also on the wrong stop: Ector speaks it at Joyous Gard, over the body during the funeral service, not at the Glastonbury hermitage. Moved to the burial stop.
- **The Alnwick/Bamborough hedge** was cited to Book XX. It is Book XXI, Chapter XII. Corrected in both files.
- **Merlin's prophecy** dropped "Sir" from "that shall be Sir Launcelot or else Galahad his son"; restored, and the citation sharpened to Book II, Chapter XIX. The sword is Balin's sword, not "the Adventurous Sword"; that phrase was removed from the campa and the suggested_ref.
- **The cart hesitation** was attributed to "trans. A. S. Kline, poetryintranslation.com, ll. 360-377" and rendered as rhymed verse. That page returns 404 and no Kline translation of the *Charrette* could be found; the wording matches no locatable edition. Replaced with W. W. Comfort's verbatim 1914 prose, vv. 247-398, greppable in Gutenberg 831, and the Kline entry removed from `sources`.
- **The first-kiss rubric** was given as "Qant la reine Genieure baisa por la boche Lancelot", unverifiable and reversing the agent. Replaced with the attested rubric of BnF Français 118, f. 219v: "comment mesire lancelot baisa la royne genievre la premiere fois".
- **The hermit's reproof** was sourced to Book XI, Chapters IX-X, which is the Elaine material. It is Book XIII, Chapters XIX-XX. Corrected, and a verbatim line from Lancelot's confession added (the canon plainly offered one and the stop was silent).
- **The Bade/Bath claim** was the entry most likely to be invention and turned out to be sound: Chrétien does seat Bademagu's birthday court "at his city of Bade", and Foerster's note (Comfort's footnote 426) reads Bade as Bath. A verbatim quote and the exact citation were added so the claim now carries its own proof. The vague "R. S. Loomis and D. D. R. Owen" source line was replaced with Comfort's footnotes 426 and 414.
- A verbatim quote from the hermit-bishop's vision (Book XXI, Chapter XII) was added to the death stop, replacing the eulogy that moved north.

Quote count rose 6 to 9; all three additions were mirrored in Spanish, so parity holds.

### Canon errors fixed
- **The Chevalier Mal Fet was in the wrong episode.** The madness campa had strangers calling him "the ill-made knight" during his two wild years. In Malory he answers to no name at all in the madness; he takes "Le Chevaler Mal Fet, the knight that hath trespassed" only afterward, on the Joyous Isle, as a deliberate alias. Moved.
- **The burial sequence was inverted.** The body was described as kept fifteen days above ground at the hermitage and then carried north. Malory has the opposite: the bier travels fifteen days to Joyous Gard, and only there is the corpse kept aloft fifteen days more before burial.
- **Constantine did not ride behind the bier.** He is chosen king after the burial, once the fellowship has dispersed from Joyous Gard. Removed. The procession is the hermit-bishop and nine knights; Sir Ector rides in mid-service after seven years searching England, Scotland and Wales, and does not learn of the death until Bors tells him, which replaces the invented "arriving too late by a day".
- **"Six years" was attached to the wrong stretch.** Malory's six years are the penance at the hermitage *before* Guinevere dies; after her burial Lancelot sickens within six weeks. The queen's death was therefore re-dated 0537-06-01 to 0542-11-01, which also makes 0543-01-15 land exactly on Malory's own fifteen-day journey north. Chronology stays ordered and the 502-543 span in `years` is unchanged.
- **Meleagant was not beheaded "at the queen's own open wish."** Godefroi has Lancelot sever the right arm at one stroke, break three teeth, unlace the helmet and take the head, with the queen watching from a tower window. Corrected.
- **Dolorous Gard was described from nowhere in the canon:** "a giant-hearted knight and his brothers", "more than sixty imprisoned lords and ladies", and a renaming "on the spot". The Prose Lancelot has Brandin of the Isles, two walls of ten knights each, the Copper Knight, the jewelled slab in the churchyard reading that Lancelot of the Lake son of King Ban will lie there, and the renaming only after the copper maiden's keys release the whirlwind and break the enchantments. Rewritten to the attested account; the prisoner count, which no source supports, is gone.
- **The queen was handed back at Carlisle, not at Joyous Gard.** Malory rides her from Joyous Gard to Carlisle for the delivery; the campa now says so while the stop stays pinned where the interdict reaches Lancelot.

### What remains uncertain
The time-fold flagged in the original report stands and was deliberately not "corrected": Galahad's canonical age at the Grail Quest cannot be reconciled with a 537 Camlann, and the file compresses it rather than inventing a rival chronology. Gorre's topography is confused in Chrétien himself, as his own translator's footnote 414 concedes: the Bade/Bath court is a real textual anchor but the sword bridge's position relative to the kingdom's frontier is not recoverable, so the two Gorre stops share the Bath pin as the only named point the poem supplies. Corbenic, Sorelois, the roads of Logres, the wild country and the forest hermitage have no medieval consensus location and keep approximate pins that the campas name as guesses. Whether Joyous Gard is Bamburgh or Alnwick is unresolved in Malory and left unresolved here, with his own hedge quoted. No stop in this file is or should be `attested`.

## Verification pass II, 2026-07-20 (structure, coordinates, canon fidelity)

Second independent pass. `json_check.py` reported OK on arrival (7 segments, 31 stops, 9 quoted) and OK on exit. **Stop count, stop order and segment structure are unchanged — the Spanish twin stays positionally aligned.** All edits were in-place field repairs.

### Structure and chronology
Schema matches `joan_of_arc.journey.json` field for field (`traveler`/`title`/`years`/`calendar`/`register`/`segments[].name`/`stops[]` with `name`, `lat`, `lng`, `date`, `date_confidence`, `campa`, `quote`, `quote_source`, `suggested_refs`, `sources`). Dates are strictly ascending across all 31 stops, not merely within segments. Every `date_confidence` is `traditional`, which is the honest value for a legendary chronology: nothing here is `attested` and nothing is bare `inferred`.

### Coordinates — 12 spot-checked, 2 tightened
| stop | checked against | result |
|---|---|---|
| Comper (×2) | Château de Comper, Concoret, 48.07057 / -2.17231 | exact; also matches the shared pin in `lady-of-the-lake.journey.json` |
| Bamburgh (×4) | Bamburgh Castle, 55.6089 / -1.7102 | was 55.6094 / -1.7113 (~90 m); **tightened** |
| Glastonbury (×2) | Glastonbury Abbey, 51.1456 / -2.7145 | was 51.1464 / -2.7155 (~120 m); **tightened** |
| Amesbury | Amesbury Abbey (Historic England), 51.1745 / -1.7854 | exact |
| Winchester (×5) | Winchester, Great Hall / Westgate quarter | correct |
| Carlisle (×2) | Carlisle, 54.8951 / -2.9382 | correct (city, not castle keep — the campa says "outside Carlisle") |
| Bath (×2) | Bath centre, 51.3811 / -2.3590 | correct |
| Bayonne | Bayonne, 43.4929 / -1.4748 | correct |
| Trèbe / Benoic | Bourges, 47.0810 / 2.3988 | correct for the Berry identification the campa declares |
| Salisbury Plain | Camlann pin | consistent with the atlas's own Camlann anchor |

No stop was in the wrong country or the wrong region. The five deliberately unlocated pins (Sorelois, the roads of Logres, the wild country, the forest hermitage, Corbenic) each name themselves as guesses in the stop name or campa and were left alone.

### Quotes — all 9 verified verbatim, none nulled, none invented
Seven Malory quotes were checked character-by-character against Gutenberg 1251/1252: Merlin on Balin's sword (II.xix), Lancelot's confession to the hermit (XIII.xx), Guinevere at Amesbury (XXI.ix), the Alnwick/Bamborough hedge (XXI.xii), the hermit-bishop's vision (XXI.xii), and Ector's lament (XXI.xiii). Two Chrétien quotes were checked against Comfort 1914 (Gutenberg 831): the cart hesitation and "the king was holding a joyous court at his city of Bade", the latter carrying Foerster's own footnote 426, "Bade = Bath." The BnF Français 118 f. 219v kiss rubric was independently confirmed via Biblissima's record for that folio. **No quote required nulling or restoration.** The previous pass's quote work holds.

### Canon errors found and fixed
- **Elaine of Benoic does not die.** The Comper campa had the Lady of the Lake lifting the child "from his dead mother's side". In the Vulgate she sets him on the bank, runs to the dying Ban, and returns to an empty bank; she then takes the veil with her sister Evaine and is known ever after as the Queen of Great Sorrows. Rewritten. This is the one substantive canon error in the file.
- **The interdict came through the Bishop of Rochester,** not the archbishop of Canterbury. Malory XX.xiii names him from the French book. Corrected.
- **The queen does not watch the beheading of Meleagant from a tower window.** Godefroi puts the duel in the garden and says only that no one present felt any pity. The tower detail (introduced by the previous pass) was removed and the canon's own line put in its place.
- **Dolorous Gard details sharpened to the source:** the slab is a great *metal* slab, not "jewelled"; the barrier is two *gates* of ten knights each; the copper figures below are *knights* (plural), preceding the copper maiden with the two keys.
- **Suggested_ref wording** for Gorre restored to Comfort's actual phrase, "the kingdom whence no foreigner returns" (was "from which no stranger returns").

### Register
Nine campas ran over the 110-word ceiling and were trimmed to 97-107 without losing an episode; present tense and the mythic register are intact throughout. The great episodes — the sword bridge, the blood on the sheets, the Grail chamber, the rescue at the stake, the bishop's laughter — carry their weight. 31 stops is above the threshold; the canon offers more (Tarquin, the Chapel Perilous, the Fair Maid of Astolat, the healing of Sir Urre), but adding them would break positional alignment with the Spanish twin, so none were added.

### Could not confirm
That Lancelot was christened Galahad *for his grandfather* — the christening name is well attested, the grandfather's identity is not, and the clause was left standing as the campa's own soft claim. Whether the queen girds on Lancelot's sword at the knighting is version-dependent; the campa already hedges it with "by the oldest telling". The internal tension between Benoic-at-Bourges (birth) and Benwick-at-Bayonne (exile) is Malory's own — he offers Bayonne *and* Beaune — and both stops name their identification openly rather than pretending to one map.
