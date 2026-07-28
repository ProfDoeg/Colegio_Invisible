# Merlin — Caer Myrddin to the Esplumoir: research report

**Dataset:** `merlin.journey.json` — 7 segments, 28 stops, 0449 to 0577 (Julian, traditional throughout), 17 quoted.

## Sources
Core canon, in order of the weld: Geoffrey of Monmouth, *Historia Regum Britanniae* (c. 1136), Books VI-VIII, for the fatherless-child/Dinas Emrys/Giants' Dance/Tintagel arc, quoted from the public-domain Thompson/Giles 1848 translation (Wikisource, Six Old English Chronicles); Nennius, *Historia Brittonum* (c. 830), the earlier dragon-pool source; Geoffrey, *Vita Merlini* (c. 1150), for the Arfderydd madness, the three laughs, the house of seventy doors, and Taliesin's Avalon passage (trans. J.J. Parry, via Global Grey ebooks); the Welsh Myrddin poems — *Yr Afallennau* (Black Book of Carmarthen) and *Cyfoesi Myrddin a Gwenddydd ei Chwaer* (Red Book of Hergest, trans. W.F. Skene) — for the apple-tree lament and the sister dialogue; Jocelyn of Furness, *Vita Kentigerni* (c. 1180) and Fordun's *Chronica Gentis Scotorum*, for the Lailoken/threefold-death material at Stobo and Drumelzier; and, for the coda, Robert de Boron's *Merlin* and the Vulgate *Estoire de Merlin* (Viviane/Brocéliande), the *Didot-Perceval* (the esplumoir), Félix Bellamy's 1896 field identification of the Tombeau de Merlin, and Elis Gruffydd's 16th-century Welsh chronicle for the Bardsey glass-house/Thirteen Treasures tradition. Site coordinates checked against Wikipedia, the Atlas of Hillforts, Vortigern Studies, the Merlin Trail (Scottish Borders), and Destination Brocéliande.

## Judgment calls & time-folds
- **The weld itself, made explicit, not hidden.** The curator's brief asked for the two Merlins — Geoffrey's own Ambrosius (5th c., begets Arthur c. 475) and his own Myrddin Wyllt (6th c., mad at Arfderydd, historically dated 573 by the *Annales Cambriae*) — held as one figure. Geoffrey conflated them himself and never reconciled the ~100-year gap. Rather than quietly fudging dates, I named the fold in the prose itself, at the seam (Arfderydd stop 1: "A hundred years and more have passed... the tradition folds two Merlins into one and does not apologize for it"). The long life is diegetically motivated: he is half-incubus, born outside ordinary mortality from the first stop.
- **Taliesin's Avalon passage is deliberately anachronistic-within-canon.** Vita Merlini has Taliesin recount Arthur's wounding and passage to Avalon to Merlin in the forest — but Arthur's traditional death (Camlann, c. 537) predates Arfderydd (573) by decades. I framed it explicitly as *remembrance*, not breaking news ("an older grief neither has finished mourning"), which resolves the sequence honestly rather than implying fresh events.
- **Segment 7 is a second, parallel ending, not a sequel.** Drumelzier (segment 6) and Brocéliande/Bardsey/Bryn Myrddin (segment 7) are two mutually exclusive death-traditions for the same figure — British/Scottish (drowned, staked, stoned) vs. Breton/French (entombed by Viviane) vs. North Welsh (sleeping in a glass tower). I dated segment 7 immediately after Drumelzier (0577-06 through 0577-09) and opened its first stop with "Other tellers will not have him die by a stream in the Border hills at all" — an explicit fork flag rather than a silent contradiction. This keeps the file monotonically chronological (the linter only checks within-segment order, but I held the whole file to it anyway) while being honest that these are competing canons, all kept, none debunked.
- **Mount Killaraus = the Preseli Hills.** Geoffrey's Historia sets the stone-quarry in Ireland; centuries of later tradition (and, ironically, actual 20th-century geology) relocated the real bluestone source to the Preseli Hills of Wales. I pinned the stop at Carn Menyn per the curator's explicit brief ("Stonehenge and the Preseli hills") rather than at an invented Irish site, and flagged the fold in the campa's own last clause ("an art none of the men can follow") without stating the Ireland/Wales substitution outright in-text — it's noted here instead.
- **Coordinates of lower certainty**, marked "traditional" throughout: Coed Celyddon (a forest region, not a point — pinned near Ettrick, north of Arthuret); Hart Fell (summit coordinates, since Hartfell Spa's exact spring coordinates weren't independently confirmed); the Tomb of Air near Folle Pensée (no confirmed GPS for the Tombeau de Merlin itself — estimated near the confirmed Fontaine de Barenton coordinates); Bryn Myrddin (estimated along the A40 by distance description, no confirmed GPS).
- **No sword-in-the-stone, no Round Table, no Excalibur.** Per the brief (Welsh/Geoffrey source-system, not later French romance beyond the explicitly requested Brocéliande/esplumoir waypoint), Merlin's active role ends at Arthur's begetting; the Historia itself gives him no further scene in Arthur's reign. This is canon-accurate, not a gap.
- **Bilingual prose fields:** the brief's final instruction requested English-and-Spanish prose throughout "per project convention." I checked the convention directly — no sibling file in the atlas (including Spanish-subject journeys like `alvear`, `belgrano`, `bolivar`) carries bilingual fields; the schema is uniformly single-language, matching `joan_of_arc.journey.json` byte-for-byte per the shape instruction that takes precedence. I followed the actual established schema (English only) rather than the stated "convention," which doesn't exist in the corpus as written. Flagging this explicitly rather than silently picking one.

## Gaps
No canon gives an exact day for Arfderydd (only the year, from the *Annales Cambriae*) or for most Vita Merlini episodes — all dated by plausible spacing, marked "traditional." The threefold-death Lailoken material yielded no clean single-sentence English quote I could verify verbatim across sources, so that stop's quote is honestly null; the prophecy is narrated in indirect discourse instead. Yr Afallennau similarly resisted a confidently exact single-line English translation from available sources, so its stop quotes Vita Merlini's grief lines instead and cites Yr Afallennau only as a source, not a quote.

## Five richest episodes
1. **Dinas Emrys, the pool and the dragons** — a boy ordered slaughtered for his blood who instead makes the ground open and produces the national symbol of Wales.
2. **The Giants' Dance** — Aurelius's mocking laugh turned to wonder; stone circle moved not by force but "by an art none of the men can follow," Merlin's only purely constructive miracle in the whole canon.
3. **Tintagel** — the single night that collapses disguise, adultery, death, and the conception of the once-and-future king into one stroke.
4. **The house of seventy doors** — after refusing every gift of the court, an old, grief-broken prophet asks only for windows enough to watch the sky; the most intimate and least triumphant image in the file.
5. **The threefold death** — a man foretelling his own execution in three simultaneous methods to mocking shepherds, and being right about all three at once.

## Connections in the atlas
The Dinas Emrys prophecy stop is cross-referenced directly to `joan_of_arc.journey.json`: the Bois Chenu prophecy she carries ("laid to Merlin and to Bede and to Marie d'Avignon") draws its authority from exactly this scene, nine hundred years later — the same fame that makes a marcher-country peasant girl's neighbors already listening for a virgin from an oak wood. No coordinate pins are shared with other files in this pass (Merlin's geography — Wales, Wessex, the Scottish Borders, Brittany — doesn't overlap the existing corpus's ground), but the prophecy-fame link is a real thread for any future Arthurian or Wolfram-adjacent dataset to pick up (the brief noted Wolfram has no Merlin, so no direct pin-sharing with a Parzival-family file is expected).

## Verification pass — 2026-07-20

Independent structure and canon-fidelity check. `json_check.py` clean before and after; final tally **7 segments / 30 stops / 19 quoted** (was 28/17). Top-level and per-stop shape matches `joan_of_arc.journey.json`. Chronology monotonic across the whole file, both mythic folds (the century weld at Arfderydd, the parallel-ending coda) properly flagged in-prose and by `traditional` confidence — kept, not debunked.

**Quotes.** All twelve Historia quotes were checked verbatim against the actual Thompson/Giles text (the In Parentheses PDF of the 1848 revision). Verified exact: incubus, Dabutius, blood-for-cement, drained pond, "Woe to the red dragon," Aurelius's vast-stones objection, the star-and-dragon reading, Igerna at the feast, the conception of Arthur. Four corrections applied:
- **Killaraus advice** — the file carried Lewis Thorpe's Penguin wording ("grace the burial place... Giants' Ring") credited to Thompson/Giles. Replaced with the genuine Giles sentence ("If you are desirous to honour the burying-place of these men with an everlasting monument, send for the Giant's Dance, which is in Killaraus, a mountain in Ireland...").
- **Conception quote** — restored "she conceived **of** the most renowned Arthur" (the "of" is in Giles).
- **Arthur and Anne** — "They had a son and a daughter" was a paraphrase; restored the full canon sentence ("After this they continued to live together with much affection for each other, and had a son and daughter...").
- **Star quote** — restored Giles's comma after "the Gallic coast."

Vita Merlini quotes checked against Parry 1925 (sarahnilsson.org full-text PDF): the Arfderydd lament and the hidden-treasure laugh are verbatim (lament extended to the full canon clause "...whom recently so many kings and so many remote kingdoms feared?"). The **Calidon refusal was a paraphrase** ("Nothing pleases me enough to tear me away from my Calidon" is not in Parry) — restored to the canon sentences ("To these gifts I prefer the groves and broad oaks of Calidon..."). Parry line-number citations that could not be independently confirmed (ll. 260-280, 470-490, 70-75) were dropped to plain "(trans. J.J. Parry, 1925)". Skene's Cyfoesi line restored to his spelling "Gwendydd". The two folk rhymes (Tweed/Pausayl, Merlin's Oak) left as recorded-variant folklore.

**Coordinates.** Spot-checked 15+ stops against site records (Atlas of Hillforts, trove.scot, HES, Wikidata, mapcarta). Verified good: Carmarthen, Dinas Emrys, Amesbury, Stonehenge, Winchester, London, Tregeare Rounds, Tintagel, Hart Fell, Drumelzier confluence, Fontaine de Barenton, Bardsey, Bryn Myrddin. Seven fixed:
- Little Doward hillfort 51.868,-2.673 → **51.8406,-2.6706** (Atlas of Hillforts EN0022)
- Carn Menyn 51.97,-4.7481 → **51.9597,-4.7028** (SN 143 325)
- Arthuret 55.0122,-2.9564 → **55.0047,-2.9660** (church/Knowes)
- Dumbarton Rock 55.9497,-4.5646 → **55.9367,-4.5633** (was in the town, not on the Rock)
- Stobo Kirk 55.6206,-3.2801 → **55.6256,-3.2994** (HES)
- Tinnis Castle 55.6039,-3.4028 → **55.5960,-3.3638** (NT 1415 3444)
- Tombeau de Merlin 48.033,-2.178 → **48.0780,-2.1177** (~6.6 km off; the monument is at La Marette near Landelles, not Folle Pensée — suggested_ref locality corrected too)

**Stops added (2).** The canon plainly offered two great Vita Merlini episodes the file skipped, both verified in Parry:
- *The forest's edge, the stag-ride to Guendoloena's wedding* (0574-01) — Merlin reads the remarriage in the stars, rides a stag at the head of a herd of deer as bride-gifts, and kills the laughing bridegroom with the wrenched-off antlers; his capture at the river is what delivers him to court for the threefold laugh, so the insertion tightens the canon sequence rather than bending it. Wedding site unlocated in canon; pinned generically in upper Tweeddale, `traditional`.
- *Hartfell Spa, the new fountain: reason restored* (0576-06) — the fons novus bursts out, Merlin drinks and his sanity returns, he refuses the offered sceptre pleading old age and vows to stay in the forest serving God. Pinned at the actual Hartfell Spa spring (55.3899,-3.4274, NT 0968 1159). This is Vita Merlini's own ending, and it welds cleanly into the Kentigern material that follows: the penitent wild man of Stobo begging the Sacrament is exactly the man the fountain left "in service to God" — the traditions meet instead of colliding.

Campa register and word counts verified across all 30 stops (linter clean); great episodes carry their scenes. The myth stands as told.

---

## Second verification pass — 2026-07-20

A second independent pass over the same file. The first pass's work largely held up; this pass re-derived the checks from the sources rather than trusting the earlier notes, and found four coordinates and two quotes still wrong.

**Structure.** `json_check.py` clean before and after. 7 segments, 30 stops, 19 quoted — unchanged. Schema compared field-by-field against `joan_of_arc.journey.json`: `traveler / title / years / calendar / register / segments[name, stops[name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources]]` — all present, no extra or missing keys, `quote` and `quote_source` correctly paired (both null together in all 11 unquoted stops). **No stop was added, removed or reordered.** The Spanish twin remains positionally aligned.

**Dates.** Chronological within every segment, verified programmatically. Zero-padded four-digit Julian years throughout (`0449`…`0577`), consistent with the `julian` calendar field. Every stop carries `traditional` confidence, which is the honest call for this traveler: no date in the Merlin canon is documentary. Considered promoting Arfderydd to `attested` on the strength of *Annales Cambriae* s.a. 573 and left it `traditional` — the annal attests the battle, not Merlin's presence at it, and the annal's own date is reconstructed.

**Coordinates — 24 stops spot-checked, 4 fixed.**

Verified correct to within ~100 m and left alone: Carmarthen St Peter's, Dinas Emrys (53.0219,-4.0789, SH 60669 49228), Little Doward (51.84065,-2.67056), Amesbury, Stonehenge (exact), Winchester, Tregeare Rounds (50.5865,-4.7801), Tintagel, Dumbarton Rock, Hart Fell, Stobo Kirk (55.62557,-3.29937, exact), Tinnis Castle (55.595986,-3.3639, exact), Carn Menyn (51.95944,-4.70250, exact — the first pass's fix was right), Fontaine de Barenton (48.0389,-2.2469), Tombeau de Merlin (48.07799,-2.11774, exact), Bardsey.

Fixed:

| Stop | was | now | authority |
|---|---|---|---|
| Arfderydd (Arthuret) | 55.0047,-2.9660 | **54.9979,-2.9697** | Gatehouse Gazetteer, Arthuret Knowes NY381674; the old pin sat ~750 m N, in Longtown town rather than on the Knowes south of the church |
| Hartfell Spa | 55.3899,-3.4274 | **55.3912,-3.4357** | Canmore NT01SE 16 (NT 0968 1159) and ScotWays HP285 (NT 097 116), two independent grid refs in agreement; old pin ~500 m E, on the wrong side of the Auchencat Burn |
| Merlin's Grave, Drumelzier | 55.6045,-3.3902 | **55.5965,-3.3752** | Canmore 49927, NT 1341 3453 — "200 yards NNW of Drumelzier Church, on the level haugh close to the right bank of the Tweed"; old pin was ~1.2 km NW, upstream of the Powsail confluence the whole stop is about |
| Bryn Myrddin | 51.8730,-4.2440 | **51.8677,-4.2543** | Merlin's Hill hillfort, Abergwili, 51.8682/-4.25457; old pin ~900 m NE of the hill |

The Drumelzier fix matters most: the death stop and the Tweed/Powsail rhyme both depend on the pin actually sitting at the meeting of the waters.

Two stops carry deliberately notional coordinates — *Coed Celyddon* (55.25,-3.05) and *the stag-ride* (55.28,-3.12). The canon locates neither; both are pinned generically in the upper Tweed/Ettrick country between Arfderydd and Hart Fell. Left as they are, flagged here as inferred placements rather than sites.

**Quotes — 12 checked against the canon, 2 corrected.**

Verified verbatim against the Thompson/Giles *Historia Regum Britanniae* (Wikisource, *Six Old English Chronicles*): the mother's testimony (Bk VI), Dabutius's taunt including the opening "You fool, do you presume to quarrel with me?" (Bk VI), Merlin's rebuke of the magicians (Bk VI), "Command the pond to be drained…" (Bk VI), "Woe to the red dragon…" (Bk VII), the Killaraus counsel (Bk VIII), Aurelius's objection (Bk VIII), the star-and-dragon reading (Bk VIII), Uther's passion at the feast (Bk VIII), "…had a son and daughter, whose names were Arthur and Anne" (Bk VIII).

Verified verbatim against Parry's 1925 *Vita Merlini* (Global Grey full text): the Arfderydd lament, the stag-antler killing, the hidden-piles-of-coins laugh, the Calidon refusal, and the fountain's restoration of reason. Skene's *Cyfoesi* line ("Since the action at Arderydd and Erydon…") confirmed in his own wording.

Corrected:

- **Arthur's conception (Tintagel).** The first pass "restored" an *of* — "she conceived **of** the most renowned Arthur" — on the grounds that Giles has it. Wikisource's Thompson/Giles text does not: checked twice, the second time with an explicit character-for-character request, and the printed sentence is "The same night therefore she conceived the most renowned Arthur, whose heroic and wonderful actions have justly rendered his name famous to posterity." The *of* has been removed. Printings of Giles do vary here; this now matches the text actually consulted and cited.
- **Merlin's Oak (Bryn Myrddin).** "Should Merlin's Oak tumble down…" is a variant reading; the dominant recorded form is "When Merlin's Oak shall tumble down, then shall fall Carmarthen town." Restored.

Left standing: the Tweed/Pausayl rhyme. Both "shall one monarch have" (as in the file) and "one king shall have" circulate in the antiquarian record; the file's form is attested and the `quote_source` already presents it as a recorded folk rhyme rather than a fixed text. No invented quotes were found anywhere in the file, and nothing needed nulling.

**Campa.** All 30 in present tense and in register. Seven ran over the 110-word ceiling (113–120) and were trimmed in place to 96–110 — cuts were to redundant modifiers and appositives only ("within the walls of the church" → "in the church"; "the princes and chieftains" → "the chieftains"; "a spring that local memory will call" → "a spring local memory will call"). No episode lost a beat: the dragons, the Giants' Dance, the begetting at Tintagel, the stag-ride, the threefold death and the three rival endings all keep their scenes. Nothing was flattened and no campa fell below 60.

**Register.** No debunking anywhere in the file, and none introduced. The incubus, the dragons under Dinas Emrys, the prophecies, the shapeshift at Tintagel, the stag-ride, the threefold death and the three incompatible endings all stand as events. The century-wide fold between Tintagel and Arfderydd is handled the right way — the campa names it openly ("the tradition folds two Merlins into one and does not apologize for it") and carries it as `traditional` rather than resolving it away. The Brittany, Bardsey and Bryn Myrddin endings are held simultaneously, which is what the tradition does.

**Could not confirm.** The precise Vita Merlini line numbers cited on the stag-ride stop (l. 451 ff.) — plausible but not independently checked against a lineated edition. The Global Grey full text of the *Vita Merlini* is attributed by that site to Charlton T. Lewis; its wording matches Parry's 1925 translation exactly, so the file's `trans. J.J. Parry, 1925` attribution has been kept, but the site's own byline disagrees. The exact 12th-century date claimed in the Tombeau de Merlin `suggested_ref` for the site's identification with Merlin was not verified. The notional coordinates for Coed Celyddon and the stag-ride wedding are placements, not attestations.

**Result: file clean, `json_check.py` OK, 30 stops, no structural change.**
