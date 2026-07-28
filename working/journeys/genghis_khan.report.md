# Genghis Khan — The Blood Clot and the Mountain: research report

**Dataset:** `genghis_khan.journey.json` — 41 stops, 9 named segments, 7 quotes. Calendar: Julian (c. 1162–1227). Register: national mythology — the Secret History's wonders (the blood clot in the fist, the mountain's shelter, the shaman's decree of the title, the leap at the Indus) narrated as events.

## Sources
- **Spine:** *The Secret History of the Mongols* (tr. Igor de Rachewiltz; also Cleaves), the sole Mongolian-voiced canon, covering birth through 1227.
- **Biography/synthesis:** Paul Ratchnevsky, *Genghis Khan: His Life and Legacy*; Jack Weatherford, *Genghis Khan and the Making of the Modern World*.
- **Persian chroniclers of the Khwarezm war:** Ata-Malik Juvaini, *Tarikh-i Jahangushay* (the Bukhara mosque speech); Rashid al-Din, *Jami' al-Tawarikh* (the deathbed counsel to his sons, tr. Thackston); Minhaj-i-Siraj Juzjani (the Otrar trade letter).
- **The Daoist eyewitness:** Li Zhichang's record of Qiu Chuji's journey, tr. Arthur Waley as *The Travels of an Alchemist* (1931) — the one outside witness to Chinggis Khan speaking privately, 1222.
- **Per-episode:** Wikipedia/Grokipedia articles on the Otrar Catastrophe, sieges of Bukhara/Samarkand/Gurganj, Battle of the Indus, Mongol invasions of Georgia, Battle of the Kalka River, Mongol conquest of Western Xia, Burial place of Genghis Khan, Ikh Khorig; UNESCO's Great Burkhan Khaldun Mountain inscription.

## Judgment calls
- **The two Burkhan Khaldun pins.** As directed, the mountain appears twice — the youthful refuge/vow (segment 2) and the unmarked grave/Ikh Khorig coda (segment 9) — using the same coordinates (48.7523, 108.6582) both times, the return deliberate rather than an error.
- **Ganja cross-ref.** The Jebe-Subutai raid's Azerbaijan stop uses the exact Ganja coordinates (40.683, 46.360) already fixed in `nizami.journey.json`, and the campa explicitly notes the poet's tomb — already twelve years old — standing through the raid.
- **Quotes kept honest and few (7/41).** Genghis's own directly-recorded first-person speech is thin next to a figure like Joan of Arc with a stenographed trial. I used only lines with a real chain of attribution to his own mouth: the Burkhan Khaldun vow and "Börte! Börte!" (Secret History), the Jin-war prayer and Otrar trade letter (Ratchnevsky/Juzjani after Chinese-Persian sources), the Bukhara "punishment of God" speech (Juvaini), the Qiu Chuji exchange (Waley's translation of an eyewitness), and the deathbed counsel (Rashid al-Din). I explicitly dropped two famous but misattributed "Genghis quotes" — the bundled-arrows unity fable (Secret History actually gives this to his ancestor Alan Gua, not to him) and the free-floating "greatest happiness" internet quote (kept only in the Rashid al-Din–sourced deathbed form, which has real chain of custody).
- **Approximate coordinates, marked honestly.** Several steppe battle sites have no fixed modern location — Dalan Baljut ("Seventy Marshes"), the Baljuna covenant pool (identified here with Buir Lake, one of several competing scholarly guesses), Qalaqaljid Sands/Jeje'er Heights, Chakirmaut at Mount Naqu, the Ordos hunting ground, Toghrul's death near the Naiman border. All are marked `traditional` with the uncertainty noted in `sources`, the same honest-stand-in convention used for Nizami's imagined geography.
- **A deliberate time-fold.** Segment 7 (Jebe and Subutai's raid: Persia → Ganja → Georgia → Kalka, 1220–1223) and segment 8 (the Indus and Qiu Chuji, Nov 1221 – May 1222) run in the curator's requested narrative order rather than strict world-clock order — the Indus battle (Nov 1221) actually falls chronologically *inside* the raid's date range. Each segment is internally chronological (the validator's actual requirement); the two threads — the khan's own southward campaign and his generals' western raid — are simply told one after the other rather than interleaved, exactly as Nizami's dataset folds composition-date against legendary-setting-date.
- **Xi Xia/Jochi sequencing.** Historically Jochi's death (Feb 1227) happened *during* the Xi Xia campaign, not before it as the curator's arc phrase suggested; I kept the real order (return → campaign opens → the fall from the horse → news of Jochi's death → the khan's own death) since all of this fits inside one segment without contradiction, rather than force an artificial split.

## Gaps
- No stop for the "missing ten years" (c. 1187–1196) between Dalan Baljut and the Tatar campaign — sources genuinely disagree on what Temüjin did in this stretch (possible Jin vassal service is speculative), so the segment jumps the gap rather than invent a stop.
- Karakorum, built by Ögedei after 1235, is outside this life and not included.

## The five richest episodes
1. **The vow on Burkhan Khaldun** — the recurring sacred pin, refuge and grave in one place, the one relationship in the whole life that never breaks.
2. **Bukhara's Friday mosque** — "I am the punishment of God," the single sentence that carries the whole Khwarezmian campaign's self-justification.
3. **The muddy waters of Baljuna** — nineteen men of three faiths sharing a handful of dirty water and an oath, the multi-ethnic seed inside the most totalizing conqueror's story.
4. **Qiu Chuji and the medicine of long life** — the one scene where an outside eyewitness records the khan's own voice in private conversation, and he is refused the one thing he actually asks for.
5. **The secret cortège and the Ikh Khorig** — the empire that mapped and postal-routed half of Asia deliberately erasing one grave from its own record, a secrecy that has held for eight centuries.

## Connections to the atlas
- **nizami.journey.json** — shared Ganja pin, explicit cross-reference both directions (Nizami's tomb standing through the raid that passed his gate).
- **marco_polo.journey.json** (added in this same fleet) — Genghis is the grandfather of Kublai Khan, whom Marco Polo serves; this journey is the steppe world's founding arc that Marco's later journey presupposes.
- The **yam and paiza** (segment 4) is the same infrastructure Marco Polo will later travel under a century later.
- Register note: like Nizami and unlike Joan of Arc, this is a figure whose own voice survives only in fragments quoted by others (Persian chroniclers, a Daoist eyewitness, an epic compiled after his death) rather than a stenographed trial — the low quote count (7/41) is a feature of the source record, not an oversight.

---

## Verification pass — 2026-07-13

Independent structure-and-canon-fidelity check. `json_check.py` passes clean before and after repairs: 9 segments / 41 stops / 7 quoted. Top-level and per-stop key sets match `joan_of_arc.journey.json` exactly; calendar `julian`, register identical. All segments internally chronological; the deliberate raid/Indus time-fold (Indus, Nov 1221, inside the raid's 1220-1223 span) is kept per the nizami composition-vs-setting precedent. 41 stops is inside the 30-45 target; no stops added.

### Coordinates (15 spot-checked, 3 fixed)

Exact against sources: Delüün Boldog (49.0217/111.6247, Wikipedia exact), Otrar (42.8525/68.3028, exact), Konye-Urgench (42.326/59.152), Zhongdu/Beijing, Bukhara, Samarkand, Nishapur, Hamadan, Ganja (nizami cross-ref pin), Zhongxing/Yinchuan, Liupanshan. Burkhan Khaldun final pin (48.7523/108.6582) matches the UNESCO World Heritage centre point; Wikipedia's peak is ~25 km east at 48.762/109.010 — the mountain's identification is itself contested, so both stand; the flight-refuge stop (48.75/108.95) sits on the same massif. Left as-is.

**Fixed:**
- **Avarga** (3 stops): 47.20/109.17 → 47.0944/109.1528, the excavated Avraga site at the Kherlen-Tsenker confluence (Wikipedia).
- **Kalka River**: 47.50/37.50 → 47.2508/37.4956, the Wikipedia battle pin on the Kalchyk, Donetsk Oblast.
- **Battle of the Indus**: 33.0011/71.5497 (Kalabagh tradition) → 33.77/72.18, the pin given by the stop's own cited source (Wikipedia, Battle of the Indus; near the Kabul-Indus confluence). Site remains debated; aligned to the cited source.

### Quotes (all 7 checked, 3 repaired)

Verbatim-confirmed: the Otrar letter ("master of the lands of the rising sun...", Juzjani), the Bukhara "punishment of God" (Juvaini, canonical wording), the Qiu Chuji audience ("Adept, what Medicine of Long Life have you brought me from afar?", Waley verbatim), "Börte! Börte!" (SH §110).

**Repaired:**
1. **Burkhan Khaldun vow** — was a loose paraphrase; restored to de Rachewiltz §103: "Thanks to Burqan Qaldun I escaped with my life, a louse's life. Every morning I will sacrifice to Burqan Qaldun, every day I will pray to it: the offspring of my offspring shall be mindful of this and do likewise!"
2. **Pre-Jin prayer (1211)** — "I was not the author of this trouble; grant me strength to exact vengeance" is the prayer before the *Khwarezmian* campaign (Weatherford, after Juvaini), not the Jin war; it was misattributed here. Replaced with the attested verdict announced on the fourth dawn of the 1211 mountain prayer: "The Eternal Blue Sky has promised us victory and vengeance." (Weatherford). Source line corrected (Ratchnevsky attribution dropped).
3. **Liupanshan deathbed counsel** — was a sanitized condensation; restored to the canonical Rashid al-Din wording: "The greatest joy for a man is to defeat his enemies, to drive them before him, to take all they possess, to see those they love in tears, to ride their horses, and to hold their wives and daughters in his arms." The register says the canon is true; the canon is not polite. The unverifiable "tr. Thackston" claim dropped from the source line.

### Campa

Six campa ran 111-117 words — inside the linter's 55-120 tolerance but over the 60-110 target (wooden collar, Indus leap, Amu Darya sage, Avarga rest, Liupanshan death, secret cortège). Each trimmed to 106-110 with no episode, name, or image lost; two hedges ("He is said to leave", "By tradition") removed as off-register — the canon is true, the date_confidence field already carries the epistemics. All campa now 60-110, present tense, register intact.

### Verdict

Dataset is sound. Myth kept whole: the blood clot, the vow, the louse's life, the mud of Baljuna, the molten silver, the thousand horses over the grave — all stand as the canon tells them.
