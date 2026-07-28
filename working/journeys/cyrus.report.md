# Cyrus the Great — The Lord's Anointed, Anshan to the Massagetae

**35 stops · 7 segments · 22 quotes · c. 600–530 BC (julian_bce)**

## Sources

Four canons braided, as the prompt asks, and narrated as true:

- **Herodotus, *Histories* Book I** — the spine. The Astyages dreams (1.107–8), the exposure and Spako the she-dog (1.108–13), the boy-king game and recognition (1.114–16), the Thyestean revenge on Harpagus (1.117–19), the hare-letter and the parable of the two days (1.123–26), the fall of Ecbatana, Croesus (1.46–91), the camel stratagem and the pyre (1.79–88), the fall of Babylon by the diverted Euphrates (1.190–91), and the whole Massagetae/Tomyris finale (1.201–14).
- **Scripture** — Isaiah 44:28–45:1 (shepherd, anointed), Ezra 1 (the edict, the restored vessels), Ezra 3 (the foundation laid), Daniel 5 (Belshazzar's feast, MENE MENE TEKEL UPHARSIN). The KJV wording is quoted verbatim.
- **The cuneiform record** — the **Cyrus Cylinder** (titulature; the return of gods and peoples, lines 20–33) and the **Nabonidus Chronicle** (the 550 BC fall of Astyages; Opis; Sippar 14 Tashritu; Ugbaru/Gubaru entering Babylon "without a battle"; Cyrus's own entry 3 Arahsamnu). These are the attested anchors.
- **Strabo 15.3.7 / Plutarch, *Alexander* 69 / Arrian 6.29** — the Pasargadae tomb-epitaph via Aristobulus, and Alexander weeping there.

Xenophon's *Cyropaedia* is cited as canon but leaned on lightly and by name only — it is a philosophical romance whose geography is invented, so I did not build stops from it, using it only where it agrees with the frontier tradition (the eastern satrapies).

## Judgment calls, folds, and gaps

- **Two registers of date-confidence.** The cuneiform gives three genuinely *attested* pin-points: 550 (Astyages), the autumn 539 sequence (Opis 25 Sept ≈ 12 Oct entry), and 538 Babylon. Everything from the exposed-infant cycle through the Persian revolt is *traditional* (Herodotean legend), and the eastern satrapies are *inferred* (attested as fact, undatable in detail). I marked them honestly rather than forcing precision.
- **The great tradition-fold** is that Cyrus's birth-legend is a *doublet* of Sargon, Moses, Romulus — the exposed royal infant, the substitute corpse, the animal-nurse (Spako = "bitch," which Herodotus himself flags as the seed of the she-dog rumor). I narrated it straight, in-register, but the folkloric shape is the point.
- **Where the canons collide on Cyrus's death**, I chose Herodotus (Massagetae, Tomyris, the head in the wineskin) because it is the richest and the one the art tradition ran with. Ctesias, Berossus, and Xenophon each give a different, gentler death; the prompt's own itinerary names the Tomyris version, so that is the true one here.
- **Coordinates**: Anshan = Tall-i Malyan; Ecbatana = Hamadan; Pasargadae, Sardis, Delphi, Babylon, Opis, Sippar, Susa, Jerusalem are firm. The Massagetae stops and Cyropolis sit on the Jaxartes (Syr Darya) frontier — genuinely uncertain ground, placed at the traditional NE limit and marked *traditional/inferred*.
- **The vessels-as-hinge**: the same Temple gold Nebuchadnezzar looted is profaned by Belshazzar in Daniel 5 and handed back by Cyrus in Ezra 1:7. I let that object thread the two scriptural episodes together, which is faithful to the canon's own cross-reference.

## The five richest episodes

1. **The boy-king game** (Ecbatana) — the whipped noble's son, the frank face, Astyages seeing his own blood. The prophecy fulfills itself in a children's game.
2. **Croesus on the pyre** (Sardis) — "O Solon, Solon!", the fire already caught, and Apollo's black storm out of a clear sky. Herodotus's masterpiece of dramatic irony.
3. **Belshazzar's feast** (Babylon) — the disembodied hand, the writing on the plaster, Daniel's MENE MENE TEKEL — the miraculous narrated as fact, dated to the night of the fall.
4. **The edict and the Cyrus Cylinder** (Babylon) — the gentile named messiah in Isaiah, the captives and their gods sent home, cuneiform and scripture in rare agreement.
5. **Tomyris and the wineskin** (the steppe) — the wine-trap, Spargapises's suicide, the oath by the Sun, and the severed head plunged in blood: "Drink your fill."

## Connections in the atlas

Cyrus faces, per the prompt, **Zoroaster's Persia** and **Solomon's Temple** — the fire-religion of his own plateau and the sanctuary he commands rebuilt. He is the hinge between them and the atlas's whole scriptural quarter: he is the *end* of the exile that **Moses** began and the prophets carried, the deliverer Isaiah named. Downstream he opens onto **Jesus** (Second-Temple Judaism exists because of this edict). As a conqueror-king whose life is half chronicle and half legend he rhymes with **Hannibal** (the childhood oath vs. the childhood game; both careers scripted by a foretold destiny) and with **Alexander** — who closes Cyrus's story by weeping at his tomb, making the Pasargadae epitaph a literal bridge from this journey to the Macedonian's. Where **Muhammad** and **Charlemagne** found empire-and-faith fused, Cyrus is the archetype of the *tolerant* imperator whose legitimacy is granted by the gods of the conquered themselves.

---

## Verification (2026-07-05)

Structural and canon-fidelity pass. Repairs made in place; re-validated with Python.

**1. Parse & schema.** JSON parses. Top-level keys, segment keys (`name`, `stops`), and all ten stop keys (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`) match the `joan_of_arc.journey.json` sibling template exactly — zero key diff. 7 segments, 35 stops, 22 non-null quotes, confirming the researcher's counts.

**2. Chronology & confidence.** All 35 dates sort strictly ascending under numeric BCE parsing, globally and within every segment (−0600 earliest → −0530 latest; 0 violations). The two Babylon-fall stops correctly share −0539-10-12 (Belshazzar's feast + the diverted Euphrates are the same night). Confidence tiers are honest: the Herodotean legend cycle (birth, revolt, Croesus, Massagetae) is `traditional`; the undatable eastern satrapies are `inferred`; the cuneiform anchors (550 Astyages, autumn-539 Opis/Sippar/entry, 538 Babylon) and the physical tomb are `attested`. Subject dies within the journey (Massagetae) — correct: Cyrus is not a living person, so ending at his death and tomb is right.

**3. Coordinates — 12 spot-checked, all within tolerance, none fixed.**
- Ecbatana/Hamadan 34.799/48.515 — exact (34.804/48.510).
- Anshan/Tall-i Malyan 29.999/52.400 — ~1 km (30.007/52.405).
- Pasargadae tomb 30.194/53.178 — ~1 km (30.190/53.167).
- Sardis 38.488/28.040 — exact (38.486/28.038).
- Delphi 38.482/22.501 — exact.
- Babylon 32.542/44.421 (+ small per-stop variants) — ~1 km (32.535/44.419).
- Opis 33.150/44.700 — ~4 km (site itself only tentatively located; 33.18/44.70).
- Sippar 33.060/44.267 — lat exact, lng ~1.4 km (33.059/44.252).
- Susa 32.189/48.257 — exact.
- Jerusalem 31.778/35.235 — Temple Mount, exact.
- Cyropolis 40.280/69.620 — traditional Istaravshan/Kurkath region on the Jaxartes (site undetermined in the canon).
- Massagetae stops (Araxes/steppe, ~44.8–45.2 N / 65.5–66.2 E) — the lower Syr Darya / Aral steppe, the traditional Massagetae ground; genuinely uncertain and marked as such.

**4. Quotes — 6+ spot-checked against the canon.**
- Daniel 5:25-28 (MENE MENE TEKEL UPHARSIN + interpretation) — verbatim KJV, faithfully stitched.
- Ezra 1:2 and 1:7 — verbatim KJV; 1:3 condensed with ellipsis, faithful.
- Cyrus Cylinder lines 20-22 (titulature, peaceful entry) and 32-33 (return of gods and peoples) — match the Livius translation.
- Herodotus 1.212 (Tomyris's oath by the Sun) and 1.214 (over the head in the wineskin) — faithful modernizations of the Rawlinson wording.
- Tomb-epitaph (Strabo/Plutarch via Aristobulus) — standard published translation variant.
- **One fix:** the Isaiah 45:1 / 44:28 quote paraphrased the 44:28 clause as "that saith of Jerusalem, She shall be built." Restored to KJV: "even saying to Jerusalem, Thou shalt be built." (Isaiah 45:1 was already verbatim.)

**5. Campa register & length.** All present-tense, in the mythic-true register; the great episodes (boy-king game, Croesus's pyre, Belshazzar's hand, the Cylinder, Tomyris's wineskin) carry their full weight. Four campas exceeded the 110-word ceiling on first pass (Croesus pyre 114, Jerusalem foundation 114, Pasargadae tomb 112, and the pyre again after a partial trim). **Trimmed all four** to land inside 60–110 without losing an image or shifting register. Final range 78–108 words.

**6. Stop count.** 35 stops sits inside the 30–45 target and covers the canon's whole arc across all four braided sources; no additions warranted.

No myth was debunked. Theophany (Apollo's rain), marvel (the hand on the wall), and prophecy-fulfilled (Isaiah's named messiah) all stand, held in place by confidence tiers rather than excised.

## Pin normalization — 2026-07-13
Connectivity audit found cyrus to be the atlas's ONLY unconnected journey — and only because the Jerusalem stop ("the foundations of the Second Temple laid", -0537-07-01) sat at 31.778,35.235: one truncated digit (~40m) off the Temple Mount canonical pin 31.778,35.2354 shared byte-exactly by abraham, jesus, muhammad and solomon. Repinned to the canonical. The edict of return now lands on the same coordinate where Abraham binds Isaac, Solomon builds, Jesus overturns the tables, and Muhammad ascends.
