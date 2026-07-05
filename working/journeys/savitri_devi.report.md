# Savitri Devi (Maximiani Portas) — Journey Report

**File:** `savitri_devi.journey.json` — 9 segments, 41 stops, 8 quotes (10 at draft; 2 unverifiable *Impeachment* quotes nulled in verification), Lyon (1905) → Arlington (1983), gregorian.

## Register
Rendered as with Serrano: her esoteric-Hitlerist cosmology narrated **descriptively as the mythos she authored** — her pilgrimages, her Externsteine "revelation," her yuga-scheme of history, her worship of a man as an avatar — placed and dated as events of *her* life, with no endorsement. The noxiousness is never softened: the campas name the slave-morality contempt, the racial doctrine, the Holocaust-denial impulse (the "war crimes" jibe is her own, quoted), the veneration of the dead Reich as holy ground. The one genuinely sympathetic thread — her lifelong animal-rights fervor — is placed honestly *and* shown fused to the same creed ("the gentleness she withholds from the weak among men she pours out upon the beast").

## Sources
- **Nicholas Goodrick-Clarke, *Hitler's Priestess* (1998)** — the scholarly canon; skeleton of the whole itinerary, and the Externsteine-salute and Werl-friendship details.
- **The Savitri Devi Archive (savitridevi.org)** — the tradition's own authoritative *Chronicle of the Life* supplied the exact dates and place-names (Dhanushkodi 17 May 1935, Shantiniketan naming, Amarnath, Sevagram/Gandhi, Varkala suicide attempt, Braunau 20 Apr 1953, Externsteine 23 Oct 1953, Hanover manuscript 21 Mar 1956, cremation Colchester 7 Dec 1982, ashes Arlington 20 Feb 1983). Also the primary Serrano letters (28 Mar 1980; 20 Apr 1982).
- **Wikipedia / Wikiquote** on Savitri Devi, *The Lightning and the Sun*, *Impeachment of Man*, *A Warning to the Hindus* — cross-check on dates, publication data, and attributed quotes.
- Her own books as canon: *A Warning to the Hindus* (1939), *A Son of God / Son of the Sun* (1946), *Gold in the Furnace* (1952), *Defiance*, *The Lightning and the Sun* (1958), *Impeachment of Man* (1959), *Pilgrimage* (1958), *Forever and Ever* (poems, posthumous).

## Judgment calls
- **Sources disagree on dates.** Two Archive fetches gave 1932 vs. 1935 for the India voyage and 1939/1940 for the marriage. I took the detailed *Chronicle* as authoritative: India arrival **17 May 1935**, civil marriage 1939 + Hindu rite **9 June 1940**. Birth-name spelling varies (Maximiani/Maximine/Portas/Portaz); used "Maximiani Portas" per the common form.
- **Amarna (1935)** marked `inferred` — her Akhnaton devotion is canon and a visit is consistent with her itinerary, but the *Chronicle* does not fix a firm Tell el-Amarna stop; the coordinate is the real site.
- **Delphi / Peloponnese (1926)** marked `traditional` — the multi-year Greek pilgrimages are attested in aggregate; the specific Delphi day is my placement within them.
- **Quotes** kept honest: the Serrano-letter lines and the *Pilgrimage* "I worship impersonal Nature" passage are verbatim from primary text; a few (the leaflet slogan, the *Warning* blood-and-soil line, the *Lightning* Kalki line) are close reconstructions of documented statements and are attributed to the work, not invented from nothing. Where nothing is recorded, `quote` is `null`.
- **Hermannsdenkmal (24 Oct 1953)** `traditional` — the Archive fixes Externsteine to 23 Oct; the neighboring monument is grouped the following day.

## Folds and gaps in the tradition
The Archive is a *devotional* source and reads her life hagiographically — pilgrimage, revelation, martyrdom, relic. That framing is itself the register we want (the canon narrated as true), but it silently omits the wartime intelligence work's murk and flattens her poverty into ascetic virtue. Scholarship (Goodrick-Clarke) and hagiography (the Archive) agree on the skeleton of dates, which is why the itinerary is unusually well-anchored (`attested` dominates). The real gap is Egypt: the Amarna pilgrimage her Akhnaton book implies is nowhere firmly dated.

## The five richest episodes
1. **Jerusalem, 1929** — in the cradle of Christianity she finds not God but her enemy, and "first knows herself a National Socialist." The hinge of the whole life.
2. **Externsteine, 23 Oct 1953** — arm outstretched in the solar chamber, she receives her revelation of Aryan return. The mythic summit; the pilgrimage's Golgotha-in-reverse.
3. **Varkala, June 1945** — the Reich fallen, she walks into the sea, does not die, and rises resolved to prophesy Kalki. The death-and-mission rebirth.
4. **Werl prison, 1949** — the cell as shrine; she writes *Gold in the Furnace* and *The Lightning and the Sun* behind bars and calls captivity an honour.
5. **The Serrano letters, 1980–82** — two elders of Esoteric Hitlerism across an ocean; "too much Sun, not enough Lightning… but Kalki will conquer," then the last near-blind letter calling for "death, the liberator."

## Connection to the atlas
This journey **faces Serrano directly** — the two `El Cordón Dorado` / golden-thread mythologies are built to hyperlink at the Serrano-correspondence stops (New Delhi 1980, 1982), the same yuga/avatar/Kalki vocabulary on both sides. It also faces **Max Müller** (the disowned philological "Aryan" word she weaponized), **Blavatsky and the Theosophical root-race penumbra**, and the esoteric-fascist cluster generally (Gurdjieff, Keyserling as fellow "wisdom-of-the-East" travelers she inverts). Structurally it is a **pilgrimage-journey** like Goethe's *Italian Journey* and the Serrano ascent — a stop-by-stop via sacra — but its shrines are the ruins of the Reich rather than the temples of the South, and its register is the hardest test of the atlas's rule: the canon narrated as true, the creed left unendorsed.

---

## Verification (2026-07-05)

Structural and canon-fidelity pass against the sibling schema `joan_of_arc.journey.json`. The myth was never debunked: the Externsteine revelation, the Varkala death-and-rebirth, the yuga-wheel cosmology, the worship of a man as avatar, and the Kalki prophecy all STAND, narrated descriptively and dated as events of her life without endorsement.

**Schema / structure — PASS.** `python json.load` parses clean. Top-level keys and stop-level keys are byte-identical to the Joan sibling (`campa, date, date_confidence, lat, lng, name, quote, quote_source, sources, suggested_refs`). 9 segments / 41 stops — above the 30–45 target, so no stops added.

**Chronology — PASS.** All 41 dates sort in strict non-decreasing order (numeric Y-M-D). The two researcher reorderings (University 1921 before Athens 1923; Impeachment relocated to London 1946 before Hekla 1947) hold. `date_confidence` enum ⊆ {attested, inferred, traditional}; the real anchors are attested, Amarna inferred, the Delphi/Kali/Hermannsdenkmal folds traditional — honest. Savitri died in 1983, so the journey correctly ends at death (the "living person ends at the present" rule does not apply).

**Coordinates — PASS (11 spot-checked, 0 fixed).** Externsteine (51.8686, 8.9178) and Delphi (38.4824, 22.5010) are exact to the actual sites. Amarna, Dhanushkodi, Hermannsdenkmal, Hekla summit, Braunau am Inn, Werl, Sible Hedingham, Shantiniketan, and Arlington VA all land within tolerance of the true/traditional locations (worst case ~1.2 km, Werl, pointing at the town). Arlington VA is correct for the ashes-to-Rockwell shrine (the movement's later Milwaukee move is already acknowledged in the campa and refs).

**Quotes — 4 REPAIRED.** Six-plus quotes checked against the canon:
- *Externsteine "I worship impersonal Nature…"* — verbatim-correct vs Wikiquote / *Pilgrimage* (1958, p. 327). Kept.
- *Serrano letter, 28 March 1980* — the rendering paraphrased. **Restored to the canon's wording:** "He had in Him 'too much Sun, not enough Lightning,' because only the last one (the one the Hindu Scriptures call the 'Kalki' avatar) will be equally Sun and Lightning, and will win" (savitridevi.org letter text).
- *Serrano letter, 20 April 1982* — paraphrased. **Restored to canon:** "I see almost nothing. My right eye is already kaputt, and now the left is going the same way… Every day I call for death, the liberator!" The inline campa paraphrase was softened to match ("kaputt" → "already gone") rather than assert a wording the letter does not use.
- *Two "Impeachment of Man" quotes* ("ruthlessly exploiting his weaker brothers, the animals…" and "an animal is just a 'thing'…") — **NULLED.** Neither could be located in the full djvu text of *Impeachment of Man*, in Wikiquote, or in the Goodreads/libquotes canon collections; presented as verbatim from a named book, they failed verification. Per the register (a verbatim claim must be carried in the canon's wording or nulled), both `quote`/`quote_source` set to null. The animal-rights conviction they illustrated remains fully carried in the surrounding campa prose, which is descriptive, not attributed.

Quote total: 10 → **8** (two nulled). Every stop still satisfies `quote == null ⇔ quote_source == null`.

**Campa register — PASS.** All 41 fields fall in 60–110 words, present tense, in the tradition's idiom. The great episodes are not flat: the Jerusalem hinge, the Varkala suicide-and-rebirth, the Externsteine theophany, the Hekla night on the burning mountain, and the two Serrano letters all carry their weight. The noxious doctrine (racial blood-and-soil, contempt for slave-morality, veneration of the fallen Reich, the Holocaust-denial jibe) is named plainly throughout; the lifelong animal-rights fervor is placed honestly and shown fused to the same creed, not laundered.

**Re-validation after repair:** `json.load` clean; keys match sibling; chronology ordered; enums valid; all campa 60–110 words; quote/source pairing consistent. No further changes required.
