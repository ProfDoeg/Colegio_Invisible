# Jesus of Nazareth — journey report

**Traveler:** Jesus of Nazareth (Yeshua, the Christ)
**Span:** c. 4 BC – AD 33 (julian). 46 stops in 7 named segments.
**Register:** reverent mythography — the four Gospels taken whole and true. Theophanies, miracles and the Resurrection are narrated as events, because in this register they are. Quotes are the King James text (public-domain, canonical-sounding English); 45 of 46 stops carry a recorded word of scripture, the sole `null` being Deir al-Muharraq (Coptic tradition, no logion attached).

## Sources
- **The four Gospels** (Matthew, Mark, Luke, John) and Acts 1 — the spine of every stop; cited per-stop by book/chapter/verse.
- **Site geolocation** verified against latitude databases and pilgrimage references: Church of the Nativity (31.704, 35.208), Basilica of the Annunciation (32.702, 35.298), Qasr el-Yahud on the Jordan, Wedding Church at Cana (Kafr Kanna), Capernaum synagogue, Mount of Beatitudes, Church of the Multiplication at Tabgha, Kursi/Gergesa, Banias/Caesarea Philippi, Mount Tabor, Bethany/Al-Eizariya (Tomb of Lazarus), the Cenacle on Mount Zion, Gethsemane / Church of All Nations, the Church of the Holy Sepulchre (Golgotha + Tomb), Bethphage, El-Qubeibeh (Emmaus), the Chapel of the Ascension on Olivet. Coptic Holy Family sites (Abu Serga in Old Cairo; Deir al-Muharraq at Qusqam, Asyut) placed from the Coptic pilgrimage tradition.

## Judgment calls
- **Coordinates = traditional sites, not archaeological certainties.** I used the site where the canon/Church *locates* the event (e.g. Golgotha and the Tomb are placed at the Holy Sepulchre, the western/Catholic reading; the Garden Tomb was not used). Transfiguration is placed on Mt Tabor (the dominant tradition) though the Gospel names only "a high mountain" and some hold Hermon.
- **Emmaus** has four rival identifications (El-Qubeibeh, Nicopolis, Motza, Abu Ghosh); I placed the stop at El-Qubeibeh, the Franciscan tradition, and named Nicopolis in the refs.
- **date_confidence:** every stop is marked `traditional` — honest for a life whose day-by-day chronology is liturgical/traditional rather than documentary. The *frame* is historically anchored (Herod the Great's death in 4 BC; Pilate's prefecture AD 26–36; a Passover crucifixion), but no individual Gospel scene is attested to a calendar day, so I did not inflate any to `attested`.
- **Dates & the BCE encoding:** the Nativity is set at Dec of 5 BC (`-0005-12-25`), nine liturgical months after the Annunciation (25 March, `-0005`), with the Magi and Presentation falling in early 4 BC (`-0004`). The ministry is compressed into the traditional three-Passover span (John's chronology), AD 29–33. Ascension dated 40 days after Easter (Acts 1).

## The tradition's own time-folds and geographic splits
- **Two infancy narratives, harmonized.** Matthew (Magi → flight to Egypt → return) and Luke (shepherds → Presentation in the Temple → Nazareth) are independent. The Church folds them into one sequence; I kept both, which produces the classic tension of the Presentation (Luke, 40th day, at the Temple) sitting near the Flight (Matthew). This is a genuine tradition-fold, not an error — the two evangelists' timelines are stitched, and I preserved both events rather than choosing.
- **A folded ministry.** The Synoptics read as roughly one year around Galilee; John supplies three Passovers and the Judea/Samaria material (Sychar, Jerusalem feasts, the woman taken in adultery). I used John's longer frame so both the Galilean signs and the Jerusalem/Samaria episodes have room.
- **Galilee as the miracle-lake.** Stilling the storm, the Gerasene demoniac (east shore, Kursi), the feeding of the 5,000 (Tabgha), and walking on the water all ring the one small lake within a few coordinates of each other — a tight geographic cluster the itinerary makes visible.
- **The Passion collapses into ~72 hours** across a few hundred metres of Jerusalem: Cenacle → Gethsemane → Caiaphas → Pilate/Herod → Via Dolorosa → Golgotha → Tomb — the densest spatial-temporal knot in the whole corpus, the center it is all built to turn around.

## The five richest episodes
1. **The Baptism in the Jordan** (Qasr el-Yahud) — the whole Trinity manifest at once over the river: the opened heavens, the descending dove, the Father's voice. The public beginning.
2. **The Transfiguration** (Mount Tabor) — face like the sun, Moses and Elias, the bright cloud and the voice; the glory shown to three before the descent to the Cross.
3. **The raising of Lazarus** (Bethany) — "I am the resurrection"; the four-days-dead man walking out bound in graveclothes; the last sign that seals the council against him.
4. **Gethsemane** — the agony, the sweat like blood, the strengthening angel, the sleeping disciples, Judas's kiss; the will bent to the Father's in the dark.
5. **Golgotha and the empty tomb** — the seven words, the darkness, the rent veil, the centurion's confession — answered on the third day by the angel at the stone and "He is not here: for he is risen." The hinge of the register.

---

## Verification (2026-07-05)

Structure- and canon-fidelity pass. The myth stays whole: no theophany, miracle, or Resurrection scene was touched. Two coordinate/date corrections and confirmation of quote and site fidelity.

**Schema.** JSON parses. Top-level keys, segment keys, and the ten-key stop shape (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`) match the sibling `joan_of_arc.journey.json` exactly. 7 segments, 46 stops, 45 quotes + 1 honest null (Deir al-Muharraq). Stop count sits above the 45-65 target floor, so no stops were added.

**Chronology — one fold corrected.** The dataset was monotonic within every segment, but a single cross-segment back-step existed: the Massacre of the Innocents was dated `-0004-01-10` and the Flight to Egypt `-0004-02-01`, both *before* the Presentation in the Temple (`-0004-02-02`) that closes the previous segment. This was the Matthew/Luke infancy time-fold the report flags, but the specific day-dates made the itinerary read backward. Since these are liturgical/traditional dates and the canon has Herod act *after* waiting on the Magi (who depart at Epiphany, `-0004-01-06`), the Massacre was moved to `-0004-02-05` and the Flight to `-0004-02-06`, just past the Presentation. The whole journey is now strictly monotonic (numeric BCE sort) with no loss of the fold's substance. All `date_confidence` values remain `traditional` — appropriate, and not inflated.

**Coordinates — one fix.** Web-spot-checked 11 sites against Wikipedia / geolocation databases. Correct within tolerance: Church of the Holy Sepulchre (Golgotha/tomb/empty-tomb cluster, 31.778/35.229), Mount Tabor (32.687/35.390), Basilica of the Annunciation (32.702/35.298), Qasr al-Yahud (31.838/35.539), Church of the Nativity (31.703/35.205), Capernaum (32.880/35.573), Kursi/Gergesa (32.826/35.650). **Fixed:** Deir al-Muharraq was at `27.2258, 30.8925`, ~20 km off the actual monastery near Cusae; corrected to `27.3845, 30.7795` (Wikipedia).

**Quotes — 7 spot-checked, all exact KJV, none altered.** Luke 2:14 (Gloria), Mark 5:41 (Talitha cumi), Matthew 3:17 (the voice at Jordan), John 11:25 (I am the resurrection), Mark 14:8 (the anointing), Luke 23:46 (into thy hands) — every one a verbatim King James match to its cited chapter-and-verse. The single null (Deir al-Muharraq, Coptic tradition, no logion) is honest and was left null.

**Voice.** All 46 campa are present-tense, reverent mythography, 88-114 words (four run 111-114, within the researcher's 58-115 tolerance and warranted by the density of those scenes: the Presentation, Sychar, Nain, the anointing at Bethany). The five great episodes — the Baptism with the whole Trinity over the river, the Transfiguration, Lazarus called forth, the Agony in the garden, and Golgotha with the empty tomb — are all rendered at full theophanic weight, none flat.

**Result:** PASS after 2 fixes (1 coordinate, 1 date-fold spanning 2 stops). File re-validated: parses, monotonic, schema-matched.
