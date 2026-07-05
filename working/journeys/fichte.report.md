# Fichte — The I That Posits Itself (Rammenau to Berlin, 1762–1814)

**Traveler:** Johann Gottlieb Fichte. **Shape:** 7 segments, 26 stops, 8 quotes, gregorian, all attested or traditional. Register: national mythology — the canon (his works, the letters, the founding legend) narrated as true.

## Sources
- **Stanford Encyclopedia of Philosophy** and **IEP** (utm) — the spine of the chronology: tutor years, the Königsberg pilgrimage (4 July 1791), Jena chair (May 1794), atheism dispute, Berlin/Erlangen, the Addresses, the university, death.
- **Wikipedia (Fichte; Addresses to the German Nation; Atheism dispute; An Attempt at a Critique of All Revelation; The Vocation of Man; Dorotheenstadt Cemetery)** — dates, anonymity of the 1792 book, death 29 Jan 1814, burial beside Hegel.
- **Deutsche Biographie / ADB (Wikisource) / Gemeinde Rammenau** — the goose-boy legend and the Miltitz sermon episode in the tradition's own German.
- **Primary text for quotes:** Wikisource *The Vocation of Man*, Part 3 (verbatim "Not merely to know, but according to thy knowledge to do, is thy vocation"); the Priory full text and Wikisource *Seventh Address* for the Addresses passages; the 1790 "new world" letter as transmitted by SEP/IEP.

## Judgment calls
- **Death date:** two dates circulate (27 vs 29 January 1814). I took **29 January** — the date carried by Wikipedia's infobox and the cemetery/biographical consensus; the 27th appears in older encyclopedia stubs. Flagged as attested.
- **Legend dates:** the sermon-recital (c. 1771) and the near-suicide on the bridge during the tutor years are **traditional** — real in the canon, loosely dated. Miltitz's arrival "too late for the sermon" is the received form of the story; I kept it as the tradition tells it.
- **Königsberg coordinates** use modern Kaliningrad (54.710, 20.510); **Jena–Auerstedt** given a single field coordinate between the two villages.
- **Quote sourcing:** where a quote is a standard rendering rather than a page-checked line (the 1794 Scholar's Vocation line; the §1 "absolute positing"; the 1798 divine-order line; the 1790 letter), I attributed to work and section, not to a specific pagination. The two load-bearing Addresses quotes (Seventh and Fourteenth) and the two Vocation lines are the strongest.

## The tradition's own folds / gaps
- The **atheism dispute** is a self-inflicted fall: Fichte's own threat of resignation was accepted. The canon reads it as martyrdom of a free thinker; the record shows a proud man out-manoeuvred. I narrated the pride, not just the persecution.
- The **Addresses** are the mythic peak but also the ideologically fraught node. Per the register I rendered them descriptively as national mythology, foregrounding Fichte's own *anti-racial* criterion (Seventh Address: belonging is by freedom and spirit, "wherever born, whatever language") rather than any later ethnic reading.

## Five richest episodes
1. **The sermon recited back entire** (Rammenau) — the founding miracle: memory wins the patron, the education begins.
2. **The pilgrimage to Kant** (Königsberg, 4 July 1791) — cold interview, then the book written in weeks that Kant gets published.
3. **The anonymous book mistaken for Kant's fourth Critique** (1792) — fame overnight.
4. **The Wissenschaftslehre in the packed hall** (Jena, 1794) — the I positing itself, the young idealists gathering.
5. **The Addresses under the bayonets** (Berlin, 13 Dec 1807) — the nation summoned into being by a philosopher's voice in an occupied city.

## Connection to the atlas
Fichte is a **pedagogy-and-nation** node bridging several existing journeys. He shares the German-idealist / Romantic dawn with **Jung** and the esoteric-idealist thread, and directly with the pedagogues **Fröbel** and the wider education strand (the university-founder as nation-builder). His self-positing "I" and the university-of-Berlin founding link the philosophy of freedom to the institution-building seen in the founder-figures of the atlas (**Bolívar, Belgrano, Miranda, San Martín/Alvear**) — the same 1806–1814 world-historical decade of Napoleon and liberation wars, viewed from the German rather than the American side. The Addresses' "nation summoned by a voice" rhymes with the oratory-as-founding motif running through the liberators.

---

## Verification (2026-07-05)

Structural, chronological, coordinate, and quote audit against the sibling schema (`joan_of_arc.journey.json`). Register preserved throughout — nothing debunked; the tradition's own legend beats (sermon recited entire, the bridge near-despair) stay, marked by confidence.

**1. Schema & parse.** JSON parses. Top-level keys identical to the Joan sibling (`calendar, register, segments, title, traveler, years`). Every stop carries all 10 required keys (`campa, date, date_confidence, lat, lng, name, quote, quote_source, sources, suggested_refs`). Segment objects match (`name, stops`). 7 segments, 26 stops, 8 quotes.

**2. Chronology & confidence.** All 26 dates sort in strict chronological order (1762-05-19 → 1814-01-29), no inversions. Confidences honest: real anchors `attested`; the two legend beats `traditional` (sermon recital c.1771; the itinerant-tutor/bridge years); school-enrollment approximations `inferred` (Meißen 1772, Poitiers-style dating not applicable here). Fichte died 1814 — not a living person, so ending on the typhus death is correct.

**3. Coordinates (12 spot-checked).** Rammenau, Meißen, Schulpforta, Jena, Leipzig, Zürich, Königsberg, Berlin, Erlangen, Jena–Auerstedt, Dorotheenstadt cemetery. All within tolerance except two, now **fixed in place**:
- **Schulpforta** was 51.155/11.727 (~1.9 km off); corrected to **51.1425/11.7522** (Wikipedia infobox for Pforta).
- **Rammenau** was 51.155/14.148 (~1 km east); tightened to **51.150/14.133** (Wikipedia infobox).
- Königsberg (54.71/20.51), Erlangen (49.599/11.006), Jena (~50.93/11.589), Zürich (47.373/8.541), Meißen (51.161/13.472), Dorotheenstadt (52.52/13.383) all verified acceptable against the actual/traditional sites.

**4. Quotes (6 spot-checked).**
- Vocation of Man Bk III, "Not merely to know, but according to thy knowledge to do, is thy vocation" — **verbatim** (Wikisource, Part 3). ✓
- Seventh Address, "…is of our blood; he is one of us, and will come over to our side" — **verbatim** (Wikisource). ✓
- Fourteenth Address, "You of all modern peoples have the seed of human perfection most decidedly in you…" — legitimate older-translation variant (Jones & Turnbull; Wikisource reads "most unmistakably lies"); second sentence verbatim. Retained. ✓
- 1790 Weisshuhn letter, "I have been living in a new world…" — **verbatim**. ✓
- Divine Governance (1798), "That living and efficaciously acting moral order is itself God…" — substantively verbatim (translation variant of "The living and efficaciously acting moral order is itself God. We require no other God…"). Retained. ✓
- **Death-stop quote — REPAIRED.** Was "I ought at all times to do that which conscience demands of me for its own sake — this is my whole vocation," attributed to Vocation of Man Bk III but **not present there** (paraphrase misattributed as verbatim). Restored to the canon's actual Bk III wording: *"To listen to it, to obey it honestly and unreservedly, without fear or equivocation,—this is my true vocation, the whole end and purpose of my existence."* (Wikisource, Part 3.)

**5. Campa register.** All 26 campas 74–101 words, within the 60–110 window; present tense throughout; the great episodes (sermon, pilgrimage to Kant, anonymous Critique, the I positing itself, the Addresses under the bayonets) are not flat.

**6. Stop count.** 26 stops — within the 25–40 target band (lower end). Not padded; the canon's beats are covered end to end.

**Repairs made in place:** Schulpforta coordinate; Rammenau coordinate; death-stop quote restored to canon wording. Re-validated: JSON parses, all keys intact, dates still ordered.
