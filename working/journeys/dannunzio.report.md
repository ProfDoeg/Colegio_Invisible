# d'Annunzio journey — research report

**Dataset:** `dannunzio.journey.json` — 68 stops, 8 segments, 1863–1938, register: national mythology (the canon is true). 17 stops carry canonical quotes; the rest are honestly null.

## Sources
Primary verification by web search (Italian sources): it.wikipedia (Discorso di Quarto, Volo su Vienna, Beffa di Buccari, Impresa di Fiume, Reggenza del Carnaro, Notturno), the Vittoriale's own almanacco (fiume.vittoriale.it — "Santa Entrata"; vittoriale.it — the death in the Zambracca), Wikisource (Notturno, Prima offerta — incipit quoted verbatim), Marina Militare (Buccari bottle text verbatim), mirkoriazzoli.it (both Vienna leaflet texts), queryonline.it (the 1880 fake-death notice: Gazzetta della Domenica, 13 Nov 1880, signed "G. Rutini"), ANVGD (Cantrida/Pittaluga). Backbone biographies cited per stop: Andreoli *Il vivere inimitabile*, Woodhouse *Defiant Archangel*, Hughes-Hallett *The Pike*.

## Judgment calls
- **Two births:** the parish birth (attested) and the brigantine *Irene* legend (traditional) are separate stops — the register demands the legend be placed as an event.
- **Vienna leaflet:** quoted d'Annunzio's own prolix text ("In questo mattino d'agosto…"), not Ojetti's famous "saluto a tre colori" — that one is narrated in the campa with attribution, since the quote field is for the traveler's words.
- **"Fate fuoco su queste medaglie!"** — wording varies across chronicles; kept as quote with the source note flagging it as chronicle/memoir tradition.
- **Duel of 1886** (Magnico, the scalp wound, the baldness legend): dated `inferred`; the baldness-from-perchloride is tradition and framed as such.
- **La Gioconda** premiere venue was uncertain, so the stop is the dedication at the Capponcina instead.
- Mausoleum stop dated to the state funeral (1938-03-03); the 1963 translation of the body is folded into the campa.
- The Garda/Goethe resonance requested for the corpus is planted twice: Villa Cargnacco arrival and the mausoleum finale (Malcesine, "one water").

## Gaps
Exact dates for Cicognini entry (autumn 1874), Naples arrival, Paris arrival, Puglia prow installation, and the Verona station meeting (late Sept 1937) are inferred/traditional. Letters to Duse are narrated (her "Vedo il sole" appears in campa) but not quoted in the quote field, which I reserved for his words; the Gioconda dedication stands in for the epistolary voice.

## Five richest episodes
1. **The road to Francavilla, 13 Nov 1880** — the self-authored death notice: the first myth, and it rhymes with the desk-death of 1938.
2. **The dark room of the Casetta Rossa, 1916** — the blinded seer writing Notturno on 10,000 paper strips; incipit quoted verbatim.
3. **The flight over Vienna, 9 Aug 1918** — two stops (San Pelagio dawn, Stephansplatz); an air raid made entirely of rhetoric.
4. **Cantrida, 12 Sept 1919** — the breast of medals offered to General Pittaluga's guns; the army defects into the myth.
5. **The Carta del Carnaro, 8 Sept 1920** — music as a religious and social institution of the state (art. LXIV quoted) — the natural anchor for a music-bearing quipu corpus.

## Verification pass (2026-07-05)

Independent structure-and-canon-fidelity check of `dannunzio.journey.json`. The myth was not touched; only geography was repaired.

**Structure.** JSON parses; 8 segments, 68 stops (within the 50-70 target — no additions needed); every stop carries the full key set (`name, date, date_confidence, lat, lng, campa, quote, quote_source, sources, suggested_refs`). All dates ISO, strictly non-decreasing across the whole journey (same-day clusters at the birth, the Vienna flight, and the Santa Entrata are correctly ordered internally). Confidence labels are honest: `attested` for documented events (Quarto, Buccari, Vienna, Ronchi, the death), `traditional`/`inferred` where the canon is looser.

**Campa voice.** All 68 stops fall in 76-108 words, present tense throughout. The great episodes (Quarto beatitudes, Buccari, Vienna leaflets, the Fiume balcony, the Natale di sangue, the Zambracca death, the mausoleum finale) are not flat — spot-read and confirmed. The mausoleum stop honestly narrates the later construction ("and later raise over him the mausoleum") while keeping the 3 March 1938 funeral as the attested date.

**Quotes.** 6+ spot-checked against the canon: Quarto beatitudes, Buccari bottle message ("...pronti sempre a osare l'inosabile"), Vienna autograph leaflet, Fiume balcony proclamation, Carta del Carnaro art. LXIV, "Io ho quel che ho donato", plus "Il Verso è tutto", "vado verso la vita", the Pioggia nel pineto incipit, Notturno's prima offerta, and "Vittoria nostra, non sarai mutilata" (Corriere della Sera, 24 Oct 1918). All verbatim per the canonical texts; nulls remain where the canon records no words. Nothing nulled.

**Coordinates.** 12 sites web-checked against OSM/Nominatim; the remainder verified against known landmarks. 25 stop coordinates repaired in place:

- Casa natale, Corso Manthonè, Pescara → 42.4612, 14.2119 (was ~300 m SE)
- Convitto Cicognini, Prato (2 stops) → 43.8789, 11.0932
- Conventino di Michetti, Francavilla (2 stops) → 42.4156, 14.2939 (was ~1 km off)
- Eremo dannunziano, San Vito Chietino → 42.2977, 14.4622 (was ~1.4 km off)
- La Capponcina, Settignano (3 stops) → 43.7809, 11.3200 (via della Capponcina)
- Scoglio/Monumento dei Mille, Quarto → 44.3882, 8.9943 (was ~500 m E)
- Castello di San Pelagio (Vienna-flight field) → 45.3142, 11.8219 (was ~4 km off — the largest error)
- Guvernerova palača, Rijeka (4 Fiume stops) → 45.3296, 14.4427
- Vittoriale cluster (Prioria/entrance, 8 stops) → ~45.6244, 10.5642; Puglia prow → 45.6253, 10.5656; Mausoleo degli Eroi → 45.6259, 10.5659

Verified as accurate and left untouched: Palazzo Altemps, Montecitorio, Teatro Costanzi, Hotel Regina (via Veneto), Campidoglio, Hotel Danieli, Casetta Rossa, Théâtre du Châtelet, Arcachon/Le Moulleau, Montichiari airfield, Timavo mouth, Grado, Bakar, Kantrida, Ronchi, Kotor, Stephansplatz, Verona Porta Nuova, Chieti, Athens, Genoa, Naples, Milan theatres, Marina di Pisa.

**Post-repair validation.** Re-ran the full python check after the edits: parses, 68 stops, 17 quotes, chronology intact, word counts in range, all coords float. Dataset is sound.
