# Juan Domingo Perón — Lobos to Buenos Aires (1895–1974)

**39 stops · 7 segments · 12 quotes · gregorian · register: national mythology, the canon is true.**

The canon here is Perón's own speeches and memoirs plus the vast Argentine historiography of Peronism. The register treats the movement's sacred dates and the myth of Perón-and-Evita as true events to be placed and dated — not endorsing the ideology, narrating the deeds.

## Sources
- **Instituto Nacional Juan Domingo Perón** (jdperon.gob.ar) and **es.wikipedia** for the spine of dates.
- **educ.ar** and **Página/12** for the verbatim 17 October 1945 balcony speech ("tres honras... el primer trabajador argentino").
- **Infobae** long-form features for the granular episodes: Martín García (the "complicit doctor" and the pleurisy pretext), the Luna Park meeting, the Happyland cabaret in Panama, the last speech ("la más maravillosa música"), the death at Olivos.
- **es.wikipedia — Exilio de Perón / Masacre de Ezeiza / Bombardeo de la plaza de Mayo** for the exile itinerary, Ezeiza, and the June 1955 bombing.
- **Gestar** and Wikipedia for the Five-Year Plan, railway nationalization, and the three banners.
- **La Nación / Río Negro / Museo de la Familia Perón (Chubut)** for the Patagonian boyhood (Camarones, Sierra Cuadrada, La Porteña).
- **Prodavinci / La Nación** for the Italian mission (Merano/Tridentina, Aosta alpine school, Piazza Venezia, 10 June 1940).

## Judgment calls
- **Birth (1895, Lobos):** the canon's own date and place, though revisionists argue 1893 / Roque Pérez. I narrate the kept date and note the dispute in-campa — the myth's own fold.
- **Coordinates:** major sites use standard city coords; La Porteña / Sierra Cuadrada is `inferred` (no fixed monument; approximate interior meseta). Camarones is confirmed exact.
- **Milan corpse (1957 marker):** the concealment spanned years; I dated it to the burial-under-false-name phase (`traditional`) and placed it at Musocco. It sits inside the Madrid segment thematically, breaking strict chronology so the corpse-odyssey reads as one thread — flagged.
- **Quotes:** all 12 are attested recorded words (Perón, Eva, or the national announcement). Where tradition alone records a line (Eva's "gracias por existir" at Luna Park) I attributed it to tradition, not fact. Stops without recorded words carry `null` honestly.
- **Register restraint:** Perón's admiration of Mussolini's corporatism is placed as event (what he observed and carried home) without endorsement; the balcony/plaza fusion is drawn as the through-line from Piazza Venezia 1940 to Plaza de Mayo 1945.

## The tradition's folds and gaps
- **17 de Octubre** is the movement's liturgical center — its date recurs as sacred (the Junín marriage five days after; the Villarrica refuge dated to a 17th; the villa named *17 de Octubre*). The mythos self-references its own founding day.
- **Two-headed movement:** the canon papers over the union-right / guerrilla-left schism that erupts as blood at Ezeiza. I let the massacre stand as the fracture the myth cannot heal.
- **The wandering corpses** (Eva's 16-year exile in Milan; Perón's own posthumous mutilations) are a genuine national gothic the histories dwell on; only Eva's belongs to his lifetime and is included.

## Five richest episodes
1. **17 October 1945, the balcony and the descamisados** — the birth of Peronism; feet in the fountains, the night-time roar, verbatim quote.
2. **Piazza Venezia, 10 June 1940** — Perón watching Mussolini's balcony fuse leader and crowd; the seed of his own balcony myth.
3. **Ezeiza, 20 June 1973** — two million welcomers, homecoming turned massacre; the movement drawing its own blood.
4. **The renunciamiento / death of Evita (1951–52)** — the passion play on 9 de Julio and "entró en la inmortalidad."
5. **Panama's Happyland cabaret (1956)** — the exile meeting Isabel, the $300 contract; the future first woman president rising from a nightclub as Eva rose from radio.

## Connection to the atlas
This journey rhymes deliberately with its siblings in the directory. Perón's **exile-and-return** structure directly echoes **San Martín** and **O'Higgins** (the liberators who left and were called back) — the prompt's named mirror. His Argentine ground overlaps **Che Guevara** (the same Buenos Aires, the opposite politics of the same era) and the Argentine founders **Belgrano** and **Alvear**. His Italian station (Merano, Bolzano) crosses **Goethe's Italian Journey** on the same Dolomite road, and his corporatist study touches **D'Annunzio's** Italy. Together they extend the atlas's Argentine and Southern-Cone thread while giving it its 20th-century caudillo — the balcony as the recurring mythic site.

---

## Verification (2026-07-05)

Structural, chronological, canon-fidelity, coordinate, and quote pass against the sibling schema (`joan_of_arc.journey.json`). Repaired in place; JSON re-validated (parses; 39 stops, 7 segments; all campa 60–110 words; full key set on every stop; numeric lat/lng).

**Schema & structure — PASS.** Top-level keys, segment keys (`name`, `stops`), and the ten-key stop set (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`) are byte-identical to the Joan of Arc sibling. 39 stops in 7 segments (4/4/4/7/6/6/8), above the 30–45 target — no stops added.

**Chronology — PASS (one deliberate fold).** Dates ascend across the whole file except the single flagged exception: **Milan — the hidden corpse of Eva (1957)** sits after **Puerta de Hierro villa (1960)**. This is the intended corpse-odyssey thread placed thematically in the Madrid segment, already disclosed in the Judgment calls above; left as authored. Gregorian throughout, so no julian/BCE sign issue arises. Perón dies in 1974, so the journey correctly closes at death (not a living-person case).

**Confidences — PASS.** Real anchors are `attested` (birth register, Colegio Militar entry, the Italian postings, every dated political act from 1943 on). The soft early-Patagonia and doctrinal-teaching stops are `traditional`; La Porteña/Sierra Cuadrada and the Milan burial marker are `inferred`/`traditional` — honest.

**Coordinates — web-spot-checked 12 stops; 2 corrected, 10 confirmed.**
- **FIXED — Colegio Militar de la Nación:** was `-34.5089, -58.5236` (a point ~13 km off, in the wrong suburb). The Colegio is at El Palomar; corrected to **`-34.5977, -58.6060`**.
- **FIXED — Milan / hidden corpse of Eva:** was `45.4642, 9.1900` (central Milan, by the Duomo), but the campa names the **Musocco** cemetery (Cimitero Maggiore, Zone 8, NW Milan) where Eva was buried as "María Maggi." Corrected to **`45.5050, 9.1340`**.
- Confirmed within tolerance: Lobos (`-35.1836/-59.0956` vs town center −35.185/−59.091), Camarones (near-exact), Río Gallegos (exact), Merano (exact), Aosta (exact), Isla Martín García (exact), Ezeiza (exact), Olivos (~1 km, fine for the quinta), Puerta de Hierro Madrid (edge of the neighborhood near the villa/golf club, fine), Colón Panama (near-exact).

**Quotes — spot-checked 8 against the canon; all hold, none nulled.**
- 17 Oct 1945 balcony "tres honras… soldado… patriota… primer trabajador argentino" — attested (educ.ar / Página 12 / INJDP). Verbatim.
- 12 Jun 1974 "la más maravillosa música… la palabra del pueblo argentino" — attested (Infobae / Gestar). Verbatim.
- Eva's renunciamiento (22 Aug 1951) — the file's "no renuncio a la lucha ni al trabajo… renuncio a los honores" is a widely-attested rendering of the line (co-circulates with "no renuncio a mi puesto de lucha, renuncio a los honores"); a real variant, not a paraphrase-invention. Kept.
- "Eva Perón entró en la inmortalidad" (26 Jul 1952) — attested; Apold's official communiqué after Furnot's radio announcement. Correctly attributed to the national announcement.
- 1973 Congress "un hombre demasiado humilde al servicio de una causa siempre demasiado grande para mí" — attested in his Congress addresses. Kept.
- "Los ferrocarriles son argentinos" (1 Mar 1948) — the canonical slogan of the Retiro nationalization; honestly labeled a Peronist proclamation, not a verbatim Perón line. Kept.
- "El día que creamos la Secretaría… es el día inicial de nuestro movimiento" and the three banners "Soberanía política, independencia económica y justicia social" — both authentic Peronist formulations, correctly attributed.

**Campa / register — PASS.** All 39 in the 60–110 band (85–103), present tense, in the national-mythology register. The great episodes (the balcony, Piazza Venezia, Ezeiza, the renunciamiento, the last balcony) carry their weight and are not flat.

**Net changes:** 2 coordinate fixes; no stops added, no quotes nulled, no campa rewritten. No debunking — the balcony liturgy, the Perón–Evita myth, and the corpse-odyssey stand as authored, marked by confidence rather than removed.
