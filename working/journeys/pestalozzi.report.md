# Pestalozzi journey — research report

**Dataset:** `pestalozzi.journey.json` — 53 stops, 8 segments, 1746-01-12 → 1827-02-19, 12 quotes.

## Sources
Primary spine: Arthur Brühlmeier's biography (bruehlmeier.info, the standard modern hagiographic-sympathetic life) and heinrich-pestalozzi.de (full texts of the Stanser Brief and Schwanengesang, plus the station-by-station biography). Cross-checked against the Historisches Lexikon der Schweiz (hls-dhs-dss.ch), English Wikipedia, socialnet.de, and Basel local history (grabmacherjoggi.ch) for the Czar Alexander audience. Quotes verified against the Stanser Brief full text, the Schwanengesang excerpts, and the photographed grave inscription (Wikipedia Commons / heinrich-pestalozzi.de).

## Judgment calls
- **Quotes with ellipses:** the Stans "Krätze" arrival description and the Altdorf question are quoted in compressed form (ellipses) from the Stanser Brief rather than risk word-perfect claims on long passages. The "midst of the children" passage is the standard anthologized wording.
- **Traditional-register quotes:** "Ich will Schulmeister werden!", the shoe-mending remark, the "lived like a beggar" line, and the deathbed forgiveness are canonical in the biographical tradition but not archival documents; each is sourced as such, never to a fake letter.
- **Epitaph:** quoted from the 1846 Keller inscription, omitting the dates line (one source claims the stone reads 1745 — unresolved, so left off).
- **Dates:** year-only events carry mid-year/seasonal dates marked `traditional` or `inferred`; only day-attested events (birth, wedding 30 Sep 1769, citizenship 26 Aug 1792, Stans commission/arrival/opening/closure, Jaqueli's death, Anna's death, birthday address, death, burial) are `attested`. Stans departure follows the 9 June sources.
- **Placement:** Jaqueli's death is staged at Burgdorf (where the family regathers) since the death place is not firmly attested; Herbart is placed at Burgdorf (historically correct) with Yverdon carrying Froebel, against the looser tradition that puts both at Yverdon.
- **Wagon omen:** Brühlmeier's October 1804 vineyard near-miss is folded into the Yverdon arrival stop and narrated as an omen, per register.

## Gaps
Exact father's death date (1751 only); exact Neuhof move-in day; Clendy opening day (13 Sept is traditional); the 1802 Paris consulta day-dates; the birth house itself is demolished (Kunsthaus quarter coordinates used). No verifiable quote survives for Anna's death or the Czar audience, so those carry null — honest per the rules.

## Five richest episodes
1. **Stans (5 stops):** the commission among the massacre ruins, the 14 January intake, the "meine Hand lag in ihrer Hand" winter, the Altdorf children's vote, the French requisition — the mythic core, all quotable from the Stanser Brief.
2. **The Neuhof sacrifice (1774-80):** the farm that fails into a poor-house that fails greater; "I lived like a beggar to teach beggars to live like men."
3. **Gurnigel resolve:** the broken 53-year-old coming down the mountain with "Ich will Schulmeister werden!"
4. **Basel 1814:** the Czar of Russia embracing the shabby schoolmaster who lectured him on serfdom.
5. **The closing ring:** Swan Song written among the ruins of the first failure; death at Brugg; burial at the Birr schoolhouse wall under "Alles für Andere, für sich Nichts."

## Verification pass (2026-07-05)

Independent structure and canon-fidelity check; repairs applied in place to `pestalozzi.journey.json` and re-validated with python.

**Structure.** JSON parses; 8 segments / 53 stops (within the 35-55 target, no additions needed); every stop carries the exact key set (name, date, date_confidence, lat, lng, campa, quote, quote_source, sources, suggested_refs); dates ISO and strictly ordered within segments (and globally); confidence values limited to attested/inferred/traditional and honestly distributed (day-attested events only are `attested`). Campa 82-107 words throughout, present tense, the great episodes (Stans intake, Altdorf vote, Czar embrace, Birr burial) carry weight — not flat.

**Coordinates.** Eleven sites web-checked (OSM/Nominatim, Wikidata). Confirmed as-is: Neuhof (Pestalozzistrasse 100, Birr — 47.4307/8.2098, dataset points within ~120 m), Yverdon Castle (46.7783/6.6415), Grossmünster (47.3701/8.5439), Brugg, Münchenbuchsee, Aarau, Luzern, Stansstad, Langenthal, Zurich old-town stops. **Fixed 13 stops:**
- Höngg parsonage → 47.4017/8.4966 (by the Höngg church; was ~350 m off).
- Kirchberg BE → 47.0852/7.5816 (village; was ~1.1 km east).
- Gebenstorf wedding → 47.4818/8.2405 (village/church; was ~400 m off).
- Stans (4 stops) → 46.955/8.3656 (the convent building itself — today Kloster St. Klara; the Stanser Brief's own "Ursulinerinnen" naming kept per canon, the source itself footnotes the order).
- Gurnigelbad → 46.7614/7.4436 (the bath, Riggisberg; was ~600 m off).
- Burgdorf Castle (3 stops) → 47.0549/7.6290 (Schloss per Wikidata/OSM; was ~220 m off).
- Clendy → 46.7790/6.6549 (the Clendy quarter; the old point sat toward the lake).
- Birr grave → 47.4368/8.2016 (the village church / schoolhouse wall; was ~570 m east).

**Quotes.** Six spot-checked against heinrich-pestalozzi.de full texts (the cited canon) plus the Keller inscription. Grave epitaph and Tagebuch line verbatim-correct as they stood; "Die Anschauung ist das absolute Fundament aller Erkenntnis" is the standard anthologized declarative of the Wie-Gertrud clause — kept. **Four re-aligned to the canon's exact wording:**
- Stans arrival (Krätze): "Viele traten ... ein" restored (was "kamen"), ellipses kept.
- "In ihrer Mitte": aligned to the full-text edition ("von Morgen bis Abend soviel als allein", "Aug'"), with ellipses now marking both omitted sentences before "Ihre Suppe war die meinige".
- Altdorf question: replaced a paraphrase with the verbatim sentence ("...wollet ihr nicht unsere gute Obrigkeit bitten, daß sie etwa 20 dieser Kinder in unser Haus aufnehme?").
- Schwanengesang close: restored "in euch selber gereift", "in diesen Bogen", and the doubled "in Wahrheit und Liebe ... hinzu".
- Nachforschungen: the third-person summary formula replaced with Pestalozzi's own first-person sentence, "Also bin ich ein Werk der Natur, ein Werk meines Geschlechts und ein Werk meiner selbst."

Traditional-register quotes (Schulmeister resolve, Bettler line, shoe-mending, deathbed forgiveness) left as sourced-to-tradition; nulls at Anna's death and the Czar audience left null — the canon carries no words there. Post-repair validation: parses, 53 stops, dates ordered, campa in range, 12 quotes.
