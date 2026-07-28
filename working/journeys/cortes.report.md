# Report — Hernán Cortés journey dataset

**Sources.** Canon spine: Cortés's own five *Cartas de Relación* to Charles V (1519–1526) and Bernal Díaz del Castillo's *Historia verdadera de la conquista de la Nueva España* (written ~1568, printed 1632), cross-checked against López de Gómara's *Historia de la conquista de México* and modern syntheses (Arqueología Mexicana, Noticonquista/UNAM, Infobae historical desk, Wikipedia ES/EN) for dates, coordinates, and disputed points (the "burned vs. run-aground" ships; the Popotla weeping; the Voltaire carriage anecdote). All quotes were verified against primary-source excerpts before inclusion; five of eight are Bernal Díaz or Cortés's own words, one is the crowd anecdote (marked explicitly as Voltaire-transmitted, not in the Spanish chronicles).

**Judgment calls.**
- *Ships "burned" vs. "given al través."* Modern scholarship is firm that the ships were scuttled/beached, not torched — the "quema de las naves" is a 16th-century legend. I kept the curator's framing ("no way back") but wrote the campa to the documented method, with the quote sourced to Bernal Díaz's account of the captains' counsel rather than to Cortés alone.
- *The Popotla tree.* Bernal Díaz never mentions Popotla or weeping; the scene enters the tradition later. Marked `date_confidence: "traditional"` and the campa states the discrepancy in-register, the way Joan's fairy-tree stops handle folklore against trial testimony.
- *Coyoacán torture of Cuauhtémoc.* Not in Cortés's own letters; comes from Torquemada and later chroniclers. Marked traditional.
- *The crowd/carriage quote.* Traced to Voltaire's *Essai sur les mœurs* (1756), relayed by Prescott — apocryphal by consensus, absent from 16th-century Spanish sources. Per the curator's instruction I did not null it, but the `quote_source` says so plainly rather than passing it off as attested.
- *Villa Rica founding date.* Sources split between the original beach camp (22 April 1519) and the later move to Quiahuiztlán/La Antigua; I used the founding date and let the Cempoala/scuttling stops carry the mid-1519 relocation implicitly rather than adding a third near-duplicate stop.
- *Izancanac coordinates.* The exact site of Cuauhtémoc's execution is lost; I used the Candelaria-river / Itzamkanac region (Campeche-Tabasco border) that most modern scholarship favors, and said so in the campa ("a jungle that swallows the exact place") rather than implying false precision.

**Cross-references within the atlas.** Columbus's Hispaniola stops (Môle-Saint-Nicolas, La Navidad) and his Cuba coasting (Bariay, the Gulf of Cortés oath) sit on different specific sites than Cortés's own Hispaniola/Cuba stops (Santo Domingo city, Azua, Maisí, Santiago de Cuba) — same islands, no literal pin-share, so none was forced. Pizarro has no journey file yet in the corpus; the Extremadura kinship is carried in prose instead, at the Medellín stop, naming the shared Pizarro Altamirano blood between Cortés's mother and the child Francisco Pizarro growing up in nearby Trujillo — ready to be pin-shared properly once a `pizarro.journey.json` exists.

**Five richest episodes.** (1) The giving of Doña Marina at Centla — a slave-girl's tongue becomes the fulcrum of an empire's fall, and the Nahuas rename Cortés for her. (2) The ships given to the través at Vera Cruz — a fleet's death as a legal and psychological weapon. (3) The causeway meeting with Moctezuma, 8 November 1519 — Bernal Díaz's "cosas de encantamiento" line, the most quoted sentence in the whole conquest corpus. (4) La Noche Triste — greed literally drowning men, Bernal Díaz's cries for help still audible four centuries later. (5) The coda: bones moved at least six documented times over four centuries, settling, by what the tradition insists is no accident, meters from the exact causeway where the whole story began.

**Gaps/time-folds.** The 1504–1519 Caribbean years (fifteen years of Cortés's life) are compressed into four stops — deliberately, since the canon itself treats them as prologue, not story; Bernal Díaz gives them a few pages against hundreds for 1519–1521. The Baja California expeditions (1533–1539) are folded into the single 1535 landfall that gave the gulf his name, since the curator's arc calls for "the sea that bears his name" rather than a full survey of three failed colonizing voyages.

---

## Verification pass — 2026-07-13

Structure and canon-fidelity check of `cortes.journey.json` (42 stops, 9 segments, 8 quoted). `json_check.py` clean before and after repairs; top-level and per-stop keys match `joan_of_arc.journey.json` exactly; chronology ordered within and across all segments; the journey correctly ends with the traveler dead (the 1947 bones coda). Nothing debunked: Popotla, the Coyoacán torture, and the Voltaire carriage anecdote all stay, marked by confidence and honest sourcing as the healing model requires. Stop count within the 30–45 target; no additions needed.

**Coordinates.** 20+ sites spot-checked against actual/traditional locations. Most were exact (Salamanca, Cholula pyramid, Cempoala, Tlaxcala, Otumba, Texcoco, Tlatelolco, San Juan de Ulúa, La Antigua, Coyoacán, Cuernavaca palace, Béjar, Toledo, La Paz, Trujillo, Hospital de Jesús, the deliberate few-meter causeway/Hospital offset). Six were off and were fixed in place:

- *Maisí* — pin sat exactly on Baracoa (20.3472, -74.4967), ~60 km from the stop's own named site; moved to Punta de Maisí (20.2419, -74.1519) to match the campa's "the island's eastern point."
- *Azua* — pin was ~17 km west of the 1504 site; moved to Pueblo Viejo, Azua (18.400, -70.767), where the ruins of Compostela de Azua (destroyed by the 1751 earthquake) actually lie.
- *Paso de Cortés* — ~2.5 km off; corrected to the pass/monument (19.0867, -98.6453).
- *Popotla tree* — ~800 m off; corrected to the ahuehuete at Calzada México-Tacuba 453 (19.4554, -99.1794).
- *Izancanac* — pin was ~70 km west of the Candelaria basin, not on the river; moved to El Tigre/Itzamkanac, the INAH site modern scholarship favors (18.1333, -90.8333), consistent with the report's own judgment call.
- *Castilleja de la Cuesta* — ~2 km off toward Tomares; corrected to the town (37.3856, -6.0569).

**Quotes.** All 7 canon quotes checked against primary-source text (the 8th is the flagged Voltaire anecdote, kept as sourced). Verbatim as inscribed: Bernal cap. 37 (Doña Marina), cap. 58 ("diese al través con todos"), cap. 128 (Noche Triste — fragments verified against the chapter text via Noticonquista), and Cortés's Tercera Carta (the Cuauhtémoc dagger). Three repairs to restore canon wording:

- Amadís quote (cap. 87): stray accent, "cómo iba a México" → "como iba a México". Remaining differences from other printings ("que se cuentan" vs "que cuentan") are edition-level variants, left as is.
- Segunda Carta (mezquitas): "collaciones" → "colaciones" (the attested spelling; "de ella"/"della" left as a modernization variant).
- Cuauhtémoc's dying words (cap. 177): "Tu Dios te la demande, pues yo no te la di…" → "Dios te la demande, pues yo no me la di cuando a ti me entregué en mi ciudad de México" — the dataset's slip inverted the sense (he did not give himself that death when he surrendered). Restored to the standard modernized Bernal rendering.

**Confidence honesty.** One downgrade: the Toledo audience with Charles V (1528-07-01) was marked "attested" on a placeholder day; the year is attested, the day is not — changed to "inferred", matching how Béjar/Cuernavaca/Trujillo placeholders are handled.

**Campa register.** Spot-read across all segments: present tense throughout, 60–110 words (linter-clean), and the great episodes (causeway meeting, Noche Triste, Otumba standard, the dagger at Tlatelolco, the wandering bones) carry their weight — not flat. The Toxcatl stop narrates an event in Cortés's absence but says so in its first clause and lands the news on him at the coast, which keeps it a stop on *his* journey.

Re-validated after repairs: `OK — segments=9 stops=42 quoted=8`, no WARN lines.
