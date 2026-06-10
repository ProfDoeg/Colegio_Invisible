# The essay corpus — La Doncella cycle

Source texts for the consolidated publication (the Book of 108 plan in
`docs/design/book-108-cathedral.md` names ~108 essays; the author
estimates 50–52 in this numbered series). Delivered in batches,
filed VERBATIM — organization lives here, never edits to the text.
Candidate errata are LOGGED below for the author's own pass; the
files are untouched.

Numbering runs DESCENDING from 220. Each file: number+title line,
English text, separator, Spanish text — exactly as received.

## Received

| # | file | langs | center of gravity |
|---|------|-------|-------------------|
| 220 | [220_la_coronacion.md](220_la_coronacion.md) | EN+ES | coronations & sanctified violence: Civic Crown, Reims, Cusco's Epiphany, Mama Huaco, Sendero Luminoso, Marianne |
| 219 | [219_trauma_y_trama.md](219_trauma_y_trama.md) | EN+ES | trauma/trama etymology, kairos as loom-portal, ESMA & the embroidery taller, Annina Rinaldi / J'adorable |
| 218 | [218_atavismo_y_los_ninos_perdidos.md](218_atavismo_y_los_ninos_perdidos.md) | EN+ES | lost children & atavism: famine folktales, STAR epigenetics, Sendak/Barrie/Schumacher, mozos perdidos, gaucho etymology, the ombú |
| 217 | [217_el_estandarte.md](217_el_estandarte.md) | EN+ES | the standard: campo/champ, Le Corbusier's right angle, Joan's three ensigns, stā→estandarte, NIST/ITAR cryptography |
| 216 | [216_la_espada.md](216_la_espada.md) | EN+ES | the sword of Saint Catherine: Fierbois, Hypatia, Constantine→Clovis→Martel→Charlemagne |
| 215 | [215_runaway_bride.md](215_runaway_bride.md) | EN+ES | the runaway bride: Thecla, Pelagia/Margaret, Marina; articles 8–16; Joan's gender strategy as war machine |
| 214 | [214_arte_de_los_hilos_divinos.md](214_arte_de_los_hilos_divinos.md) | EN+ES | ars filorum numinis: Black Forest spinners, fairy godmothers, Merlin's prophecy, distaff iconography |
| 213 | [213_las_tres_virgenes_martires.md](213_las_tres_virgenes_martires.md) | EN+ES | the three Virgin Martyrs: Margaret, Catherine, Barbara — full hagiographies; the three-sisters archetype |
| 212 | [212_domremy_por_katrin_vates.md](212_domremy_por_katrin_vates.md) | EN+ES | Katrin Vates' 'Domrémy' embroidery: technique, the five-fiber Khamsa, THE 32-BYTE STEGANOGRAPHIC PAYLOAD |
| 211 | [211_fata.md](211_fata.md) | EN+ES | fata/fée/hada etymologies, Aeneid, Prose Edda, Njáls Saga loom, Moirai/Norns |

Received: **10 of ~50–52** (batch 1, 2026-06-10).

## Connective threads (for the eventual book structure)

- The Vates 'Domrémy' embroidery is the corpus's anchor object (212),
  read outward through fates (211), martyrs (213), thread-craft (214),
  gender (215), sword (216), standard (217), atavism (218),
  trauma/trama (219), coronation (220).
- The ombú tree binds Lorraine to La Pampa (212, 217, 218).
- 217 EL ESTANDARTE speaks directly to the protocol's own Estandarte
  (0xee) — standards, cryptography (SHA-256, secp256k1), state, field.
- 219 names the 108 suitors of Penelope; 212 carries a 32-byte hex
  payload (`6da7a9a9…4910`) "encoded by the psychopomps of the Winter
  Triangle" — connects to the cemetery sky. Corpus object of interest;
  no action taken.
- The narrator is El Ermitaño-adjacent: first-person passages reference
  the Ivory Palace expulsion (219), the grandmother of the Lower East
  Side (213), walks in Cazón with Tomás (217).

## Candidate errata (author's call — files untouched)

- 216 EN: final sentence of ¶4 appears truncated: "lasted until 1453 CE
  when the Ottoman Turks." (ES completes the thought: "cayó ante los
  turcos otomanos"). Also lowercase "byzantium".
- 220: "Panchamama" (EN) vs "Pachamama" (ES) — spelling divergence.
- ES recurring: "an ella" / "menciona an Edith" (220, 212) — looks like
  a find-replace artifact for "a ella / a Edith"; appears ≥4 times.
- 219 ES: "la escapatoria de Khorramdel en el río ruyò" — "ruyò" has no
  EN counterpart ("escape at the river"); possible stray token.
- 217 ES: "tres enseñas mientras dirigía los ejércitos de Francia:, y
  un gran estandarte de batalla, un pendón, y una bandera" — garbled
  punctuation/order vs EN (banner, pennon, standard).
- 217 EN: Joan quote "to save for killing anyone" — reads oddly;
  period translation quirk or typo for "save for killing" / "safe
  from killing"; as received.
- 212: artist surname differs between attributions: "Sinchinoca" (EN
  caption) vs "Sinchinova" (body + ES caption).
- 213: "Orantes River" (EN) vs "Río Orontes" (ES).
- 214 EN: "conjouring" (conjuring).
- 218: EN ends "at the border" — ES "en la frontera bordada"
  (embroidered border); divergence may be deliberate.
- 211 EN: "naval strands of the etheric body" (navel?); "eigen-fee"
  reads as a deliberate fée pun — not flagged.

## Pipeline notes

Destination: 0x01 essay bodies (EN/ES as separate inscriptions or a
bilingual volume structure — author's call), assembled per the
book-108 design (per-essay-pair 0x09 wrappers, fractal diamond). The
zero-errata gates (quipu_preflight: graph equality + galley seal) are
built and waiting. Nothing inscribes until the corpus is complete and
the galley is signed off.
