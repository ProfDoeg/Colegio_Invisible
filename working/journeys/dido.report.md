# Dido (Elissa of Tyre) — build report

## Sources
Two independent canons carry her, and both are treated as true in their own register. The **historical/legendary founding tradition** comes down through Timaeus of Tauromenium (fragments, 4th–3rd c. BC, who fixed Carthage's founding at 814 BC), Pompeius Trogus's lost *Historiae Philippicae* as epitomized by Justin (18.4–6, quoted at length in J. S. Watson's 1853 translation — this is where the sand-sack ruse, Cyprus, the ox-hide, Iarbas, and the pyre all come from), and Josephus's *Against Apion* 1.18, which preserves Menander of Ephesus's Tyrian king-list synchronizing Pygmalion's reign and Dido's flight to c. 825 BC. The **poets' tradition** is Virgil's *Aeneid* (books 1, 4, 6), with her own last testament supplied by Ovid's *Heroides* 7 and her afterlife by Ovid's *Fasti* 3 (Anna Perenna). The Punic-War coda draws on Appian's *Punica* and Plutarch's *Caesar*. Coordinates and several stops (the storm, the murals, the cave, the pyre, the underworld) are **shared pins**, matched exactly, with `aeneas.journey.json`; Tyre and the Byrsa-hill birth of Hannibal are shared pins with `hannibal.journey.json`, which already names her directly ("Dido sailed west from this rock to found the city that raised him").

## Judgment calls
- **Two deaths, one queen.** Justin's Elissa dies chastely by her own hand to refuse Iarbas and keep faith with her first husband — no Aeneas exists in her lifetime. Virgil's Dido dies of love for a man ancient critics (Justin himself, later Macrobius) already knew she couldn't have met, since Aeneas belongs some 300+ years earlier. Rather than pick one, the dataset holds both: Segment 3 ends in the *historical* register (founding through Iarbas's first suitorship, ending ~814 BC); Segment 4 is explicitly framed as "the poets' fold of time," dated to Aeneas's own chronology (-1182, matching `aeneas.journey.json` byte-for-byte); Segment 6 returns to the historical thread for her actual, attested death. The campa text for Segment 6's opening stop says so out loud ("the older and, the historians insist, the truer telling").
- **Dates are a deliberate two-track system.** Segments 1–3 and 6–7 run on the Josephus/Menander-anchored historical chronology (birth ~850, flight 825, founding 824–814 BC). Segments 4–5 run on the Virgilian poetic chronology (-1182/-1180), which is *not* chronologically consistent with the surrounding segments — this is the time-fold the brief invites, made visible rather than hidden.
- **Coordinates for Cyprus** use Kition/Larnaca (the best-attested Phoenician colony with an Astarte temple) since no ancient source names the landing point precisely.
- Iarbas's ultimatum and the pyre are dated to the same year (814 BC, matching Timaeus's founding date, reinterpreted here as the year of her death after roughly a decade's reign) — a synthesis of two numbers ancient sources report separately (825 BC flight/founding via Josephus, 814 BC via Timaeus), rather than a contradiction.

## Gaps
No stop invents an omen or vision unattested in a source; where the canon is silent (e.g., her exact birth date, the precise Cyprus anchorage), `date_confidence` is marked `traditional` or `inferred` accordingly, and campa language stays general rather than invented-specific.

## The five richest episodes
1. **The sand-sacks thrown to the sea** (Segment 1) — grief weaponized as its own alibi.
2. **The ox-hide cut to a thousand strips** (Segment 3) — the founding trick that names a hill and a whole tradition of Carthaginian cunning.
3. **"Anna soror, quae me suspensam insomnia terrent"** through the confrontation and last letter (Segment 4) — her own interior voice, distinct from the political-military lens `aeneas.journey.json` takes on the same days.
4. **Her true last words**, "Vixi et quem dederat cursum fortuna peregi" (Segment 4) — used here instead of the curse itself (which the Aeneas file already carries), restoring her own voice to her own death.
5. **"She would go to her husband, as they had desired her"** (Segment 6) — the historical Elissa's double-edged last line, heard as consent by the crowd and understood as defiance only when the sword falls.

## Connections to the atlas
Direct shared pins with `aeneas.journey.json` (storm, shore, murals, cave, pyre, underworld — same coordinates and, for the poetic segments, the same dates) and with `hannibal.journey.json` (Tyre; Byrsa hill at Hannibal's birth, -0247-01-01, identical coordinates and date to that file's opening stop). The closing segment threads Carthage's whole afterlife — Hannibal as the curse's bearer, the Third Punic War as its "furthest reach," and Augustus's refounding as the line she cursed returning to rebuild what she made — back into a single arc that any reader of `aeneas.journey.json` or `hannibal.journey.json` will recognize from the other side.

## Verification pass — 2026-07-18

Structure and canon-fidelity check (verifier, not the original researcher). `json_check.py` clean before and after: 7 segments, 32 stops, 20 quoted, no WARN lines.

**Structure.** Matches the Joan of Arc reference schema (traveler/title/years/calendar/register + segments/stops with all per-stop keys). Chronology ascending within every segment, BCE sorted numerically; the poets' time-fold (segments 4-5, -1182/-1180) is carried at `traditional` confidence and framed inside the campa itself — held as canon, not debunked. Subject long dead; afterlives segment closes at the Augustan refounding.

**Shared pins verified against sibling files.** All identical to `aeneas.journey.json`: storm (-1182-06-10, 37.9/11.5), shore (-1182-06-12, 36.83/10.25), murals (-1182-06-13, 36.8528/10.3233), banquet (-1182-06-13, 36.8530/10.3236), cave (-1182-07-01, 36.8/10.2), pyre (-1182-11-15, 36.8525/10.3240), Fields of Mourning (-1181-07-11, 40.83/14.085). Hannibal's Byrsa birth (-0247-01-01, 36.8528/10.3233) matches `hannibal.journey.json`'s opening stop exactly.

**Coordinates.** Spot-checked 13 stops: Tyre, Tyre harbor, Kition/Larnaca, the Sicilian sea-road, Byrsa (x many), Avernus, the Numicius near Lavinium/Ardea, the 146 BC and 29 BC Carthage stops — all on or acceptably near the actual/traditional sites. One tightening applied: Utica moved from 37.0667/10.0667 to the archaeological site at 37.0567/10.0622.

**Quotes.** Checked all 20 against the canon, not just the required six. Verbatim confirmed: Aeneid 1.135, 1.340-341, 1.461-462, 4.9, 4.172, 4.305-306, 4.625, 4.653-654, 6.469-471; Ovid Heroides 7.195-196; Watson's Justin ox-hide pair (18.5), augurs' warning (18.4), priest of Jupiter (18.5), eighty wives (18.5), "she would go to her husband" (18.6). Four repairs:

1. **Fabricated Latin removed.** "Tum sic effata sepulcro / intulit ereptas, quas coeli ianitor Orco / servet, opes." was attributed to Aeneid 1.359-361 but exists nowhere in Virgil (its shards trace to unrelated texts, e.g. Ovid Ex Ponto 4.7). Replaced with the genuine lines for that very moment, Aeneid 1.358-359: "Auxiliumque viae veteres tellure recludit / thesauros, ignotum argenti pondus et auri."
2. **Sand-sacks entreaty (18.4)** was a paraphrase; restored to Watson verbatim: "That he would favourably receive his wealth which he had left behind him, and accept that as an offering to his shade." (checked against Watson's text at attalus.org).
3. **Councilors' argument (18.6)** was a paraphrase, and the campa flattened Justin's actual scene. Restored the deputies' verbatim reply — "She herself, if she wished her city to be secure, must do what she required of others." — and rewrote the campa to carry the canon's Punic-honesty trap: the feigned request for a teacher, her reproach that life itself is owed to country, her own maxim sprung back on her.
4. **Tribute quote** was paraphrased and miscited to 19.2; the founding-era clause is in 18.5 — "An annual tribute being fixed for the ground which it was to occupy." — cite corrected, with 19.1 (the tribute still contested centuries later) added to sources.

**Campa.** All within 60-110 words (lint-confirmed), present tense, in register; the great episodes (sand-sacks, ox-hide, cave, pyre, the silent shade) are not flat. Stop count 32 sits inside the 30-45 target; no additions needed.

No changes to index.json.
