# Jung journey — research report

**Dataset:** 73 stops, 9 segments (named after MDR's own chapter arc: First Years / School Years / Psychiatric Years / Sigmund Freud / Confrontation with the Unconscious / North Africa and the Tower / Travels / Golden Flower–Eranos–India / Visions), 41 quotes. Span 1875-1961, gregorian.

**Sources.** Canon above all: *Memories, Dreams, Reflections* (Jaffé), supplemented by *The Freud/Jung Letters* (McGuire), *The Red Book* (Shamdasani), Septem Sermones, Barbara Hannah, Deirdre Bair, von Franz (*His Myth in Our Time*, last dream), van der Post (*Jung and the Story of Our Time*, the poplar and the vision at sea), Serrano (*A Record of Two Friendships*), Jones. Web-verified: mother's death January 1923 with tower begun two months later; wedding 14 Feb 1903 (civil + ball at Hotel Bellevue **above the Rhine Falls** — the Laufen circle closing, a gift of the record); Africa sailing 15 Oct 1925 and Elgon camp struck late Dec 1925; Face to Face broadcast 22 Oct 1959; Serrano's approach 5 May 1959.

**Judgment calls.** (1) First Freud meeting: sources split between 27 Feb and 3 Mar 1907; used 1907-03-03, `traditional`. (2) India itinerary order (Bombay–Sanchi–Konarak–Calcutta–Kandy) is reconstructed; MDR puts Konarak before the Calcutta fever, so I kept that, all `inferred`. (3) Seven Sermons haunting pinned to Sunday 30 Jan 1916 per Black Books scholarship. (4) The "bulwark against the black tide" quote attached to Nuremberg 1910 per MDR's own dating. (5) Emma's memorial ("O vas insigne...", "she was a queen") from Hannah, not MDR. (6) Per register, the Goethe-descent legend and the household canon (split poplar, van der Post's "I'll be seeing you") are narrated as fact. (7) Dropped Tozeur, Fordham, and the dissertation as separate stops to stay in the 55-75 band; folded into neighbors.

**Gaps in the canon.** Exact days for the childhood events (dream at Laufen, manikin, cathedral vision) — dated by Jung's stated ages, `traditional`. Eranos casa coordinates approximate (Moscia shoreline). Elgon camp position approximate. The 1925 railway déjà-vu cliff located only as "between Mombasa and Nairobi."

**Corpus faces.** Eranos stops carry `Goethe atlas — Eranos (on-chain)`; Kesswil, the father's and mother's deaths, the ancestor tablets and the death stop carry `House of Jung genealogy (on-chain)`; the Serrano stop carries the inscribed letter of 14 Sept 1960.

**Five richest episodes.** (1) The Laufen phallus dream — the man-eater enthroned, the whole opus in a child's night. (2) The cathedral vision and its terrible grace. (3) The descent diptych: Schaffhausen blood-flood → 12 Dec plunge → Siegfried, with Philemon's dead kingfisher as the lake's countersignature. (4) The 1944 visions — earth from orbit, the stone temple, Haemmerli's exact exchange of deaths on 4 April. (5) The ending: last dream of the engraved stone and gold-threaded roots, then the lightning splitting the poplar at the hour of death — the register's perfect final line.

## Verification (2026-07-05)

Independent structural and canon-fidelity pass on `jung.journey.json`.

**Structure.** JSON parses. 9 segments / 73 stops (target 55-75 — no additions needed). Every stop carries the full key set (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`); all coordinates are numeric. Dates are globally monotonic across the whole journey (1875-07-26 → 1961-06-06), not merely per segment.

**Coordinates.** 16 stops geocode-checked against OSM Nominatim: Kesswil, Schloss Laufen, Kleinhüningen, Basel Münster, Burghölzli, Berggasse 19, Clark University, Taos Pueblo, Konark, Sanchi, Temple of the Tooth (Kandy), Bollingen, Ascona/Eranos, Château-d'Oex, Seestrasse 228 Küsnacht. All within 0.0-1.6 km of the true sites — no fixes required. Two apparent outliers resolved in the file's favor: Taos Pueblo (file matches the UNESCO coordinates of the adobe village; OSM node is the reservation centroid 8 km off) and Sanchi (file sits on the stupa hill, ~1 km from the town node). Eranos deliberately points at Moscia, not Ascona center — correct.

**Quotes.** 41 quotes; 10+ spot-checked against canon: man-eater (MDR ch.1), sitting-on-the-stone (ch.1), cathedral vision (ch.2), "Why, then, I must get to work!" (ch.2), "He died in time for you" (ch.3), thirteen hours (ch.5), bookcase detonation (ch.5), black tide of mud (ch.5), Seven Sermons opening (Septem Sermones), "She was a queen!" (Hannah), "I don't need to believe. I know." (Face to Face, 22 Oct 1959), "I'll be seeing you" (van der Post). All carried by the cited canon; none nulled.

**Campa voice.** Present tense throughout; great episodes (cathedral turd, the plunge, Philemon, Taos, Athi Plains, 1944 visions, the split poplar) are not flat. Seven stops ran over the 110-word ceiling (up to 121); each was trimmed minimally in place — connective tissue only, no canonical detail or image removed (manikin 110, Grail dream 106, 1944 earth-vision 109, Haemmerli 109, Serrano 110, marketplace dream 110, death/poplar 109).

**Result.** File repaired in place and re-validated with python: 73 stops, chronology clean, all word counts in 60-110, coordinates verified, quotes canonical.
