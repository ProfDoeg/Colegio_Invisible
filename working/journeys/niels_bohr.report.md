# Niels Bohr — Research Report

**42 stops, 7 segments, 6 quoted, span 1885-1962 (gregorian).**

## Sources
Primary: Bohr's 1913 trilogy "On the Constitution of Atoms and Molecules" (Phil. Mag.); his Nobel Lecture (11 Dec 1922, nobelprize.org); his Open Letter to the United Nations (9 June 1950, full text pulled via `fredsakademiet.dk` PDF and read with `pdf_text.py`), which itself quotes his July 1944 memorandum to Roosevelt verbatim. Secondary: Abraham Pais, *Niels Bohr's Times*; the Niels Bohr Institute's historical-sites pages (nbi.ku.dk) for exact addresses (Ved Stranden 14, Blegdamsvej 17, the Carlsberg Æresbolig); the Niels Bohr Archive's 2002 release of Bohr's unsent draft letters on the 1941 Heisenberg meeting; AHF/Atomic Heritage Foundation and blog.nuclearsecrecy.com for Los Alamos and the Hyde Park Aide-Mémoire; Jacques Hymans (LRB) for the Churchill-meeting quote; contemporary press accounts of the 1943 escape and Mosquito flight.

## Judgment calls
- **Register**: treated as attested biography throughout, not myth — the "campa" register still narrates the drama (the arrow of oxygen deprivation over the North Sea, the blackboard sketch found the day he died) as event, per house style, but nothing here is legendary; almost every stop is "attested" or "traditional," none "inferred" beyond a couple of school-age placeholders.
- **Coordinates for the 1940s Copenhagen stops split two ways**: Institute business (the aqua regia, the Institute-as-refuge) is pinned to Blegdamsvej 17; personal/home events (Heisenberg's 1941 visit, the September 1943 flight, the coat-of-arms design, the death) are pinned to the Carlsberg honorary residence (55.676, 12.545) — matching the coordinates already used in the sibling `heisenberg.journey.json` file, confirmed by direct comparison.
- **Christian's drowning (1934)**: sources disagree on Kattegat vs. Øresund; no source gives a precise location. Marked `traditional` with a generic point off north Zealand rather than inventing false precision.
- **The Mosquito-flight "slept like a baby" line**: multiple secondary sources paraphrase this remark but none gave me verbatim wording I could stand behind, so I left that stop's quote null rather than manufacture a quotation — an explicit application of "quote null is honest."
- **Time-fold**: the "Complementarity" segment runs 1927-1934, deliberately separating the *naming* of complementarity (Como/Solvay, 1927-30) from its *heraldic* expression (the 1947 coat of arms), which is chronologically much later and placed in the final segment instead — the curator's brief grouped them thematically, but the schema's chronology-within-segment rule took precedence.

## Five richest episodes
1. **The 1913 trilogy** — sent to Rutherford in installments, the quantum leap enters the atom; I could quote the paper's own opening sentences.
2. **The escape, 29 Sept – 6 Oct 1943** — the flight from the Carlsberg mansion, the fishing boat, the audience with King Gustav V (Bohr refusing to leave Sweden until the king publicly promised asylum to Danish Jews), and the Mosquito's bomb bay where he passed out from oxygen loss.
3. **Los Alamos as "Nicholas Baker"** — "is it big enough?" to Oppenheimer, and Oppenheimer's own credit to Bohr for cracking the plutonium initiator in February 1945.
4. **Churchill vs. Roosevelt, May–Sept 1944** — the dismissive "treated us like two schoolboys" meeting, the warmer Roosevelt audience, and the Hyde Park Aide-Mémoire that secretly ordered Bohr watched — a real, sourced irony the campa plays straight.
5. **The coat of arms and the death** — the yin-yang/*contraria sunt complementa* motto in 1947, and the unfinished photon-box sketch found on his blackboard the day he died in 1962, closing the Einstein argument without quite closing it.

## Connections to the atlas
This journey shares three confirmed pins with existing siblings, checked directly against their JSON rather than assumed: **einstein.journey.json** (Brussels, 1927-10-24, identical date), **heisenberg.journey.json** (Göttingen 1922, Copenhagen 1926-27 uncertainty, Copenhagen 1941-09-16, all cross-checked), and **robert_oppenheimer.journey.json** ("Bohr on the mesa," 1943-12-30, same coordinates reused). `suggested_refs` entries point at all three explicitly as shared pins, in the convention set by `joan_of_arc.journey.json`.

---

## Verification — 2026-07-24

Independent structural + canon-fidelity pass by a verifier agent. **Result: PASS, no repairs made.**

- **Lint**: `json_check.py` returns `OK` (no WARN lines) — required top-level and per-stop keys present, dates chronological within every segment, all `date_confidence` values valid, lat/lng numeric and in range, all campa within the 60–110-word band, quote/quote_source paired both-or-neither. Tally confirmed: traveler set, **7 segments, 42 stops, 6 quoted** — within the 30–45 target, no additions warranted.
- **Chronology / confidences**: dates run monotonically 1885→1962; span ends at Bohr's death (correct for a non-living subject). Confidence labels are honest — the three `traditional` pins (Fælledparken goalkeeping, the June 1912 Rutherford memorandum date, Christian's 1934 drowning at a generic offshore point) and the two school-age `inferred` pins are exactly where documented precision is unavailable. The Solvay-era "God does not play dice" line to Born is flagged in-campa with the loose "around this time," appropriate given the actual letter predates the 1927 conference.
- **Coordinates**: spot-checked >12 stops against known site locations from knowledge (live web spot-check unavailable this session — WebSearch budget exhausted). Site pins (Ved Stranden 14, Cavendish/Free School Lane, Manchester, Slagelse, Solvay/Parc Léopold, Los Alamos mesa, Bromma, Limhamn, Hyde Park) all land on or beside the actual sites. The recurring Copenhagen pins — **Blegdamsvej 17 (55.699, 12.5658)** and the **Carlsberg Æresbolig (55.676, 12.545)** — were verified by `grep` against `heisenberg.journey.json` to be **byte-for-byte the established shared-pin coordinates of the fleet**; left unchanged, since atlas consistency outranks a sub-kilometre nudge.
- **Quotes**: all six carry a `quote_source`; checked against the canon — the 1913 Phil. Mag. opening (verbatim), "treated us like two schoolboys" (Churchill meeting, Hymans/LRB), the Roosevelt-memorandum passage (via the 1950 UN Open Letter), Oppenheimer's initiator credit, the *contraria sunt complementa* motto, and the UN Open Letter's "open world" sentence. None paraphrased-as-quotation; the deliberately-null stops (Mosquito flight, etc.) correctly withhold rather than invent.
- **Campa register**: present-tense, in the house mythic-biography voice, great episodes (the 1913 leap, the 1943 escape and King Gustav V, Churchill vs. Roosevelt, the blackboard photon-box found the day he died) carry their drama; none flat.

No changes were made to the JSON; it re-lints `OK`. One item deferred to a future live-web pass (not a defect): confirm the Como 1927 pin (45.8125, 9.0654) against Villa Olmo if that becomes the preferred anchor.
