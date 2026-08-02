# atlas_tools — the survey instruments

Rebuilt 2026-08-01. The originals (`load.py`, `social.py`, `aliases.py`, `geo.py`,
`temporal.py`) produced `atlas_network_survey.md` on 2026-07-12 against 82 journeys,
then were lost: they lived in a session scratchpad under `/tmp` and were never
committed. `git log --all --diff-filter=A` confirms they never entered history.

These are committed so that does not happen again.

    python3 survey.py > ../atlas_network_survey_$(date +%F).md

Successive surveys are diffable. Every number is measured against the files;
nothing is estimated.

## Modules

| module | answers |
|---|---|
| `load.py` | corpus loader. Keeps coordinate **repr strings** as well as floats, because the convention is byte-identical pins and `50.978` != `50.9780` |
| `aliases.py` | which strings name a traveler. Accent-folded, derived from each journey's own fields first; `EXTRA` only for names prose uses that the file never states |
| `social.py` | cross-mention graph, mutual gaze, orphan-hub ranking |
| `geo.py` | haversine co-location, pin drift, pin spread, canonical pins, geographic deserts |
| `temporal.py` | date parsing, chronological regressions, the BCE globe bug, temporal deserts |
| `style.py` | house style on **authored** text only — quotes are verbatim source and exempt |

## Two things worth knowing before trusting output

**`datekey` vs `truekey`.** `temporal.datekey()` mirrors `build_atlas_globe.datekey()`
exactly, including its BCE quirk: it negates the whole fractional year, so months run
*backwards* inside a single BCE year (`-1738-06-01` -> `-1738.417` sorts before
`-1738-01-01` -> `-1738.0`). `truekey()` orders correctly.

**Scope of that quirk — do NOT overstate it.** The globe does not sort stops by `k`.
Stops are appended in file order and drawn in file order, so journey paths render
correctly; `travelers.sort(key=k0)` orders only the traveler *list*, and that ordering
was verified correct (identical under datekey and truekey). `k` drives only the time
scrubber, "nearest stop in time", the who-else-was-here list, and next/prev-in-time
navigation. So the effect is confined to time navigation *within one BCE year*:
**273 adjacent same-year pairs** (hannibal 36, moses 32, alexander 26...). Nothing
visible when tracing a journey. Fixing it is optional and low priority.

`regressions()` uses truekey and reports genuine data errors — exactly **1** as of
2026-08-01 (`juan_peron`, already known from the July survey).

**`discover_orphans()` is a proposer, not a judge.** It finds recurring capitalised
bigrams with no file of their own, so it surfaces places and relics (Buenos Aires,
True Cross, Round Table) alongside people. Use `orphan_hubs(candidates)` with an
explicit candidate map when you want a ranked answer to "who earns a file next";
use `discover_orphans()` only to generate candidates for a human to adjudicate.

## Conventions these tools enforce

- **Byte-identical sibling pins** — the same event in two journeys carries the same
  coordinates, character for character.
- **Canonical pins** — a place already shared byte-exact by 3+ journeys is inherited,
  never re-derived. Paris `(48.8566, 2.3522)` is in 18 journeys; the Kaaba
  `(21.4225, 39.8262)` in 8.
- **Mutual gaze** — if A's prose names B, B's should name A.
- **House style** — no em dash, straight quotes only, campa 450-650 chars.
  `quote` is exempt: editing a quotation to fit house style would falsify it.
