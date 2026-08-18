# The atlas research pipeline

Clickless research of one queue subject into a report.md and journey.json.
Canonical script: working/journeys/atlas_tools/research_pipeline.js (invoke via
the Workflow tool with scriptPath + args {slug, name, brief, dir}).

Division of labor, fixed by the author (2026-08-02):
- Preflight (added 2026-08-18): one cheap low-effort sonnet call checks
  working/journeys/*.journey.json and removed/*.journey.json for an existing
  file on the SAME real person under a DIFFERENT slug, confirming any match
  by actually reading its traveler/title fields, not by slug string
  comparison alone. If found, the whole run aborts before Gather with
  {aborted: true, reason: 'duplicate_found', ...}. Added after four
  same-day collisions (moses_de_leon, count_orlando_di_chiusi,
  st_anthony_of_padua, plus two caught pre-launch) where a subject was
  already researched under a shorter slug than its queue row's full bolded
  name naively slugifies to, the stale queue row was never dropped, and two
  of the four burned a full ~700k-token run before anyone noticed. The
  orchestrator must still drop the queue row and check for stale duplicates
  itself before EVERY launch (naive slug match is not enough, use loose
  token overlap or better); this phase is the backstop for when that check
  is skipped or wrong, not a replacement for it.
- Gather: five sonnet lenses (chronology, geography, quotes, corpus interlock,
  afterlife) over WebSearch/WebFetch, PDFs read with python3 + pypdf.
- Verify: two Opus adversarial checkers. One refutes facts, dates, and
  coordinates; one authenticates every quotation - an invented quote is the
  worst failure the pipeline can produce, so untraceable quotes are rejected.
- Write: Opus drafts both artifacts from the verified pool, reading an
  existing journey and report as exemplars first. House style is embedded in
  every prompt: no em dash, straight quotes, campa 450-650 chars, [A]/[R]
  evidence tags, canonical pins inherited byte-identically, mutual gaze.
- Gate: mechanical python checks (schema, lengths, dashes, register string,
  date order) plus a humanizer pass, with an in-place fix loop.
- Orchestration and final review: Fable in the main loop; the author reads
  the artifacts before anything is committed as canon.

Prerequisites: permissions allowing WebFetch/WebSearch/python/Write (user
settings), pypdf installed. Nothing in the run requires a click.

## Clickless command conventions (added 2026-08-02 after the pilot)

Two Bash patterns trigger manual approval regardless of allowlists: compound
commands containing cd with a write operation, and heredocs with unquoted
delimiters. Every command in this pipeline (orchestrator and agents alike):
- uses absolute paths, never cd; git runs as git -C /abs/path
- runs python via script files (Write the script, then python3 /abs/path.py)
  or python3 -c with single quotes; never an unquoted heredoc

## Traducir (added 2026-08-02)

Phase 5: Opus writes es/<slug>.journey.json from the English original with
es/abdelkader.journey.json as exemplar. Register "mitologia nacional: el canon
es verdadero"; traveler unchanged; title, names, campa, quotes in Spanish;
coordinates and dates copied unchanged; campa 450-760 (Spanish breathes
longer). Translation on Spanish terms, never sentence-for-sentence; estilo
rules from the humanizar skill. Mechanical es-gate runs inside the stage.
