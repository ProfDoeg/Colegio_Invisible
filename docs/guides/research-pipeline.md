# The atlas research pipeline

Clickless research of one queue subject into a report.md and journey.json.
Canonical script: working/journeys/atlas_tools/research_pipeline.js (invoke via
the Workflow tool with scriptPath + args {slug, name, brief, dir}).

Division of labor, fixed by the author (2026-08-02):
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
