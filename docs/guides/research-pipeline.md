# The atlas research pipeline

Clickless research of one queue subject into a report.md and journey.json.
Canonical script: working/journeys/atlas_tools/research_pipeline.js (invoke via
the Workflow tool with scriptPath + args {slug, name, brief, dir}).

Before you launch anything (mandatory, added 2026-08-18): run
`python3 working/journeys/atlas_tools/ledger.py --check "Full Name"` FIRST,
always, no exceptions -- this is not a courtesy step, it IS step one of
launching a subject, the same way `git pull` is step one of committing.
`ledger.py` already contains correct fuzzy duplicate detection (word-set
containment against every built journey slug, not naive exact-slug
comparison) via its existing `is_built()`, which every other number in this
tool already relies on. `--check` just exposes that same logic for one name:
`ALREADY BUILT: <name>` or `not built: <name>`. If it says built, stop --
find the existing file, don't relaunch.

Then claim the row, deterministically (added same day, per the operator's
directive: "I'd rather make it programmatic and not depend on you to remember
your instructions because sometimes you don't"):

    python3 working/journeys/atlas_tools/queue_mark.py claim "Exact Bolded Name"

No model involved. It pulls, finds the row whose bolded cell is EXACTLY that
text (anything but a single match refuses), inserts a dated, owner-tagged
`_(researching ...)_` marker, commits that one file, and pushes. The push is
the cross-instance lock: if the other instance claimed the same row first, the
script detects the collision, undoes itself to a clean tree, and exits 4 so
you pick another subject. A marker with a stale date is a dead run; clearing
one is a human call. Set QM_OWNER in the instance's environment (nodus1,
nodus2) so markers name their claimant.

When the subject lands, remove the row in the SAME commit as its artifacts:

    python3 working/journeys/atlas_tools/queue_mark.py drop "Exact Bolded Name"

drop edits the file and deliberately does not commit. The full liturgy:
ledger.py --check, then queue_mark.py claim, then the Workflow run, then one
commit carrying journey + report + es/ + the queue-row removal together.

Why this exists: four same-day collisions on 2026-08-18 (moses_de_leon,
count_orlando_di_chiusi, st_anthony_of_padua, plus two caught pre-launch)
where a subject had already been researched days earlier but its queue row
was never removed, so a throwaway ad hoc slugify script kept reporting it
as fresh; two of the four burned a full ~700k-token pipeline run before
anyone noticed. An in-script Preflight agent call was tried and rejected
same-day as wasteful (paid, every run, script has no filesystem access so
it can't check for free). The actual fix already existed in ledger.py; it
just wasn't being used as the source of truth for picking next subjects.

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

## The supplied research file (dossier arg, added 2026-08-18)

The operator supplies deep research as an .md file (typically sent to the
instance as a Telegram attachment). Pass its absolute path as the `dossier`
arg and all five gather lenses receive it as framed background: a lead, not a
source. They read it to know which names, dates, places, works, and disputes
are worth chasing, then find everything independently; they are told in as
many words not to copy its wording, not to carry a claim because it appears
there, and not to cite it. This replaces cramming the research into `brief`,
where an imperative sentence once got read as a work order mid-Gather.

    Workflow scriptPath=.../research_pipeline.js args={
      slug, name, brief, dir, dossier: "/abs/path/to/research.md" }

Omit `dossier` and the pipeline behaves exactly as before.

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
