#!/usr/bin/env python3
"""Phase 0 of the connections-harmonization pass: backfill a fresh "## Atlas
Connections" section for the ~289 dossiers written before the roster-addendum
feature existed (2026-08-31), so every dossier has a connections section for
Phase 1 (extraction) to work from.

ADDITIVE ONLY, deliberately conservative: this runner never edits a dossier
in the tracked repo. It only writes the new section's text to
~/codex_lab/connections_out/<slug>.section.md for a human (Anthony/the
orchestrating instance) to spot-check, then insert with a separate,
reviewed step -- unlike the original dossier-creation runner, this one
touches already-published files, so no auto-staging here.

Sections are written directly in the harmonized tag format (T1-T5, T9;
sign; subtype for T2) agreed with Anthony on 2026-09-05, so these 289
won't need Phase 1 extraction at all once inserted -- only the ~607
dossiers that already had a prose-only Atlas Connections section do.

Run under tmux:  tmux -L codexbatch new-session -d -s phase0 \\
    "HOME=/home/drdoeg WORKERS=5 python3 ~/codex_lab/connections_phase0_runner.py >> ~/codex_lab/connections_phase0.log 2>&1"
"""
import csv, os, re, subprocess, threading, time

HOME = os.path.expanduser('~')
REPO = f'{HOME}/taller/Colegio_Invisible/working/journeys'
LAB = f'{HOME}/codex_lab'
OUT = f'{LAB}/connections_out'
CODEX = f'{HOME}/.local/bin/codex'
WORKERS = int(os.environ.get('WORKERS', '5'))
QUOTA_SLEEPS = [900, 1800, 3600]

LOCK = threading.Lock()
IN_PROGRESS = set()
FAILURES = {}

MARK_START = '=== ATLAS_CONNECTIONS_SECTION_START ==='
MARK_END = '=== ATLAS_CONNECTIONS_SECTION_END ==='

TYPE_GUIDE = """
Use these six connection types, each tagged at the start of its bullet as **[T<number><sign>]**:

T1 - Wrote about a past figure. Sign: + on the EARLIER/written-about figure's own dossier, - on the LATER figure who did the writing. On THIS dossier, use whichever sign applies to this subject's role in that pair.
T2 - Prophecy/hyperstition: an earlier figure's prophecy predicts OR causally helps manifest a later figure. Sign: + earlier/prophet, - later/fulfiller. Add a subtype word in the tag: prediction (retrofitted match after the fact, no causal role), hyperstition (belief in the prophecy caused people to act in ways that produced the outcome), or unresolved. Example tags: [T2+ hyperstition], [T2- prediction].
T3 - Discourse: correspondence, mutual or one-sided written engagement, or one seeing the other perform. No sign (undirected).
T4 - Proximity/milieu: same time and place, not necessarily interacting. No sign.
T5 - Friendship or personal meeting. No sign.
T9 - Shared object or site as the connector, without shared occupancy (an instrument, manuscript, relic, or place that passed between them). Sign: + on whoever came first/originated it, - on whoever came later.

Do not force a connection: only record what evidence actually supports. Never infer one from mere contemporaneity, shared geography, subject matter, or tradition alone. If nothing is supported for a given roster name, omit it or note the absence briefly -- absence is a finding, not a gap to fill.
"""


def log(msg, worker=None):
    tag = f'[w{worker}] ' if worker is not None else ''
    line = time.strftime('%m-%d %H:%M:%S ') + tag + msg
    print(line, flush=True)
    open(f'{LAB}/connections_phase0.log', 'a').write(line + '\n')


def catalog_rows():
    return list(csv.DictReader(open(f'{REPO}/catalog_subjects.csv')))


def roster_text(rows):
    return '\n'.join(f"{r['slug']}: {r['traveler'].split('(')[0].split(',')[0].strip()}"
                      for r in rows if r['slug'])


def build_worklist(rows):
    slugs = []
    for r in rows:
        slug = r['slug']
        path = f'{REPO}/dossiers/{slug}.dossier.md'
        if not os.path.exists(path):
            continue
        text = open(path, encoding='utf-8', errors='replace').read()
        if 'atlas connection' in text.lower():
            continue
        slugs.append(slug)
    return slugs


def build_prompt(name, dossier_text, roster):
    return f"""You are adding ONLY a new "## Atlas Connections" section to an existing, already-complete research dossier on {name}. Do not summarize, critique, or rewrite any other part of the dossier -- your job is exclusively to research and report this subject's documented crossings with the atlas roster below.

EXISTING DOSSIER ON {name} (context only, do not reproduce it):
---
{dossier_text}
---

ATLAS ROSTER (slug: name) -- check for genuine documented crossings between {name} and any of these {len(roster.splitlines())} people:
---
{roster}
---
{TYPE_GUIDE}

Use web search to verify or find connections not already evident in the dossier text above. For each connection found, write one bullet under a "### <Counterpart Name>" subheading, giving: the tag, the nature of the connection, dates/places where known, and the same evidentiary label convention used elsewhere in this project (documented fact / reported fact / allegation or theory / rumor or myth). If nothing at all is supported for the roster as a whole, say so plainly in a short closing paragraph -- do not fabricate to fill space.

Print your result as a single markdown block, starting with the exact line
{MARK_START}
followed by a heading "## Atlas Connections" and your content, and ending with the exact line
{MARK_END}
Print nothing else outside those two marker lines. Do not attempt file writes or shell commands."""


def extract(logtext):
    i = logtext.rfind(MARK_START)
    j = logtext.rfind(MARK_END)
    if i < 0 or j < 0 or j <= i:
        return None
    return logtext[i + len(MARK_START):j].strip()


def quota_wall(text):
    return re.search(r'rate.limit|usage limit (reached|exceeded)|too many requests|error 429'
                      r'|at capacity|try a different model|internal server error|error 5\d\d'
                      r'|reconnecting\.\.\.|unexpected status \d+',
                      text[-2000:], re.I)


def claim_next(slugs):
    with LOCK:
        for slug in slugs:
            if slug in IN_PROGRESS:
                continue
            if os.path.exists(f'{OUT}/{slug}.section.md'):
                continue
            IN_PROGRESS.add(slug)
            return slug
        return None


def release(slug):
    with LOCK:
        IN_PROGRESS.discard(slug)


def run_one(slug, name, dossier_text, roster, worker):
    prompt = build_prompt(name, dossier_text, roster)
    logfile = f'{LAB}/run0_{slug}.log'
    log(f'{slug}: run ({name})', worker)
    try:
        with open(logfile, 'w') as lf:
            subprocess.run([CODEX, 'exec', '-s', 'workspace-write', '--skip-git-repo-check',
                             '-C', LAB, '-c', 'tools.web_search=true', '-'],
                            input=prompt, stdout=lf, stderr=subprocess.STDOUT,
                            text=True, timeout=2700,
                            env={**os.environ, 'HOME': HOME,
                                 'PATH': f'{HOME}/.local/bin:' + os.environ.get('PATH', '')})
    except subprocess.TimeoutExpired:
        log(f'{slug}: TIMEOUT, will retry', worker)
        return False
    text = open(logfile, encoding='utf-8', errors='replace').read()
    if quota_wall(text):
        return 'quota'
    section = extract(text)
    if not section:
        log(f'{slug}: no section markers found, tail: ' + text[-160:].replace('\n', ' '), worker)
        return False
    if re.search(r'\nERROR: ', section):
        log(f'{slug}: section contains an ERROR: line, discarding', worker)
        return False
    if '## Atlas Connections' not in section:
        section = '## Atlas Connections\n\n' + section
    open(f'{OUT}/{slug}.section.md', 'w').write(section)
    log(f'{slug}: DONE {section.count(chr(10))} lines', worker)
    return True


def worker_loop(worker, slugs, name_by_slug, text_by_slug, roster):
    quota_step = 0
    while True:
        slug = claim_next(slugs)
        if slug is None:
            return
        try:
            result = run_one(slug, name_by_slug[slug], text_by_slug[slug], roster, worker)
        finally:
            release(slug)
        if result == 'quota':
            wait = QUOTA_SLEEPS[min(quota_step, len(QUOTA_SLEEPS) - 1)]
            quota_step += 1
            log(f'quota wall; sleeping {wait // 60} min', worker)
            time.sleep(wait)
            continue
        quota_step = 0
        if result is not True:
            with LOCK:
                FAILURES[slug] = FAILURES.get(slug, 0) + 1
                n = FAILURES[slug]
            if n >= 3:
                log(f'{slug}: 3 failures, giving up', worker)
                open(f'{OUT}/{slug}.section.md', 'w').write('# skipped: repeated failures\n')
            time.sleep(30)


def main():
    os.makedirs(OUT, exist_ok=True)
    rows = catalog_rows()
    roster = roster_text(rows)
    slugs = build_worklist(rows)
    name_by_slug = {r['slug']: r['traveler'].split('(')[0].split(',')[0].strip() for r in rows}
    text_by_slug = {s: open(f'{REPO}/dossiers/{s}.dossier.md', encoding='utf-8', errors='replace').read()
                    for s in slugs}
    log(f'=== phase 0 starting: {len(slugs)} subjects need a connections section, {WORKERS} workers')
    threads = [threading.Thread(target=worker_loop, args=(i, slugs, name_by_slug, text_by_slug, roster),
                                 daemon=True) for i in range(WORKERS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    log('=== phase 0 complete')


if __name__ == '__main__':
    main()
