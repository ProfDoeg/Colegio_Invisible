#!/usr/bin/env python3
"""The dossier machine: work through ~/codex_lab/worklist.txt unattended.

Loop: take the next slug whose dossier exists in neither dossiers/ nor
~/codex_lab/out/, assemble the prompt (PROMPT_TEMPLATE body + display name +
delivery clause + ATLAS_CONNECTIONS_ADDENDUM), run `codex exec` with the
prompt on stdin, extract the dossier from the final print in the run log,
run mechanical checks, save to ~/codex_lab/out/<slug>.dossier.md, append a
status line to ~/codex_lab/batch.log. Repeat until the worklist is done,
then sleep and re-check hourly (new subjects appear as the queue breathes).

2026-09-04: runs WORKERS threads concurrently (default 5, override with the
WORKERS env var). All shared-state mutations - claiming the next slug,
pulling/committing/pushing STAGE_REPO, the periodic repo refresh, the
failures counter - go through one global lock, LOCK. The slow part (the
actual `codex exec` web-research call, several minutes) runs OUTSIDE the
lock, which is where the concurrency actually helps; everything touching
shared git state or shared in-memory counters is serialized so N workers
can never race each other onto the same subject or corrupt STAGE_REPO's
working tree with concurrent git operations.

Deliberate properties:
  - The sandbox on this box cannot write files (bwrap userns restriction),
    so dossiers are delivered as the model's printed final message.
  - Real quota walls (matched only in the log TAIL: the echoed prompt
    contains the word "quotations") trigger exponential backoff, tracked
    per-worker so one worker backing off does not stall the others.
  - Every N completions (shared across all workers) the runner pulls the
    repo and regenerates the addendum so the roster stays current.
  - Kill and restart at will: done work is skipped by file existence.

Run under tmux:  tmux -L codexbatch new-session -d -s runner \\
    "python3 ~/codex_lab/codex_dossier_runner.py >> ~/codex_lab/runner.log 2>&1"
"""
import csv, os, re, subprocess, threading, time

HOME = os.path.expanduser('~')
REPO = f'{HOME}/taller/Colegio_Invisible/working/journeys'
LAB = f'{HOME}/codex_lab'
OUT = f'{LAB}/out'
CODEX = f'{HOME}/.local/bin/codex'
WORKLIST = f'{LAB}/worklist.txt'
STAGE_REPO = f'{LAB}/repo'  # the runner's own clone; staging is deterministic
                            # code here, not an agent tapping approve (the
                            # land_subject.py precedent)
REFRESH_EVERY = 15          # completions between repo pull + addendum regen
QUOTA_SLEEPS = [900, 1800, 3600, 7200]   # backoff ladder on real quota walls
WORKERS = int(os.environ.get('WORKERS', '5'))
TRAILER = 'Co-Authored-By: El Gólem <golem@localhost>'

LOCK = threading.Lock()          # guards next_slug(), STAGE_REPO git ops,
                                  # refresh_repo(), the failures dict
IN_PROGRESS = set()              # slugs currently claimed by a worker
STATE = {'done_since_refresh': 0, 'failures': {}}

def log(msg, worker=None):
    tag = f'[w{worker}] ' if worker is not None else ''
    line = time.strftime('%m-%d %H:%M:%S ') + tag + msg
    print(line, flush=True)
    open(f'{LAB}/batch.log', 'a').write(line + '\n')

def catalog_row(slug):
    for r in csv.DictReader(open(f'{REPO}/catalog_subjects.csv')):
        if r['slug'] == slug:
            return r
    return None

def subject_hint(row):
    """2026-09-03: bare names like "Arthur Ben" got REFUSED by Codex as
    unidentifiable, even though every one of them already has a full,
    built journey in the atlas (a real, specific person, not an ambiguous
    search) -- the worklist prompt just never told Codex that. This atlas
    already has a dossier gap for EVERY subject, built or not, per Anthony;
    a bare name with no disambiguation is the actual bug. Feed the existing
    journey's own title/years/traveler string back in as a hint whenever
    one exists, so Codex knows exactly who it is confirming, not guessing."""
    if not row or row.get('status') != 'built':
        return ''
    bits = []
    if row.get('traveler'):
        bits.append(f"Full name/description on file: {row['traveler']}")
    if row.get('years'):
        bits.append(f"Life dates on file: {row['years']}")
    if row.get('title'):
        bits.append(f"This atlas already has a journey for them titled: \"{row['title']}\"")
    if not bits:
        return ''
    return ('\n\nIDENTIFICATION HINT (this atlas already has this exact person '
            'documented -- use this to confirm identity, not as a source of '
            'facts to merely restate): ' + '. '.join(bits) + '.')

def build_prompt(name, hint=''):
    tpl = open(f'{REPO}/dossiers/PROMPT_TEMPLATE.md').read().split('---', 1)[1].strip()
    tpl = tpl.replace('[NAME]', name).replace('[name]', name) + hint
    add = open(f'{REPO}/dossiers/ATLAS_CONNECTIONS_ADDENDUM.md').read().split('---', 1)[1].strip()
    deliver = (f'\n\nUse web search extensively for sources. Run a DEDICATED adversarial pass: '
               f'search explicitly for "{name}" combined with controversy, scandal, allegations, '
               f'lawsuit, fraud, accusations, conspiracy, criticism, and the like, including the '
               f'most recent two years; the dossier must engage the major negative and contested '
               f'material with the usual evidentiary labels rather than omit it. Do not attempt '
               f'file writes or shell commands. Print the complete finished dossier, in full, as '
               f'your final message: a single Markdown document titled "# {name}: Research '
               f'Dossier", including the Atlas Connections section, ending with the full list '
               f'of source URLs.')
    return tpl + deliver + '\n\n' + add

def extract(logtext, name):
    marker = f'# {name}: Research Dossier'
    i = logtext.rfind(marker)
    if i < 0:
        i = logtext.rfind('# ' + name)
    if i < 0:
        return None
    return re.sub(r'\ntokens used\n[\d,]+\s*$', '\n', logtext[i:])

def checks(doc):
    problems = []
    lines = doc.count('\n')
    if lines < 350: problems.append(f'short ({lines} lines)')
    if 'http' not in doc[-4000:]: problems.append('no source list at end')
    if 'Atlas Connections' not in doc: problems.append('no Atlas Connections section')
    conn = doc.split('Atlas Connections', 1)[-1]
    META = {'finding', 'findings', 'audit', 'result', 'results', 'summary',
            'negative', 'none', 'absence', 'note', 'notes', 'method'}
    for h in re.findall(r'^### (.+)$', conn, re.M):
        if META & {w.strip('*,():').lower() for w in h.split()}:
            continue                      # meta-sections are not person entries
        words = [w.strip('*,()') for w in h.split() if len(w.strip('*,()')) >= 4]
        block = conn.split('### ' + h, 1)[-1][:1200].lower()
        # any name-word appearing in the body clears the entry (bodies usually
        # use surnames; the old first-word check false-flagged "Peter A. Thiel")
        if words and not any(w.lower() in block for w in words):
            problems.append(f'header not echoed: {h[:40]}')
    return problems

def quota_wall(text):
    # "Selected model is at capacity" (2026-09-02 incident): this pattern was
    # NOT caught here, so quota_wall() returned false, extract() then matched
    # the echoed prompt's own "# {name}: Research Dossier" title text (the
    # delivery instructions quote it verbatim) rather than real model output,
    # and 388 garbage "dossiers" (prompt + roster + this error, nothing else)
    # got written to out/ and logged DONE before anyone caught it. Any of
    # these phrases must trigger the same sleep-and-retry path as a quota
    # wall, never fall through to extract().
    # 2026-09-03: "ERROR: Reconnecting... N/5" then "ERROR: unexpected status
    # 404 Not Found ... codex/responses" is the same class of transient
    # backend trouble as a quota wall and deserves the same backoff sleep,
    # not an immediate retry.
    return re.search(r'rate.limit|usage limit (reached|exceeded)|too many requests|error 429'
                     r'|at capacity|try a different model|internal server error|error 5\d\d'
                     r'|reconnecting\.\.\.|unexpected status \d+',
                     text[-2000:], re.I)

def refresh_repo_locked():
    """Caller must hold LOCK."""
    subprocess.run(['git', 'pull', '--ff-only', '-q'],
                   cwd=f'{HOME}/taller/Colegio_Invisible', capture_output=True)
    subprocess.run(['python3', 'atlas_tools/make_addendum.py'],
                   cwd=REPO, capture_output=True)

def git_stage(cmd):
    return subprocess.run(['git'] + cmd, cwd=STAGE_REPO, capture_output=True, text=True)

def auto_stage_locked(slug, name, doc):
    """Deterministic staging of a clean dossier into the runner's own clone.
    Caller must hold LOCK - this touches STAGE_REPO's working tree and
    .git, which is not safe for concurrent access from multiple workers.
    Returns True on success; on any git trouble the file stays in out/ for
    the review path instead."""
    if not os.path.isdir(STAGE_REPO):
        return False
    dest_rel = 'working/journeys/dossiers/' + slug + '.dossier.md'
    git_stage(['pull', '--ff-only', '-q'])
    open(os.path.join(STAGE_REPO, dest_rel), 'w').write(doc)
    git_stage(['add', dest_rel])
    r = git_stage(['commit', '-q', '-m', f'Stage codex dossier: {name}',
                   '-m', 'Codex-researched, roster-aware; staged deterministically by the runner.',
                   '-m', TRAILER])
    if r.returncode != 0:
        return False
    for attempt in (1, 2):
        if git_stage(['push', '-q']).returncode == 0:
            break
        git_stage(['pull', '--rebase', '-q'])
    git_stage(['push', '-q', 'github'])
    return True

def claim_next_slug():
    """Atomically pick a slug no one else is working on and mark it claimed.
    Returns None if the worklist is exhausted (of unclaimed subjects) right
    now - callers should back off and retry rather than treat that as
    permanently done, since another worker's in-flight subject will free up
    eventually, and the worklist itself may grow."""
    with LOCK:
        if not os.path.exists(WORKLIST):
            return None
        # 2026-09-03 incident: STAGE_REPO (this dedup source) only used to
        # refresh opportunistically inside auto_stage(), i.e. only on a
        # completion. Dossiers staged externally (pushed straight to
        # origin) went unseen until this clone happened to refresh, which
        # could be many hours later. Result: "Abu Karib As'ad" got
        # re-researched from scratch 13 hours apart, twice. Pull fresh on
        # every claim - cheap when there is nothing new, and it is the
        # only thing standing between "already have it" and redoing work.
        if os.path.isdir(STAGE_REPO):
            subprocess.run(['git', 'pull', '--ff-only', '-q'], cwd=STAGE_REPO,
                           capture_output=True)
        for line in open(WORKLIST):
            slug = line.strip()
            if not slug or slug.startswith('#'):
                continue
            if slug in IN_PROGRESS:
                continue
            if os.path.exists(f'{OUT}/{slug}.dossier.md'):
                continue
            if os.path.exists(f'{REPO}/dossiers/{slug}.dossier.md'):
                continue
            if os.path.exists(f'{STAGE_REPO}/working/journeys/dossiers/{slug}.dossier.md'):
                continue
            IN_PROGRESS.add(slug)
            return slug
        return None

def release_slug(slug):
    with LOCK:
        IN_PROGRESS.discard(slug)

def record_failure(slug):
    with LOCK:
        STATE['failures'][slug] = STATE['failures'].get(slug, 0) + 1
        return STATE['failures'][slug]

def note_completion_locked_maybe_refresh():
    """Bump the shared completion counter; refresh the repo every
    REFRESH_EVERY across ALL workers combined, not per-worker."""
    with LOCK:
        STATE['done_since_refresh'] += 1
        if STATE['done_since_refresh'] >= REFRESH_EVERY:
            refresh_repo_locked()
            STATE['done_since_refresh'] = 0
            log('repo pulled, addendum regenerated')

def run_one(slug, worker):
    row = catalog_row(slug)
    name = row['traveler'].split('(')[0].split(',')[0].strip() if row else None
    if not name:
        log(f'{slug}: NOT IN CATALOG, marking skipped', worker)
        open(f'{OUT}/{slug}.dossier.md', 'w').write('# skipped: not in catalog\n')
        return True
    prompt = build_prompt(name, subject_hint(row))
    logfile = f'{LAB}/run_{slug}.log'
    log(f'{slug}: run ({name})', worker)
    try:
        with open(logfile, 'w') as lf:
            subprocess.run([CODEX, 'exec', '-s', 'workspace-write', '--skip-git-repo-check',
                            '-C', LAB, '-c', 'tools.web_search=true', '-'],
                           input=prompt, stdout=lf, stderr=subprocess.STDOUT,
                           text=True, timeout=5400,
                           env={**os.environ, 'HOME': HOME,
                                'PATH': f'{HOME}/.local/bin:' + os.environ.get('PATH', '')})
    except subprocess.TimeoutExpired:
        log(f'{slug}: TIMEOUT after 90 min, will retry next pass', worker)
        return False
    text = open(logfile).read()
    if quota_wall(text):
        return 'quota'
    doc = extract(text, name)
    if not doc:
        log(f'{slug}: no dossier in output, tail: ' + text[-160:].replace('\n', ' '), worker)
        return False
    # 2026-09-03 incident #2: a run of network failures ("ERROR: Reconnecting...
    # N/5" then "ERROR: unexpected status 404 Not Found ... codex/responses")
    # produced 113 more garbage stubs the same way as the 2026-09-02 capacity
    # incident - a NEW error string quota_wall() didn't have, so extract()
    # again matched the echoed prompt instead of real output. Rather than
    # keep enumerating every possible CLI error phrase (whack-a-mole),
    # reject on principle: a real dossier never contains a literal CLI
    # "ERROR: " line. Catches this class of failure regardless of the exact
    # wording of whatever error OpenAI's side produces next.
    if re.search(r'\nERROR: ', doc):
        log(f'{slug}: extracted doc contains an ERROR: line, discarding, tail: '
            + text[-160:].replace('\n', ' '), worker)
        return False
    probs = checks(doc)
    if probs:
        open(f'{OUT}/{slug}.dossier.md', 'w').write(doc)
        log(f'{slug}: DONE {doc.count(chr(10))} lines, held in out/ FLAGS: {"; ".join(probs)}', worker)
        return True
    with LOCK:
        staged = auto_stage_locked(slug, name, doc)
    if staged:
        log(f'{slug}: DONE {doc.count(chr(10))} lines, STAGED', worker)
    else:
        open(f'{OUT}/{slug}.dossier.md', 'w').write(doc)
        log(f'{slug}: DONE {doc.count(chr(10))} lines, staging failed, held in out/', worker)
    return True

def worker_loop(worker):
    quota_step = 0
    while True:
        slug = claim_next_slug()
        if slug is None:
            # Worklist has nothing free right now - could be genuinely done,
            # or every remaining subject is claimed by other workers.
            # Refresh on worker 0 only, so N workers don't all pull/regen
            # the addendum in lockstep every idle tick.
            if worker == 0:
                with LOCK:
                    refresh_repo_locked()
            time.sleep(60)
            continue
        try:
            result = run_one(slug, worker)
        finally:
            release_slug(slug)
        if result == 'quota':
            wait = QUOTA_SLEEPS[min(quota_step, len(QUOTA_SLEEPS) - 1)]
            quota_step += 1
            log(f'quota wall; sleeping {wait // 60} min (step {quota_step})', worker)
            time.sleep(wait)
            continue
        quota_step = 0
        if result is True:
            note_completion_locked_maybe_refresh()
        else:
            n = record_failure(slug)
            if n >= 3:
                log(f'{slug}: 3 failures, marking skipped for human review', worker)
                open(f'{OUT}/{slug}.dossier.md', 'w').write('# skipped: repeated failures\n')
            time.sleep(60)

def main():
    os.makedirs(OUT, exist_ok=True)
    log(f'=== runner starting, {WORKERS} workers')
    threads = [threading.Thread(target=worker_loop, args=(i,), daemon=True)
               for i in range(WORKERS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

if __name__ == '__main__':
    main()
