#!/usr/bin/env python3
"""The dossier machine: work through ~/codex_lab/worklist.txt unattended.

Loop: take the next slug whose dossier exists in neither dossiers/ nor
~/codex_lab/out/, assemble the prompt (PROMPT_TEMPLATE body + display name +
delivery clause + ATLAS_CONNECTIONS_ADDENDUM), run `codex exec` with the
prompt on stdin, extract the dossier from the final print in the run log,
run mechanical checks, save to ~/codex_lab/out/<slug>.dossier.md, append a
status line to ~/codex_lab/batch.log. Repeat until the worklist is done,
then sleep and re-check hourly (new subjects appear as the queue breathes).

Deliberate properties:
  - The sandbox on this box cannot write files (bwrap userns restriction),
    so dossiers are delivered as the model's printed final message.
  - Real quota walls (matched only in the log TAIL: the echoed prompt
    contains the word "quotations") trigger exponential backoff.
  - Every N completions the runner pulls the repo and regenerates the
    addendum so the roster stays current.
  - Kill and restart at will: done work is skipped by file existence.

Run under tmux:  tmux -L codexbatch new-session -d -s runner \\
    "python3 ~/codex_lab/codex_dossier_runner.py >> ~/codex_lab/runner.log 2>&1"
"""
import csv, os, re, subprocess, time

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
TRAILER = 'Co-Authored-By: El Gólem <golem@localhost>'

def log(msg):
    line = time.strftime('%m-%d %H:%M:%S ') + msg
    print(line, flush=True)
    open(f'{LAB}/batch.log', 'a').write(line + '\n')

def display_name(slug):
    for r in csv.DictReader(open(f'{REPO}/catalog_subjects.csv')):
        if r['slug'] == slug:
            return r['traveler'].split('(')[0].split(',')[0].strip()
    return None

def build_prompt(name):
    tpl = open(f'{REPO}/dossiers/PROMPT_TEMPLATE.md').read().split('---', 1)[1].strip()
    tpl = tpl.replace('[NAME]', name).replace('[name]', name)
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
    return re.search(r'rate.limit|usage limit (reached|exceeded)|too many requests|error 429',
                     text[-2000:], re.I)

def refresh_repo():
    subprocess.run(['git', 'pull', '--ff-only', '-q'],
                   cwd=f'{HOME}/taller/Colegio_Invisible', capture_output=True)
    subprocess.run(['python3', 'atlas_tools/make_addendum.py'],
                   cwd=REPO, capture_output=True)

def git_stage(cmd):
    return subprocess.run(['git'] + cmd, cwd=STAGE_REPO, capture_output=True, text=True)

def auto_stage(slug, name, doc):
    """Deterministic staging of a clean dossier into the runner's own clone.
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

def next_slug():
    if not os.path.exists(WORKLIST):
        return None
    for line in open(WORKLIST):
        slug = line.strip()
        if not slug or slug.startswith('#'):
            continue
        if os.path.exists(f'{OUT}/{slug}.dossier.md'):
            continue
        if os.path.exists(f'{REPO}/dossiers/{slug}.dossier.md'):
            continue
        if os.path.exists(f'{STAGE_REPO}/working/journeys/dossiers/{slug}.dossier.md'):
            continue
        return slug
    return None

def run_one(slug):
    name = display_name(slug)
    if not name:
        log(f'{slug}: NOT IN CATALOG, marking skipped')
        open(f'{OUT}/{slug}.dossier.md', 'w').write('# skipped: not in catalog\n')
        return True
    prompt = build_prompt(name)
    logfile = f'{LAB}/run_{slug}.log'
    log(f'{slug}: run ({name})')
    try:
        with open(logfile, 'w') as lf:
            subprocess.run([CODEX, 'exec', '-s', 'workspace-write', '--skip-git-repo-check',
                            '-C', LAB, '-c', 'tools.web_search=true', '-'],
                           input=prompt, stdout=lf, stderr=subprocess.STDOUT,
                           text=True, timeout=5400,
                           env={**os.environ, 'HOME': HOME,
                                'PATH': f'{HOME}/.local/bin:' + os.environ.get('PATH', '')})
    except subprocess.TimeoutExpired:
        log(f'{slug}: TIMEOUT after 90 min, will retry next pass')
        return False
    text = open(logfile).read()
    if quota_wall(text):
        return 'quota'
    doc = extract(text, name)
    if not doc:
        log(f'{slug}: no dossier in output, tail: ' + text[-160:].replace('\n', ' '))
        return False
    probs = checks(doc)
    if probs:
        open(f'{OUT}/{slug}.dossier.md', 'w').write(doc)
        log(f'{slug}: DONE {doc.count(chr(10))} lines, held in out/ FLAGS: {"; ".join(probs)}')
        return True
    if auto_stage(slug, name, doc):
        log(f'{slug}: DONE {doc.count(chr(10))} lines, STAGED')
    else:
        open(f'{OUT}/{slug}.dossier.md', 'w').write(doc)
        log(f'{slug}: DONE {doc.count(chr(10))} lines, staging failed, held in out/')
    return True

def main():
    os.makedirs(OUT, exist_ok=True)
    done_since_refresh = 0
    quota_step = 0
    failures = {}
    log('=== runner starting')
    while True:
        slug = next_slug()
        if slug is None:
            log('worklist clear; sleeping 1h and refreshing')
            refresh_repo()
            time.sleep(3600)
            continue
        if failures.get(slug, 0) >= 3:
            log(f'{slug}: 3 failures, marking skipped for human review')
            open(f'{OUT}/{slug}.dossier.md', 'w').write('# skipped: repeated failures\n')
            continue
        result = run_one(slug)
        if result == 'quota':
            wait = QUOTA_SLEEPS[min(quota_step, len(QUOTA_SLEEPS) - 1)]
            quota_step += 1
            log(f'quota wall; sleeping {wait // 60} min (step {quota_step})')
            time.sleep(wait)
            continue
        quota_step = 0
        if result is True:
            done_since_refresh += 1
            if done_since_refresh >= REFRESH_EVERY:
                refresh_repo()
                done_since_refresh = 0
                log('repo pulled, addendum regenerated')
        else:
            failures[slug] = failures.get(slug, 0) + 1
            time.sleep(60)

if __name__ == '__main__':
    main()
