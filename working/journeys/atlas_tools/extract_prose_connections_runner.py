#!/usr/bin/env python3
"""Phase 1b: LLM-based extraction of the ~779 dossiers whose Atlas
Connections section is prose-only (pre-2026-09-05 format) or empty, into
the same structured record shape extract_tagged_connections.py produces
for the already-tagged 117. No web search needed -- this only reads text
already in the dossier and classifies it against the six connection types
agreed with Anthony on 2026-09-05.

Read-only against dossiers (never edits them). Each job reads one file
and writes one sidecar to ~/codex_lab/extracted/<slug>.json -- no shared
git state, no STAGE_REPO, so the concurrency story is simpler than the
dossier-writing runner: claim-a-slug is the only thing that needs a lock.

Run under tmux:  tmux -L codexbatch new-session -d -s extract1 \\
    "HOME=/home/drdoeg WORKERS=5 python3 ~/codex_lab/extract_prose_connections_runner.py >> ~/codex_lab/extract1_stdout.log 2>&1"
"""
import csv, json, os, re, subprocess, threading, time

HOME = os.path.expanduser('~')
REPO = f'{HOME}/taller/Colegio_Invisible/working/journeys'
LAB = f'{HOME}/codex_lab'
OUT = f'{LAB}/extracted'
CODEX = f'{HOME}/.local/bin/codex'
WORKERS = int(os.environ.get('WORKERS', '5'))
QUOTA_SLEEPS = [900, 1800, 3600]

LOCK = threading.Lock()
IN_PROGRESS = set()
FAILURES = {}

MARK_START = '=== EXTRACT_JSON_START ==='
MARK_END = '=== EXTRACT_JSON_END ==='

TYPE_GUIDE = """
Classify each connection you find into exactly one of these six types, matching this project's fixed scheme:

1 - Wrote about a past figure. sign "+" if THIS dossier's subject is the EARLIER/written-about figure, "-" if THIS subject is the LATER one doing the writing.
2 - Prophecy/hyperstition: an earlier figure's prophecy predicts OR causally helps manifest a later figure. sign "+" if this subject is the earlier/prophet, "-" if the later/fulfiller. subtype: "prediction" (retrofitted match, no causal role), "hyperstition" (belief in the prophecy caused people to act in ways that produced the outcome), or "unresolved".
3 - Discourse: correspondence, mutual or one-sided written engagement, or one seeing the other perform. sign "" (undirected).
4 - Proximity/milieu: same time and place, not necessarily interacting. sign "" (undirected).
5 - Friendship or personal meeting. sign "" (undirected).
9 - Shared object or site as the connector, without shared occupancy. sign "+" if this subject came first/originated it, "-" if later.
"""


def log(msg, worker=None):
    tag = f'[w{worker}] ' if worker is not None else ''
    line = time.strftime('%m-%d %H:%M:%S ') + tag + msg
    print(line, flush=True)
    open(f'{LAB}/extract1.log', 'a').write(line + '\n')


def catalog_rows():
    return list(csv.DictReader(open(f'{REPO}/catalog_subjects.csv')))


def connections_section(text):
    m = re.search(r'^#+ .*Atlas Connections.*$', text, re.M)
    if not m:
        return ''
    rest = text[m.end():]
    nxt = re.search(r'^## ', rest, re.M)
    return rest[:nxt.start()] if nxt else rest


def build_worklist(rows):
    already = {f[:-5] for f in os.listdir(OUT) if f.endswith('.json')}
    slugs = []
    for r in rows:
        slug = r['slug']
        if slug in already:
            continue
        path = f'{REPO}/dossiers/{slug}.dossier.md'
        if not os.path.exists(path):
            continue
        slugs.append(slug)
    return slugs


def build_prompt(name, section_text):
    return f"""Below is the "Atlas Connections" section of an existing, already-researched dossier on {name}. Your job is ONLY to classify what it already says into structured records -- do not research anything new, do not add facts not already present, do not use web search or any tool.

ATLAS CONNECTIONS SECTION (subject: {name}):
---
{section_text if section_text.strip() else '(This section is empty or contains no specific documented connection.)'}
---
{TYPE_GUIDE}

For each specific named counterpart the text documents an ACTUAL connection with (skip generic/meta headers like "Other roster members", "Method", "Findings", and skip entries that explicitly say NO connection was found), emit one JSON object:
  {{"counterpart_name_raw": "<name as written>", "type": <1|2|3|4|5|9>, "sign": "+"|"-"|"", "subtype": "prediction"|"hyperstition"|"unresolved"|null, "text": "<one-sentence paraphrase of the claim, in your own words>"}}

If a header lists multiple people (e.g. "Abraham, Moses, and other biblical figures"), emit one record per named person, each with the same type/sign/text. If the whole section documents no genuine connections at all, output an empty array.

Print your result as exactly:
{MARK_START}
<JSON array, and nothing else>
{MARK_END}
Print nothing outside those two marker lines."""


def extract_json(logtext):
    i = logtext.rfind(MARK_START)
    j = logtext.rfind(MARK_END)
    if i < 0 or j < 0 or j <= i:
        return None
    raw = logtext[i + len(MARK_START):j].strip()
    raw = re.sub(r'^```(json)?', '', raw).strip()
    raw = re.sub(r'```$', '', raw).strip()
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass
    return None


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
            if os.path.exists(f'{OUT}/{slug}.json'):
                continue
            IN_PROGRESS.add(slug)
            return slug
        return None


def release(slug):
    with LOCK:
        IN_PROGRESS.discard(slug)


def run_one(slug, name, section_text, worker):
    prompt = build_prompt(name, section_text)
    logfile = f'{LAB}/run1_{slug}.log'
    log(f'{slug}: run ({name})', worker)
    try:
        with open(logfile, 'w') as lf:
            subprocess.run([CODEX, 'exec', '-s', 'workspace-write', '--skip-git-repo-check',
                             '-C', LAB, '-c', 'tools.web_search=false', '-'],
                            input=prompt, stdout=lf, stderr=subprocess.STDOUT,
                            text=True, timeout=600,
                            env={**os.environ, 'HOME': HOME,
                                 'PATH': f'{HOME}/.local/bin:' + os.environ.get('PATH', '')})
    except subprocess.TimeoutExpired:
        log(f'{slug}: TIMEOUT, will retry', worker)
        return False
    text = open(logfile, encoding='utf-8', errors='replace').read()
    if quota_wall(text):
        return 'quota'
    data = extract_json(text)
    if data is None:
        log(f'{slug}: no valid JSON found, tail: ' + text[-160:].replace('\n', ' '), worker)
        return False
    records = [{**rec, 'counterpart_slug': None} for rec in data]
    json.dump(records, open(f'{OUT}/{slug}.json', 'w'), indent=1, ensure_ascii=False)
    log(f'{slug}: DONE {len(records)} records', worker)
    return True


def worker_loop(worker, slugs, name_by_slug, section_by_slug):
    quota_step = 0
    while True:
        slug = claim_next(slugs)
        if slug is None:
            return
        try:
            result = run_one(slug, name_by_slug[slug], section_by_slug[slug], worker)
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
                json.dump([], open(f'{OUT}/{slug}.json', 'w'))
            time.sleep(15)


def main():
    os.makedirs(OUT, exist_ok=True)
    rows = catalog_rows()
    slugs = build_worklist(rows)
    name_by_slug = {r['slug']: r['traveler'].split('(')[0].split(',')[0].strip() for r in rows}
    section_by_slug = {}
    for s in slugs:
        text = open(f'{REPO}/dossiers/{s}.dossier.md', encoding='utf-8', errors='replace').read()
        section_by_slug[s] = connections_section(text)
    log(f'=== extraction phase 1b starting: {len(slugs)} subjects, {WORKERS} workers')
    threads = [threading.Thread(target=worker_loop, args=(i, slugs, name_by_slug, section_by_slug),
                                 daemon=True) for i in range(WORKERS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    log('=== extraction phase 1b complete')


if __name__ == '__main__':
    main()
