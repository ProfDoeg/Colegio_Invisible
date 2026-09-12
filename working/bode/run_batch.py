#!/usr/bin/env python3
"""Run the Bode collection dossiers unattended: N at a time, skipping any that exist,
committing and pushing each one as it lands (exact paths, both remotes), logging to
working/bode/batch_progress.log. Deterministic, no model in the loop, per the
land_subject.py precedent.

    python3 working/bode/run_batch.py [concurrency]

The list and order come from make_briefs.py's ORDER (briefs/<slug>.brief.md must exist).
"""
import os, subprocess, sys, threading, time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
RUNNER = os.path.join(REPO, "working", "journeys", "atlas_tools", "codex_dossier_bode.py")
PROGRESS = os.path.join(HERE, "batch_progress.log")
sys.path.insert(0, HERE)
from make_briefs import ORDER, SIGNS      # noqa: E402

N = int(sys.argv[1]) if len(sys.argv) > 1 else 3
git_lock = threading.Lock()


def log(msg):
    line = time.strftime("%m-%d %H:%M:%S ") + msg
    print(line, flush=True)
    open(PROGRESS, "a").write(line + "\n")


def git(*args):
    return subprocess.run(["git", "-C", REPO, *args], capture_output=True, text=True)


def land(slug, name):
    rel = f"working/bode/{slug}.dossier.md"
    with git_lock:
        git("add", rel)
        git("commit", "-q", "-m", f"bode: {name} dossier", "-m",
            "Codex-researched from the constellation prompt and the per-figure brief (working/bode). "
            "Separate from the atlas.", "-m", "Co-Authored-By: El Gólem <golem@localhost>")
        for remote in ("origin", "github"):
            r = git("push", remote, "main")
            if r.returncode != 0:
                log(f"  push to {remote} failed: {r.stderr.strip()[:200]}")


def one(slug):
    name = SIGNS[slug][0]
    out = os.path.join(HERE, f"{slug}.dossier.md")
    if os.path.exists(out):
        log(f"skip {slug}: exists"); return slug, "exists"
    brief = os.path.join(HERE, "briefs", f"{slug}.brief.md")
    log(f"start {slug} ({name})")
    r = subprocess.run([sys.executable, RUNNER, slug, name, brief], capture_output=True, text=True)
    if r.returncode == 0 and os.path.exists(out):
        lines = sum(1 for _ in open(out))
        land(slug, name)
        log(f"DONE {slug}: {lines} lines, committed and pushed"); return slug, "done"
    log(f"FAIL {slug}: rc={r.returncode} {r.stdout.strip()[-200:]}"); return slug, "fail"


if __name__ == "__main__":
    todo = [s for s in ORDER if not os.path.exists(os.path.join(HERE, f"{s}.dossier.md"))]
    log(f"batch: {len(todo)} to run, {N} at a time")
    results = {}
    with ThreadPoolExecutor(max_workers=N) as ex:
        for slug, status in ex.map(one, todo):
            results[status] = results.get(status, 0) + 1
    log(f"batch finished: {results}")
