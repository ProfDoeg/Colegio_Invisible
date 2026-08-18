#!/usr/bin/env python3
"""Deterministic QUEUE.md bookkeeping. No model, no agent, no judgment.

Born 2026-08-18, the night four subjects were researched twice because queue
bookkeeping lived in an agent's memory of its instructions. The operator's
directive, verbatim: "I'd rather make it programmatic and not depend on you to
remember your instructions because sometimes you don't." This script is that.
It is also the disproof of the claim that queue marking was impossible without
an agent call: the workflow script's sandbox cannot touch files, but nothing
says the bookkeeping has to live inside the workflow script.

    python3 queue_mark.py claim "Gustav Gräser"    # mark, commit, push (the lock)
    python3 queue_mark.py drop  "Gustav Gräser"    # remove row; NOT committed
    python3 queue_mark.py status "Gustav Gräser"   # print the row, if any

The launch liturgy (see docs/guides/research-pipeline.md):
    ledger.py --check   -> already built under any slug?     (free)
    queue_mark.py claim -> marked+committed+pushed, or refuse (free)
    Workflow            -> the research                       (the only paid part)
    commit artifacts + queue_mark.py drop in the SAME commit  (free)

claim is the cross-instance lock. nodus1 and nodus2 work from separate
checkouts whose only shared surface is the remote, so a marker that stays
local locks nothing: claim pulls first, edits, commits exactly one file, and
pushes. The remote rejecting the second push is what makes two simultaneous
claims on one row impossible. drop deliberately does NOT commit: the removal
rides in the same commit as the journey and report that justify it.

The row is matched by the literal text between the asterisks of its bolded
cell, exactly: '**Gustav Gräser**'. Not the slug, not the traveler name, no
accent folding, no substring. The Gräser run was launched as slug
gusto_graeser, name "Gusto Graeser", against a row reading "Gustav Gräser"
with "Karl Gräser" on the next line; anything looser than exact-or-abort
eventually deletes the wrong brother.

Exit codes: 0 ok; 2 row not found or not unique; 3 already claimed;
4 lost the race to the other instance; 5 push failed twice; 6 git trouble.
"""

import argparse
import datetime
import os
import pathlib
import re
import socket
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
MARKER_RE = re.compile(r" _\(researching \d{4}-\d{2}-\d{2}[^)]*\)_")


def default_owner():
    """Who is claiming. The marker must differ BETWEEN instances: two claims
    that render identical text produce identical commits, and git rebase drops
    the second as an already-applied patch instead of conflicting, leaving both
    instances convinced they hold the row. Caught by the test suite on day one.
    QM_OWNER overrides. The fallback includes the checkout's grandparent
    directory, not hostname alone: nodus1 and nodus2 run on the SAME host, so
    bare hostname would give them identical tags and silently disarm the very
    race protection built for them (~/taller vs ~/instance2_work is what
    actually tells them apart)."""
    tag = os.environ.get("QM_OWNER")
    if tag:
        return tag
    host = socket.gethostname().split(".")[0]
    checkout = pathlib.Path(__file__).resolve().parents[3].parent.name
    return "{}:{}".format(host, checkout) if checkout else host


def say(msg):
    print(msg, file=sys.stderr)


def run(args, cwd, ok_codes=(0,)):
    p = subprocess.run(args, cwd=str(cwd), capture_output=True, text=True)
    if p.returncode not in ok_codes:
        say("FAILED: {}\n{}".format(" ".join(args), (p.stderr or p.stdout).strip()))
    return p


def find_row(lines, name):
    """The row whose bolded cell is exactly **name**. Exact count or nothing."""
    token = "**{}**".format(name)
    hits = [i for i, l in enumerate(lines) if token in l]
    return token, hits


def load(qfile):
    text = qfile.read_text(encoding="utf-8")
    return text, text.split("\n")


def cmd_status(qfile, name):
    _, lines = load(qfile)
    _, hits = find_row(lines, name)
    if not hits:
        print("not in queue: {}".format(name))
        return 0
    for i in hits:
        print(lines[i])
    return 0 if len(hits) == 1 else 2


def cmd_drop(qfile, name):
    text, lines = load(qfile)
    token, hits = find_row(lines, name)
    if len(hits) != 1:
        say("refusing: '{}' matches {} rows (need exactly 1)".format(token, len(hits)))
        return 2
    gone = lines.pop(hits[0])
    qfile.write_text("\n".join(lines), encoding="utf-8")
    say("dropped (uncommitted, commit it WITH the subject's artifacts):")
    say("  " + gone)
    return 0


def push_all(cwd):
    """Push to every remote. The repo lives on two (the nodus bare repo the
    instances share, and GitHub); a claim that reaches only one is invisible
    to half the claimants, which was caught live on the Lombardi claim. The
    upstream remote is the lock: if it rejects, return False so the race
    handling runs. Other remotes get the claim best-effort; a warning, not an
    undo, because the lock itself already won."""
    up = run(["git", "-C", str(cwd), "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
             cwd, ok_codes=(0, 1))
    lock_remote = up.stdout.split("/")[0].strip() if up.returncode == 0 else "origin"
    if run(["git", "-C", str(cwd), "push", lock_remote], cwd, ok_codes=(0, 1)).returncode != 0:
        return False
    others = [r for r in run(["git", "-C", str(cwd), "remote"], cwd).stdout.split()
              if r and r != lock_remote]
    for r in others:
        if run(["git", "-C", str(cwd), "push", r, "HEAD"], cwd, ok_codes=(0, 1)).returncode != 0:
            say("warning: claim did not reach remote '{}'; push it by hand so the other side sees the lock".format(r))
    return True


def cmd_claim(qfile, name, no_git=False):
    cwd = qfile.parent

    # The lock only means anything against a current queue. A checkout that
    # skipped the pull can "claim" a row another instance already dropped.
    if not no_git and not os.environ.get("QM_SKIP_PULL"):
        if run(["git", "-C", str(cwd), "pull", "--ff-only"], cwd).returncode != 0:
            return 6

    text, lines = load(qfile)
    token, hits = find_row(lines, name)
    if len(hits) != 1:
        say("refusing: '{}' matches {} rows (need exactly 1)".format(token, len(hits)))
        return 2
    i = hits[0]
    if MARKER_RE.search(lines[i]):
        say("already claimed, not touching it (a stale date means a dead run; clearing it is a human call):")
        say("  " + lines[i])
        return 3

    marker = " _(researching {} {})_".format(datetime.date.today().isoformat(), default_owner())
    lines[i] = lines[i].replace(token, token + marker, 1)
    qfile.write_text("\n".join(lines), encoding="utf-8")
    say("marked: " + lines[i])
    if no_git:
        return 0

    # Exactly one file. Never -A, never a second path: this working tree
    # routinely carries other people's uncommitted work.
    rel = qfile.name
    if run(["git", "-C", str(cwd), "add", rel], cwd).returncode != 0:
        return 6
    msg = "Claim {} in journey queue".format(name)
    if run(["git", "-C", str(cwd), "commit", "-m", msg,
            "-m", "Co-Authored-By: El Gólem <golem@localhost>"], cwd).returncode != 0:
        return 6

    def undo():
        # Un-commit, then restore the file from the NEW head (not from upstream:
        # restoring a fetched-ahead version against an older head leaves the tree
        # dirty, which the test suite caught). The next pull fast-forwards.
        run(["git", "-C", str(cwd), "reset", "HEAD~1"], cwd)
        run(["git", "-C", str(cwd), "checkout", "HEAD", "--", rel], cwd)

    if push_all(cwd):
        say("claimed, committed, and pushed.")
        return 0

    # Rejected: the other instance pushed first. Rebase and see what they did.
    say("push rejected; rebasing to see whether the other instance took this row")
    p = run(["git", "-C", str(cwd), "pull", "--rebase"], cwd, ok_codes=(0, 1))
    if p.returncode != 0:
        # Conflict means both edits touched the same line: the same row.
        run(["git", "-C", str(cwd), "rebase", "--abort"], cwd)
        undo()
        say("row claimed by the other instance; undone cleanly. Pick another subject.")
        return 4

    _, lines = load(qfile)
    _, hits = find_row(lines, name)
    row = lines[hits[0]] if len(hits) == 1 else ""
    if marker not in row:
        undo()
        say("row changed under us during rebase; undone cleanly. Pick another subject.")
        return 4

    if push_all(cwd):
        say("claimed, committed, and pushed (after one rebase).")
        return 0
    undo()
    say("push rejected twice; undone cleanly. Something is wrong with the remote; look by hand.")
    return 5


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["claim", "drop", "status"])
    ap.add_argument("name", help="the EXACT text between the asterisks of the row's bolded cell")
    ap.add_argument("--queue", default=str(HERE.parent / "QUEUE.md"),
                    help="path to QUEUE.md (default: the atlas queue beside this script)")
    ap.add_argument("--no-git", action="store_true",
                    help="claim edits the file only: no pull, no commit, no push. For tests")
    args = ap.parse_args()

    qfile = pathlib.Path(args.queue).resolve()
    if not qfile.exists():
        say("no such file: {}".format(qfile))
        return 6
    if args.command == "claim":
        return cmd_claim(qfile, args.name, args.no_git)
    if args.command == "drop":
        return cmd_drop(qfile, args.name)
    return cmd_status(qfile, args.name)


if __name__ == "__main__":
    sys.exit(main())
