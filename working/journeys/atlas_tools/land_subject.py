#!/usr/bin/env python3
"""Deterministic landing of a completed subject. No model, no agent, no judgment.

Born 2026-08-21, the night the operator watched the same three-command
sequence (pull, commit, push twice) get typed out by hand after every single
subject and asked, correctly, why a human was tapping "approve" on a shape a
script could just run. queue_mark.py already proved the model for this:
"I'd rather make it programmatic and not depend on you to remember your
instructions because sometimes you don't." This is the other half of the
launch liturgy in a script: not the claim, the landing.

    python3 land_subject.py <slug> "<Exact QUEUE.md Name>"

Does, in order: pull --ff-only; drop the queue row (reusing queue_mark's own
drop, not a reimplementation); git add QUEUE.md plus whichever of
<slug>.journey.json, <slug>.report.md, es/<slug>.journey.json,
pending_atlas_review.md exist; one commit, "Add <Name> journey (EN + ES),
drop from queue" + the standard co-author trailer; push to every remote. One
rebase-and-retry if the push is rejected, same as claim; if that also fails
this prints what happened and exits nonzero rather than guessing, because
that pattern (two pushes racing) is exactly the case a human should look at
once instead of a script resolving silently.

pending_atlas_review.md is riding along here for the same reason the queue
drop does: it is the gate's self-reference log, written by the same run that
produced the journey being landed, and it was getting left uncommitted after
every landing that touched it -- caught by hand on hesiod, 2026-08-22.
git add on an unchanged tracked file is a no-op, so including it
unconditionally costs nothing on runs that never touch it.

Every git invocation here is a subprocess.run with a list of argv, never a
shell string: no chaining, no command substitution, nothing for a permission
analyzer to flag and nothing for a human on a phone to have to read and
approve mid-batch.

Exit codes: 0 ok; 2 queue row not found or not unique; 5 push failed twice;
6 git trouble.
"""

import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import queue_mark as qm  # noqa: E402


def main():
    if len(sys.argv) != 3:
        qm.say("usage: land_subject.py <slug> \"<Exact QUEUE.md Name>\"")
        return 2
    slug, name = sys.argv[1], sys.argv[2]

    dir_ = HERE.parent
    qfile = dir_ / "QUEUE.md"

    if qm.run(["git", "-C", str(dir_), "pull", "--ff-only"], dir_).returncode != 0:
        return 6

    rc = qm.cmd_drop(qfile, name)
    if rc != 0:
        return rc

    candidates = [
        "QUEUE.md",
        "{}.journey.json".format(slug),
        "{}.report.md".format(slug),
        "es/{}.journey.json".format(slug),
        "pending_atlas_review.md",
    ]
    files = [f for f in candidates if f == "QUEUE.md" or (dir_ / f).exists()]
    missing = [f for f in candidates if f not in files]
    if missing:
        qm.say("warning: expected but not found, landing without them: {}".format(missing))

    if qm.run(["git", "-C", str(dir_), "add"] + files, dir_).returncode != 0:
        return 6

    msg = "Add {} journey (EN + ES), drop from queue".format(name)
    if qm.run(["git", "-C", str(dir_), "commit", "-m", msg,
               "-m", "Co-Authored-By: El Gólem <golem@localhost>"], dir_).returncode != 0:
        return 6

    if qm.push_all(dir_):
        qm.say("landed, committed, and pushed.")
        return 0

    qm.say("push rejected; rebasing once and retrying")
    p = qm.run(["git", "-C", str(dir_), "pull", "--rebase"], dir_, ok_codes=(0, 1))
    if p.returncode != 0:
        qm.say("rebase conflict landing {}: resolve by hand, do not force-push".format(slug))
        return 5

    if qm.push_all(dir_):
        qm.say("landed, committed, and pushed (after one rebase).")
        return 0

    qm.say("push rejected twice landing {}: look by hand, do not force-push".format(slug))
    return 5


if __name__ == "__main__":
    sys.exit(main())
