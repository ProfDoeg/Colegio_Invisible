"""stage_dossiers.py -- safely move finished dossiers from out/ into the repo.

Written 2026-09-02 after 51 corrupted "dossiers" (an unhandled OpenAI
"Selected model is at capacity" error, echoed straight back as a stub, see
codex_dossier_runner.py's quota_wall()) got committed to the shared repo by a
manual `cp *.dossier.md` pass that trusted file presence in out/ as proof of
real content. It was not. This script replaces every future manual staging
pass -- never cp out/*.dossier.md directly again.

    python3 ~/codex_lab/stage_dossiers.py            # copy good ones into
                                                      # the repo's dossiers/,
                                                      # print what was
                                                      # skipped and why
    python3 ~/codex_lab/stage_dossiers.py --dry-run  # report only, copy nothing

Does NOT commit or push -- copying only. The orchestrator still runs the
usual git liturgy (add/commit/push origin+github) by hand afterward, same as
every other artifact in this repo. This script's only job is to keep garbage
out of that git add in the first place.
"""
import os, re, sys

OUT = "/home/drdoeg/codex_lab/out"
REPO_DOSSIERS = "/home/drdoeg/instance2_work/Colegio_Invisible/working/journeys/dossiers"

BAD_SIGNATURES = [
    "Selected model is at capacity",
    "ERROR: ",
    "usage limit",
    "rate limit",
    "too many requests",
]


def sanity_check(text):
    """Returns a list of problems; empty list means the file looks like a
    real dossier. Deliberately cheap and conservative -- false positives
    (holding back a real dossier for a human look) cost nothing; false
    negatives (staging garbage) are what this script exists to prevent."""
    problems = []
    lines = text.count("\n")
    if lines < 200:
        problems.append(f"too short ({lines} lines, real dossiers run 900+)")
    for sig in BAD_SIGNATURES:
        if sig in text:
            problems.append(f'contains error signature: "{sig}"')
    if "http" not in text[-4000:]:
        problems.append("no source URLs in the closing section")
    if not re.search(r"^# .+: Research Dossier", text, re.M):
        problems.append("missing the '# NAME: Research Dossier' title line")
    return problems


def main():
    dry_run = "--dry-run" in sys.argv
    if not os.path.isdir(OUT):
        print(f"no such directory: {OUT}")
        return
    files = sorted(f for f in os.listdir(OUT) if f.endswith(".dossier.md"))
    if not files:
        print("out/ is empty, nothing to stage")
        return

    staged, skipped = [], []
    for fname in files:
        path = os.path.join(OUT, fname)
        text = open(path, encoding="utf-8", errors="replace").read()
        dest = os.path.join(REPO_DOSSIERS, fname)
        if os.path.exists(dest):
            # 2026-09-03: this exact gap silently overwrote a real, already-
            # committed dossier (abu_karib) with a second independently
            # re-researched one, because out/ had a stale second attempt no
            # one had told to skip. Never trust "it's in out/" as proof the
            # repo doesn't already have it - always check the destination.
            problems = [f"already exists in the repo, NOT overwriting"]
            skipped.append((fname, problems))
            continue
        problems = sanity_check(text)
        if problems:
            skipped.append((fname, problems))
            continue
        if not dry_run:
            open(dest, "w", encoding="utf-8").write(text)
        staged.append(fname)

    print(f"{'would stage' if dry_run else 'staged'}: {len(staged)}")
    for f in staged:
        print(f"  {f}")
    print(f"\nskipped (left in out/ for a human look): {len(skipped)}")
    for f, problems in skipped:
        print(f"  {f}: {'; '.join(problems)}")

    if staged and not dry_run:
        print(
            f"\nNow run the usual git liturgy on {REPO_DOSSIERS} for the "
            f"{len(staged)} staged files (add/commit/push origin+github), "
            f"then delete the staged ones from {OUT}."
        )


if __name__ == "__main__":
    main()
