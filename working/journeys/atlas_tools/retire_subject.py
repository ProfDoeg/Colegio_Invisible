#!/usr/bin/env python3
"""retire_subject.py -- archive one or more subjects to removed/ AND retire their
tags, so the connections graph does not keep edges to a node that is gone.

    python3 atlas_tools/retire_subject.py <slug> [<slug> ...]

Per Anthony (2026-09-08): "When we archive we should retire tags too otherwise
the graph will break." Removal never deletes anything; it moves. For each slug:

  1. git mv <slug>.journey.json, <slug>.report.md -> removed/
             es/<slug>.journey.json                -> removed/es/
             dossiers/<slug>.dossier.md            -> removed/dossiers/
     (each skipped silently if already there)
  2. In every remaining dossier's "### Connection Tags" block, drop the lines
     that name the retired subject: mirror lines "(mirrored from
     <slug>.dossier.md)" and own lines "- **<Name>** [Tn]" where <Name> is any
     counterpart_name the graph has used for that slug. Prose sections are left
     alone: they are research, not graph.
  3. Drop every row of connections.csv whose subject_slug or counterpart_slug
     is the retired slug.
  4. Drop the slug's own records from ~/codex_lab/tags_per_subject.json and
     every record in other subjects whose counterpart_slug is the slug, so the
     next build_connections_csv.py does not resurrect the edges. A dated
     backup of the json is written beside it first.
  5. Regenerate catalog_subjects.csv / catalog_stops.csv (catalog.py) and the
     roster addendum (make_addendum.py).
  6. git add the exact paths touched. It does NOT commit: the main loop does,
     with the usual message "Archive X to removed/ per author instruction".

Restoring a subject is the reverse move plus a tag re-extraction; this script
does not do that.
"""
import csv, datetime, glob, json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.abspath(os.path.join(HERE, ".."))
REPO = os.path.abspath(os.path.join(D, "..", ".."))
TAGS = os.path.expanduser("~/codex_lab/tags_per_subject.json")


def git(*a):
    return subprocess.run(["git", "-C", REPO, *a], check=True, capture_output=True, text=True).stdout


def rel(p):
    return os.path.relpath(p, REPO)


def move(src, dst_dir, touched):
    if not os.path.exists(src):
        return
    os.makedirs(dst_dir, exist_ok=True)
    git("mv", rel(src), rel(dst_dir) + "/")
    touched.append(rel(src)); touched.append(rel(os.path.join(dst_dir, os.path.basename(src))))
    print(f"  moved {rel(src)} -> {rel(dst_dir)}/")


def main(slugs):
    touched = []
    # names the graph has used for each retired slug (for own-line matching)
    names = {s: set() for s in slugs}
    conn_path = os.path.join(D, "connections.csv")
    rows = list(csv.DictReader(open(conn_path, newline="", encoding="utf-8")))
    for r in rows:
        if r["counterpart_slug"] in names:
            names[r["counterpart_slug"]].add(r["counterpart_name"].strip())
    cat = {r["slug"]: r for r in csv.DictReader(open(os.path.join(D, "catalog_subjects.csv"), encoding="utf-8"))}
    for s in slugs:
        if s in cat:
            names[s].add(cat[s]["traveler"].split("(")[0].strip())

    for s in slugs:
        print(f"== {s}")
        move(os.path.join(D, f"{s}.journey.json"), os.path.join(D, "removed"), touched)
        move(os.path.join(D, f"{s}.report.md"), os.path.join(D, "removed"), touched)
        move(os.path.join(D, "es", f"{s}.journey.json"), os.path.join(D, "removed", "es"), touched)
        move(os.path.join(D, "dossiers", f"{s}.dossier.md"), os.path.join(D, "removed", "dossiers"), touched)

    # 2. tag lines in other dossiers
    mirror_re = re.compile(r"\(mirrored from (" + "|".join(re.escape(s) for s in slugs) + r")\.dossier\.md\)")
    all_names = {n for s in slugs for n in names[s] if n}
    own_re = re.compile(r"^- \*\*(" + "|".join(re.escape(n) for n in sorted(all_names, key=len, reverse=True)) + r")\*\* \[T\d[+-]?\]") if all_names else None
    dropped_lines = 0
    for p in sorted(glob.glob(os.path.join(D, "dossiers", "*.dossier.md"))):
        txt = open(p, encoding="utf-8").read()
        if "### Connection Tags" not in txt:
            continue
        head, _, tail = txt.partition("### Connection Tags")
        out, changed = [], False
        for line in tail.split("\n"):
            if mirror_re.search(line) or (own_re and own_re.match(line)):
                changed = True; dropped_lines += 1
                print(f"  tag dropped in {os.path.basename(p)}: {line.strip()[:90]}")
                continue
            out.append(line)
        if changed:
            open(p, "w", encoding="utf-8").write(head + "### Connection Tags" + "\n".join(out))
            touched.append(rel(p))
    print(f"  {dropped_lines} tag line(s) dropped from other dossiers")

    # 3. connections.csv
    keep = [r for r in rows if r["subject_slug"] not in names and r["counterpart_slug"] not in names]
    if len(keep) != len(rows):
        with open(conn_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(keep)
        touched.append(rel(conn_path))
    print(f"  connections.csv: {len(rows)} -> {len(keep)} rows")

    # 4. tags_per_subject.json
    if os.path.exists(TAGS):
        tags = json.load(open(TAGS, encoding="utf-8"))
        before = sum(len(v) for v in tags.values())
        bak = TAGS + "." + datetime.date.today().isoformat() + ".bak"
        if not os.path.exists(bak):
            open(bak, "w", encoding="utf-8").write(open(TAGS, encoding="utf-8").read())
        for s in slugs:
            tags.pop(s, None)
        for k in list(tags):
            tags[k] = [r for r in tags[k] if r.get("counterpart_slug") not in names]
        after = sum(len(v) for v in tags.values())
        with open(TAGS, "w", encoding="utf-8") as f:
            json.dump(tags, f, ensure_ascii=False, indent=1)
        print(f"  tags_per_subject.json: {before} -> {after} records (backup {os.path.basename(bak)})")
    else:
        print(f"  WARNING: {TAGS} not found; tags json untouched")

    # 5. catalog + addendum
    subprocess.run([sys.executable, os.path.join(HERE, "catalog.py")], check=True)
    subprocess.run([sys.executable, os.path.join(HERE, "make_addendum.py")], check=True)
    for p in ("catalog_subjects.csv", "catalog_stops.csv", os.path.join("dossiers", "ATLAS_CONNECTIONS_ADDENDUM.md")):
        touched.append(rel(os.path.join(D, p)))

    # 6. stage exact paths
    existing = [p for p in dict.fromkeys(touched) if os.path.exists(os.path.join(REPO, p))]
    if existing:
        git("add", "--", *existing)
    print("staged:", len(existing), "paths. Now commit with the archive message; nothing committed yet.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
