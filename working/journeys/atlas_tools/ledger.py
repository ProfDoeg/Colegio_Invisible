"""ledger.py — the one authoritative count of the atlas.

Every number about "how many characters" comes from here. Do not re-derive the
arithmetic in conversation: run this and read it out. It counts files on disk,
so it is only ever as current as the checkout it runs in - it prints a warning
if the working copy is behind its remotes.

    python3 ledger.py

Four tiers, deliberately distinguished:
  LIVE       what the published globe actually shows (the canon)
  RESEARCHED journey files written and committed, not yet promoted to the globe
  QUEUED     names in QUEUE.md with no journey file yet
  TOTAL      RESEARCHED + QUEUED, if the whole queue is eventually built
"""
import glob, json, os, re, subprocess, unicodedata, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.abspath(os.path.join(HERE, ".."))
REPO = os.path.abspath(os.path.join(D, "..", ".."))
LIVE_URL = "https://colegioinvisible.com/atlas/atlas_globe.html"


def slugify(name):
    s = unicodedata.normalize("NFD", name)
    s = "".join(c for c in s if unicodedata.category(c) != "Mn").lower()
    s = re.sub(r"\(.*?\)", " ", s)
    return re.sub(r"[^a-z0-9]+", "_", s).strip("_")


def git(*a):
    try:
        return subprocess.run(["git", "-C", REPO, *a], capture_output=True,
                              text=True, timeout=30).stdout.strip()
    except Exception:
        return ""


def live_count():
    try:
        with urllib.request.urlopen(LIVE_URL, timeout=30) as r:
            h = r.read().decode("utf-8", "ignore")
        i = h.find("const ATLAS")
        j = h.index("[", i)
        return len(json.JSONDecoder().raw_decode(h[j:])[0])
    except Exception as e:
        return f"unreachable ({type(e).__name__})"


built = {os.path.basename(p).replace(".journey.json", "")
         for p in glob.glob(D + "/*.journey.json")}
es = {os.path.basename(p).replace(".journey.json", "")
      for p in glob.glob(D + "/es/*.journey.json")}

rows, seen = [], set()
for line in open(D + "/QUEUE.md", encoding="utf-8"):
    m = re.match(r"\|\s*[^|]*\|\s*\*\*(.+?)\*\*\s*\|", line)
    if m:
        slug = slugify(m.group(1).strip())
        if slug not in seen:
            seen.add(slug)
            rows.append((m.group(1).strip(), slug))


def is_built(slug):
    return bool({slug, slug.split("_")[-1], "_".join(slug.split("_")[:2])} & built)


todo = [r for r in rows if not is_built(r[1])]

print("ATLAS LEDGER")
print("=" * 46)
print(f"  LIVE (published globe)      {live_count()}")
print(f"  RESEARCHED (files on disk)  {len(built)}   [es: {len(es)}]")
print(f"  QUEUED (no file yet)        {len(todo)}")
print(f"  {'-'*42}")
print(f"  TOTAL if queue completed    {len(built) + len(todo)}")
print()
print(f"  QUEUE.md distinct names     {len(rows)}")
print(f"  missing Spanish editions    {len(built - es)}")

head = git("rev-parse", "--short", "HEAD")
dirty = len([l for l in git("status", "--short", "--", "working/journeys").splitlines() if l])
print(f"\n  commit {head}   uncommitted journey files: {dirty}")

git("fetch", "-q", "--all")
for remote in ("origin", "github"):
    ref = git("rev-parse", "--short", f"{remote}/main")
    if ref:
        behind = git("rev-list", "--count", f"HEAD..{remote}/main")
        ahead = git("rev-list", "--count", f"{remote}/main..HEAD")
        state = "in sync" if behind == "0" == ahead else f"ahead {ahead}, behind {behind}"
        print(f"  {remote:8} {ref}   {state}")

if dirty:
    print("\n  WARNING: uncommitted journey files - commit before quoting these numbers")
