"""ledger.py — the one authoritative count of the atlas.

Every number about "how many characters" comes from here. Do not re-derive the
arithmetic in conversation: run this and read it out. It counts files on disk,
so it is only ever as current as the checkout it runs in - it prints a warning
if the working copy is behind its remotes.

    python3 ledger.py
    python3 ledger.py --next 5           # next 5 unresearched, QUEUE.md top-to-bottom
    python3 ledger.py --next 5 --bottom   # next 5 unresearched, QUEUE.md bottom-to-top

Four tiers, deliberately distinguished:
  LIVE       what the published globe actually shows (the canon)
  RESEARCHED journey files written and committed, not yet promoted to the globe
  QUEUED     names in QUEUE.md with no journey file yet
  TOTAL      RESEARCHED + QUEUED, if the whole queue is eventually built

--next uses the SAME is_built() fuzzy matching as the counts above (word-set
containment against every existing journey slug, not naive exact-slug
comparison). Added 2026-08-18 after four same-day collisions where an ad hoc
throwaway slugify-and-compare script missed subjects already researched
under a shorter slug than their QUEUE.md row naively slugifies to (e.g. an
existing "moses_de_leon.journey.json" vs the naive slug of the row "Rabbi
Moses de León"). This tool's own is_built() already handled that case
correctly - the fix is to always pick subjects from HERE, never from a
one-off script, not to add a paid agent check.
"""
import argparse, glob, json, os, re, subprocess, sys, unicodedata, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.abspath(os.path.join(HERE, ".."))
REPO = os.path.abspath(os.path.join(D, "..", ".."))
LIVE_URL = "https://colegioinvisible.com/atlas/atlas_globe.html"


def slugify(name):
    s = unicodedata.normalize("NFD", name)
    s = "".join(c for c in s if unicodedata.category(c) != "Mn").lower()
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
    # trailing annotations after the bold name (queue_mark.py's " _(researching
    # ...)_ " claim marker, or a manually added " (personal associate)" tag)
    # must not require an immediate pipe - found 2026-08-19 after both caused
    # affected rows to silently vanish from every count below, undercounting
    # QUEUED and TOTAL and hiding real subjects from --next.
    m = re.match(r"\|\s*[^|]*\|\s*\*\*(.+?)\*\*[^|]*\|", line)
    if m:
        name = m.group(1).strip()
        slug = slugify(name)
        if slug not in seen:
            seen.add(slug)
            alias = re.search(r"\((.+?)\)", name)
            # two parenthetical patterns show up in QUEUE.md and need different
            # handling: "Adriano (Hadrian)" - the paren is a translation/gloss
            # of the SAME name, so the bare name (paren stripped) is what the
            # journey file is slugged as - vs. "Jean-Baptiste Alliette
            # (Etteilla)" - the paren IS the person's actual handle, so the
            # alias itself is what the journey file is slugged as. Carry both
            # candidates plus the alias so is_built can try all three.
            bare = slugify(re.sub(r"\(.*?\)", " ", name)) if alias else slug
            rows.append((name, slug, bare, slugify(alias.group(1)) if alias else None))


STOP = {"de", "of", "the", "and", "al", "el", "la", "von", "van", "der", "di", "ii", "iii"}
built_words = {b: set(b.split("_")) - STOP for b in built}


def _slug_matches(slug):
    qwords = set(slug.split("_")) - STOP
    if not qwords:
        return slug in built
    for bwords in built_words.values():
        if not bwords:
            continue
        if len(bwords) == 1:
            # a single bare-surname journey slug only counts as a match if
            # it's ALL the queued name reduces to. Containment alone is
            # unsafe here - e.g. built "jung" must NOT match queued "Carl
            # Jung of Mainz" or "Carl Gustav Jung (the elder)", both
            # explicitly different people from jung.journey.json who just
            # share the surname.
            if bwords == qwords:
                return True
        # a multi-word journey slug is specific enough that containment in
        # either direction (abbreviated to surname(s), or the reverse) is a
        # safe signal of the same person
        elif bwords <= qwords or qwords <= bwords:
            return True
    return False


def is_built(slug, bare_slug=None, alias_slug=None):
    if alias_slug and alias_slug in built:
        # a parenthetical alias like "(Etteilla)" or "(Txillardegi)" names
        # the person's common handle directly - an exact hit is unambiguous
        return True
    return _slug_matches(slug) or (bare_slug and bare_slug != slug and _slug_matches(bare_slug))


todo = [r for r in rows if not is_built(r[1], r[2], r[3])]

ap = argparse.ArgumentParser(add_help=False)
ap.add_argument("--next", type=int, default=None)
ap.add_argument("--bottom", action="store_true")
ap.add_argument("--check")
args, _ = ap.parse_known_args()

if args.check:
    s = slugify(args.check)
    alias = re.search(r"\((.+?)\)", args.check)
    bare = slugify(re.sub(r"\(.*?\)", " ", args.check)) if alias else s
    a = slugify(alias.group(1)) if alias else None
    hit = is_built(s, bare, a)
    print(f"{'ALREADY BUILT' if hit else 'not built'}: {args.check}")
    sys.exit(0)

if args.next is not None:
    picks = list(reversed(todo)) if args.bottom else todo
    for name, *_ in picks[:args.next]:
        print(name)
    sys.exit(0)

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
