"""catalog.py -- exports the whole ATLAS as two flat CSVs for browsing in a
spreadsheet or querying with pandas/sqlite, generated fresh from the journey
files every run so it can never go stale like a hand-kept sheet would.

    python3 catalog.py                      # writes ../catalog_subjects.csv
                                             # and ../catalog_stops.csv

catalog_subjects.csv -- one row per subject, BUILT and QUEUED together
  (status column distinguishes them): slug, traveler, title, years,
  register, n_segments, n_stops, first_date, last_date, path, status,
  dossier_path. Queued rows have blank title/years/etc -- that data does
  not exist until the subject is researched -- and slug is the naive
  guess, not necessarily what research_pipeline.js will actually use. A
  queue row already matched to a built journey (ledger.py's is_built
  logic, reused here) is left out of the queued half entirely, so a
  subject with a stale un-dropped queue row does not appear twice.

  dossier_path points at working/journeys/dossiers/<slug>.dossier.md when
  one exists -- an operator-supplied deep-research file staged ahead of
  the pipeline run (see research-pipeline.md's `dossier` arg). This is
  what makes "which queued subjects are ready to launch the moment tokens
  free up" a one-column filter instead of a memory exercise.

catalog_stops.csv -- one row per STOP across every BUILT journey: slug,
  traveler, segment, stop name, lat, lng, date, date_confidence. This is the
  one that answers "who passed through place X" (filter/sort by lat/lng)
  and "who was where in year Y" (filter/sort by date) directly in a
  spreadsheet, since a subject's own years/title field is often too coarse
  for that. Queued subjects have no stops yet, so they are not in this file.

Both are derived purely from load.Corpus (the same loader every other survey
module uses) plus QUEUE.md -- no separate parsing path to drift out of sync.
"""
import csv
import os
import re
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
from load import Corpus  # noqa: E402
from temporal import truekey  # noqa: E402

STOP = {"de", "of", "the", "and", "al", "el", "la", "von", "van", "der", "di", "ii", "iii"}


def slugify(name):
    s = unicodedata.normalize("NFD", name)
    s = "".join(c for c in s if unicodedata.category(c) != "Mn").lower()
    return re.sub(r"[^a-z0-9]+", "_", s).strip("_")


def queued_only(corpus, queue_path):
    """QUEUE.md rows not already matched to a built journey. Mirrors
    ledger.py's is_built() word-set containment exactly, so this agrees
    with the ledger's QUEUED count."""
    built = set(corpus.journeys.keys())
    built_words = {b: set(b.split("_")) - STOP for b in built}

    def _slug_matches(slug):
        qwords = set(slug.split("_")) - STOP
        if not qwords:
            return slug in built
        for bwords in built_words.values():
            if not bwords:
                continue
            if len(bwords) == 1:
                if bwords == qwords:
                    return True
            elif bwords <= qwords or qwords <= bwords:
                return True
        return False

    out, seen = [], set()
    for line in open(queue_path, encoding="utf-8"):
        m = re.match(r"\|\s*[^|]*\|\s*\*\*(.+?)\*\*[^|]*\|", line)
        if not m:
            continue
        name = m.group(1).strip()
        slug = slugify(name)
        if slug in seen:
            continue
        seen.add(slug)
        alias = re.search(r"\((.+?)\)", name)
        bare = slugify(re.sub(r"\(.*?\)", " ", name)) if alias else slug
        alias_slug = slugify(alias.group(1)) if alias else None
        if alias_slug and alias_slug in built:
            continue
        if _slug_matches(slug) or (bare != slug and _slug_matches(bare)):
            continue
        out.append((slug, name))
    return out


def dossier_for(slug, dossiers_dir):
    p = os.path.join(dossiers_dir, f"{slug}.dossier.md")
    return p if os.path.exists(p) else ""


def write_subjects(corpus, queue_path, dossiers_dir, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["slug", "traveler", "title", "years", "register",
                    "n_segments", "n_stops", "first_date", "last_date", "path",
                    "status", "dossier_path"])
        for slug, j in sorted(corpus.journeys.items()):
            dated = [s.date for s in j.stops if s.date]
            dated_sorted = sorted(dated, key=truekey)
            first_date = dated_sorted[0] if dated_sorted else ""
            last_date = dated_sorted[-1] if dated_sorted else ""
            n_segments = len({s.seg_i for s in j.stops})
            w.writerow([slug, j.traveler, j.title, j.years, j.register,
                        n_segments, len(j.stops), first_date, last_date, j.path,
                        "built", dossier_for(slug, dossiers_dir)])
        for slug, name in queued_only(corpus, queue_path):
            w.writerow([slug, name, "", "", "", "", "", "", "", "",
                        "queued", dossier_for(slug, dossiers_dir)])


def write_stops(corpus, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["slug", "traveler", "segment", "stop_index", "stop_name",
                    "lat", "lng", "date", "date_confidence"])
        for slug, j in sorted(corpus.journeys.items()):
            for s in j.stops:
                w.writerow([slug, j.traveler, s.seg_name, s.i, s.name,
                            s.lat if s.located else "", s.lng if s.located else "",
                            s.date, s.date_conf])


if __name__ == "__main__":
    c = Corpus()
    queue_path = os.path.join(D, "QUEUE.md")
    dossiers_dir = os.path.join(D, "dossiers")
    subj_path = os.path.join(D, "catalog_subjects.csv")
    stop_path = os.path.join(D, "catalog_stops.csv")
    write_subjects(c, queue_path, dossiers_dir, subj_path)
    write_stops(c, stop_path)
    n_queued = len(queued_only(c, queue_path))
    n_dossiers = sum(1 for f in os.listdir(dossiers_dir) if f.endswith(".dossier.md")) if os.path.isdir(dossiers_dir) else 0
    print(f"{len(c.journeys)} built + {n_queued} queued = {len(c.journeys) + n_queued} subjects -> {subj_path}")
    print(f"{n_dossiers} dossiers staged in {dossiers_dir}")
    print(f"{len(c.stops)} stops -> {stop_path}")
    if c.errors:
        print(f"{len(c.errors)} unreadable files skipped:")
        for n, e in c.errors:
            print(f"  {n}: {e}")
