"""catalog.py -- exports the whole corpus as two flat CSVs for browsing in a
spreadsheet or querying with pandas/sqlite, generated fresh from the journey
files every run so it can never go stale like a hand-kept sheet would.

    python3 catalog.py                      # writes ../catalog_subjects.csv
                                             # and ../catalog_stops.csv

catalog_subjects.csv -- one row per journey: slug, traveler, title, years,
  register, n_segments, n_stops, first_date, last_date, path.

catalog_stops.csv -- one row per STOP across every journey: slug, traveler,
  segment, stop name, lat, lng, date, date_confidence. This is the one that
  answers "who passed through place X" (filter/sort by lat/lng) and "who was
  where in year Y" (filter/sort by date) directly in a spreadsheet, since a
  subject's own years/title field is often too coarse for that.

Both are derived purely from load.Corpus, the same loader every other survey
module uses -- no separate parsing path to drift out of sync.
"""
import csv
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
from load import Corpus  # noqa: E402
from temporal import truekey  # noqa: E402


def write_subjects(corpus, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["slug", "traveler", "title", "years", "register",
                    "n_segments", "n_stops", "first_date", "last_date", "path"])
        for slug, j in sorted(corpus.journeys.items()):
            dated = [s.date for s in j.stops if s.date]
            dated_sorted = sorted(dated, key=truekey)
            first_date = dated_sorted[0] if dated_sorted else ""
            last_date = dated_sorted[-1] if dated_sorted else ""
            n_segments = len({s.seg_i for s in j.stops})
            w.writerow([slug, j.traveler, j.title, j.years, j.register,
                        n_segments, len(j.stops), first_date, last_date, j.path])


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
    subj_path = os.path.join(D, "catalog_subjects.csv")
    stop_path = os.path.join(D, "catalog_stops.csv")
    write_subjects(c, subj_path)
    write_stops(c, stop_path)
    print(f"{len(c.journeys)} subjects -> {subj_path}")
    print(f"{len(c.stops)} stops -> {stop_path}")
    if c.errors:
        print(f"{len(c.errors)} unreadable files skipped:")
        for n, e in c.errors:
            print(f"  {n}: {e}")
