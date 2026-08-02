"""temporal.py — date parsing, contradictions, and the empty centuries.

Mirrors build_atlas_globe.py's own datekey() exactly, so anything this module
calls an ordering problem is one the globe will actually render. Precision is
DERIVED from the source string - "1519" is a year, "1519-04-21" a day - so a
full date asserts a certainty the research may not carry.
"""
import collections
import re


def datekey(iso):
    """Fractional year. Mirrors build_atlas_globe.datekey (BCE via leading '-')."""
    if not iso:
        return 0.0
    neg = iso.startswith("-")
    s = iso[1:] if neg else iso
    p = (s.split("-") + ["1", "1"])[:3]
    try:
        y, m, d = int(p[0]), int(p[1] or 1), int(p[2] or 1)
    except ValueError:
        return 0.0
    k = y + (m - 1) / 12.0 + (d - 1) / 372.0
    return -k if neg else k


def truekey(iso):
    """Correct chronological order, including BCE.

    datekey() negates the whole fractional year, so within a BCE year the months
    run backwards: -1738-06-01 -> -1738.417 sorts BEFORE -1738-01-01 -> -1738.0,
    although June 1738 BC is later than January 1738 BC. truekey keeps the year
    negative but lets the month/day advance forward inside it.
    """
    if not iso:
        return 0.0
    neg = iso.startswith("-")
    s = iso[1:] if neg else iso
    p = (s.split("-") + ["1", "1"])[:3]
    try:
        y, m, d = int(p[0]), int(p[1] or 1), int(p[2] or 1)
    except ValueError:
        return 0.0
    frac = (m - 1) / 12.0 + (d - 1) / 372.0
    return (-y + frac) if neg else (y + frac)


def precision(iso):
    if not iso:
        return "none"
    s = iso[1:] if iso.startswith("-") else iso
    n = len([p for p in s.split("-") if p != ""])
    return {1: "year", 2: "month", 3: "day"}.get(n, "none")


class Temporal:
    def __init__(self, corpus):
        self.corpus = corpus

    def unparseable(self):
        return [s for s in self.corpus.stops
                if s.date and datekey(s.date) == 0.0 and not s.date.startswith("0")]

    def regressions(self):
        """Genuine data errors: stops that go backwards in real chronology.

        Judged with truekey, so BCE files are not falsely accused of the globe's
        own month-inversion. Use bce_order_bug() for that.
        """
        out = []
        for j in self.corpus.journeys.values():
            per_seg = collections.defaultdict(list)
            for s in j.stops:
                if s.date:
                    per_seg[s.seg_i].append(s)
            for ss in per_seg.values():
                for a, b in zip(ss, ss[1:]):
                    if truekey(b.date) < truekey(a.date):
                        out.append((j.slug, a, b))
        return out

    def bce_order_bug(self):
        """Stops the globe will render out of order because datekey() inverts
        months within a BCE year. A defect in build_atlas_globe.datekey, not in
        the data - listed per journey so the blast radius is visible."""
        hit = collections.Counter()
        for j in self.corpus.journeys.values():
            for a, b in zip(j.stops, j.stops[1:]):
                if not (a.date.startswith("-") and b.date.startswith("-")):
                    continue
                if truekey(a.date) < truekey(b.date) and datekey(a.date) > datekey(b.date):
                    hit[j.slug] += 1
        return hit.most_common()

    def contradictions(self, geo, radius_m=1500, min_days=1):
        """Same place, both files dated - but the dates disagree. Needs a Geo."""
        out = []
        for a, b, d in geo.co_located(radius_m):
            if not (a.date and b.date):
                continue
            gap = abs(datekey(a.date) - datekey(b.date))
            if gap * 372.0 >= min_days:
                out.append((a, b, d, gap))
        return sorted(out, key=lambda t: t[2])

    def deserts(self, min_years=50):
        """Spans with no journey active - measured from stop dates, not `years`."""
        pts = sorted({datekey(s.date) for s in self.corpus.stops if s.date})
        gaps = []
        for a, b in zip(pts, pts[1:]):
            if b - a >= min_years:
                gaps.append((a, b, b - a))
        return sorted(gaps, key=lambda t: -t[2])

    def precision_profile(self):
        c = collections.Counter(precision(s.date) for s in self.corpus.stops)
        return c.most_common()


if __name__ == "__main__":
    from load import Corpus
    t = Temporal(Corpus())
    print("=== date precision across the corpus ===")
    for k, n in t.precision_profile():
        print(f"  {k:6} {n}")
    print("\n=== BCE month-inversion: stops the GLOBE renders out of order ===")
    print("    (defect in build_atlas_globe.datekey, not in the journey data)")
    bug = t.bce_order_bug()
    print(f"    {sum(n for _, n in bug)} stop pairs across {len(bug)} journeys")
    for slug, n in bug[:12]:
        print(f"      {slug:24} {n:4}")
    print("\n=== genuine chronological regressions (real data errors) ===")
    reg = t.regressions()
    print(f"    {len(reg)} found")
    for slug, a, b in reg[:15]:
        print(f"  {slug:20} {a.date} -> {b.date}   {a.name[:34]} -> {b.name[:34]}")
    print("\n=== temporal deserts (>=50y with nothing active) ===")
    for a, b, g in t.deserts()[:12]:
        print(f"  {a:9.1f} -> {b:9.1f}   {g:6.1f} empty years")
