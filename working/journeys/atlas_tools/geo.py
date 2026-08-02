"""geo.py — co-location, and the byte-identical sibling pin rule.

The atlas convention: when two journeys record the same event, the pin must be
identical byte for byte. 50.978 and 50.9780 are the same coordinate and a
different pin, so comparison is on the source repr, not the float.

Two failure modes this finds:
  DRIFT   - near-identical pins that should be one pin (same event, two files)
  SPREAD  - one place written several ways across the corpus (Grafton Way had 4)
"""
import collections
import math

EARTH_KM = 6371.0088


def haversine(a_lat, a_lng, b_lat, b_lng):
    """Great-circle distance in metres."""
    p1, p2 = math.radians(a_lat), math.radians(b_lat)
    dp = p2 - p1
    dl = math.radians(b_lng - a_lng)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_KM * math.asin(min(1.0, math.sqrt(h))) * 1000.0


def _cell(stop, deg=0.05):
    return (round(stop.lat / deg), round(stop.lng / deg))


class Geo:
    def __init__(self, corpus):
        self.corpus = corpus
        self.stops = corpus.located

    def co_located(self, radius_m=2000, cross_journey_only=True):
        """Stop pairs within `radius_m`. Buckets by coarse cell first so this is
        near-linear rather than 6000^2."""
        buckets = collections.defaultdict(list)
        for s in self.stops:
            buckets[_cell(s)].append(s)
        seen, out = set(), []
        for (cx, cy), group in buckets.items():
            near = []
            for dx in (-1, 0, 1):
                for dy in (-1, 0, 1):
                    near += buckets.get((cx + dx, cy + dy), [])
            for a in group:
                for b in near:
                    if a is b or (cross_journey_only and a.slug == b.slug):
                        continue
                    key = tuple(sorted((id(a), id(b))))
                    if key in seen:
                        continue
                    seen.add(key)
                    d = haversine(a.lat, a.lng, b.lat, b.lng)
                    if d <= radius_m:
                        out.append((a, b, d))
        return sorted(out, key=lambda t: t[2])

    def pin_drift(self, radius_m=1500, same_date_only=False):
        """Same event, two files, pins NOT byte-identical - the convention broken."""
        out = []
        for a, b, d in self.co_located(radius_m):
            if a.pin == b.pin:
                continue                                   # already conformant
            if same_date_only and a.date != b.date:
                continue
            out.append((a, b, d))
        return out

    def pin_spread(self, radius_m=300, min_variants=2):
        """One physical place written with several different pins across the
        corpus. Returns clusters worth collapsing to a canonical pin."""
        buckets = collections.defaultdict(list)
        for s in self.stops:
            buckets[_cell(s, 0.01)].append(s)
        clusters = []
        for group in buckets.values():
            if len(group) < 2:
                continue
            variants = collections.defaultdict(list)
            for s in group:
                variants[s.pin].append(s)
            if len(variants) < min_variants:
                continue
            pins = list(variants)
            spread = max(
                haversine(variants[p][0].lat, variants[p][0].lng,
                          variants[q][0].lat, variants[q][0].lng)
                for p in pins for q in pins)
            if spread <= radius_m:
                clusters.append((len(variants), spread, variants))
        return sorted(clusters, key=lambda t: -t[0])

    def canonical_pins(self, min_journeys=3):
        """Pins already shared byte-exact by several journeys. New journeys must
        inherit these rather than re-derive them."""
        by_pin = collections.defaultdict(set)
        for s in self.stops:
            by_pin[s.pin].add(s.slug)
        return sorted(((p, sorted(v)) for p, v in by_pin.items() if len(v) >= min_journeys),
                      key=lambda t: -len(t[1]))

    def deserts(self, deg=10):
        """Coarse cells held by a single journey - the geographic gaps."""
        cells = collections.defaultdict(set)
        for s in self.stops:
            cells[(math.floor(s.lat / deg) * deg, math.floor(s.lng / deg) * deg)].add(s.slug)
        return sorted(((c, sorted(v)) for c, v in cells.items() if len(v) == 1))


if __name__ == "__main__":
    from load import Corpus
    g = Geo(Corpus())
    print("=== canonical pins (3+ journeys, byte-exact) ===")
    for pin, slugs in g.canonical_pins()[:10]:
        print(f"  ({pin[0]}, {pin[1]}) {len(slugs):3} journeys  {', '.join(slugs[:6])}")
    print("\n=== pin drift: same event, non-identical pins ===")
    for a, b, d in g.pin_drift(same_date_only=True)[:15]:
        print(f"  {d:7.0f}m  {a.slug}({a.lat_s},{a.lng_s}) vs {b.slug}({b.lat_s},{b.lng_s})  [{a.date}]")
        print(f"           {a.name[:60]} | {b.name[:60]}")
