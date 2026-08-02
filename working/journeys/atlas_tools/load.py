"""load.py — the corpus loader every other survey module builds on.

Reads every <slug>.journey.json in the journeys directory into flat, indexable
records. Deliberately tolerant: a malformed file is reported, never fatal, so a
survey over 153 files is not stopped by one of them.

Stop coordinates are kept as the ORIGINAL repr strings alongside the floats,
because the atlas convention is byte-identical sibling pins: 50.978 and 50.9780
are the same number and a different pin.
"""
import glob
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
JOURNEYS = os.path.abspath(os.path.join(HERE, ".."))


class Stop:
    __slots__ = ("slug", "traveler", "seg_i", "seg_name", "i", "name", "lat", "lng",
                 "lat_s", "lng_s", "date", "date_conf", "campa", "quote",
                 "quote_source", "sources", "suggested_refs")

    def __init__(self, slug, traveler, seg_i, seg_name, i, raw):
        self.slug, self.traveler = slug, traveler
        self.seg_i, self.seg_name, self.i = seg_i, seg_name, i
        self.name = raw.get("name", "") or ""
        self.lat, self.lng = raw.get("lat"), raw.get("lng")
        # preserve exact source formatting for the byte-identical pin rule
        self.lat_s = repr(raw.get("lat"))
        self.lng_s = repr(raw.get("lng"))
        self.date = raw.get("date", "") or ""
        self.date_conf = raw.get("date_confidence", "") or ""
        self.campa = raw.get("campa", "") or ""
        self.quote = raw.get("quote") or ""
        self.quote_source = raw.get("quote_source") or ""
        self.sources = raw.get("sources") or []
        self.suggested_refs = raw.get("suggested_refs") or []

    @property
    def located(self):
        return isinstance(self.lat, (int, float)) and isinstance(self.lng, (int, float))

    @property
    def pin(self):
        """The pin as the convention sees it: exact source text, not rounded."""
        return (self.lat_s, self.lng_s)

    def __repr__(self):
        return f"<{self.slug}:{self.i} {self.name[:34]!r} {self.date}>"


class Journey:
    def __init__(self, path):
        self.path = path
        self.slug = os.path.basename(path).replace(".journey.json", "")
        j = json.load(open(path, encoding="utf-8"))
        self.raw = j
        self.traveler = j.get("traveler", self.slug)
        self.title = j.get("title", "")
        self.years = j.get("years", "")
        self.register = j.get("register", "")
        self.calendar = j.get("calendar", "")
        self.stops = []
        n = 0
        for si, seg in enumerate(j.get("segments", []) or []):
            sname = seg.get("name", f"Segment {si+1}")
            for raw in seg.get("stops", []) or []:
                self.stops.append(Stop(self.slug, self.traveler, si, sname, n, raw))
                n += 1

    @property
    def text(self):
        """All authored text — campa only. Quotes are verbatim source and are
        explicitly NOT held to house style."""
        return "\n".join(s.campa for s in self.stops)

    def __repr__(self):
        return f"<Journey {self.slug} stops={len(self.stops)}>"


class Corpus:
    def __init__(self, directory=None):
        self.dir = directory or JOURNEYS
        self.journeys, self.errors = {}, []
        for p in sorted(glob.glob(os.path.join(self.dir, "*.journey.json"))):
            try:
                j = Journey(p)
                self.journeys[j.slug] = j
            except Exception as e:                      # noqa: BLE001 - report, never fail
                self.errors.append((os.path.basename(p), f"{type(e).__name__}: {e}"))

    @property
    def stops(self):
        return [s for j in self.journeys.values() for s in j.stops]

    @property
    def located(self):
        return [s for s in self.stops if s.located]

    def __len__(self):
        return len(self.journeys)

    def summary(self):
        st, loc = self.stops, self.located
        out = [f"{len(self.journeys)} journeys | {len(st)} stops | {len(loc)} located"]
        if self.errors:
            out.append(f"  {len(self.errors)} UNREADABLE:")
            out += [f"    {n}: {e}" for n, e in self.errors]
        return "\n".join(out)


if __name__ == "__main__":
    c = Corpus()
    print(c.summary())
