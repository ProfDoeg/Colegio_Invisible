"""style.py — enforce house style on AUTHORED text only.

The rules, measured from the corpus rather than assumed (see the survey):
  - no em dash in authored prose (commit 1f5b517 stripped them corpus-wide)
  - straight quotes only: zero curly ' or "" in 8,020 strings
  - campa runs 450-650 chars (95% of entries; median 550)

`quote` is verbatim source text - KJV, Qur'an, letters - and is deliberately
EXEMPT. Editing a quotation to fit house style would falsify it.
"""
import collections
import re

EM_DASH = "—"
CURLY = ["‘", "’", "“", "”"]

CAMPA_MIN, CAMPA_MAX = 450, 650


class Style:
    def __init__(self, corpus):
        self.corpus = corpus

    def em_dashes(self):
        """Em dashes in authored fields. Quotes are exempt; register is not."""
        out = []
        for j in self.corpus.journeys.values():
            if EM_DASH in (j.register or ""):
                out.append((j.slug, "register", j.register))
            if EM_DASH in (j.title or ""):
                out.append((j.slug, "title", j.title))
            for s in j.stops:
                if EM_DASH in s.campa:
                    out.append((j.slug, f"campa[{s.i}]", s.name[:40]))
                if EM_DASH in s.name:
                    out.append((j.slug, f"name[{s.i}]", s.name[:40]))
        return out

    def curly_quotes(self):
        out = []
        for j in self.corpus.journeys.values():
            for s in j.stops:
                for field in ("campa", "name"):
                    v = getattr(s, field)
                    if any(c in v for c in CURLY):
                        out.append((j.slug, f"{field}[{s.i}]", s.name[:40]))
        return out

    def campa_length(self):
        """Entries outside the measured band."""
        short, long_ = [], []
        for s in self.corpus.stops:
            n = len(s.campa)
            if n == 0:
                continue
            if n < CAMPA_MIN:
                short.append((s, n))
            elif n > CAMPA_MAX:
                long_.append((s, n))
        return sorted(short, key=lambda t: t[1]), sorted(long_, key=lambda t: -t[1])

    def missing_campa(self):
        return [s for s in self.corpus.stops if not s.campa.strip()]

    def register_variants(self):
        """The register sentence should be ONE string. Punctuation drift here is
        invisible to readers and obvious to a diff."""
        return collections.Counter(j.register for j in self.corpus.journeys.values())

    def quote_density(self):
        """Corpus median is ~12 per journey; 0-3 was flagged as a quote desert."""
        rows = [(j.slug, sum(1 for s in j.stops if s.quote), len(j.stops))
                for j in self.corpus.journeys.values()]
        return sorted(rows, key=lambda t: t[1])


if __name__ == "__main__":
    from load import Corpus
    st = Style(Corpus())
    print("=== register variants (should be exactly 1) ===")
    for v, n in st.register_variants().most_common():
        mark = "  <-- EM DASH" if EM_DASH in (v or "") else ""
        print(f"  {n:4}  {v!r}{mark}")
    em = st.em_dashes()
    print(f"\n=== em dashes in authored text: {len(em)} ===")
    for slug, field, ctx in em[:12]:
        print(f"  {slug:22} {field:14} {ctx}")
    cq = st.curly_quotes()
    print(f"\n=== curly quotes: {len(cq)} (rule says zero) ===")
    for slug, field, ctx in cq[:8]:
        print(f"  {slug:22} {field:14} {ctx}")
    short, long_ = st.campa_length()
    print(f"\n=== campa outside {CAMPA_MIN}-{CAMPA_MAX}: {len(short)} short, {len(long_)} long ===")
    for s, n in short[:5]:
        print(f"  SHORT {n:4}  {s.slug}:{s.i} {s.name[:44]}")
    for s, n in long_[:5]:
        print(f"  LONG  {n:4}  {s.slug}:{s.i} {s.name[:44]}")
