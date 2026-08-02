"""social.py — the cross-mention graph, and the orphan hubs it exposes.

This is the module that answers the atlas's admission question. A subject earns
a file by being an ORPHAN HUB: already named in N existing journeys, with no
journey of its own. Napoleon was the archetype at 16 mentions.

Also measures the mutual gaze: if A's prose names B, B's should name A. The
asymmetries are the interlock repairs.
"""
import collections
import re

from aliases import Aliases, norm


class Social:
    def __init__(self, corpus):
        self.corpus = corpus
        self.aliases = Aliases(corpus)
        # who names whom: {namer: {named: count}}
        self.graph = {}
        for slug, j in corpus.journeys.items():
            self.graph[slug] = self.aliases.names_in(j.text, exclude=slug)

    # ---- mutual gaze --------------------------------------------------------
    def asymmetries(self, min_count=1):
        """Pairs where A names B but B never names A."""
        out = []
        for a, named in self.graph.items():
            for b, n in named.items():
                if n >= min_count and not self.graph.get(b, {}).get(a):
                    out.append((a, b, n))
        return sorted(out, key=lambda t: -t[2])

    def reciprocal(self):
        seen, out = set(), []
        for a, named in self.graph.items():
            for b, n in named.items():
                if b in self.graph and self.graph[b].get(a):
                    key = tuple(sorted((a, b)))
                    if key not in seen:
                        seen.add(key)
                        out.append((key[0], key[1], n, self.graph[b][a]))
        return sorted(out, key=lambda t: -(t[2] + t[3]))

    # ---- orphan hubs --------------------------------------------------------
    def orphan_hubs(self, candidates, min_journeys=2):
        """Rank proposed subjects by how many existing journeys already name them.

        `candidates` maps a proposed slug -> list of name strings.
        """
        ranked = []
        for slug, names in candidates.items():
            if slug in self.corpus.journeys:
                continue                                    # already has a file
            alt = sorted({re.escape(norm(n)) for n in names if len(n) >= 4},
                         key=len, reverse=True)
            if not alt:
                continue
            pat = re.compile(r"\b(?:%s)\b" % "|".join(alt))
            hits = {}
            for s, j in self.corpus.journeys.items():
                c = len(pat.findall(norm(j.text)))
                if c:
                    hits[s] = c
            if len(hits) >= min_journeys:
                ranked.append((slug, len(hits), sum(hits.values()),
                               sorted(hits, key=lambda k: -hits[k])))
        return sorted(ranked, key=lambda t: (-t[1], -t[2]))

    def discover_orphans(self, min_journeys=3, top=25):
        """Find capitalised person-like names recurring across journeys with no
        file of their own. Heuristic and noisy by design - it proposes, a human
        adjudicates."""
        pat = re.compile(r"\b([A-Z][a-zéà-ÿ]{3,})\s+([A-Z][a-zéà-ÿ]{3,})\b")
        per_name = collections.defaultdict(set)
        for slug, j in self.corpus.journeys.items():
            for m in pat.finditer(j.text):
                per_name[f"{m.group(1)} {m.group(2)}"].add(slug)
        known = set()
        for names in self.aliases.by_slug.values():
            known |= {norm(n) for n in names}
        out = []
        for name, slugs in per_name.items():
            if len(slugs) < min_journeys:
                continue
            n = norm(name)
            if any(k in n or n in k for k in known):
                continue
            out.append((name, len(slugs), sorted(slugs)))
        return sorted(out, key=lambda t: -t[1])[:top]


if __name__ == "__main__":
    from load import Corpus
    c = Corpus()
    s = Social(c)
    print(c.summary())
    print("\n=== strongest reciprocal pairs ===")
    for a, b, n, m in s.reciprocal()[:10]:
        print(f"  {a:22} <-> {b:22} {n:3}/{m}")
    print("\n=== asymmetries (A names B, B silent) ===")
    for a, b, n in s.asymmetries()[:15]:
        print(f"  {a:22} -> {b:22} {n:3}  (no return gaze)")
    print("\n=== candidate orphan hubs (discovered) ===")
    for name, k, slugs in s.discover_orphans():
        print(f"  {name:28} {k:3} journeys  {', '.join(slugs[:6])}")
