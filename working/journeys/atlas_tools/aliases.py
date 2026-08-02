"""aliases.py — resolve a traveler to the strings that actually name them in prose.

The survey's cross-mention counts only work if "Perón"/"Evita"/"Eva Duarte" all
resolve to eva_peron, and if a bare surname like "Goethe" counts while a false
friend does not. Names are derived from each journey's own fields first, so the
corpus stays the source of truth; the manual table is only for cases prose uses
a name the file never states.

Accent-insensitive by design: prose writes Peron and Perón interchangeably.
"""
import re
import unicodedata

# Names prose uses that a journey's own fields never contain.
EXTRA = {
    "eva_peron":    ["Evita", "Eva Duarte", "la Señora"],
    "juan_peron":   ["el General", "Perón"],
    "napoleon":     ["Bonaparte", "the Emperor", "the Corsican"],
    "goethe_full":  ["Goethe"],
    "che_guevara":  ["Che", "Guevara"],
    "san_martin":   ["San Martín", "el Libertador"],
    "bolivar":      ["Bolívar", "el Libertador"],
    "muhammad":     ["the Prophet"],
    "jesus":        ["Christ", "the Nazarene"],
    "joan_of_arc":  ["Jeanne", "the Maid", "la Pucelle"],
    "dannunzio":    ["d'Annunzio", "the Comandante"],
}

# Tokens too generic to count as naming someone.
STOP = {
    "the", "of", "de", "del", "la", "le", "el", "von", "van", "der", "den", "di",
    "da", "ibn", "bin", "al", "saint", "st", "san", "sir", "king", "queen",
    "emperor", "pope", "the great", "full", "and", "y",
}


def strip_accents(s):
    return "".join(c for c in unicodedata.normalize("NFD", s)
                   if unicodedata.category(c) != "Mn")


def norm(s):
    return strip_accents(s or "").lower()


def _candidates(journey):
    """Name strings for one journey, from its own fields plus the manual table."""
    out = set()
    for field in (journey.traveler, journey.slug.replace("_", " ")):
        if not field:
            continue
        # "Odysseus (Ulysses)" -> "Odysseus", "Ulysses"
        for part in re.split(r"[()·/]|,\s|\balias\b", field):
            part = part.strip(" .·—-")
            if len(part) < 3:
                continue
            out.add(part)
            # trailing surname: "Johann Wolfgang von Goethe" -> "Goethe"
            toks = [t for t in part.split() if norm(t) not in STOP]
            if len(toks) > 1 and len(toks[-1]) > 3:
                out.add(toks[-1])
    out |= set(EXTRA.get(journey.slug, []))
    return {n for n in out if norm(n) not in STOP and len(n) >= 4}


class Aliases:
    def __init__(self, corpus):
        self.corpus = corpus
        self.by_slug = {slug: _candidates(j) for slug, j in corpus.journeys.items()}
        # compiled word-boundary matchers over accent-folded text
        self.patterns = {}
        for slug, names in self.by_slug.items():
            alt = sorted({re.escape(norm(n)) for n in names}, key=len, reverse=True)
            if alt:
                self.patterns[slug] = re.compile(r"\b(?:%s)\b" % "|".join(alt))

    def mentions(self, text, slug):
        """How many times `text` names the traveler of `slug`."""
        p = self.patterns.get(slug)
        return len(p.findall(norm(text))) if p else 0

    def names_in(self, text, exclude=None):
        """Which travelers this text names, as {slug: count}."""
        n = norm(text)
        hits = {}
        for slug, p in self.patterns.items():
            if slug == exclude:
                continue
            c = len(p.findall(n))
            if c:
                hits[slug] = c
        return hits


if __name__ == "__main__":
    from load import Corpus
    c = Corpus()
    a = Aliases(c)
    for slug in ("napoleon", "goethe_full", "eva_peron"):
        if slug in a.by_slug:
            print(f"{slug:14} -> {sorted(a.by_slug[slug])}")
