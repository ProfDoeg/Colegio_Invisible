"""dupes.py -- possible-duplicate finder across the WHOLE atlas: built journeys
and QUEUE.md rows together, not just one name checked against the other.

ledger.py's is_built() answers "does this one name already exist" for the
launch liturgy. This answers the different question: "which pairs across the
entire corpus and queue look like they might be the same person", so a human
can scan the list and adjudicate. Word-set containment (ledger's method) is
kept as one signal; a plain string-similarity ratio is added alongside it to
also catch misspellings and transliteration drift that share no common token.

    python3 dupes.py                # all candidate pairs, ranked
    python3 dupes.py --min 0.75     # loosen the similarity threshold
"""
import argparse
import difflib
import os
import re
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
from load import Corpus  # noqa: E402

STOP_TITLES = {
    "dr", "sir", "saint", "st", "san", "rabbi", "king", "queen", "emperor",
    "pope", "father", "mother", "the", "of", "de", "del", "la", "le", "el",
    "von", "van", "der", "den", "di", "da", "ibn", "bin", "al", "and", "y",
}


def norm(s):
    s = unicodedata.normalize("NFD", s or "")
    s = "".join(c for c in s if unicodedata.category(c) != "Mn").lower()
    s = re.sub(r"[^a-z0-9\s]", " ", s)
    toks = [t for t in s.split() if t not in STOP_TITLES]
    return " ".join(toks)


def queue_names(queue_path):
    """Every distinct bolded name in QUEUE.md, tolerant of trailing
    annotations after the closing ** (see ledger.py's row regex fix,
    2026-08-19 -- the same tolerance is needed here or claimed/tagged rows
    silently drop out of duplicate checking too)."""
    names, seen = [], set()
    for line in open(queue_path, encoding="utf-8"):
        m = re.match(r"\|\s*[^|]*\|\s*\*\*(.+?)\*\*[^|]*\|", line)
        if not m:
            continue
        name = m.group(1).strip()
        key = norm(name)
        if key and key not in seen:
            seen.add(key)
            names.append(name)
    return names


def all_subjects(corpus, queue_path):
    """[(display_name, status, key)] for every built journey and every
    queued row, deduplicated by normalized key within each source."""
    out = []
    for slug, j in corpus.journeys.items():
        out.append((j.traveler or slug, "built:" + slug, norm(j.traveler or slug)))
    for name in queue_names(queue_path):
        out.append((name, "queued", norm(name)))
    return out


def candidates(subjects, min_ratio=0.82):
    """Pairwise scan. Two signals: word-set containment (catches 'Carl Jung'
    vs 'Carl Gustav Jung'), and a string-similarity ratio (catches spelling/
    transliteration drift a token match misses). Either signal alone is
    enough to surface a pair; both need a human to adjudicate, not either
    fixed here automatically."""
    out = []
    n = len(subjects)
    for i in range(n):
        name_a, status_a, key_a = subjects[i]
        words_a = set(key_a.split())
        for j in range(i + 1, n):
            name_b, status_b, key_b = subjects[j]
            if key_a == key_b:
                out.append((1.0, "identical", name_a, status_a, name_b, status_b))
                continue
            words_b = set(key_b.split())
            contained = bool(words_a) and bool(words_b) and (words_a <= words_b or words_b <= words_a)
            ratio = difflib.SequenceMatcher(None, key_a, key_b).ratio()
            if contained:
                out.append((ratio, "word-containment", name_a, status_a, name_b, status_b))
            elif ratio >= min_ratio:
                out.append((ratio, "string-similarity", name_a, status_a, name_b, status_b))
    return sorted(out, key=lambda t: -t[0])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--min", type=float, default=0.82, help="string-similarity threshold")
    args = ap.parse_args()

    c = Corpus()
    subjects = all_subjects(c, os.path.join(D, "QUEUE.md"))
    print(f"{len(subjects)} distinct subjects (built + queued)\n")
    cands = candidates(subjects, args.min)
    print(f"{len(cands)} candidate pairs\n")
    for ratio, reason, a, sa, b, sb in cands:
        print(f"  {ratio:.2f} [{reason:17}] {a!r:40} ({sa})  <->  {b!r:40} ({sb})")
