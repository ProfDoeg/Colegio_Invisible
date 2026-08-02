"""fix_campa_dashes.py — replace em dashes in `campa` with comma, semicolon or period.

Scope, per the author's instruction (2026-08-01):
  - `campa` only. `name` keeps its dashes. `quote`/`quote_source` are verbatim
    source and are never touched (Virgil's "Quos ego—!" is the figure itself).

Rules, in order:
  PAIR   two dashes in one sentence are parenthetical  -> both become commas
  COORD  followed by and/but/or/nor/yet/so/not/rather   -> comma
  CLAUSE followed by an independent clause              -> semicolon
  APPOS  anything else (appositive, list, elaboration)  -> comma

Dry-run by default. `--apply` writes the files.

    python3 fix_campa_dashes.py            # proposal only
    python3 fix_campa_dashes.py --apply    # write
"""
import collections
import glob
import json
import os
import re
import sys

EM = "—"
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.abspath(os.path.join(HERE, ".."))

COORD = {"and", "but", "or", "nor", "yet", "so", "not", "rather", "never",
         "though", "although", "while", "whereas"}
SUBJ = {"it", "he", "she", "they", "we", "i", "you", "there", "this", "that",
        "these", "those", "his", "her", "their", "its"}
# finite verbs common in this register, used to spot an independent clause
VERB = re.compile(
    r"\b(is|are|was|were|will|would|has|have|had|does|do|did|can|could|may|might|"
    r"must|shall|should|remains?|becomes?|comes?|goes|takes?|makes?|means?|marks?|"
    r"holds?|keeps?|leaves?|gives?|sends?|calls?|names?|sets?|puts?|runs?|stands?|"
    r"falls?|rises?|writes?|reads?|speaks?|dies|lives?|returns?|arrives?|enters?|"
    r"carries|carry|proves?|shows?|opens?|closes?|begins?|ends?)\b")


DET = {"the", "a", "an", "his", "her", "their", "its", "one", "two", "three"}


def _sentence_bounds(text, idx):
    lo = max(text.rfind(". ", 0, idx), text.rfind("! ", 0, idx),
             text.rfind("? ", 0, idx))
    lo = 0 if lo < 0 else lo + 2
    hi = text.find(". ", idx)
    hi = len(text) if hi < 0 else hi
    return lo, hi


def _is_clause(span):
    """Does `span` open an independent clause?"""
    span = span.strip()
    if not span:
        return False
    words = re.split(r"[\s,;:]+", span)
    first = words[0].lower().strip(".,;:'\"")
    if first in SUBJ:
        return bool(VERB.search(span[:80]))
    if first in DET:
        # subject noun phrase then a finite verb close behind
        return bool(VERB.search(" ".join(words[:7])))
    return False


def plan(text):
    """Decide every dash on the ORIGINAL text, before any edit is applied.

    Returns [(index, replacement, rule)] left to right.
    """
    idxs = [i for i, ch in enumerate(text) if ch == EM]
    decided = {}

    # true parentheticals: two dashes in one sentence bracketing a NON-clause
    by_sentence = collections.defaultdict(list)
    for i in idxs:
        by_sentence[_sentence_bounds(text, i)].append(i)
    for (lo, hi), group in by_sentence.items():
        if len(group) == 2:
            inner = text[group[0] + 1:group[1]]
            if "," in inner or ";" in inner:
                # The aside carries its own internal punctuation, so commas would
                # erase the boundary and the reader could not see where it ends.
                # Documented exception, same principle as `name` and quotations:
                # the dash stays where nothing else does its work.
                decided[group[0]] = (None, "KEEP")
                decided[group[1]] = (None, "KEEP")
            elif not _is_clause(inner):
                decided[group[0]] = (",", "PAIR")
                decided[group[1]] = (",", "PAIR")

    for i in idxs:
        if i in decided:
            continue
        _, hi = _sentence_bounds(text, i)
        after = text[i + 1:hi].strip()
        first = re.split(r"[\s,;:]+", after)[0].lower().strip(".,;:'\"") if after else ""
        if first in COORD:
            decided[i] = (",", "COORD")
        elif _is_clause(after):
            decided[i] = (";", "CLAUSE")
        else:
            decided[i] = (",", "APPOS")

    return [(i, *decided[i]) for i in idxs]


def rewrite(campa):
    """Return (new_text, [(rule, before, replacement, after), ...])."""
    decisions = plan(campa)
    notes = []
    for i, rep, rule in decisions:
        notes.append((rule, campa[max(0, i - 58):i].rstrip(), rep or "(kept)",
                      campa[i + 1:i + 59].lstrip()))
    out = campa
    # apply right-to-left so earlier indices stay valid
    for i, rep, rule in sorted((d for d in decisions if d[1] is not None),
                               key=lambda t: -t[0]):
        start, end = i, i + 1
        while start > 0 and out[start - 1] == " ":
            start -= 1
        while end < len(out) and out[end] == " ":
            end += 1
        prev = out[start - 1] if start else ""
        rep_final = "" if prev in ",;:." else rep
        out = out[:start] + rep_final + " " + out[end:]
    return out, notes


# Match a "campa": "..." value with JSON escapes intact. Editing the raw text
# rather than round-tripping through json.dump keeps every other byte of the
# file identical - a dump would re-indent compact inline arrays and bury a
# 153-line edit inside a 400-line reformat.
CAMPA_RE = re.compile(r'("campa"\s*:\s*)"((?:[^"\\]|\\.)*)"')


def main(apply=False):
    stats = collections.Counter()
    changed_files = 0
    total = 0
    report = []

    for path in sorted(glob.glob(os.path.join(SRC, "*.journey.json"))):
        raw = open(path, encoding="utf-8").read()
        slug = os.path.basename(path).replace(".journey.json", "")
        hits = []

        def repl(m):
            value = json.loads('"' + m.group(2) + '"')
            if EM not in value:
                return m.group(0)
            new, notes = rewrite(value)
            if new == value:
                return m.group(0)
            hits.append(notes)
            return m.group(1) + json.dumps(new, ensure_ascii=False)

        out = CAMPA_RE.sub(repl, raw)
        if out == raw:
            continue
        changed_files += 1
        for notes in hits:
            for rule, b, r, a in notes:
                if r == "(kept)":
                    continue
                stats[rule] += 1
                total += 1
                report.append((slug, rule, b, r, a))
        if apply:
            # verify the edit still parses before it touches disk
            json.loads(out)
            open(path, "w", encoding="utf-8").write(out)

    print(("APPLIED" if apply else "PROPOSAL (dry run)") +
          f": {total} dashes in {changed_files} files")
    print("  by rule: " + ", ".join(f"{k}={v}" for k, v in stats.most_common()))
    return report


if __name__ == "__main__":
    rep = main(apply="--apply" in sys.argv)
    print("\n--- sample, 3 per rule ---")
    seen = collections.Counter()
    for slug, rule, b, r, a in rep:
        if seen[rule] >= 3:
            continue
        seen[rule] += 1
        print(f"\n[{rule}] {slug}")
        print(f"   ...{b}  >>{r}<<  {a}...")
