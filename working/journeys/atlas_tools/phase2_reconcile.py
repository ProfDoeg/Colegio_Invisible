#!/usr/bin/env python3
"""Phase 2: build the edge list from all extracted records and classify
each pair (A, B) as ONE_SIDED (only one dossier documents it -- mirror
automatically), AGREEING (both sides document it compatibly -- just tag
both), or CONFLICT (both sides document it but disagree on type or
direction -- needs an adjudicator). Script-only, no LLM calls here.

Writes ~/codex_lab/phase2_report.json with the full classification and
prints a summary. Run this before spending any adjudicator budget.
"""
import json, os
from collections import defaultdict

EXTRACTED = '/home/drdoeg/codex_lab/extracted'
DIRECTIONAL = {1, 2, 9}


def load_all():
    by_slug = {}
    for fname in os.listdir(EXTRACTED):
        if not fname.endswith('.json'):
            continue
        slug = fname[:-5]
        records = json.load(open(os.path.join(EXTRACTED, fname), encoding='utf-8'))
        by_slug[slug] = [r for r in records if r.get('counterpart_slug')]
    return by_slug


def opposite(sign):
    return {'+': '-', '-': '+', '': ''}.get(sign, '')


def classify_pair(a, b, a_recs, b_recs):
    """Per-claim comparison, not per-pair: a pair is only a real CONFLICT
    if the SAME type is asserted on both sides with an incompatible sign
    (both dossiers can't be the 'earlier' figure) or an incompatible
    T2 subtype. A type present on one side and simply absent on the
    other is a gap to fill, not a contradiction -- merge it in (matches
    Anthony's lean-toward-connection instruction: never sever for an
    absence, only for an actual disagreement)."""
    if a_recs and not b_recs:
        return 'ONE_SIDED', {'from': a, 'to': b, 'has': a_recs, 'missing_on': b}
    if b_recs and not a_recs:
        return 'ONE_SIDED', {'from': b, 'to': a, 'has': b_recs, 'missing_on': a}

    point_conflicts = []
    a_by_type = defaultdict(list)
    for r in a_recs:
        a_by_type[r['type']].append(r)
    b_by_type = defaultdict(list)
    for r in b_recs:
        b_by_type[r['type']].append(r)

    for t in set(a_by_type) & set(b_by_type):
        for ra in a_by_type[t]:
            want_sign = opposite(ra['sign']) if t in DIRECTIONAL else ''
            match = [rb for rb in b_by_type[t] if rb['sign'] == want_sign]
            if not match:
                point_conflicts.append({'type': t, 'a_record': ra, 'b_records': b_by_type[t]})
            elif t == 2:
                subs_a, subs_b = ra.get('subtype'), match[0].get('subtype')
                if subs_a and subs_b and subs_a != subs_b and 'unresolved' not in (subs_a, subs_b):
                    point_conflicts.append({'type': t, 'subtype_mismatch': True,
                                             'a_record': ra, 'b_records': match})

    if point_conflicts:
        return 'CONFLICT', {'a': a, 'b': b, 'a_records': a_recs, 'b_records': b_recs,
                             'point_conflicts': point_conflicts}
    # everything present on both sides is compatible; anything on one
    # side but not the other (different types) is a gap to merge
    a_only = [r for r in a_recs if r['type'] not in b_by_type]
    b_only = [r for r in b_recs if r['type'] not in a_by_type]
    return 'AGREEING', {'a': a, 'b': b, 'a_records': a_recs, 'b_records': b_recs,
                         'a_only_types': a_only, 'b_only_types': b_only}


def main():
    by_slug = load_all()
    edges = defaultdict(lambda: {'a_recs': [], 'b_recs': []})
    for slug, records in by_slug.items():
        for r in records:
            other = r['counterpart_slug']
            if other == slug or other not in by_slug:
                continue
            key = tuple(sorted((slug, other)))
            side = 'a_recs' if key[0] == slug else 'b_recs'
            edges[key][side].append(r)

    results = {'ONE_SIDED': [], 'AGREEING': [], 'CONFLICT': []}
    for (a, b), sides in edges.items():
        kind, detail = classify_pair(a, b, sides['a_recs'], sides['b_recs'])
        results[kind].append(detail)

    print(f"total edges considered: {len(edges)}")
    for kind in ('ONE_SIDED', 'AGREEING', 'CONFLICT'):
        print(f'{kind}: {len(results[kind])}')

    json.dump(results, open('/home/drdoeg/codex_lab/phase2_report.json', 'w'),
              indent=1, ensure_ascii=False)
    print('\nfull detail written to ~/codex_lab/phase2_report.json')

    print('\nsample point-conflicts:')
    for c in results['CONFLICT'][:8]:
        print(f"  {c['a']} <-> {c['b']} ({len(c['point_conflicts'])} point conflict(s))")
        for pc in c['point_conflicts']:
            print(f"    T{pc['type']}: {c['a']} says {pc['a_record']['sign']} -- {pc['a_record']['text'][:90]}")
            for rb in pc['b_records']:
                print(f"           {c['b']} says {rb['sign']} -- {rb['text'][:90]}")


if __name__ == '__main__':
    main()
