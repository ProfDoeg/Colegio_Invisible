#!/usr/bin/env python3
"""Fill in counterpart_slug for every record in ~/codex_lab/extracted/*.json
that doesn't already have one (the 779 Codex-classified ones), using the
same robust roster-matching logic as extract_tagged_connections.py.
Rewrites each file in place. Reports anything still unresolved.
"""
import csv, json, os, sys
sys.path.insert(0, os.path.expanduser('~/codex_lab'))
from extract_tagged_connections import build_roster, resolve

REPO = '/home/drdoeg/instance2_work/Colegio_Invisible/working/journeys'
EXTRACTED = '/home/drdoeg/codex_lab/extracted'


def main():
    rows = list(csv.DictReader(open(f'{REPO}/catalog_subjects.csv')))
    by_norm, segs_by_slug = build_roster(rows)
    valid_slugs = {r['slug'] for r in rows}
    total, filled, unresolved = 0, 0, []
    for fname in sorted(os.listdir(EXTRACTED)):
        if not fname.endswith('.json'):
            continue
        path = os.path.join(EXTRACTED, fname)
        records = json.load(open(path, encoding='utf-8'))
        changed = False
        for rec in records:
            total += 1
            slug = rec.get('counterpart_slug')
            if slug and slug in valid_slugs:
                continue
            resolved = resolve(rec['counterpart_name_raw'], by_norm, segs_by_slug)
            if resolved:
                rec['counterpart_slug'] = resolved
                filled += 1
                changed = True
            else:
                unresolved.append((fname[:-5], rec['counterpart_name_raw']))
        if changed:
            json.dump(records, open(path, 'w', encoding='utf-8'), indent=1, ensure_ascii=False)
    print(f'total records: {total}')
    print(f'newly resolved: {filled}')
    print(f'still unresolved: {len(unresolved)}')
    for s, h in unresolved[:60]:
        print(f'  {s}: "{h}"')


if __name__ == '__main__':
    main()
