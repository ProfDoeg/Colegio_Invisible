#!/usr/bin/env python3
"""Phase 3, step A: for every dossier, compute the FULL final list of
connection-tag entries (its own existing claims + mirrored entries for
whatever a counterpart documents that this dossier doesn't). Per
Anthony's direction 2026-09-05: don't retrofit tags into old prose,
append a single new "### Connection Tags" block at the end of the
Atlas Connections section instead -- purely additive, no risk of
misplacing a tag inside an existing sentence.

Writes ~/codex_lab/tags_per_subject.json: {slug: [ {counterpart_slug,
counterpart_name, type, sign, subtype, source, text}, ... ]}
"source" is "own" (this dossier's own documented claim) or "mirror"
(added because the counterpart documents it and this dossier didn't).
"""
import csv, json, os
from collections import defaultdict

REPO = '/home/drdoeg/instance2_work/Colegio_Invisible/working/journeys'
EXTRACTED = '/home/drdoeg/codex_lab/extracted'
DIRECTIONAL = {1, 2, 9}


def opposite(sign):
    return {'+': '-', '-': '+', '': ''}.get(sign, '')


def load_all():
    by_slug = {}
    for fname in os.listdir(EXTRACTED):
        if not fname.endswith('.json'):
            continue
        slug = fname[:-5]
        records = json.load(open(os.path.join(EXTRACTED, fname), encoding='utf-8'))
        by_slug[slug] = [r for r in records if r.get('counterpart_slug')]
    return by_slug


def main():
    rows = list(csv.DictReader(open(f'{REPO}/catalog_subjects.csv')))
    name_by_slug = {r['slug']: r['traveler'].split('(')[0].split(',')[0].strip() for r in rows}
    by_slug = load_all()

    final = defaultdict(list)
    seen = defaultdict(set)  # (slug, counterpart_slug, type, sign) already added

    def add(slug, counterpart_slug, type_, sign, subtype, source, text):
        key = (counterpart_slug, type_, sign)
        if key in seen[slug]:
            return
        seen[slug].add(key)
        final[slug].append({
            'counterpart_slug': counterpart_slug,
            'counterpart_name': name_by_slug.get(counterpart_slug, counterpart_slug),
            'type': type_, 'sign': sign, 'subtype': subtype,
            'source': source, 'text': text,
        })

    # own claims
    for slug, records in by_slug.items():
        for r in records:
            other = r['counterpart_slug']
            if other == slug or other not in by_slug:
                continue
            add(slug, other, r['type'], r['sign'], r.get('subtype'), 'own', r['text'])

    # mirrors: for every record A has about B, ensure B has the flipped counterpart
    for slug, records in by_slug.items():
        for r in records:
            other = r['counterpart_slug']
            if other == slug or other not in by_slug:
                continue
            t = r['type']
            want_sign = opposite(r['sign']) if t in DIRECTIONAL else r['sign']
            key = (slug, t, want_sign)
            if key in seen[other]:
                continue  # already documented on the other side
            add(other, slug, t, want_sign, r.get('subtype'), 'mirror', r['text'])

    os.makedirs('/home/drdoeg/codex_lab', exist_ok=True)
    json.dump(final, open('/home/drdoeg/codex_lab/tags_per_subject.json', 'w'),
              indent=1, ensure_ascii=False)
    total = sum(len(v) for v in final.values())
    own = sum(1 for v in final.values() for r in v if r['source'] == 'own')
    mirror = total - own
    print(f'subjects with at least one tag: {len(final)}')
    print(f'total tag entries: {total} (own: {own}, mirrored: {mirror})')


if __name__ == '__main__':
    main()
