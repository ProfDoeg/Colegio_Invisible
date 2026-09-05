#!/usr/bin/env python3
"""Build the queryable connections.csv from tags_per_subject.json: one row
per directed claim, exactly matching what's now written in each dossier's
Connection Tags block (own claims + mirrors). Written to the tracked repo
alongside catalog_subjects.csv/catalog_stops.csv.
"""
import csv, json

TAGS = '/home/drdoeg/codex_lab/tags_per_subject.json'
OUT = '/home/drdoeg/instance2_work/Colegio_Invisible/working/journeys/connections.csv'

TYPE_LABEL = {1: 'wrote_about', 2: 'prophecy_hyperstition', 3: 'discourse',
              4: 'proximity_milieu', 5: 'friendship_meeting', 9: 'shared_object_site'}


def main():
    tags_per_subject = json.load(open(TAGS, encoding='utf-8'))
    rows = []
    for slug, records in sorted(tags_per_subject.items()):
        for rec in records:
            rows.append({
                'subject_slug': slug,
                'counterpart_slug': rec['counterpart_slug'],
                'counterpart_name': rec['counterpart_name'],
                'type': rec['type'],
                'type_label': TYPE_LABEL.get(rec['type'], ''),
                'sign': rec['sign'],
                'subtype': rec.get('subtype') or '',
                'source': rec['source'],
                'text': rec['text'],
            })
    with open(OUT, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['subject_slug', 'counterpart_slug', 'counterpart_name',
                                           'type', 'type_label', 'sign', 'subtype', 'source', 'text'])
        w.writeheader()
        w.writerows(rows)
    print(f'wrote {OUT} ({len(rows)} rows)')


if __name__ == '__main__':
    main()
