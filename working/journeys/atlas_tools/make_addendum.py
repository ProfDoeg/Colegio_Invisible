#!/usr/bin/env python3
"""Regenerate dossiers/ATLAS_CONNECTIONS_ADDENDUM.md from the current catalog.

The addendum rides at the end of every dossier research prompt so the
researcher knows the full roster and documents an "Atlas Connections"
section: crossings found in the sources, never forced. Regenerate after
the roster changes (new subjects queued, catalog regenerated).

    python3 atlas_tools/make_addendum.py
"""
import csv, os

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def main():
    rows = list(csv.DictReader(open(os.path.join(HERE, 'catalog_subjects.csv'))))
    names = sorted({r['traveler'].split('(')[0].split(',')[0].strip()
                    for r in rows if r['traveler'].strip()})
    roster = '; '.join(names)
    text = f"""# Atlas-connections addendum

Appended to the standing dossier prompt (PROMPT_TEMPLATE.md) since 2026-08-31, per Anthony's
direction: bring the investigation of the social graph down to the research level.
Regenerate with atlas_tools/make_addendum.py after the roster changes.

---

ATLAS CONNECTIONS. This dossier belongs to an atlas of {len(names)} historical lives. While
researching the subject, watch for any documented crossing with the people listed below: a
meeting, correspondence, collaboration, rivalry, teacher-student bond, patronage, shared
scene or institution, family tie, or a documented influence explicitly acknowledged in the
sources. Add a section titled "Atlas Connections" before the source list. For each connection
found, give: the name, the nature of the connection, dates and places where known, and the
same evidentiary label used elsewhere in the dossier (documented fact / reported fact /
allegation or theory / rumor or myth). DO NOT force or invent connections: only record what
the sources actually support, never infer a link from mere contemporaneity or shared
geography, and if few or none of the listed names genuinely intersect the subject's life,
say so plainly. Absence is a finding.

The atlas roster: {roster}
"""
    out = os.path.join(HERE, 'dossiers', 'ATLAS_CONNECTIONS_ADDENDUM.md')
    open(out, 'w').write(text)
    print(f'wrote {out} ({len(names)} names)')

if __name__ == '__main__':
    main()
