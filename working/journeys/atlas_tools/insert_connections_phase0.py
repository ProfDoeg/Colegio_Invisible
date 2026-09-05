#!/usr/bin/env python3
"""Additive-only insertion of the Phase 0 backfilled 'Atlas Connections'
sections into the tracked repo's dossiers. Never touches any existing text:
inserts the new section immediately before the LAST '## Sources' heading, or
appends at the end of the file if that heading is absent. Run with
--dry-run first to see exactly what would change.
"""
import os, re, sys

REPO_DOSSIERS = '/home/drdoeg/instance2_work/Colegio_Invisible/working/journeys/dossiers'
SECTIONS = '/home/drdoeg/codex_lab/connections_out'


def insert(dossier_text, section_text):
    section_text = section_text.strip() + '\n'
    matches = list(re.finditer(r'^## Sources\b.*$', dossier_text, re.M))
    if matches:
        pos = matches[-1].start()
        before = dossier_text[:pos].rstrip('\n') + '\n\n'
        after = dossier_text[pos:]
        return before + section_text + '\n' + after
    return dossier_text.rstrip('\n') + '\n\n' + section_text


def main():
    dry_run = '--dry-run' in sys.argv
    files = sorted(f for f in os.listdir(SECTIONS) if f.endswith('.section.md'))
    changed, missing_dossier = [], []
    for fname in files:
        slug = fname[:-len('.section.md')]
        dossier_path = os.path.join(REPO_DOSSIERS, f'{slug}.dossier.md')
        if not os.path.exists(dossier_path):
            missing_dossier.append(slug)
            continue
        section_text = open(os.path.join(SECTIONS, fname), encoding='utf-8', errors='replace').read()
        dossier_text = open(dossier_path, encoding='utf-8', errors='replace').read()
        if 'atlas connection' in dossier_text.lower():
            print(f'SKIP {slug}: dossier already has a connections section')
            continue
        new_text = insert(dossier_text, section_text)
        if not dry_run:
            open(dossier_path, 'w', encoding='utf-8').write(new_text)
        changed.append(slug)
    print(f"\n{'would insert' if dry_run else 'inserted'} into {len(changed)} dossiers")
    if missing_dossier:
        print(f'missing dossier file for: {missing_dossier}')


if __name__ == '__main__':
    main()
