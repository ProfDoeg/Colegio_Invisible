#!/usr/bin/env python3
"""Phase 3, step B: append one new "### Connection Tags" block at the end
of each dossier's Atlas Connections section (right before whatever
heading follows it, or at file end). Additive only -- never touches a
byte of existing content. Run with --dry-run to preview counts only.
"""
import json, os, re, sys

REPO_DOSSIERS = '/home/drdoeg/instance2_work/Colegio_Invisible/working/journeys/dossiers'
TAGS = '/home/drdoeg/codex_lab/tags_per_subject.json'

TYPE_LABEL = {1: 'wrote about', 2: 'prophecy/hyperstition', 3: 'discourse',
              4: 'proximity/milieu', 5: 'friendship/meeting', 9: 'shared object/site'}


def format_tag(rec):
    tag = f"[T{rec['type']}{rec['sign']}"
    if rec.get('subtype'):
        tag += f" {rec['subtype']}"
    tag += ']'
    line = f"- **{rec['counterpart_name']}** {tag}"
    if rec['source'] == 'mirror':
        line += f" (mirrored from {rec['counterpart_slug']}.dossier.md)"
    return line


def build_block(records):
    lines = ['### Connection Tags', '',
             'Machine-readable summary of this dossier\'s Atlas Connections, added '
             '2026-09-05 during the connections-harmonization pass. Types: T1 wrote '
             'about a past figure, T2 prophecy/hyperstition, T3 discourse, T4 '
             'proximity/milieu, T5 friendship/meeting, T9 shared object or site. '
             'Sign + = this subject is the earlier/source figure, - = the later '
             'figure, blank = undirected. See the prose above (or the counterpart\'s '
             'own dossier) for the full claim.', '']
    for rec in records:
        lines.append(format_tag(rec))
    return '\n'.join(lines) + '\n'


def insert(dossier_text, block):
    m = re.search(r'^#+ .*Atlas Connections.*$', dossier_text, re.M)
    if not m:
        # no connections section at all (shouldn't happen post-Phase-0, but
        # fall back to end of file rather than skip)
        return dossier_text.rstrip('\n') + '\n\n' + block
    rest = dossier_text[m.end():]
    nxt = re.search(r'^## ', rest, re.M)
    if nxt:
        cut = m.end() + nxt.start()
    else:
        cut = len(dossier_text)
    before = dossier_text[:cut].rstrip('\n') + '\n\n'
    after = dossier_text[cut:]
    return before + block + '\n' + after


def main():
    dry_run = '--dry-run' in sys.argv
    tags_per_subject = json.load(open(TAGS, encoding='utf-8'))
    changed, skipped_no_dossier, skipped_already = 0, 0, 0
    for slug, records in tags_per_subject.items():
        if not records:
            continue
        path = os.path.join(REPO_DOSSIERS, f'{slug}.dossier.md')
        if not os.path.exists(path):
            skipped_no_dossier += 1
            continue
        text = open(path, encoding='utf-8', errors='replace').read()
        if '### Connection Tags' in text:
            skipped_already += 1
            continue
        block = build_block(records)
        new_text = insert(text, block)
        if not dry_run:
            open(path, 'w', encoding='utf-8').write(new_text)
        changed += 1
    print(f"{'would update' if dry_run else 'updated'}: {changed}")
    print(f'skipped (no dossier file): {skipped_no_dossier}')
    print(f'skipped (already has a Connection Tags block): {skipped_already}')


if __name__ == '__main__':
    main()
