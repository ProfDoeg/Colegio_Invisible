#!/usr/bin/env python3
"""Emit the retroactive dossier worklist: built journeys with no dossier,
oldest-built first (first git commit of the journey file), one slug per line.

Oldest-first because the earliest fleets carried the thinnest verification.
Skips subjects whose dossier exists in dossiers/ OR in the runner's out/
directory (pass it as argv[1] if it exists).

    python3 atlas_tools/retro_worklist.py [/home/drdoeg/codex_lab/out] > worklist.txt
"""
import glob, os, subprocess, sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else ''
    have = {os.path.basename(p)[:-len('.dossier.md')]
            for p in glob.glob(os.path.join(HERE, 'dossiers', '*.dossier.md'))}
    if outdir and os.path.isdir(outdir):
        have |= {os.path.basename(p)[:-len('.dossier.md')]
                 for p in glob.glob(os.path.join(outdir, '*.dossier.md'))}
    pending = []
    for p in sorted(glob.glob(os.path.join(HERE, '*.journey.json'))):
        slug = os.path.basename(p)[:-len('.journey.json')]
        if slug in have:
            continue
        ts = subprocess.run(
            ['git', 'log', '--diff-filter=A', '--follow', '--format=%at', '--', p],
            capture_output=True, text=True, cwd=HERE).stdout.strip().splitlines()
        first = int(ts[-1]) if ts else 0
        pending.append((first, slug))
    pending.sort()
    for _, slug in pending:
        print(slug)
    print(f'# {len(pending)} pending', file=sys.stderr)

if __name__ == '__main__':
    main()
