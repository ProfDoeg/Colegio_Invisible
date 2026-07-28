#!/usr/bin/env python3
"""Overlay translated chunks onto the English skeletons -> es/<slug>.journey.json.

Coordinates, dates, confidences, sources, suggested_refs pass through from the
English originals untouched; only text fields are replaced. A journey is only
written when every chunk validates. Prints a re-run list of bad/missing chunks.
"""
import json, glob, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
OUT_DIR = os.path.join(SRC, 'es')
os.makedirs(OUT_DIR, exist_ok=True)

BAD_CHARS = '—–'

# The ban is on the RHETORICAL dash, not on typography (Anthony, 2026-07-20).
# An en-dash binding two endpoints with no spaces is a range and is allowed:
# Oran-Argel, 1145-1221. Any em-dash, and any spaced dash, is the rhetorical
# construct and stays banned.
RANGE_DASH = re.compile(r'(?<=\S)–(?=\S)')

def dashes(s):
    if not isinstance(s, str):
        return False
    return any(c in RANGE_DASH.sub('', s) for c in BAD_CHARS)

manifest = json.load(open(os.path.join(HERE, 'manifest.json')))
by_slug = {}
for cid in manifest:
    by_slug.setdefault(cid.rsplit('.', 1)[0], []).append(cid)

bad, ok = [], 0
for slug, cids in sorted(by_slug.items()):
    j = json.load(open(os.path.join(SRC, slug + '.journey.json')))
    stops_by_key = {}
    header = None
    errs = []
    for cid in sorted(cids):
        p = os.path.join(HERE, 'out', cid + '.json')
        if not os.path.exists(p):
            errs.append((cid, 'missing')); continue
        try:
            c = json.load(open(p))
        except Exception as e:
            errs.append((cid, f'unparseable: {e}')); continue
        if 'header' in c:
            header = c['header']
        for st in c.get('stops', []):
            stops_by_key[(st.get('si'), st.get('i'))] = (cid, st)

    # positional coverage + field validation against the English skeleton
    for si, seg in enumerate(j.get('segments', [])):
        for i, en in enumerate(seg.get('stops', [])):
            got = stops_by_key.get((si, i))
            if not got:
                flat_i = sum(len(s2.get('stops', [])) for s2 in j['segments'][:si]) + i
                errs.append((cids[min(flat_i // 12, len(cids) - 1)], f'stop {si}/{i} uncovered')); continue
            cid, st = got
            for fld in ('name', 'campa'):
                if en.get(fld) and not (isinstance(st.get(fld), str) and st.get(fld).strip()):
                    errs.append((cid, f'stop {si}/{i} empty {fld}'))
            if (en.get('quote') is None) != (st.get('quote') is None):
                errs.append((cid, f'stop {si}/{i} quote nullity mismatch'))
            for fld in ('name', 'campa', 'quote', 'quote_source'):
                if dashes(st.get(fld)):
                    errs.append((cid, f'stop {si}/{i} dash in {fld}'))
    if header is None:
        errs.append((cids[0], 'header missing'))
    else:
        for k in ('traveler', 'title', 'register'):
            if not (header.get(k) or '').strip():
                errs.append((cids[0], f'header empty {k}'))
            if dashes(header.get(k)):
                errs.append((cids[0], f'header dash in {k}'))
        names = header.get('segment_names', [])
        if len(names) != len(j.get('segments', [])):
            errs.append((cids[0], 'segment_names count mismatch'))
        elif any(dashes(n) or not n.strip() for n in names):
            errs.append((cids[0], 'segment_names bad entry'))

    if errs:
        bad.extend(errs); continue

    j['traveler'] = header['traveler']
    j['title'] = header['title']
    j['register'] = header['register']
    for si, seg in enumerate(j['segments']):
        seg['name'] = header['segment_names'][si]
        for i, en in enumerate(seg.get('stops', [])):
            _, st = stops_by_key[(si, i)]
            en['name'] = st['name']
            en['campa'] = st['campa']
            en['quote'] = st.get('quote')
            en['quote_source'] = st.get('quote_source')
    with open(os.path.join(OUT_DIR, slug + '.journey.json'), 'w') as f:
        json.dump(j, f, ensure_ascii=False, indent=1)
    ok += 1

print(f'{ok}/{len(by_slug)} journeys merged')
if bad:
    rerun = sorted({cid for cid, _ in bad})
    print(f'{len(bad)} problems in {len(rerun)} chunks:')
    for cid, why in bad[:40]:
        print(f'  {cid}: {why}')
    with open(os.path.join(HERE, 'rerun.json'), 'w') as f:
        json.dump(rerun, f)
    print('rerun list -> rerun.json')
    sys.exit(1)
