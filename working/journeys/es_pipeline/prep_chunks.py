#!/usr/bin/env python3
"""Split the 109 journeys into translation chunks of <=12 stops.

Each chunk file carries only the text an agent must translate, keyed by
(segment index, stop index) so the merge is purely positional. Chunk 0 of
each journey also carries the header: title, register, traveler, and every
segment name.
"""
import json, glob, os

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
IN = os.path.join(HERE, 'in')
os.makedirs(IN, exist_ok=True)

CHUNK = 12
manifest = []
for f in sorted(glob.glob(os.path.join(SRC, '*.journey.json'))):
    slug = os.path.basename(f).replace('.journey.json', '')
    j = json.load(open(f))
    flat = []
    for si, seg in enumerate(j.get('segments', [])):
        for i, st in enumerate(seg.get('stops', [])):
            flat.append({
                'si': si, 'i': i,
                'name': st.get('name', ''),
                'campa': st.get('campa', ''),
                'quote': st.get('quote'),
                'quote_source': st.get('quote_source'),
            })
    for ci in range(0, max(1, (len(flat) + CHUNK - 1) // CHUNK)):
        part = flat[ci * CHUNK:(ci + 1) * CHUNK]
        chunk = {'slug': slug, 'chunk': ci, 'stops': part}
        if ci == 0:
            chunk['header'] = {
                'traveler': j.get('traveler', ''),
                'title': j.get('title', ''),
                'register': j.get('register', ''),
                'segment_names': [s.get('name', '') for s in j.get('segments', [])],
            }
        cid = f'{slug}.{ci:02d}'
        with open(os.path.join(IN, cid + '.json'), 'w') as out:
            json.dump(chunk, out, ensure_ascii=False, indent=1)
        manifest.append(cid)

with open(os.path.join(HERE, 'manifest.json'), 'w') as out:
    json.dump(manifest, out, indent=0)
print(f'{len(manifest)} chunks')
