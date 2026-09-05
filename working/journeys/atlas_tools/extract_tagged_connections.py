#!/usr/bin/env python3
"""Phase 1a: deterministic extraction for the 289 dossiers whose Atlas
Connections section was already written in the tagged format (Phase 0,
2026-09-05) -- no LLM needed, just a regex parse. The remaining ~607
prose-only dossiers are handled by extract_connections_runner.py (Codex).

Writes one JSON array per dossier to ~/codex_lab/extracted/<slug>.json:
  {counterpart_slug, counterpart_name_raw, type, sign, subtype, text}
counterpart_slug is null if the heading text couldn't be resolved against
the roster (flagged for manual look, should be rare since Phase 0 wrote
these headings from the same roster in the first place).
"""
import csv, json, os, re, unicodedata

REPO = '/home/drdoeg/instance2_work/Colegio_Invisible/working/journeys'
OUT = '/home/drdoeg/codex_lab/extracted'

TAG_RE = re.compile(r'\*\*\[T(\d+)([+-]?)(?:\s+(\w+))?\]\*\*')
HEADING_RE = re.compile(r'^### (.+)$', re.M)


def norm(s):
    s = unicodedata.normalize('NFKD', s).encode('ascii', 'ignore').decode('ascii')
    return re.sub(r'[^a-z0-9]', '', s.lower())


def name_segments(traveler):
    """Roster names are messy: 'Aurelius Augustinus, Saint Augustine of
    Hippo', 'Simon bar Jonah, called Cephas, the Apostle Peter', 'Plinio
    el Viejo (Gaius Plinius Secundus, Pliny the Elder)'. Dossiers written
    in English cite whichever alias they like, sometimes a partial one
    ('Whitfield Diffie' for catalog's 'Bailey Whitfield Diffie'). Extract
    every plausible candidate segment, not just the first."""
    segs = set()
    outer = re.sub(r'\([^)]*\)', lambda m: '', traveler)
    paren = re.findall(r'\(([^)]*)\)', traveler)
    parts = [outer] + paren
    for p in parts:
        for piece in re.split(r',|/| called ', p):
            piece = piece.strip()
            if piece:
                segs.add(piece)
    return segs


def build_roster(rows):
    by_norm = {}
    segs_by_slug = {}
    for r in rows:
        segs = name_segments(r['traveler']) | {r['slug'].replace('_', ' ')}
        segs_by_slug[r['slug']] = segs
        for s in segs:
            by_norm[norm(s)] = r['slug']
    return by_norm, segs_by_slug


STOPWORDS = {'the', 'of', 'de', 'el', 'la', 'saint', 'st', 'san', 'don', 'von', 'van', 'bar', 'ben'}


def resolve(heading, by_norm, segs_by_slug):
    key = norm(heading)
    if key in by_norm:
        return by_norm[key]
    for tok in re.split(r',| and | with |/', heading):
        k = norm(tok)
        if k in by_norm:
            return by_norm[k]
    # substring match against every roster segment (either direction),
    # guarded by a minimum length so short tokens don't false-match
    if len(key) >= 6:
        for slug, segs in segs_by_slug.items():
            for s in segs:
                nk = norm(s)
                if len(nk) >= 6 and (nk in key or key in nk):
                    return slug
    # last resort: significant-word overlap (e.g. shared surname)
    words = {w for w in re.split(r'[^a-zA-Z]+', heading) if len(w) >= 4
             and w.lower() not in STOPWORDS}
    if words:
        for slug, segs in segs_by_slug.items():
            seg_words = {w for s in segs for w in re.split(r'[^a-zA-Z]+', s)
                         if len(w) >= 4 and w.lower() not in STOPWORDS}
            if words & seg_words:
                return slug
    return None


def connections_section(text):
    m = re.search(r'^## Atlas Connections\s*$', text, re.M)
    if not m:
        return None
    rest = text[m.end():]
    nxt = re.search(r'^## ', rest, re.M)
    return rest[:nxt.start()] if nxt else rest


def extract_one(slug, text, by_norm, segs_by_slug):
    section = connections_section(text)
    if section is None or not TAG_RE.search(section):
        return None  # not a tagged-format section -- leave for the Codex runner
    records = []
    headings = list(HEADING_RE.finditer(section))
    for i, h in enumerate(headings):
        start = h.end()
        end = headings[i + 1].start() if i + 1 < len(headings) else len(section)
        block = section[start:end]
        heading_text = h.group(1).strip()
        slug2 = resolve(heading_text, by_norm, segs_by_slug)
        for tm in TAG_RE.finditer(block):
            type_num, sign, subtype = tm.groups()
            bullet_start = block.rfind('\n', 0, tm.start()) + 1
            bullet_end = block.find('\n\n', tm.end())
            bullet_end = bullet_end if bullet_end != -1 else len(block)
            records.append({
                'counterpart_slug': slug2,
                'counterpart_name_raw': heading_text,
                'type': int(type_num),
                'sign': sign or '',
                'subtype': subtype,
                'text': block[bullet_start:bullet_end].strip(),
            })
    return records


def main():
    rows = list(csv.DictReader(open(f'{REPO}/catalog_subjects.csv')))
    by_norm, segs_by_slug = build_roster(rows)
    os.makedirs(OUT, exist_ok=True)
    tagged, not_tagged, no_records = 0, 0, 0
    unresolved = []
    for r in rows:
        slug = r['slug']
        path = f'{REPO}/dossiers/{slug}.dossier.md'
        if not os.path.exists(path):
            continue
        text = open(path, encoding='utf-8', errors='replace').read()
        records = extract_one(slug, text, by_norm, segs_by_slug)
        if records is None:
            not_tagged += 1
            continue
        tagged += 1
        if not records:
            no_records += 1
        for rec in records:
            if rec['counterpart_slug'] is None:
                unresolved.append((slug, rec['counterpart_name_raw']))
        json.dump(records, open(f'{OUT}/{slug}.json', 'w'), indent=1, ensure_ascii=False)
    print(f'tagged sections parsed: {tagged}')
    print(f'  of which had zero records: {no_records}')
    print(f'not-yet-tagged (leave for Codex extraction): {not_tagged}')
    print(f'unresolved counterpart headings: {len(unresolved)}')
    for s, h in unresolved[:30]:
        print(f'  {s}: "{h}"')


if __name__ == '__main__':
    main()
