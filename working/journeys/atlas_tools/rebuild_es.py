"""Rebuild es/<slug>.journey.json so it mirrors the merged English file stop for stop:
old stops come verbatim from the old Spanish edition (matched by position with the old
English), new stops come from the writer's Spanish output (matched by lat/lng/date)."""
import json, subprocess, sys
slug = sys.argv[1]
REPO = "/home/drdoeg/taller/Colegio_Invisible"; J = f"{REPO}/working/journeys"

def head(rel):
    return json.loads(subprocess.run(["git", "-C", REPO, "show", f"HEAD:{rel}"], capture_output=True, text=True, check=True).stdout)

def stops(j): return [s for seg in j["segments"] for s in seg["stops"]]
def key(s): return (s["lat"], s["lng"], s["date"])

old_en = head(f"working/journeys/{slug}.journey.json"); old_es = head(f"working/journeys/es/{slug}.journey.json")
new_en = json.load(open(f"{J}/{slug}.journey.json", encoding="utf-8"))
cur_es = json.load(open(f"{J}/es/{slug}.journey.json", encoding="utf-8"))
oe, os_ = stops(old_en), stops(old_es)
assert len(oe) == len(os_), "old editions differ in length"
old_es_by_en_name = {e["name"]: s for e, s in zip(oe, os_)}
old_es_campas = {s["campa"] for s in os_}
pool = [s for s in stops(cur_es) if s["campa"] not in old_es_campas]   # the writer's genuinely new Spanish stops
used = set()

def pick(e):
    for i, s in enumerate(pool):
        if i in used: continue
        if key(s) == key(e):
            used.add(i); return s
    raise SystemExit(f"no Spanish stop for new English stop {e['name']!r} {key(e)}")

old_seg_names = {e["name"]: s["name"] for e, s in zip(old_en["segments"], old_es["segments"])}
out_segs = []
for gi, seg in enumerate(new_en["segments"]):
    es_name = old_seg_names.get(seg["name"]) or (cur_es["segments"][gi]["name"] if gi < len(cur_es["segments"]) else seg["name"])
    es_stops = []
    for e in seg["stops"]:
        if e["name"] in old_es_by_en_name: es_stops.append(old_es_by_en_name[e["name"]])
        else: es_stops.append(pick(e))
    out_segs.append({**({k: v for k, v in (old_es["segments"][gi].items() if gi < len(old_es["segments"]) else []) if k not in ("name", "stops")}), "name": es_name, "stops": es_stops})
out = {k: v for k, v in old_es.items() if k != "segments"}
out["segments"] = out_segs
se, ss = stops(new_en), stops(out)
assert [key(s) for s in se] == [key(s) for s in ss], "alignment failed"
open(f"{J}/es/{slug}.journey.json", "w", encoding="utf-8").write(json.dumps(out, ensure_ascii=False, indent=1) + "\n")
print(f"es rebuilt: {len(ss)} stops, {len(used)} new from the writer, {len(ss) - len(used)} old verbatim; unused new: {len(pool) - len(used)}")
for s in ss:
    n = len(s["campa"])
    if not 450 <= n <= 760: print("  campa length", n, s["name"])
