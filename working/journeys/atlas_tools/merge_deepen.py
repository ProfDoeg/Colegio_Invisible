"""After a deepening run that ADDS stops between existing ones: every old stop must
survive verbatim (matched by name; restored from git if altered or dropped), new
stops are kept, both editions must stay aligned, the report must keep its old text.
Usage: python3 merge_deepen.py <slug>"""
import json, re, subprocess, sys
slug = sys.argv[1]
REPO = "/home/drdoeg/taller/Colegio_Invisible"; J = f"{REPO}/working/journeys"
BAD = "—“”‘’"

def head(rel):
    return subprocess.run(["git", "-C", REPO, "show", f"HEAD:{rel}"], capture_output=True, text=True, check=True).stdout

def stops(j): return [s for seg in j["segments"] for s in seg["stops"]]

report = []; counts = {}
for ed in ("", "es/"):
    rel = f"working/journeys/{ed}{slug}.journey.json"
    old = json.loads(head(rel)); new = json.load(open(f"{J}/{ed}{slug}.journey.json", encoding="utf-8"))
    old_by_name = {s["name"]: s for s in stops(old)}
    restored = 0; missing = []
    for seg in new["segments"]:
        for i, s in enumerate(seg["stops"]):
            o = old_by_name.get(s["name"])
            if o is not None and s != o:
                seg["stops"][i] = o; restored += 1
    present = {s["name"] for s in stops(new)}
    for name, o in old_by_name.items():
        if name not in present:
            # put it back in the segment whose stops bracket its date, in date order
            missing.append(name)
            target = new["segments"][-1]
            for seg in new["segments"]:
                ds = [x["date"] for x in seg["stops"]]
                if ds and ds[0] <= o["date"] <= ds[-1]: target = seg; break
            k = next((i for i, x in enumerate(target["stops"]) if x["date"] > o["date"]), len(target["stops"]))
            target["stops"].insert(k, o)
    for key in ("traveler", "title", "years", "register", "calendar"):
        if key in old and new.get(key) != old[key]:
            new[key] = old[key]; restored += 1
    added = [s for s in stops(new) if s["name"] not in old_by_name]
    for s in added:
        lo, hi = (450, 650) if ed == "" else (450, 760)
        n = len(s.get("campa", ""))
        if not lo <= n <= hi: report.append(f"{ed}{slug}: campa length {n} at '{s['name']}'")
        if any(c in s.get("campa", "") + s.get("name", "") for c in BAD): report.append(f"{ed}{slug}: bad chars at '{s['name']}'")
    counts[ed] = (len(stops(old)), len(stops(new)), len(added), restored, missing)
    text = json.dumps(new, ensure_ascii=False, indent=2 if ed == "" else 1) + "\n"
    if ed == "":   # the English files keep string arrays on one line
        STR = r'"(?:[^"\\]|\\.)*"'
        text = re.sub(r'\[\n\s+(' + STR + r')((?:,\n\s+' + STR + r')*)\n\s+\]',
                      lambda m: "[" + re.sub(r',\n\s+', ', ', m.group(1) + m.group(2)) + "]", text)
    open(f"{J}/{ed}{slug}.journey.json", "w", encoding="utf-8").write(text)

en = json.load(open(f"{J}/{slug}.journey.json")); es = json.load(open(f"{J}/es/{slug}.journey.json"))
se, ss = stops(en), stops(es)
if [(s["lat"], s["lng"], s["date"]) for s in se] != [(s["lat"], s["lng"], s["date"]) for s in ss]:
    report.append("EN/ES misaligned (lat/lng/date or count)")
dates = [s["date"] for s in se]
dec = [(a, b) for a, b in zip(dates, dates[1:]) if b < a]
if dec: report.append(f"dates decrease at {dec[:3]}")

old_rep = head(f"working/journeys/{slug}.report.md")
new_rep = open(f"{J}/{slug}.report.md", encoding="utf-8").read()
probe = old_rep.strip().splitlines()[-1][:80] if old_rep.strip() else ""
if probe and probe not in new_rep:
    open(f"{J}/{slug}.report.md", "w", encoding="utf-8").write(old_rep.rstrip() + "\n\n---\n\n## Deepening run, 2026-09-11\n\n" + new_rep)
    report.append("report: old text was not preserved; concatenated old + new")
for ed, (o, n, a, r, m) in counts.items():
    print(f"{ed or 'en/'}: {o} -> {n} stops, {a} added, {r} restored verbatim, {len(m)} reinserted {m}")
print("issues:", len(report))
for r in report: print("  ", r)
