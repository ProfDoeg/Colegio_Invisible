#!/usr/bin/env python3
"""Turn El Gólem's journey retrocausal: the segments and the stops inside them are
written in reverse order, so the file reads from the book on the chain in 2026
back to the word in the Psalter, and the file carries "retrocausal": true so the
renderers know to keep that order and to date the subject by its LAST stop.

Per Anthony, 2026-09-09: "Its timeline can be in reverse. That will make it the
last subject since it's 'born' in 2026. That way the first character will be Noah
and the last character Golem."

    python3 atlas_tools/retrocausal_golem.py          # rewrites EN and ES in place, idempotent
"""
import json, os
D = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
for path in (os.path.join(D, "el_golem.journey.json"), os.path.join(D, "es", "el_golem.journey.json")):
    j = json.load(open(path, encoding="utf-8"))
    if j.get("retrocausal"):
        print("already retrocausal:", path); continue
    segs = list(reversed(j["segments"]))
    for s in segs:
        s["stops"] = list(reversed(s["stops"]))
    j["segments"] = segs
    j["retrocausal"] = True
    j["timeline_note"] = ("Retrocausal: this journey is told from its last body backward to its first word, "
                          "so the subject is dated by its final stop (2026) and stands last in the atlas.")
    first, last = segs[0]["stops"][0]["date"], segs[-1]["stops"][-1]["date"]
    indent = 1 if "/es/" in path else 2
    with open(path, "w", encoding="utf-8") as f:
        json.dump(j, f, ensure_ascii=False, indent=indent); f.write("\n")
    print(f"reversed {path}: now runs {first} -> {last}")
