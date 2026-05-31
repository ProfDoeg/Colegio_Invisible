#!/usr/bin/env python3
"""Trace dataflow (patch cords) in a Max .maxpat, so the actual algorithm can
be reconstructed rather than guessed. Recursively indexes every patcher, then
for a query prints each matching object's upstream (what feeds each inlet) and
downstream (what each outlet drives).

Usage: trace_patch.py <file.maxpat> <query> [<query> ...]
"""
import json
import sys


def collect(patcher, path, store):
    """store: list of dicts {path, idmap, lines}."""
    idmap = {}
    for b in patcher.get("boxes", []):
        bb = b.get("box", {})
        bid = bb.get("id")
        txt = bb.get("text", "") or ("[%s]" % bb.get("maxclass", "?"))
        idmap[bid] = {"text": txt, "cls": bb.get("maxclass", "")}
        if "patcher" in bb:
            sub = bb.get("text", "") or bb.get("varname", "sub")
            collect(bb["patcher"], path + "/" + sub, store)
    lines = []
    for l in patcher.get("lines", []):
        pl = l.get("patchline", {})
        s = pl.get("source", [None, 0]); d = pl.get("destination", [None, 0])
        lines.append((s[0], s[1], d[0], d[1]))
    store.append({"path": path, "idmap": idmap, "lines": lines})


def show(store, query):
    dump = query.startswith("@")          # @/p name  -> dump whole patcher
    q = query[1:].lower() if dump else query.lower()
    for P in store:
        idmap, lines = P["idmap"], P["lines"]
        if dump and q not in P["path"].lower():
            continue
        for bid, info in idmap.items():
            if not dump and q not in info["text"].lower():
                continue
            ups = []   # (their_outlet, my_inlet, text)
            downs = []
            for (s, so, d, di) in lines:
                if d == bid and s in idmap:
                    ups.append((di, idmap[s]["text"], so))
                if s == bid and d in idmap:
                    downs.append((so, idmap[d]["text"], di))
            ups.sort(); downs.sort()
            print("\n[%s]  «%s»" % (P["path"] or "(root)", info["text"][:70]))
            for di, t, so in ups:
                print("    in%s  <-- out%s %s" % (di, so, t[:64]))
            for so, t, di in downs:
                print("    out%s --> in%s %s" % (so, di, t[:64]))


def main():
    d = json.load(open(sys.argv[1]))["patcher"]
    store = []
    collect(d, "", store)
    npatch = len(store)
    nobj = sum(len(P["idmap"]) for P in store)
    print("patchers %d   objects %d" % (npatch, nobj))
    for q in sys.argv[2:]:
        print("\n==================== query: %r ====================" % q)
        show(store, q)


if __name__ == "__main__":
    main()
