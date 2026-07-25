#!/usr/bin/env python3
"""build_network_quipu.py — turn a *.network.json dataset into a 0xce/0x05
network quipu, and prove it round-trips through the codec.

    python3 build_network_quipu.py templar.network.json [--verbose]

The dataset schema is the codec's own vocabulary plus provenance, with ONE
deliberate difference: edges name their endpoints, they do not index them.

    {"from": "London, New Temple", "to": "Paris, Maison du Temple", ...}

Indices are what network.py wants at build time, but they are the wrong thing
to hand-edit or to have a research fleet emit: insert a node at position 3 and
every later edge silently rewires to the wrong pair, with no error and no way
to see it in a diff. Names fail loudly instead, right here, naming the edge.

Read-only with respect to the dataset. Writes nothing unless --out is given.
"""
import argparse
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, ROOT)

import network as netcodec  # noqa: E402


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def to_codec(ds):
    """dataset -> (title, nodes, edges) in the shape build_network wants."""
    nodes, index, dupes = [], {}, []
    for n in ds["nodes"]:
        name = n["name"]
        if name in index:
            dupes.append(name)
        index[name] = len(nodes)
        node = {
            "name": name,
            "ntype": n.get("ntype", "place"),
            "lat": n.get("lat"),
            "lng": n.get("lng"),
            "born": n.get("born"),
            "died": n.get("died"),
        }
        # optional text annotations the codec carries in the more-block
        for k in ("note", "region", "modern"):
            if n.get(k):
                node[k] = n[k]
        nodes.append(node)
    if dupes:
        raise SystemExit("duplicate node names (edges could not be resolved): %s"
                         % ", ".join(sorted(set(dupes))))

    edges, missing = [], []
    for e in ds["edges"]:
        a, b = e["from"], e["to"]
        if a not in index:
            missing.append((a, e))
        if b not in index:
            missing.append((b, e))
        if a in index and b in index:
            flags = netcodec.FLAG_DIRECTED if e.get("directed") else 0
            w = e.get("weight")
            edges.append((index[a], index[b], e.get("etype", "road"), flags,
                          float(w) if w is not None else None))
    if missing:
        lines = ["edge endpoint not found among nodes:"]
        for name, e in missing:
            lines.append("  %r  (in edge %s -> %s)" % (name, e["from"], e["to"]))
        raise SystemExit("\n".join(lines))

    return ds.get("network") or ds["title"], nodes, edges


def approx(a, b, tol=1e-4):
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, float) and math.isnan(a):
        return isinstance(b, float) and math.isnan(b)
    return abs(a - b) <= tol


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--out", help="write the assembled blob here (default: dry run)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    ds = load(args.dataset)
    title, nodes, edges = to_codec(ds)

    hdr, body = netcodec.build_network(title, nodes, edges)
    blob = hdr + body
    got = netcodec.read_network(blob)

    # ---- round-trip gate: what went in must come back out -------------------
    fails = []
    if got["title"] != title:
        fails.append("title: %r != %r" % (got["title"], title))
    if len(got["nodes"]) != len(nodes):
        fails.append("node count: %d != %d" % (len(got["nodes"]), len(nodes)))
    for src, out in zip(nodes, got["nodes"]):
        if src["name"] != out["name"]:
            fails.append("name: %r != %r" % (out["name"], src["name"]))
            continue
        for k in ("lat", "lng", "born", "died"):
            if not approx(src.get(k), out.get(k)):
                fails.append("%s.%s: %r != %r" % (src["name"], k, out.get(k), src.get(k)))
        # read_network returns the RAW BYTE; the dataset writes the name. Compare
        # through the codec's own map rather than assuming either representation.
        want = src.get("ntype", "place")
        want_b = netcodec.NTYPE_NAME_TO_BYTE[want] if isinstance(want, str) else want
        got_b = out.get("ntype")
        if isinstance(got_b, str):
            got_b = netcodec.NTYPE_NAME_TO_BYTE.get(got_b)
        if got_b != want_b:
            fails.append("%s.ntype: %r != %r" % (src["name"], out.get("ntype"), want))
    if len(got["edges"]) != len(edges):
        fails.append("edge count: %d != %d" % (len(got["edges"]), len(edges)))

    abstract = [n["name"] for n in got["nodes"] if n.get("lat") is None]
    def nname(v):
        return v if isinstance(v, str) else netcodec.NTYPE_BYTE_TO_NAME.get(v, "?%s" % v)

    def ename(v):
        return v if isinstance(v, str) else netcodec.ETYPE_BYTE_TO_NAME.get(v, "?%s" % v)

    kinds = {}
    for n in got["nodes"]:
        k = nname(n.get("ntype"))
        kinds[k] = kinds.get(k, 0) + 1
    etypes = {}
    for e in got["edges"]:
        et = ename(e.get("etype") if isinstance(e, dict) else e[2])
        etypes[et] = etypes.get(et, 0) + 1

    print("%s" % title)
    print("  %d nodes  %d edges  %d bytes" % (len(nodes), len(edges), len(blob)))
    print("  ntypes: %s" % ", ".join("%s=%d" % kv for kv in sorted(kinds.items())))
    print("  etypes: %s" % ", ".join("%s=%d" % (k, v) for k, v in sorted(etypes.items())))
    print("  abstract (no fixed locus): %s" % (", ".join(abstract) or "none"))
    if args.verbose:
        for n in got["nodes"]:
            loc = "abstract" if n.get("lat") is None else "%.4f,%.4f" % (n["lat"], n["lng"])
            print("    %-28s %-9s %-22s %s-%s"
                  % (n["name"][:28], nname(n.get("ntype")), loc,
                     n.get("born"), n.get("died")))

    if fails:
        print("\nROUND-TRIP FAILED:")
        for f in fails:
            print("  " + f)
        return 1
    print("  round-trip: OK (build -> read is faithful)")

    if args.out:
        with open(args.out, "wb") as f:
            f.write(blob)
        print("  wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
