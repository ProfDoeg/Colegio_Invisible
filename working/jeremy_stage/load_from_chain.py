#!/usr/bin/env python3
"""Read the Jeremy dancer back OFF the chain and verify it round-trips.

Jeremy was split MODULO (strand i = knots[i::N]), which the canonical
read_quipu (contiguous strand0+strand1+…) cannot reassemble. So this walks
the diamond directly and interleaves correctly:

  · from the join's 255 inputs (each = a strand terminus), walk BACKWARD via
    vin[0] to the root — pure getrawtransaction, no wallet spender index
    (which is capped at 10k txs and would miss Jeremy's 22k).
  · concatenate each strand's OP_RETURNs (reversed to forward order) -> the
    strand payload, re-chunk at 80 bytes -> the original knots.
  · reassemble:  blob_knot[i + m*N] = strand_knots[i][m].
  · sha256 vs the local jeremy_perf.bin, then decode with read_dancer.

Writes the verified chain blob to data/bodies/<root>.bin and a player-ready
data/bodies/<root>.dancer.json (footage frames + graph + controllers).

  .venv/bin/python working/jeremy_stage/load_from_chain.py
"""
import os, sys, json, hashlib, time, base64
from concurrent.futures import ThreadPoolExecutor, as_completed

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO); sys.path.insert(0, os.path.join(REPO, "canonical"))
from colegio_tools import rpc_request, extract_op_return
import dancer as D

ART  = os.path.join(os.path.dirname(__file__), "artifacts")
ROOT = open(os.path.join(ART, "root.txid")).read().strip()
JOIN = open(os.path.join(ART, "join.txid")).read().strip()
LOCAL = os.path.join(os.path.dirname(__file__), "jeremy_perf.bin")
BODIES = os.path.join(REPO, "data", "bodies")
WORKERS = int(os.environ.get("WORKERS", "24"))
KNOT = 80

log = lambda m: print("[%s] %s" % (time.strftime("%H:%M:%S"), m), flush=True)


def op_return_hex(txid, _cache={}):
    if txid not in _cache:
        raw = rpc_request("getrawtransaction", [txid, 1])
        op = None
        for v in raw.get("vout", []):
            d = extract_op_return(v)
            if d:
                op = d; break
        _cache[txid] = (op, raw["vin"][0]["txid"] if raw.get("vin") else None)
    return _cache[txid]


def walk_strand(terminus_txid):
    """Backward-walk one strand from its terminus to the root; return its
    OP_RETURN payload bytes in FORWARD (root->terminus) order."""
    hexes = []
    cur = terminus_txid
    while cur is not None and cur != ROOT:
        op, prev = op_return_hex(cur)
        if op:
            hexes.append(op)
        cur = prev
    hexes.reverse()                       # was terminus->first; make first->terminus
    return bytes.fromhex("".join(hexes))


def main():
    t0 = time.time()
    log("reading join %s …" % JOIN[:16])
    join = rpc_request("getrawtransaction", [JOIN, 1])
    termini = [vin["txid"] for vin in join["vin"]]
    N = len(termini)
    log("join has %d inputs (strand termini) · walking back to root %s…" % (N, ROOT[:16]))

    strand_payloads = [None] * N
    done = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(walk_strand, t): k for k, t in enumerate(termini)}
        for fut in as_completed(futs):
            k = futs[fut]
            strand_payloads[k] = fut.result()
            done += 1
            if done % 25 == 0 or done == N:
                log("  walked %d / %d strands" % (done, N))

    # re-chunk each strand payload into the original 80-byte knots
    strand_knots = [[p[j:j+KNOT] for j in range(0, len(p), KNOT)] for p in strand_payloads]
    K = sum(len(s) for s in strand_knots)
    result = [None] * K
    for i in range(N):
        for m, knot in enumerate(strand_knots[i]):
            result[i + m * N] = knot
    if any(r is None for r in result):
        log("!!! gap in reassembly — %d missing knots" % sum(r is None for r in result)); return
    blob = b"".join(result)
    log("reassembled %d knots -> %d bytes (modulo-interleaved)" % (K, len(blob)))

    # verify against local
    chain_sha = hashlib.sha256(blob).hexdigest()
    if os.path.exists(LOCAL):
        local = open(LOCAL, "rb").read()
        local_sha = hashlib.sha256(local).hexdigest()
        match = chain_sha == local_sha
        log("local  jeremy_perf.bin : %d B  sha256 %s…" % (len(local), local_sha[:16]))
        log("chain  reassembled     : %d B  sha256 %s…" % (len(blob), chain_sha[:16]))
        log("BYTE-FOR-BYTE MATCH ✓" if match else "!!! MISMATCH — chain != local")
        # show that the naive contiguous reader would have scrambled it
        contig = b"".join(b"".join(s) for s in strand_knots)
        log("contiguous (read_quipu style) sha256 %s… -> %s"
            % (hashlib.sha256(contig).hexdigest()[:16],
               "same (would also work)" if contig == local else "DIFFERENT (confirms modulo needed)"))
    else:
        log("(no local jeremy_perf.bin to compare)")

    # cache the verified chain blob where the dataset expects it
    os.makedirs(BODIES, exist_ok=True)
    open(os.path.join(BODIES, ROOT + ".bin"), "wb").write(blob)
    log("wrote data/bodies/%s.bin" % ROOT)

    # decode
    tlen = blob[7]
    header, body = blob[:8 + tlen], blob[8 + tlen:]
    p = D.read_dancer(header, body)
    g = p["graph"]; foot = g["footage"][0][1]
    log("decoded 0x%02x dancer '%s' · variant=%s · tone=0x%02x"
        % (blob[4], p["title"], p["variant_name"], p["tone"]))
    log("  footage: %d frames · %dx%d · %d colors · %d fps · keyint %d"
        % (len(foot["frames"]), foot["nw"], foot["nh"], len(foot["palette"]),
           foot["fps"], foot["keyint"]))
    log("  graph:   %d nodes · %d labels · start %d"
        % (len(g["nodes"]), len(g["labels"]), g["start"]))
    log("  controllers: %d (default %d)" % (len(p["controllers"]), p["default"]))
    for ci, c in enumerate(p["controllers"]):
        names = [m["name"] for m in c["methods"]]
        gens = [str(m.get("generator")) for m in c["methods"] if m["name"] == "quantum"]
        log("    ctrl %d: methods=%s%s · %d bindings"
            % (ci, names, (" quantum-gens=" + ",".join(gens)) if gens else "", len(c["bindings"])))

    # emit a player-ready json (frames as tight sprites + palette + graph)
    def b64(bs): return base64.b64encode(bytes(bs)).decode()
    frames_out = []
    for f in foot["frames"]:
        frames_out.append({"x": f["x"], "y": f["y"], "w": f["w"], "h": f["h"],
                           "cx": round(f["cx"], 4), "cy": round(f["cy"], 4),
                           "facing": f["facing"],
                           "mask": b64(bytes(f["mask"])),         # 1 byte per pixel (0/1)
                           "idx": b64(bytes(f["idx"]))})          # 1 byte per opaque pixel
    out = {"title": p["title"], "nw": foot["nw"], "nh": foot["nh"], "fps": foot["fps"],
           "palette": foot["palette"], "frames": frames_out,
           "graph": {"start": g["start"],
                     "nodes": [{"ord": n["ord"], "sym": n["sym"],
                                "edges": [{"dst": e["dst"], "time": e["time"],
                                           "space": e["space"]} for e in n["edges"]]}
                               for n in g["nodes"]],
                     "labels": g["labels"]},
           "default_method": p["controllers"][p["default"]].get("default_method", 0)}
    jpath = os.path.join(BODIES, ROOT + ".dancer.json")
    json.dump(out, open(jpath, "w"))
    log("wrote %s (%.1f MB) — player-ready" % (jpath, os.path.getsize(jpath) / 1e6))
    log("done in %.0fs" % (time.time() - t0))


if __name__ == "__main__":
    main()
