#!/usr/bin/env python3
"""bundle_sale.py — bring the On Custody verified-key sale into the tracked corpus.

The sale was inscribed from El Golem's seller address, which is not one of the
nine addresses `update_quipu_data.py` walks, so none of it was ever catalogued:
not the box, not the keydrop that publishes its key, not the bond or the claim.
This script fetches exactly that set and writes it into the same three places
the catalogued quipu live in, so the whole swap can be opened with no node:

    data/bodies/<root>.bin       assembled header+body blob, one per quipu
    data/cache/rawtx.jsonl       the lineage transactions, cache record form
    data/thread/<txid>.hex       the same transactions verbatim, and tracked
    data/quipu_data.csv          one catalog row per quipu

The verbatim hex is there because the cache record keeps no scripts, and two
of the sale's facts live in scripts: the seller's identity pubkey sits in the
box root's scriptSig, and session_priv sits revealed in the claim's.

Two sources, either of which is enough:

    --fork  drdoeg@192.168.1.231   a quipu-fork node, over ssh, for `quipuscan`
                                   (the assembled blobs come from here)
    --rpc   127.0.0.1:22555        any txindex node, for the raw transactions

Run it once from a machine that can reach both. After that the corpus carries
the sale and `open_from_chain.py` needs nothing but the repo.

    .venv/bin/python working/sale/bundle_sale.py
    .venv/bin/python working/sale/bundle_sale.py --dry-run
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "canonical"))

DATA = os.path.join(REPO, "data")
BODIES = os.path.join(DATA, "bodies")
CACHE = os.path.join(DATA, "cache", "rawtx.jsonl")
THREAD = os.path.join(DATA, "thread")
CATALOG = os.path.join(DATA, "quipu_data.csv")

SELLER = "DA4zu5QTQXvwLg58KTZEgiShyBN9gxc5ka"

BOX = "f74a53b76bb2b6dfc9e26e7218525cfcb1f440cd3becbf4e38b31fbaf7b71d6d"
DROP = "333960698b0539a8438739e73e23d90425d395c7edb43be6018c0e7a3226361f"
BOND = "51839f00701d7328e9d1deb41090ac339c3b793e893ab77a2ae68f6453a29173"
CLAIM = "dd57dbc9bcb1d3cb17a1d48ee3ae28e238d46726ec16a711d75ca1be4c75d882"

# The bundle has to contain the whole thread from the box to the keydrop, or a
# reader walking it forward hits a gap and mistakes a strand for a plain output.
# Forward walking needs a spend index; walking backward needs only txindex, and
# the keydrop root is downstream of everything, so the closure is collected by
# walking back from it and stopping at the box. Bond and claim are anchors: they
# descend from the buyer's funds, not from the textile, so they are named rather
# than discovered.
ANCHORS = [BOX, BOND, CLAIM]


def collect_thread(node, start, stop_at, cap=200):
    """Every transaction between `start` and `stop_at`, walking inputs backward."""
    seen, order, frontier = {stop_at}, [], [start]
    while frontier and len(order) < cap:
        txid = frontier.pop(0)
        if txid in seen:
            continue
        seen.add(txid)
        order.append(txid)
        raw = node("getrawtransaction", [txid, 1])
        for v in raw.get("vin", []):
            if "txid" in v and v["txid"] not in seen:
                frontier.append(v["txid"])
    if len(order) >= cap:
        raise SystemExit(f"thread from {start[:12]} exceeded {cap} transactions")
    return order


def rpc(url, user, password, method, params):
    req = json.dumps({"jsonrpc": "1.0", "id": "b", "method": method,
                      "params": params}).encode()
    r = urllib.request.Request(url, data=req)
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    r.add_header("Authorization", "Basic " + token)
    r.add_header("Content-Type", "text/plain")
    out = json.loads(urllib.request.urlopen(r, timeout=30).read())
    if out.get("error"):
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]


def quipuscan(host, rpcport, address):
    """Assembled blobs for every quipu paying `address`, via a fork node."""
    cmd = ["ssh", "-o", "BatchMode=yes", host,
           f"dogecoin-cli -rpcport={rpcport} quipuscan {address}"]
    return json.loads(subprocess.check_output(cmd, timeout=120).decode())


def extract_op_return(vout):
    asm = vout.get("scriptPubKey", {}).get("asm", "")
    if not asm.startswith("OP_RETURN"):
        return None
    parts = asm.split()
    return parts[1] if len(parts) > 1 else ""


def cache_record(raw, height):
    """The exact shape update_quipu_data.py appends to rawtx.jsonl."""
    op_ret = None
    for v in raw.get("vout", []):
        d = extract_op_return(v)
        if d:
            op_ret = d
            break
    return {
        "txid": raw["txid"], "blockhash": raw.get("blockhash"),
        "blockheight": height, "blocktime": raw.get("blocktime"),
        "inputs": [f"{v['txid']}:{v['vout']}" for v in raw.get("vin", []) if "txid" in v],
        "values": [v["value"] for v in raw.get("vout", [])],
        "num_inputs": len(raw.get("vin", [])), "num_outputs": len(raw.get("vout", [])),
        "op_return": op_ret,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fork", default="drdoeg@192.168.1.231",
                    help="ssh target of a quipu-fork node (blobs)")
    ap.add_argument("--fork-rpcport", default="22600")
    ap.add_argument("--rpc", default="http://127.0.0.1:22555/",
                    help="txindex node RPC url (raw transactions)")
    ap.add_argument("--rpcuser", default=os.environ.get("RPC_USER", "drdoeg"))
    ap.add_argument("--rpcpassword", default=os.environ.get("RPC_PASSWORD", "password"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    node = lambda m, p: rpc(args.rpc, args.rpcuser, args.rpcpassword, m, p)

    # --- blobs, from the fork node -----------------------------------------
    print(f"quipuscan {SELLER} via {args.fork}")
    found = {q["root"]: q for q in quipuscan(args.fork, args.fork_rpcport, SELLER)}
    for want in (BOX, DROP):
        if want not in found:
            raise SystemExit(f"fork node did not return {want[:12]}")
    blobs = {}
    for root, q in found.items():
        blobs[root] = bytes.fromhex(q["header"]["raw"]) + bytes.fromhex(q["body"])
        print(f"  {root[:12]}  sub 0x{blobs[root][6]:02x}  {len(blobs[root])} B")

    # --- lineage transactions, from any txindex node ------------------------
    print(f"collecting the thread {DROP[:12]} back to {BOX[:12]}")
    lineage = ANCHORS + collect_thread(node, DROP, BOX)
    print(f"fetching {len(lineage)} lineage transactions")
    have = set()
    if os.path.exists(CACHE):
        with open(CACHE) as f:
            for line in f:
                try:
                    have.add(json.loads(line)["txid"])
                except (json.JSONDecodeError, KeyError):
                    continue
    records, heights, rawhex = [], {}, {}
    for txid in lineage:
        raw = node("getrawtransaction", [txid, 1])
        bh = raw.get("blockhash")
        if bh not in heights:
            heights[bh] = node("getblock", [bh])["height"]
        rec = cache_record(raw, heights[bh])
        records.append(rec)
        rawhex[txid] = raw["hex"]
        mark = "cached" if txid in have else "new"
        print(f"  {txid[:12]}  block {rec['blockheight']}  {mark}")

    if args.dry_run:
        print("dry run, nothing written")
        return

    # --- write --------------------------------------------------------------
    os.makedirs(BODIES, exist_ok=True)
    for root, blob in blobs.items():
        path = os.path.join(BODIES, f"{root}.bin")
        with open(path, "wb") as f:
            f.write(blob)
        print(f"wrote data/bodies/{root[:12]}….bin  {len(blob)} B")

    os.makedirs(THREAD, exist_ok=True)
    for txid, hexstr in rawhex.items():
        with open(os.path.join(THREAD, f"{txid}.hex"), "w") as f:
            f.write(hexstr)
    print(f"wrote {len(rawhex)} transactions to data/thread/")

    fresh = [r for r in records if r["txid"] not in have]
    if fresh:
        with open(CACHE, "a") as f:
            for r in fresh:
                f.write(json.dumps(r) + "\n")
        print(f"appended {len(fresh)} records to data/cache/rawtx.jsonl")

    write_catalog_rows(records, blobs)


def write_catalog_rows(records, blobs):
    """One row per quipu, in the existing column order, appended if absent."""
    import csv

    import colegio_pipeline as CP
    from canonical import encrypted as E
    from tone import TONES

    by_txid = {r["txid"]: r for r in records}
    with open(CATALOG) as f:
        rows = list(csv.reader(f))
    header, existing = rows[0], {r[0] for r in rows[1:]}

    new = []
    for root in (BOX, DROP):
        if root in existing:
            print(f"catalog already has {root[:12]}, left alone")
            continue
        blob = blobs[root]
        hdr, body = CP.split_blob(blob)
        res = E.read_encrypted_quipu(hdr, body)
        rec = by_txid[root]
        sub = blob[6]
        dims = {"sub_family": f"0x{sub:02x}", "variant": blob[7]}
        if res.get("session_pub"):
            dims["session_pub"] = res["session_pub"]
        if res.get("header_fields"):
            dims.update(res["header_fields"])
        new.append([
            root, "", SELLER, "golem",
            "0x0e", "encrypted",
            f"0x{blob[5]:02x}", TONES.get(blob[5], ""),
            res.get("title", ""),
            json.dumps(dims),
            len(blob), rec["blockheight"], rec["blocktime"],
            f"bodies/{root}.bin",
            "verified-key sale, see docs/quipu-syntax/verified-key-sale.md",
            "canonical_v1",
        ])
    if not new:
        return
    with open(CATALOG, "a", newline="") as f:
        w = csv.writer(f)
        for row in new:
            w.writerow(row)
    print(f"appended {len(new)} catalog rows to data/quipu_data.csv")


if __name__ == "__main__":
    main()
