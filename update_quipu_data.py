#!/usr/bin/env python3
"""Refresh the Quipu dataset from chain — the runnable form of NB 60.

Re-walks the 9 watched addresses, parses every canonical inscription's
structural header, and rewrites the local dataset:

    data/quipu_data.csv          one row per inscription
    data/bodies/{root_txid}.bin  raw header+body bytes per inscription
    data/tx_inputs.csv           slim (txid, inputs) table
    data/quipu_edges.csv         funding / keydrop / citation edges

Run after new inscriptions land on chain:

    .venv/bin/python update_quipu_data.py

(No prior-dataset archiving — this overwrites quipu_data.csv directly; it
keeps only the cheap body/CSV coherence check, which needs no archive.)

Confirmed raw transactions are cached in data/cache/rawtx.jsonl as they
are fetched, so a killed run resumes its fetch phase almost for free.
Unconfirmed (mempool) txs are never cached. Delete the cache file to
force a cold refetch (e.g. after a deep reorg, which at our depths is
theoretical).
"""
import os
import sys
import json
import re
import time
import pandas as pd
from collections import Counter

REPO = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "canonical"))

from colegio_tools import (rpc_request, extract_op_return, identify_quipus,
                           read_quipu, outputs_walk_index)
from tone import TONES as TONE_NAMES, VALID_TONES

DATA_DIR = os.path.join(REPO, "data")
BODIES_DIR = os.path.join(DATA_DIR, "bodies")
CACHE_DIR = os.path.join(DATA_DIR, "cache")
RAWTX_CACHE = os.path.join(CACHE_DIR, "rawtx.jsonl")

_T0 = time.time()


def log(*args):
    """Timestamped, flushed — visible the moment it happens, even through
    a pipe. The killed 2026-06-10 run taught us why."""
    print(f"[{time.time() - _T0:7.1f}s]", *args, flush=True)

ADDRESSES = {
    "9xth7DcLGb1nACScMBeSfDCfghhLKF7yqs": "bordado",
    "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX": "apocrypha",
    "A7pfCe2Cw9JD2C4vEZbpDmUZJy7B2TaefV": "ha",
    "AD28bxzxyrd3a4Qgad2VNQ2eN5Leg8ozuw": "ca",
    "A3ShjwjsAE4ysM66EZJM3A28tPnL2jNDgC": "multiman",
    "A3ABo52FjMJ57KSjbKyfe9aiKkH2jntXHY": "test_multisig3",
    "DPy94XwsHvFpXfA2C6PjERknyNjQYacufZ": "test1",
    "D6hcCyELYoMgPiMUfjGgBSHNSdZWrULupx": "test2",
    "DPJAJuNW9ajjnEUy9RhYDjoMB9aFmkLdDb": "test3",
}
ADDRESS_LIST = list(ADDRESSES.keys())

TYPE_NAMES = {
    0x00: "text", 0x01: "essay", 0x03: "image", 0x07: "audio",
    0x09: "book",
    0x0e: "encrypted", 0x1d: "identity",
    0x3d: "scene",
    0x5c: "latex",
    0xab: "binding", 0xcc: "cert",
    0xce: "celestial", 0xee: "estandarte",
}


# ---------- per-type structural header parsing ----------
def parse_dims(blob):
    """Return (dimensions_dict, title, header_length) for any v1 quipu."""
    if len(blob) < 6 or blob[:4] != b"\xc1\xdd\x00\x01":
        return {}, "", 0
    t = blob[4]

    def pipe_title(hdr_end):
        title = ""
        if hdr_end < len(blob) and blob[hdr_end:hdr_end + 1] == b"|":
            close = blob.find(b"|", hdr_end + 1)
            if close > 0:
                title = blob[hdr_end + 1:close].decode("utf-8", errors="replace")
                hdr_end = close + 1
        return title, hdr_end

    if t == 0x00:                                   # text
        return ({},) + pipe_title(6)
    if t == 0x01:                                   # essay
        return ({},) + pipe_title(6)
    if t == 0x5c:                                   # latex
        return ({},) + pipe_title(6)
    if t == 0x03:                                   # image
        if len(blob) < 12:
            return {}, "", 0
        color = blob[6]; W = (blob[7] << 8) | blob[8]; H = (blob[9] << 8) | blob[10]; bd = blob[11]
        dims = {"color": color, "W": W, "H": H, "bit_depth": bd}
        if color not in (0x00, 0x01):
            return dims, "", 12
        ch = 1 if color == 0 else 3
        expected_body = (W * H * ch * bd + 7) // 8
        body_offset = len(blob) - expected_body
        if body_offset < 12:
            return dims, "", 12
        text = blob[12:body_offset].decode("utf-8", errors="replace")
        if "|" in text:
            fields = [p for p in (q.strip() for q in text.split("|")) if p]
            title = fields[0] if fields else ""
        else:
            cut = text.find("�")
            if cut >= 0:
                text = text[:cut]
            title = text.strip()
        return dims, title, body_offset
    if t == 0x0e:                                   # encrypted
        if len(blob) < 8:
            return {}, "", 0
        title, hdr_end = pipe_title(8)
        return {"sub_family": blob[6], "variant": blob[7]}, title, hdr_end
    if t == 0x09:                                   # book
        title, hdr_end = pipe_title(6)
        while hdr_end < len(blob) and blob[hdr_end] != 0x01:   # past key=value| pairs to version byte
            nxt = blob.find(b"|", hdr_end)
            if nxt < 0:
                break
            hdr_end = nxt + 1
        return {}, title, hdr_end
    if t == 0x3d:                                   # scene
        title, hdr_end = pipe_title(6)
        while hdr_end < len(blob) and blob[hdr_end:hdr_end + 1] != b"{":   # past key=value| to JSON body
            nxt = blob.find(b"|", hdr_end)
            if nxt < 0:
                break
            hdr_end = nxt + 1
        return {}, title, hdr_end
    if t == 0xcc:                                   # cert
        if len(blob) < 8:
            return {}, "", 0
        sub = (blob[6] << 8) | blob[7]
        body = blob[8:]
        title = ""
        if body[:1] == b"|":
            close = body.find(b"|", 1)
            if close > 0:
                title = body[1:close].decode("utf-8", errors="replace").strip()
        return {"subtype": sub}, title, 8
    if t == 0xce:                                   # celestial v1
        if len(blob) < 12:
            return {}, "", 0
        kind = blob[6]; grouped = blob[7]; meta = blob[8]
        K = (blob[9] << 8) | blob[10]; T = blob[11]
        title = blob[12:12 + T].decode("utf-8", errors="replace") if T else ""
        return {"kind": kind, "grouped": grouped, "meta": meta, "K": K}, title, 12 + T
    if t == 0xee:                                   # estandarte
        return {}, "", 6
    return {}, "", 0


def _clean_title(title):
    """Lenient-title hygiene at the dataset boundary: cut at the first
    replacement char (decode damage) or control char (binary spill — the
    pre-redesign celestial 4e53bb26… puts packed star data where v1 keeps
    its title length). Newlines/tabs are legitimate (Paco's epitaph)."""
    out = []
    for c in title:
        if c == "�" or (ord(c) < 0x20 and c not in "\n\t"):
            break
        out.append(c)
    return "".join(out).strip()


def find_join_txid(root_txid, df_outputs):
    """Walk every strand to its terminus; return the tx that spends them all."""
    idx = outputs_walk_index(df_outputs)["txout"]
    termini_spenders = []
    n = 0
    while True:
        cur = f"{root_txid}:{n}"
        last_spender = None
        for _ in range(50000):
            hit = idx.get(cur)
            if hit is None:
                break
            sp = hit[0]
            if not sp:
                break
            last_spender = sp
            cur = f"{sp}:0"
        if last_spender is None:
            break
        termini_spenders.append(last_spender)
        n += 1
        if n > 32:
            break
    if not termini_spenders:
        return None
    most_common, count = Counter(termini_spenders).most_common(1)[0]
    return most_common if count >= 2 else termini_spenders[-1]


# ---------- strict canonical checks ----------
def check_image_strict(blob):
    if len(blob) < 12:
        return False
    if blob[5] not in VALID_TONES:
        return False
    if blob[6] not in (0x00, 0x01):
        return False
    bd = blob[11]
    if not (1 <= bd <= 8):
        return False
    W = (blob[7] << 8) | blob[8]; H = (blob[9] << 8) | blob[10]
    if W == 0 or H == 0:
        return False
    ch = 1 if blob[6] == 0 else 3
    expected = (W * H * ch * bd + 7) // 8
    return len(blob) - expected >= 12


def check_scene_strict(blob):
    if len(blob) < 7 or blob[5] not in VALID_TONES or blob[6:7] != b"|":
        return False
    body_start = blob.find(b"|{", 6)
    if body_start < 0:
        return False
    try:
        body = json.loads(blob[body_start + 1:].decode("utf-8"))
    except Exception:
        return False
    return isinstance(body, dict) and body.get("asset", {}).get("version") == "2.0"


STRICT_CHECKS = {
    "text":      lambda b: b[5] in VALID_TONES and (len(b) <= 6 or b[6:7] != b"|" or b.find(b"|", 7) >= 0),
    "essay":     lambda b: b[5] in VALID_TONES and (len(b) <= 6 or b[6:7] != b"|" or b.find(b"|", 7) >= 0),
    "image":     check_image_strict,
    "cert":      lambda b: len(b) >= 8 and b[5] in VALID_TONES and ((b[6] << 8) | b[7]) in (0x0001, 0x0002),
    "encrypted": lambda b: len(b) >= 8 and b[5] in VALID_TONES and b[6] in (0xae, 0xec, 0x0d),
    "celestial": lambda b: len(b) >= 12 and b[5] in VALID_TONES and b[6] in (0x00, 0x01) and b[7] in (0x00, 0x01) and b[8] in (0x00, 0x01),
    "scene":     check_scene_strict,
}


# ---------- pipeline steps ----------
def _load_rawtx_cache():
    """{txid: detailed-record} from prior runs. Tolerates a torn final line
    (the run that wrote it may have been killed mid-append)."""
    cache = {}
    if os.path.exists(RAWTX_CACHE):
        with open(RAWTX_CACHE) as f:
            for line in f:
                try:
                    rec = json.loads(line)
                    cache[rec["txid"]] = rec
                except (json.JSONDecodeError, KeyError):
                    continue
    return cache


def scan():
    """Pull wallet events, fetch raw txs (cache-aware), build
    df_transactions + df_outputs."""
    log(f"PHASE scan · tip: {rpc_request('getblockcount')}")
    log("pulling wallet events…")
    # Page until a short page: a fixed window silently truncates the OLDEST
    # events once the wallet outgrows it — exactly how the 2022 strand txs
    # vanished from the 2026-06-10 run (200000 events on the nose).
    all_events = []
    PAGE = 100000
    skip = 0
    while True:
        page = rpc_request("listtransactions", ["*", PAGE, skip, True])
        all_events.extend(page)
        log(f"  page at skip={skip}: {len(page)} events")
        if len(page) < PAGE:
            break
        skip += PAGE
    all_txids = {e["txid"] for e in all_events if e.get("address") in ADDRESSES}
    log(f"  {len(all_events)} events -> {len(all_txids)} unique txids")

    cache = _load_rawtx_cache()
    detailed = [cache[t] for t in all_txids if t in cache]
    to_fetch = sorted(all_txids - set(cache))
    log(f"  {len(detailed)} from cache · {len(to_fetch)} to fetch via RPC")

    os.makedirs(CACHE_DIR, exist_ok=True)
    bh_cache = {}
    t_phase = time.time()
    with open(RAWTX_CACHE, "a") as cache_f:
        for i, txid in enumerate(to_fetch):
            try:
                raw = rpc_request("getrawtransaction", [txid, 1])
            except Exception as e:
                log(f"  skip {txid[:12]}…: {e}")
                continue
            bh = raw.get("blockhash")
            if bh and bh in bh_cache:
                height = bh_cache[bh]
            elif bh:
                height = rpc_request("getblock", [bh])["height"]
                bh_cache[bh] = height
            else:
                height = None
            op_ret = None
            for v in raw.get("vout", []):
                d = extract_op_return(v)
                if d:
                    op_ret = d
                    break
            rec = {
                "txid": txid, "blockhash": bh, "blockheight": height,
                "blocktime": raw.get("blocktime"),
                "inputs": [f"{vin['txid']}:{vin['vout']}" for vin in raw.get("vin", []) if "txid" in vin],
                "values": [v["value"] for v in raw.get("vout", [])],
                "num_inputs": len(raw.get("vin", [])), "num_outputs": len(raw.get("vout", [])),
                "op_return": op_ret,
            }
            detailed.append(rec)
            if height is not None:        # never cache unconfirmed txs
                cache_f.write(json.dumps(rec) + "\n")
            if (i + 1) % 2000 == 0:
                cache_f.flush()
                rate = (i + 1) / max(time.time() - t_phase, 1e-9)
                log(f"  fetched {i + 1} / {len(to_fetch)}  ({rate:.0f} tx/s)")

    df_tx = pd.DataFrame(detailed).sort_values(["blockheight", "blocktime"]).reset_index(drop=True)

    log("building outputs frame…")
    rows = []
    for txid, num_outputs, values, op_ret, bh, bt in zip(
            df_tx["txid"], df_tx["num_outputs"], df_tx["values"],
            df_tx["op_return"], df_tx["blockheight"], df_tx["blocktime"]):
        for n in range(num_outputs):
            rows.append({
                "txout": f"{txid}:{n}", "spent_in": None,
                "value": values[n] if n < len(values) else None,
                "op_return": op_ret, "blockheight": bh,
                "blocktime": bt, "txid": txid, "n": n,
            })
    df_out = pd.DataFrame(rows)
    txout_to_idx = {txout: idx for idx, txout in enumerate(df_out["txout"])}
    spent_col = df_out["spent_in"].to_numpy(dtype=object)
    for txid, inputs in zip(df_tx["txid"], df_tx["inputs"]):
        for inp in inputs:
            idx = txout_to_idx.get(inp)
            if idx is not None:
                spent_col[idx] = txid
    df_out["spent_in"] = spent_col
    df_out = df_out.sort_values(["blockheight", "blocktime"]).reset_index(drop=True)
    df_out["op_return"] = df_out["op_return"].fillna("")
    df_out["spent_in"] = df_out["spent_in"].fillna("")
    log(f"df_transactions: {len(df_tx)} rows · df_outputs: {len(df_out)} rows")
    return df_tx, df_out


def extract(df_tx, df_out):
    """Identify roots, walk each, parse header, write bodies -> df_quipus."""
    log("PHASE extract · identifying quipu root candidates…")
    roots = identify_quipus(df_tx, df_out)
    log(f"{len(roots)} quipu root candidates")

    addr_per_root = {}
    for root in roots:
        try:
            raw = rpc_request("getrawtransaction", [root, 1])
            addr = raw["vout"][0].get("scriptPubKey", {}).get("addresses", [None])[0]
        except Exception:
            addr = None
        addr_per_root[root] = addr

    rows, skipped = [], []
    for ri, root in enumerate(roots):
        if ri and ri % 25 == 0:
            log(f"  walked {ri} / {len(roots)} candidates")
        try:
            hh, bh = read_quipu(root, df_outputs=df_out)
        except Exception as e:
            rows.append({"root_txid": root, "notes": f"walk error: {e}"})
            continue
        blob = bytes.fromhex(hh + bh)
        if len(blob) < 6 or blob[:4] != b"\xc1\xdd\x00\x01":
            skipped.append(root)
            continue
        t, tone = blob[4], blob[5]
        dims, title, hdr_end = parse_dims(blob)
        addr = addr_per_root.get(root)

        tx_row = df_tx[df_tx["txid"] == root]
        blockheight = int(tx_row.iloc[0]["blockheight"]) if not tx_row.empty and tx_row.iloc[0]["blockheight"] else None
        blocktime = int(tx_row.iloc[0]["blocktime"]) if not tx_row.empty and tx_row.iloc[0]["blocktime"] else None

        notes = ""
        if t == 0x03 and dims:
            ch = 1 if dims["color"] == 0 else 3
            expected_body = (dims["W"] * dims["H"] * ch * dims["bit_depth"] + 7) // 8
            actual_body = len(blob) - hdr_end
            if actual_body != expected_body:
                notes = f"image body mismatch: expect {expected_body} B, actual {actual_body} B"

        with open(os.path.join(BODIES_DIR, f"{root}.bin"), "wb") as f:
            f.write(blob)

        rows.append({
            "root_txid": root, "join_txid": find_join_txid(root, df_out) or "",
            "address": addr or "", "label": ADDRESSES.get(addr, "(unknown)"),
            "type_byte": f"0x{t:02x}", "type_name": TYPE_NAMES.get(t, f"unknown_0x{t:02x}"),
            "tone": f"0x{tone:02x}", "tone_name": TONE_NAMES.get(tone, f"unknown_0x{tone:02x}"),
            "title": _clean_title(title), "dimensions_json": json.dumps(dims, sort_keys=True),
            "total_bytes": len(blob), "blockheight": blockheight, "blocktime": blocktime,
            "body_file": f"bodies/{root}.bin", "notes": notes,
        })

    df_q = pd.DataFrame(rows).sort_values(["blockheight", "root_txid"]).reset_index(drop=True)
    log(f"{len(df_q)} canonical inscriptions extracted · {len(skipped)} heuristic false positives skipped")
    return df_q


def tag_status(df_q):
    log("PHASE tag_status")
    statuses = []
    for _, row in df_q.iterrows():
        tname = row["type_name"]
        if tname.startswith("unknown_") or tname == "identity" or tname not in STRICT_CHECKS:
            statuses.append("not_yet_canonicalized")
            continue
        bpath = os.path.join(DATA_DIR, row["body_file"])
        if not os.path.exists(bpath):
            statuses.append("pre_canonical")
            continue
        blob = open(bpath, "rb").read()
        statuses.append("canonical_v1" if STRICT_CHECKS[tname](blob) else "pre_canonical")
    df_q["canonical_status"] = statuses
    for k, v in Counter(statuses).most_common():
        log(f"  {k:25s} {v}")
    return df_q


def save(df_q, df_tx):
    """Write quipu_data.csv (overwrite) + tx_inputs.csv; coherence-check bodies."""
    log("PHASE save")
    csv_path = os.path.join(DATA_DIR, "quipu_data.csv")
    df_q.to_csv(csv_path, index=False)
    log(f"wrote {csv_path} ({os.path.getsize(csv_path)} bytes)")

    body_files = [f for f in os.listdir(BODIES_DIR) if f.endswith(".bin")]
    csv_bodies = {os.path.basename(p) for p in df_q["body_file"].dropna()}
    disk_bodies = set(body_files)
    missing = sorted(csv_bodies - disk_bodies)
    orphan = sorted(disk_bodies - csv_bodies)
    if missing:
        log(f"  [coherence] {len(missing)} CSV rows with no body file:", [b[:16] for b in missing[:8]])
    if orphan:
        log(f"  [coherence] {len(orphan)} body files with no CSV row:", [b[:16] for b in orphan[:8]])
    if not (missing or orphan):
        log("  [coherence] CSV rows and body files match exactly")

    slim = df_tx[["txid", "inputs"]].copy()
    slim["inputs"] = slim["inputs"].apply(json.dumps)
    slim_path = os.path.join(DATA_DIR, "tx_inputs.csv")
    slim.to_csv(slim_path, index=False)
    log(f"wrote {slim_path} ({len(slim)} txs)")


def build_edges(df_q, df_tx):
    """Funding / keydrop / citation edges -> quipu_edges.csv."""
    log("PHASE build_edges")
    from encrypted import read_encrypted_quipu
    from scene import read_scene_quipu, scene_quipu_refs

    df_q = df_q[df_q["root_txid"].notna()].copy()
    all_roots = set(df_q["root_txid"])
    joins = set(df_q["join_txid"].dropna())
    join_to_root = {r["join_txid"]: r["root_txid"] for _, r in df_q.iterrows()
                    if isinstance(r.get("join_txid"), str) and r["join_txid"]}
    quipu_struct = all_roots | joins

    tx_inputs = {}
    for _, tx in df_tx.iterrows():
        parsed = [tuple(s.rsplit(":", 1)) for s in tx["inputs"]]
        tx_inputs[tx["txid"]] = [(t, int(v)) for t, v in parsed if t]

    def trace_back(root_txid, max_hops=15):
        seen, queue, hits = set(), [(root_txid, 0)], []
        while queue:
            txid, hops = queue.pop(0)
            if hops > max_hops or txid in seen:
                continue
            seen.add(txid)
            if hops > 0 and txid in quipu_struct:
                hits.append((txid, hops))
                continue
            for prev_txid, _ in tx_inputs.get(txid, []):
                if prev_txid not in seen:
                    queue.append((prev_txid, hops + 1))
        return hits

    funding = []
    for _, q in df_q.iterrows():
        for anc, hops in trace_back(q["root_txid"]):
            src_root = anc if anc in all_roots else join_to_root.get(anc)
            if src_root and src_root != q["root_txid"]:
                funding.append({"source_quipu": src_root, "consumer_quipu": q["root_txid"],
                                "hops": hops, "kind": "funding"})

    keydrop = []
    for _, q in df_q.iterrows():
        if q["type_name"] != "encrypted":
            continue
        if json.loads(q["dimensions_json"] or "{}").get("sub_family") != 0x0d:
            continue
        bpath = os.path.join(DATA_DIR, q["body_file"])
        if not os.path.exists(bpath):
            continue
        blob = open(bpath, "rb").read()
        try:
            parsed = read_encrypted_quipu(blob[:8], blob[8:])
        except Exception as e:
            log(f"  keydrop parse failed for {q['root_txid'][:8]}…: {e}")
            continue
        for d in parsed.get("drops", []):
            if d.get("ref_txid") in all_roots:
                keydrop.append({"source_quipu": q["root_txid"], "consumer_quipu": d["ref_txid"],
                                "hops": 0, "kind": "keydrop"})

    CIT = re.compile(r"<<\s*([0-9a-fA-F]{64})\s*>>")
    LBL = re.compile(r"(\w+)\s*:\s*<<\s*([0-9a-fA-F]{64})\s*>>")

    def body_text_for(q, blob):
        if q["type_name"] in ("text", "essay"):
            off = 6
            if len(blob) > 6 and blob[6:7] == b"|":
                close = blob.find(b"|", 7)
                if close > 0:
                    off = close + 1
            return blob[off:].decode("utf-8", errors="replace")
        if q["type_name"] == "cert":
            return blob[8:].decode("utf-8", errors="replace")
        return ""

    citation, seen_cit = [], set()
    for _, q in df_q.iterrows():
        if q["type_name"] not in ("text", "essay", "cert"):
            continue
        blob = open(os.path.join(DATA_DIR, q["body_file"]), "rb").read()
        text = body_text_for(q, blob)
        labeled = {m.group(2).lower(): m.group(1) for m in LBL.finditer(text)}
        for m in CIT.finditer(text):
            ref = m.group(1).lower()
            if ref not in all_roots or ref == q["root_txid"]:
                continue
            lab = labeled.get(ref, "").lower()
            kind = ("citation_image" if lab == "image"
                    else "citation_auth" if lab in ("certificateauthority", "certauthority", "ca")
                    else "citation")
            key = (q["root_txid"], ref, kind)
            if key not in seen_cit:
                seen_cit.add(key)
                citation.append({"source_quipu": q["root_txid"], "consumer_quipu": ref,
                                 "hops": 0, "kind": kind})

    for _, q in df_q.iterrows():
        if q["type_name"] != "scene":
            continue
        blob = open(os.path.join(DATA_DIR, q["body_file"]), "rb").read()
        body_start = blob.find(b"|{", 6)
        if body_start < 0:
            continue
        try:
            parsed = read_scene_quipu(blob[:body_start + 1], blob[body_start + 1:])
        except Exception as e:
            log(f"  scene parse failed for {q['root_txid'][:8]}…: {e}")
            continue
        for _node_idx, ref_kind, ref in scene_quipu_refs(parsed):
            ref_lo = ref.lower()
            if ref_lo not in all_roots or ref_lo == q["root_txid"]:
                continue
            kind = f"citation_scene_{ref_kind}"
            key = (q["root_txid"], ref_lo, kind)
            if key not in seen_cit:
                seen_cit.add(key)
                citation.append({"source_quipu": q["root_txid"], "consumer_quipu": ref_lo,
                                 "hops": 0, "kind": kind})

    df_edges = pd.DataFrame(funding + keydrop + citation)
    df_edges.to_csv(os.path.join(DATA_DIR, "quipu_edges.csv"), index=False)
    log(f"{len(funding)} funding · {len(keydrop)} keydrop · {len(citation)} citation -> quipu_edges.csv")


def main():
    os.makedirs(BODIES_DIR, exist_ok=True)
    df_tx, df_out = scan()
    df_q = extract(df_tx, df_out)
    df_q = tag_status(df_q)
    save(df_q, df_tx)
    build_edges(df_q, df_tx)
    log("done.")


if __name__ == "__main__":
    main()
