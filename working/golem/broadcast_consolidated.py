"""Broadcast the precomputed El Libro del Gólem inscription.

13 quipus, 63 strands, 1102 knot transactions, all signed by multiman
2-of-2 multisig. Reads precomputed tx hex from artifacts/.

Phases:
    1. splitter
    2. 13 per-quipu roots in parallel
    3. all 63 strands in parallel (each ≤ 25 knots, fits one wave)
    4. WAIT for every strand terminus to confirm in a block
    5. megajoin

Idempotent + resumable: re-running detects which txs are already on
chain and skips them.

Run via:
    python -u working/golem/broadcast_consolidated.py
"""
import os, sys, time, threading, random
from pathlib import Path

THIS_DIR = Path(__file__).parent
PROJECT  = THIS_DIR.parent.parent
sys.path.insert(0, str(PROJECT))

from colegio_tools import rpc_request, MEMPOOL_ANCESTOR_LIMIT

ARTIFACTS = THIS_DIR / "artifacts"
LOG_PATH  = THIS_DIR / "broadcast.log"

QUIPU_ORDER = [
    "binding", "cover", "forward",
    "essay1", "essay2", "essay3", "essay4", "essay5",
    "art1", "art2", "art3", "art4",
    "book",
]

SEND_SEMAPHORE = threading.Semaphore(4)

_LOG_LOCK = threading.Lock()
_LOG_FILE = open(LOG_PATH, "a", buffering=1)

def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    with _LOG_LOCK:
        _LOG_FILE.write(line + "\n")
        _LOG_FILE.flush()
        os.fsync(_LOG_FILE.fileno())
    print(line, flush=True)

def load(stem, suffix):
    return (ARTIFACTS / f"{stem}.{suffix}").read_text().strip()

def load_strand(key, idx):
    txns  = (ARTIFACTS / f"strand_{key}_{idx}.txns").read_text().splitlines()
    txids = (ARTIFACTS / f"strand_{key}_{idx}.txids").read_text().splitlines()
    assert len(txns) == len(txids), f"strand {key}_{idx} length mismatch"
    return txns, txids

def on_chain_with_confs(txid):
    try:
        t = rpc_request("gettransaction", [txid])
        return t.get("confirmations", 0)
    except Exception:
        pass
    try:
        raw = rpc_request("getrawtransaction", [txid, 1])
        bh = raw.get("blockhash")
        if not bh:
            return 0
        blk = rpc_request("getblock", [bh])
        tip = rpc_request("getblockcount", [])
        return tip - blk["height"] + 1
    except Exception:
        return None

def wait_confirmed(txid, label, poll=15, max_wait=900):
    elapsed = 0
    while elapsed < max_wait:
        confs = on_chain_with_confs(txid)
        if confs is not None and confs > 0:
            log(f"  ✓ {label} confirmed ({elapsed}s)")
            return
        time.sleep(poll)
        elapsed += poll
    raise TimeoutError(f"{label} did not confirm in {max_wait}s")

def send_with_retry(hex_str, label, max_attempts=12):
    delay = 0.4
    for _ in range(max_attempts):
        with SEND_SEMAPHORE:
            try:
                rpc_request("sendrawtransaction", [hex_str])
                return True
            except Exception as e:
                msg = str(e).lower()
                if "already" in msg or "duplicate" in msg:
                    return True
                retryable = (
                    "work queue" in msg or "depth exceeded" in msg or
                    "connection" in msg or "timed out" in msg or "500" in msg
                )
                if not retryable:
                    log(f"  *** {label} permanent failure: {e}")
                    return False
        time.sleep(delay + random.uniform(0, 0.3))
        delay = min(delay * 1.7, 8.0)
    log(f"  *** {label} gave up after {max_attempts} retries")
    return False

def send_if_needed(hex_str, expected_txid, label):
    confs = on_chain_with_confs(expected_txid)
    if confs is not None:
        log(f"  ↺ {label} already broadcast (confs={confs})")
        return
    if not send_with_retry(hex_str, label):
        raise RuntimeError(f"{label} could not be broadcast")
    log(f"  ✓ {label} sent: {expected_txid[:16]}…")

def find_resume_index(txids):
    lo, hi, last = 0, len(txids)-1, -1
    while lo <= hi:
        mid = (lo+hi)//2
        if on_chain_with_confs(txids[mid]) is not None:
            last = mid; lo = mid+1
        else:
            hi = mid-1
    return last + 1

# ----------------------------------------------------------------------
log("=" * 72)
log("EL LIBRO DEL GÓLEM — BROADCAST")
log("=" * 72)

strand_lookup = {}
for key in QUIPU_ORDER:
    idx = 0
    while True:
        p = ARTIFACTS / f"strand_{key}_{idx}.txns"
        if not p.exists():
            break
        strand_lookup[(key, idx)] = load_strand(key, idx)
        idx += 1
total_knots = sum(len(t) for t, _ in strand_lookup.values())
log(f"found {len(strand_lookup)} strands, {total_knots} total knot txs")

# Phase 1: splitter
log("")
log("[1/5] splitter")
splitter_hex  = load("splitter", "hex")
splitter_txid = load("splitter", "txid")
send_if_needed(splitter_hex, splitter_txid, "splitter")
wait_confirmed(splitter_txid, "splitter")

# Phase 2: 13 per-quipu roots in parallel
log("")
log(f"[2/5] {len(QUIPU_ORDER)} per-quipu roots")
root_txids = {k: load(f"root_{k}", "txid") for k in QUIPU_ORDER}
for k in QUIPU_ORDER:
    hex_str = load(f"root_{k}", "hex")
    send_if_needed(hex_str, root_txids[k], f"root[{k}]")
for k in QUIPU_ORDER:
    wait_confirmed(root_txids[k], f"root[{k}]")

# Phase 3: all 63 strands in parallel
log("")
log(f"[3/5] {len(strand_lookup)} strands in parallel (each ≤{MEMPOOL_ANCESTOR_LIMIT} knots)")

def broadcast_strand(key, idx, txns, txids):
    n = len(txns)
    start = find_resume_index(txids)
    if start >= n:
        log(f"  strand[{key}_{idx:>2}] already complete ({n} knots)")
        return True
    if start > 0:
        log(f"  strand[{key}_{idx:>2}] resuming from knot {start} ({n - start} remaining)")
    else:
        log(f"  strand[{key}_{idx:>2}] {n} knots starting")
    i = start
    while i < n:
        wave_end = min(i + MEMPOOL_ANCESTOR_LIMIT, n)
        for j in range(i, wave_end):
            if not send_with_retry(txns[j], f"strand[{key}_{idx}] knot {j}"):
                return False
        log(f"  strand[{key}_{idx:>2}] wave sent: {i}..{wave_end-1} ({wave_end}/{n})")
        if wave_end < n:
            try:
                wait_confirmed(txids[wave_end - 1],
                               f"strand[{key}_{idx}] wave anchor knot {wave_end-1}",
                               poll=15, max_wait=1500)
            except TimeoutError as e:
                log(f"  *** {e}")
                return False
        i = wave_end
    log(f"  strand[{key}_{idx:>2}] DONE (terminus {txids[-1][:16]}…)")
    return True

threads = []
for (key, idx), (txns, txids) in strand_lookup.items():
    t = threading.Thread(target=broadcast_strand, args=(key, idx, txns, txids),
                         name=f"{key}_{idx}")
    t.start()
    threads.append(t)
for t in threads:
    t.join()
log(f"all {len(threads)} strand threads finished")

# Phase 4: wait for every strand terminus to confirm in a block
log("")
log("[4/5] waiting for all strand termini to mine into a block")
termini = [(f"{k}_{i}", txids[-1])
           for (k, i), (_, txids) in strand_lookup.items()]
poll, max_wait, elapsed = 30, 2400, 0
while elapsed < max_wait:
    confs = [(label, on_chain_with_confs(txid)) for label, txid in termini]
    n_confirmed = sum(1 for _, c in confs if c is not None and c > 0)
    log(f"  termini confirmed: {n_confirmed}/{len(confs)}   (elapsed {elapsed}s)")
    if n_confirmed == len(confs):
        break
    pending = [l for l, c in confs if c is None or c <= 0]
    if len(pending) <= 10:
        log(f"  pending: {pending}")
    time.sleep(poll)
    elapsed += poll
else:
    raise TimeoutError(f"not all termini confirmed within {max_wait}s")

# Phase 5: megajoin
log("")
log("[5/5] megajoin")
join_hex  = load("megajoin", "hex")
join_txid = load("megajoin", "txid")
send_if_needed(join_hex, join_txid, "megajoin")
wait_confirmed(join_txid, "megajoin")

log("")
log("=" * 72)
log("EL LIBRO DEL GÓLEM IS ON CHAIN.")
log("=" * 72)
log(f"  splitter:    {splitter_txid}")
for k in QUIPU_ORDER:
    log(f"  root[{k:<8}] {root_txids[k]}")
log(f"  megajoin:    {join_txid}")
log(f"  residual at multiman (final output): {join_txid}:0")
