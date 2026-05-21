"""Broadcast the precomputed consolidated 5-quipu inscription.

Order:
    1. splitter
    2. 5 per-quipu roots (parallel)
    3. all N strands, each in waves of 25 knots, parallel across strands
    4. WAIT for all strand termini to confirm in a block
    5. mega-join

Reads precomputed tx hex from working/goethe_hebrew/artifacts/.

Design notes (these are the things to keep right):

- Idempotent + resumable. Re-running detects which txs are already on
  chain and skips them. Safe to re-launch after any crash.

- Direct file logging with explicit fsync() per line. Python's stdout
  is block-buffered when piped through tee/grep, and threaded writers
  can lose hundreds of progress lines if the process dies. The
  log file is the ground truth.

- The mega-join must wait for every strand terminus to be MINED, not
  just in-mempool. Doge's mempool-ancestor-chain limit is 25, and each
  image body strand has ~355 ancestors. A mega-join broadcast while
  the termini are still pending will fail with `too-long-mempool-chain`.
  We poll until every terminus has confirmations >= 1.

Run via:

    python -u broadcast_consolidated.py
"""
import os, sys, time, threading
from pathlib import Path

THIS_DIR = Path(__file__).parent
PROJECT  = THIS_DIR.parent.parent
sys.path.insert(0, str(PROJECT))

from colegio_tools import rpc_request, MEMPOOL_ANCESTOR_LIMIT

ARTIFACTS = THIS_DIR / "artifacts"
LOG_PATH  = THIS_DIR / "broadcast.log"
QUIPU_KEYS = ["image", "essay", "dichtung", "fett", "juden"]

# ---- Logging --------------------------------------------------------------
_LOG_LOCK = threading.Lock()
_LOG_FILE = open(LOG_PATH, "a", buffering=1)  # line-buffered

def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    with _LOG_LOCK:
        _LOG_FILE.write(line + "\n")
        _LOG_FILE.flush()
        os.fsync(_LOG_FILE.fileno())
    print(line, flush=True)

# ---- Helpers --------------------------------------------------------------
def load(key, suffix):
    return (ARTIFACTS / f"{key}.{suffix}").read_text().strip()

def load_strand(key, idx):
    txns  = (ARTIFACTS / f"strand_{key}_{idx}.txns").read_text().splitlines()
    txids = (ARTIFACTS / f"strand_{key}_{idx}.txids").read_text().splitlines()
    assert len(txns) == len(txids), f"strand {key}_{idx} length mismatch"
    return txns, txids

def on_chain_with_confs(txid):
    """Return confirmations count, or None if the node doesn't know the tx."""
    try:
        t = rpc_request("gettransaction", [txid])
        return t.get("confirmations", 0)
    except Exception:
        return None

def wait_confirmed(txid, label, poll=15, max_wait=900):
    """Block until txid has >= 1 confirmation."""
    elapsed = 0
    while elapsed < max_wait:
        confs = on_chain_with_confs(txid)
        if confs is not None and confs > 0:
            log(f"  ✓ {label} confirmed ({elapsed}s)")
            return
        time.sleep(poll)
        elapsed += poll
    raise TimeoutError(f"{label} did not confirm in {max_wait}s")

def send_if_needed(hex_str, expected_txid, label):
    """Send via RPC if the node doesn't already know the txid (idempotent)."""
    confs = on_chain_with_confs(expected_txid)
    if confs is not None:
        log(f"  ↺ {label} already broadcast (confs={confs})")
        return
    returned = rpc_request("sendrawtransaction", [hex_str])
    assert returned == expected_txid, f"{label}: got {returned}"
    log(f"  ✓ {label} sent: {expected_txid[:16]}…")

def find_resume_index(txids):
    """Binary-search the highest knot index already on chain. Returns the
    next index to broadcast (i.e., last_known + 1)."""
    lo, hi, last = 0, len(txids)-1, -1
    while lo <= hi:
        mid = (lo+hi)//2
        if on_chain_with_confs(txids[mid]) is not None:
            last = mid; lo = mid+1
        else:
            hi = mid-1
    return last + 1

# ---- Discovery ------------------------------------------------------------
log("=" * 72)
log("CONSOLIDATED INSCRIPTION BROADCAST")
log("=" * 72)

strand_lookup = {}  # (key, idx) -> (txns, txids)
for key in QUIPU_KEYS:
    idx = 0
    while True:
        p = ARTIFACTS / f"strand_{key}_{idx}.txns"
        if not p.exists():
            break
        strand_lookup[(key, idx)] = load_strand(key, idx)
        idx += 1
log(f"found {len(strand_lookup)} strands, {sum(len(t) for t,_ in strand_lookup.values())} total knot txs")

# ---- Phase 1: splitter ----------------------------------------------------
log("")
log("[1/5] splitter")
splitter_hex  = load("splitter", "hex")
splitter_txid = load("splitter", "txid")
send_if_needed(splitter_hex, splitter_txid, "splitter")
wait_confirmed(splitter_txid, "splitter")

# ---- Phase 2: 5 per-quipu roots ------------------------------------------
log("")
log("[2/5] per-quipu roots")
root_txids = {k: load(f"root_{k}", "txid") for k in QUIPU_KEYS}
for k in QUIPU_KEYS:
    hex_str = load(f"root_{k}", "hex")
    send_if_needed(hex_str, root_txids[k], f"root[{k}]")
for k in QUIPU_KEYS:
    wait_confirmed(root_txids[k], f"root[{k}]")

# ---- Phase 3: parallel strand broadcast ----------------------------------
log("")
log(f"[3/5] {len(strand_lookup)} strands in parallel waves of {MEMPOOL_ANCESTOR_LIMIT}")

def broadcast_strand(key, idx, txns, txids):
    n = len(txns)
    start = find_resume_index(txids)
    if start >= n:
        log(f"  strand[{key}_{idx}] already complete ({n} knots)")
        return True
    if start > 0:
        log(f"  strand[{key}_{idx}] resuming from knot {start} ({n - start} remaining)")
    else:
        log(f"  strand[{key}_{idx}] {n} knots starting")
    i = start
    while i < n:
        wave_end = min(i + MEMPOOL_ANCESTOR_LIMIT, n)
        for j in range(i, wave_end):
            try:
                rpc_request("sendrawtransaction", [txns[j]])
            except Exception as e:
                msg = str(e).lower()
                if "already" in msg or "duplicate" in msg:
                    continue  # already in mempool/chain, fine
                log(f"  *** strand[{key}_{idx}] knot {j} FAILED: {e}")
                return False
        log(f"  strand[{key}_{idx}] wave sent: {i}..{wave_end-1} ({wave_end}/{n})")
        if wave_end < n:
            anchor = txids[wave_end - 1]
            try:
                wait_confirmed(anchor, f"strand[{key}_{idx}] wave anchor knot {wave_end-1}",
                               poll=15, max_wait=1500)
            except TimeoutError as e:
                log(f"  *** {e}")
                return False
        i = wave_end
    log(f"  strand[{key}_{idx}] DONE (terminus {txids[-1][:16]}…)")
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

# ---- Phase 4: WAIT for every strand terminus to confirm ------------------
# Critical: without this, the mega-join would fail with too-long-mempool-chain
# because each strand terminus carries up to 355 unconfirmed ancestors.
log("")
log("[4/5] waiting for all strand termini to confirm in a block")
termini = [(f"{k}_{i}", txids[-1]) for (k, i), (_, txids) in strand_lookup.items()]
poll, max_wait, elapsed = 30, 1800, 0
while elapsed < max_wait:
    confs = [(label, on_chain_with_confs(txid)) for label, txid in termini]
    n_confirmed = sum(1 for _, c in confs if c is not None and c > 0)
    n_total = len(confs)
    log(f"  termini confirmed: {n_confirmed}/{n_total}   (elapsed {elapsed}s)")
    if n_confirmed == n_total:
        break
    pending = [l for l, c in confs if c is None or c <= 0]
    if len(pending) <= 8:
        log(f"  pending: {pending}")
    time.sleep(poll)
    elapsed += poll
else:
    raise TimeoutError(f"not all termini confirmed within {max_wait}s")

# ---- Phase 5: mega-join --------------------------------------------------
log("")
log("[5/5] mega-join")
join_hex  = load("megajoin", "hex")
join_txid = load("megajoin", "txid")
send_if_needed(join_hex, join_txid, "mega-join")
wait_confirmed(join_txid, "mega-join")

log("")
log("=" * 72)
log("ALL DONE. The corpus is on chain.")
log("=" * 72)
log(f"  splitter:        {splitter_txid}")
for k in QUIPU_KEYS:
    log(f"  root[{k:<10}] {root_txids[k]}")
log(f"  mega-join:       {join_txid}")
log(f"  Final 1.00 DOGE residual: {join_txid}:0  (back to apocrypha)")
_LOG_FILE.close()
