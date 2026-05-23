"""Broadcast the precomputed consolidated 3-quipu cementerio inscription.

Order:
    1. splitter
    2. 3 per-quipu roots (parallel)
    3. all 66 strands, each ≤25 knots (fits one mempool ancestor wave;
       confirms in one block). Strands broadcast in parallel.
    4. WAIT for every strand terminus to be MINED (not just in-mempool)
       so the mega-join doesn't fail with too-long-mempool-chain.
    5. mega-join

Reads precomputed tx hex from working/cemetery/artifacts/.

Design notes (kept from working/goethe_hebrew/broadcast_consolidated.py):

- Idempotent + resumable. Re-running detects which txs are already on
  chain and skips them. Safe to re-launch after any crash.

- Direct file logging with explicit fsync() per line. Python's stdout
  is block-buffered when piped through tee/grep, and threaded writers
  can lose hundreds of progress lines if the process dies. The log
  file is the ground truth.

- The mega-join must wait for every strand terminus to be MINED. Even
  though each strand fits one wave (≤25 knots), the terminus is still
  in-mempool until a block confirms it; a mega-join broadcast against
  in-mempool termini fails with too-long-mempool-chain.

Run via:

    python -u broadcast_consolidated.py
"""
import os, sys, time, threading, random
from pathlib import Path

THIS_DIR = Path(__file__).parent
PROJECT  = THIS_DIR.parent.parent
sys.path.insert(0, str(PROJECT))

from colegio_tools import rpc_request, MEMPOOL_ANCESTOR_LIMIT

ARTIFACTS = THIS_DIR / "corrections_artifacts"
LOG_PATH  = THIS_DIR / "broadcast_corrections.log"
QUIPU_KEYS = ["binding", "essay"]

# Cap concurrent sendrawtransaction calls so 66 strand threads don't
# stampede Doge's RPC work queue (which is small and rejects with
# "Work queue depth exceeded" when overwhelmed).
SEND_SEMAPHORE = threading.Semaphore(4)

# ---- Logging --------------------------------------------------------------
_LOG_LOCK = threading.Lock()
_LOG_FILE = open(LOG_PATH, "a", buffering=1)

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
    """Return confirmations count, or None if the node doesn't know the tx
    AT ALL (not in chain, not in mempool). Wallet-scoped gettransaction
    can miss txs broadcast via sendrawtransaction even when the chain has
    them, so we fall back to chain-scoped getrawtransaction."""
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
    """Block until txid has ≥1 confirmation."""
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
    """Send via RPC if node doesn't already know the txid (idempotent).
    Uses send_with_retry for transient-error resilience."""
    confs = on_chain_with_confs(expected_txid)
    if confs is not None:
        log(f"  ↺ {label} already broadcast (confs={confs})")
        return
    if not send_with_retry(hex_str, label):
        raise RuntimeError(f"{label} could not be broadcast")
    log(f"  ✓ {label} sent: {expected_txid[:16]}…")

def find_resume_index(txids):
    """Binary-search the highest knot index already on chain."""
    lo, hi, last = 0, len(txids)-1, -1
    while lo <= hi:
        mid = (lo+hi)//2
        if on_chain_with_confs(txids[mid]) is not None:
            last = mid; lo = mid+1
        else:
            hi = mid-1
    return last + 1

def send_with_retry(hex_str, label, max_attempts=12):
    """Call sendrawtransaction with a concurrency cap + retry on transient
    work-queue / connection errors. Returns True on success, False on
    permanent failure. Idempotent: 'already in mempool/chain' counts as
    success."""
    delay = 0.4
    for attempt in range(max_attempts):
        with SEND_SEMAPHORE:
            try:
                rpc_request("sendrawtransaction", [hex_str])
                return True
            except Exception as e:
                msg = str(e).lower()
                if "already" in msg or "duplicate" in msg:
                    return True
                retryable = (
                    "work queue" in msg or
                    "depth exceeded" in msg or
                    "connection" in msg or
                    "timed out" in msg or
                    "500" in msg
                )
                if not retryable:
                    log(f"  *** {label} permanent failure: {e}")
                    return False
        # transient — wait outside the semaphore so other threads can proceed
        sleep_for = delay + random.uniform(0, 0.3)
        delay = min(delay * 1.7, 8.0)
        time.sleep(sleep_for)
    log(f"  *** {label} gave up after {max_attempts} retries")
    return False

# ---- Discovery ------------------------------------------------------------
log("=" * 72)
log("CEMENTERIO CORRECTIONS BROADCAST (binding + essay v2)")
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
log(f"found {len(strand_lookup)} strands, "
    f"{sum(len(t) for t,_ in strand_lookup.values())} total knot txs")

# ---- Phase 1: splitter ----------------------------------------------------
log("")
log("[1/5] splitter")
splitter_hex  = load("splitter", "hex")
splitter_txid = load("splitter", "txid")
send_if_needed(splitter_hex, splitter_txid, "splitter")
wait_confirmed(splitter_txid, "splitter")

# ---- Phase 2: 3 per-quipu roots ------------------------------------------
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
log(f"[3/5] {len(strand_lookup)} strands in parallel "
    f"(each ≤{MEMPOOL_ANCESTOR_LIMIT} knots; one wave per strand)")

def broadcast_strand(key, idx, txns, txids):
    n = len(txns)
    start = find_resume_index(txids)
    if start >= n:
        log(f"  strand[{key}_{idx:>2}] already complete ({n} knots)")
        return True
    if start > 0:
        log(f"  strand[{key}_{idx:>2}] resuming from knot {start} "
            f"({n - start} remaining)")
    else:
        log(f"  strand[{key}_{idx:>2}] {n} knots starting")
    i = start
    while i < n:
        wave_end = min(i + MEMPOOL_ANCESTOR_LIMIT, n)
        for j in range(i, wave_end):
            ok = send_with_retry(txns[j], f"strand[{key}_{idx}] knot {j}")
            if not ok:
                return False
        log(f"  strand[{key}_{idx:>2}] wave sent: {i}..{wave_end-1} "
            f"({wave_end}/{n})")
        if wave_end < n:
            anchor = txids[wave_end - 1]
            try:
                wait_confirmed(anchor,
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
    t = threading.Thread(
        target=broadcast_strand, args=(key, idx, txns, txids),
        name=f"{key}_{idx}",
    )
    t.start()
    threads.append(t)
for t in threads:
    t.join()
log(f"all {len(threads)} strand threads finished")

# ---- Phase 4: WAIT for every strand terminus to be MINED ----------------
log("")
log("[4/5] waiting for all strand termini to confirm in a block")
termini = [(f"{k}_{i}", txids[-1])
           for (k, i), (_, txids) in strand_lookup.items()]
poll, max_wait, elapsed = 30, 1800, 0
while elapsed < max_wait:
    confs = [(label, on_chain_with_confs(txid)) for label, txid in termini]
    n_confirmed = sum(1 for _, c in confs if c is not None and c > 0)
    n_total = len(confs)
    log(f"  termini confirmed: {n_confirmed}/{n_total}   "
        f"(elapsed {elapsed}s)")
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
    log(f"  root[{k:<9}] {root_txids[k]}")
log(f"  mega-join:       {join_txid}")
log(f"  residual at apocrypha (final output): {join_txid}:0")
