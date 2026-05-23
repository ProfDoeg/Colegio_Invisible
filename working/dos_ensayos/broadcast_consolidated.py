"""Broadcast the precomputed Dos ensayos inscription.

Single 0x09 book quipu, standalone diamond. Phases:
    1. splitter
    2. book root
    3. all 2 strands in parallel (3 knots total)
    4. wait for both termini to be mined
    5. join

Idempotent + resumable. Reads precomputed tx hex from artifacts/.

Run via:
    python -u working/dos_ensayos/broadcast_consolidated.py
"""
import os, sys, time, threading, random
from pathlib import Path

THIS_DIR = Path(__file__).parent
PROJECT  = THIS_DIR.parent.parent
sys.path.insert(0, str(PROJECT))

from colegio_tools import rpc_request, MEMPOOL_ANCESTOR_LIMIT

ARTIFACTS = THIS_DIR / "artifacts"
LOG_PATH  = THIS_DIR / "broadcast.log"

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

def load_strand(idx):
    txns  = (ARTIFACTS / f"strand_book_{idx}.txns").read_text().splitlines()
    txids = (ARTIFACTS / f"strand_book_{idx}.txids").read_text().splitlines()
    assert len(txns) == len(txids)
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

log("=" * 72)
log("DOS ENSAYOS BOOK INSCRIPTION BROADCAST")
log("=" * 72)

strand_lookup = {}
idx = 0
while True:
    p = ARTIFACTS / f"strand_book_{idx}.txns"
    if not p.exists():
        break
    strand_lookup[idx] = load_strand(idx)
    idx += 1
log(f"found {len(strand_lookup)} strands, "
    f"{sum(len(t) for t,_ in strand_lookup.values())} total knot txs")

log("")
log("[1/5] splitter")
splitter_hex  = load("splitter", "hex")
splitter_txid = load("splitter", "txid")
send_if_needed(splitter_hex, splitter_txid, "splitter")
wait_confirmed(splitter_txid, "splitter")

log("")
log("[2/5] book root")
root_hex  = load("root_book", "hex")
root_txid = load("root_book", "txid")
send_if_needed(root_hex, root_txid, "root[book]")
wait_confirmed(root_txid, "root[book]")

log("")
log(f"[3/5] {len(strand_lookup)} strands in parallel")

def broadcast_strand(idx, txns, txids):
    n = len(txns)
    start = find_resume_index(txids)
    if start >= n:
        log(f"  strand[{idx}] already complete ({n} knots)")
        return True
    if start > 0:
        log(f"  strand[{idx}] resuming from knot {start} ({n - start} remaining)")
    else:
        log(f"  strand[{idx}] {n} knots starting")
    i = start
    while i < n:
        wave_end = min(i + MEMPOOL_ANCESTOR_LIMIT, n)
        for j in range(i, wave_end):
            if not send_with_retry(txns[j], f"strand[{idx}] knot {j}"):
                return False
        log(f"  strand[{idx}] wave sent: {i}..{wave_end-1} ({wave_end}/{n})")
        if wave_end < n:
            try:
                wait_confirmed(txids[wave_end - 1],
                               f"strand[{idx}] wave anchor knot {wave_end-1}",
                               poll=15, max_wait=1500)
            except TimeoutError as e:
                log(f"  *** {e}")
                return False
        i = wave_end
    log(f"  strand[{idx}] DONE (terminus {txids[-1][:16]}…)")
    return True

threads = []
for idx, (txns, txids) in strand_lookup.items():
    t = threading.Thread(target=broadcast_strand, args=(idx, txns, txids),
                         name=f"strand_{idx}")
    t.start()
    threads.append(t)
for t in threads:
    t.join()
log(f"all {len(threads)} strand threads finished")

log("")
log("[4/5] waiting for all strand termini to confirm in a block")
termini = [(f"strand_{i}", txids[-1]) for i, (_, txids) in strand_lookup.items()]
poll, max_wait, elapsed = 30, 1800, 0
while elapsed < max_wait:
    confs = [(label, on_chain_with_confs(txid)) for label, txid in termini]
    n_confirmed = sum(1 for _, c in confs if c is not None and c > 0)
    log(f"  termini confirmed: {n_confirmed}/{len(confs)}   (elapsed {elapsed}s)")
    if n_confirmed == len(confs):
        break
    time.sleep(poll)
    elapsed += poll
else:
    raise TimeoutError(f"not all termini confirmed within {max_wait}s")

log("")
log("[5/5] join")
join_hex  = load("join", "hex")
join_txid = load("join", "txid")
send_if_needed(join_hex, join_txid, "join")
wait_confirmed(join_txid, "join")

log("")
log("=" * 72)
log("ALL DONE. Dos ensayos is on chain.")
log("=" * 72)
log(f"  splitter:     {splitter_txid}")
log(f"  book root:    {root_txid}")
log(f"  join:         {join_txid}")
log(f"  residual at apocrypha (final output): {join_txid}:0")
