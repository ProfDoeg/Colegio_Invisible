"""Resume the broadcast from where it stopped.

For each strand, determine how many knots have been broadcast on chain, then
push the rest in waves of 25 with confirmation waits between waves.
Then broadcast the mega-join.

Logs directly to working/goethe_hebrew/resume.log via line-buffered file
writes — no piped tee, no buffered stdout that vanishes on crash.
"""
import os, sys, time, threading, queue
from pathlib import Path

THIS_DIR = Path(__file__).parent
PROJECT  = THIS_DIR.parent.parent
sys.path.insert(0, str(PROJECT))

from colegio_tools import rpc_request, MEMPOOL_ANCESTOR_LIMIT

ARTIFACTS = THIS_DIR / "artifacts"
LOG_PATH  = THIS_DIR / "resume.log"
LOG_LOCK  = threading.Lock()
LOG_FILE  = open(LOG_PATH, "a", buffering=1)  # line-buffered

def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    with LOG_LOCK:
        LOG_FILE.write(line + "\n")
        LOG_FILE.flush()
        os.fsync(LOG_FILE.fileno())
    print(line, flush=True)

QUIPU_KEYS = ["image", "essay", "dichtung", "fett", "juden"]

# Discover strands + detect current state
def find_last_broadcast(txids):
    """Binary search: largest index i where node knows tx txids[i]."""
    lo, hi, last = 0, len(txids)-1, -1
    while lo <= hi:
        mid = (lo+hi)//2
        try:
            rpc_request("gettransaction", [txids[mid]])
            last = mid
            lo = mid+1
        except Exception:
            hi = mid-1
    return last

log("=" * 72)
log("RESUME BROADCAST — surveying strand state on chain")
log("=" * 72)

strand_lookup = {}  # (key, idx) -> (txns, txids, start_index)
for k in QUIPU_KEYS:
    idx = 0
    while (ARTIFACTS / f"strand_{k}_{idx}.txids").exists():
        txns  = (ARTIFACTS / f"strand_{k}_{idx}.txns").read_text().splitlines()
        txids = (ARTIFACTS / f"strand_{k}_{idx}.txids").read_text().splitlines()
        last_broadcast = find_last_broadcast(txids)
        start = last_broadcast + 1
        strand_lookup[(k, idx)] = (txns, txids, start)
        log(f"  strand[{k}_{idx}] {len(txids)} knots — on chain up to {last_broadcast}, resume from {start}")
        idx += 1

total_remaining = sum(len(t) - s for (t, _, s) in strand_lookup.values())
total_knots     = sum(len(t)     for (t, _, _) in strand_lookup.values())
log(f"\ntotal knots: {total_knots}   already on chain: {total_knots - total_remaining}   "
    f"to broadcast: {total_remaining}")

if total_remaining == 0:
    log("\nAll strands fully broadcast already. Moving to mega-join.")
else:
    # ---- Phase A: resume strands in parallel waves ------------------------
    def broadcast_strand(key, idx, txns, txids, start):
        n = len(txns)
        if start >= n:
            log(f"  strand[{key}_{idx}] already complete")
            return True
        log(f"  strand[{key}_{idx}] resuming from knot {start} ({n - start} remaining)")
        i = start
        while i < n:
            wave_end = min(i + MEMPOOL_ANCESTOR_LIMIT, n)
            for j in range(i, wave_end):
                try:
                    rpc_request("sendrawtransaction", [txns[j]])
                except Exception as e:
                    # Could be "already in mempool" / "already known" — log and continue
                    msg = str(e)
                    if "already" in msg.lower() or "duplicate" in msg.lower():
                        pass  # ok
                    else:
                        log(f"  strand[{key}_{idx}] knot {j} FAILED: {e}")
                        return False
            log(f"  strand[{key}_{idx}] wave sent: knots {i}..{wave_end-1} ({wave_end}/{n})")
            if wave_end < n:
                anchor = txids[wave_end - 1]
                elapsed = 0
                while elapsed < 1500:
                    try:
                        t = rpc_request("gettransaction", [anchor])
                        if t.get("confirmations", 0) > 0:
                            break
                    except Exception:
                        pass
                    time.sleep(15)
                    elapsed += 15
                else:
                    log(f"  *** strand[{key}_{idx}] anchor wait timed out ***")
                    return False
                log(f"  strand[{key}_{idx}] anchor knot {wave_end-1} confirmed ({elapsed}s)")
            i = wave_end
        log(f"  strand[{key}_{idx}] DONE (terminus {txids[-1][:16]}…)")
        return True

    threads = []
    for (key, idx), (txns, txids, start) in strand_lookup.items():
        if start >= len(txns):
            continue
        t = threading.Thread(
            target=broadcast_strand,
            args=(key, idx, txns, txids, start),
            name=f"{key}_{idx}",
        )
        t.start()
        threads.append(t)

    log(f"\nspawned {len(threads)} broadcast threads")
    for t in threads:
        t.join()
    log("\nall strand threads finished")

# ---- Phase B: mega-join broadcast ----------------------------------------
join_hex  = (ARTIFACTS / "megajoin.hex").read_text().strip()
join_txid = (ARTIFACTS / "megajoin.txid").read_text().strip()

# First check whether mega-join is already broadcast
try:
    t = rpc_request("gettransaction", [join_txid])
    log(f"\nmega-join {join_txid[:16]}… already on chain (confs={t.get('confirmations',0)})")
except Exception:
    log(f"\nbroadcasting mega-join {join_txid[:16]}…")
    try:
        returned = rpc_request("sendrawtransaction", [join_hex])
        assert returned == join_txid, f"got {returned}"
        log(f"  ✓ mega-join sent")
        # wait for it to confirm
        elapsed = 0
        while elapsed < 1500:
            try:
                t = rpc_request("gettransaction", [join_txid])
                if t.get("confirmations", 0) > 0:
                    log(f"  ✓ mega-join confirmed ({elapsed}s)")
                    break
            except Exception:
                pass
            time.sleep(15)
            elapsed += 15
        else:
            log(f"  *** mega-join confirmation wait timed out ***")
    except Exception as e:
        log(f"  *** mega-join broadcast FAILED: {e} ***")

log("\n" + "=" * 72)
log("RESUME BROADCAST DONE")
log("=" * 72)
LOG_FILE.close()
