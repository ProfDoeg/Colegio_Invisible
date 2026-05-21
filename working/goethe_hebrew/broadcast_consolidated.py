"""Broadcast the precomputed consolidated 5-quipu inscription.

Order:
    1. splitter
    2. 5 per-quipu roots (parallel)
    3. all 17 strands, each in waves of 25 knots, parallel across strands
    4. mega-join

Reads precomputed tx hex from working/goethe_hebrew/artifacts/.
"""
import sys, time, threading, queue
from pathlib import Path

THIS_DIR = Path(__file__).parent
PROJECT = THIS_DIR.parent.parent
sys.path.insert(0, str(PROJECT))

from colegio_tools import rpc_request, MEMPOOL_ANCESTOR_LIMIT

ARTIFACTS = THIS_DIR / "artifacts"

QUIPU_KEYS = ["image", "essay", "dichtung", "fett", "juden"]

def load(key, suffix):
    return (ARTIFACTS / f"{key}.{suffix}").read_text().strip()

def load_strand(key, idx):
    txns  = (ARTIFACTS / f"strand_{key}_{idx}.txns").read_text().splitlines()
    txids = (ARTIFACTS / f"strand_{key}_{idx}.txids").read_text().splitlines()
    assert len(txns) == len(txids), f"strand {key}_{idx} length mismatch"
    return txns, txids

# Discover all strands
strand_lookup = {}  # (key, idx) -> (txns, txids)
for key in QUIPU_KEYS:
    idx = 0
    while True:
        p = ARTIFACTS / f"strand_{key}_{idx}.txns"
        if not p.exists():
            break
        strand_lookup[(key, idx)] = load_strand(key, idx)
        idx += 1

print(f"Found {len(strand_lookup)} strands; total knot txs: "
      f"{sum(len(t) for t,_ in strand_lookup.values())}")
print()

# ---- Step 1: splitter -----------------------------------------------------
splitter_hex  = load("splitter", "hex")
splitter_txid = load("splitter", "txid")
print(f"[1/4] Broadcasting splitter {splitter_txid[:16]}…")
returned = rpc_request("sendrawtransaction", [splitter_hex])
assert returned == splitter_txid, f"got {returned}"
print(f"      ✓ sent")

# Wait for splitter to confirm before broadcasting per-quipu roots
def wait_confirmed(txid, label, poll=15, max_wait=600):
    print(f"      waiting for {label} ({txid[:16]}…) to confirm…", end="", flush=True)
    elapsed = 0
    while elapsed < max_wait:
        try:
            t = rpc_request("gettransaction", [txid])
            if t.get("confirmations", 0) > 0:
                print(f" ✓ ({elapsed}s)")
                return
        except Exception:
            pass
        time.sleep(poll)
        elapsed += poll
        print(".", end="", flush=True)
    raise TimeoutError(f"{label} did not confirm in {max_wait}s")

wait_confirmed(splitter_txid, "splitter")

# ---- Step 2: 5 per-quipu roots --------------------------------------------
print()
print(f"[2/4] Broadcasting 5 per-quipu roots (parallel)…")
root_txids = {k: load(f"root_{k}", "txid") for k in QUIPU_KEYS}
for k in QUIPU_KEYS:
    hex_str = load(f"root_{k}", "hex")
    txid    = root_txids[k]
    returned = rpc_request("sendrawtransaction", [hex_str])
    assert returned == txid, f"root {k}: got {returned}"
    print(f"      ✓ root[{k:<10}] {txid[:16]}…")

# Wait for ALL 5 roots to confirm before pushing strands
for k in QUIPU_KEYS:
    wait_confirmed(root_txids[k], f"root[{k}]")

# ---- Step 3: 17 strands in parallel, each in waves of 25 ------------------
print()
print(f"[3/4] Broadcasting {len(strand_lookup)} strands in parallel waves of {MEMPOOL_ANCESTOR_LIMIT}…")

def broadcast_strand(key, idx, txns, txids, log_q):
    """Broadcast one strand in waves; log progress via queue."""
    n = len(txns)
    log_q.put(f"  strand[{key}_{idx}] {n} knots starting")
    i = 0
    while i < n:
        wave_end = min(i + MEMPOOL_ANCESTOR_LIMIT, n)
        for j in range(i, wave_end):
            rpc_request("sendrawtransaction", [txns[j]])
        log_q.put(f"  strand[{key}_{idx}] sent {wave_end}/{n}")
        if wave_end < n:
            # Wait for last sent to confirm before next wave
            anchor = txids[wave_end - 1]
            elapsed = 0
            while elapsed < 1200:
                try:
                    t = rpc_request("gettransaction", [anchor])
                    if t.get("confirmations", 0) > 0:
                        break
                except Exception:
                    pass
                time.sleep(15)
                elapsed += 15
            else:
                log_q.put(f"  *** strand[{key}_{idx}] anchor wait timed out ***")
                return False
        i = wave_end
    log_q.put(f"  strand[{key}_{idx}] DONE (terminus {txids[-1][:16]}…)")
    return True

log_q   = queue.Queue()
threads = []
for (key, idx), (txns, txids) in strand_lookup.items():
    t = threading.Thread(
        target=broadcast_strand,
        args=(key, idx, txns, txids, log_q),
    )
    t.start()
    threads.append(t)

# Drain log queue while threads run
done_count = 0
total = len(threads)
while done_count < total:
    alive = sum(1 for t in threads if t.is_alive())
    done_count = total - alive
    try:
        msg = log_q.get(timeout=10)
        print(msg)
    except queue.Empty:
        print(f"      [progress] {done_count}/{total} strands complete; {alive} running")

for t in threads:
    t.join()

# Drain remaining queue
while not log_q.empty():
    print(log_q.get())

print()
print("All strands broadcast and confirmed.")

# ---- Step 4: mega-join ----------------------------------------------------
print()
print(f"[4/4] Broadcasting mega-join…")
join_hex  = load("megajoin", "hex")
join_txid = load("megajoin", "txid")
returned = rpc_request("sendrawtransaction", [join_hex])
assert returned == join_txid, f"got {returned}"
print(f"      ✓ mega-join sent: {join_txid}")
wait_confirmed(join_txid, "mega-join")

print()
print("=" * 72)
print("ALL DONE. The corpus is on chain.")
print("=" * 72)
print(f"  splitter:           {splitter_txid}")
for k in QUIPU_KEYS:
    print(f"  root[{k:<10}]    {root_txids[k]}")
print(f"  mega-join:          {join_txid}")
print()
print(f"  Final 1.00 DOGE residual: {join_txid}:0  (back to apocrypha)")
