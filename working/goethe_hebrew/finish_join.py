"""Wait for all 17 strand termini to confirm, then broadcast the mega-join.

The earlier broadcast failed with `too-long-mempool-chain` because the image
strand termini were still in mempool with 354 ancestors each. Once they're
confirmed (mined into a block), the mega-join's ancestor chain becomes empty
and it can broadcast cleanly.
"""
import os, sys, time
from pathlib import Path

THIS_DIR = Path(__file__).parent
PROJECT  = THIS_DIR.parent.parent
sys.path.insert(0, str(PROJECT))

from colegio_tools import rpc_request

ARTIFACTS = THIS_DIR / "artifacts"
LOG_PATH  = THIS_DIR / "finish.log"
LOG_FILE  = open(LOG_PATH, "a", buffering=1)

def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    LOG_FILE.write(line + "\n")
    LOG_FILE.flush()
    os.fsync(LOG_FILE.fileno())
    print(line, flush=True)

# Find all strand termini = last txid in each strand_*.txids
termini = []
for p in sorted(ARTIFACTS.glob("strand_*.txids")):
    txids = p.read_text().splitlines()
    termini.append((p.stem, txids[-1]))

log(f"waiting for {len(termini)} strand termini to confirm…")

POLL = 30
MAX  = 1800
elapsed = 0
while elapsed < MAX:
    confs_per = []
    for label, txid in termini:
        try:
            t = rpc_request("gettransaction", [txid])
            confs_per.append((label, t.get("confirmations", 0)))
        except Exception:
            confs_per.append((label, -1))
    n_confirmed = sum(1 for _, c in confs_per if c > 0)
    n_total     = len(confs_per)
    log(f"  {n_confirmed}/{n_total} termini confirmed   (elapsed {elapsed}s)")
    if n_confirmed == n_total:
        break
    # show which are still pending
    pending = [l for l, c in confs_per if c <= 0]
    if len(pending) <= 8:
        log(f"  pending: {pending}")
    time.sleep(POLL)
    elapsed += POLL
else:
    log("*** termini did not all confirm in time ***")
    sys.exit(1)

log("all strand termini confirmed — broadcasting mega-join")

join_hex  = (ARTIFACTS / "megajoin.hex").read_text().strip()
join_txid = (ARTIFACTS / "megajoin.txid").read_text().strip()

# Check if already on chain (idempotent)
try:
    t = rpc_request("gettransaction", [join_txid])
    log(f"mega-join already on chain (confs={t.get('confirmations',0)})")
except Exception:
    returned = rpc_request("sendrawtransaction", [join_hex])
    assert returned == join_txid, f"got {returned}"
    log(f"✓ mega-join broadcast: {join_txid}")

# Wait for join to confirm
elapsed = 0
while elapsed < 600:
    try:
        t = rpc_request("gettransaction", [join_txid])
        if t.get("confirmations", 0) > 0:
            log(f"✓ mega-join confirmed in {elapsed}s")
            break
    except Exception:
        pass
    time.sleep(15)
    elapsed += 15
else:
    log("*** mega-join not confirmed in time ***")
    sys.exit(1)

log("\n" + "=" * 60)
log("ALL DONE. The corpus is on chain.")
log("=" * 60)
LOG_FILE.close()
