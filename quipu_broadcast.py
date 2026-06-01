#!/usr/bin/env python3
"""Robust broadcast + chain-tracking primitives for quipu inscriptions.

Factored from the cemetery / goethe broadcasts. The robustness that matters for
a long, multi-thousand-tx campaign where mempool entries get dropped:

  · tx_status / query_block — read the CHAIN directly (getrawtransaction), since
    wallet-scoped gettransaction misses txs sent via sendrawtransaction. A tx
    that fell out of mempool without confirming reads as 'unknown'.
  · send_if_needed — idempotent: (re)broadcast ONLY when the node has forgotten
    the tx. This is how a dropped-mempool knot gets re-woven.
  · send_with_retry — concurrency-capped, backed-off, 'already in mempool' = ok.
  · find_resume_index — binary-search how far a dead broadcast got, to resume.
"""
import os, sys, time, random, threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from colegio_tools import rpc_request

SEND_SEMAPHORE = threading.Semaphore(int(os.environ.get("SEND_CONCURRENCY", "4")))


def current_height():
    return rpc_request("getblockcount", [])


def tx_status(txid):
    """('confirmed', height) | ('mempool', None) | ('unknown', None).

    Chain-scoped so it is robust to (a) the wallet not knowing sendraw'd txs and
    (b) a tx being dropped from mempool — that reads as 'unknown', the signal to
    re-broadcast."""
    try:
        raw = rpc_request("getrawtransaction", [txid, 1])
    except Exception:
        return ("unknown", None)
    bh = raw.get("blockhash")
    if not bh:
        return ("mempool", None)
    try:
        return ("confirmed", rpc_request("getblock", [bh])["height"])
    except Exception:
        return ("confirmed", None)


def query_block(txid):
    """Confirming block height, or None if unconfirmed/unknown."""
    st, h = tx_status(txid)
    return h if st == "confirmed" else None


def on_chain_with_confs(txid):
    """Confirmations (0 = in mempool), or None if the node has forgotten the tx."""
    st, h = tx_status(txid)
    if st == "unknown":
        return None
    if st == "mempool":
        return 0
    try:
        return (current_height() - h + 1) if h is not None else 1
    except Exception:
        return 1


def send_with_retry(hex_str, label="tx", max_attempts=12):
    """sendrawtransaction with a concurrency cap + backoff on transient
    work-queue/connection errors. 'already in mempool/chain' counts as success."""
    delay = 0.4
    for _ in range(max_attempts):
        with SEND_SEMAPHORE:
            try:
                rpc_request("sendrawtransaction", [hex_str]); return True
            except Exception as e:
                msg = str(e).lower()
                if "already" in msg or "duplicate" in msg:
                    return True
                if not any(k in msg for k in ("work queue", "depth exceeded",
                                              "connection", "timed out", "500")):
                    return False           # permanent (bad tx, etc.)
        time.sleep(delay + random.uniform(0, 0.3))
        delay = min(delay * 1.7, 8.0)
    return False


def send_if_needed(hex_str, txid, label="tx"):
    """Idempotent (re)broadcast: only send if the node has forgotten the tx.
    Returns 'have' (already known) | 'sent' | 'failed'."""
    if tx_status(txid)[0] != "unknown":
        return "have"
    return "sent" if send_with_retry(hex_str, label) else "failed"


def find_resume_index(txids):
    """Highest contiguous index the node already knows, +1 (where to resume)."""
    lo, hi, last = 0, len(txids) - 1, -1
    while lo <= hi:
        mid = (lo + hi) // 2
        if tx_status(txids[mid])[0] != "unknown":
            last = mid; lo = mid + 1
        else:
            hi = mid - 1
    return last + 1


if __name__ == "__main__":
    # smoke: import-only check (no node required to import)
    print("quipu_broadcast ok — tx_status/send_if_needed/send_with_retry/find_resume_index/query_block")
