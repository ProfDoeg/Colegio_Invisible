#!/usr/bin/env python3
"""Keyless broadcaster for the signed Jeremy diamond. No private key — it only
sends pre-signed hexes from working/jeremy_stage/artifacts/.

  root -> wait confirm -> strand knots in ancestor-safe rounds -> join

Robust: idempotent sends (send_with_retry), confirmed-frontier tracking per
strand (binary search), and drop-recovery (a strand stuck with in-flight knots
gets its window re-sent). Writes progress.json each round for the loom.

  .venv/bin/python working/jeremy_stage/broadcast_jeremy.py
"""
import os, sys, json, time, socket
socket.setdefaulttimeout(45)          # so a stalled node RPC can't hang us forever
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import quipu_broadcast as qb
from quipu_orchestrator import _txid_of_serial

ART  = os.path.join(os.path.dirname(__file__), "artifacts")
PROG = os.path.join(ART, "progress.json")
ANCESTOR = int(os.environ.get("ANCESTOR", "24"))
POLL     = int(os.environ.get("POLL", "20"))
rd = lambda f: open(os.path.join(ART, f)).read().strip()

root_hex, root_txid = rd("root.txn"), rd("root.txid")
join_hex, join_txid = rd("join.txn"), rd("join.txid")
N = 0
while os.path.exists(os.path.join(ART, "strand_%d.txns" % N)): N += 1
strands = [open(os.path.join(ART, "strand_%d.txns" % i)).read().split() for i in range(N)]
ids = [[_txid_of_serial(h) for h in s] for s in strands]      # local txids, no RPC
PER = [len(s) for s in strands]; TOTAL = sum(PER)
sent = [0]*N; conf = [0]*N; stuck = [0]*N
log = lambda m: print("[%s] %s" % (time.strftime("%H:%M:%S"), m), flush=True)

def write_progress(phase):
    json.dump({"phase": phase, "n": N, "per": PER, "sent": sent, "conf": conf,
               "root": root_txid, "join": join_txid, "confirmed": sum(conf),
               "sent_total": sum(sent), "total": TOTAL,
               "root_conf": qb.query_block(root_txid) is not None if phase != "root" else False},
              open(PROG, "w"))

def frontier(s):
    lo, hi, last = conf[s], sent[s]-1, conf[s]-1
    while lo <= hi:
        mid = (lo+hi)//2
        if qb.tx_status(ids[s][mid])[0] == "confirmed":
            last = mid; lo = mid+1
        else:
            hi = mid-1
    return last+1

log("Jeremy broadcast — %d strands, %d knots" % (N, TOTAL))
# 1. root
log("root: %s" % qb.send_if_needed(root_hex, root_txid, "root")); write_progress("root")
log("waiting for root to confirm…")
while qb.query_block(root_txid) is None:
    time.sleep(POLL)
log("root confirmed")

# resume from chain state — don't re-send knots the node already knows
log("scanning frontier to resume…")
for s in range(N):
    sent[s] = qb.find_resume_index(ids[s])      # known (confirmed or mempool) frontier
for s in range(N):
    conf[s] = frontier(s)                       # confirmed frontier
log("resumed: sent %d · confirmed %d / %d" % (sum(sent), sum(conf), TOTAL))

# 2. strand knots, ancestor-safe rounds
rnd = 0
while sum(conf) < TOTAL:
    rnd += 1
    for s in range(N):
        prev = conf[s]
        while sent[s] < PER[s] and (sent[s]-conf[s]) < ANCESTOR:
            if qb.send_with_retry(strands[s][sent[s]], "s%dk%d" % (s, sent[s])):
                sent[s] += 1
            else:
                break          # ancestor limit / not-yet-acceptable — retry next round
    for s in range(N):
        c = frontier(s)
        if c == conf[s] and sent[s] > conf[s]:
            stuck[s] += 1
            if stuck[s] >= 10:       # drop-recovery: only after ~3+ blocks of no progress
                sent[s] = conf[s]; stuck[s] = 0
        else:
            stuck[s] = 0
        conf[s] = c
    write_progress("fill")
    log("round %d: sent %d · confirmed %d / %d" % (rnd, sum(sent), sum(conf), TOTAL))
    if sum(conf) >= TOTAL:
        break
    time.sleep(POLL)

# 3. join
log("all knots confirmed — join: %s" % qb.send_if_needed(join_hex, join_txid, "join"))
write_progress("close")
while qb.query_block(join_txid) is None:
    time.sleep(POLL)
write_progress("done")
log("DONE — Jeremy is woven into the chain. join %s" % join_txid)
