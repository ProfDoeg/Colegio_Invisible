#!/usr/bin/env python3
"""Supervisor for the keyless Gana-forest broadcaster. Keeps
broadcast_consolidated.py alive until "ALL DONE" appears in broadcast.log.

Restart triggers:
  · the broadcaster process exits before done            -> relaunch (resumes
    losslessly from the on-chain frontier)
  · broadcast.log goes stale (no write in STALL_S)        -> kill + relaunch,
    so a hung RPC can't freeze the weave forever

The broadcaster is idempotent + resumable, so kill/relaunch never double-spends.
Keyless — no private key anywhere here.

  nohup .venv/bin/python working/lineage/supervise_consolidated.py \
      > working/lineage/supervise.log 2>&1 &
"""
import os, sys, time, signal, subprocess

HERE  = os.path.dirname(os.path.abspath(__file__))
LOG   = os.path.join(HERE, "broadcast.log")
BCAST = os.path.join(HERE, "broadcast_consolidated.py")
ROOT  = os.path.abspath(os.path.join(HERE, "..", ".."))
PY    = sys.executable
DONE_MARK = "diamond closed"
STALL_S   = int(os.environ.get("STALL_S", "180"))
POLL      = 10

log = lambda m: print("[SUPERVISOR %s] %s" % (time.strftime("%H:%M:%S"), m), flush=True)

def is_done():
    try:
        with open(LOG) as f:
            return DONE_MARK in f.read()[-4000:]
    except Exception:
        return False

def launch():
    log("launching broadcaster")
    return subprocess.Popen([PY, "-u", BCAST], cwd=ROOT,
                            stdout=open(LOG, "a"), stderr=subprocess.STDOUT)

def kill(p):
    if p.poll() is not None:
        return
    p.send_signal(signal.SIGTERM)
    for _ in range(10):
        if p.poll() is not None:
            return
        time.sleep(0.5)
    p.kill()

proc = launch()
restarts = 0
while True:
    time.sleep(POLL)
    if is_done():
        log("done marker found — inscription complete. exiting supervisor.")
        break
    if proc.poll() is not None:
        if is_done():
            continue
        restarts += 1
        log("broadcaster exited (code %s) before done — restart #%d" % (proc.returncode, restarts))
        proc = launch(); continue
    try:
        age = time.time() - os.path.getmtime(LOG)
    except OSError:
        age = 0
    if age > STALL_S:
        restarts += 1
        log("log stale %.0fs > %ds — kill + restart #%d" % (age, STALL_S, restarts))
        kill(proc); proc = launch()

log("supervisor done after %d restart(s)." % restarts)
