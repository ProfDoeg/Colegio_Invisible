#!/usr/bin/env python3
"""Supervisor for the keyless Jeremy broadcaster. Keeps broadcast_jeremy.py alive
until the inscription is done (progress.json phase=="done").

Restart triggers:
  · the broadcaster process exits before phase=="done"  -> relaunch (it resumes
    losslessly from the on-chain frontier via find_resume_index)
  · progress.json goes stale (no write in STALL_S seconds) -> kill + relaunch,
    so a hung RPC can't freeze the weave forever

The broadcaster is idempotent + resumable, so killing/relaunching never double-
spends: it only (re)sends knots the node has forgotten. Keyless — no key here.

  .venv/bin/python working/jeremy_stage/supervise_jeremy.py
"""
import os, sys, json, time, signal, subprocess

HERE   = os.path.dirname(os.path.abspath(__file__))
ART    = os.path.join(HERE, "artifacts")
PROG   = os.path.join(ART, "progress.json")
BCAST  = os.path.join(HERE, "broadcast_jeremy.py")
PY     = sys.executable
STALL_S = int(os.environ.get("STALL_S", "150"))   # progress.json must move within this
POLL    = 10

log = lambda m: print("[SUPERVISOR %s] %s" % (time.strftime("%H:%M:%S"), m), flush=True)

def phase():
    try:
        return json.load(open(PROG)).get("phase")
    except Exception:
        return None

def launch():
    log("launching broadcaster")
    return subprocess.Popen([PY, BCAST], cwd=os.path.abspath(os.path.join(HERE, "..", "..")),
                            stdout=open(os.path.join(HERE, "broadcast.log"), "a"),
                            stderr=subprocess.STDOUT)

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
    ph = phase()
    if ph == "done":
        log("phase=done — inscription complete. exiting supervisor.")
        break
    # exited without finishing?
    if proc.poll() is not None:
        restarts += 1
        log("broadcaster exited (code %s) before done — restart #%d" % (proc.returncode, restarts))
        proc = launch()
        continue
    # stalled? (progress.json not written recently)
    try:
        age = time.time() - os.path.getmtime(PROG)
    except OSError:
        age = 0
    if age > STALL_S:
        restarts += 1
        log("progress stale %.0fs > %ds — kill + restart #%d" % (age, STALL_S, restarts))
        kill(proc)
        proc = launch()

log("supervisor done after %d restart(s)." % restarts)
