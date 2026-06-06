"""BROADCAST the Gana forest (keyless) — thin wrapper over the canonical engine
(quipu_diamond.broadcast_consolidated_diamond). Idempotent + resumable; holds no
key. Logs to broadcast.log (fsync per line) so the supervisor + loom can follow.

  .venv/bin/python -u working/lineage/broadcast_consolidated.py
"""
import os, sys, time, threading
from pathlib import Path

THIS = Path(__file__).parent
REPO = THIS.parent.parent
sys.path.insert(0, str(REPO)); sys.path.insert(0, str(THIS))

import warnings; warnings.filterwarnings("ignore")
from quipu_diamond import broadcast_consolidated_diamond

_lock = threading.Lock()
_f = open(THIS / "broadcast.log", "a", buffering=1)
def log(msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    with _lock:
        _f.write(line + "\n"); _f.flush(); os.fsync(_f.fileno())
    print(line, flush=True)

broadcast_consolidated_diamond(str(THIS / "artifacts"), log=log,
                               strand_workers=int(os.environ.get("STRAND_WORKERS", "16")))
