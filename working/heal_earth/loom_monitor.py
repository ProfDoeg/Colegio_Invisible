#!/usr/bin/env python3
"""Live loom for the heal_earth broadcast (coasts & lakes), as textile weaving.

  warp threads = strands   (178, grouped under their 17 quipus)
  weft passes  = blocks    (each block sweeps the knots it confirmed)
  knot dots    = strand txs (filled when woven into a block, hollow when pending)

Reads working/lineage/artifacts/ (splitter/roots/strands/megajoin txids), polls
the local node directly (chain-scoped, robust to wallet/mempool gaps), and serves
an auto-refreshing page. Watch-only: it never broadcasts. Stops when the mega-join
confirms.

  .venv/bin/python working/lineage/loom_monitor.py        # http://localhost:8765/
"""
import os, sys, time, threading, http.server, socketserver
from pathlib import Path
from collections import defaultdict

THIS_DIR = Path(__file__).parent
PROJECT  = THIS_DIR.parent.parent
sys.path.insert(0, str(PROJECT)); sys.path.insert(0, str(THIS_DIR))

import warnings; warnings.filterwarnings("ignore")
from colegio_tools import rpc_request
LOOM_PIECE = os.environ.get("LOOM_PIECE", "earth_combined")
LOOM_TITLE = os.environ.get("LOOM_TITLE", "Earth — the Italian Journey upon the world's coasts and lakes")
PIECES = [(LOOM_PIECE, "earth", "hope")]
NAMES = {LOOM_PIECE: LOOM_TITLE}

ARTIFACTS = Path(os.environ.get("LOOM_ARTIFACTS", THIS_DIR / "artifacts" / "diamond_combined"))
OUT       = THIS_DIR / "loom.html"
PORT      = int(os.environ.get("PORT", "8765"))
POLL_INTERVAL = int(os.environ.get("POLL", "20"))
QUIPU_KEYS = [pid for pid, *_ in PIECES]

TONE_COLOR = {"hope": "#2f8f6f", "reverence": "#b8860b", "play": "#6a9a4a", "seeking": "#5d8aa8",
              "lust": "#a8432a", "grief": "#5a6b7a", "ordinary": "#8a7a5a"}
QUIPU_COLORS = {pid: TONE_COLOR.get(tone, "#8a4a3a") for pid, _, tone, *_ in PIECES}
QUIPU_LABELS = {pid: NAMES.get(pid, pid) for pid, *_ in PIECES}

splitter_txid = (ARTIFACTS / "splitter.txid").read_text().strip()
megajoin_txid = (ARTIFACTS / "megajoin.txid").read_text().strip()
root_txids    = {k: (ARTIFACTS / f"root_{k}.txid").read_text().strip() for k in QUIPU_KEYS}
quipu_strands = {}
for k in QUIPU_KEYS:
    s, idx = [], 0
    while (ARTIFACTS / f"strand_{k}_{idx}.txids").exists():
        s.append((ARTIFACTS / f"strand_{k}_{idx}.txids").read_text().splitlines()); idx += 1
    quipu_strands[k] = s
total_strands = sum(len(s) for s in quipu_strands.values())
total_knots   = sum(sum(len(ids) for ids in s) for s in quipu_strands.values())
print(f"loom: {len(QUIPU_KEYS)} quipus, {total_strands} strands, {total_knots} knots, port {PORT}")

def query_block(txid):
    try:
        raw = rpc_request("getrawtransaction", [txid, 1])
        bh = raw.get("blockhash")
        if not bh:
            return -1            # in mempool, not yet mined
        return rpc_request("getblock", [bh])["height"]
    except Exception:
        return None              # unknown

def poll_all():
    sb = query_block(splitter_txid)
    rb = {k: query_block(t) for k, t in root_txids.items()}
    ks = {}
    for k in QUIPU_KEYS:
        for si, ids in enumerate(quipu_strands[k]):
            for ki, txid in enumerate(ids):
                ks[(k, si, ki)] = query_block(txid)
    return ks, sb, rb, query_block(megajoin_txid)

CSS = """
body{background:#faf7f2;color:#1f1d1a;font-family:"Iowan Old Style",Charter,Georgia,serif;margin:0;padding:22px 30px 60px;line-height:1.4}
h1{font-size:1.5rem;margin:0 0 2px;color:#8a4a3a}
.subtitle{color:#6b665e;font-size:.9rem;margin:0 0 18px;font-style:italic}
.summary{background:#f3eee5;border:1px solid #d8d2c6;border-radius:4px;padding:10px 14px;margin:0 0 18px;font:12px/1.5 "SF Mono",Menlo,monospace;color:#4a3829}
.summary b{color:#8a4a3a}
.loom{display:flex;gap:26px;align-items:flex-start;margin:0 0 24px;overflow-x:auto;flex-wrap:wrap}
.quipu-title{font-size:.7rem;color:#6b665e;margin:0 0 5px;font-family:"SF Mono",Menlo,monospace}
.fabric{border:1px solid #d8d2c6;background:#fcfaf5;padding:4px;border-radius:2px}
.row{display:flex;gap:2px;height:8px;margin-bottom:1px;align-items:center}
.cell{width:8px;height:8px;border-radius:50%;background:transparent;border:1px solid #c8c2b6;box-sizing:border-box}
.cell.mempool{background:transparent;border:2px solid #e8b73a}
.cell.confirmed{background:var(--qc,#8a4a3a);border-color:var(--qc,#8a4a3a)}
.cell.empty{border-color:transparent}
.footer{margin-top:30px;padding-top:12px;border-top:1px solid #d8d2c6;font:10px/1.5 "SF Mono",Menlo,monospace;color:#6b665e;word-break:break-all}
.footer .label{color:#aaa}
"""

def render(ks, sb, rb, mj, started):
    confirmed = sum(1 for v in ks.values() if v is not None and v >= 0)
    mempool   = sum(1 for v in ks.values() if v == -1)
    elapsed   = int(time.time() - started); mm, ss = divmod(elapsed, 60)
    blocks_seen = defaultdict(int)
    for v in ks.values():
        if v is not None and v >= 0:
            blocks_seen[v] += 1
    fabrics = []
    for k in QUIPU_KEYS:
        strands = quipu_strands[k]; depth = max(len(s) for s in strands)
        rows = []
        for ki in range(depth):
            cells = []
            for si, ids in enumerate(strands):
                if ki < len(ids):
                    b = ks.get((k, si, ki))
                    cls = "cell confirmed" if (b is not None and b >= 0) else ("cell mempool" if b == -1 else "cell")
                    cells.append(f'<div class="{cls}"></div>')
                else:
                    cells.append('<div class="cell empty"></div>')
            rows.append(f'<div class="row">{"".join(cells)}</div>')
        fabrics.append(
            f'<div style="--qc:{QUIPU_COLORS[k]}"><div class="quipu-title">{QUIPU_LABELS[k][:22]} '
            f'({len(strands)}s)</div><div class="fabric">{"".join(rows)}</div></div>')
    if mj is not None and mj >= 0:
        status = f'<b>DONE</b> · mega-join woven into block {mj}'; refresh = ''
    else:
        status = (f'<b>{confirmed}/{len(ks)}</b> knots woven · {mempool} in mempool · '
                  f'{len(ks)-confirmed-mempool} pending · {mm}m{ss:02d}s')
        refresh = f'<meta http-equiv="refresh" content="{POLL_INTERVAL}">'
    bsum = " · ".join(f"#{h}:{n}" for h, n in sorted(blocks_seen.items())) or "(none yet)"
    rl = "".join(
        f'<div><span class="label">root[{k}]</span> {root_txids[k]} · '
        f'{("block "+str(rb[k])) if (rb[k] is not None and rb[k]>=0) else ("mempool" if rb[k]==-1 else "PENDING")}</div>'
        for k in QUIPU_KEYS)
    sl = ("block "+str(sb)) if (sb is not None and sb >= 0) else ("mempool" if sb == -1 else "PENDING")
    ml = ("block "+str(mj)) if (mj is not None and mj >= 0) else ("mempool" if mj == -1 else "pending termini")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">{refresh}
<title>gana loom — {confirmed}/{len(ks)}</title><style>{CSS}</style></head><body>
<h1>The Gana forest · loom</h1>
<div class="subtitle">17 quipus, {total_strands} strands, {total_knots} knots. Each warp thread is one strand; each knot is one transaction.<br>
<span style="font-family:'SF Mono',Menlo,monospace;font-size:.8rem">○ pending&nbsp;&nbsp;◌ <span style="color:#c79320">amber ring = in mempool (sent)</span>&nbsp;&nbsp;● solid = woven into a block (confirmed)</span></div>
<div class="summary">{status} · blocks: {bsum}</div>
<div class="loom">{"".join(fabrics)}</div>
<div class="footer">
<div><span class="label">splitter</span> {splitter_txid} · {sl}</div>{rl}
<div><span class="label">mega-join</span> {megajoin_txid} · {ml}</div>
<div style="margin-top:6px;color:#aaa">auto-refresh {POLL_INTERVAL}s · polled {time.strftime('%H:%M:%S')}</div>
</div></body></html>"""

# ---- serve loom.html in the background ------------------------------------
class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k): super().__init__(*a, directory=str(THIS_DIR), **k)
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path in ("/", ""):
            self.path = "/loom.html"
        return super().do_GET()

OUT.write_text("<html><body>starting…</body></html>", encoding="utf-8")
socketserver.ThreadingTCPServer.allow_reuse_address = True
srv = socketserver.ThreadingTCPServer(("127.0.0.1", PORT), Handler)
srv.daemon_threads = True
threading.Thread(target=srv.serve_forever, daemon=True).start()
print(f"serving http://localhost:{PORT}/")

started = time.time()
while True:
    ks, sb, rb, mj = poll_all()
    OUT.write_text(render(ks, sb, rb, mj, started), encoding="utf-8")
    done = sum(1 for v in ks.values() if v is not None and v >= 0)
    print(f"[{time.strftime('%H:%M:%S')}] {done}/{len(ks)} confirmed · mega-join: {'block '+str(mj) if (mj is not None and mj>=0) else 'pending'}")
    if mj is not None and mj >= 0:
        print("DONE — mega-join confirmed."); break
    time.sleep(POLL_INTERVAL)
