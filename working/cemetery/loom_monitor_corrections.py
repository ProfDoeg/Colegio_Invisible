"""Live status monitor for the consolidated cementerio broadcast,
visualized as textile weaving.

  warp threads  = strands       (vertical, 66 of them)
  weft passes   = blocks        (horizontal, each block sweeps across
                                 the knots it confirmed)
  knot dots     = strand txs    (terracotta when woven into a block,
                                 hollow when still pending)

Writes loom.html every POLL_INTERVAL seconds; the page auto-refreshes
itself in the browser. Open at http://localhost:8765/loom.html.

Stops automatically when every knot + mega-join is confirmed.
"""
import os, sys, time
from pathlib import Path
from collections import defaultdict

THIS_DIR = Path(__file__).parent
PROJECT  = THIS_DIR.parent.parent
sys.path.insert(0, str(PROJECT))

import warnings; warnings.filterwarnings("ignore")
from colegio_tools import rpc_request

ARTIFACTS = THIS_DIR / "corrections_artifacts"
OUT       = THIS_DIR / "loom_corrections.html"
QUIPU_KEYS = ["binding", "essay"]
POLL_INTERVAL = 4  # seconds — small inscription, can poll faster


# ---- Load artifact metadata ------------------------------------------------
splitter_txid = (ARTIFACTS / "splitter.txid").read_text().strip()
megajoin_txid = (ARTIFACTS / "megajoin.txid").read_text().strip()
root_txids    = {k: (ARTIFACTS / f"root_{k}.txid").read_text().strip() for k in QUIPU_KEYS}

# Build matrix: per-quipu list of (strand_index, [knot_txids])
quipu_strands = {}
for k in QUIPU_KEYS:
    strands = []
    idx = 0
    while (ARTIFACTS / f"strand_{k}_{idx}.txids").exists():
        ids = (ARTIFACTS / f"strand_{k}_{idx}.txids").read_text().splitlines()
        strands.append(ids)
        idx += 1
    quipu_strands[k] = strands

total_strands = sum(len(s) for s in quipu_strands.values())
total_knots   = sum(sum(len(ids) for ids in s) for s in quipu_strands.values())
max_strand_len = max(len(ids) for s in quipu_strands.values() for ids in s)

print(f"monitor: {len(QUIPU_KEYS)} quipus, {total_strands} strands, "
      f"{total_knots} knots, max strand depth {max_strand_len}")


# ---- Chain state polling ---------------------------------------------------
def query_block(txid):
    """Return block_height of confirming block, or None if unconfirmed/missing.
    Uses chain-scoped getrawtransaction directly (wallet-scoped gettransaction
    misses txs broadcast via sendrawtransaction from external builders)."""
    try:
        raw = rpc_request("getrawtransaction", [txid, 1])
        bh = raw.get("blockhash")
        if not bh:
            return None  # in mempool but not in a block yet
        blk = rpc_request("getblock", [bh])
        return blk["height"]
    except Exception:
        return None  # not found at all


def poll_all():
    """Return (knot_state, splitter_block, root_blocks, megajoin_block)
       where knot_state[(quipu_key, strand_idx, knot_idx)] = block_height or None."""
    splitter_block = query_block(splitter_txid)
    root_blocks    = {k: query_block(t) for k, t in root_txids.items()}
    knot_state     = {}
    for k in QUIPU_KEYS:
        for si, ids in enumerate(quipu_strands[k]):
            for ki, txid in enumerate(ids):
                knot_state[(k, si, ki)] = query_block(txid)
    megajoin_block = query_block(megajoin_txid)
    return knot_state, splitter_block, root_blocks, megajoin_block


# ---- HTML rendering --------------------------------------------------------
QUIPU_LABELS = {
    "binding": "Corrections binding (0xab)",
    "essay":   "Cementerio de los Animales (essay v2)",
}
QUIPU_COLORS = {
    "binding": "#a89860",  # warm tan (binding)
    "essay":   "#5d8aa8",  # blue (ordinary essay)
}

CSS = """
:root { color-scheme: light; }
body {
    background: #faf7f2;
    color: #1f1d1a;
    font-family: "Iowan Old Style", "Charter", Georgia, serif;
    margin: 0;
    padding: 24px 32px 64px;
    line-height: 1.4;
}
h1 {
    font-size: 1.6rem;
    font-weight: 600;
    margin: 0 0 4px;
    color: #8a4a3a;
}
.subtitle {
    color: #6b665e;
    font-size: 0.92rem;
    margin: 0 0 24px;
    font-style: italic;
}
.summary {
    background: #f3eee5;
    border: 1px solid #d8d2c6;
    border-radius: 4px;
    padding: 10px 14px;
    margin: 0 0 24px;
    font: 12px/1.5 "SF Mono", Menlo, monospace;
    color: #4a3829;
}
.summary b { color: #8a4a3a; }
.loom {
    display: flex;
    gap: 38px;
    align-items: flex-start;
    margin: 0 0 24px;
    overflow-x: auto;
}
.quipu {
    display: inline-block;
}
.quipu-title {
    font-size: 0.78rem;
    color: #6b665e;
    margin: 0 0 6px;
    font-family: "SF Mono", Menlo, monospace;
    letter-spacing: 0.04em;
}
.fabric {
    border: 1px solid #d8d2c6;
    background: #fcfaf5;
    padding: 4px;
    border-radius: 2px;
    position: relative;
}
.row {
    display: flex;
    gap: 2px;
    height: 9px;
    margin-bottom: 1px;
    align-items: center;
}
.cell {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: transparent;
    border: 1px solid #c8c2b6;
    box-sizing: border-box;
}
.cell.confirmed {
    background: var(--quipu-color, #8a4a3a);
    border-color: var(--quipu-color, #8a4a3a);
    box-shadow: 0 0 0 1px rgba(0,0,0,0.06);
}
.cell.empty {
    border-color: transparent;
}
.row-label {
    font: 9px "SF Mono", Menlo, monospace;
    color: #aaa;
    margin-right: 6px;
    width: 20px;
    text-align: right;
}
.weft-line {
    position: absolute;
    left: 0; right: 0;
    height: 1px;
    background: #c97e6e;
    opacity: 0.35;
    pointer-events: none;
}
.weft-label {
    position: absolute;
    right: -56px;
    font: 9px "SF Mono", Menlo, monospace;
    color: #c97e6e;
    transform: translateY(-50%);
    white-space: nowrap;
}
.legend {
    color: #6b665e;
    font-size: 0.75rem;
    font-family: "SF Mono", Menlo, monospace;
    margin: 0 0 16px;
}
.legend .swatch {
    display: inline-block;
    width: 10px; height: 10px;
    border-radius: 50%;
    margin: 0 6px 0 14px;
    vertical-align: -1px;
}
.legend .swatch.confirmed { background: #8a4a3a; }
.legend .swatch.pending {
    background: transparent; border: 1px solid #c8c2b6;
}
.footer {
    margin-top: 36px;
    padding-top: 14px;
    border-top: 1px solid #d8d2c6;
    font: 10px/1.5 "SF Mono", Menlo, monospace;
    color: #6b665e;
    word-break: break-all;
}
.footer .label { color: #aaa; }
.footer a { color: #c97e6e; text-decoration: none; }
"""

def render_html(knot_state, splitter_block, root_blocks, megajoin_block, started_at):
    confirmed = sum(1 for v in knot_state.values() if v is not None)
    pending   = len(knot_state) - confirmed
    elapsed   = int(time.time() - started_at)
    mm, ss    = divmod(elapsed, 60)

    # Group blocks: which block heights have at least one of our knots
    blocks_seen = defaultdict(int)
    for v in knot_state.values():
        if v is not None:
            blocks_seen[v] += 1

    # Build the fabric for each quipu
    fabrics = []
    for k in QUIPU_KEYS:
        strands = quipu_strands[k]
        max_depth = max(len(s) for s in strands)
        rows_html = []
        for ki in range(max_depth):
            cells = []
            for si, ids in enumerate(strands):
                if ki < len(ids):
                    block = knot_state.get((k, si, ki))
                    cls = "cell confirmed" if block is not None else "cell"
                    cells.append(f'<div class="{cls}"></div>')
                else:
                    cells.append('<div class="cell empty"></div>')
            label = f'<div class="row-label">{ki}</div>'
            rows_html.append(f'<div class="row">{label}{"".join(cells)}</div>')
        # Render any weft lines for blocks that included knots from this quipu
        n_strands = len(strands)
        fabric_width = n_strands * 11 + 28  # cell+gap +label
        fabrics.append(
            f'<div class="quipu" style="--quipu-color: {QUIPU_COLORS[k]}">'
            f'<div class="quipu-title">{QUIPU_LABELS[k]}  '
            f'({n_strands} strands × ≤{max_depth} knots)</div>'
            f'<div class="fabric" style="min-width:{fabric_width}px">'
            + "".join(rows_html) +
            '</div></div>'
        )

    # Summary line
    if megajoin_block:
        status = f'<b>DONE</b> · mega-join confirmed in block {megajoin_block}'
        refresh_meta = ''  # stop auto-refresh
    elif confirmed == len(knot_state) and all(root_blocks.values()) and splitter_block:
        status = f'<b>{confirmed}/{len(knot_state)}</b> knots confirmed · awaiting mega-join'
        refresh_meta = '<meta http-equiv="refresh" content="' + str(POLL_INTERVAL) + '">'
    else:
        status = (f'<b>{confirmed}/{len(knot_state)}</b> knots woven · '
                  f'{pending} still on the warp · elapsed {mm}m{ss:02d}s')
        refresh_meta = '<meta http-equiv="refresh" content="' + str(POLL_INTERVAL) + '">'

    block_summary = " · ".join(f"#{h}: {n} knots" for h, n in sorted(blocks_seen.items()))

    # Splitter + roots
    splitter_label = f'block {splitter_block}' if splitter_block else 'PENDING'
    root_lines = []
    for k in QUIPU_KEYS:
        b = root_blocks[k]
        root_lines.append(
            f'<div><span class="label">root[{k}]</span> '
            f'<a href="https://dogechain.info/tx/{root_txids[k]}" target="_blank">'
            f'{root_txids[k]}</a> · {"block " + str(b) if b else "PENDING"}</div>'
        )
    mj_label = (f'block {megajoin_block}' if megajoin_block else
                ('PENDING (waiting on termini)' if pending else 'READY TO BROADCAST'))

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
{refresh_meta}
<title>cementerio loom — {confirmed}/{len(knot_state)}</title>
<style>{CSS}</style>
</head>
<body>
<h1>Cementerio de los Animales · loom</h1>
<div class="subtitle">Each warp thread is one strand. Each knot is one transaction.
Knots fill in as blocks weave through them.</div>

<div class="summary">{status} · last block heights: {block_summary or '(none yet)'}</div>

<div class="legend">
  <span class="swatch confirmed"></span> woven (confirmed)
  <span class="swatch pending"></span> on the warp (pending)
</div>

<div class="loom">
  {"".join(fabrics)}
</div>

<div class="footer">
  <div><span class="label">splitter</span>
    <a href="https://dogechain.info/tx/{splitter_txid}" target="_blank">{splitter_txid}</a>
    · {splitter_label}</div>
  {"".join(root_lines)}
  <div><span class="label">mega-join</span>
    <a href="https://dogechain.info/tx/{megajoin_txid}" target="_blank">{megajoin_txid}</a>
    · {mj_label}</div>
  <div style="margin-top:8px;color:#aaa">
    auto-refresh every {POLL_INTERVAL}s · polled at {time.strftime('%H:%M:%S')}
  </div>
</div>
</body>
</html>
"""

# ---- Main loop -------------------------------------------------------------
started = time.time()
while True:
    ks, sb, rb, mj = poll_all()
    OUT.write_text(render_html(ks, sb, rb, mj, started), encoding="utf-8")
    confirmed = sum(1 for v in ks.values() if v is not None)
    print(f"[{time.strftime('%H:%M:%S')}] {confirmed}/{len(ks)} confirmed · "
          f"mega-join: {'block ' + str(mj) if mj else 'pending'}")
    if mj:
        print("DONE — mega-join confirmed; exiting monitor")
        break
    time.sleep(POLL_INTERVAL)
