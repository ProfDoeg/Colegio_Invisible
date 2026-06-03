#!/usr/bin/env python3
"""The Loom — publish a quipu and watch it being woven onto the chain.

Two panels, side by side:
  · QUIPU — the inscription as strands of knots (circles): root -> N strands ->
            join. Each knot is pending (faint), in mempool (amber), or confirmed
            in a colour matching the block that wove it.
  · BLOCKS — one horizontal bar per block, coloured to match the knots it carried,
            length = knots woven, labelled with height / fullness / fee. The shared
            colour shows exactly which knots went into which block.
  · top strip — weave progress + live Dogecoin network stats.

Modes:
  sim  (default) — drive a simulated broadcast + block arrivals (node down ok).
  rpc           — watch a real broadcast against a live dogecoind (hooks below).

Run:  .venv/bin/python quipu_loom.py        # sim, Jeremy-sized, :8799
"""
import os, sys, json, time, threading, http.server, socketserver, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", "8799"))
MODE = os.environ.get("MODE", "sim")

KNOTS      = int(os.environ.get("KNOTS", "22306"))      # body knots (Jeremy footage)
STRANDS    = int(os.environ.get("STRANDS", "64"))       # fewer = bigger, legible circles
TIP_DOGE   = float(os.environ.get("TIP", "0.05"))       # DOGE per tx
START_H    = int(os.environ.get("START_H", "6229800"))  # next block height
BLOCK_SEC  = float(os.environ.get("BLOCK_SEC", "2.4"))  # demo block cadence
KPSPB      = int(os.environ.get("KPSPB", "26"))         # knots per strand each block
BLOCKKNOTS = int(os.environ.get("BLOCKKNOTS", str(KPSPB * STRANDS)))  # exact -> even per strand
BLOCK_CAP  = 1_000_000                                   # ~1 MB Dogecoin block
OURTX_BYTES = 280                                        # one knot tx ~ bytes


def distribute(total, n):
    return [total // n + (1 if i < total % n else 0) for i in range(n)]


def _rle(col):
    """Run-length encode a strand's knots -> [[value, count], ...] (one entry per
    run of same state, i.e. one circle per block-colour with a count)."""
    out = []
    for v in col:
        if out and out[-1][0] == v:
            out[-1][1] += 1
        else:
            out.append([v, 1])
    return out


# ---------------------------------------------------------------------------
# Live Dogecoin network (chain stats for the top strip)
# ---------------------------------------------------------------------------

CHAIN = {"stats": {}, "agg": {}, "ok": False, "err": "", "updated": 0}


def _getjson(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    return json.load(urllib.request.urlopen(req, timeout=25))


def chain_poller():
    while True:
        try:
            raw = _getjson("https://api.blockchair.com/dogecoin/blocks?limit=20&s=id(desc)")["data"]
            tot_fees = sum((r["fee_total"] or 0) / 1e8 for r in raw)
            tot_size = sum(r["size"] for r in raw) or 1
            st = _getjson("https://api.blockchair.com/dogecoin/stats").get("data", {})
            CHAIN["stats"] = {"height": st.get("blocks"), "mempool_tx": st.get("mempool_transactions"),
                              "tx_24h": st.get("transactions_24h"), "blocks_24h": st.get("blocks_24h")}
            CHAIN["agg"] = {"avg_fee_kb": round(tot_fees / tot_size * 1000, 4),
                            "avg_full": round(sum(min(1.0, r["size"] / BLOCK_CAP) for r in raw) / len(raw), 4)}
            CHAIN["ok"] = True; CHAIN["err"] = ""
        except Exception as e:
            CHAIN["ok"] = False; CHAIN["err"] = str(e)[:120]
        CHAIN["updated"] = time.time()
        time.sleep(30)


# ---------------------------------------------------------------------------
# The Loom — tracks which block confirmed each knot
# ---------------------------------------------------------------------------

class Loom:
    """grid[s][k]: 0 pending · 1 mempool · b+2 confirmed in block index b."""
    def __init__(self):
        self.n = STRANDS
        self.per = distribute(KNOTS, self.n)
        self.maxper = max(self.per) if self.per else 0
        self.total_knots = KNOTS
        self.grid = [[0] * p for p in self.per]
        self.bptr = [0] * self.n
        self.cptr = [0] * self.n
        self.root = "pending"; self.join = "pending"
        self.root_block = -1; self.join_block = -1
        self.blocks = []
        self.h2b = {}   # height->block index; was only created in load_plan, so the progress driver (which skips load_plan when STRANDS/KNOTS already match) crashed in block_for_height every tick and the loom never painted
        self.phase = "idle"; self.height = START_H - 1
        self.t0 = None; self.lock = threading.Lock()

    def broadcast_more(self, knots):
        with self.lock:
            left = knots; progress = True
            while left > 0 and progress:
                progress = False
                for s in range(self.n):
                    if left <= 0: break
                    if self.bptr[s] < self.per[s]:
                        self.grid[s][self.bptr[s]] = 1; self.bptr[s] += 1; left -= 1; progress = True

    def land_block(self, height, wove, h="", full=None, txs=None, fee_kb=None):
        with self.lock:
            bidx = len(self.blocks); left = wove; count = 0; progress = True
            while left > 0 and progress:
                progress = False
                for s in range(self.n):
                    if left <= 0: break
                    if self.cptr[s] < self.bptr[s]:
                        self.grid[s][self.cptr[s]] = bidx + 2; self.cptr[s] += 1; left -= 1; count += 1; progress = True
            if self.root == "mempool": self.root = "confirmed"; self.root_block = bidx; count += 1
            if self.join == "mempool": self.join = "confirmed"; self.join_block = bidx; count += 1
            self.height = height
            ob = count * OURTX_BYTES
            self.blocks.append({"idx": bidx, "height": height, "time": time.strftime("%H:%M:%S"),
                                "knots": count, "hash": h,
                                "full": full if full is not None else round(min(1.0, ob / BLOCK_CAP), 4),
                                "txs": txs if txs is not None else count,
                                "fee_kb": fee_kb if fee_kb is not None else round(TIP_DOGE / (OURTX_BYTES / 1000.0), 3)})

    def all_confirmed(self):
        with self.lock:
            return sum(1 for col in self.grid for v in col if v >= 2) >= self.total_knots

    # ---- rpc plan + confirmation (drive from real txids) ----
    def load_plan(self, strands_txids, root_txid="", join_txid="", strands_hexes=None):
        with self.lock:
            self.n = len(strands_txids)
            self.per = [len(t) for t in strands_txids]
            self.maxper = max(self.per) if self.per else 0
            self.total_knots = sum(self.per)
            self.grid = [[0] * p for p in self.per]
            self.txids = strands_txids; self.hexes = strands_hexes
            self.root_txid = root_txid; self.join_txid = join_txid
            self.h2b = {}; self.blocks = []
            self.root = "pending"; self.join = "pending"

    def block_for_height(self, h, size=None, txs=None):
        if h in self.h2b:
            return self.h2b[h]
        bidx = len(self.blocks)
        self.blocks.append({"idx": bidx, "height": h, "time": time.strftime("%H:%M:%S"),
                            "knots": 0, "hash": "",
                            "full": round(min(1.0, size / BLOCK_CAP), 4) if size else None,
                            "txs": txs, "fee_kb": None})
        self.h2b[h] = bidx; self.height = max(self.height, h)
        return bidx

    def confirm_knot(self, s, k, height, size=None, txs=None):
        with self.lock:
            bidx = self.block_for_height(height, size, txs)
            if self.grid[s][k] != bidx + 2:
                self.grid[s][k] = bidx + 2; self.blocks[bidx]["knots"] += 1

    def mark(self, s, k, v):
        with self.lock:
            self.grid[s][k] = v

    def reset(self):
        with self.lock:
            self.grid = [[0] * p for p in self.per]
            self.bptr = [0] * self.n; self.cptr = [0] * self.n
            self.root = "pending"; self.join = "pending"; self.root_block = -1; self.join_block = -1
            self.blocks = []; self.phase = "idle"; self.height = START_H - 1; self.t0 = None

    def state(self):
        with self.lock:
            conf = sum(1 for col in self.grid for v in col if v >= 2)
            mem  = sum(1 for col in self.grid for v in col if v == 1)
            pend = self.total_knots - conf - mem
            done = conf + (1 if self.root == "confirmed" else 0) + (1 if self.join == "confirmed" else 0)
            elapsed = (time.time() - self.t0) / 60 if self.t0 else 0
            rate = conf / elapsed if elapsed > 0.05 else 0
            eta = (self.total_knots - conf) / rate if rate > 0 else None
            strands_done = sum(1 for col in self.grid if col and all(v >= 2 for v in col))
            runs = [_rle(g) for g in self.grid]
            maxruns = max((len(r) for r in runs), default=1)
            net = CHAIN.get("stats", {}); ag = CHAIN.get("agg", {})
            return {
                "mode": MODE, "phase": self.phase, "n": self.n, "maxruns": maxruns,
                "runs": runs, "root": self.root, "join": self.join,
                "root_block": self.root_block, "join_block": self.join_block,
                "total_knots": self.total_knots, "total_tx": self.total_knots + 2,
                "confirmed_knots": conf, "mempool_knots": mem, "pending_knots": pend,
                "strands_done": strands_done, "height": self.height, "blocks": self.blocks,
                "spent_doge": round(done * TIP_DOGE, 2), "budget_doge": round((self.total_knots + 2) * TIP_DOGE, 2),
                "rate_per_min": round(rate, 0), "eta_min": round(eta, 1) if eta is not None else None,
                "net": {"ok": CHAIN.get("ok"), "height": net.get("height"), "mempool_tx": net.get("mempool_tx"),
                        "tx_24h": net.get("tx_24h"), "avg_fee_kb": ag.get("avg_fee_kb"), "avg_full": ag.get("avg_full")},
            }


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------

def sim_driver(loom):
    loop = os.environ.get("LOOP", "1") != "0"
    while True:
        loom.reset(); time.sleep(0.8); loom.t0 = time.time()
        loom.phase = "instantiate"; loom.root = "mempool"; h = START_H
        loom.land_block(h, 0, "%064x" % h); h += 1
        loom.phase = "fill"
        loom.broadcast_more(BLOCKKNOTS)                  # prime one block into mempool
        while not loom.all_confirmed():
            time.sleep(BLOCK_SEC)
            loom.land_block(h, BLOCKKNOTS, "%064x" % h); h += 1
            loom.broadcast_more(BLOCKKNOTS)              # keep ~one block queued, no balloon
        loom.phase = "close"; loom.join = "mempool"
        time.sleep(BLOCK_SEC); loom.land_block(h, 0, "%064x" % h)
        loom.phase = "done"
        if not loop: return
        time.sleep(7.0)


def _load_artifacts(art):
    """Read a staged inscription's per-strand txids (+ optional hexes) from a dir:
       strand_0.txids / strand_0.txns / ... plus optional root.txid, join.txid."""
    strands_txids, strands_hexes = [], []; i = 0
    while os.path.exists(os.path.join(art, "strand_%d.txids" % i)):
        strands_txids.append(open(os.path.join(art, "strand_%d.txids" % i)).read().split())
        hp = os.path.join(art, "strand_%d.txns" % i)
        strands_hexes.append(open(hp).read().split() if os.path.exists(hp) else None)
        i += 1
    def _rd(name):
        p = os.path.join(art, name)
        return open(p).read().strip() if os.path.exists(p) else ""
    have_hex = any(h for h in strands_hexes)
    return strands_txids, (strands_hexes if have_hex else None), _rd("root.txid"), _rd("join.txid")


def rpc_driver(loom):
    """Watch (and, with hexes, robustly re-broadcast) a real inscription against a
    live dogecoind. Tracks each knot chain-scoped via quipu_broadcast, so dropped-
    mempool txs are detected and re-sent. Set LOOM_ARTIFACTS to the staged dir."""
    import quipu_broadcast as qb
    art = os.environ.get("LOOM_ARTIFACTS", "")
    poll = int(os.environ.get("POLL", "15"))
    if not art or not os.path.isdir(art):
        loom.phase = "no artifacts (set LOOM_ARTIFACTS)"; return
    txids, hexes, root_txid, join_txid = _load_artifacts(art)
    if not txids:
        loom.phase = "no strands in artifacts"; return
    loom.load_plan(txids, root_txid, join_txid, hexes)
    loom.t0 = time.time(); loom.phase = "watching"; size_cache = {}
    while not loom.all_confirmed():
        try:
            for s, strand in enumerate(loom.txids):
                for k, txid in enumerate(strand):
                    if loom.grid[s][k] >= 2:          # already woven
                        continue
                    st, h = qb.tx_status(txid)
                    if st == "confirmed" and h is not None:
                        if h not in size_cache:
                            try:
                                bh = qb.rpc_request("getblockhash", [h]); blk = qb.rpc_request("getblock", [bh])
                                size_cache[h] = (blk.get("size"), blk.get("nTx") or len(blk.get("tx", [])))
                            except Exception:
                                size_cache[h] = (None, None)
                        loom.confirm_knot(s, k, h, *size_cache[h])
                    elif st == "mempool":
                        loom.mark(s, k, 1)
                    else:                              # unknown — dropped or not yet sent
                        if loom.hexes and loom.hexes[s] and os.environ.get("LOOM_BROADCAST") == "1":
                            r = qb.send_if_needed(loom.hexes[s][k], txid, "s%dk%d" % (s, k))
                            loom.mark(s, k, 1 if r in ("have", "sent") else 0)
                        else:
                            loom.mark(s, k, 0)   # watch-only (default): never send, just observe
            for which, txid in (("root", loom.root_txid), ("join", loom.join_txid)):
                if not txid: continue
                st, _ = qb.tx_status(txid)
                setattr(loom, which, "confirmed" if st == "confirmed" else
                        ("mempool" if st == "mempool" else "pending"))
        except Exception as e:
            print("[loom] rpc:", e)
        time.sleep(poll)
    loom.phase = "done"


def progress_driver(loom):
    """Render the weave from broadcast_jeremy.py's progress.json (no node polling
    of our own — the broadcaster owns the chain queries). One getblockcount per
    tick colours newly-confirmed knots by the block that landed."""
    import quipu_broadcast as qb
    PROG = os.path.join(os.environ.get("LOOM_ARTIFACTS", ""), "progress.json")
    loom.t0 = time.time(); loom.phase = "reading"; last_tip = None
    while True:
        try:
            p = json.load(open(PROG))
            if loom.n != p["n"] or sum(loom.per) != p["total"]:
                loom.load_plan([[""] * x for x in p["per"]])
            tip = None
            try: tip = qb.current_height()
            except Exception: pass
            with loom.lock:
                bidx = None
                if tip is not None:
                    bidx = loom.block_for_height(tip) if tip != last_tip else loom.h2b.get(tip)
                    last_tip = tip
                for s in range(min(loom.n, p["n"])):
                    cf, sn = p["conf"][s], p["sent"][s]
                    col = loom.grid[s]
                    for k in range(len(col)):
                        if k < cf:
                            if col[k] < 2:
                                if bidx is not None:
                                    col[k] = bidx + 2; loom.blocks[bidx]["knots"] += 1
                                else:
                                    col[k] = 2
                        elif k < sn:
                            col[k] = 1
                        else:
                            col[k] = 0
                loom.phase = p.get("phase", "reading")
                loom.root = "confirmed" if p.get("root_conf") else ("mempool" if p.get("root") else "pending")
                loom.join = "confirmed" if p.get("phase") == "done" else "pending"
        except Exception:
            pass
        time.sleep(2)


LOOM = Loom()

HTML = r"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>the loom</title>
<style>
 :root{--gold:#c2a76b;--ky:#e8b73a;--soft:#888477}
 html,body{margin:0;height:100%;background:#15130e;color:#e9e2cf;font:13px/1.4 -apple-system,Helvetica,sans-serif;overflow:hidden}
 #top{height:56px;display:flex;align-items:center;gap:16px;padding:0 18px;background:#1d1a13;border-bottom:1px solid #332e22}
 #top h1{font:600 15px/1 Georgia,serif;color:var(--gold);margin:0;white-space:nowrap}
 .phase{display:inline-block;padding:1px 9px;border-radius:9px;background:var(--gold);color:#1a1a1a;font-weight:600;font-size:11px}
 #pwrap{width:300px} .bar{height:9px;background:#2a261c;border-radius:5px;overflow:hidden}
 .bar>i{display:block;height:100%;background:linear-gradient(90deg,var(--ky),var(--gold));width:0%}
 .chips{display:flex;gap:15px;flex-wrap:wrap;font-variant-numeric:tabular-nums;font-size:12px}
 .chip .l{color:var(--soft);font-size:10px;text-transform:uppercase;letter-spacing:.04em;margin-right:5px}
 .chip b{color:var(--gold)}
 #main{display:flex;height:calc(100vh - 56px)}
 #quipu{flex:1;position:relative} canvas{display:block;width:100%;height:100%}
 #blocks{width:340px;background:#1a1711;border-left:1px solid #332e22;overflow:auto;padding:12px 14px}
 #blocks h2{font:600 12px/1 Georgia,serif;color:var(--gold);margin:0 0 10px}
 .blk{margin-bottom:8px} .blk.fresh .barb{box-shadow:0 0 0 2px var(--ky)}
 .blk .hd{display:flex;justify-content:space-between;font-size:11px;color:var(--soft);margin-bottom:2px}
 .blk .hd .h{color:var(--ky);font-variant-numeric:tabular-nums}
 .barb{height:18px;border-radius:4px;position:relative;overflow:hidden;background:#241f16}
 .barb>i{display:block;height:100%} .barb>span{position:absolute;left:7px;top:0;line-height:18px;font-size:11px;color:#15130e;font-weight:700}
</style></head><body>
<div id="top">
 <h1>the loom</h1><span class="phase" id="phase">idle</span>
 <div id="pwrap"><div class="bar"><i id="pbar"></i></div></div>
 <div class="chips" id="chips"></div>
</div>
<div id="main">
 <div id="quipu"><canvas id="c"></canvas></div>
 <div id="blocks"><h2>blocks &middot; knots woven in each</h2><div id="blist"></div></div>
</div>
<script>
const c=document.getElementById('c'), x=c.getContext('2d');
let DPR=Math.min(2,devicePixelRatio||1), S=null, lastH=null;
function resize(){c.width=Math.max(1,c.clientWidth*DPR);c.height=Math.max(1,c.clientHeight*DPR); if(S)draw();}
addEventListener('resize',resize);
function blkColor(b){return 'hsl('+((b*53)%360)+',58%,60%)';}
function fmt(n){return (n==null?'—':n.toLocaleString());}
function draw(){
 if(!S)return; const W=c.width,H=c.height; x.fillStyle='#15130e'; x.fillRect(0,0,W,H);
 const n=S.n, rows=S.maxruns||1, padX=26*DPR, padTop=46*DPR, padBot=42*DPR;
 const gw=(W-2*padX)/n, gh=(H-padTop-padBot)/rows, d=Math.min(gw,gh), r=Math.max(1.2,d*0.46);
 const showN = d>=13*DPR;                         // room for a count badge
 x.textAlign='center'; x.textBaseline='middle'; x.font=(Math.round(r*1.0))+'px -apple-system,sans-serif';
 x.fillStyle='#3a3320'; x.fillRect(padX,padTop-18*DPR,W-2*padX,3*DPR);
 x.fillStyle=S.root==='confirmed'?blkColor(S.root_block):(S.root==='mempool'?'#e8b73a':'#5a533f');
 x.beginPath();x.arc(W/2,padTop-30*DPR,6*DPR,0,7);x.fill();
 for(let s=0;s<n;s++){ const runs=S.runs[s].slice().reverse(), cx=padX+gw*(s+0.5);
   for(let j=0;j<runs.length;j++){ const v=runs[j][0], cnt=runs[j][1], cy=padTop+gh*(j+0.5);
     x.fillStyle = v===0?'#2a261c' : (v===1?'#e8b73a' : blkColor(v-2));
     x.beginPath(); x.arc(cx,cy,r,0,7); x.fill();
     if(showN && cnt>1){ x.fillStyle = v===0?'#9a9279':'#15130e'; x.fillText(cnt, cx, cy+0.5*DPR); }
   } }
 x.fillStyle='#3a3320'; x.fillRect(padX,H-padBot+15*DPR,W-2*padX,3*DPR);
 x.fillStyle=S.join==='confirmed'?blkColor(S.join_block):(S.join==='mempool'?'#e8b73a':'#5a533f');
 x.beginPath();x.arc(W/2,H-padBot+27*DPR,6*DPR,0,7);x.fill();
}
async function poll(){
 try{ S=await (await fetch('/state')).json();
  document.getElementById('phase').textContent=S.phase;
  document.getElementById('pbar').style.width=(100*S.confirmed_knots/S.total_knots).toFixed(1)+'%';
  const net=S.net||{};
  document.getElementById('chips').innerHTML=[
   ['woven',fmt(S.confirmed_knots)+' / '+fmt(S.total_knots)],['mempool',fmt(S.mempool_knots)],
   ['strands',S.strands_done+'/'+S.n],['spent',S.spent_doge+' / '+S.budget_doge+' Ɖ'],
   ['rate',S.rate_per_min?fmt(S.rate_per_min)+'/min':'—'],['eta',S.eta_min!=null?S.eta_min+'m':'—'],
   ['net height',fmt(net.height)],['net mempool',fmt(net.mempool_tx)],
   ['net fee/kB',net.avg_fee_kb!=null?net.avg_fee_kb+' Ɖ':'—'],
   ['net full',net.avg_full!=null?(100*net.avg_full).toFixed(2)+'%':'—'],
  ].map(p=>'<span class="chip"><span class="l">'+p[0]+'</span><b>'+p[1]+'</b></span>').join('');
  const bl=S.blocks, maxk=Math.max(1,...bl.map(b=>b.knots));
  document.getElementById('blist').innerHTML=bl.slice().reverse().map((b,i)=>{
   const meta=(b.full!=null?' · '+(100*b.full).toFixed(1)+'% full':'')+(b.fee_kb!=null?' · '+b.fee_kb+' Ɖ/kB':'');
   return '<div class="blk'+(i===0&&b.height!==lastH?' fresh':'')+'">'
   +'<div class="hd"><span class="h">#'+b.height+'</span><span>'+b.time+meta+'</span></div>'
   +'<div class="barb"><i style="width:'+(100*b.knots/maxk).toFixed(1)+'%;background:'+blkColor(b.idx)+'"></i><span>+'+fmt(b.knots)+' knots</span></div></div>';
  }).join('');
  if(bl.length) lastH=bl[bl.length-1].height;
  draw();
 }catch(e){}
 setTimeout(poll,900);
}
resize(); poll();
</script></body></html>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path.startswith("/state"):
            body = json.dumps(LOOM.state()).encode(); ctype = "application/json"
        else:
            body = HTML.encode(); ctype = "text/html"
        self.send_response(200); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)


def main():
    drv = {"sim": sim_driver, "rpc": rpc_driver, "progress": progress_driver}.get(MODE, sim_driver)
    threading.Thread(target=drv, args=(LOOM,), daemon=True).start()
    threading.Thread(target=chain_poller, daemon=True).start()
    socketserver.TCPServer.allow_reuse_address = True
    print("loom: %s · %d knots · %d strands · ~%.0f DOGE budget" % (MODE, KNOTS, STRANDS, (KNOTS + 2) * TIP_DOGE))
    print("open  http://localhost:%d/" % PORT)
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()
