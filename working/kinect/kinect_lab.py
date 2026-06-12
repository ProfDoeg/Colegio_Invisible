#!/usr/bin/env python3
"""Kinect editing lab — scrub, filter, composite, and label a recorded take.

Separate from the capture studio: this opens a finished take (depth.bin +
rgb.bin) with random access and is where the take becomes a dancer —
tuning the mask/filter chain, compositing masked colour, and dropping
labelled breadcrumbs that become the graph's pose-label nodes.

  view modes:   rgb · depth · mask · masked-colour · depth-shaded · overlay
  filter chain: depth band → open → close/hole-fill → largest-blob
  breadcrumbs:  {frame,label} saved to <take>/breadcrumbs.json — these are
                the labelled key-poses the 0xda graph layer cuts on.

Run:   python3 kinect_lab.py /path/to/take_dir [port]
View:  http://<host>:8786
"""
import io
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import numpy as np
from PIL import Image, ImageDraw

try:
    import scipy.ndimage as ndi
    HAVE_SCIPY = True
except ImportError:
    HAVE_SCIPY = False

W, Hgt = 640, 480
TAKE = sys.argv[1] if len(sys.argv) > 1 else None
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8786

meta = json.load(open(os.path.join(TAKE, "meta.json")))
ND = meta["depth_frames"]
NR = meta["rgb_frames"]
N = min(ND, NR)
FPS = 30
depth = np.memmap(os.path.join(TAKE, "depth.bin"), dtype=np.uint16, mode="r",
                  shape=(ND, Hgt, W))
rgb = (np.memmap(os.path.join(TAKE, "rgb.bin"), dtype=np.uint8, mode="r",
                 shape=(NR, Hgt, W, 3)) if os.path.exists(os.path.join(TAKE, "rgb.bin"))
       else None)
CRUMBS = os.path.join(TAKE, "breadcrumbs.json")
BG_PATH = os.path.join(TAKE, "bg_plate.npy")
RGBBG_PATH = os.path.join(TAKE, "bg_rgb.npy")

# background plates — built from an empty-room range. DEPTH plate gives the
# solid body; RGB plate recovers what the IR laser scatters off (hair, dark
# or shiny cloth) in a thin collar around the depth body.
BG = np.load(BG_PATH) if os.path.exists(BG_PATH) else None
RGBBG = np.load(RGBBG_PATH) if os.path.exists(RGBBG_PATH) else None
BG_MARGIN = 300.0
RGB_THRESH = 38.0          # per-pixel colour distance from empty-room plate
HAIR_COLLAR = 22           # px dilation ring around the depth body for RGB votes


def build_bg(a, b):
    """Build depth + RGB background plates from frames [a,b] (subject OUT of
    frame). Depth = per-pixel median valid depth (static surface). RGB =
    per-pixel median colour (empty room), used only inside the body collar."""
    global BG, RGBBG
    a, b = max(0, min(a, b)), min(N, max(a, b) + 1)
    samp = np.stack([depth[f] for f in range(a, b)]).astype(np.float32)
    samp[samp == 0] = np.nan
    bg = np.nanmedian(samp, axis=0)
    BG = np.where(np.isnan(bg), 65535, bg).astype(np.float32)
    np.save(BG_PATH, BG)
    if rgb is not None:
        rs = np.stack([rgb[f] for f in range(a, b)]).astype(np.float32)
        RGBBG = np.median(rs, axis=0).astype(np.float32)
        np.save(RGBBG_PATH, RGBBG)
    return int(b - a), float(np.median(BG[BG < 65535]))


def _mask(d, near, far, open_i, close_i, blob, col=None):
    body = (d > near) & (d <= far) & (d > 0)
    if BG is not None:                        # drop anything not closer than the
        body &= d < (BG - BG_MARGIN)          # static background (couch, wall…)

    if HAVE_SCIPY:
        if open_i:
            body = ndi.binary_opening(body, iterations=open_i)
        if close_i:
            body = ndi.binary_closing(body, iterations=close_i)
            body = ndi.binary_fill_holes(body)
        if blob and body.any():
            lbl, n = ndi.label(body)
            if n > 1:
                body = lbl == (1 + int(np.argmax(ndi.sum(body, lbl, range(1, n + 1)))))

        # hair / IR-scatter recovery: RGB only votes INSIDE a collar around the
        # depth body, and only to ADD. Far-field RGB false positives (shadows,
        # couch) never enter the collar, so the depth body stays authoritative.
        if RGBBG is not None and col is not None and body.any():
            collar = ndi.binary_dilation(body, iterations=HAIR_COLLAR) & ~body
            diff = np.sqrt(((col.astype(np.float32) - RGBBG) ** 2).sum(-1))
            hair = collar & (diff > RGB_THRESH)
            m = body | hair
            m = ndi.binary_closing(m, iterations=2)
            m = ndi.binary_fill_holes(m)
            if blob and m.any():
                lbl, n = ndi.label(m)
                if n > 1:
                    m = lbl == (1 + int(np.argmax(ndi.sum(m, lbl, range(1, n + 1)))))
            return m
        return body
    return body


def _density(frames, p):
    """Accumulated, normalised mask envelope of a set of frames (0..1) —
    the pose prototype: where all crumbs of a label consistently sit."""
    acc = np.zeros((Hgt, W), np.float32)
    n = 0
    for gf in frames[:60]:                 # cap cost
        if 0 <= gf < N:
            acc += _mask(depth[gf].astype(np.float32), p["near"], p["far"],
                         p["open"], p["close"], p["blob"])
            n += 1
    if n:
        acc /= acc.max() if acc.max() > 0 else 1.0
    return acc


def render(i, p):
    i = max(0, min(N - 1, i))
    d = depth[i].astype(np.float32)
    near, far = p["near"], p["far"]
    col = rgb[i] if rgb is not None else np.zeros((Hgt, W, 3), np.uint8)
    m = _mask(d, near, far, p["open"], p["close"], p["blob"], col=col)
    mode = p["mode"]

    if mode == "rgb":
        out = col.copy()
    elif mode == "depth":
        t = np.clip((d - 500) / 4000, 0, 1)
        g = ((1 - t) * 255).astype(np.uint8); g[d <= 0] = 0
        out = np.stack([g] * 3, -1)
    elif mode == "mask":
        out = (m[..., None] * np.uint8(255)).repeat(3, 2)
    elif mode == "masked":               # masked colour — the dancer cutout
        out = np.where(m[..., None], col, 0)
    elif mode == "shaded":               # silhouette shaded by depth band
        t = np.clip((d - near) / max(far - near, 1), 0, 1)
        g = np.zeros((Hgt, W), np.uint8); g[m] = ((1 - t[m]) * 255).astype(np.uint8)
        out = np.stack([g] * 3, -1)
    else:                                # overlay: colour dimmed, figure lit
        out = (col * 0.35).astype(np.uint8)
        out[m] = col[m]

    # onion-skin envelope: cyan density of all same-label crumbs, painted
    # OUTSIDE the current figure so the live silhouette stays crisp — align
    # the figure into the hot zone to keep the pose cluster consistent.
    ghost = p.get("ghost")
    if ghost:
        dens = _density(ghost, p)
        out = out.astype(np.float32)
        a = (dens * 0.65)[..., None] * (~m)[..., None]
        tint = np.array([0, 200, 255], np.float32)
        out = out * (1 - a) + tint * a
        # warm outline where the current figure spills OUTSIDE the envelope
        spill = m & (dens < 0.15)
        out[spill] = np.array([255, 90, 40], np.float32)
        out = out.clip(0, 255).astype(np.uint8)

    img = Image.fromarray(out)
    if p["mirror"]:
        img = img.transpose(Image.FLIP_LEFT_RIGHT)
    dd = ImageDraw.Draw(img)
    lab = "  ghost:%d" % len(ghost) if ghost else ""
    dd.text((6, 5), "f%d  %.1fs  cov %.1f%%%s" % (i, i / FPS, 100 * m.mean(), lab),
            fill=(255, 220, 80))
    buf = io.BytesIO(); img.save(buf, "JPEG", quality=80)
    return buf.getvalue()


SYM_NAME = {1: "normal", 2: "flipped", 3: "symmetric"}   # 0xda sym = n-1


def load_crumbs():
    if os.path.exists(CRUMBS):
        try:
            c = json.load(open(CRUMBS))
            for x in c:                       # back-compat: default sym=normal
                x.setdefault("sym", 1)
            return c
        except Exception:
            return []
    return []


def save_crumbs(c):
    c = sorted(c, key=lambda x: x["frame"])
    json.dump(c, open(CRUMBS, "w"), indent=1)
    _write_precrumb(c)
    return c


def _write_precrumb(c):
    """Emit avatar_maker precrumb format: `idx, label sym frame;` — one per
    crumb, ordered by frame. Round-trips with the 2009 *_precrumb.txt files
    and feeds the auto-map / 0xda graph build."""
    lines = []
    for i, x in enumerate(c, 1):
        lines.append("%d, %s %d %d;" % (i, x["label"], int(x.get("sym", 1)), x["frame"]))
    with open(os.path.join(TAKE, "precrumb.txt"), "w") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


PAGE = """<!doctype html><html><head><title>Kinect lab — %TAKE%</title><style>
body{background:#111;color:#ddd;font-family:Menlo,monospace;margin:12px}
#wrap{position:relative;display:inline-block}
img{width:800px;image-rendering:pixelated;border:1px solid #333;display:block}
.row{margin:8px 0}label{color:#999;margin-right:3px}
input[type=number]{width:64px;background:#222;color:#eee;border:1px solid #444;padding:2px}
input[type=range]{vertical-align:middle}
button{padding:5px 12px;margin-right:6px;background:#2a2a2a;color:#eee;border:1px solid #555;cursor:pointer;border-radius:3px}
select{background:#222;color:#eee;border:1px solid #444;padding:3px}
#scrub{width:800px}
#crumbs{margin-top:8px}.crumb{display:inline-block;background:#223;border:1px solid #446;
 padding:2px 8px;margin:2px;border-radius:3px;cursor:pointer}
.tick{position:absolute;bottom:0;width:2px;height:10px;background:#ff5050}
#bar{position:relative;width:800px;height:10px;background:#222;margin-top:2px}
</style></head><body>
<div id=wrap><img id=v></div>
<div id=bar></div>
<input id=scrub type=range min=0 max=%N% value=0 step=1>
<div class=row>
 <button id=play onclick=tog()>▶ play</button>
 <span id=pos></span>
 <label>mode</label><select id=mode onchange=draw()>
   <option value=masked>masked colour</option>
   <option value=overlay>overlay</option>
   <option value=rgb>rgb</option>
   <option value=depth>depth</option>
   <option value=mask>mask</option>
   <option value=shaded>depth-shaded</option>
 </select>
 <label><input type=checkbox id=mir checked onchange=draw()>mirror</label>
</div>
<div class=row>
 <label>near</label><input id=near type=number value=2200 step=50 onchange=draw()>
 <label>far</label><input id=far type=number value=3300 step=50 onchange=draw()>
 <label>open</label><input id=open type=number value=1 min=0 max=4 onchange=draw()>
 <label>close/fill</label><input id=close type=number value=1 min=0 max=6 onchange=draw()>
 <label><input type=checkbox id=blob checked onchange=draw()>largest blob</label>
</div>
<div class=row>
 <label>pose</label><input id=lbl list=vocab autocomplete=off
   style="width:150px;background:#222;color:#eee;border:1px solid #444"
   placeholder="label (Tab to drop)">
 <datalist id=vocab></datalist>
 <label>sym</label>
 <span id=symsel>
  <button class=sym data-s=1 onclick=setSym(1)>1 normal</button>
  <button class=sym data-s=2 onclick=setSym(2)>2 flipped</button>
  <button class=sym data-s=3 onclick=setSym(3)>3 symmetric</button>
 </span>
 <button id=drop onclick=addCrumb()>● drop @ playhead</button>
 <label><input type=checkbox id=onion checked onchange=draw()>onion-skin envelope</label>
 <button onclick=saveCrumbs()>save</button>
 <button onclick=resetCrumbs() style="background:#5a1111">reset all</button>
 <span id=msg style="color:#8c8"></span>
</div>
<div class=row style="border-top:1px solid #333;padding-top:8px">
 <b style="color:#9bf">background</b> (subject OUT of frame) —
 <button onclick=bgMark('a')>set start @here</button>
 <button onclick=bgMark('b')>set end @here</button>
 <span id=bgrange style="color:#9bf"></span>
 <button id=buildbg onclick=buildBg() style="background:#1a3a5a">build plate</button>
 <button onclick=clearBg()>clear plate</button>
 <span id=bgmsg style="color:#8c8"></span>
</div>
<div class=row style="color:#777;font-size:12px">
 keys: <b>space</b> play/pause · <b>← →</b> step frame · <b>1/2/3</b> sym ·
 <b>type label + Enter</b> drops a crumb at the playhead and reuses the last label on Enter-again
</div>
<div id=crumbs></div>
<style>.sym{padding:3px 8px}.sym.on{background:#446;border-color:#88a}
.crumb.s2{background:#322;border-color:#644}.crumb.s3{background:#232;border-color:#464}</style>
<script>
const $=id=>document.getElementById(id);
let cur=0, playing=false, crumbs=[], sym=1, lastLabel='';
let bgA=null, bgB=null;
const N=%N%;
function bgMark(which){if(which==='a')bgA=cur; else bgB=cur;
 $('bgrange').textContent=(bgA!=null?`start ${bgA} (${(bgA/30).toFixed(1)}s)`:'start —')+
  '  ·  '+(bgB!=null?`end ${bgB} (${(bgB/30).toFixed(1)}s)`:'end —');drawBar()}
async function buildBg(){if(bgA==null||bgB==null){$('bgmsg').textContent='set start AND end first';return}
 $('bgmsg').textContent='building plate…';
 const r=await(await fetch('/buildbg',{method:'POST',body:JSON.stringify({a:bgA,b:bgB})})).json();
 $('bgmsg').textContent=`plate built from ${r.frames} frames (bg ≈ ${r.bg_med}mm) — couch should be gone`;draw()}
async function clearBg(){await fetch('/clearbg',{method:'POST'});$('bgmsg').textContent='plate cleared';draw()}
function activeLabel(){return ($('lbl').value.trim()||lastLabel)}
function ghostFrames(){if(!$('onion').checked)return '';
 const l=activeLabel();if(!l)return '';
 const fs=crumbs.filter(c=>c.label===l).map(c=>c.frame);
 return fs.length?('&ghost='+fs.join(',')):''}
function params(){return `near=${$('near').value}&far=${$('far').value}&open=${$('open').value}`+
 `&close=${$('close').value}&blob=${$('blob').checked?1:0}&mode=${$('mode').value}&mirror=${$('mir').checked?1:0}`}
function draw(){$('v').src=`/frame?i=${cur}&${params()}${ghostFrames()}&_=${Date.now()}`;
 const l=activeLabel(),n=l?crumbs.filter(c=>c.label===l).length:0;
 $('pos').textContent=`f ${cur}/${N} (${(cur/30).toFixed(1)}s)`+(l?`  ·  envelope: ${l} ×${n}`:'')}
$('scrub').addEventListener('input',e=>{cur=+e.target.value;draw()});
function tog(){playing=!playing;$('play').textContent=playing?'⏸ pause':'▶ play';if(playing)loop()}
function loop(){if(!playing)return;cur=(cur+1)%N;$('scrub').value=cur;draw();setTimeout(loop,66)}
function setSym(s){sym=s;[...document.querySelectorAll('.sym')].forEach(b=>
 b.classList.toggle('on',+b.dataset.s===s))}
function vocabList(){return [...new Set(crumbs.map(c=>c.label))].sort()}
function refreshVocab(){$('vocab').innerHTML=vocabList().map(l=>`<option value="${l}">`).join('')}
function addCrumb(){let l=$('lbl').value.trim()||lastLabel||('pose'+crumbs.length);
 const ex=crumbs.findIndex(c=>c.frame===cur);
 if(ex>=0){const o=crumbs[ex];
   if(!confirm(`A breadcrumb already exists at f${cur}: "${o.label}·${o.sym}".\n`+
     `OK = overwrite with "${l}·${sym}", Cancel = keep it.`)){
     $('msg').textContent=`kept ${o.label}·${o.sym} @f${cur}`;return}
   crumbs.splice(ex,1)}
 lastLabel=l; crumbs.push({frame:cur,label:l,sym:sym});
 renderCrumbs();refreshVocab();draw();
 $('msg').textContent=`${ex>=0?'↻ overwrote':'+'} ${l} (${['','normal','flipped','symmetric'][sym]}) @f${cur}`}
function resetCrumbs(){if(!crumbs.length){$('msg').textContent='no breadcrumbs to reset';return}
 if(!confirm(`Delete ALL ${crumbs.length} breadcrumbs? This cannot be undone (save to persist).`))return;
 crumbs=[];lastLabel='';renderCrumbs();refreshVocab();draw();$('msg').textContent='reset — all breadcrumbs cleared'}
function drawBar(){let h=crumbs.map(c=>`<div class=tick style="left:${800*c.frame/N}px"></div>`).join('');
 if(bgA!=null&&bgB!=null){const x0=800*Math.min(bgA,bgB)/N,w=800*Math.abs(bgB-bgA)/N;
  h+=`<div style="position:absolute;bottom:0;left:${x0}px;width:${w}px;height:10px;background:rgba(80,140,255,.5)"></div>`}
 $('bar').innerHTML=h}
function renderCrumbs(){crumbs.sort((a,b)=>a.frame-b.frame);
 $('crumbs').innerHTML=crumbs.map((c,k)=>`<span class="crumb s${c.sym}" onclick='goto(${c.frame})'>`+
  `${c.label}·${c.sym} @${(c.frame/30).toFixed(1)}s <b onclick='event.stopPropagation();delCrumb(${k})'>×</b></span>`).join('');
 drawBar()}
function goto(f){cur=f;$('scrub').value=f;draw()}
function delCrumb(k){crumbs.splice(k,1);renderCrumbs();refreshVocab()}
async function saveCrumbs(){const r=await(await fetch('/crumbs',{method:'POST',
 body:JSON.stringify(crumbs)})).json();
 $('msg').textContent=`saved ${r.n} crumbs → breadcrumbs.json + precrumb.txt`}
$('lbl').addEventListener('input',draw);   // envelope updates as you type the pose
document.addEventListener('keydown',e=>{
 if(e.target===$('lbl')){if(e.key==='Enter'){addCrumb();draw()}return}
 if(e.key===' '){e.preventDefault();tog()}
 else if(e.key==='ArrowRight'){playing=false;cur=Math.min(N,cur+1);$('scrub').value=cur;draw()}
 else if(e.key==='ArrowLeft'){playing=false;cur=Math.max(0,cur-1);$('scrub').value=cur;draw()}
 else if(e.key==='1'||e.key==='2'||e.key==='3')setSym(+e.key)});
async function init(){crumbs=await(await fetch('/crumbs')).json();
 setSym(1);renderCrumbs();refreshVocab();draw()}
init();
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/":
            body = PAGE.replace("%N%", str(N - 1)).replace("%TAKE%", os.path.basename(TAKE)).encode()
            self.send_response(200); self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)
        elif u.path == "/frame":
            ghost = [int(x) for x in q.get("ghost", "").split(",") if x.strip().lstrip("-").isdigit()]
            p = {"near": float(q.get("near", 2200)), "far": float(q.get("far", 3300)),
                 "open": int(q.get("open", 1)), "close": int(q.get("close", 1)),
                 "blob": q.get("blob", "1") == "1", "mode": q.get("mode", "masked"),
                 "mirror": q.get("mirror", "1") == "1", "ghost": ghost}
            j = render(int(q.get("i", 0)), p)
            self.send_response(200); self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(j))); self.end_headers()
            self.wfile.write(j)
        elif u.path == "/crumbs":
            b = json.dumps(load_crumbs()).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers()
            self.wfile.write(b)
        else:
            self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n) if n else b""
        if path == "/crumbs":
            saved = save_crumbs(json.loads(raw or b"[]"))
            self._json({"ok": True, "n": len(saved)})
        elif path == "/buildbg":
            q = json.loads(raw or b"{}")
            nf, med = build_bg(int(q["a"]), int(q["b"]))
            self._json({"ok": True, "frames": nf, "bg_med": round(med)})
        elif path == "/clearbg":
            global BG, RGBBG
            BG = None
            RGBBG = None
            for p in (BG_PATH, RGBBG_PATH):
                if os.path.exists(p):
                    os.remove(p)
            self._json({"ok": True})
        else:
            self.send_error(404)


if __name__ == "__main__":
    if not TAKE:
        sys.exit("usage: kinect_lab.py <take_dir> [port]")
    print("lab on :%d  take=%s  frames=%d  rgb=%s  scipy=%s"
          % (PORT, os.path.basename(TAKE), N, rgb is not None, HAVE_SCIPY), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
