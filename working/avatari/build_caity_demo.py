#!/usr/bin/env python3
"""Reconstruct the 2009 stage as a self-contained WebGL demo.

Builds caity_demo.html — a single file (Three.js via CDN, all art embedded as
base64) that recreates the Jitter stage: floor + curtain backdrop, caity as a
camera-facing billboard driven by her motion graph (nodes = tagged poses,
edges = time/space/displacement). Three live controls:

  * camera      — mouse orbit + wheel zoom
  * focal point — WASD moves the look-at / chase target on the floor
  * caity       — arrow keys steer her (read edges by displacement), or press
                  C to make her chase the focal point; 1/2/3 auto-play the
                  2009 control modes.

This is the controller reading the graph's displacement to actualise a path —
graph = possibility, controller = intention.

Run:  .venv/bin/python working/avatari/build_caity_demo.py
"""
import os
import sys
import json
import base64

import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import explore as E

MOVIE = "caity1png.mov"
CRUMBS = "caity_super_pcrumbs.txt"
MAP = "caity_map.txt"
ATHRESH = 24
COLS = 8


def b64_img(path):
    return "data:image/jpeg;base64," + base64.b64encode(open(path, "rb").read()).decode()


# ---- appearance metric (centroid-aligned full-character colour) ----------
def appearance(im):
    CW, CH = 44, 72
    s = CH / im.height
    im = im.resize((max(1, round(im.width * s)), CH), Image.LANCZOS)
    a = np.array(im).astype(np.float32)
    al = a[:, :, 3] > ATHRESH
    ys, xs = np.nonzero(al)
    canvas = np.zeros((CH, CW, 4), np.float32)
    if len(xs) == 0:
        return canvas
    ox = int(round(CW / 2 - xs.mean())); oy = int(round(CH / 2 - ys.mean()))
    H0, W0 = a.shape[:2]
    sy0, sy1 = max(0, -oy), min(H0, CH - oy)
    sx0, sx1 = max(0, -ox), min(W0, CW - ox)
    if sy1 > sy0 and sx1 > sx0:
        canvas[sy0 + oy:sy1 + oy, sx0 + ox:sx1 + ox] = a[sy0:sy1, sx0:sx1]
    return canvas


def appdist(A, B):
    aA = A[:, :, 3] > ATHRESH; aB = B[:, :, 3] > ATHRESH
    both = aA & aB; either = aA | aB
    n = int(either.sum())
    if n == 0:
        return 1.0
    cd = np.abs(A[:, :, :3][both] - B[:, :, :3][both]).sum() / (255 * 3)
    return float((cd + int((either & ~both).sum())) / n)


def add_tunnels(sprites, nodes, edges, thresh=0.14):
    """Stitch the recorded phrase-cliques into one traversable graph: add
    genuine appearance matches below `thresh`, then bridge any still-separate
    components with their single best (lowest-distance) cross-component match."""
    N = len(sprites)
    desc = [appearance(s) for s in sprites]
    parent = list(range(N))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x

    def union(a, b):
        parent[find(a)] = find(b)

    existing = set()
    for i in range(N):
        for e in edges[i]:
            if e["to"] != i:
                union(i, e["to"]); existing.add((i, e["to"])); existing.add((e["to"], i))

    pairs = sorted((appdist(desc[i], desc[j]), i, j)
                   for i in range(N) for j in range(i + 1, N))

    def link(i, j, kind):
        dx = nodes[j]["fcx"] - nodes[i]["fcx"]
        edges[i].append({"to": j, "dx": round(dx, 4), "time": 1, "space": 1,
                         "weight": 1, "control": 1, "tunnel": kind})
        edges[j].append({"to": i, "dx": round(-dx, 4), "time": 1, "space": 1,
                         "weight": 1, "control": 1, "tunnel": kind})

    tun = 0
    for d, i, j in pairs:
        if d < thresh and (i, j) not in existing:
            link(i, j, 1); union(i, j); existing |= {(i, j), (j, i)}; tun += 1
    bridges = 0
    for d, i, j in pairs:
        if find(i) != find(j):
            link(i, j, 2); union(i, j); bridges += 1
    return tun, bridges


def main():
    crumbs = E.parse_crumbs(os.path.join(E.SRCDIR, CRUMBS))
    graph = E.parse_map(os.path.join(E.SRCDIR, MAP))
    frames = [c["frame"] for c in crumbs]
    imgs = E.extract_frames(MOVIE, frames)

    # crop each node to its alpha bbox; record body-centroid-x within the crop
    sprites, meta = [], []
    for c in crumbs:
        im = imgs[c["frame"]]
        a = np.array(im)
        al = a[:, :, 3] > ATHRESH
        ys, xs = np.nonzero(al)
        x0, y0, x1, y1 = xs.min(), ys.min(), xs.max() + 1, ys.max() + 1
        sp = im.crop((x0, y0, x1, y1))
        aw = a[y0:y1, x0:x1, 3].astype(np.float64)
        cxpx = float((np.arange(sp.width)[None, :] * aw).sum() / aw.sum())
        sprites.append(sp)
        meta.append({"label": c["label"], "frame": c["frame"],
                     "cx_sprite": cxpx / sp.width,
                     "fcx": E.centroid_x(im)})       # stage position in source frame

    cellW = max(s.width for s in sprites)
    cellH = max(s.height for s in sprites)
    rows = (len(sprites) + COLS - 1) // COLS
    atlas = Image.new("RGBA", (COLS * cellW, rows * cellH), (0, 0, 0, 0))
    for k, sp in enumerate(sprites):
        col, row = k % COLS, k // COLS
        px = col * cellW + (cellW - sp.width) // 2
        py = row * cellH + (cellH - sp.height)          # feet at cell bottom
        atlas.alpha_composite(sp, (px, py))
        # body-centroid-x within the cell (fraction)
        meta[k]["col"] = col
        meta[k]["row"] = row
        meta[k]["cx_cell"] = ((cellW - sp.width) // 2 + meta[k]["cx_sprite"] * sp.width) / cellW

    atlas_path = os.path.join(HERE, "caity_atlas.png")
    atlas.save(atlas_path)
    atlas_b64 = "data:image/png;base64," + base64.b64encode(open(atlas_path, "rb").read()).decode()

    # edges per node (node index = order in crumbs); dx = stage displacement
    frame_to_node = {c["frame"]: i for i, c in enumerate(crumbs)}
    nodes = []
    edges = []
    for i, c in enumerate(crumbs):
        nodes.append({"label": meta[i]["label"], "col": meta[i]["col"], "row": meta[i]["row"],
                      "cxCell": round(meta[i]["cx_cell"], 4), "fcx": round(meta[i]["fcx"], 4)})
        es = []
        for e in graph.get(c["frame"], []):
            if e["dst"] not in frame_to_node:
                continue
            j = frame_to_node[e["dst"]]
            dx = meta[j]["fcx"] - meta[i]["fcx"]
            es.append({"to": j, "dx": round(dx, 4), "time": e["time"],
                       "space": e["space"], "weight": e["weight"], "control": e["control"]})
        edges.append(es)

    rec_edges = sum(len(e) for e in edges)
    tun, bridges = add_tunnels(sprites, nodes, edges)
    print("recorded edges %d  +tunnels %d (seamless) +bridges %d (connect) -> connected"
          % (rec_edges, tun, bridges))

    # start node nearest centre stage
    start = min(range(len(nodes)), key=lambda i: abs(nodes[i]["fcx"] - 0.5))

    data = {"cell": [cellW, cellH], "cols": COLS, "rows": rows,
            "atlasW": atlas.width, "atlasH": atlas.height,
            "nodes": nodes, "edges": edges, "start": start}

    html = HTML.replace("__ATLAS__", atlas_b64) \
               .replace("__FLOOR__", b64_img(os.path.join(E.SRCDIR, "floor.jpg"))) \
               .replace("__CURTAIN__", b64_img(os.path.join(E.SRCDIR, "curtain.jpg"))) \
               .replace("__DATA__", json.dumps(data))
    out = os.path.join(HERE, "caity_demo.html")
    open(out, "w").write(html)
    print("nodes %d  edges %d  cell %dx%d  atlas %dx%d" %
          (len(nodes), sum(len(e) for e in edges), cellW, cellH, atlas.width, atlas.height))
    print("wrote", os.path.relpath(out, os.path.expanduser("~")))
    print("open it directly in a browser (assets are embedded; no server needed)")


HTML = r"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>caity — stage</title>
<style>
 html,body{margin:0;height:100%;background:#05060a;overflow:hidden;font:13px/1.5 -apple-system,Helvetica,sans-serif;color:#cfd3e0}
 #hud{position:fixed;left:14px;top:12px;z-index:10;background:rgba(8,10,18,.72);padding:10px 13px;border-radius:8px;max-width:330px}
 #hud b{color:#fff} #hud .k{color:#8ad6a0} kbd{background:#222838;border-radius:4px;padding:1px 6px;color:#e7eaf2;border:1px solid #333b50}
 #stat{position:fixed;right:14px;top:12px;z-index:10;background:rgba(8,10,18,.72);padding:8px 12px;border-radius:8px;font-variant-numeric:tabular-nums}
 a{color:#8ad6a0}
</style>
<script src="https://unpkg.com/three@0.128.0/build/three.min.js"></script>
<script src="https://unpkg.com/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
</head><body>
<div id="hud">
 <div><b>caity · live stage</b></div>
 <div style="margin-top:6px">
  <span class="k">mouse</span> orbit camera · wheel zoom<br>
  <span class="k">W A S D</span> move focal point (target)<br>
  <span class="k">&larr; &rarr;</span> steer caity · <span class="k">&darr;</span> hold<br>
  <span class="k">C</span> chase focal point · <span class="k">1 2 3</span> auto-mode · <span class="k">0</span> manual
 </div>
</div>
<div id="stat"></div>
<script>
const DATA = __DATA__;
const ATLAS_SRC="__ATLAS__", FLOOR_SRC="__FLOOR__", CURTAIN_SRC="__CURTAIN__";

const STAGE_W = 12.0;          // world units across the stage (full traverse)
const CELL_H_WORLD = 3.2;      // world height of a pose cell (feet at y=0)
const STEP_MS = 230;           // limited-animation cadence

const [cellW,cellH]=DATA.cell;
const CELL_W_WORLD = CELL_H_WORLD * cellW/cellH;

// ---- renderer / scene ------------------------------------------------------
const renderer=new THREE.WebGLRenderer({antialias:true});
renderer.setPixelRatio(window.devicePixelRatio);
renderer.setSize(innerWidth,innerHeight); renderer.outputEncoding=THREE.sRGBEncoding;
document.body.appendChild(renderer.domElement);
const scene=new THREE.Scene(); scene.background=new THREE.Color(0x05060a);
scene.fog=new THREE.Fog(0x05060a, 18, 38);
const camera=new THREE.PerspectiveCamera(45,innerWidth/innerHeight,0.1,200);
camera.position.set(0,4.2,13);
const controls=new THREE.OrbitControls(camera,renderer.domElement);
controls.target.set(0,1.8,0); controls.enablePan=false; controls.minDistance=5; controls.maxDistance=30;
controls.maxPolarAngle=Math.PI*0.49;

scene.add(new THREE.AmbientLight(0xb9c4e0,0.85));
const key=new THREE.DirectionalLight(0xfff0e0,0.7); key.position.set(4,9,6); scene.add(key);

const tex=s=>{const t=new THREE.TextureLoader().load(s);t.encoding=THREE.sRGBEncoding;return t;};

// floor
const floor=new THREE.Mesh(new THREE.PlaneGeometry(STAGE_W+6,12),
  new THREE.MeshStandardMaterial({map:tex(FLOOR_SRC),roughness:.95}));
floor.rotation.x=-Math.PI/2; floor.position.set(0,0,-1); scene.add(floor);
// curtain backdrop
const curtain=new THREE.Mesh(new THREE.PlaneGeometry(STAGE_W+6,9),
  new THREE.MeshStandardMaterial({map:tex(CURTAIN_SRC),roughness:1}));
curtain.position.set(0,4.5,-5.0); scene.add(curtain);

// focal point marker (the look-at / chase target)
const focal=new THREE.Mesh(new THREE.SphereGeometry(0.16,20,20),
  new THREE.MeshBasicMaterial({color:0x8ad6a0}));
focal.position.set(0,1.6,0); scene.add(focal);
const ring=new THREE.Mesh(new THREE.RingGeometry(0.28,0.34,28),
  new THREE.MeshBasicMaterial({color:0x8ad6a0,side:THREE.DoubleSide,transparent:true,opacity:.6}));
ring.rotation.x=-Math.PI/2; ring.position.y=0.02; scene.add(ring);

// ---- caity billboard + per-pose textures from the atlas --------------------
const atlasImg=new Image();
const poseTex=[];
const caityMat=new THREE.MeshBasicMaterial({transparent:true,alphaTest:0.5,side:THREE.DoubleSide});
const caity=new THREE.Mesh(new THREE.PlaneGeometry(CELL_W_WORLD,CELL_H_WORLD),caityMat);
const caityGrp=new THREE.Group(); caityGrp.add(caity); caity.position.y=CELL_H_WORLD/2; scene.add(caityGrp);
// soft contact shadow
const shadow=new THREE.Mesh(new THREE.CircleGeometry(0.9,24),
  new THREE.MeshBasicMaterial({color:0x000000,transparent:true,opacity:0.32}));
shadow.rotation.x=-Math.PI/2; shadow.position.y=0.015; scene.add(shadow);

atlasImg.onload=()=>{
  for(let i=0;i<DATA.nodes.length;i++){
    const n=DATA.nodes[i];
    const cv=document.createElement('canvas'); cv.width=cellW; cv.height=cellH;
    cv.getContext('2d').drawImage(atlasImg, n.col*cellW, n.row*cellH, cellW, cellH, 0,0,cellW,cellH);
    const t=new THREE.CanvasTexture(cv); t.encoding=THREE.sRGBEncoding; poseTex.push(t);
  }
  setNode(DATA.start,true); animate();
};
atlasImg.src=ATLAS_SRC;

// ---- avatar state / controller ---------------------------------------------
let node=DATA.start, facing=1, worldX=0, targetX=0;
let intent=0;                 // -1 left, +1 right, 0 hold
let mode='manual';            // manual | chase | 1 | 2 | 3
let lastStep=0;

function setNode(i,snap){
  node=i; caityMat.map=poseTex[i]; caityMat.needsUpdate=true;
  const n=DATA.nodes[i];
  // place body-centroid at worldX (mirror flips the offset)
  const off=(n.cxCell-0.5)*CELL_W_WORLD;
  caity.scale.x=facing;
  caityGrp.userData.off=off;
  if(snap){worldX=n.fcx*STAGE_W-STAGE_W/2; targetX=worldX;}
}

function eligible(){
  // edges available under the current mode
  let es=DATA.edges[node];
  if(mode==='1'||mode==='2'||mode==='3'){const c=+mode; es=es.filter(e=>e.control===c&&e.weight>0);}
  else {es=es.filter(e=>e.weight>0);}
  return es;
}

function step(){
  const es=eligible(); if(!es.length) return;
  let want=intent;
  if(mode==='chase') want=Math.sign(focal.position.x-worldX)|| (Math.random()<.5?1:-1);
  let pick;
  if(mode==='1'||mode==='2'||mode==='3'){          // auto: weighted random within mode
    const tot=es.reduce((s,e)=>s+e.weight,0); let r=Math.random()*tot;
    pick=es.find(e=>(r-=e.weight)<=0)||es[0];
  } else if(want===0){                              // hold: prefer small displacement, weighted
    const cand=es.map(e=>({e,s:e.weight/(1+Math.abs(e.dx)*20)}));
    const tot=cand.reduce((s,c)=>s+c.s,0); let r=Math.random()*tot;
    pick=(cand.find(c=>(r-=c.s)<=0)||cand[0]).e;
  } else {                                          // steer / chase: bias toward the wanted
    // displacement, but stay probabilistic so she dances out of dead ends
    let cand=es.filter(e=>e.to!==node);             // no self-loops under intent
    if(!cand.length) cand=es;
    const imp=cand.filter(e=>e.dx*facing*want>0.01); // edges that move the wanted way
    const pool=imp.length?imp:cand;                  // else explore (keep moving)
    const scored=pool.map(e=>{const eff=Math.max(0,e.dx*facing*want);
                              return {e,s:e.weight*(1+8*eff)};});
    const tot=scored.reduce((s,c)=>s+c.s,0); let r=Math.random()*tot;
    pick=(scored.find(c=>(r-=c.s)<=0)||scored[0]).e;
  }
  // apply the edge
  const dxWorld=pick.dx*facing*STAGE_W;
  targetX=Math.max(-STAGE_W/2,Math.min(STAGE_W/2,worldX+dxWorld));
  if(pick.space===2) facing*=-1;
  setNode(pick.to,false);
}

// ---- input -----------------------------------------------------------------
const keys={};
addEventListener('keydown',e=>{
  keys[e.code]=true;
  if(e.code==='ArrowLeft')intent=-1;
  if(e.code==='ArrowRight')intent=1;
  if(e.code==='ArrowDown')intent=0;
  if(e.key==='c'||e.key==='C')mode=(mode==='chase'?'manual':'chase');
  if('0123'.includes(e.key))mode=(e.key==='0'?'manual':e.key);
  if(['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(e.code))e.preventDefault();
});
addEventListener('keyup',e=>{keys[e.code]=false;});

function moveFocal(dt){
  const sp=6*dt; let dx=0,dz=0;
  if(keys['KeyA'])dx-=sp; if(keys['KeyD'])dx+=sp;
  if(keys['KeyW'])dz-=sp; if(keys['KeyS'])dz+=sp;
  if(dx||dz){
    focal.position.x=Math.max(-STAGE_W/2,Math.min(STAGE_W/2,focal.position.x+dx));
    focal.position.z=Math.max(-4,Math.min(4,focal.position.z+dz));
    ring.position.x=focal.position.x; ring.position.z=focal.position.z;
    controls.target.copy(focal.position);
  }
}

// ---- loop ------------------------------------------------------------------
let prev=performance.now();
function animate(){
  requestAnimationFrame(animate);
  const now=performance.now(), dt=Math.min(.05,(now-prev)/1000); prev=now;
  moveFocal(dt);
  const driving = mode!=='manual' || intent!==0;
  if(now-lastStep>STEP_MS && (driving)){ step(); lastStep=now; }
  // glide world position toward target (the step looks like a stride)
  worldX += (targetX-worldX)*Math.min(1,dt*9);
  caityGrp.position.x = worldX - facing*caityGrp.userData.off;
  shadow.position.x = worldX;
  // billboard caity to face the camera (around Y)
  const a=Math.atan2(camera.position.x-caityGrp.position.x, camera.position.z-caityGrp.position.z);
  caityGrp.rotation.y=a;
  controls.update();
  renderer.render(scene,camera);
  document.getElementById('stat').innerHTML =
    `pose <b>${DATA.nodes[node].label}</b> · facing ${facing>0?'R':'L'}<br>`+
    `x ${worldX.toFixed(2)} · mode <b>${mode}</b> · intent ${intent>0?'→':intent<0?'←':'·'}`;
}
addEventListener('resize',()=>{camera.aspect=innerWidth/innerHeight;camera.updateProjectionMatrix();renderer.setSize(innerWidth,innerHeight);});
</script></body></html>
"""

if __name__ == "__main__":
    main()
