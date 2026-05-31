#!/usr/bin/env python3
"""Faithful live port of the Max avatar_trueplayer (see SYSTEM.md).

Unlike the <video> attempts, this preloads the frames (downsampled into a few
RGBA atlas pages) and STEPS them exactly like offline_player.py / the Max patch:

  * continuous ±1 frame accumulator (forward / reverse via the edge `time`),
  * at a tagged frame (coll map node) a weighted-random pick from the map
    weights, filtered by the active `control`,
  * `space` mirror, centroid-compensated splice so cuts never teleport,
  * position carried by the real footage between cuts (the true vocabulary).

No <video> seeking, so cuts and reverse are frame-exact — what Max does.

Needs the frame cache working/avatari/_frames_<char> and centroids
(_centroids_<char>.json) from build_interactive.py.

Run:  CHAR=patrick .venv/bin/python working/avatari/build_player.py
"""
import os
import sys
import json
import math
import subprocess

import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
LIVE = os.path.join(HERE, "live")
sys.path.insert(0, HERE)
import explore as E

FPS = 30
FFMPEG = "/usr/local/bin/ffmpeg"
CHARS = {                        # (movie, crumbs, map)
    "caity":   ("caity1png.mov", "caity_super_pcrumbs.txt", "caity_map.txt"),
    "patrick": ("patrick2png.mov", "patrick_pc.txt", "patrick_mapped.txt"),
    "jeremy":  ("jeremy2png.mov", "jeremy_precrumb.txt", "jeremy_supermap.txt"),
}
CHAR = os.environ.get("CHAR", "jeremy")
MOVIE, CRUMBS, MAP = CHARS[CHAR]
FRAMES = os.path.join(HERE, "_frames_" + CHAR)
CENTROIDS = os.path.join(HERE, "_centroids_" + CHAR + ".json")

CELL_H = 64                      # downsampled frame height in the atlas
PAGE = 2048                      # atlas page size


def extract_frames():
    os.makedirs(FRAMES, exist_ok=True)
    if len([f for f in os.listdir(FRAMES) if f.startswith("f_")]) > 100:
        return
    print("extracting %s frames…" % CHAR)
    subprocess.run([FFMPEG, "-v", "error", "-i", os.path.join(E.SRCDIR, MOVIE),
                    "-vf", "format=rgba", "-vsync", "0",
                    os.path.join(FRAMES, "f_%04d.png")], check=True)


def compute_centroids():
    if os.path.exists(CENTROIDS):
        return json.load(open(CENTROIDS))
    print("computing centroids…")
    files = sorted(f for f in os.listdir(FRAMES) if f.startswith("f_"))
    cxs = []
    for f in files:
        a = np.asarray(Image.open(os.path.join(FRAMES, f)).split()[3], np.float64)
        tot = a.sum()
        cxs.append(round(float((np.arange(a.shape[1])[None, :] * a).sum() / tot) / a.shape[1], 4)
                   if tot else 0.5)
    json.dump(cxs, open(CENTROIDS, "w"))
    return cxs


def build_atlas():
    files = sorted(f for f in os.listdir(FRAMES) if f.startswith("f_"))
    nF = len(files)
    sample = Image.open(os.path.join(FRAMES, files[0]))
    fw, fh = sample.size
    cw = max(1, round(CELL_H * fw / fh))
    cols, rows = PAGE // cw, PAGE // CELL_H
    per = cols * rows
    pages = math.ceil(nF / per)
    print("atlas: %d frames  cell %dx%d  %dx%d/page  %d pages" %
          (nF, cw, CELL_H, cols, rows, pages))
    pfx = "atlas_%s_" % CHAR
    meta = {"nF": nF, "cw": cw, "ch": CELL_H, "cols": cols, "rows": rows, "atlas": pfx,
            "per": per, "pages": pages, "atlasW": cols * cw, "atlasH": rows * CELL_H}
    if all(os.path.exists(os.path.join(LIVE, "%s%02d.png" % (pfx, p))) for p in range(pages)):
        print("  atlas cached (%s)" % CHAR); return meta
    for p in range(pages):
        atlas = Image.new("RGBA", (cols * cw, rows * CELL_H), (0, 0, 0, 0))
        for k in range(p * per, min((p + 1) * per, nF)):
            im = Image.open(os.path.join(FRAMES, files[k])).convert("RGBA").resize((cw, CELL_H), Image.LANCZOS)
            i = k - p * per
            atlas.paste(im, ((i % cols) * cw, (i // cols) * CELL_H))
        atlas.save(os.path.join(LIVE, "%s%02d.png" % (pfx, p)))
        print("  wrote %s%02d.png" % (pfx, p))
    return meta


def main():
    os.makedirs(LIVE, exist_ok=True)
    print("=== faithful player for %s ===" % CHAR)
    extract_frames()
    meta = build_atlas()

    graph = E.parse_map(os.path.join(E.SRCDIR, MAP))
    crumbs = E.parse_crumbs(os.path.join(E.SRCDIR, CRUMBS))
    cx = compute_centroids()
    json.dump(cx, open(os.path.join(LIVE, "centroids.json"), "w"))

    node_frames = sorted(graph)
    edges = {f: [[e["dst"], e["time"], e["space"], e["weight"], e["control"]]
                 for e in graph[f] if 0 <= e["dst"] < meta["nF"]]
             for f in node_frames}
    labels = {str(c["frame"]): c["label"] for c in crumbs}
    variant = {str(c["frame"]): c["variant"] for c in crumbs}   # 1 same-side, 2 reflected, 3 symmetric
    start = max(edges, key=lambda f: len(edges[f]))

    # sanity: do edge space-values line up with the source variant's reflection rule?
    from collections import Counter
    rule = {1: Counter(), 2: Counter(), 3: Counter()}
    for f in node_frames:
        v = variant.get(str(f))
        if v in rule:
            for e in graph[f]:
                if e["weight"] > 0:
                    rule[v][e["space"]] += 1
    for v in (1, 2, 3):
        print("variant %d source-poses emit space-counts %s" % (v, dict(rule[v])))

    data = dict(meta, fps=FPS, nodeFrames=node_frames, edges=edges,
                start=start, labels=labels, variant=variant)
    json.dump(data, open(os.path.join(LIVE, "player.json"), "w"))
    open(os.path.join(LIVE, "player.html"), "w").write(HTML)
    nctrl = sorted({e[4] for v in edges.values() for e in v})
    print("nodes %d  edges %d  controls %s  start %d (%s)" %
          (len(node_frames), sum(len(v) for v in edges.values()),
           nctrl, start, labels.get(str(start), "?")))
    print("open  http://localhost:8781/live/player.html")


HTML = r"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>player</title>
<style>
 html,body{margin:0;height:100%;overflow:hidden;background:#05060a;font:13px/1.4 -apple-system,Helvetica,sans-serif;color:#cdd2df;cursor:grab}
 body.drag{cursor:grabbing}
 #hud{position:fixed;left:14px;top:12px;z-index:10;background:rgba(8,10,18,.72);padding:9px 12px;border-radius:8px}
 #hud .k{color:#8ad6a0}
 #stat{position:fixed;right:14px;top:12px;z-index:10;background:rgba(8,10,18,.72);padding:7px 11px;border-radius:8px;font-variant-numeric:tabular-nums}
</style>
<script src="https://unpkg.com/three@0.128.0/build/three.min.js"></script>
</head><body>
<div id="hud"><b>player · faithful</b><br><span class="k">drag</span> look · <span class="k">WASD</span> move · <span class="k">QE</span> up/down<br><span class="k">&larr;&uarr;&darr;&rarr;</span> move the attractor</div>
<div id="stat"></div>
<script>
fetch('player.json').then(r=>r.json()).then(D=>Promise.all(
  Array.from({length:D.pages},(_,p)=>new Promise(res=>{const im=new Image();im.onload=()=>res(im);im.src=D.atlas+String(p).padStart(2,'0')+'.png';}))
).then(imgs=>fetch('centroids.json').then(r=>r.json()).then(CX=>start(D,imgs,CX))));

function start(D, atlasImgs, CX){
 const FPS=D.fps, nF=D.nF, cw=D.cw, ch=D.ch, cols=D.cols, per=D.per;
 const nodeSet=new Set(D.nodeFrames);
 const PW=4.5*(cw/ch), PH=4.5, PLANE_Z=0;        // plane sized to the true frame aspect
 const dcx=(f,m)=> m ? 1-CX[f] : CX[f];

 const R=new THREE.WebGLRenderer({antialias:true}); R.setPixelRatio(devicePixelRatio);
 R.setSize(innerWidth,innerHeight); R.outputEncoding=THREE.sRGBEncoding; document.body.appendChild(R.domElement);
 const scene=new THREE.Scene(); scene.background=new THREE.Color(0x05060a); scene.fog=new THREE.Fog(0x05060a,22,55);
 const cam=new THREE.PerspectiveCamera(55,innerWidth/innerHeight,0.1,300);
 const tex=s=>{const t=new THREE.TextureLoader().load(s);t.encoding=THREE.sRGBEncoding;return t;};
 scene.add(new THREE.AmbientLight(0xb7c2dd,0.95));
 const floor=new THREE.Mesh(new THREE.PlaneGeometry(40,16),new THREE.MeshStandardMaterial({map:tex('floor.jpg'),roughness:.96}));
 floor.rotation.x=-Math.PI/2; floor.position.set(0,0,-1); scene.add(floor);
 const curtain=new THREE.Mesh(new THREE.PlaneGeometry(40,12),new THREE.MeshStandardMaterial({map:tex('curtain.jpg'),roughness:1}));
 curtain.position.set(0,6,-6); scene.add(curtain);

 // atlas pages -> textures (one per page); we show a cell by offset/repeat
 const pages=atlasImgs.map(im=>{const t=new THREE.CanvasTexture(im);t.flipY=false;t.encoding=THREE.sRGBEncoding;
   t.minFilter=THREE.LinearFilter;t.magFilter=THREE.LinearFilter;t.generateMipmaps=false;
   t.repeat.set(cw/D.atlasW, -ch/D.atlasH); return t;});   // -y: atlas rows are top-down
 const dmat=new THREE.MeshBasicMaterial({transparent:true,alphaTest:0.5,side:THREE.DoubleSide});
 const dancer=new THREE.Mesh(new THREE.PlaneGeometry(PW,PH),dmat);
 const grp=new THREE.Group(); grp.add(dancer); dancer.position.y=PH/2; grp.position.z=PLANE_Z; scene.add(grp);
 const shadow=new THREE.Mesh(new THREE.CircleGeometry(.7,24),new THREE.MeshBasicMaterial({color:0,transparent:true,opacity:.3}));
 shadow.rotation.x=-Math.PI/2; shadow.position.y=.015; scene.add(shadow);
 // attractor — moved with the arrow keys; biases the weighted-random pick at each node
 const att=new THREE.Mesh(new THREE.SphereGeometry(0.18,20,20),new THREE.MeshBasicMaterial({color:0x9be0b0}));
 const ring=new THREE.Mesh(new THREE.RingGeometry(.30,.36,30),new THREE.MeshBasicMaterial({color:0x9be0b0,transparent:true,opacity:.6,side:THREE.DoubleSide}));
 ring.rotation.x=-Math.PI/2; scene.add(att); scene.add(ring);
 let ballX=0, ballZ=0.6;
 function showFrame(f){
   const p=Math.floor(f/per), i=f-p*per, col=i%cols, row=Math.floor(i/cols);
   const t=pages[p]; t.offset.set(col*cw/D.atlasW, (row+1)*ch/D.atlasH);   // -y mapping
   dmat.map=t; dmat.needsUpdate=true;
 }

 // ---- the faithful player loop (offline_player / Max) ----
 let N=D.start, d=1, mirror=false, offX=0;
 const BETA=2.0, EXK=6;                 // landing temperature / discount horizon
 const nodesSorted=D.nodeFrames.slice().sort((a,b)=>a-b);
 function nextNode(f){ for(const n of nodesSorted){ if(n>f) return n; } return nodesSorted[0]; }
 // DISCOUNTED displacement: Mv + ½M²v + ¼M³v + …  (immediate step dominates; no multistep commitment)
 function excursion(dst,m){ let f=dst,net=0,w=1; for(let i=0;i<EXK;i++){ const nn=nextNode(f); net+=w*(dcx(nn,m)-dcx(f,m)); f=nn; w*=0.5; } return net*PW; }
 function wpick(scored){ const tot=scored.reduce((a,c)=>a+c.s,0); let r=Math.random()*tot,p=scored[scored.length-1];
   for(const c of scored){ r-=c.s; if(r<=0){p=c;break;} } return p.e; }
 function pickEdge(node){
   const es=(D.edges[node]||[]).filter(e=>e[3]>0); if(!es.length) return null;
   const v=D.variant[String(node)]||3;
   if(v===3){            // SYMMETRIC: the ball picks keep-vs-flip handedness whose excursion LANDS on it
     const bodyX=offX+(dcx(node,mirror)-0.5)*PW;
     return wpick(es.map(e=>{ const nm=e[2]===2?!mirror:mirror; const land=bodyX+excursion(e[0],nm);
       return {e, s:e[3]*Math.exp(-BETA*Math.abs(land-ballX))}; }));   // land near ball -> self-damps
   }
   return wpick(es.map(e=>({e, s:e[3]})));   // variant 1 (no reflect) / 2 (forced reflect): just play
 }
 function stepFrame(){
   const prevN=N, prevM=mirror;
   N+=d;
   if(N<0){N=0;d=1;} else if(N>=nF){N=nF-1;d=-1;}
   if(nodeSet.has(N)){
     const e=pickEdge(N);
     if(e){ const dst=e[0], tm=e[1], sp=e[2]; const newM = sp===2 ? !mirror : mirror;
       if(Math.abs(dst-prevN)>1 || newM!==prevM)
         offX += (dcx(prevN,prevM)-dcx(dst,newM))*PW;   // videoplane shifts -Δcentroid: no apparent teleport
       N=dst; d = tm===1?1:-1; mirror=newM;
     }
   }
 }
 function place(){             // natural footage movement; cuts compensated -> no apparent teleport, no slide
   const x=offX+(dcx(N,mirror)-0.5)*PW;
   showFrame(N); dancer.scale.x = mirror?-1:1;
   grp.position.x = offX; shadow.position.x = x;
 }

 // ---- fly camera ----
 let yaw=0,pitch=-0.05; cam.position.set(0,2.6,16);
 const keys={}; let drag=false,px=0,py=0;
 R.domElement.addEventListener('mousedown',e=>{drag=true;px=e.clientX;py=e.clientY;document.body.classList.add('drag');});
 addEventListener('mouseup',()=>{drag=false;document.body.classList.remove('drag');});
 addEventListener('mousemove',e=>{if(!drag)return;yaw-=(e.clientX-px)*0.003;pitch-=(e.clientY-py)*0.003;pitch=Math.max(-1.3,Math.min(1.3,pitch));px=e.clientX;py=e.clientY;});
 addEventListener('keydown',e=>{keys[e.code]=true; if(e.code.startsWith('Arrow'))e.preventDefault();}); addEventListener('keyup',e=>keys[e.code]=false);
 function fly(dt){const sp=(keys['ShiftLeft']?14:6)*dt;
   const f=new THREE.Vector3(-Math.sin(yaw),0,-Math.cos(yaw)), rt=new THREE.Vector3(Math.cos(yaw),0,-Math.sin(yaw));
   if(keys['KeyW'])cam.position.addScaledVector(f,sp); if(keys['KeyS'])cam.position.addScaledVector(f,-sp);
   if(keys['KeyD'])cam.position.addScaledVector(rt,sp); if(keys['KeyA'])cam.position.addScaledVector(rt,-sp);
   if(keys['KeyE'])cam.position.y+=sp; if(keys['KeyQ'])cam.position.y-=sp; cam.position.y=Math.max(.6,cam.position.y);
   cam.quaternion.setFromEuler(new THREE.Euler(pitch,yaw,0,'YXZ'));}

 // ---- loop: step frames at FPS, render at rAF ----
 let prev=performance.now(), acc=0;
 function loop(){
   requestAnimationFrame(loop);
   const now=performance.now(), dt=Math.min(.1,(now-prev)/1000); prev=now;
   fly(dt);
   const bsp=6*dt;
   if(keys['ArrowLeft'])ballX-=bsp; if(keys['ArrowRight'])ballX+=bsp;
   if(keys['ArrowUp'])ballZ-=bsp; if(keys['ArrowDown'])ballZ+=bsp;
   ballX=Math.max(-7,Math.min(7,ballX)); ballZ=Math.max(-3,Math.min(3,ballZ));
   att.position.set(ballX,0.18,ballZ); ring.position.set(ballX,0.02,ballZ);
   acc+=dt; const STEP=1/FPS; let guard=0;
   while(acc>=STEP && guard++<8){ stepFrame(); acc-=STEP; }
   place();
   R.render(scene,cam);
   document.getElementById('stat').innerHTML=`frame ${N} · ${d>0?'▶':'◀'}${mirror?' ⇄':''} · x ${(offX+(dcx(N,mirror)-0.5)*PW).toFixed(1)} → ball ${ballX.toFixed(1)}`;
 }
 showFrame(N); place(); loop();
 addEventListener('resize',()=>{cam.aspect=innerWidth/innerHeight;cam.updateProjectionMatrix();R.setSize(innerWidth,innerHeight);});
}
</script></body></html>
"""

if __name__ == "__main__":
    main()
