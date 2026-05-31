#!/usr/bin/env python3
"""Build the live, interactive caity stage (working/avatari/live/index.html).

Faithful to avatar_trueplayer (see SYSTEM.md): a VideoTexture of the real
recording plays forward; the controller cuts only at tagged poses, with the
videoplane offset by the centroid difference at each cut (seamless splice). On
top of that engine:

  * a fly camera (the `navigator`),
  * an ATTRACTOR that traces an oval for 30 s then freezes; caity is drawn to it
    by steering toward footage segments whose drift heads her that way, and
    settles when she arrives,
  * PROXIMITY: fly close and she kneels (freezes on her lowest pose) and a
    password bubble appears over her head.

Needs the frame cache (working/avatari/_allframes) from offline_player.py and
the alpha WebM (live/caity.webm). Run:
    .venv/bin/python working/avatari/build_interactive.py
"""
import os
import sys
import json
import shutil
import subprocess

import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
LIVE = os.path.join(HERE, "live")
sys.path.insert(0, HERE)
import explore as E

FFMPEG = "/usr/local/bin/ffmpeg"
FPS = 30

# which dancer: (movie, crumbs, map, frame_w, frame_h)
CHARS = {
    "caity":   ("caity1png.mov", "caity_super_pcrumbs.txt", "caity_map.txt", 720, 279),
    "patrick": ("patrick2png.mov", "patrick_pc.txt", "patrick_mapped.txt", 720, 219),
}
CHAR = os.environ.get("CHAR", "patrick")
MOVIE, CRUMBS, MAP, FRAME_W, FRAME_H = CHARS[CHAR]
FRAMES = os.path.join(HERE, "_frames_" + CHAR)


def extract_frames():
    """Dump every frame of the movie (RGBA) into the char frame cache."""
    os.makedirs(FRAMES, exist_ok=True)
    if len([f for f in os.listdir(FRAMES) if f.startswith("f_")]) > 100:
        return
    print("extracting %s frames…" % CHAR)
    subprocess.run([FFMPEG, "-v", "error", "-i", os.path.join(E.SRCDIR, MOVIE),
                    "-vf", "format=rgba", "-vsync", "0",
                    os.path.join(FRAMES, "f_%04d.png")], check=True)


def encode_packed():
    """One H.264: top half = colour on black, bottom half = alpha matte."""
    cache = os.path.join(HERE, "_packed_" + CHAR + ".mp4")
    if not os.path.exists(cache):
        print("encoding packed video for %s…" % CHAR)
        subprocess.run([FFMPEG, "-v", "error", "-y", "-i", os.path.join(E.SRCDIR, MOVIE),
                        "-filter_complex",
                        "[0:v]format=rgba,split=2[v1][v2];[v1]format=yuv420p[top];"
                        "[v2]alphaextract,format=yuv420p[bot];[top][bot]vstack=inputs=2[o]",
                        "-map", "[o]", "-c:v", "libx264", "-pix_fmt", "yuv420p",
                        "-g", "10", "-crf", "20", cache], check=True)
    shutil.copy(cache, os.path.join(LIVE, "dancer.mp4"))


def all_centroids():
    cache = os.path.join(HERE, "_centroids_" + CHAR + ".json")
    if os.path.exists(cache):
        cx = json.load(open(cache))
        json.dump(cx, open(os.path.join(LIVE, "centroids.json"), "w"))
        return cx
    files = sorted(f for f in os.listdir(FRAMES) if f.startswith("f_"))
    cx = []
    for i, f in enumerate(files):
        a = np.asarray(Image.open(os.path.join(FRAMES, f)).split()[3], np.float64)
        tot = a.sum()
        cx.append(round(float((np.arange(a.shape[1])[None, :] * a).sum() / tot) / a.shape[1], 4)
                  if tot else 0.5)
        if i % 500 == 0:
            print("  centroids %d/%d" % (i, len(files)))
    json.dump(cx, open(cache, "w"))
    json.dump(cx, open(os.path.join(LIVE, "centroids.json"), "w"))
    return cx


def centroid_y(frame_idx, files):
    a = np.asarray(Image.open(os.path.join(FRAMES, files[frame_idx])).split()[3], np.float64)
    tot = a.sum()
    return float((np.arange(a.shape[0])[:, None] * a).sum() / tot) / a.shape[0] if tot else 0.5


def main():
    os.makedirs(LIVE, exist_ok=True)
    print("=== building live stage for: %s ===" % CHAR)
    extract_frames()
    encode_packed()
    crumbs = E.parse_crumbs(os.path.join(E.SRCDIR, CRUMBS))
    graph = E.parse_map(os.path.join(E.SRCDIR, MAP))

    print("computing centroids for all frames…")
    cx = all_centroids()

    node_frames = sorted(graph)
    files = sorted(f for f in os.listdir(FRAMES) if f.startswith("f_"))
    # kneel = the lowest pose (largest centroid-y among nodes)
    cy = {f: centroid_y(f, files) for f in node_frames}
    kneel = max(node_frames, key=lambda f: cy[f])

    # forward edges only (time==1); the V4 reverse is dropped for the browser
    edges = {}
    labels = {}
    for c in crumbs:
        labels[c["frame"]] = c["label"]
    for f in node_frames:
        es = []
        for e in graph[f]:
            if e["time"] == 1 and e["weight"] > 0 and 0 <= e["dst"] < len(cx):
                es.append([e["dst"], e["space"], e["weight"]])
        if es:
            edges[f] = es

    # start her at the richest node (most outgoing moves) = the middle of the
    # motion graph, so she's dancing inside the graph from frame one
    start = max(edges, key=lambda f: len(edges[f]))
    data = {"fps": FPS, "frameW": FRAME_W, "frameH": FRAME_H,
            "nodeFrames": node_frames, "edges": edges, "kneel": kneel, "start": start,
            "labels": {str(k): v for k, v in labels.items()}, "nFrames": len(cx)}
    json.dump(data, open(os.path.join(LIVE, "graph.json"), "w"))
    print("nodes %d  kneel frame %d (%s)  edges %d"
          % (len(node_frames), kneel, labels.get(kneel, "?"),
             sum(len(v) for v in edges.values())))

    open(os.path.join(LIVE, "index.html"), "w").write(HTML)
    print("wrote live/index.html, live/graph.json, live/centroids.json")
    print("serve working/avatari and open /live/  (needs live/caity.webm)")


HTML = r"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>caity — live</title>
<style>
 html,body{margin:0;height:100%;overflow:hidden;background:#05060a;font:13px/1.4 -apple-system,Helvetica,sans-serif;color:#cdd2df;cursor:grab}
 body.drag{cursor:grabbing}
 #hud{position:fixed;left:14px;top:12px;z-index:10;background:rgba(8,10,18,.72);padding:9px 12px;border-radius:8px;max-width:300px}
 #hud .k{color:#8ad6a0}
 #stat{position:fixed;right:14px;top:12px;z-index:10;background:rgba(8,10,18,.72);padding:7px 11px;border-radius:8px;font-variant-numeric:tabular-nums}
 #bubble{position:fixed;z-index:20;display:none;transform:translate(-50%,-100%);background:#fbf7ea;color:#19202c;
   padding:8px 12px;border-radius:12px;box-shadow:0 6px 22px rgba(0,0,0,.5);white-space:nowrap;font-weight:600}
 #bubble:after{content:"";position:absolute;left:50%;bottom:-9px;transform:translateX(-50%);
   border:9px solid transparent;border-top-color:#fbf7ea;border-bottom:0}
 #bubble input{margin-left:8px;border:1px solid #b9b2a0;border-radius:6px;padding:3px 7px;font:inherit;width:120px}
</style>
<script src="https://unpkg.com/three@0.128.0/build/three.min.js"></script>
</head><body>
<div id="hud"><b>caity · live</b><br>
 <span class="k">drag</span> look · <span class="k">W A S D</span> move · <span class="k">Q E</span> down/up · <span class="k">shift</span> faster<br>
 fly close to her…</div>
<div id="stat"></div>
<div id="bubble">May I have the password?<input id="pw" type="password" autocomplete="off"></div>
<script>
const FB="graph.json", CB="centroids.json";
Promise.all([fetch(FB).then(r=>r.json()), fetch(CB).then(r=>r.json())]).then(([D,CX])=>start(D,CX));

function start(D, CX){
 const FPS=D.fps, FW=D.frameW, FH=D.frameH;
 const nodeSet=new Set(D.nodeFrames);
 const nodesSorted=D.nodeFrames.slice().sort((a,b)=>a-b);
 const PLANE_H=4.5, PLANE_W=PLANE_H*FW/FH, PLANE_Z=0;
 const dcx=(f,fac)=> fac>0 ? CX[f] : 1-CX[f];           // displayed centroid (mirror-aware)
 function nextNode(f){ for(const n of nodesSorted){ if(n>f) return n; } return nodesSorted[0]; }
 function segDrift(B){ return CX[nextNode(B)]-CX[B]; }   // where the footage from B heads

 // ---- scene ----
 const R=new THREE.WebGLRenderer({antialias:true}); R.setPixelRatio(devicePixelRatio);
 R.setSize(innerWidth,innerHeight); R.outputEncoding=THREE.sRGBEncoding; document.body.appendChild(R.domElement);
 const scene=new THREE.Scene(); scene.background=new THREE.Color(0x05060a); scene.fog=new THREE.Fog(0x05060a,22,55);
 const cam=new THREE.PerspectiveCamera(55,innerWidth/innerHeight,0.1,300);
 const tex=s=>{const t=new THREE.TextureLoader().load(s);t.encoding=THREE.sRGBEncoding;return t;};
 scene.add(new THREE.AmbientLight(0xb7c2dd,0.9));
 const key=new THREE.DirectionalLight(0xfff0e0,0.6); key.position.set(5,10,7); scene.add(key);
 const floor=new THREE.Mesh(new THREE.PlaneGeometry(40,16),
   new THREE.MeshStandardMaterial({map:tex("floor.jpg"),roughness:.96}));
 floor.rotation.x=-Math.PI/2; floor.position.set(0,0,-1); scene.add(floor);
 const curtain=new THREE.Mesh(new THREE.PlaneGeometry(40,12),
   new THREE.MeshStandardMaterial({map:tex("curtain.jpg"),roughness:1}));
 curtain.position.set(0,6,-6); scene.add(curtain);

 // attractor
 const att=new THREE.Mesh(new THREE.SphereGeometry(0.18,20,20), new THREE.MeshBasicMaterial({color:0x9be0b0}));
 scene.add(att);
 const ring=new THREE.Mesh(new THREE.RingGeometry(.30,.36,30),
   new THREE.MeshBasicMaterial({color:0x9be0b0,transparent:true,opacity:.6,side:THREE.DoubleSide}));
 ring.rotation.x=-Math.PI/2; ring.position.y=.02; scene.add(ring);
 const ATTX=3.0, ACZ=0.5;   // stationary target off to her side (chase test)

 // dancer videoplane — texture is a CANVAS we draw the presented frame into, so
 // the texture is exactly the frame our state uses (no VideoTexture timing skew)
 const vid=document.createElement('video'); vid.src="dancer.mp4"; vid.muted=true; vid.loop=false;
 vid.playsInline=true; vid.preload="auto";
 const cnv=document.createElement('canvas'); const cctx=cnv.getContext('2d');
 const vtex=new THREE.CanvasTexture(cnv); vtex.flipY=false;
 vtex.minFilter=THREE.LinearFilter; vtex.magFilter=THREE.LinearFilter;
 // packed frame: top half = colour on black, bottom half = alpha matte (grayscale)
 const dmat=new THREE.ShaderMaterial({ uniforms:{map:{value:vtex}}, transparent:true, side:THREE.DoubleSide,
   vertexShader:"varying vec2 vUv; void main(){vUv=uv; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0);}",
   fragmentShader:"uniform sampler2D map; varying vec2 vUv; void main(){ float cy=(1.0-vUv.y)*0.5;"+
     "float a=texture2D(map, vec2(vUv.x, cy+0.5)).r; if(a<0.12) discard;"+
     "vec3 c=texture2D(map, vec2(vUv.x, cy)).rgb; gl_FragColor=vec4(c,a);}" });
 const dancer=new THREE.Mesh(new THREE.PlaneGeometry(PLANE_W,PLANE_H),dmat);
 const grp=new THREE.Group(); grp.add(dancer); dancer.position.y=PLANE_H/2; grp.position.z=PLANE_Z; scene.add(grp);
 const shadow=new THREE.Mesh(new THREE.CircleGeometry(.8,24),
   new THREE.MeshBasicMaterial({color:0,transparent:true,opacity:.3}));
 shadow.rotation.x=-Math.PI/2; shadow.position.y=.015; scene.add(shadow);

 // ---- avatar state ----
 // the graph carries BOTH the dance and the locomotion. at each tagged pose we
 // weighted-random sample the next move (the "quantum selector"), biased toward
 // footage that drifts her toward the target. centroid compensation makes the
 // cut seamless, so her stage position is carried by the real footage.
 let facing=1, offX=0, lastNode=-1, kneeling=false, seeking=false, shown=0, pending=null, seekT=0, presented=0;
 const hasRVFC = 'requestVideoFrameCallback' in vid;
 function curFrame(){ return Math.max(0,Math.min(D.nFrames-1, Math.round(vid.currentTime*FPS)||0)); }
 function bodyX(){ return offX+(dcx(shown,facing)-0.5)*PLANE_W; }   // TRUE position carried by the footage
 function placeDancer(){ dancer.scale.x=facing; grp.position.x=offX; shadow.position.x=bodyX(); }
 function doCut(B,space){
   const nf= space===2 ? -facing : facing;
   if(B===shown){ offX += (dcx(shown,facing)-dcx(shown,nf))*PLANE_W; facing=nf; lastNode=B; return; }  // in-place mirror
   pending={B, nf, from:shown, ff:facing}; lastNode=B; seeking=true; seekT=performance.now(); vid.currentTime=B/FPS;
 }
 function capture(){ if(cnv.width){ cctx.drawImage(vid,0,0,cnv.width,cnv.height); vtex.needsUpdate=true; } }
 // frame-presentation callback: capture the EXACT presented frame AND resolve the
 // pending mirror in one step — texture + flip are set together, never a frame apart.
 function splice(p){ offX += (dcx(p.from,p.ff)-dcx(p.B,p.nf))*PLANE_W; facing=p.nf; shown=p.B; }  // seamless cut
 function onFrame(_,meta){
   presented=Math.max(0,Math.min(D.nFrames-1, Math.round(meta.mediaTime*FPS)));
   if(pending){ if(Math.abs(presented-pending.B)<=1){ splice(pending); pending=null; seeking=false; } }
   else { shown=presented; }
   capture();
   vid.requestVideoFrameCallback(onFrame);
 }
 function syncFrame(now){        // fallback only when rVFC is unavailable
   if(hasRVFC) return;
   presented=curFrame();
   if(pending){ if(Math.abs(presented-pending.B)<=1 || now-seekT>500){ splice(pending); pending=null; seeking=false; } }
   else shown=presented;
   capture();
 }
 vid.addEventListener('ended',()=>{ doCut(nodesSorted[(Math.random()*nodesSorted.length)|0],1); vid.play(); });
 vid.addEventListener('loadedmetadata',()=>{ cnv.width=vid.videoWidth; cnv.height=vid.videoHeight; });
 vid.addEventListener('loadeddata',()=>{ if(!cnv.width){ cnv.width=vid.videoWidth; cnv.height=vid.videoHeight; }
   vid.currentTime=D.start/FPS; presented=shown=D.start; lastNode=D.start; vid.play();
   if(hasRVFC) vid.requestVideoFrameCallback(onFrame); });
 const BETA=5.0;
 function selectMove(targetX){     // the BALL drives which path we tunnel to (weighted-random, target-biased)
   const es=D.edges[shown]; if(!es) return;
   const want=targetX-bodyX(); const dir=Math.abs(want)<0.5?0:Math.sign(want);   // dead-zone near target → ambient
   const scored=es.map(e=>{ const B=e[0], space=e[1], w=e[2];
       const nf= space===2?-facing:facing;
       const drift=(CX[nextNode(B)]-CX[B])*(nf>0?1:-1);   // footage drift if we take this path
       return {B,space, s:w*Math.exp(BETA*dir*drift)}; });
   const tot=scored.reduce((a,c)=>a+c.s,0); let r=Math.random()*tot, pick=scored[scored.length-1];
   for(const c of scored){ r-=c.s; if(r<=0){pick=c;break;} }
   doCut(pick.B,pick.space);     // mirror tunneling allowed — sequenced on the render clock
 }

 // ---- fly camera ----
 let yaw=0, pitch=-0.05; cam.position.set(0,2.6,16);
 const keys={}; let dragging=false, px=0, py=0;
 const typing=()=>document.activeElement && document.activeElement.id==='pw';
 R.domElement.addEventListener('mousedown',e=>{dragging=true;px=e.clientX;py=e.clientY;document.body.classList.add('drag');});
 addEventListener('mouseup',()=>{dragging=false;document.body.classList.remove('drag');});
 addEventListener('mousemove',e=>{ if(!dragging)return; yaw-=(e.clientX-px)*0.003; pitch-=(e.clientY-py)*0.003;
   pitch=Math.max(-1.3,Math.min(1.3,pitch)); px=e.clientX; py=e.clientY; });
 addEventListener('keydown',e=>{ if(typing())return; keys[e.code]=true; });
 addEventListener('keyup',e=>{ keys[e.code]=false; });
 function fly(dt){
   const sp=(keys['ShiftLeft']||keys['ShiftRight']?14:6)*dt;
   const f=new THREE.Vector3(-Math.sin(yaw),0,-Math.cos(yaw));
   const rt=new THREE.Vector3(Math.cos(yaw),0,-Math.sin(yaw));
   if(keys['KeyW'])cam.position.addScaledVector(f,sp);
   if(keys['KeyS'])cam.position.addScaledVector(f,-sp);
   if(keys['KeyD'])cam.position.addScaledVector(rt,sp);
   if(keys['KeyA'])cam.position.addScaledVector(rt,-sp);
   if(keys['KeyE'])cam.position.y+=sp; if(keys['KeyQ'])cam.position.y-=sp;
   cam.position.y=Math.max(0.6,cam.position.y);
   cam.quaternion.setFromEuler(new THREE.Euler(pitch,yaw,0,'YXZ'));
 }

 // ---- proximity / password ----
 const bubble=document.getElementById('bubble'), pw=document.getElementById('pw');
 pw.addEventListener('keydown',e=>{ if(e.key==='Enter'){ bubble.firstChild.textContent="…welcome."; pw.value="";
     setTimeout(()=>{ kneeling=false; bubble.style.display='none'; bubble.firstChild.textContent="May I have the password?"; vid.play(); },900);} });
 function projectHead(){
   const v=new THREE.Vector3(bodyX(),2.35,PLANE_Z).project(cam);   // above her kneeling head
   return {x:(v.x*0.5+0.5)*innerWidth, y:(-v.y*0.5+0.5)*innerHeight, front:v.z<1};
 }

 addEventListener('click',()=>{ if(vid.paused && !kneeling) vid.play(); });

 // ---- loop ----
 let prev=performance.now(), t0=performance.now();
 function loop(){
   requestAnimationFrame(loop);
   const now=performance.now(), dt=Math.min(.05,(now-prev)/1000); prev=now;
   fly(dt);
   att.position.set(ATTX,0.16,ACZ);                 // stationary target (chase test)
   ring.position.x=att.position.x; ring.position.z=att.position.z;
   syncFrame(now);            // fallback frame sync when rVFC is unavailable
   if(seeking && now-seekT>600){ if(pending){ splice(pending); pending=null; } seeking=false; capture(); }  // stuck-seek watchdog

   // proximity?
   const close=Math.hypot(cam.position.x-bodyX(),cam.position.z-PLANE_Z)<4.2;
   if(close && !kneeling){ kneeling=true; doCut(D.kneel,1); vid.pause(); bubble.style.display='block'; if(document.activeElement!==pw)pw.focus(); }
   if(kneeling){
     const h=projectHead(); bubble.style.left=h.x+'px'; bubble.style.top=Math.max(14,h.y-12)+'px';
     bubble.style.display=h.front?'block':'none';
     if(!close){ kneeling=false; bubble.style.display='none'; vid.play(); }
   } else {
     if(vid.paused) vid.play();
     if(!seeking && nodeSet.has(shown) && shown!==lastNode){ lastNode=shown; selectMove(att.position.x); }   // ball-biased path choice
   }
   placeDancer();
   R.render(scene,cam);
   const reached=Math.abs(bodyX()-att.position.x)<0.5;
   document.getElementById('stat').innerHTML =
     `x ${bodyX().toFixed(1)} · ${kneeling?'<b>kneeling</b>':(reached?'arrived':'drawn to attractor')}`;
 }
 window.__dbg={cam,att,grp,get x(){return bodyX();},get kneeling(){return kneeling;},get seeking(){return seeking;},get shown(){return shown;},get facing(){return facing;},get paused(){return vid.paused;}};
 loop();
 addEventListener('resize',()=>{cam.aspect=innerWidth/innerHeight;cam.updateProjectionMatrix();R.setSize(innerWidth,innerHeight);});
}
</script></body></html>
"""

if __name__ == "__main__":
    main()
