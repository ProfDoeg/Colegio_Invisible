#!/usr/bin/env python3
"""Generate a DELTA-decoded player for Jeremy: frames reconstructed live from
keyframes + per-frame diffs, to show the delta-coded footage plays identically
to the sparse baseline (delta coding is lossless — same pixels, fewer bytes).

Emits into live/jeremy_c/ (served by the running play_compressed server on :8790):
  delta.json   {meta, palette, cx[], key{frame:b64 triples}, diff[ b64 triples ]}
  delta.html   a player that rebuilds each frame from the nearest keyframe + diffs

Variant (c): a keyframe every KEY frames (random-access). Variant (b) is the
same pixels with fewer keyframes — identical on screen, so this one player shows
both. Run:  RH=128 KEY=30 .venv/bin/python working/avatari/play_delta.py
"""
import os, sys, json, base64, math
import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
FR   = os.path.join(HERE, "_frames_jeremy")
CEN  = os.path.join(HERE, "_centroids_jeremy.json")
OUT  = os.path.join(HERE, "live", "jeremy_c")
RH   = int(os.environ.get("RH", "128"))
PALN = int(os.environ.get("PALN", "32"))
ALPHA= int(os.environ.get("ALPHA", "100"))
KEY  = int(os.environ.get("KEY", "30"))
STEP = int(os.environ.get("STEP", "1"))          # frame decimation: 1=30fps, 2=15fps
NAME = os.environ.get("OUTNAME", "delta")        # output basename (delta / delta16 / ...)
FPS  = round(30 / STEP)
GRAPH = os.path.join(os.path.dirname(__file__), "live", "player.json")


def main():
    files = sorted(f for f in os.listdir(FR) if f.startswith("f_"))
    nF = len(files)
    sw0, sh0 = Image.open(os.path.join(FR, files[0])).size
    RW = round(RH * sw0 / sh0)
    cxs = json.load(open(CEN))

    samp = []
    for k in range(0, nF, 30):
        im = Image.open(os.path.join(FR, files[k])).convert("RGBA").resize((RW, RH), Image.LANCZOS)
        a = np.asarray(im)[..., 3]; rgb = np.asarray(im.convert("RGB"))[a > ALPHA]
        if len(rgb): samp.append(rgb[:: max(1, len(rgb)//400)])
    samp = np.concatenate(samp, 0)
    master = Image.fromarray(samp.reshape(-1, 1, 3).astype("uint8")).quantize(colors=PALN, method=Image.MEDIANCUT)
    pf = master.getpalette()[:PALN*3]
    palette = [[pf[3*i], pf[3*i+1], pf[3*i+2]] for i in range(PALN)]

    def state(fn):
        im = Image.open(os.path.join(FR, fn)).convert("RGBA").resize((RW, RH), Image.LANCZOS)
        a = np.asarray(im)[..., 3]
        q = np.asarray(im.convert("RGB").quantize(palette=master, dither=Image.Dither.NONE)).astype(np.int16)
        return np.where(a > ALPHA, q, -1).reshape(-1)

    kept = list(range(0, nF, STEP))                        # decimated frame indices
    nK = len(kept)
    key, diff = {}, [""]
    raw = 96                                                # palette bytes (32*3)
    P = None
    for k, orig in enumerate(kept):
        S = state(files[orig])
        if k % KEY == 0:                                   # keyframe: opaque triples
            op = np.where(S >= 0)[0]
            buf = bytearray()
            for p in op:
                buf += bytes([p & 255, p >> 8, int(S[p])])
            key[str(k)] = base64.b64encode(bytes(buf)).decode(); raw += len(buf)
        if P is not None:                                  # diff vs previous
            chg = np.where(S != P)[0]
            buf = bytearray()
            for p in chg:
                v = int(S[p]); buf += bytes([p & 255, p >> 8, 255 if v < 0 else v])
            diff.append(base64.b64encode(bytes(buf)).decode()); raw += len(buf)
        P = S
        if k % 400 == 0: print("  ...", k)

    # ---- remap the motion graph into the decimated frame numbering ----
    G = json.load(open(GRAPH))
    mp = lambda f: min(nK - 1, round(f / STEP))
    nodes_new = sorted({mp(f) for f in G["nodeFrames"]})
    edges_new, var_new = {}, {}
    for f in G["nodeFrames"]:
        nf = mp(f)
        for e in G["edges"][str(f)]:
            edges_new.setdefault(str(nf), []).append([mp(e[0]), e[1], e[2], e[3], e[4]])
        if str(f) in G.get("variant", {}):
            var_new[str(nf)] = G["variant"][str(f)]
    graph = dict(nodeFrames=nodes_new, edges=edges_new, variant=var_new, start=mp(G["start"]))

    data = dict(meta=dict(RW=RW, RH=RH, fps=FPS, key=KEY, nF=nK, palette=palette),
                cx=[round(float(cxs[o]), 4) for o in kept], key=key, diff=diff, graph=graph)
    json.dump(data, open(os.path.join(OUT, NAME + ".json"), "w"))
    open(os.path.join(OUT, NAME + ".html"), "w").write(
        HTML.replace("fetch('delta.json')", "fetch('%s.json')" % NAME))
    sz = os.path.getsize(os.path.join(OUT, NAME + ".json"))
    print("wrote %s.json  (%d frames @ %d fps, %d colors, %d keyframes, browser json %.1f MB)"
          % (NAME, nK, FPS, PALN, len(key), sz/1e6))
    print("  NOTE: browser json is UNPACKED 3-byte triples; for the real packed"
          " on-chain size run delta_footage.py at the same RH/PALN/STEP.")
    print("open  http://localhost:8790/live/jeremy_c/%s.html" % NAME)


HTML = r"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>delta player</title>
<style>
 html,body{margin:0;height:100%;overflow:hidden;background:#05060a;font:13px/1.4 -apple-system,Helvetica,sans-serif;color:#cdd2df;cursor:grab}
 body.drag{cursor:grabbing}
 #hud{position:fixed;left:14px;top:12px;z-index:10;background:rgba(8,10,18,.72);padding:9px 12px;border-radius:8px}
 #hud .k{color:#8ad6a0}
 #stat{position:fixed;right:14px;top:12px;z-index:10;background:rgba(8,10,18,.72);padding:7px 11px;border-radius:8px;font-variant-numeric:tabular-nums}
</style>
<script src="https://unpkg.com/three@0.128.0/build/three.min.js"></script>
</head><body>
<div id="hud"><b>player · delta-decoded</b><br><span class="k">drag</span> look · <span class="k">WASD</span> move · <span class="k">QE</span> up/down<br><span class="k">&larr;&uarr;&darr;&rarr;</span> move the attractor</div>
<div id="stat"></div>
<script>
fetch('delta.json').then(r=>r.json()).then(J=>{
  (J.graph ? Promise.resolve(J.graph) : fetch('../player.json').then(r=>r.json())).then(D=>start(J,D));
});

function b64(s){const bin=atob(s);const u=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)u[i]=bin.charCodeAt(i);return u;}

function start(J, D){
 const M=J.meta, RW=M.RW, RH=M.RH, nF=M.nF, KEY=M.key, FPS=M.fps, AR=RW/RH;
 const PH=4.5, PW=PH*AR;
 const PAL=M.palette, CX=J.cx;
 // decode keyframes + diffs to typed arrays
 const KF={}; for(const k in J.key) KF[k]=b64(J.key[k]);
 const DF=J.diff.map(s=>s?b64(s):new Uint8Array(0));
 const state=new Int16Array(RW*RH);
 let curF=-1;
 function loadKey(k){ state.fill(-1); const u=KF[String(k)]; for(let i=0;i<u.length;i+=3){ const p=u[i]|(u[i+1]<<8); state[p]=u[i+2]; } }
 function applyDiff(f){ const u=DF[f]; for(let i=0;i<u.length;i+=3){ const p=u[i]|(u[i+1]<<8), v=u[i+2]; state[p]=(v===255)?-1:v; } }
 function reconstruct(target){
   if(target===curF) return;
   if(target===curF+1 && curF>=0){ applyDiff(target); curF=target; return; }
   const k=Math.floor(target/KEY)*KEY; loadKey(k);
   for(let j=k+1;j<=target;j++) applyDiff(j);
   curF=target;
 }
 // canvas the reconstructed notional frame is painted into -> texture
 const cv=document.createElement('canvas'); cv.width=RW; cv.height=RH;
 const ctx=cv.getContext('2d'); const img=ctx.createImageData(RW,RH);
 function paint(){ const d=img.data; for(let i=0,j=0;i<state.length;i++,j+=4){ const s=state[i];
   if(s>=0){ const c=PAL[s]; d[j]=c[0]; d[j+1]=c[1]; d[j+2]=c[2]; d[j+3]=255; } else { d[j+3]=0; } }
   ctx.putImageData(img,0,0); tex.needsUpdate=true; }
 const dcx=(f,m)=> m ? 1-CX[f] : CX[f];

 const R=new THREE.WebGLRenderer({antialias:true}); R.setPixelRatio(devicePixelRatio);
 R.setSize(innerWidth,innerHeight); R.outputEncoding=THREE.sRGBEncoding; document.body.appendChild(R.domElement);
 const scene=new THREE.Scene(); scene.background=new THREE.Color(0x05060a); scene.fog=new THREE.Fog(0x05060a,22,60);
 const cam=new THREE.PerspectiveCamera(55,innerWidth/innerHeight,0.1,300);
 scene.add(new THREE.AmbientLight(0xb7c2dd,1.0));
 const floor=new THREE.Mesh(new THREE.PlaneGeometry(48,18),new THREE.MeshStandardMaterial({color:0x14171f,roughness:.97}));
 floor.rotation.x=-Math.PI/2; floor.position.set(0,0,-1); scene.add(floor);
 const back=new THREE.Mesh(new THREE.PlaneGeometry(48,14),new THREE.MeshStandardMaterial({color:0x0c0e15,roughness:1}));
 back.position.set(0,7,-6); scene.add(back);
 const line=new THREE.Mesh(new THREE.PlaneGeometry(48,0.03),new THREE.MeshBasicMaterial({color:0x2b3550}));
 line.rotation.x=-Math.PI/2; line.position.y=0.02; scene.add(line);

 const tex=new THREE.CanvasTexture(cv); tex.minFilter=THREE.LinearFilter; tex.magFilter=THREE.LinearFilter; tex.generateMipmaps=false;
 const dmat=new THREE.MeshBasicMaterial({map:tex,transparent:true,alphaTest:0.5,side:THREE.DoubleSide});
 const dancer=new THREE.Mesh(new THREE.PlaneGeometry(PW,PH),dmat);
 const grp=new THREE.Group(); grp.add(dancer); dancer.position.y=PH/2; scene.add(grp);
 const shadow=new THREE.Mesh(new THREE.CircleGeometry(.5,24),new THREE.MeshBasicMaterial({color:0,transparent:true,opacity:.32}));
 shadow.rotation.x=-Math.PI/2; shadow.position.y=.015; scene.add(shadow);
 const att=new THREE.Mesh(new THREE.SphereGeometry(0.18,20,20),new THREE.MeshBasicMaterial({color:0x9be0b0}));
 const ring=new THREE.Mesh(new THREE.RingGeometry(.30,.36,30),new THREE.MeshBasicMaterial({color:0x9be0b0,transparent:true,opacity:.6,side:THREE.DoubleSide}));
 ring.rotation.x=-Math.PI/2; scene.add(att); scene.add(ring);
 let ballX=0, ballZ=0.6;

 const nodeSet=new Set(D.nodeFrames);
 let N=D.start, d=1, mirror=false, offX=0;
 const BETA=2.0, EXK=6;
 const nodesSorted=D.nodeFrames.slice().sort((a,b)=>a-b);
 function nextNode(f){ for(const n of nodesSorted){ if(n>f) return n; } return nodesSorted[0]; }
 function excursion(dst,m){ let f=dst,net=0,w=1; for(let i=0;i<EXK;i++){ const nn=nextNode(f); net+=w*(dcx(nn,m)-dcx(f,m)); f=nn; w*=0.5; } return net*PW; }
 function wpick(scored){ const tot=scored.reduce((a,c)=>a+c.s,0); let r=Math.random()*tot,p=scored[scored.length-1];
   for(const c of scored){ r-=c.s; if(r<=0){p=c;break;} } return p.e; }
 function pickEdge(node){
   const es=(D.edges[node]||[]).filter(e=>e[3]>0); if(!es.length) return null;
   const v=D.variant[String(node)]||3;
   if(v===3){ const bodyX=offX+(dcx(node,mirror)-0.5)*PW;
     return wpick(es.map(e=>{ const nm=e[2]===2?!mirror:mirror; const land=bodyX+excursion(e[0],nm);
       return {e, s:e[3]*Math.exp(-BETA*Math.abs(land-ballX))}; })); }
   return wpick(es.map(e=>({e, s:e[3]})));
 }
 function stepFrame(){
   const prevN=N, prevM=mirror;
   N+=d; if(N<0){N=0;d=1;} else if(N>=nF){N=nF-1;d=-1;}
   if(nodeSet.has(N)){ const e=pickEdge(N);
     if(e){ const dst=e[0], tm=e[1], sp=e[2]; const newM=sp===2?!mirror:mirror;
       if(Math.abs(dst-prevN)>1||newM!==prevM) offX+=(dcx(prevN,prevM)-dcx(dst,newM))*PW;
       N=dst; d=tm===1?1:-1; mirror=newM; } }
 }
 function place(){ reconstruct(N); paint();
   dancer.scale.x = mirror?-1:1; grp.position.x = offX;
   shadow.position.x = offX + (dcx(N,mirror)-0.5)*PW; }

 let yaw=0,pitch=-0.04; cam.position.set(0,2.6,15);
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

 let prev=performance.now(), acc=0;
 function loop(){
   requestAnimationFrame(loop);
   const now=performance.now(), dt=Math.min(.1,(now-prev)/1000); prev=now;
   fly(dt);
   const bsp=6*dt;
   if(keys['ArrowLeft'])ballX-=bsp; if(keys['ArrowRight'])ballX+=bsp;
   if(keys['ArrowUp'])ballZ-=bsp; if(keys['ArrowDown'])ballZ+=bsp;
   ballX=Math.max(-8,Math.min(8,ballX)); ballZ=Math.max(-3,Math.min(3,ballZ));
   att.position.set(ballX,0.18,ballZ); ring.position.set(ballX,0.02,ballZ);
   acc+=dt; const STEP=1/FPS; let guard=0;
   while(acc>=STEP && guard++<8){ stepFrame(); acc-=STEP; }
   place();
   R.render(scene,cam);
   document.getElementById('stat').innerHTML=`frame ${N} · ${d>0?'▶':'◀'}${mirror?' ⇄':''} · delta-decoded · ball ${ballX.toFixed(1)}`;
 }
 reconstruct(N); paint(); loop();
 addEventListener('resize',()=>{cam.aspect=innerWidth/innerHeight;cam.updateProjectionMatrix();R.setSize(innerWidth,innerHeight);});
}
</script></body></html>
"""


if __name__ == "__main__":
    main()
