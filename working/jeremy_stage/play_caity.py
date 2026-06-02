#!/usr/bin/env python3
"""Pose-graph player for the Caity dancer (Type A / Type C).

Caity is a SPARSE pose graph, not continuous footage, so this walks node->node
at a limited-animation cadence and GLIDES her body toward each pose's recorded
stage centroid (cx) — the smooth 2009-stage feel — rather than snapping
frame-by-frame the way Jeremy's continuous player does.

Writes <play_dir>/index.html for the served data/bodies/caity_play dir; reads
caity.dancer.json (frames = tight sprites + per-pose cx; graph = nodes carrying
footage ordinals + Klein-four edges).

  .venv/bin/python working/jeremy_stage/play_caity.py        # writes index.html
"""
import os, sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PLAY = os.path.join(REPO, "data", "bodies", "caity_play")
DJSON = os.environ.get("DJSON", "caity.dancer.json")
TITLE = os.environ.get("TITLE", "Caity — Type A (super choreography)")
SUB   = os.environ.get("SUB", "49 poses · built from breadcrumbs")

HTML = r"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>__TITLE__</title>
<style>
 html,body{margin:0;height:100%;overflow:hidden;background:#05060a;font:13px/1.45 -apple-system,Helvetica,sans-serif;color:#cdd2df;cursor:grab}
 body.drag{cursor:grabbing}
 #hud{position:fixed;left:14px;top:12px;z-index:10;background:rgba(8,10,18,.74);padding:10px 13px;border-radius:8px;max-width:340px}
 #hud b{color:#e8edf7} #hud .k{color:#8ad6a0}
 #stat{position:fixed;right:14px;top:12px;z-index:10;background:rgba(8,10,18,.74);padding:8px 12px;border-radius:8px;font-variant-numeric:tabular-nums}
 #load{position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);color:#8ad6a0}
</style>
<script src="https://unpkg.com/three@0.128.0/build/three.min.js"></script>
</head><body>
<div id="hud"><b>__TITLE__</b><br>__SUB__<br>
<span class="k">drag</span> look · <span class="k">WASD</span> fly · <span class="k">QE</span> up/down<br>
<span class="k">&larr;&uarr;&darr;&rarr;</span> move attractor · <span class="k">C</span> chase · <span class="k">M</span> method</div>
<div id="stat"></div>
<div id="load">decoding footage…</div>
<script>
const DJSON="__DJSON__";
const METHODS=["uniform","boltzmann","quantum","quantum","quantum","quantum","keyboard"];
function b64(s){const b=atob(s),u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u;}
fetch(DJSON).then(r=>r.json()).then(J=>{document.getElementById('load').remove();start(J);});

function start(J){
 const RW=J.nw,RH=J.nh,PAL=J.palette,AR=RW/RH;
 const PH=3.4, PW=PH*AR, STAGE_W=12, STEP_MS=200, BETA=2.0;
 const FR=J.frames.map(f=>({x:f.x,y:f.y,w:f.w,h:f.h,cx:f.cx,facing:f.facing,mask:b64(f.mask),idx:b64(f.idx)}));
 const nodes=J.graph.nodes;                       // {ord,sym,edges:[{dst,time,space}]}
 const CX=nodes.map(n=>FR[n.ord].cx);             // each node's stage centroid
 const posX=i=>(CX[i]-0.5)*STAGE_W;

 // ---- paint a node's tight sprite into the notional canvas ----
 const cv=document.createElement('canvas');cv.width=RW;cv.height=RH;
 const ctx=cv.getContext('2d');const img=ctx.createImageData(RW,RH);
 function paint(ni){const f=FR[nodes[ni].ord],d=img.data;d.fill(0);let oi=0;
   for(let r=0;r<f.h;r++)for(let c=0;c<f.w;c++){if(f.mask[r*f.w+c]){const col=PAL[f.idx[oi++]];
     const p=((f.y+r)*RW+(f.x+c))*4;d[p]=col[0];d[p+1]=col[1];d[p+2]=col[2];d[p+3]=255;}}
   ctx.putImageData(img,0,0);tex.needsUpdate=true;}

 // ---- 3D stage ----
 const R=new THREE.WebGLRenderer({antialias:true});R.setPixelRatio(devicePixelRatio);
 R.setSize(innerWidth,innerHeight);R.outputEncoding=THREE.sRGBEncoding;document.body.appendChild(R.domElement);
 const scene=new THREE.Scene();scene.background=new THREE.Color(0x05060a);scene.fog=new THREE.Fog(0x05060a,22,60);
 const cam=new THREE.PerspectiveCamera(50,innerWidth/innerHeight,0.1,300);cam.position.set(0,2.8,13);
 scene.add(new THREE.AmbientLight(0xb7c2dd,1.0));
 const floor=new THREE.Mesh(new THREE.PlaneGeometry(STAGE_W+8,16),new THREE.MeshStandardMaterial({color:0x14171f,roughness:.97}));
 floor.rotation.x=-Math.PI/2;floor.position.z=-1;scene.add(floor);
 const back=new THREE.Mesh(new THREE.PlaneGeometry(STAGE_W+8,12),new THREE.MeshStandardMaterial({color:0x0c0e15,roughness:1}));
 back.position.set(0,6,-6);scene.add(back);
 const line=new THREE.Mesh(new THREE.PlaneGeometry(STAGE_W+8,.03),new THREE.MeshBasicMaterial({color:0x2b3550}));
 line.rotation.x=-Math.PI/2;line.position.y=.02;scene.add(line);
 const tex=new THREE.CanvasTexture(cv);tex.minFilter=THREE.LinearFilter;tex.magFilter=THREE.NearestFilter;tex.generateMipmaps=false;
 const dmat=new THREE.MeshBasicMaterial({map:tex,transparent:true,alphaTest:0.5,side:THREE.DoubleSide});
 const dancer=new THREE.Mesh(new THREE.PlaneGeometry(PW,PH),dmat);
 const grp=new THREE.Group();grp.add(dancer);dancer.position.y=PH/2;scene.add(grp);
 const shadow=new THREE.Mesh(new THREE.CircleGeometry(.7,24),new THREE.MeshBasicMaterial({color:0,transparent:true,opacity:.32}));
 shadow.rotation.x=-Math.PI/2;shadow.position.y=.015;scene.add(shadow);
 const att=new THREE.Mesh(new THREE.SphereGeometry(.18,20,20),new THREE.MeshBasicMaterial({color:0x9be0b0}));
 const ring=new THREE.Mesh(new THREE.RingGeometry(.30,.36,30),new THREE.MeshBasicMaterial({color:0x9be0b0,transparent:true,opacity:.6,side:THREE.DoubleSide}));
 ring.rotation.x=-Math.PI/2;scene.add(att);scene.add(ring);
 let ballX=0,ballZ=0.6;

 // ---- walk state ----
 let cur=J.graph.start||0, mirror=false, worldX=posX(cur), targetX=worldX;
 let method=0, chase=false, intent=0, lastStep=0;   // default: free local wander, NOT chasing
 function weighted(sc){const t=sc.reduce((a,c)=>a+c.s,0)||1;let r=Math.random()*t,p=sc[sc.length-1];
   for(const c of sc){r-=c.s;if(r<=0){p=c;break;}} return p.e;}
 function pickEdge(){
   const es=nodes[cur].edges; if(!es.length) return null;
   const m=METHODS[method];
   if(chase || m==="boltzmann" || m==="quantum")    // chase the attractor (opt-in)
     return weighted(es.map(e=>({e,s:Math.exp(-BETA*Math.abs(posX(e.dst)-ballX))})));
   if(m==="keyboard" && intent!==0){                // steer toward intent
     const want=es.filter(e=>Math.sign(posX(e.dst)-worldX)===intent);
     const pool=want.length?want:es; return pool[(Math.random()*pool.length)|0];
   }
   // free run: follow her phrases — strongly prefer the small recorded-adjacent
   // moves over the long connectivity jumps, so she dances ~in place, no sliding
   return weighted(es.map(e=>({e,s:1/(1+Math.abs(posX(e.dst)-worldX)*4)})));
 }
 function step(){const e=pickEdge(); if(!e) return; if(e.space===1)mirror=!mirror; cur=e.dst; targetX=posX(cur);}

 let yaw=0,pitch=-0.05;const keys={};let drag=false,px=0,py=0;
 R.domElement.addEventListener('mousedown',e=>{drag=true;px=e.clientX;py=e.clientY;document.body.classList.add('drag');});
 addEventListener('mouseup',()=>{drag=false;document.body.classList.remove('drag');});
 addEventListener('mousemove',e=>{if(!drag)return;yaw-=(e.clientX-px)*.003;pitch-=(e.clientY-py)*.003;pitch=Math.max(-1.3,Math.min(1.3,pitch));px=e.clientX;py=e.clientY;});
 addEventListener('keydown',e=>{keys[e.code]=true;
   if(e.code==='ArrowLeft')intent=-1; if(e.code==='ArrowRight')intent=1; if(e.code==='ArrowDown')intent=0;
   if(e.code==='KeyC')chase=!chase; if(e.code==='KeyM')method=(method+1)%METHODS.length;
   if(e.code.startsWith('Arrow'))e.preventDefault();});
 addEventListener('keyup',e=>keys[e.code]=false);
 function fly(dt){const sp=(keys['ShiftLeft']?14:6)*dt;
   const f=new THREE.Vector3(-Math.sin(yaw),0,-Math.cos(yaw)),rt=new THREE.Vector3(Math.cos(yaw),0,-Math.sin(yaw));
   if(keys['KeyW'])cam.position.addScaledVector(f,sp);if(keys['KeyS'])cam.position.addScaledVector(f,-sp);
   if(keys['KeyD'])cam.position.addScaledVector(rt,sp);if(keys['KeyA'])cam.position.addScaledVector(rt,-sp);
   if(keys['KeyE'])cam.position.y+=sp;if(keys['KeyQ'])cam.position.y-=sp;cam.position.y=Math.max(.6,cam.position.y);
   cam.quaternion.setFromEuler(new THREE.Euler(pitch,yaw,0,'YXZ'));}

 let prev=performance.now();
 function loop(){requestAnimationFrame(loop);
   const now=performance.now(),dt=Math.min(.05,(now-prev)/1000);prev=now;fly(dt);
   const bsp=6*dt;
   if(keys['ArrowLeft'])ballX-=bsp;if(keys['ArrowRight'])ballX+=bsp;
   if(keys['ArrowUp'])ballZ-=bsp;if(keys['ArrowDown'])ballZ+=bsp;
   ballX=Math.max(-STAGE_W/2,Math.min(STAGE_W/2,ballX));ballZ=Math.max(-3,Math.min(3,ballZ));
   att.position.set(ballX,.18,ballZ);ring.position.set(ballX,.02,ballZ);
   if(now-lastStep>STEP_MS){step();lastStep=now;}
   worldX+=(targetX-worldX)*Math.min(1,dt*7);     // glide between poses (the stride)
   grp.position.x=worldX;dancer.scale.x=mirror?-1:1;shadow.position.x=worldX;
   grp.rotation.y=Math.atan2(cam.position.x-grp.position.x,cam.position.z-grp.position.z);
   paint(cur);R.render(scene,cam);
   document.getElementById('stat').innerHTML=`pose ${cur}/${nodes.length}${mirror?' ⇄':''} · method <b>${METHODS[method]}</b>${chase?' · chasing':''} · x ${worldX.toFixed(1)}`;
 }
 paint(cur);loop();
 addEventListener('resize',()=>{cam.aspect=innerWidth/innerHeight;cam.updateProjectionMatrix();R.setSize(innerWidth,innerHeight);});
}
</script></body></html>
"""


def main():
    os.makedirs(PLAY, exist_ok=True)
    html = HTML.replace("__TITLE__", TITLE).replace("__SUB__", SUB).replace("__DJSON__", DJSON)
    open(os.path.join(PLAY, "index.html"), "w").write(html)
    print("wrote %s/index.html (DJSON=%s)" % (PLAY, DJSON))


if __name__ == "__main__":
    main()
