#!/usr/bin/env python3
"""New player for the compressed 'little images' footage.

Plays the tight sprites from compress_footage.py DIRECTLY — no 720-wide
reconstitution. Each sprite is drawn as a quad sized to its real proportion of
the notional frame and placed by its anchor (centroid), with the same
graph + controller + cut-compensation as the faithful player. This validates
the adjusted animation model before we freeze the 0xda byte layout.

Loads:
  live/jeremy_c/footage.json + atlas_NN.png   (the compressed footage)
  live/player.json                            (the motion graph, reused)

Run:  .venv/bin/python working/avatari/play_compressed.py   (serves on :8790)
"""
import os, http.server, socketserver, functools

HERE = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(HERE, "live", "jeremy_c")
PORT = int(os.environ.get("PORT", "8790"))

HTML = r"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>compressed player</title>
<style>
 html,body{margin:0;height:100%;overflow:hidden;background:#05060a;font:13px/1.4 -apple-system,Helvetica,sans-serif;color:#cdd2df;cursor:grab}
 body.drag{cursor:grabbing}
 #hud{position:fixed;left:14px;top:12px;z-index:10;background:rgba(8,10,18,.72);padding:9px 12px;border-radius:8px}
 #hud .k{color:#8ad6a0}
 #stat{position:fixed;right:14px;top:12px;z-index:10;background:rgba(8,10,18,.72);padding:7px 11px;border-radius:8px;font-variant-numeric:tabular-nums}
</style>
<script src="https://unpkg.com/three@0.128.0/build/three.min.js"></script>
</head><body>
<div id="hud"><b>player · compressed footage</b><br><span class="k">drag</span> look · <span class="k">WASD</span> move · <span class="k">QE</span> up/down<br><span class="k">&larr;&uarr;&darr;&rarr;</span> move the attractor</div>
<div id="stat"></div>
<script>
Promise.all([fetch('footage.json').then(r=>r.json()), fetch('../player.json').then(r=>r.json())])
.then(([F,D])=>Promise.all(
  Array.from({length:F.pages},(_,p)=>new Promise(res=>{const im=new Image();im.onload=()=>res(im);im.src='atlas_'+String(p).padStart(2,'0')+'.png';}))
).then(imgs=>start(F,D,imgs)));

function start(F, D, atlasImgs){
 const FPS=F.fps, RW=F.RW, RH=F.RH, AR=RW/RH;
 const PH=4.5, PW=PH*AR;                  // plane = the notional frame
 const AW=F.cols*F.cell_w, AH=F.rows*F.cell_h;
 const FR=F.frames;
 const nF=FR.length;
 const nodeSet=new Set(D.nodeFrames);
 const dcx=(f,m)=> m ? 1-FR[f].cx : FR[f].cx;          // centroid, mirror-aware

 const R=new THREE.WebGLRenderer({antialias:true}); R.setPixelRatio(devicePixelRatio);
 R.setSize(innerWidth,innerHeight); R.outputEncoding=THREE.sRGBEncoding; document.body.appendChild(R.domElement);
 const scene=new THREE.Scene(); scene.background=new THREE.Color(0x05060a); scene.fog=new THREE.Fog(0x05060a,22,60);
 const cam=new THREE.PerspectiveCamera(55,innerWidth/innerHeight,0.1,300);
 scene.add(new THREE.AmbientLight(0xb7c2dd,1.0));
 const floor=new THREE.Mesh(new THREE.PlaneGeometry(48,18),new THREE.MeshStandardMaterial({color:0x14171f,roughness:.97}));
 floor.rotation.x=-Math.PI/2; floor.position.set(0,0,-1); scene.add(floor);
 const back=new THREE.Mesh(new THREE.PlaneGeometry(48,14),new THREE.MeshStandardMaterial({color:0x0c0e15,roughness:1}));
 back.position.set(0,7,-6); scene.add(back);
 // a faint baseline so we can see the feet land on the floor
 const line=new THREE.Mesh(new THREE.PlaneGeometry(48,0.03),new THREE.MeshBasicMaterial({color:0x2b3550}));
 line.rotation.x=-Math.PI/2; line.position.y=0.02; scene.add(line);

 // atlas pages -> textures
 const pages=atlasImgs.map(im=>{const t=new THREE.CanvasTexture(im);t.flipY=false;t.encoding=THREE.sRGBEncoding;
   t.minFilter=THREE.LinearFilter;t.magFilter=THREE.LinearFilter;t.generateMipmaps=false;return t;});
 const dmat=new THREE.MeshBasicMaterial({transparent:true,alphaTest:0.5,side:THREE.DoubleSide});
 const dancer=new THREE.Mesh(new THREE.PlaneGeometry(1,1),dmat);   // unit quad, scaled per frame
 scene.add(dancer);
 const shadow=new THREE.Mesh(new THREE.CircleGeometry(.5,24),new THREE.MeshBasicMaterial({color:0,transparent:true,opacity:.32}));
 shadow.rotation.x=-Math.PI/2; shadow.position.y=.015; scene.add(shadow);
 const att=new THREE.Mesh(new THREE.SphereGeometry(0.18,20,20),new THREE.MeshBasicMaterial({color:0x9be0b0}));
 const ring=new THREE.Mesh(new THREE.RingGeometry(.30,.36,30),new THREE.MeshBasicMaterial({color:0x9be0b0,transparent:true,opacity:.6,side:THREE.DoubleSide}));
 ring.rotation.x=-Math.PI/2; scene.add(att); scene.add(ring);
 let ballX=0, ballZ=0.6;

 function showFrame(f){
   const r=FR[f], t=pages[r.page];
   t.repeat.set(r.w/AW, -r.h/AH);
   t.offset.set(r.u/AW, (r.v+r.h)/AH);
   dmat.map=t; dmat.needsUpdate=true;
 }

 // ---- faithful player loop (same controller as build_player) ----
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
   if(v===3){
     const bodyX=offX+(dcx(node,mirror)-0.5)*PW;
     return wpick(es.map(e=>{ const nm=e[2]===2?!mirror:mirror; const land=bodyX+excursion(e[0],nm);
       return {e, s:e[3]*Math.exp(-BETA*Math.abs(land-ballX))}; }));
   }
   return wpick(es.map(e=>({e, s:e[3]})));
 }
 function stepFrame(){
   const prevN=N, prevM=mirror;
   N+=d; if(N<0){N=0;d=1;} else if(N>=nF){N=nF-1;d=-1;}
   if(nodeSet.has(N)){
     const e=pickEdge(N);
     if(e){ const dst=e[0], tm=e[1], sp=e[2]; const newM = sp===2 ? !mirror : mirror;
       if(Math.abs(dst-prevN)>1 || newM!==prevM)
         offX += (dcx(prevN,prevM)-dcx(dst,newM))*PW;     // centroid compensation
       N=dst; d = tm===1?1:-1; mirror=newM;
     }
   }
 }
 function place(){
   const r=FR[N];
   const centerFrac = r.fx + r.fw/2;
   const cF = mirror ? 1-centerFrac : centerFrac;        // sprite center, rigid to centroid
   const x = offX + (cF-0.5)*PW;
   const y = PH*(1-(r.fy + r.fh/2));                     // feet on the floor
   showFrame(N);
   dancer.scale.set(r.fw*PW*(mirror?-1:1), r.fh*PH, 1);
   dancer.position.set(x, y, 0);
   shadow.position.x = offX + (dcx(N,mirror)-0.5)*PW;    // ground point at the centroid
 }

 // ---- fly camera ----
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
   document.getElementById('stat').innerHTML=`frame ${N} · ${d>0?'▶':'◀'}${mirror?' ⇄':''} · ${RW}×${RH} sprites · x ${(offX+(dcx(N,mirror)-0.5)*PW).toFixed(1)} → ball ${ballX.toFixed(1)}`;
 }
 showFrame(N); place(); loop();
 addEventListener('resize',()=>{cam.aspect=innerWidth/innerHeight;cam.updateProjectionMatrix();R.setSize(innerWidth,innerHeight);});
}
</script></body></html>
"""


def main():
    with open(os.path.join(OUT, "play.html"), "w") as f:
        f.write(HTML)
    os.chdir(HERE)
    Handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=HERE)
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print("compressed player at  http://localhost:%d/live/jeremy_c/play.html" % PORT)
        httpd.serve_forever()


if __name__ == "__main__":
    main()
