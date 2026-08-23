#!/usr/bin/env python3
"""Build quipu_out/pulse_globe.html — the atlas's history animated as a network pulse.

Every consecutive-stop leg of every journey fires in chronological order:
a gold flash decaying into the persistent blue skeleton, so the whole
network assembles itself across ~5000 years. Event-paced time (constant
pulses/sec), year readout + scrubbable event-space timeline. One shader,
one draw call for all arcs.
"""
import json, glob, os, re, math, collections

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'quipu_out', 'pulse_globe.html')
DONOR = os.path.join(HERE, 'quipu_out', 'joan_globe.html')

def datekey(iso):
    if not iso: return None
    neg = iso.startswith('-')
    p = ((iso[1:] if neg else iso).split('-') + ['1','1'])[:3]
    try: y, m, d = int(p[0]), int(p[1] or 1), int(p[2] or 1)
    except ValueError: return None
    frac = (m-1)/12.0 + (d-1)/372.0
    return (-y + frac) if neg else (y + frac)

J = {os.path.basename(f)[:-13]: json.load(open(f)) for f in sorted(glob.glob(os.path.join(HERE, '*.journey.json')))}
legs = []
for slug, j in J.items():
    seq = []
    for seg in j.get('segments', []):
        for s in seg.get('stops', []):
            if isinstance(s.get('lat'), (int, float)):
                seq.append((s['lat'], s['lng'], datekey(s.get('date',''))))
    for (la1,lo1,k1),(la2,lo2,k2) in zip(seq, seq[1:]):
        k = k2 if k2 is not None else k1
        if k is None: continue
        if abs(la1-la2) < 1e-6 and abs(lo1-lo2) < 1e-6: continue
        legs.append((k, round(la1,3), round(lo1,3), round(la2,3), round(lo2,3)))
legs.sort(key=lambda l: l[0])
print(f"legs with dates: {len(legs)}  span {legs[0][0]:.0f} .. {legs[-1][0]:.0f}")
LEGS = [[l[1], l[2], l[3], l[4]] for l in legs]
YEARS = [round(l[0], 2) for l in legs]

raw = open(DONOR).read()
three_start = raw.find('<script>/**')
three_end = raw.find('</script>', three_start) + len('</script>')
head = raw[:three_end]
assert three_start > 0
head += ('\n<style>#titlebar,#meta,#hint,#controls{display:none!important}'
         '#app{display:block!important}#stage{position:fixed!important;inset:0!important;'
         'width:100vw!important;height:100vh!important}</style>')

HEAL = os.path.join(HERE, '..', 'heal_earth')
topo = json.load(open(os.path.join(HEAL, 'land-50m.json')))
sc, tr = topo['transform']['scale'], topo['transform']['translate']
coast_lines = []
for arc in topo['arcs']:
    x = y = 0; pts = []
    for dx, dy in arc:
        x += dx; y += dy
        pts.append([round(x*sc[0]+tr[0], 3), round(y*sc[1]+tr[1], 3)])
    if len(pts) > 1: coast_lines.append(pts)

app = """
<script>
(function(){
  const THREE=window.THREE, R=1.0;
  const stage=document.getElementById('stage');
  function llv(lat,lng,r){
    const la=lat*Math.PI/180, lo=lng*Math.PI/180;
    return new THREE.Vector3(r*Math.cos(la)*Math.cos(lo), r*Math.sin(la), -r*Math.cos(la)*Math.sin(lo));
  }
  const scene=new THREE.Scene();
  const camera=new THREE.PerspectiveCamera(42,1,0.01,200);
  const D0=new THREE.Vector3(0,0.42,1).normalize();
  let camDist=2.7;
  function updateCam(){ camera.position.copy(D0).multiplyScalar(camDist); camera.lookAt(0,0,0); }
  const renderer=new THREE.WebGLRenderer({antialias:true});
  renderer.setPixelRatio(Math.min(devicePixelRatio,2)); stage.appendChild(renderer.domElement);
  scene.add(new THREE.AmbientLight(0xffffff,0.55));
  const sun=new THREE.DirectionalLight(0xfff2d0,0.9); sun.position.set(3,2,4); scene.add(sun);
  (function(){ const g=new THREE.BufferGeometry(), N=1400, a=new Float32Array(N*3);
    for(let i=0;i<N;i++){ const v=new THREE.Vector3(Math.random()-.5,Math.random()-.5,Math.random()-.5).normalize().multiplyScalar(60+Math.random()*40);
      a[i*3]=v.x;a[i*3+1]=v.y;a[i*3+2]=v.z; }
    g.setAttribute('position',new THREE.BufferAttribute(a,3));
    scene.add(new THREE.Points(g,new THREE.PointsMaterial({color:0x8fa3c8,size:0.05,sizeAttenuation:true,transparent:true,opacity:0.7}))); })();
  const globe=new THREE.Group(); scene.add(globe);
  globe.add(new THREE.Mesh(new THREE.SphereGeometry(R,64,64),
    new THREE.MeshPhongMaterial({color:0x0b1526,emissive:0x050a14,shininess:6,transparent:true,opacity:0.32,depthWrite:false})));
  (function(){ const segs=[];
    for(const line of COAST){ for(let i=0;i<line.length-1;i++){
      const a=llv(line[i][1],line[i][0],R*1.002), b=llv(line[i+1][1],line[i+1][0],R*1.002);
      segs.push(a.x,a.y,a.z,b.x,b.y,b.z); } }
    const g=new THREE.BufferGeometry(); g.setAttribute('position',new THREE.BufferAttribute(new Float32Array(segs),3));
    globe.add(new THREE.LineSegments(g,new THREE.LineBasicMaterial({color:0x8fd8f4,transparent:true,opacity:0.55}))); })();

  // ---- all legs as ONE LineSegments with a birth-index attribute -----------
  const N=LEGS.length;
  const pos=[], birth=[], along=[];
  for(let i=0;i<N;i++){
    const [la1,lo1,la2,lo2]=LEGS[i];
    const va=llv(la1,lo1,1), vb=llv(la2,lo2,1);
    const ang=va.angleTo(vb)||1e-4, lift=0.02+0.22*ang/Math.PI;
    const n=Math.max(6,Math.min(28,Math.round(ang*22)));
    let prev=null;
    for(let s=0;s<=n;s++){ const t=s/n;
      const v=va.clone().multiplyScalar(Math.sin((1-t)*ang)).add(vb.clone().multiplyScalar(Math.sin(t*ang))).divideScalar(Math.sin(ang));
      v.normalize().multiplyScalar(R*(1.008+lift*Math.sin(Math.PI*t)));
      if(prev){ pos.push(prev.x,prev.y,prev.z,v.x,v.y,v.z); birth.push(i,i); along.push((s-1)/n,t); }
      prev=v; }
  }
  const geo=new THREE.BufferGeometry();
  geo.setAttribute('position',new THREE.BufferAttribute(new Float32Array(pos),3));
  geo.setAttribute('birth',new THREE.BufferAttribute(new Float32Array(birth),1));
  geo.setAttribute('along',new THREE.BufferAttribute(new Float32Array(along),1));
  const mat=new THREE.ShaderMaterial({
    uniforms:{uNow:{value:0},uN:{value:N},uCyc:{value:-1.0},uRamp:{value:1.0},uSig:{value:0.055},uAmp:{value:1.0}},
    vertexShader:'attribute float birth; attribute float along; varying float vB; varying float vA;'+
      'void main(){ vB=birth; vA=along; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0); }',
    fragmentShader:'uniform float uNow; uniform float uN; uniform float uCyc; uniform float uRamp; uniform float uSig; uniform float uAmp; varying float vB; varying float vA;'+
      'void main(){ float flash; float base;'+
      ' if(uCyc<0.0){'+                                 // history: one smooth wave crest, nothing steps
      '   float dt=uNow-vB;'+                           // events since (or until) this legs moment
      '   float rise=smoothstep(-30.0,30.0,dt);'+       // soft materialization
      '   flash=exp(-dt*dt/(2.0*40.0*40.0));'+          // gaussian crest centred on the moment
      '   base=0.10*rise;'+
      ' } else {'+                                      // steady: gaussian pulse travelling each line,
      '   float d=fract(uCyc-vA);'+                     // time-blurred: sigma widened by the temporal
      '   d=d>0.5?d-1.0:d;'+                            // window, peak scaled to conserve energy
      '   flash=exp(-d*d/(2.0*uSig*uSig))*uAmp*uRamp;'+
      '   base=0.10;'+
      ' }'+
      ' vec3 ember=vec3(0.22,0.45,0.75);'+
      ' vec3 gold=vec3(1.0,0.78,0.32);'+
      ' vec3 c=mix(ember,gold,flash);'+
      ' float a=base+0.9*flash;'+
      ' gl_FragColor=vec4(c,a); }',
    transparent:true, blending:THREE.AdditiveBlending, depthWrite:false});
  globe.add(new THREE.LineSegments(geo,mat));

  // ---- HUD: year, timeline, controls ---------------------------------------
  const hud=document.createElement('div');
  hud.style.cssText='position:fixed;top:14px;left:14px;z-index:9;font:14px/1.5 Georgia,serif;color:#dce8f8;background:rgba(8,13,24,0.72);padding:10px 14px;border-radius:8px';
  hud.innerHTML='<b>the pulse</b> — the atlas assembling itself<br><span id="yr" style="font-size:26px;color:#f2c14e"></span><br>'+
    'spin <input id="spin" type="range" min="-3" max="3" step="0.25" value="0" style="vertical-align:middle;width:110px;accent-color:#f2c14e"> <span id="spv" style="color:#f2c14e">off</span><br>'+
    '<span style="opacity:0.65">space pause &middot; 1/2/3 speed &middot; &larr;/&rarr; spin &middot; click timeline to scrub<br>drag to turn &middot; scroll to zoom</span>';
  document.body.appendChild(hud);
  const tl=document.createElement('canvas');
  tl.style.cssText='position:fixed;left:3vw;right:3vw;bottom:16px;width:94vw;height:46px;z-index:9;cursor:crosshair';
  document.body.appendChild(tl);
  const yrEl=document.getElementById('yr');
  function yearLabel(y){ return y<0? (Math.ceil(-y)+' BC') : (Math.floor(y)+''); }
  function drawTL(now){
    const w=tl.width=tl.clientWidth*devicePixelRatio, h=tl.height=tl.clientHeight*devicePixelRatio;
    const cx=tl.getContext('2d'); cx.clearRect(0,0,w,h);
    cx.fillStyle='rgba(8,13,24,0.7)'; cx.fillRect(0,0,w,h);
    cx.fillStyle='rgba(90,169,230,0.8)';
    for(let x=0;x<w;x+=2){ const i=Math.floor(x/w*N);
      cx.fillRect(x, h*0.55, 1.4, -h*0.34*Math.min(1,(YEARS[Math.min(N-1,i+40)]-YEARS[i]>0? 40/(N*(YEARS[Math.min(N-1,i+40)]-YEARS[i])/ (YEARS[N-1]-YEARS[0])):1))); }
    cx.font=(11*devicePixelRatio)+'px Georgia'; cx.fillStyle='#8fa3c8';
    [-2000,-1000,0,500,1000,1300,1500,1700,1800,1850,1900,1950,2000].forEach(Y=>{
      let i=0,j=N-1; while(i<j){const m=(i+j)>>1; if(YEARS[m]<Y)i=m+1;else j=m;}
      const x=i/N*w; cx.fillRect(x,h*0.58,1,h*0.16);
      cx.fillText(yearLabel(Y),x+3,h*0.92); });
    cx.fillStyle='#f2c14e'; cx.fillRect(now/N*w-1.5,0,3,h*0.58);
  }
  tl.addEventListener('pointerdown',e=>{ const r=tl.getBoundingClientRect();
    now=Math.max(0,Math.min(N-1,(e.clientX-r.left)/r.width*N)); steadyT=0; });

  let now=0, playing=true, speed=120, steadyT=0;   // pulses per second; steadyT drives the end-cycle
  const CYCLE=1/0.5;                                // 0.5 Hz pulse chain
  const SIG0=0.055, SIGT=0.020;                     // spatial sigma; temporal blur window (s)
  const SIG=Math.hypot(SIG0, SIGT/CYCLE);           // gaussian time blur = wider spatial gaussian
  let spin=0;                                       // axial spin, revolutions per minute (0 = off)
  const spinEl=document.getElementById('spin'), spvEl=document.getElementById('spv');
  function setSpin(v){ spin=Math.max(-3,Math.min(3,v)); spinEl.value=spin;
    spvEl.textContent=spin===0?'off':spin+' rpm'; }
  spinEl.addEventListener('input',()=>setSpin(parseFloat(spinEl.value)));
  window.addEventListener('keydown',e=>{
    if(e.code==='Space'){e.preventDefault(); playing=!playing;}
    else if(e.key==='1')speed=40; else if(e.key==='2')speed=120; else if(e.key==='3')speed=480;
    else if(e.key==='0'){now=0; steadyT=0;}
    else if(e.key==='ArrowLeft'){e.preventDefault(); setSpin(spin-0.25);}
    else if(e.key==='ArrowRight'){e.preventDefault(); setSpin(spin+0.25);} });

  const target=new THREE.Quaternion().setFromEuler(new THREE.Euler(0,-0.6,0));
  const dom=renderer.domElement;
  const ptrs=new Map();
  dom.addEventListener('pointerdown',e=>{ ptrs.set(e.pointerId,[e.clientX,e.clientY]); dom.setPointerCapture(e.pointerId); });
  dom.addEventListener('pointermove',e=>{ const p=ptrs.get(e.pointerId); if(!p)return;
    const dx=e.clientX-p[0], dy=e.clientY-p[1]; ptrs.set(e.pointerId,[e.clientX,e.clientY]);
    const dq=new THREE.Quaternion().setFromEuler(new THREE.Euler(dy*0.005,dx*0.005,0,'XYZ')); target.premultiply(dq); });
  const release=e=>{ptrs.delete(e.pointerId);};
  dom.addEventListener('pointerup',release); dom.addEventListener('pointercancel',release);
  dom.addEventListener('wheel',e=>{e.preventDefault(); camDist=Math.max(1.45,Math.min(6,camDist*Math.exp(e.deltaY*0.001))); updateCam();},{passive:false});
  function resize(){ const w=stage.clientWidth,h=stage.clientHeight; renderer.setSize(w,h); camera.aspect=w/h; camera.updateProjectionMatrix(); }
  window.addEventListener('resize',resize); resize(); updateCam();

  let lastT=performance.now();
  const spinQ=new THREE.Quaternion(), yAxis=new THREE.Vector3(0,1,0);
  (function animate(){ requestAnimationFrame(animate);
    const t=performance.now(), dt=(t-lastT)/1000; lastT=t;
    if(spin!==0){ spinQ.setFromAxisAngle(yAxis, spin*2*Math.PI/60*dt); target.premultiply(spinQ); }
    if(playing) now=Math.min(N-1+120, now+speed*dt);
    const steady=(now>=N-1+120);
    mat.uniforms.uCyc.value=-1.0;               // no end-cycle: history completes and the
    mat.uniforms.uNow.value=now;                // full 2026 map simply holds, static
    const yi=Math.max(0,Math.min(N-1,Math.floor(now)));
    yrEl.textContent=yearLabel(YEARS[yi]);
    drawTL(Math.min(now,N-1));
    globe.quaternion.slerp(target,1-Math.pow(0.91,Math.max(1,dt*60)));
    renderer.render(scene,camera); })();
})();
</script>
"""

with open(OUT, 'w') as f:
    f.write('<!doctype html><meta charset="utf-8">\n')
    f.write('<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">\n')
    f.write('<title>pulse globe</title>\n')
    f.write(head)
    f.write('\n<script>\nconst LEGS = ' + json.dumps(LEGS, separators=(',', ':')) + ';\n')
    f.write('const YEARS = ' + json.dumps(YEARS, separators=(',', ':')) + ';\n')
    f.write('const COAST = ' + json.dumps(coast_lines, separators=(',', ':')) + ';\n</script>\n')
    f.write(app)
print(f"wrote {OUT} ({os.path.getsize(OUT)//1024} KB)")
