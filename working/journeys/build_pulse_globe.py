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
  function updateCam(){ const off=Math.max(0,1-camera.aspect)*0.65;   // portrait: raise the globe
    camera.position.copy(D0).multiplyScalar(camDist); camera.lookAt(0,-off,0); }
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

  // ---- premium chrome: styles, veil, i18n, HUD, timeline -------------------
  const css=document.createElement('style');
  css.textContent=
    '#veil{position:fixed;inset:0;z-index:20;background:radial-gradient(120% 120% at 50% 40%,#0d1626 0%,#05080f 70%);display:flex;align-items:center;justify-content:center;flex-direction:column;gap:14px;transition:opacity .9s ease;font-family:Georgia,serif}'+
    '#veil.gone{opacity:0;pointer-events:none}'+
    '#veil .t{font-size:30px;color:#eadfbf;letter-spacing:.35em}'+
    '#veil .bar{width:200px;height:1px;background:linear-gradient(90deg,transparent,#f2c14e,transparent);animation:shim 1.6s ease-in-out infinite}'+
    '@keyframes shim{0%,100%{opacity:.25}50%{opacity:1}}'+
    '#veil .s{font-size:13px;color:#8fa3c8;letter-spacing:.18em}'+
    '#vig{position:fixed;inset:0;z-index:5;pointer-events:none;background:radial-gradient(130% 130% at 50% 42%,transparent 55%,rgba(2,4,9,.55) 100%)}'+
    '#panelcol{position:fixed;top:max(14px,env(safe-area-inset-top));left:max(14px,env(safe-area-inset-left));z-index:9;display:flex;flex-direction:column;align-items:flex-start;gap:8px;font:14px/1.55 Georgia,serif;width:min(340px,calc(100vw - 28px))}'+
    '#hud{width:100%;box-sizing:border-box;color:#dce8f8;background:linear-gradient(160deg,rgba(16,24,42,.80),rgba(8,13,24,.66));backdrop-filter:blur(14px) saturate(1.25);-webkit-backdrop-filter:blur(14px) saturate(1.25);padding:12px 14px;border-radius:14px;border:1px solid rgba(242,193,78,.18);box-shadow:0 14px 44px rgba(0,0,0,.5),inset 0 1px 0 rgba(255,255,255,.06)}'+
    '.hrow{display:flex;gap:10px;align-items:center;justify-content:space-between}'+
    '.hrow .btn{flex:1;margin:0;text-align:center;white-space:nowrap;padding:4px 6px;font-size:12.5px}'+
    '.hrow2{display:flex;align-items:center;gap:7px;margin-top:10px;color:#b9c8e2;font-size:13px;white-space:nowrap}'+
    '.hrow2 input[type=range]{flex:1;min-width:56px}'+
    '#yr{font-size:26px;color:#f2c14e;margin:2px 0 0 4px}'+
    '.btn{font:inherit;font-size:13px;color:#f2c14e;background:linear-gradient(180deg,rgba(242,193,78,.16),rgba(242,193,78,.07));border:1px solid rgba(242,193,78,.45);border-radius:999px;padding:4px 16px;margin:4px 8px 6px 0;cursor:pointer;letter-spacing:.06em;transition:transform .12s ease,box-shadow .12s ease,background .12s ease}'+
    '.btn:hover{transform:translateY(-1px);box-shadow:0 4px 14px rgba(242,193,78,.18);background:linear-gradient(180deg,rgba(242,193,78,.24),rgba(242,193,78,.10))}'+
    '.btn:active{transform:translateY(0)}'+
    '.btn:focus-visible{outline:2px solid rgba(242,193,78,.7);outline-offset:2px}'+
    '#hud input[type=range]{vertical-align:middle;-webkit-appearance:none;appearance:none;height:22px;background:transparent}'+
    '#hud input[type=range]::-webkit-slider-runnable-track{height:4px;border-radius:2px;background:linear-gradient(90deg,rgba(242,193,78,.5),rgba(143,163,200,.25))}'+
    '#hud input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:16px;height:16px;border-radius:50%;background:#f2c14e;margin-top:-6px;box-shadow:0 0 8px rgba(242,193,78,.5)}'+
    '#hud input[type=range]::-moz-range-track{height:4px;border-radius:2px;background:rgba(143,163,200,.3)}'+
    '#hud input[type=range]::-moz-range-thumb{width:16px;height:16px;border:none;border-radius:50%;background:#f2c14e}'+
    '#hint{display:block;color:#93a6c6;font-size:12px;opacity:.85;transition:opacity 1.2s ease;margin-left:4px}'+
    '#tlwrap{position:fixed;left:50%;transform:translateX(-50%);bottom:max(12px,env(safe-area-inset-bottom));width:min(1200px,94vw);z-index:9;background:linear-gradient(160deg,rgba(16,24,42,.72),rgba(8,13,24,.6));backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border:1px solid rgba(143,163,200,.16);border-radius:12px;box-shadow:0 10px 34px rgba(0,0,0,.45);padding:5px 10px}'+
    '#tl{display:block;width:100%;height:52px;cursor:crosshair}';
  document.head.appendChild(css);

  const STR={
    es:{title:'el pulso',sub:'el atlas tejiendose a si mismo',spin:'giro',off:'quieto',rpm:'rpm',obl:'oblicuidad',
        speed:'velocidad',speeds:{40:'lento',120:'normal',480:'rapido'},
        hint:'espacio pausa \u00b7 1/2/3 velocidad \u00b7 \u2190/\u2192 giro \u00b7 toca la l\u00ednea del tiempo para viajar<br>arrastra para girar \u00b7 pellizca o rueda para acercar',
        loading:'cargando el atlas\u2026',bc:' a. C.'},
    en:{title:'the pulse',sub:'the atlas assembling itself',spin:'spin',off:'off',rpm:'rpm',obl:'obliquity',
        speed:'speed',speeds:{40:'slow',120:'normal',480:'fast'},
        hint:'space pause \u00b7 1/2/3 speed \u00b7 \u2190/\u2192 spin \u00b7 tap the timeline to scrub<br>drag to turn \u00b7 pinch or scroll to zoom',
        loading:'loading the atlas\u2026',bc:' BC'}};
  let L=STR.es, langCode='es';
  STR.es.sub='el atlas teji\u00e9ndose a s\u00ed mismo';
  STR.es.speeds={40:'lento',120:'normal',480:'r\u00e1pido'};

  document.body.insertAdjacentHTML('beforeend',
    '<div id="veil"><div class="t">el pulso</div><div class="bar"></div><div class="s" id="veilS"></div></div><div id="vig"></div>');
  const col=document.createElement('div');
  col.id='panelcol';
  col.innerHTML='<div id="hud">'+
      '<div class="hrow"><button class="btn" id="spd"></button></div>'+
      '<div class="hrow2"><span id="spinL"></span> <input id="spin" type="range" min="0" max="3" step="0.25" value="0"> <span id="spv" style="color:#f2c14e"></span>'+
      ' \u00b7 <span id="oblL"></span> <span id="obq">0.0\u00b0</span></div>'+
    '</div>'+
    '<span id="yr"></span><span id="hint"></span>';
  document.body.appendChild(col);
  const tlwrap=document.createElement('div'); tlwrap.id='tlwrap';
  const tl=document.createElement('canvas'); tl.id='tl'; tlwrap.appendChild(tl);
  document.body.appendChild(tlwrap);
  const yrEl=document.getElementById('yr');
  function yearLabel(y){ return y<0? (Math.ceil(-y)+L.bc) : (Math.floor(y)+''); }
  const ERAS=[-2000,-1000,0,500,1000,1300,1500,1700,1800,1850,1900,1950,2000];
  let hoverI=null, tlDown=false;
  function drawTL(now){
    const dpr=devicePixelRatio;
    const w=tl.width=tl.clientWidth*dpr, h=tl.height=tl.clientHeight*dpr;
    const cx=tl.getContext('2d'); cx.clearRect(0,0,w,h);
    const grad=cx.createLinearGradient(0,h*0.18,0,h*0.58);
    grad.addColorStop(0,'rgba(143,216,244,0.95)'); grad.addColorStop(1,'rgba(90,169,230,0.55)');
    cx.fillStyle=grad;
    for(let x=0;x<w;x+=2){ const i=Math.floor(x/w*N);
      cx.fillRect(x, h*0.58, 1.4, -h*0.36*Math.min(1,(YEARS[Math.min(N-1,i+40)]-YEARS[i]>0? 40/(N*(YEARS[Math.min(N-1,i+40)]-YEARS[i])/ (YEARS[N-1]-YEARS[0])):1))); }
    cx.font=(10.5*dpr)+'px Georgia'; cx.fillStyle='rgba(143,163,200,0.9)';
    let lastEnd=-1e9;
    ERAS.forEach(Y=>{
      let i=0,j=N-1; while(i<j){const m=(i+j)>>1; if(YEARS[m]<Y)i=m+1;else j=m;}
      const x=i/N*w; cx.fillStyle='rgba(143,163,200,0.5)'; cx.fillRect(x,h*0.62,1,h*0.12);
      const txt=yearLabel(Y), tw=cx.measureText(txt).width;
      if(x+3>lastEnd+10*dpr && x+3+tw<w){ cx.fillStyle='rgba(143,163,200,0.9)'; cx.fillText(txt,x+3,h*0.95); lastEnd=x+3+tw; } });
    if(hoverI!==null){
      const hx=hoverI/N*w;
      cx.fillStyle='rgba(234,223,191,0.5)'; cx.fillRect(hx-0.5,0,1,h*0.62);
      const txt=yearLabel(YEARS[Math.max(0,Math.min(N-1,Math.floor(hoverI)))]);
      cx.font=(11*dpr)+'px Georgia'; const tw=cx.measureText(txt).width;
      cx.fillStyle='rgba(234,223,191,0.95)';
      cx.fillText(txt, Math.max(2,Math.min(w-tw-2,hx-tw/2)), h*0.16);
    }
    cx.save(); cx.shadowColor='rgba(242,193,78,0.9)'; cx.shadowBlur=7*dpr;
    cx.fillStyle='#f2c14e'; cx.fillRect(now/N*w-1.2*dpr,0,2.4*dpr,h*0.60); cx.restore();
  }
  function tlSeek(e){ const r=tl.getBoundingClientRect();
    now=Math.max(0,Math.min(N-1,(e.clientX-r.left)/r.width*N)); steadyT=0; }
  tl.addEventListener('pointerdown',e=>{ tlDown=true; tl.setPointerCapture(e.pointerId); tlSeek(e); });
  tl.addEventListener('pointermove',e=>{ if(tlDown){ tlSeek(e); }
    const r=tl.getBoundingClientRect(); hoverI=Math.max(0,Math.min(N-1,(e.clientX-r.left)/r.width*N)); });
  tl.addEventListener('pointerup',e=>{ tlDown=false; });
  tl.addEventListener('pointerleave',e=>{ hoverI=null; });

  let now=0, playing=true, speed=120, steadyT=0;   // pulses per second; steadyT drives the end-cycle
  const SPEEDS=[40,120,480];
  const spdBtn=document.getElementById('spd');
  function setSpeed(v){ speed=v; spdBtn.textContent=L.speed+' \u00b7 '+(L.speeds[v]||v); }
  spdBtn.addEventListener('click',()=>{ const i=SPEEDS.indexOf(speed);
    setSpeed(SPEEDS[(i+1)%SPEEDS.length]); });
  const CYCLE=1/0.5;                                // 0.5 Hz pulse chain
  const SIG0=0.055, SIGT=0.020;                     // spatial sigma; temporal blur window (s)
  const SIG=Math.hypot(SIG0, SIGT/CYCLE);           // gaussian time blur = wider spatial gaussian
  let spin=0;                                       // axial spin, revolutions per minute (0 = off)
  const spinEl=document.getElementById('spin'), spvEl=document.getElementById('spv');
  function setSpin(v){ spin=Math.max(0,Math.min(3,v)); spinEl.value=spin;
    spvEl.textContent=spin===0?L.off:spin+' '+L.rpm; }
  spinEl.addEventListener('input',()=>setSpin(parseFloat(spinEl.value)));
  function applyLang(code){ langCode=code; L=STR[code]; document.documentElement.lang=code;
    document.getElementById('spinL').textContent=L.spin;
    document.getElementById('oblL').textContent=L.obl;
    document.getElementById('hint').innerHTML=L.hint;
    document.getElementById('veilS').textContent=L.loading;
    document.title=L.title+' \u2014 Colegio Invisible';
    setSpeed(speed); setSpin(spin); }
  applyLang('es');
  const veil=document.getElementById('veil');
  let veilGone=false;
  setTimeout(()=>{ const h=document.getElementById('hint'); if(h) h.style.opacity=0.28; },8000);
  window.addEventListener('keydown',e=>{
    if(e.code==='Space'){e.preventDefault(); playing=!playing;}
    else if(e.key==='1')setSpeed(40); else if(e.key==='2')setSpeed(120); else if(e.key==='3')setSpeed(480);
    else if(e.key==='0'){now=0; steadyT=0;}
    else if(e.key==='ArrowLeft'){e.preventDefault(); setSpin(spin-0.25);}
    else if(e.key==='ArrowRight'){e.preventDefault(); setSpin(spin+0.25);} });

  const target=new THREE.Quaternion().setFromEuler(new THREE.Euler(0,-0.6,0));
  const dom=renderer.domElement;
  dom.style.touchAction='none';                     // canvas owns all gestures; no browser pinch/scroll
  const ptrs=new Map();
  let pinchDist=null, userZoomed=false;
  dom.addEventListener('pointerdown',e=>{ ptrs.set(e.pointerId,[e.clientX,e.clientY]); dom.setPointerCapture(e.pointerId);
    if(ptrs.size===2){ const [a,b]=[...ptrs.values()]; pinchDist=Math.hypot(a[0]-b[0],a[1]-b[1]); } });
  dom.addEventListener('pointermove',e=>{ const p=ptrs.get(e.pointerId); if(!p)return;
    const dx=e.clientX-p[0], dy=e.clientY-p[1]; ptrs.set(e.pointerId,[e.clientX,e.clientY]);
    if(ptrs.size===2){                              // pinch: zoom, no rotation
      const [a,b]=[...ptrs.values()]; const d=Math.hypot(a[0]-b[0],a[1]-b[1]);
      if(pinchDist && d>0){ camDist=Math.max(1.45,Math.min(8,camDist*pinchDist/d)); userZoomed=true; updateCam(); }
      pinchDist=d; return; }
    const dq=new THREE.Quaternion().setFromEuler(new THREE.Euler(dy*0.005,dx*0.005,0,'XYZ')); target.premultiply(dq); });
  const release=e=>{ptrs.delete(e.pointerId); if(ptrs.size<2)pinchDist=null;};
  dom.addEventListener('pointerup',release); dom.addEventListener('pointercancel',release);
  dom.addEventListener('wheel',e=>{e.preventDefault(); userZoomed=true; camDist=Math.max(1.45,Math.min(8,camDist*Math.exp(e.deltaY*0.001))); updateCam();},{passive:false});
  function fitDist(aspect){                          // distance at which the globe fits the frame
    const vhalf=42/2*Math.PI/180, hhalf=Math.atan(Math.tan(vhalf)*aspect);
    return 1.12/Math.sin(Math.min(vhalf,hhalf)); }
  function resize(){ const w=stage.clientWidth,h=stage.clientHeight; renderer.setSize(w,h); camera.aspect=w/h; camera.updateProjectionMatrix();
    if(!userZoomed){ camDist=Math.max(2.7,fitDist(w/h)); }
    updateCam(); }
  window.addEventListener('resize',resize); resize(); updateCam();

  let lastT=performance.now();
  const spinQ=new THREE.Quaternion(), yAxis=new THREE.Vector3(0,1,0);
  const obqEl=document.getElementById('obq'), axW=new THREE.Vector3();
  let obShown=-1;
  function trackObliquity(){
    axW.set(0,1,0).applyQuaternion(globe.quaternion)
       .transformDirection(camera.matrixWorldInverse);   // as the EYE sees it: view space,
    const ob=Math.acos(Math.min(1,Math.max(-1,axW.y)))*180/Math.PI;  // dotted with the screen vertical
    if(Math.abs(ob-obShown)<0.05) return;
    obShown=ob;
    const earth=Math.abs(ob-23.44)<=0.5;               // the true obliquity, greeted in gold
    obqEl.textContent=ob.toFixed(1)+'\\u00b0'+(earth?' \\u2295':'');
    obqEl.style.color=earth?'#f2c14e':'#dce8f8';
  }
  (function animate(){ requestAnimationFrame(animate);
    const t=performance.now(), dt=(t-lastT)/1000; lastT=t;
    if(spin!==0){ spinQ.setFromAxisAngle(yAxis, spin*2*Math.PI/60*dt); target.multiply(spinQ); }
    if(playing) now=Math.min(N-1+120, now+speed*dt);
    const steady=(now>=N-1+120);
    mat.uniforms.uCyc.value=-1.0;               // no end-cycle: history completes and the
    mat.uniforms.uNow.value=now;                // full 2026 map simply holds, static
    const yi=Math.max(0,Math.min(N-1,Math.floor(now)));
    yrEl.textContent=yearLabel(YEARS[yi]);
    drawTL(Math.min(now,N-1));
    globe.quaternion.slerp(target,1-Math.pow(0.91,Math.max(1,dt*60)));
    trackObliquity();
    renderer.render(scene,camera);
    if(!veilGone){ veilGone=true; requestAnimationFrame(()=>veil.classList.add('gone')); } })();
})();
</script>
"""

with open(OUT, 'w') as f:
    f.write('<!doctype html><html lang="es"><meta charset="utf-8">\n')
    f.write('<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">\n')
    f.write('<title>el pulso \u2014 Colegio Invisible</title>\n')
    f.write(head)
    f.write('\n<script>\nconst LEGS = ' + json.dumps(LEGS, separators=(',', ':')) + ';\n')
    f.write('const YEARS = ' + json.dumps(YEARS, separators=(',', ':')) + ';\n')
    f.write('const COAST = ' + json.dumps(coast_lines, separators=(',', ':')) + ';\n</script>\n')
    f.write(app)
print(f"wrote {OUT} ({os.path.getsize(OUT)//1024} KB)")
