#!/usr/bin/env python3
"""Build quipu_out/atlas_globe.html — the whole-network globe.

Reuses joan_globe.html as donor (CSS + HTML skeleton + inlined three.js +
COAST coastline blob, all byte-verbatim) and replaces the single-journey app
with a 102-traveler atlas:
  - every journey drawn as a dim colored line (the network)
  - one traveler selected: bright line, segment-colored stop balls, marker
  - Left/Right: step the selected traveler's stops (sets "the moment")
  - Up/Down: swap traveler — flies (globe-quaternion slerp) to wherever the
    new traveler is nearest to the current moment
  - Space: play through the selected traveler; click a ball to jump
Travelers are ordered chronologically by first-stop date.
"""
import json, glob, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, 'quipu_out')
DONOR = os.path.join(OUT_DIR, 'joan_globe.html')
ES = '--es' in sys.argv                 # --es: build from es/ translations
SRC_DIR = os.path.join(HERE, 'es') if ES else HERE
OUT = os.path.join(OUT_DIR, 'atlas_globe_es.html' if ES else 'atlas_globe.html')

# ---- date key: comparable float, BCE-safe (-0966-05-01 < -0530-01-01) ------
# The year stays negative for BCE but month/day advance FORWARD inside it:
# negating the whole fraction made June 1738 BC sort before January 1738 BC,
# which inverted next/prev-in-time navigation within any single BCE year.
def datekey(iso):
    if not iso: return 0.0
    neg = iso.startswith('-')
    s = iso[1:] if neg else iso
    p = (s.split('-') + ['1', '1'])[:3]
    try:
        y, m, d = int(p[0]), int(p[1] or 1), int(p[2] or 1)
    except ValueError:
        return 0.0
    frac = (m - 1) / 12.0 + (d - 1) / 372.0
    return (-y + frac) if neg else (y + frac)

# ---- gather the atlas -------------------------------------------------------
travelers = []
for f in sorted(glob.glob(os.path.join(SRC_DIR, '*.journey.json'))):
    j = json.load(open(f))
    slug = os.path.basename(f).replace('.journey.json', '')
    segs, stops = [], []
    for si, seg in enumerate(j.get('segments', [])):
        segs.append(seg.get('name', f'Segment {si+1}'))
        for st in seg.get('stops', []):
            if not isinstance(st.get('lat'), (int, float)): continue
            stops.append({
                'n': st.get('name', ''), 'lat': st['lat'], 'lng': st['lng'],
                'd': st.get('date', ''),
                's': si, 'c': st.get('campa', ''),
                'q': st.get('quote'), 'qs': st.get('quote_source'),
                'k': round(datekey(st.get('date', '')), 4),
            })
    if not stops: continue
    travelers.append({
        'slug': slug,
        'traveler': j.get('traveler', slug),
        'title': j.get('title', ''),
        'years': j.get('years', ''),
        'segments': segs,
        'stops': stops,
        'k0': stops[0]['k'],
    })
travelers.sort(key=lambda t: t['k0'])
for t in travelers: del t['k0']
print(f"{len(travelers)} travelers, {sum(len(t['stops']) for t in travelers)} stops")

# ---- donor pieces -----------------------------------------------------------
raw = open(DONOR).read()
three_start = raw.find('<script>/**')
three_end = raw.find('</script>', three_start) + len('</script>')
head = raw[:three_end]                      # css + html skeleton + three.js
assert three_start > 0, 'donor structure changed'

# ---- coastline: heal_earth land-50m topojson + the corrected lakes ----------
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
lakes = json.load(open(os.path.join(HEAL, 'lakes_journey.geojson')))
lake_lines = []
for feat in lakes['features']:
    for ring in feat['geometry']['coordinates']:
        lake_lines.append([[round(p[0], 4), round(p[1], 4)] for p in ring])
print(f"coast arcs: {len(coast_lines)}, lake rings: {len(lake_lines)}")
coast = ('const COAST = ' + json.dumps(coast_lines, separators=(',', ':')) + ';\n'
         'const LAKES = ' + json.dumps(lake_lines, separators=(',', ':')) + ';')

# patch the hint line for the new controls
head = head.replace(
    '<div id="hint">' + head.split('<div id="hint">')[1].split('</div>')[0] + '</div>',
    '<div id="hint"><b>&uarr;/&darr;</b> traveler &nbsp;&middot;&nbsp; '
    '<b>&larr;/&rarr;</b> stop &nbsp;&middot;&nbsp; <b>,/.</b> same place '
    '&nbsp;&middot;&nbsp; drag to turn &nbsp;&middot;&nbsp; scroll to zoom</div>', 1)

# third control: autoplay retired, the button restarts the journey
head = head.replace('>Play<', '>Restart<', 1)

# language switch: each build links its sibling
SWAP = ('atlas_globe.html', 'EN') if ES else ('atlas_globe_es.html', 'ES')
head = head.replace('<div id="titlebar">',
    f'<a id="lang" href="{SWAP[0]}">{SWAP[1]}</a><div id="titlebar">', 1)
head = head.replace('</style>',
    '#lang{position:absolute;right:14px;top:12px;z-index:5;color:var(--gold);'
    'text-decoration:none;font-size:12px;letter-spacing:.12em;'
    'border:.5px solid var(--line);border-radius:6px;padding:4px 8px;'
    'background:rgba(10,16,28,.55)}\n</style>', 1)

# mobile: dvh-safe heights, touch targets, traveler bar, safe-area inset
MOBILE_CSS = """
  #app{height:100dvh}
  aside#panel{height:100dvh}
  #stage canvas{touch-action:none}
  button,select{touch-action:manipulation}
  #counter .others{color:var(--gold);cursor:pointer;border-bottom:1px dotted var(--gold)}
  #travbar{display:flex;gap:8px;padding:12px 16px 0;align-items:center}
  #travbar select{flex:1;min-width:0;background:var(--panel2);color:var(--ink);
    border:.5px solid var(--line);border-radius:8px;padding:8px 10px;font-size:13px;
    -webkit-appearance:none;appearance:none}
  #travbar button{background:var(--panel2);color:var(--ink);border:.5px solid var(--line);
    border-radius:8px;padding:8px 14px;font-size:16px;line-height:1;cursor:pointer}
  @media (max-width:820px){
    #app{flex-direction:column;height:100dvh}
    #stage{height:auto;flex:1 1 40%}
    aside#panel{flex:0 0 60%;height:auto;min-height:0;max-width:none;width:100%;
      border-left:none;border-top:.5px solid var(--line)}
    #body{min-height:0}
    #titlebar{max-width:78%;left:12px;top:10px}
    #titlebar h1{font-size:16px}
    #titlebar p{font-size:11px}
    #hint{display:none}
    #travbar{padding:10px 12px 0}
    #meta{padding:10px 14px 8px}
    #place{font-size:17px}
    #body{padding:12px 14px 14px}
    #campa{font-size:14.5px;line-height:1.6}
    #quote{font-size:13.5px}
    #controls{padding:10px 12px calc(10px + env(safe-area-inset-bottom))}
    #controls button{padding:10px 12px}
  }
"""
head = head.replace('</style>', MOBILE_CSS + '</style>', 1)

atlas_json = json.dumps(travelers, ensure_ascii=False, separators=(',', ':'))

app = """
<script>
(function(){
  const PAL = [0xf2c14e,0x5aa9e6,0x37c2a8,0xe86a92,0xc9a15a,0x9b8cff,0xf08a4b,0xd8c26a,
               0x7bd389,0xdd7373,0x6fc3df,0xb583d6,0xe0b153,0x64b6ac,0xd98cb3,0xa3c46a];
  const CSS = PAL.map(h=>'#'+h.toString(16).padStart(6,'0'));
  const THREE = window.THREE, R=1.0;
  const stage=document.getElementById('stage');
  function llv(lat,lng,r){
    const la=lat*Math.PI/180, lo=lng*Math.PI/180;
    return new THREE.Vector3(r*Math.cos(la)*Math.cos(lo), r*Math.sin(la), -r*Math.cos(la)*Math.sin(lo));
  }
  const scene=new THREE.Scene();
  const camera=new THREE.PerspectiveCamera(42, 1, 0.01, 200);
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
  // translucent shell: the interior stays visible so chords through the planet read
  globe.add(new THREE.Mesh(new THREE.SphereGeometry(R,64,64),
    new THREE.MeshPhongMaterial({color:0x0b1526,emissive:0x050a14,shininess:6,
      transparent:true,opacity:0.32,depthWrite:false})));
  function lineLayer(lines,color,opacity,r){
    const segs=[];
    for(const line of lines){ for(let i=0;i<line.length-1;i++){
      const a=llv(line[i][1],line[i][0],r), b=llv(line[i+1][1],line[i+1][0],r);
      segs.push(a.x,a.y,a.z,b.x,b.y,b.z); } }
    const g=new THREE.BufferGeometry(); g.setAttribute('position',new THREE.BufferAttribute(new Float32Array(segs),3));
    globe.add(new THREE.LineSegments(g,new THREE.LineBasicMaterial({color,transparent:true,opacity})));
  }
  lineLayer(COAST,0x8fd8f4,0.95,R*1.002);
  lineLayer(LAKES,0xaee8ff,1.0,R*1.003);
  (function(){ const segs=[]; const push=(a,b)=>segs.push(a.x,a.y,a.z,b.x,b.y,b.z);
    for(let lat=-60;lat<=60;lat+=30){ for(let lng=-180;lng<180;lng+=6) push(llv(lat,lng,R*1.001),llv(lat,lng+6,R*1.001)); }
    for(let lng=-180;lng<180;lng+=30){ for(let lat=-90;lat<90;lat+=6) push(llv(lat,lng,R*1.001),llv(lat+6,lng,R*1.001)); }
    const g=new THREE.BufferGeometry(); g.setAttribute('position',new THREE.BufferAttribute(new Float32Array(segs),3));
    globe.add(new THREE.LineSegments(g,new THREE.LineBasicMaterial({color:0x233150,transparent:true,opacity:0.5}))); })();

  // ---- the network: every journey as a line --------------------------------
  const netMats=[];
  ATLAS.forEach((t,ti)=>{
    const pts=t.stops.map(s=>llv(s.lat,s.lng,R*1.012));
    if(pts.length<2){ t._line=null; return; }
    const curve=new THREE.CatmullRomCurve3(pts,false,'catmullrom',0.4);
    const g=new THREE.BufferGeometry().setFromPoints(curve.getPoints(Math.max(64,pts.length*10)));
    const m=new THREE.LineBasicMaterial({color:PAL[ti%PAL.length],transparent:true,opacity:0.16});
    const line=new THREE.Line(g,m); globe.add(line); t._line=m; netMats.push(m);
  });

  // ---- selected traveler: balls + marker ------------------------------------
  const selGroup=new THREE.Group(); globe.add(selGroup);
  const bgeo=new THREE.SphereGeometry(0.00283,16,16);   // journey-stop balls: a third of the old 0.0085
  let balls=[], pos=[];
  const marker=new THREE.Group();
  // present-position marker at half its old radius (Anthony, 2026-07-24): core
  // 0.013 -> 0.0065, ring 0.028/0.038 -> 0.014/0.019. Halve BOTH ring radii
  // together, or the annulus changes thickness instead of scale.
  const core=new THREE.Mesh(new THREE.SphereGeometry(0.0065,20,20),new THREE.MeshBasicMaterial({color:0xffffff}));
  const ring=new THREE.Mesh(new THREE.RingGeometry(0.014,0.019,28),
    new THREE.MeshBasicMaterial({color:0xf2c14e,side:THREE.DoubleSide,transparent:true,opacity:0.9}));
  marker.add(core); marker.add(ring); globe.add(marker);

  let target=new THREE.Quaternion();
  function faceStop(i){ const from=pos[i].clone().normalize(); target=new THREE.Quaternion().setFromUnitVectors(from,D0); }

  const $=s=>document.querySelector(s);
  function esc(t){ const d=document.createElement('div'); d.textContent=t; return d.innerHTML; }
  function fmtDate(iso){ if(!iso) return ''; let bce=iso.startsWith('-'); let s=bce?iso.slice(1):iso;
    const p=s.split('-'); const y=parseInt(p[0],10);
    const mo=['','Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    return (p[2]?parseInt(p[2],10)+' ':'')+(p[1]?mo[parseInt(p[1],10)]+' ':'')+y+(bce?' BC':'');
  }

  let ti=-1, idx=-1, moment=0;
  function buildTraveler(newTi){
    ti=(newTi+ATLAS.length)%ATLAS.length;
    const t=ATLAS[ti];
    netMats.forEach(m=>{m.opacity=0.16;});
    if(t._line) t._line.opacity=1.0;
    while(selGroup.children.length) selGroup.remove(selGroup.children[0]);
    balls=[]; pos=t.stops.map(s=>llv(s.lat,s.lng,R*1.016));
    t.stops.forEach((s,i)=>{ const m=new THREE.Mesh(bgeo,new THREE.MeshBasicMaterial({color:PAL[s.s%PAL.length]}));
      m.position.copy(pos[i]); m.userData.i=i; selGroup.add(m); balls.push(m); });
    $('#titlebar h1').textContent=t.traveler;
    $('#titlebar p').textContent=(t.years?t.years+' · ':'')+t.title+'  ·  traveler '+(ti+1)+' of '+ATLAS.length;
    const ts=document.getElementById('tsel'); if(ts) ts.value=ti;
  }
  function setIndex(i,keepMoment){
    const t=ATLAS[ti];
    idx=Math.max(0,Math.min(t.stops.length-1,i));
    const s=t.stops[idx];
    if(!keepMoment) moment=s.k;
    let here=0; { const seen=new Set();
      ATLAS.forEach((o,tj)=>{ if(tj===ti) return;
        if(o.stops.some(x=>distKm(s,x)<HERE_KM)) seen.add(tj); }); here=seen.size; }
    $('#counter').innerHTML='STOP '+(idx+1)+' / '+t.stops.length+'  ·  TRAVELER '+(ti+1)+' / '+ATLAS.length
      +(here?'  ·  <span class="others">'+here+' OTHERS HERE</span>':'');
    const oh=$('#counter .others'); if(oh) oh.onclick=()=>pivotHere(1);
    $('#chip .dot').style.background=CSS[s.s%CSS.length];
    $('#chip .segname').textContent=t.segments[s.s]||'';
    $('#place').textContent=s.n;
    $('#date').innerHTML=fmtDate(s.d);
    $('#campa').textContent=s.c||'';
    const q=$('#quote'); if(s.q){ q.hidden=false; q.innerHTML=esc(s.q)+(s.qs?'<span class="src">'+esc(s.qs)+'</span>':''); } else q.hidden=true;
    const pr=$('#prog i'); if(pr) pr.style.width=(100*(idx+1)/t.stops.length)+'%';
    marker.position.copy(pos[idx]);
    faceStop(idx);
  }
  function nearestStop(t,k){ let bi=0,bd=Infinity;
    t.stops.forEach((s,i)=>{ const d=Math.abs(s.k-k); if(d<bd){bd=d;bi=i;} }); return bi; }
  const HERE_KM=25;
  function distKm(a,b){ const p=Math.PI/180;
    const x=0.5-Math.cos((b.lat-a.lat)*p)/2+Math.cos(a.lat*p)*Math.cos(b.lat*p)*(1-Math.cos((b.lng-a.lng)*p))/2;
    return 12742*Math.asin(Math.sqrt(x)); }
  function visitorsHere(){ const s=ATLAS[ti].stops[idx], out=[];
    ATLAS.forEach((t,tj)=>{ if(tj===ti) return;
      t.stops.forEach((o,oj)=>{ if(distKm(s,o)<HERE_KM) out.push({tj,oj,k:o.k}); }); });
    out.sort((a,b)=>a.k-b.k); return out; }
  function pivotHere(dir){
    const vis=visitorsHere(); if(!vis.length) return;
    const k0=ATLAS[ti].stops[idx].k;
    let pick;
    if(dir>0){ pick=vis.find(v=>v.k>k0) || vis[0]; }
    else { const before=vis.filter(v=>v.k<k0); pick=before.length?before[before.length-1]:vis[vis.length-1]; }
    buildTraveler(pick.tj); setIndex(pick.oj); }
  function swapTraveler(dir){
    const nt=(ti+dir+ATLAS.length)%ATLAS.length;
    buildTraveler(nt);
    setIndex(nearestStop(ATLAS[nt],moment),true);   // fly to where they are at the moment
  }

  const dom=renderer.domElement;
  let dragged=false;
  const ptrs=new Map();   // pointerId -> [x,y]; one = drag, two = pinch
  dom.addEventListener('pointerdown',e=>{ if(ptrs.size===0)dragged=false;
    ptrs.set(e.pointerId,[e.clientX,e.clientY]); dom.setPointerCapture(e.pointerId); });
  dom.addEventListener('pointermove',e=>{ const p=ptrs.get(e.pointerId); if(!p)return;
    if(ptrs.size===2){
      const ids=[...ptrs.keys()], a=ptrs.get(ids[0]), b=ptrs.get(ids[1]);
      const d0=Math.hypot(a[0]-b[0],a[1]-b[1]);
      ptrs.set(e.pointerId,[e.clientX,e.clientY]);
      const a1=ptrs.get(ids[0]), b1=ptrs.get(ids[1]);
      const d1=Math.hypot(a1[0]-b1[0],a1[1]-b1[1]);
      if(d0>4&&d1>4){ camDist=Math.max(1.45,Math.min(6,camDist*d0/d1)); updateCam(); }
      dragged=true; return; }
    const dx=e.clientX-p[0], dy=e.clientY-p[1]; ptrs.set(e.pointerId,[e.clientX,e.clientY]);
    if(Math.abs(dx)+Math.abs(dy)>2)dragged=true;
    const dq=new THREE.Quaternion().setFromEuler(new THREE.Euler(dy*0.005,dx*0.005,0,'XYZ')); target.premultiply(dq); });
  const release=e=>{ptrs.delete(e.pointerId);};
  dom.addEventListener('pointerup',release);
  dom.addEventListener('pointercancel',release);
  dom.addEventListener('click',e=>{ if(dragged)return; const r=dom.getBoundingClientRect();
    const m=new THREE.Vector2(((e.clientX-r.left)/r.width)*2-1, -((e.clientY-r.top)/r.height)*2+1);
    const rc=new THREE.Raycaster(); rc.setFromCamera(m,camera); const h=rc.intersectObjects(balls);
    if(h.length) setIndex(h[0].object.userData.i); });
  dom.addEventListener('wheel',e=>{e.preventDefault(); camDist=Math.max(1.45,Math.min(6,camDist*Math.exp(e.deltaY*0.001))); updateCam();},{passive:false});
  window.addEventListener('keydown',e=>{
    const k=e.code||e.key;
    if(k==='Period'||k==='.'){e.preventDefault(); pivotHere(1);}
    else if(k==='Comma'||k===','){e.preventDefault(); pivotHere(-1);}
    else if(k==='Space'||k===' '||k==='ArrowRight'||k==='Right'){e.preventDefault(); setIndex(idx+1);}
    else if(k==='ArrowLeft'||k==='Left'){e.preventDefault(); setIndex(idx-1);}
    else if(k==='ArrowDown'||k==='Down'){e.preventDefault(); swapTraveler(1);}
    else if(k==='ArrowUp'||k==='Up'){e.preventDefault(); swapTraveler(-1);}
  });
  $('#next').onclick=()=>setIndex(idx+1);
  $('#prev').onclick=()=>setIndex(idx-1);
  $('#reset').onclick=()=>{camDist=2.7;updateCam();faceStop(idx);};
  $('#play').onclick=()=>setIndex(0);   // back to the journey's first stop

  // traveler bar: touch path to what Up/Down do, plus jump-anywhere picker
  (function(){ const panel=document.querySelector('aside#panel'); if(!panel) return;
    const bar=document.createElement('div'); bar.id='travbar';
    bar.innerHTML='<button id="tprev" aria-label="previous traveler">&lsaquo;</button>'
      +'<select id="tsel" aria-label="traveler"></select>'
      +'<button id="tnext" aria-label="next traveler">&rsaquo;</button>';
    panel.insertBefore(bar,panel.firstChild);
    const tsel=bar.querySelector('#tsel');
    ATLAS.forEach((t,i)=>{ const o=document.createElement('option');
      o.value=i; o.textContent=(i+1)+' · '+t.traveler; tsel.appendChild(o); });
    bar.querySelector('#tprev').onclick=()=>swapTraveler(-1);
    bar.querySelector('#tnext').onclick=()=>swapTraveler(1);
    tsel.onchange=e=>{ const nt=(+e.target.value+ATLAS.length)%ATLAS.length;
      buildTraveler(nt); setIndex(nearestStop(ATLAS[nt],moment),true); };
  })();

  function resize(){ const w=stage.clientWidth,h=stage.clientHeight; renderer.setSize(w,h); camera.aspect=w/h; camera.updateProjectionMatrix(); }
  window.addEventListener('resize',resize); resize(); updateCam();

  let lastT=performance.now();
  (function animate(){ requestAnimationFrame(animate);
    const now=performance.now(), dt=(now-lastT)/1000; lastT=now;
    globe.quaternion.slerp(target,1-Math.pow(0.91,Math.max(1,dt*60)));
    const t=performance.now()*0.001; marker.scale.setScalar(1+0.18*Math.sin(t*3)); ring.quaternion.copy(camera.quaternion);
    renderer.render(scene,camera); })();

  buildTraveler(0); setIndex(0);
})();
</script>
"""

# ---- Spanish UI: every chrome string the app or donor skeleton shows -------
if ES:
    UI = [
        ('<b>&uarr;/&darr;</b> traveler &nbsp;&middot;&nbsp; '
         '<b>&larr;/&rarr;</b> stop &nbsp;&middot;&nbsp; <b>,/.</b> same place '
         '&nbsp;&middot;&nbsp; drag to turn &nbsp;&middot;&nbsp; scroll to zoom',
         '<b>&uarr;/&darr;</b> viajero &nbsp;&middot;&nbsp; '
         '<b>&larr;/&rarr;</b> parada &nbsp;&middot;&nbsp; <b>,/.</b> mismo lugar '
         '&nbsp;&middot;&nbsp; arrastra para girar &nbsp;&middot;&nbsp; rueda para acercar'),
        ('&larr; Prev', '&larr; Anterior'),
        ('Next &rarr;', 'Siguiente &rarr;'),
        ('>Restart<', '>Al inicio<'),
        ('Reset view', 'Reiniciar vista'),
    ]
    for a, b in UI:
        assert a in head, f'donor string missing: {a!r}'
        head = head.replace(a, b)
    APP_UI = [
        ("const mo=['','Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];",
         "const mo=['','ene','feb','mar','abr','may','jun','jul','ago','sep','oct','nov','dic'];"),
        ("(bce?' BC':'')", "(bce?' a. C.':'')"),
        ("'  ·  traveler '+(ti+1)+' of '+ATLAS.length",
         "'  ·  viajero '+(ti+1)+' de '+ATLAS.length"),
        ("'STOP '+(idx+1)+' / '+t.stops.length+'  ·  TRAVELER '+(ti+1)+' / '+ATLAS.length",
         "'PARADA '+(idx+1)+' / '+t.stops.length+'  ·  VIAJERO '+(ti+1)+' / '+ATLAS.length"),
        ("+' OTHERS HERE</span>'", "+' MÁS AQUÍ</span>'"),
        ('aria-label="previous traveler"', 'aria-label="viajero anterior"'),
        ('aria-label="next traveler"', 'aria-label="viajero siguiente"'),
        ('aria-label="traveler"', 'aria-label="viajero"'),
    ]
    for a, b in APP_UI:
        assert a in app, f'app string missing: {a!r}'
        app = app.replace(a, b)

with open(OUT, 'w') as f:
    f.write('<!doctype html><meta charset="utf-8">\n')
    f.write('<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">\n')
    f.write(head)
    f.write('\n<script>\nconst ATLAS = ')
    f.write(atlas_json)
    f.write(';\n')
    f.write(coast)
    f.write('\n</script>\n')
    f.write(app)
print(f"wrote {OUT} ({os.path.getsize(OUT)//1024} KB)")
