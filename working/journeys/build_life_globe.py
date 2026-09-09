#!/usr/bin/env python3
"""Build quipu_out/life_globe.html — la vida: the Hyperstition automaton played on the atlas.

Every subject is a point at its home city (the city its journey visits most).
Wire arcs join who-wrote-about-whom (documented text edges, earlier -> later);
breath arcs join documented co-presence (T4/T5). The two-species Life-like
rule found in the Hyperstition repo (wire B1/S12, breath B23/S123, three
bodies unwire, three wires eat a body) is run here in numpy for TICKS ticks
from the Babylon and Monte Verita seeds, and the per-tick state is embedded so
the page animates it: gold = wired, rose = breathing, white = both. A second
run puts breath on the derived space-time layer (same ~50 km cell within five
years) so the two physics can be compared with one toggle.

    python3 build_life_globe.py            # writes quipu_out/life_globe.html
"""
import base64, csv, glob, json, math, os, re
from collections import Counter, defaultdict
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'quipu_out', 'life_globe.html')
DONOR = os.path.join(HERE, 'quipu_out', 'joan_globe.html')
TICKS = 1200
TERMINAL, GOLEM = 'nick_land', 'el_golem'
WSEEDS = ['nabucodonosor_ii', 'ezekiel']; BSEEDS = ['laban', 'isadora_duncan', 'gusto_graeser']

# ---- roster and home cities -------------------------------------------------
cat = list(csv.DictReader(open(os.path.join(HERE, 'catalog_subjects.csv'), encoding='utf-8')))
slugs = [r['slug'] for r in cat if r['status'] == 'built']
name = {r['slug']: r['traveler'].split('(')[0].split(',')[0].strip() for r in cat}
years = {}
for r in cat:
    fd = r.get('first_date') or ''
    try: years[r['slug']] = int(fd.split('-')[0]) if not fd.startswith('-') else -int(fd[1:].split('-')[0])
    except ValueError: years[r['slug']] = None
idx = {s: i for i, s in enumerate(slugs)}; N = len(slugs)

def year(iso):
    if not iso: return None
    neg = iso.startswith('-'); p = (iso[1:] if neg else iso).split('-')[0]
    try: y = int(p)
    except ValueError: return None
    return -y if neg else y

stops = defaultdict(list)
for r in csv.DictReader(open(os.path.join(HERE, 'catalog_stops.csv'), encoding='utf-8')):
    try: la, lo = float(r['lat']), float(r['lng'])
    except ValueError: continue
    stops[r['slug']].append((la, lo, year(r['date'])))
home = []
for s in slugs:
    pts = stops.get(s) or [(0.0, 0.0, None)]
    c = Counter((round(la, 1), round(lo, 1)) for la, lo, _ in pts)
    (la, lo), _ = c.most_common(1)[0]
    home.append([la, lo])
# spread coincident homes a little so a city reads as a cluster, not one dot
seen = Counter()
for i, (la, lo) in enumerate(home):
    k = (la, lo); n = seen[k]; seen[k] += 1
    if n:
        ang = n * 2.399963; rad = 0.18 * math.sqrt(n)
        home[i] = [round(la + rad * math.sin(ang), 3), round(lo + rad * math.cos(ang) / max(math.cos(math.radians(la)), 0.2), 3)]

# ---- edges ----------------------------------------------------------------------
wire = set(); breath = set()
for r in csv.DictReader(open(os.path.join(HERE, 'connections.csv'), encoding='utf-8')):
    a, b = r['subject_slug'], r['counterpart_slug']
    if a not in idx or b not in idx or a == b: continue
    t, sign = r['type'], r['sign'].strip()
    if t in ('4', '5'): breath.add((min(a, b), max(a, b)))
    elif t in ('1', '2', '3', '9'):
        if sign == '+': wire.add((a, b))
        elif sign == '-': wire.add((b, a))
        else:
            ya, yb = years.get(a), years.get(b)
            if ya is not None and yb is not None and ya != yb: wire.add((a, b) if ya < yb else (b, a))
            else: wire.add((a, b)); wire.add((b, a))
# derived co-location (~50 km, +-5 y) from the stops table
KM, YRS = 50.0, 5
DEG = KM / 111.0; WIN = 2 * YRS
buckets = defaultdict(set)
for s, pts in stops.items():
    if s not in idx: continue
    for la, lo, y in pts:
        if y is None: continue
        cell = (math.floor(la / DEG), math.floor(lo / (DEG / max(math.cos(math.radians(la)), 0.2))))
        for w in (y // WIN, (y + YRS) // WIN): buckets[(cell, w)].add((s, y))
coloc = set()
for members in buckets.values():
    by = defaultdict(list)
    for s, y in members: by[s].append(y)
    ns = sorted(by)
    for i in range(len(ns)):
        for j in range(i + 1, len(ns)):
            if abs(min(by[ns[i]]) - min(by[ns[j]])) <= YRS: coloc.add((ns[i], ns[j]))
print(f'{N} subjects, wire {len(wire)}, breath documented {len(breath)}, derived co-location {len(coloc)}')

# ---- the automaton ----------------------------------------------------------------
W = np.zeros((N, N), dtype=np.float32)
for u, v in wire: W[idx[v], idx[u]] = 1.0
def bmat(edges):
    B = np.zeros((N, N), dtype=np.float32)
    for a, b in edges: B[idx[a], idx[b]] = 1.0; B[idx[b], idx[a]] = 1.0
    return B
RULE = dict(Bw={1}, Sw={1, 2}, Bb={2, 3}, Sb={1, 2, 3}, unwire=3, metab=3)
def in_set(n, s): return np.isin(n, list(s))
def run(B):
    w = np.zeros(N, dtype=bool); b = np.zeros(N, dtype=bool)
    for s in WSEEDS: w[idx[s]] = True
    for s in BSEEDS: b[idx[s]] = True
    hw = np.zeros((TICKS, N), dtype=bool); hb = np.zeros((TICKS, N), dtype=bool)
    for t in range(TICKS):
        hw[t] = w; hb[t] = b
        nw = W @ w.astype(np.float32); nb = B @ b.astype(np.float32)
        w2 = ((~w) & in_set(nw, RULE['Bw'])) | (w & in_set(nw, RULE['Sw']))
        b2 = ((~b) & in_set(nb, RULE['Bb'])) | (b & in_set(nb, RULE['Sb']))
        w2 &= ~(b & (nb >= RULE['unwire'])); b2 &= ~(w & (nw >= RULE['metab']))
        w, b = w2, b2
    return hw, hb
def pack(h):  # TICKS x N bool -> base64 of packed bits, row-major, N padded to a byte
    return base64.b64encode(np.packbits(h, axis=1).tobytes()).decode()
runs = {}
for key, B in (('doc', bmat(breath)), ('der', bmat(coloc))):
    hw, hb = run(B)
    runs[key] = dict(w=pack(hw), b=pack(hb), popw=hw.sum(1).tolist(), popb=hb.sum(1).tolist(),
                     land=int(hw[:, idx[TERMINAL]].sum()), golem=int(hw[:, idx[GOLEM]].sum()))
    print(f"run {key}: mean wired {hw.mean(0).sum():.0f}, mean breath {hb.mean(0).sum():.0f}, land lit {runs[key]['land']}/{TICKS}, golem lit {runs[key]['golem']}/{TICKS}")
ROWBYTES = (N + 7) // 8

# ---- donor head and coastlines -------------------------------------------------------
raw = open(DONOR).read()
three_start = raw.find('<script>/**'); three_end = raw.find('</script>', three_start) + len('</script>')
head = raw[:three_end]; assert three_start > 0
head += ('\n<style>#titlebar,#meta,#hint,#controls{display:none!important}'
         '#app{display:block!important}#stage{position:fixed!important;inset:0!important;'
         'width:100vw!important;height:100vh!important}</style>')
topo = json.load(open(os.path.join(HERE, '..', 'heal_earth', 'land-50m.json')))
sc, tr = topo['transform']['scale'], topo['transform']['translate']
coast = []
for arc in topo['arcs']:
    x = y = 0; pts = []
    for dx, dy in arc:
        x += dx; y += dy; pts.append([round(x * sc[0] + tr[0], 3), round(y * sc[1] + tr[1], 3)])
    if len(pts) > 1: coast.append(pts)

WIRE = [[idx[u], idx[v]] for u, v in sorted(wire)]
BREATH = [[idx[a], idx[b]] for a, b in sorted(breath)]
NAMES = [name[s] for s in slugs]
MARK = {'land': idx[TERMINAL], 'golem': idx[GOLEM], 'abulafia': idx.get('abraham_abulafia', -1), 'deleon': idx.get('moses_de_leon', -1)}

app = r"""
<script>
(function(){
  window.addEventListener('error',e=>{ const d=document.createElement('pre'); d.style.cssText='position:fixed;left:8px;bottom:80px;z-index:99;color:#ff8080;font:12px monospace;max-width:90vw;white-space:pre-wrap'; d.textContent='error: '+e.message; document.body.appendChild(d); });
  const THREE=window.THREE, R=1.0, stage=document.getElementById('stage');
  function llv(lat,lng,r){ const la=lat*Math.PI/180, lo=lng*Math.PI/180;
    return new THREE.Vector3(r*Math.cos(la)*Math.cos(lo), r*Math.sin(la), -r*Math.cos(la)*Math.sin(lo)); }
  function unpack(b64){ const s=atob(b64), a=new Uint8Array(s.length); for(let i=0;i<s.length;i++)a[i]=s.charCodeAt(i); return a; }
  const RUNS={}; for(const k in RUNSRC){ RUNS[k]={w:unpack(RUNSRC[k].w), b:unpack(RUNSRC[k].b), popw:RUNSRC[k].popw, popb:RUNSRC[k].popb}; }
  let layer='doc';
  function bit(arr,t,i){ return (arr[t*ROWBYTES+(i>>3)] >> (7-(i&7))) & 1; }

  const scene=new THREE.Scene(), camera=new THREE.PerspectiveCamera(42,1,0.01,200);
  const D0=new THREE.Vector3(0,0.42,1).normalize(); let camDist=2.7;
  function updateCam(){ const off=Math.max(0,1-camera.aspect)*0.65; camera.position.copy(D0).multiplyScalar(camDist); camera.lookAt(0,-off,0); }
  const renderer=new THREE.WebGLRenderer({antialias:true}); renderer.setPixelRatio(Math.min(devicePixelRatio,2)); stage.appendChild(renderer.domElement);
  scene.add(new THREE.AmbientLight(0xffffff,0.55));
  const sun=new THREE.DirectionalLight(0xfff2d0,0.9); sun.position.set(3,2,4); scene.add(sun);
  (function(){ const g=new THREE.BufferGeometry(), n=1400, a=new Float32Array(n*3);
    for(let i=0;i<n;i++){ const v=new THREE.Vector3(Math.random()-.5,Math.random()-.5,Math.random()-.5).normalize().multiplyScalar(60+Math.random()*40); a[i*3]=v.x;a[i*3+1]=v.y;a[i*3+2]=v.z; }
    g.setAttribute('position',new THREE.BufferAttribute(a,3));
    scene.add(new THREE.Points(g,new THREE.PointsMaterial({color:0x8fa3c8,size:0.05,sizeAttenuation:true,transparent:true,opacity:0.7}))); })();
  const globe=new THREE.Group(); scene.add(globe);
  globe.add(new THREE.Mesh(new THREE.SphereGeometry(R,64,64), new THREE.MeshPhongMaterial({color:0x0b1526,emissive:0x050a14,shininess:6,transparent:true,opacity:0.32,depthWrite:false})));
  (function(){ const segs=[]; for(const line of COAST){ for(let i=0;i<line.length-1;i++){ const a=llv(line[i][1],line[i][0],R*1.002), b=llv(line[i+1][1],line[i+1][0],R*1.002); segs.push(a.x,a.y,a.z,b.x,b.y,b.z); } }
    const g=new THREE.BufferGeometry(); g.setAttribute('position',new THREE.BufferAttribute(new Float32Array(segs),3));
    globe.add(new THREE.LineSegments(g,new THREE.LineBasicMaterial({color:0x8fd8f4,transparent:true,opacity:0.4}))); })();

  // ---- nodes -------------------------------------------------------------------
  const NN=HOME.length, npos=new Float32Array(NN*3), ncol=new Float32Array(NN*3), nsize=new Float32Array(NN), nvec=[];
  for(let i=0;i<NN;i++){ const v=llv(HOME[i][0],HOME[i][1],R*1.012); nvec.push(v); npos[i*3]=v.x;npos[i*3+1]=v.y;npos[i*3+2]=v.z; }
  const ngeo=new THREE.BufferGeometry();
  ngeo.setAttribute('position',new THREE.BufferAttribute(npos,3));
  ngeo.setAttribute('ncolor',new THREE.BufferAttribute(ncol,3));
  ngeo.setAttribute('psize',new THREE.BufferAttribute(nsize,1));
  const nmat=new THREE.ShaderMaterial({
    uniforms:{uScale:{value:1}},
    vertexShader:'attribute float psize; attribute vec3 ncolor; varying vec3 vC; varying float vS; uniform float uScale;'+
      'void main(){ vC=ncolor; vS=psize; vec4 mv=modelViewMatrix*vec4(position,1.0); gl_PointSize=psize*uScale*(3.2/-mv.z); gl_Position=projectionMatrix*mv; }',
    fragmentShader:'varying vec3 vC; varying float vS; void main(){ vec2 d=gl_PointCoord-vec2(0.5); float r=length(d);'+
      ' if(r>0.5)discard; float a=smoothstep(0.5,0.12,r); gl_FragColor=vec4(vC, a*(0.35+0.65*min(1.0,vS/6.0))); }',
    transparent:true, blending:THREE.AdditiveBlending, depthWrite:false});
  globe.add(new THREE.Points(ngeo,nmat));

  // ---- arcs (wire directed, breath undirected) ------------------------------------------
  function arcs(pairs, lift0){
    const pos=[], eid=[], along=[];
    for(let e=0;e<pairs.length;e++){
      const va=nvec[pairs[e][0]], vb=nvec[pairs[e][1]];
      const ang=va.angleTo(vb)||1e-4, lift=lift0+0.20*ang/Math.PI, n=Math.max(4,Math.min(22,Math.round(ang*18)));
      let prev=null;
      for(let s=0;s<=n;s++){ const t=s/n;
        const v=va.clone().multiplyScalar(Math.sin((1-t)*ang)).add(vb.clone().multiplyScalar(Math.sin(t*ang))).divideScalar(Math.sin(ang));
        v.normalize().multiplyScalar(R*(1.012+lift*Math.sin(Math.PI*t)));
        if(prev){ pos.push(prev.x,prev.y,prev.z,v.x,v.y,v.z); eid.push(e,e); along.push((s-1)/n,t); }
        prev=v; } }
    const g=new THREE.BufferGeometry();
    g.setAttribute('position',new THREE.BufferAttribute(new Float32Array(pos),3));
    const lit=new Float32Array(eid.length); g.setAttribute('lit',new THREE.BufferAttribute(lit,1));
    g.setAttribute('along',new THREE.BufferAttribute(new Float32Array(along),1));
    return {geo:g, eid:eid, lit:lit};
  }
  function arcMat(rgb, base){
    return new THREE.ShaderMaterial({
      uniforms:{uT:{value:0}},
      vertexShader:'attribute float lit; attribute float along; varying float vL; varying float vA; void main(){ vL=lit; vA=along; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0); }',
      fragmentShader:'uniform float uT; varying float vL; varying float vA; void main(){'+
        ' float flow = vL>1.5 ? 0.35+0.65*exp(-pow(fract(vA-uT)-0.5,2.0)/0.02) : 1.0;'+   // 2 = source lit: a pulse runs along the arc
        ' float a = '+base+' + vL*0.42*flow; vec3 c = vec3('+rgb+'); gl_FragColor=vec4(c,a); }',
      transparent:true, blending:THREE.AdditiveBlending, depthWrite:false});
  }
  const AW=arcs(WIRE,0.015), AB=arcs(BREATH,0.03);
  const matW=arcMat('1.0,0.78,0.32','0.045'), matB=arcMat('0.95,0.40,0.55','0.045');
  globe.add(new THREE.LineSegments(AW.geo,matW)); globe.add(new THREE.LineSegments(AB.geo,matB));

  // ---- state -> colours ---------------------------------------------------------------
  let tick=0, shownTick=-1, shownLayer='';
  const GOLD=[1.0,0.80,0.36], ROSE=[0.98,0.45,0.60], BOTH=[1.0,0.97,0.90], DIM=[0.30,0.42,0.62];
  function paint(t){
    const run=RUNS[layer]; if(t===shownTick && layer===shownLayer) return; shownTick=t; shownLayer=layer;
    for(let i=0;i<NN;i++){ const w=bit(run.w,t,i), b=bit(run.b,t,i);
      const c=(w&&b)?BOTH:w?GOLD:b?ROSE:DIM; ncol[i*3]=c[0];ncol[i*3+1]=c[1];ncol[i*3+2]=c[2];
      nsize[i]=(w||b)?6.5:1.6; }
    ngeo.attributes.ncolor.needsUpdate=true; ngeo.attributes.psize.needsUpdate=true;
    for(let k=0;k<AW.eid.length;k++){ const e=AW.eid[k], s=bit(run.w,t,WIRE[e][0]), d=bit(run.w,t,WIRE[e][1]); AW.lit[k]= s&&d?1:s?2:0; }
    AW.geo.attributes.lit.needsUpdate=true;
    for(let k=0;k<AB.eid.length;k++){ const e=AB.eid[k]; AB.lit[k]=(bit(run.b,t,BREATH[e][0])&&bit(run.b,t,BREATH[e][1]))?1:0; }
    AB.geo.attributes.lit.needsUpdate=true;
  }

  // ---- chrome -----------------------------------------------------------------------
  const css=document.createElement('style');
  css.textContent=
    '#veil{position:fixed;inset:0;z-index:20;background:radial-gradient(120% 120% at 50% 40%,#0d1626 0%,#05080f 70%);display:flex;align-items:center;justify-content:center;flex-direction:column;gap:14px;transition:opacity .9s ease;font-family:Georgia,serif}'+
    '#veil.gone{opacity:0;pointer-events:none}#veil .t{font-size:30px;color:#eadfbf;letter-spacing:.35em}#veil .s{font-size:13px;color:#8fa3c8;letter-spacing:.18em}'+
    '#vig{position:fixed;inset:0;z-index:5;pointer-events:none;background:radial-gradient(130% 130% at 50% 42%,transparent 55%,rgba(2,4,9,.55) 100%)}'+
    '#panelcol{position:fixed;top:max(14px,env(safe-area-inset-top));left:max(14px,env(safe-area-inset-left));z-index:9;display:flex;flex-direction:column;align-items:flex-start;gap:8px;font:14px/1.55 Georgia,serif;width:min(360px,calc(100vw - 28px))}'+
    '#hud{width:100%;box-sizing:border-box;color:#dce8f8;background:linear-gradient(160deg,rgba(16,24,42,.80),rgba(8,13,24,.66));backdrop-filter:blur(14px) saturate(1.25);-webkit-backdrop-filter:blur(14px) saturate(1.25);padding:12px 14px;border-radius:14px;border:1px solid rgba(242,193,78,.18);box-shadow:0 14px 44px rgba(0,0,0,.5)}'+
    '.hrow{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.hrow .btn{margin:0;padding:4px 10px;font-size:12.5px}'+
    '.btn{font:inherit;font-size:13px;color:#f2c14e;background:linear-gradient(180deg,rgba(242,193,78,.16),rgba(242,193,78,.07));border:1px solid rgba(242,193,78,.45);border-radius:999px;padding:4px 16px;cursor:pointer;letter-spacing:.06em}'+
    '.btn.on{background:rgba(242,193,78,.35);color:#fff6dc}'+
    '#tk{font-size:26px;color:#f2c14e;margin:2px 0 0 4px}#stat{color:#b9c8e2;font-size:12.5px;margin-left:4px;line-height:1.5}'+
    '#legend{margin-top:8px;font-size:12px;color:#b9c8e2}#legend b{display:inline-block;width:9px;height:9px;border-radius:50%;margin:0 4px 0 8px;vertical-align:middle}'+
    '#hint{display:block;color:#93a6c6;font-size:12px;opacity:.85;transition:opacity 1.2s ease;margin-left:4px}'+
    '#tlwrap{position:fixed;left:50%;transform:translateX(-50%);bottom:max(12px,env(safe-area-inset-bottom));width:min(1200px,94vw);z-index:9;background:linear-gradient(160deg,rgba(16,24,42,.72),rgba(8,13,24,.6));backdrop-filter:blur(12px);border:1px solid rgba(143,163,200,.16);border-radius:12px;padding:5px 10px}'+
    '#tl{display:block;width:100%;height:56px;cursor:crosshair}'+
    '.lbl{position:fixed;z-index:8;pointer-events:none;font:12px Georgia,serif;color:#eadfbf;text-shadow:0 0 6px #000,0 0 2px #000;transform:translate(6px,-50%);white-space:nowrap}';
  document.head.appendChild(css);
  const STR={
    es:{title:'la vida',sub:'el autómata jugado sobre el atlas',play:'pausa',pause:'seguir',speed:'velocidad',speeds:{2:'lento',8:'normal',30:'rápido'},
        doc:'cuerpos: documentados',der:'cuerpos: co-localizados',tick:'tic',wired:'cableados',breath:'cuerpos',
        legend:'<b style="background:#f2c14e"></b>hilo (escritura)<b style="background:#f26f96"></b>cuerpo (co-presencia)<b style="background:#fff8e8"></b>ambos',
        hint:'espacio pausa · 1/2/3 velocidad · c capa · toca la línea del tiempo · arrastra para girar',loading:'calculando la vida…'},
    en:{title:'the life',sub:'the automaton played on the atlas',play:'pause',pause:'play',speed:'speed',speeds:{2:'slow',8:'normal',30:'fast'},
        doc:'bodies: documented',der:'bodies: co-located',tick:'tick',wired:'wired',breath:'bodies',
        legend:'<b style="background:#f2c14e"></b>wire (writing)<b style="background:#f26f96"></b>breath (co-presence)<b style="background:#fff8e8"></b>both',
        hint:'space pause · 1/2/3 speed · c layer · tap the timeline · drag to turn',loading:'computing the life…'}};
  let L=STR.es;
  document.body.insertAdjacentHTML('beforeend','<div id="veil"><div class="t">la vida</div><div class="s" id="veilS"></div></div><div id="vig"></div>');
  const col=document.createElement('div'); col.id='panelcol';
  col.innerHTML='<div id="hud"><div class="hrow"><button class="btn" id="pp"></button><button class="btn" id="spd"></button><button class="btn" id="lay"></button><button class="btn" id="lng">EN</button></div>'+
    '<div id="legend"></div></div><span id="tk"></span><span id="stat"></span><span id="hint"></span>';
  document.body.appendChild(col);
  const tlwrap=document.createElement('div'); tlwrap.id='tlwrap'; const tl=document.createElement('canvas'); tl.id='tl'; tlwrap.appendChild(tl); document.body.appendChild(tlwrap);
  const labels={}; for(const k in MARK){ if(MARK[k]<0)continue; const d=document.createElement('div'); d.className='lbl'; d.textContent=NAMES[MARK[k]]; document.body.appendChild(d); labels[k]=d; }

  let playing=true, speed=8, acc=0; const SPEEDS=[2,8,30];
  const ppBtn=document.getElementById('pp'), spdBtn=document.getElementById('spd'), layBtn=document.getElementById('lay'), lngBtn=document.getElementById('lng');
  function setSpeed(v){ speed=v; spdBtn.textContent=L.speed+' · '+(L.speeds[v]||v); }
  function setLayer(v){ layer=v; layBtn.textContent=L[v]; layBtn.classList.toggle('on',v==='der'); }
  function applyLang(code){ L=STR[code]; document.documentElement.lang=code; lngBtn.textContent=code==='es'?'EN':'ES';
    document.getElementById('legend').innerHTML=L.legend; document.getElementById('hint').innerHTML=L.hint;
    document.getElementById('veilS').textContent=L.loading; document.title=L.title+' — Colegio Invisible';
    ppBtn.textContent=playing?L.play:L.pause; setSpeed(speed); setLayer(layer); }
  ppBtn.addEventListener('click',()=>{playing=!playing; ppBtn.textContent=playing?L.play:L.pause;});
  spdBtn.addEventListener('click',()=>setSpeed(SPEEDS[(SPEEDS.indexOf(speed)+1)%SPEEDS.length]));
  layBtn.addEventListener('click',()=>setLayer(layer==='doc'?'der':'doc'));
  lngBtn.addEventListener('click',()=>applyLang(document.documentElement.lang==='es'?'en':'es'));
  applyLang('es');
  window.addEventListener('keydown',e=>{ if(e.code==='Space'){e.preventDefault();playing=!playing;ppBtn.textContent=playing?L.play:L.pause;}
    else if(e.key==='1')setSpeed(2); else if(e.key==='2')setSpeed(8); else if(e.key==='3')setSpeed(30);
    else if(e.key==='c'||e.key==='C')setLayer(layer==='doc'?'der':'doc'); else if(e.key==='0')tick=0; });

  function drawTL(){ const dpr=devicePixelRatio, w=tl.width=tl.clientWidth*dpr, h=tl.height=tl.clientHeight*dpr, cx=tl.getContext('2d');
    cx.clearRect(0,0,w,h); const run=RUNS[layer]; let mx=1; for(let t=0;t<TICKS;t++) mx=Math.max(mx,run.popw[t],run.popb[t]);
    function line(arr,color){ cx.beginPath(); for(let t=0;t<TICKS;t++){ const x=t/(TICKS-1)*w, y=h*0.92-arr[t]/mx*h*0.78; t?cx.lineTo(x,y):cx.moveTo(x,y); } cx.strokeStyle=color; cx.lineWidth=1.2*dpr; cx.stroke(); }
    line(run.popw,'rgba(242,193,78,0.9)'); line(run.popb,'rgba(242,111,150,0.9)');
    cx.save(); cx.shadowColor='rgba(242,193,78,0.9)'; cx.shadowBlur=7*dpr; cx.fillStyle='#f2c14e'; cx.fillRect(tick/(TICKS-1)*w-1.2*dpr,0,2.4*dpr,h); cx.restore(); }
  let tlDown=false; function tlSeek(e){ const r=tl.getBoundingClientRect(); tick=Math.max(0,Math.min(TICKS-1,Math.round((e.clientX-r.left)/r.width*(TICKS-1)))); }
  tl.addEventListener('pointerdown',e=>{tlDown=true;tl.setPointerCapture(e.pointerId);tlSeek(e);}); tl.addEventListener('pointermove',e=>{if(tlDown)tlSeek(e);}); tl.addEventListener('pointerup',()=>{tlDown=false;});

  const target=new THREE.Quaternion().setFromEuler(new THREE.Euler(0,-0.6,0)); const dom=renderer.domElement; dom.style.touchAction='none';
  const ptrs=new Map(); let pinchDist=null, userZoomed=false;
  dom.addEventListener('pointerdown',e=>{ ptrs.set(e.pointerId,[e.clientX,e.clientY]); dom.setPointerCapture(e.pointerId); if(ptrs.size===2){ const [a,b]=[...ptrs.values()]; pinchDist=Math.hypot(a[0]-b[0],a[1]-b[1]); } });
  dom.addEventListener('pointermove',e=>{ const p=ptrs.get(e.pointerId); if(!p)return; const dx=e.clientX-p[0], dy=e.clientY-p[1]; ptrs.set(e.pointerId,[e.clientX,e.clientY]);
    if(ptrs.size===2){ const [a,b]=[...ptrs.values()]; const d=Math.hypot(a[0]-b[0],a[1]-b[1]); if(pinchDist&&d>0){ camDist=Math.max(1.45,Math.min(8,camDist*pinchDist/d)); userZoomed=true; updateCam(); } pinchDist=d; return; }
    target.premultiply(new THREE.Quaternion().setFromEuler(new THREE.Euler(dy*0.005,dx*0.005,0,'XYZ'))); });
  const release=e=>{ptrs.delete(e.pointerId); if(ptrs.size<2)pinchDist=null;}; dom.addEventListener('pointerup',release); dom.addEventListener('pointercancel',release);
  dom.addEventListener('wheel',e=>{e.preventDefault(); userZoomed=true; camDist=Math.max(1.45,Math.min(8,camDist*Math.exp(e.deltaY*0.001))); updateCam();},{passive:false});
  function fitDist(aspect){ const vhalf=42/2*Math.PI/180, hhalf=Math.atan(Math.tan(vhalf)*aspect); return 1.12/Math.sin(Math.min(vhalf,hhalf)); }
  function resize(){ const w=stage.clientWidth,h=stage.clientHeight; renderer.setSize(w,h); camera.aspect=w/h; camera.updateProjectionMatrix(); if(!userZoomed)camDist=Math.max(2.7,fitDist(w/h)); updateCam(); }
  window.addEventListener('resize',resize); resize(); updateCam();

  const tkEl=document.getElementById('tk'), statEl=document.getElementById('stat'), veil=document.getElementById('veil'); let veilGone=false, lastT=performance.now();
  setTimeout(()=>{ const h=document.getElementById('hint'); if(h) h.style.opacity=0.28; },8000);
  const tmp=new THREE.Vector3();
  function placeLabels(){ const w=stage.clientWidth, h=stage.clientHeight, run=RUNS[layer];
    for(const k in labels){ const i=MARK[k]; tmp.copy(nvec[i]).applyQuaternion(globe.quaternion); const facing=tmp.clone().normalize().dot(camera.position.clone().normalize())>0.15;
      tmp.project(camera); const el=labels[k]; el.style.display=facing?'block':'none'; el.style.left=((tmp.x+1)/2*w)+'px'; el.style.top=((1-tmp.y)/2*h)+'px';
      el.style.color=bit(run.w,tick,i)?'#ffe9a8':'#8fa3c8'; } }
  (function animate(){ requestAnimationFrame(animate);
    const t=performance.now(), dt=(t-lastT)/1000; lastT=t;
    if(playing){ acc+=speed*dt; while(acc>=1){ acc-=1; tick=(tick+1)%TICKS; } }
    paint(tick); matW.uniforms.uT.value=(t/900)%1;
    const run=RUNS[layer]; tkEl.textContent=L.tick+' '+tick; statEl.textContent=L.wired+' '+run.popw[tick]+' · '+L.breath+' '+run.popb[tick];
    drawTL(); globe.quaternion.slerp(target,1-Math.pow(0.91,Math.max(1,dt*60))); placeLabels();
    renderer.render(scene,camera);
    if(!veilGone){ veilGone=true; requestAnimationFrame(()=>veil.classList.add('gone')); } })();
})();
</script>
"""

with open(OUT, 'w') as f:
    f.write('<!doctype html><html lang="es"><meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">\n')
    f.write('<title>la vida — Colegio Invisible</title>\n'); f.write(head)
    f.write('\n<script>\nconst HOME=' + json.dumps(home, separators=(',', ':')) + ';\n')
    f.write('const NAMES=' + json.dumps(NAMES, ensure_ascii=False, separators=(',', ':')) + ';\n')
    f.write('const WIRE=' + json.dumps(WIRE, separators=(',', ':')) + ';\nconst BREATH=' + json.dumps(BREATH, separators=(',', ':')) + ';\n')
    f.write('const MARK=' + json.dumps(MARK) + ';\nconst TICKS=' + str(TICKS) + ';\nconst ROWBYTES=' + str(ROWBYTES) + ';\n')
    f.write('const RUNSRC=' + json.dumps(runs, separators=(',', ':')) + ';\n')
    f.write('const COAST=' + json.dumps(coast, separators=(',', ':')) + ';\n</script>\n')
    f.write(app)
print(f'wrote {OUT} ({os.path.getsize(OUT)//1024} KB)')
