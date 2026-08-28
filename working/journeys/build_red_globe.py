#!/usr/bin/env python3
"""Build quipu_out/red_globe.html — la red: the atlas as emergent connectivity.

Layers, not journeys:
  1. cities  — stops clustered to town/city (label + geographic split), drawn as
     circles whose area ~ travelers who stood there; click one for its name.
  2. regions — a second circle level: nearby cities merged, radius^2 = sum of
     parts; shown when zoomed out (the circle model of circles).
  3. corridors — aggregate city-to-city links weighted by UNIQUE travelers,
     individual subjects masked (weight >= 2); a slow gaussian pulse flows in
     each corridor's dominant direction, brightness ~ weight.
  4. umbral — a live slider raises the corridor threshold, peeling the network
     down to its spine.
"""
import json, glob, os, re, math, collections

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'quipu_out', 'red_globe.html')
DONOR = os.path.join(HERE, 'quipu_out', 'joan_globe.html')

J = {os.path.basename(f)[:-13]: json.load(open(f)) for f in sorted(glob.glob(os.path.join(HERE, '*.journey.json')))}

def datekey(iso):
    if not iso: return None
    neg = iso.startswith('-')
    pth = ((iso[1:] if neg else iso).split('-') + ['1', '1'])[:3]
    try: y = int(pth[0])
    except ValueError: return None
    return -y if neg else y

def lead(name):
    l = re.split(r'[,:—]', name or '')[0].strip()
    return l[:40] if 2 < len(l) else None

def ang(a, b):
    la1, lo1, la2, lo2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((la2-la1)/2)**2 + math.cos(la1)*math.cos(la2)*math.sin((lo2-lo1)/2)**2
    return 2*math.degrees(math.asin(min(1, math.sqrt(h))))

# ---- 1. city nodes: same label, geographically split (twin cities apart) ----
by_label = collections.defaultdict(list)   # label -> [(lat,lng,slug)]
seqs = {}
for slug, j in J.items():
    seq = []
    for seg in j.get('segments', []):
        for st in seg.get('stops', []):
            if isinstance(st.get('lat'), (int, float)):
                L = lead(st.get('name',''))
                if L:
                    y = datekey(st.get('date',''))
                    by_label[L].append((st['lat'], st['lng'], slug, y))
                    seq.append((st['lat'], st['lng'], L, y))
    seqs[slug] = seq

nodes = []                                  # {label, lat, lng, trav:set}
def node_for(label, lat, lng, clusters):
    for c in clusters:
        if ang((lat, lng), (c['lat'], c['lng'])) < 6.0:
            return c
    c = {'label': label, 'lat': lat, 'lng': lng, 'trav': set(), 'n': 0, 'ty': {}}
    clusters.append(c); nodes.append(c)
    return c

label_clusters = {}
for label, pts in by_label.items():
    clusters = label_clusters.setdefault(label, [])
    for lat, lng, slug, y in pts:
        c = node_for(label, lat, lng, clusters)
        w = 1.0 / (c['n'] + 1)
        c['lat'] += (lat - c['lat']) * w; c['lng'] += (lng - c['lng']) * w
        c['n'] += 1; c['trav'].add(slug)
        if y is not None and (slug not in c['ty'] or y < c['ty'][slug]): c['ty'][slug] = y

def city_of(lat, lng, label):
    best, bd = None, 1e9
    for c in label_clusters.get(label, []):
        d = ang((lat, lng), (c['lat'], c['lng']))
        if d < bd: bd, best = d, c
    return best

CITIES = [c for c in nodes if len(c['trav']) >= 2]
idx = {id(c): i for i, c in enumerate(CITIES)}
print(f"city nodes: {len(nodes)}  kept (>=2 travelers): {len(CITIES)}")

# ---- 2. corridors: unique travelers per city pair, dominant direction ------
pair_trav = collections.defaultdict(set)
pair_dir = collections.Counter()
pair_ty = collections.defaultdict(dict)
for slug, seq in seqs.items():
    for (la1, lo1, L1, y1), (la2, lo2, L2, y2) in zip(seq, seq[1:]):
        c1, c2 = city_of(la1, lo1, L1), city_of(la2, lo2, L2)
        if c1 is None or c2 is None or c1 is c2: continue
        if id(c1) not in idx or id(c2) not in idx: continue
        a, b = idx[id(c1)], idx[id(c2)]
        key = (min(a, b), max(a, b))
        pair_trav[key].add(slug)
        pair_dir[(a, b)] += 1
        y = y2 if y2 is not None else y1
        if y is not None and (slug not in pair_ty[key] or y < pair_ty[key][slug]): pair_ty[key][slug] = y
CORR = []
for (a, b), trav in pair_trav.items():
    w = len(trav)
    if w < 2: continue                      # mask individual subjects
    fwd = pair_dir.get((a, b), 0); rev = pair_dir.get((b, a), 0)
    src, dst = (a, b) if fwd >= rev else (b, a)
    CORR.append([src, dst, w, sorted(pair_ty[(min(a,b),max(a,b))].values())])
print(f"corridors kept (>=2 travelers): {len(CORR)}  max weight {max(c[2] for c in CORR)}")

# ---- 3. the pyramid: agglomerative levels at shrinking radii ----------------
def agglo(radius):
    order = sorted(range(len(CITIES)), key=lambda i: -len(CITIES[i]['trav']))
    clusters = []
    for i in order:
        c = CITIES[i]
        placed = False
        for r in clusters:
            if ang((c['lat'], c['lng']), (r['lat'], r['lng'])) < radius:
                r['members'].append(i); placed = True; break
        if not placed:
            clusters.append({'lat': c['lat'], 'lng': c['lng'], 'members': [i]})
    out = []
    for r in clusters:
        trav = set(); ty = {}
        for i in r['members']:
            trav |= CITIES[i]['trav']
            for sl, y in CITIES[i]['ty'].items():
                if sl not in ty or y < ty[sl]: ty[sl] = y
        top = max(r['members'], key=lambda i: len(CITIES[i]['trav']))
        lab = CITIES[top]['label'] + (f" +{len(r['members'])-1}" if len(r['members']) > 1 else '')
        out.append([round(r['lat'], 3), round(r['lng'], 3), lab, len(trav), sorted(ty.values()), sorted(r['members'])])
    return out

CITY_JS = [[round(c['lat'], 3), round(c['lng'], 3), c['label'], len(c['trav']), sorted(c['ty'].values()), [i]] for i, c in enumerate(CITIES)]
LEVELS = [agglo(18), agglo(9), agglo(4.5), agglo(2.2), CITY_JS]
print('pyramid levels:', [len(l) for l in LEVELS])
EVT = sorted([y for c in CORR for y in c[3]] + [y for c in CITY_JS for y in c[4]])
print(f"events: {len(EVT)}  span {EVT[0]} .. {EVT[-1]}")

# ---- donor + coast ----------------------------------------------------------
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
  function updateCam(){ const off=Math.max(0,1-camera.aspect)*0.65;
    camera.position.copy(D0).multiplyScalar(camDist); camera.lookAt(0,-off,0); }
  const renderer=new THREE.WebGLRenderer({antialias:true});
  renderer.setPixelRatio(Math.min(devicePixelRatio,2)); stage.appendChild(renderer.domElement);
  scene.add(new THREE.AmbientLight(0xffffff,0.55));
  const sun=new THREE.DirectionalLight(0xfff2d0,0.9); sun.position.set(3,2,4); scene.add(sun);
  (function(){ const g=new THREE.BufferGeometry(), NS=1400, a=new Float32Array(NS*3);
    for(let i=0;i<NS;i++){ const v=new THREE.Vector3(Math.random()-.5,Math.random()-.5,Math.random()-.5).normalize().multiplyScalar(60+Math.random()*40);
      a[i*3]=v.x;a[i*3+1]=v.y;a[i*3+2]=v.z; }
    g.setAttribute('position',new THREE.BufferAttribute(a,3));
    scene.add(new THREE.Points(g,new THREE.PointsMaterial({color:0x8fa3c8,size:0.05,sizeAttenuation:true,transparent:true,opacity:0.7}))); })();
  const globe=new THREE.Group(); scene.add(globe);
  globe.add(new THREE.Mesh(new THREE.SphereGeometry(R,64,64),
    new THREE.MeshPhongMaterial({color:0x0b1526,emissive:0x050a14,shininess:6,transparent:true,opacity:0.32,depthWrite:false})));
  globe.add(new THREE.Mesh(new THREE.SphereGeometry(R*1.045,64,64), new THREE.ShaderMaterial({
    vertexShader:'varying vec3 vN; varying vec3 vV;'+
      'void main(){ vN=normalize(normalMatrix*normal); vec4 mv=modelViewMatrix*vec4(position,1.0); vV=normalize(-mv.xyz); gl_Position=projectionMatrix*mv; }',
    fragmentShader:'varying vec3 vN; varying vec3 vV;'+
      'void main(){ float rim=pow(1.0-abs(dot(vN,vV)),3.0); gl_FragColor=vec4(vec3(0.35,0.6,0.95)*rim,rim*0.5); }',
    transparent:true, blending:THREE.AdditiveBlending, side:THREE.BackSide, depthWrite:false})));
  (function(){ const segs=[];
    for(const line of COAST){ for(let i=0;i<line.length-1;i++){
      const a=llv(line[i][1],line[i][0],R*1.002), b=llv(line[i+1][1],line[i+1][0],R*1.002);
      segs.push(a.x,a.y,a.z,b.x,b.y,b.z); } }
    const g=new THREE.BufferGeometry(); g.setAttribute('position',new THREE.BufferAttribute(new Float32Array(segs),3));
    globe.add(new THREE.LineSegments(g,new THREE.LineBasicMaterial({color:0x8fd8f4,transparent:true,opacity:0.5}))); })();

  // ---- corridors: one geometry, per-vertex weight/along/phase --------------
  const WMAX=CORR.reduce((m,c)=>Math.max(m,c[2]),2);
  // each corridor is a BUNDLE: one jittered strand per traveler, so the weave
  // glows like the pulse globe and cables thicken strand-by-strand in history
  function h1(n){ return (Math.sin(n*127.1)*43758.5453)%1; }
  const pos=[], alongA=[], wA=[], phA=[], skA=[], hlA=[], corrRange=[];
  CORR.forEach((c,ci)=>{
    const A=CITY[c[0]], B=CITY[c[1]], wf=c[2];
    const va=llv(A[0],A[1],1), vb=llv(B[0],B[1],1);
    const a=va.angleTo(vb)||1e-4;
    const n=Math.max(6,Math.min(26,Math.round(a*20)));
    const perp=new THREE.Vector3().crossVectors(va,vb).normalize();
    const v0=wA.length;
    for(let st=1; st<=wf; st++){
      const ph=(h1(ci*7.3+st*1.7)+1)%1;
      const lat=(h1(ci*3.1+st*2.9))*0.012;            // lateral braid offset
      const lift=0.018+0.20*a/Math.PI*(0.85+0.3*((h1(ci+st*5.1)+1)%1));
      let prev=null, prevT=0;
      for(let s2=0;s2<=n;s2++){ const t=s2/n;
        const v=va.clone().multiplyScalar(Math.sin((1-t)*a)).add(vb.clone().multiplyScalar(Math.sin(t*a))).divideScalar(Math.sin(a));
        v.normalize();
        v.addScaledVector(perp, lat*Math.sin(Math.PI*t));
        v.normalize().multiplyScalar(R*(1.009+lift*Math.sin(Math.PI*t)));
        if(prev){ pos.push(prev.x,prev.y,prev.z,v.x,v.y,v.z);
          alongA.push(prevT,t); wA.push(0,0); phA.push(ph,ph); skA.push(st,st); hlA.push(0,0); }
        prev=v; prevT=t; }
    }
    corrRange.push([v0, wA.length-v0]);
  });
  const geo=new THREE.BufferGeometry();
  geo.setAttribute('position',new THREE.BufferAttribute(new Float32Array(pos),3));
  geo.setAttribute('along',new THREE.BufferAttribute(new Float32Array(alongA),1));
  const wBuf=new Float32Array(wA);
  const wAttr=new THREE.BufferAttribute(wBuf,1);
  geo.setAttribute('w',wAttr);
  geo.setAttribute('ph',new THREE.BufferAttribute(new Float32Array(phA),1));
  geo.setAttribute('sk',new THREE.BufferAttribute(new Float32Array(skA),1));
  const hlBuf=new Float32Array(hlA);
  const hlAttr=new THREE.BufferAttribute(hlBuf,1);
  geo.setAttribute('hl',hlAttr);
  const mat=new THREE.ShaderMaterial({
    uniforms:{uT:{value:0},uMin:{value:2},uWmax:{value:WMAX}},
    vertexShader:'attribute float along; attribute float w; attribute float ph; attribute float sk; attribute float hl;'+
      'varying float vA; varying float vW; varying float vP; varying float vS; varying float vH;'+
      'void main(){ vA=along; vW=w; vP=ph; vS=sk; vH=hl; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0); }',
    fragmentShader:'uniform float uT; uniform float uMin;'+
      'varying float vA; varying float vW; varying float vP; varying float vS; varying float vH;'+
      'void main(){ if(vW<uMin || vS>vW) discard;'+
      ' float d=fract(uT+vP-vA); d=d>0.5?d-1.0:d;'+
      ' float flash=exp(-d*d/(2.0*0.055*0.055));'+
      ' vec3 ember=vec3(0.22,0.45,0.75);'+
      ' vec3 blanco=vec3(0.80,0.92,1.0);'+          // bluish bright white, not gold
      ' vec3 c=mix(ember,blanco,flash);'+
      ' float a=0.10+0.55*flash;'+
      ' if(vH>0.5){'+                               // strands of the selected circle: celeste
      '   c=mix(c,vec3(0.50,0.80,1.0),0.65);'+
      '   a=min(1.0,a*1.9+0.10); }'+
      ' gl_FragColor=vec4(c,a); }',
    transparent:true, blending:THREE.AdditiveBlending, depthWrite:false});
  globe.add(new THREE.LineSegments(geo,mat));

  // ---- circle layers: cities and regions -----------------------------------
  function makeCircleMat(blue){ const c1=blue?'vec3(0.40,0.68,0.95)':'vec3(0.95,0.80,0.45)';
    const c2=blue?'vec3(0.60,0.88,1.0)':'vec3(1.0,0.85,0.5)';
    const boost=blue?'1.5':'1.0';
    return new THREE.ShaderMaterial({
    uniforms:{uFade:{value:1}},
    vertexShader:'varying vec2 vUv; void main(){ vUv=uv; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0); }',
    fragmentShader:'uniform float uFade; varying vec2 vUv;'+
      'void main(){ vec2 q=vUv*2.0-1.0; float d=length(q); if(d>1.0) discard;'+
      ' float ring=smoothstep(0.70,0.86,d)*(1.0-smoothstep(0.90,1.0,d));'+
      ' float glow=exp(-d*d*2.2)*0.14;'+
      ' float a=(glow+0.50*ring)*uFade*'+boost+';'+
      ' vec3 c=mix('+c1+','+c2+',ring);'+
      ' gl_FragColor=vec4(c,a); }',
    transparent:true, blending:THREE.AdditiveBlending, depthWrite:false, side:THREE.DoubleSide}); }
  const selMat=makeCircleMat(true);
  let selMesh=null, selLayer=0;
  function circleLayer(list){
    const grp=new THREE.Group(); grp.userData.items=[];
    const m0=makeCircleMat(); grp.userData.mat=m0;
    const mmax=list.reduce((m,c)=>Math.max(m,c[3]),2);
    list.forEach((c,i)=>{
      const r=0.006+0.055*Math.cbrt(c[3]/mmax);
      const m=new THREE.Mesh(new THREE.PlaneGeometry(2*r,2*r),m0);
      const v=llv(c[0],c[1],1);
      m.position.copy(v).multiplyScalar(R*1.006);
      m.quaternion.setFromUnitVectors(new THREE.Vector3(0,0,1),v);
      m.userData={label:c[2],n:c[3],years:c[4]||[],members:c[5]||[],cur:0,r:r};
      m.scale.setScalar(0.0001);
      grp.add(m); grp.userData.items.push(m);
    });
    globe.add(grp); return grp;
  }
  // the pyramid: level 0 coarsest .. level 4 = every city; zoom morphs down it
  const layers=LEVELS.map(circleLayer);
  const ANCH=[6.0,4.0,2.9,2.2,1.7];          // camDist where each level is in full focus
  function pyramidDepth(d){
    if(d>=ANCH[0]) return 0;
    if(d<=ANCH[ANCH.length-1]) return ANCH.length-1;
    for(let i=0;i<ANCH.length-1;i++){
      if(d<=ANCH[i]&&d>=ANCH[i+1]) return i+(ANCH[i]-d)/(ANCH[i]-ANCH[i+1]); }
    return 0; }

  // ---- chrome ---------------------------------------------------------------
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
    '.hrow2{display:flex;align-items:center;gap:7px;color:#b9c8e2;font-size:13px;white-space:nowrap}'+
    '.hrow2+.hrow2{margin-top:10px}'+
    '.hrow2 input[type=range]{flex:1;min-width:56px}'+
    '#hud input[type=range]{vertical-align:middle;-webkit-appearance:none;appearance:none;height:22px;background:transparent}'+
    '#hud input[type=range]::-webkit-slider-runnable-track{height:4px;border-radius:2px;background:linear-gradient(90deg,rgba(242,193,78,.5),rgba(143,163,200,.25))}'+
    '#hud input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:16px;height:16px;border-radius:50%;background:#f2c14e;margin-top:-6px;box-shadow:0 0 8px rgba(242,193,78,.5)}'+
    '#hud input[type=range]::-moz-range-track{height:4px;border-radius:2px;background:rgba(143,163,200,.3)}'+
    '#hud input[type=range]::-moz-range-thumb{width:16px;height:16px;border:none;border-radius:50%;background:#f2c14e}'+
    '#hint{display:block;color:#93a6c6;font-size:12px;opacity:.85;transition:opacity 1.2s ease;margin-left:4px}'+
    '#yr{font-size:26px;color:#f2c14e;margin:2px 0 0 4px}'+
    '.btn{font:inherit;font-size:13px;color:#f2c14e;background:linear-gradient(180deg,rgba(242,193,78,.16),rgba(242,193,78,.07));border:1px solid rgba(242,193,78,.45);border-radius:999px;padding:4px 16px;cursor:pointer;letter-spacing:.06em;transition:transform .12s ease,box-shadow .12s ease}'+
    '.btn:hover{transform:translateY(-1px);box-shadow:0 4px 14px rgba(242,193,78,.18)}'+
    '.btn:active{transform:translateY(0)}'+
    '.hrowb{display:flex;margin-bottom:10px}'+
    '.hrowb .btn{flex:1;text-align:center}'+
    '#tlwrap{position:fixed;left:50%;transform:translateX(-50%);bottom:max(12px,env(safe-area-inset-bottom));width:min(1200px,94vw);z-index:9;background:linear-gradient(160deg,rgba(16,24,42,.72),rgba(8,13,24,.6));backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border:1px solid rgba(143,163,200,.16);border-radius:12px;box-shadow:0 10px 34px rgba(0,0,0,.45);padding:5px 10px}'+
    '#tl{display:block;width:100%;height:44px;cursor:crosshair}'+
    '#chip{position:fixed;left:max(14px,env(safe-area-inset-left));bottom:calc(max(12px,env(safe-area-inset-bottom)) + 76px);z-index:10;max-width:min(320px,calc(100vw - 28px));font:15px/1.5 Georgia,serif;color:#dce8f8;background:linear-gradient(160deg,rgba(16,24,42,.85),rgba(8,13,24,.72));backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);padding:10px 16px;border-radius:12px;border:1px solid rgba(242,193,78,.22);box-shadow:0 10px 34px rgba(0,0,0,.5);display:none}'+
    '#chip b{color:#f2c14e;font-weight:normal;font-size:17px}'+
    '#chip .n{color:#93a6c6;font-size:13px}';
  document.head.appendChild(css);
  document.body.insertAdjacentHTML('beforeend',
    '<div id="veil"><div class="t">la red</div><div class="bar"></div><div class="s">cargando la red\\u2026</div></div><div id="vig"></div>');
  const col=document.createElement('div');
  col.id='panelcol';
  col.innerHTML='<div id="hud">'+
      '<div class="hrowb"><button class="btn" id="spd"></button></div>'+
      '<div class="hrow2"><span>umbral</span> <input id="thr" type="range" min="2" max="24" step="1" value="2"> <span id="thv" style="color:#f2c14e">2 viajeros</span></div>'+
      '<div class="hrow2"><span>giro</span> <input id="spin" type="range" min="0" max="3" step="0.25" value="0"> <span id="spv" style="color:#f2c14e">quieto</span>'+
      ' \\u00b7 <span id="obq">0.0\\u00b0</span></div>'+
    '</div>'+
    '<span id="yr"></span>'+
    '<span id="hint">toca un c\\u00edrculo para su nombre \\u00b7 espacio pausa \\u00b7 arrastra para girar \\u00b7 pellizca o rueda para acercar</span>';
  document.body.appendChild(col);
  const tlwrap=document.createElement('div'); tlwrap.id='tlwrap';
  const tl=document.createElement('canvas'); tl.id='tl'; tlwrap.appendChild(tl);
  document.body.appendChild(tlwrap);
  const chip=document.createElement('div'); chip.id='chip'; document.body.appendChild(chip);
  setTimeout(()=>{ const h=document.getElementById('hint'); if(h) h.style.opacity=0.35; },9000);

  // ---- the assembly clock (from the pulse): event-paced history ------------
  const NEvt=EVT.length;
  let now=0, playing=true, speed=120;
  const yrEl=document.getElementById('yr');
  function yearLabel(y){ return y<0? (Math.ceil(-y)+' a. C.') : (Math.floor(y)+''); }
  const spdBtn=document.getElementById('spd');
  const SPEEDS=[0,40,120,480], SPN={0:'detenida',40:'lento',120:'normal',480:'r\u00e1pido'};  // 0 = time stopped, scrub-only
  function setSpeed(v){ speed=v; spdBtn.textContent='velocidad \u00b7 '+SPN[v]; }
  spdBtn.addEventListener('click',()=>{ setSpeed(SPEEDS[(SPEEDS.indexOf(speed)+1)%SPEEDS.length]); });
  setSpeed(120);
  const ERAS=[-2000,-1000,0,500,1000,1300,1500,1700,1800,1850,1900,1950,2000];
  let hoverI=null, tlDown=false;
  function drawTL(cur){
    const dpr=devicePixelRatio;
    const w=tl.width=tl.clientWidth*dpr, h=tl.height=tl.clientHeight*dpr;
    const cx=tl.getContext('2d'); cx.clearRect(0,0,w,h);
    const grad=cx.createLinearGradient(0,h*0.18,0,h*0.58);
    grad.addColorStop(0,'rgba(143,216,244,0.95)'); grad.addColorStop(1,'rgba(90,169,230,0.55)');
    cx.fillStyle=grad;
    for(let x=0;x<w;x+=2){ const i=Math.floor(x/w*NEvt);
      const j=Math.min(NEvt-1,i+40);
      const span=EVT[j]-EVT[i];
      cx.fillRect(x, h*0.58, 1.4, -h*0.36*Math.min(1, span>0? 40/(NEvt*span/(EVT[NEvt-1]-EVT[0])):1)); }
    cx.font=(10.5*dpr)+'px Georgia';
    let lastEnd=-1e9;
    ERAS.forEach(Y=>{
      let i=0,j=NEvt-1; while(i<j){const m=(i+j)>>1; if(EVT[m]<Y)i=m+1;else j=m;}
      const x=i/NEvt*w; cx.fillStyle='rgba(143,163,200,0.5)'; cx.fillRect(x,h*0.62,1,h*0.12);
      const txt=yearLabel(Y), tw=cx.measureText(txt).width;
      if(x+3>lastEnd+10*dpr && x+3+tw<w){ cx.fillStyle='rgba(143,163,200,0.9)'; cx.fillText(txt,x+3,h*0.95); lastEnd=x+3+tw; } });
    if(hoverI!==null){
      const hx=hoverI/NEvt*w;
      cx.fillStyle='rgba(234,223,191,0.5)'; cx.fillRect(hx-0.5,0,1,h*0.62);
      const txt=yearLabel(EVT[Math.max(0,Math.min(NEvt-1,Math.floor(hoverI)))]);
      cx.font=(11*dpr)+'px Georgia'; const tw=cx.measureText(txt).width;
      cx.fillStyle='rgba(234,223,191,0.95)';
      cx.fillText(txt, Math.max(2,Math.min(w-tw-2,hx-tw/2)), h*0.16);
    }
    cx.save(); cx.shadowColor='rgba(242,193,78,0.9)'; cx.shadowBlur=7*dpr;
    cx.fillStyle='#f2c14e'; cx.fillRect(cur/NEvt*w-1.2*dpr,0,2.4*dpr,h*0.60); cx.restore();
  }
  function tlSeek(e){ const r=tl.getBoundingClientRect();
    now=Math.max(0,Math.min(NEvt-1,(e.clientX-r.left)/r.width*NEvt)); }
  tl.addEventListener('pointerdown',e=>{ tlDown=true; tl.setPointerCapture(e.pointerId); tlSeek(e); });
  tl.addEventListener('pointermove',e=>{ if(tlDown) tlSeek(e);
    const r=tl.getBoundingClientRect(); hoverI=Math.max(0,Math.min(NEvt-1,(e.clientX-r.left)/r.width*NEvt)); });
  tl.addEventListener('pointerup',e=>{ tlDown=false; });
  tl.addEventListener('pointerleave',e=>{ hoverI=null; });
  window.addEventListener('keydown',e=>{
    if(e.code==='Space'){e.preventDefault(); playing=!playing;}
    else if(e.key==='0')setSpeed(0); else if(e.key==='1')setSpeed(40); else if(e.key==='2')setSpeed(120); else if(e.key==='3')setSpeed(480);
    else if(e.key==='0'){now=0;} });
  function upperBound(arr,y){ let i=0,j=arr.length; while(i<j){const m=(i+j)>>1; if(arr[m]<=y)i=m+1;else j=m;} return i; }
  const corrCur=new Array(CORR.length).fill(-1);

  const thrEl=document.getElementById('thr'), thvEl=document.getElementById('thv');
  thrEl.addEventListener('input',()=>{ const v=parseInt(thrEl.value);
    mat.uniforms.uMin.value=v; thvEl.textContent=v+' viajeros'; });
  let spin=0;
  const spinEl=document.getElementById('spin'), spvEl=document.getElementById('spv');
  function setSpin(v){ spin=Math.max(0,Math.min(3,v)); spinEl.value=spin;
    spvEl.textContent=spin===0?'quieto':spin+' rpm'; }
  spinEl.addEventListener('input',()=>setSpin(parseFloat(spinEl.value)));

  const target=new THREE.Quaternion().setFromEuler(new THREE.Euler(0,-0.6,0));
  const dom=renderer.domElement;
  dom.style.touchAction='none';
  const ptrs=new Map();
  let pinchDist=null, userZoomed=false, downAt=null, downT=0, wasPinch=false;
  dom.addEventListener('pointerdown',e=>{ ptrs.set(e.pointerId,[e.clientX,e.clientY]); dom.setPointerCapture(e.pointerId);
    if(ptrs.size===2){ const [a,b]=[...ptrs.values()]; pinchDist=Math.hypot(a[0]-b[0],a[1]-b[1]); wasPinch=true; }
    else { downAt=[e.clientX,e.clientY]; downT=performance.now(); wasPinch=false; } });
  dom.addEventListener('pointermove',e=>{ const p=ptrs.get(e.pointerId); if(!p)return;
    const dx=e.clientX-p[0], dy=e.clientY-p[1]; ptrs.set(e.pointerId,[e.clientX,e.clientY]);
    if(ptrs.size===2){ const [a,b]=[...ptrs.values()]; const d=Math.hypot(a[0]-b[0],a[1]-b[1]);
      if(pinchDist && d>0){ camDist=Math.max(1.45,Math.min(8,camDist*pinchDist/d)); userZoomed=true; updateCam(); }
      pinchDist=d; return; }
    const dq=new THREE.Quaternion().setFromEuler(new THREE.Euler(dy*0.005,dx*0.005,0,'XYZ')); target.premultiply(dq); });
  const ray=new THREE.Raycaster(), ndc=new THREE.Vector2();
  const scrV=new THREE.Vector3();
  function setSelStrands(memberSet){
    let dirty=false;
    for(let i=0;i<CORR.length;i++){
      const on=memberSet && (memberSet.has(CORR[i][0])||memberSet.has(CORR[i][1])) ? 1:0;
      const [v0,cnt]=corrRange[i];
      if(hlBuf[v0]!==on){ for(let k=0;k<cnt;k++) hlBuf[v0+k]=on; dirty=true; } }
    if(dirty) hlAttr.needsUpdate=true; }
  function clearSel(){ if(selMesh){ selMesh.material=layers[selLayer].userData.mat; selMesh=null; setSelStrands(null); } }
  function identify(e){
    const r=dom.getBoundingClientRect();
    ndc.set(((e.clientX-r.left)/r.width)*2-1, -((e.clientY-r.top)/r.height)*2+1);
    ray.setFromCamera(ndc,camera);
    let bi=0,bf=-1;
    layers.forEach((g,i)=>{ const f=g.userData.mat.uniforms.uFade.value;
      if(g.visible&&f>bf){ bf=f; bi=i; } });
    // clickable = every layer that is meaningfully faded in, not just the top one:
    // a city inside a merged region stays selectable, smallest circle under the
    // pointer wins (Prague vs the blob that swallowed it).
    const active=[];
    layers.forEach(g=>{ const f=g.userData.mat.uniforms.uFade.value;
      if(g.visible&&f>0.15) active.push(g); });
    if(!active.length) active.push(layers[bi]);
    let pick=null;
    for(const g of active) for(const h of ray.intersectObjects(g.children,false)){
      const m=h.object; if(m.userData.cur<=0.01) continue;
      if(!pick||(m.userData.r||1)*m.scale.x<(pick.userData.r||1)*pick.scale.x) pick=m;
    }
    if(!pick){                                   // fingertip fallback: nearest visible circle within 24 px
      let bd=24*24;
      for(const m of active.flatMap(g=>g.userData.items)){
        if(m.userData.cur<=0.01) continue;
        scrV.setFromMatrixPosition(m.matrixWorld);
        if(scrV.clone().sub(camera.position).dot(scrV)>0) continue;   // back side of the globe
        scrV.project(camera);
        const sx=(scrV.x+1)/2*r.width, sy=(1-scrV.y)/2*r.height;
        const d2=(sx-(e.clientX-r.left))**2+(sy-(e.clientY-r.top))**2;
        if(d2<bd){ bd=d2; pick=m; } }
    }
    clearSel();
    if(!pick){ chip.style.display='none'; return; }
    selMesh=pick; selLayer=Math.max(0,layers.indexOf(pick.parent)); pick.material=selMat;
    const u=pick.userData;
    setSelStrands(new Set(u.members||[]));
    chip.innerHTML='<b>'+u.label+'</b><br><span class="n">'+u.n+(u.n===1?' viajero':' viajeros')+'</span>';
    chip.style.display='block';
  }
  const release=e=>{
    const wasTap=!wasPinch && downAt && ptrs.size===1 &&
      Math.hypot(e.clientX-downAt[0],e.clientY-downAt[1])<6 && (performance.now()-downT)<400;
    ptrs.delete(e.pointerId); if(ptrs.size<2)pinchDist=null;
    if(wasTap) identify(e); };
  dom.addEventListener('pointerup',release); dom.addEventListener('pointercancel',e=>{ptrs.delete(e.pointerId); if(ptrs.size<2)pinchDist=null;});
  dom.addEventListener('wheel',e=>{e.preventDefault(); userZoomed=true; camDist=Math.max(1.45,Math.min(8,camDist*Math.exp(e.deltaY*0.001))); updateCam();},{passive:false});
  function fitDist(aspect){ const vhalf=42/2*Math.PI/180, hhalf=Math.atan(Math.tan(vhalf)*aspect);
    return 1.12/Math.sin(Math.min(vhalf,hhalf)); }
  function resize(){ const w=stage.clientWidth,h=stage.clientHeight; renderer.setSize(w,h); camera.aspect=w/h; camera.updateProjectionMatrix();
    if(!userZoomed){ camDist=Math.max(2.7,fitDist(w/h)); }
    updateCam(); }
  window.addEventListener('resize',resize); resize(); updateCam();

  const veil=document.getElementById('veil');
  let veilGone=false, lastT=performance.now();
  const spinQ=new THREE.Quaternion(), yAxis=new THREE.Vector3(0,1,0);
  const obqEl=document.getElementById('obq'), axW=new THREE.Vector3();
  let obShown=-1;
  function trackObliquity(){
    axW.set(0,1,0).applyQuaternion(globe.quaternion)
       .transformDirection(camera.matrixWorldInverse);   // view space: dotted with the screen vertical
    const ob=Math.acos(Math.min(1,Math.max(-1,axW.y)))*180/Math.PI;
    if(Math.abs(ob-obShown)<0.05) return;
    obShown=ob;
    const earth=Math.abs(ob-23.44)<=0.5;
    obqEl.textContent=ob.toFixed(1)+'\\u00b0'+(earth?' \\u2295':'');
    obqEl.style.color=earth?'#f2c14e':'#dce8f8';
  }
  (function animate(){ requestAnimationFrame(animate);
    const t=performance.now(), dt=(t-lastT)/1000; lastT=t;
    if(spin!==0){ spinQ.setFromAxisAngle(yAxis, spin*2*Math.PI/60*dt); target.multiply(spinQ); }
    if(playing) now=Math.min(NEvt-1+120, now+speed*dt);
    const yi=Math.max(0,Math.min(NEvt-1,Math.floor(now)));
    const year=EVT[yi];
    yrEl.textContent=yearLabel(year);
    drawTL(Math.min(now,NEvt-1));
    // corridors accumulate travelers as history passes
    let dirty=false;
    for(let i=0;i<CORR.length;i++){
      const wNow=upperBound(CORR[i][3],year);
      if(wNow!==corrCur[i]){ corrCur[i]=wNow;
        const [v0,cnt]=corrRange[i];
        for(let k=0;k<cnt;k++) wBuf[v0+k]=wNow;
        dirty=true; } }
    if(dirty) wAttr.needsUpdate=true;
    // circles swell as their travelers arrive
    const grow=(grp)=>{ for(const m of grp.userData.items){
      const u=m.userData;
      const wNow=upperBound(u.years,year);
      const tgt=wNow>0?Math.cbrt(wNow/u.n):0.0001;
      u.cur+=(tgt-u.cur)*Math.min(1,dt*4);
      m.scale.setScalar(Math.max(0.0001,u.cur)); } };
    const depth=pyramidDepth(camDist);
    layers.forEach((g,i)=>{ const fade=Math.max(0,1-Math.abs(depth-i));
      g.userData.mat.uniforms.uFade.value=fade;
      g.visible=fade>0.02;
      if(g.visible) grow(g); });
    if(selMesh){ const f=layers[selLayer].userData.mat.uniforms.uFade.value;
      selMat.uniforms.uFade.value=f;
      if(f<0.03){ clearSel(); chip.style.display='none'; } }
    mat.uniforms.uT.value=(t/1000/2.0)%1;          // one corridor traversal per 2 s
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
    f.write('<title>la red — Colegio Invisible</title>\n')
    f.write(head)
    f.write('\n<script>\nconst CITY = ' + json.dumps(CITY_JS, ensure_ascii=False, separators=(',', ':')) + ';\n')
    f.write('const LEVELS = ' + json.dumps(LEVELS, ensure_ascii=False, separators=(',', ':')) + ';\n')
    f.write('const CORR = ' + json.dumps(CORR, separators=(',', ':')) + ';\n')
    f.write('const COAST = ' + json.dumps(coast_lines, separators=(',', ':')) + ';\n')
    f.write('const EVT = ' + json.dumps(EVT, separators=(',', ':')) + ';\n</script>\n')
    f.write(app)
print(f"wrote {OUT} ({os.path.getsize(OUT)//1024} KB)")
