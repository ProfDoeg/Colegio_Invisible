#!/usr/bin/env python3
"""Build quipu_out/<slug>_network.html — a network on the atlas globe.

Same planet and same navigation as the journey atlas: joan_globe.html is the
donor (CSS, HTML skeleton, inlined three.js, all byte-verbatim), the coastline
comes from the same heal_earth land-50m topojson, and the globe is the same
translucent shell so chords through the planet read.

What differs is what is drawn on it. A network is not a path:

  - nodes WITH coordinates are pinned to the surface at their lat/lng
  - nodes WITHOUT coordinates (agents, corps, crowns: things with no fixed
    locus) are free, and every frame they are pulled toward the mean of the
    neighbours their edges reach
  - because those neighbours are pinned ON the sphere, the mean of them lies
    INSIDE it. Nobody positions the placeless members. The edges do it, and
    they migrate inward on their own. That is the whole reason the shell is
    glass.

  python3 build_network_globe.py templar.network.json
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
JOURNEYS = os.path.join(HERE, '..', 'journeys')
OUT_DIR = os.path.join(JOURNEYS, 'quipu_out')
DONOR = os.path.join(OUT_DIR, 'joan_globe.html')
HEAL = os.path.join(HERE, '..', 'heal_earth')

ETYPE_NAME = {0: 'road', 1: 'sea_lane', 2: 'river', 3: 'wire',
              4: 'relay', 5: 'credit', 6: 'kinship', 7: 'uncertain'}
ETYPE_BYTE = {v: k for k, v in ETYPE_NAME.items()}
# the corpus palette, so a network looks like the rest of the work
ETYPE_COLOR = {'road': 0xc2a76b, 'sea_lane': 0x3f7fb5, 'river': 0x2a7a4d,
               'wire': 0x6faed9, 'relay': 0xe8b73a, 'credit': 0xc83727,
               'kinship': 0x6e3a8a, 'uncertain': 0x8a8f99}
NTYPE_COLOR = {'place': 0xe8b73a, 'agent': 0xf2c14e,
               'relay': 0x6faed9, 'resource': 0x37c2a8}


def build(path):
    ds = json.load(open(path, encoding='utf-8'))
    slug = ds.get('slug') or os.path.basename(path).split('.')[0]

    index = {n['name']: i for i, n in enumerate(ds['nodes'])}
    nodes = []
    for n in ds['nodes']:
        nodes.append({
            'n': n['name'],
            'k': n.get('ntype', 'place'),
            'lat': n.get('lat'),
            'lng': n.get('lng'),
            'abstract': n.get('lat') is None,
            'b': n.get('born'),
            'd': n.get('died'),
            'r': n.get('region', ''),
            'm': n.get('modern', ''),
            'note': n.get('note', ''),
        })
    edges = []
    for e in ds['edges']:
        a, b = index.get(e['from']), index.get(e['to'])
        if a is None or b is None:
            raise SystemExit('edge endpoint not among nodes: %r -> %r'
                             % (e['from'], e['to']))
        edges.append({'a': a, 'b': b, 'e': e.get('etype', 'road'),
                      'w': e.get('weight'), 'note': e.get('note', '')})

    net = {
        'title': ds.get('network') or ds.get('title'),
        'sub': ds.get('title', ''),
        'years': ds.get('years', ''),
        'summary': ds.get('summary', ''),
        'nodes': nodes,
        'edges': edges,
        'ecolor': {k: '#%06x' % v for k, v in ETYPE_COLOR.items()},
        'ncolor': {k: '#%06x' % v for k, v in NTYPE_COLOR.items()},
    }

    # ---- donor: css + skeleton + inlined three.js, verbatim ----------------
    raw = open(DONOR, encoding='utf-8').read()
    three_start = raw.find('<script>/**')
    assert three_start > 0, 'donor structure changed'
    three_end = raw.find('</script>', three_start) + len('</script>')
    head = raw[:three_end]

    head = head.replace(
        '<div id="hint">' + head.split('<div id="hint">')[1].split('</div>')[0] + '</div>',
        '<div id="hint"><b>&larr;/&rarr;</b> node &nbsp;&middot;&nbsp; '
        '<b>A</b> next placeless &nbsp;&middot;&nbsp; drag to turn '
        '&nbsp;&middot;&nbsp; scroll to zoom &nbsp;&middot;&nbsp; click a node</div>', 1)
    # the donor may carry no <title> at all; only rewrite one that exists
    if '<title>' in head and '</title>' in head:
        old_title = head.split('<title>')[1].split('</title>')[0]
        head = head.replace('<title>' + old_title + '</title>',
                            '<title>' + net['title'] + '</title>', 1)
    elif '<head>' in head:
        head = head.replace('<head>', '<head><title>' + net['title'] + '</title>', 1)

    # ---- coastline: same source as the atlas -------------------------------
    topo = json.load(open(os.path.join(HEAL, 'land-50m.json')))
    sc, tr = topo['transform']['scale'], topo['transform']['translate']
    coast_lines = []
    for arc in topo['arcs']:
        x = y = 0
        pts = []
        for dx, dy in arc:
            x += dx
            y += dy
            pts.append([round(x * sc[0] + tr[0], 3), round(y * sc[1] + tr[1], 3)])
        if len(pts) > 1:
            coast_lines.append(pts)
    lakes = json.load(open(os.path.join(HEAL, 'lakes_journey.geojson')))
    lake_lines = []
    for feat in lakes['features']:
        for ring in feat['geometry']['coordinates']:
            lake_lines.append([[round(p[0], 4), round(p[1], 4)] for p in ring])

    data = ('const COAST = ' + json.dumps(coast_lines, separators=(',', ':')) + ';\n'
            'const LAKES = ' + json.dumps(lake_lines, separators=(',', ':')) + ';\n'
            'const NET = ' + json.dumps(net, separators=(',', ':'), ensure_ascii=False) + ';')

    html = ('<!doctype html><meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width,initial-scale=1,'
            'viewport-fit=cover">\n'
            + head + '\n<script>\n' + data + '\n' + APP + '\n</script>\n</body></html>\n')
    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, slug + '_network.html')
    with open(out, 'w', encoding='utf-8') as f:
        f.write(html)

    n_abs = sum(1 for n in nodes if n['abstract'])
    print('%s: %d nodes (%d placed, %d placeless), %d edges'
          % (net['title'], len(nodes), len(nodes) - n_abs, n_abs, len(edges)))
    print('coast arcs: %d, lake rings: %d' % (len(coast_lines), len(lake_lines)))
    print('wrote %s (%d KB)' % (out, len(html) // 1024))
    return out


APP = r"""
(function(){
  const THREE = window.THREE, R = 1.0;
  const stage = document.getElementById('stage');
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
  // the same translucent shell as the atlas: the interior stays visible, which
  // is what lets the placeless members be seen at all
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

  // ---- the nodes ---------------------------------------------------------
  const N = NET.nodes, E = NET.edges;
  const POS = N.map(n => n.abstract
    ? new THREE.Vector3((Math.random()-.5)*.25,(Math.random()-.5)*.25,(Math.random()-.5)*.25)
    : llv(n.lat,n.lng,R*1.012));
  const NBR = N.map(()=>[]);
  E.forEach(e=>{ NBR[e.a].push(e.b); NBR[e.b].push(e.a); });
  const FREE = [];
  N.forEach((n,i)=>{ if(n.abstract) FREE.push(i); });

  // Nobody places the placeless. Their edges do: each is drawn to the mean of
  // its neighbours, and since those are pinned on the surface, the mean lies
  // inside the sphere. They migrate in on their own and settle.
  const INWARD = 0.55;   // how far out from the centre a placeless member rests
  function relax(dt){
    const rate = Math.min(1, dt*1.6);
    for(const i of FREE){
      const p=POS[i], nb=NBR[i];
      if(!nb.length) continue;
      let cx=0,cy=0,cz=0;
      for(const j of nb){ const q=POS[j]; cx+=q.x; cy+=q.y; cz+=q.z; }
      cx/=nb.length; cy/=nb.length; cz/=nb.length;
      // A member with a SINGLE link would otherwise converge exactly onto its
      // neighbour and sit on the surface, which is the one thing it is not.
      // Having no locus is itself a pull inward, so the rest position is a
      // fraction of the way out from the centre toward what holds it.
      cx*=INWARD; cy*=INWARD; cz*=INWARD;
      // keep several placeless members from stacking on one another
      for(const j of FREE){ if(j===i) continue; const q=POS[j];
        const dx=p.x-q.x, dy=p.y-q.y, dz=p.z-q.z;
        const d=Math.sqrt(dx*dx+dy*dy+dz*dz)||1e-3;
        if(d<0.30){ const k=(0.30-d)/d*0.55; cx+=dx*k; cy+=dy*k; cz+=dz*k; }
      }
      p.x+=(cx-p.x)*rate; p.y+=(cy-p.y)*rate; p.z+=(cz-p.z)*rate;
    }
  }

  // ---- edges: rebuilt each frame, because the free ends keep moving -------
  const eseg=new Float32Array(E.length*6), ecol=new Float32Array(E.length*6);
  E.forEach((e,i)=>{ const c=new THREE.Color(NET.ecolor[e.e]||'#8a8f99');
    for(const o of [0,3]){ ecol[i*6+o]=c.r; ecol[i*6+o+1]=c.g; ecol[i*6+o+2]=c.b; } });
  const eg=new THREE.BufferGeometry();
  eg.setAttribute('position',new THREE.BufferAttribute(eseg,3));
  eg.setAttribute('color',new THREE.BufferAttribute(ecol,3));
  globe.add(new THREE.LineSegments(eg,new THREE.LineBasicMaterial({
    vertexColors:true,transparent:true,opacity:0.85})));
  function syncEdges(){
    for(let i=0;i<E.length;i++){ const a=POS[E[i].a], b=POS[E[i].b];
      eseg[i*6]=a.x; eseg[i*6+1]=a.y; eseg[i*6+2]=a.z;
      eseg[i*6+3]=b.x; eseg[i*6+4]=b.y; eseg[i*6+5]=b.z; }
    eg.attributes.position.needsUpdate=true;
  }

  // ---- node bodies -------------------------------------------------------
  const balls=[];
  const geoPlaced=new THREE.SphereGeometry(0.0125,16,16);
  const geoFree=new THREE.SphereGeometry(0.019,18,18);
  N.forEach((n,i)=>{
    const col=new THREE.Color(NET.ncolor[n.k]||'#e8b73a');
    const m=new THREE.Mesh(n.abstract?geoFree:geoPlaced,
      new THREE.MeshBasicMaterial({color:col}));
    m.position.copy(POS[i]); m.userData.i=i; globe.add(m); balls.push(m);
    if(n.abstract){   // a faint halo, so a placeless member reads through the shell
      const h=new THREE.Mesh(new THREE.SphereGeometry(0.032,16,16),
        new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:0.16,depthWrite:false}));
      m.add(h);
    }
  });
  const marker=new THREE.Group();
  const ring=new THREE.Mesh(new THREE.RingGeometry(0.030,0.040,28),
    new THREE.MeshBasicMaterial({color:0xf2c14e,side:THREE.DoubleSide,transparent:true,opacity:0.9}));
  marker.add(ring); globe.add(marker);

  // ---- panel -------------------------------------------------------------
  const $=s=>document.querySelector(s);
  function esc(t){ const d=document.createElement('div'); d.textContent=t; return d.innerHTML; }
  function span(n){
    const y=v=>v==null?null:(v<0?Math.round(-v)+' BCE':String(Math.round(v)));
    const a=y(n.b), b=y(n.d);
    if(a&&b) return a+' to '+b;
    if(a) return 'from '+a;
    if(b) return 'until '+b;
    return '';
  }
  $('#titlebar h1').textContent=NET.title;
  $('#titlebar p').textContent=(NET.years?NET.years+' · ':'')+(NET.sub||'');

  let idx=-1;
  let target=new THREE.Quaternion();
  function faceNode(i){
    const v=POS[i].clone(); if(v.lengthSq()<1e-6) return;
    target=new THREE.Quaternion().setFromUnitVectors(v.normalize(),D0);
  }
  function setIndex(i){
    idx=(i+N.length)%N.length;
    const n=N[idx];
    const deg=NBR[idx].length;
    $('#counter').innerHTML='NODE '+(idx+1)+' / '+N.length+'  ·  '+deg+' LINK'+(deg===1?'':'S');
    $('#chip .dot').style.background=NET.ncolor[n.k]||'#e8b73a';
    $('#chip .segname').textContent=n.abstract?(n.k+' · no fixed locus'):n.k;
    $('#place').textContent=n.n;
    $('#date').textContent=span(n);
    const bits=[];
    if(n.note) bits.push(n.note);
    if(n.r) bits.push('Region: '+n.r+'.');
    if(n.m) bits.push('Today: '+n.m+'.');
    $('#campa').textContent=bits.join('\n');
    $('#campa').style.whiteSpace='pre-line';
    const links=NBR[idx].map((j,q)=>{
      const e=E.find(x=>(x.a===idx&&x.b===j)||(x.b===idx&&x.a===j));
      return '<span style="color:'+(NET.ecolor[e?e.e:'']||'#8a8f99')+'">'
        +esc(e?e.e:'?')+'</span> '+esc(N[j].n);
    });
    const q=$('#quote');
    if(links.length){ q.hidden=false; q.innerHTML=links.join('<br>'); } else q.hidden=true;
    const pr=$('#prog i'); if(pr) pr.style.width=(100*(idx+1)/N.length)+'%';
    faceNode(idx);
  }

  // ---- controls: the atlas's, verbatim in behaviour -----------------------
  const dom=renderer.domElement;
  let dragged=false;
  const ptrs=new Map();
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
    const rc=new THREE.Raycaster(); rc.params.Points={threshold:0.02};
    rc.setFromCamera(m,camera); const h=rc.intersectObjects(balls);
    if(h.length) setIndex(h[0].object.userData.i); });
  dom.addEventListener('wheel',e=>{e.preventDefault(); camDist=Math.max(1.45,Math.min(6,camDist*Math.exp(e.deltaY*0.001))); updateCam();},{passive:false});
  window.addEventListener('keydown',e=>{
    const k=e.code||e.key;
    if(k==='ArrowRight'){e.preventDefault(); setIndex(idx+1);}
    else if(k==='ArrowLeft'){e.preventDefault(); setIndex(idx-1);}
    else if(k==='KeyA'){e.preventDefault();          // jump to the next placeless member
      if(FREE.length){ const at=FREE.indexOf(idx);
        setIndex(FREE[(at+1+FREE.length)%FREE.length]); }}
  });
  const bind=(id,fn)=>{ const b=document.getElementById(id); if(b) b.onclick=fn; };
  bind('prev',()=>setIndex(idx-1));
  bind('next',()=>setIndex(idx+1));
  bind('play',()=>{ if(FREE.length) setIndex(FREE[0]); });
  bind('reset',()=>{ camDist=2.7; updateCam(); target=new THREE.Quaternion(); });
  const pl=document.getElementById('play'); if(pl) pl.textContent='Placeless';

  function resize(){ const w=stage.clientWidth,h=stage.clientHeight;
    renderer.setSize(w,h); camera.aspect=w/h; camera.updateProjectionMatrix(); }
  window.addEventListener('resize',resize); resize(); updateCam();

  let lastT=performance.now();
  (function animate(){ requestAnimationFrame(animate);
    const now=performance.now(), dt=Math.min(0.05,(now-lastT)/1000); lastT=now;
    relax(dt);
    for(let i=0;i<balls.length;i++) balls[i].position.copy(POS[i]);
    syncEdges();
    globe.quaternion.slerp(target,1-Math.pow(0.91,Math.max(1,dt*60)));
    if(idx>=0){ marker.position.copy(POS[idx]); ring.quaternion.copy(camera.quaternion); }
    renderer.render(scene,camera); })();

  setIndex(0);
})();
"""


if __name__ == '__main__':
    args = [a for a in sys.argv[1:] if not a.startswith('-')]
    if not args:
        args = ['templar.network.json']
    for a in args:
        build(a if os.path.isabs(a) else os.path.join(HERE, a))
