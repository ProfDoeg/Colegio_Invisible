#!/usr/bin/env python3
"""build_atlas2.py — the second atlas: every network on one globe.

The first atlas puts 153 journeys on a globe; this puts the networks on the same
globe, built the same way and steered the same way. A journey is a path through
places. A network is the graph the paths live in, so the two atlases are the
same world seen twice.

  Up/Down    swap network
  Left/Right step through the selected network's members
  A          jump to the next placeless member
  drag/scroll/pinch as the first atlas

All networks are drawn at once, dim and each in its own colour, so the eras
overlay: an Inca road and a Chilean telex line are on the same sphere. The
selected one comes up bright and coloured by link type.

Placeless members are not placed by arithmetic. They are pulled by their edges
each frame; since everything they attach to is pinned on the surface, they
settle inside the shell on their own.
"""
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
JOURNEYS = os.path.join(HERE, '..', 'journeys')
OUT_DIR = os.path.join(JOURNEYS, 'quipu_out')
DONOR = os.path.join(OUT_DIR, 'joan_globe.html')
HEAL = os.path.join(HERE, '..', 'heal_earth')
OUT = os.path.join(OUT_DIR, 'atlas2.html')

ETYPE_COLOR = {'road': '#c2a76b', 'sea_lane': '#3f7fb5', 'river': '#2a7a4d',
               'wire': '#6faed9', 'relay': '#e8b73a', 'credit': '#c83727',
               'kinship': '#6e3a8a', 'uncertain': '#8a8f99'}
NTYPE_COLOR = {'place': '#e8b73a', 'agent': '#f2c14e',
               'relay': '#6faed9', 'resource': '#2a7a4d'}
# one hue per network, for the dim all-at-once layer
NET_COLOR = ['#f2c14e', '#5aa9e6', '#37c2a8', '#e86a92', '#9b8cff', '#f08a4b',
             '#7bd389', '#d98cb3', '#6fc3df', '#c9a15a', '#b583d6', '#64b6ac',
             '#dd7373', '#a3c46a', '#e0b153', '#8fa3c8']


def load(path):
    ds = json.load(open(path, encoding='utf-8'))
    index = {n['name']: i for i, n in enumerate(ds['nodes'])}
    nodes = [{'n': n['name'], 'k': n.get('ntype', 'place'),
              'lat': n.get('lat'), 'lng': n.get('lng'),
              'abstract': n.get('lat') is None,
              'b': n.get('born'), 'd': n.get('died'),
              'r': n.get('region', ''), 'm': n.get('modern', ''),
              'note': n.get('note', '')} for n in ds['nodes']]
    edges = []
    for e in ds['edges']:
        a, b = index.get(e['from']), index.get(e['to'])
        if a is None or b is None:
            raise SystemExit('%s: edge endpoint not among nodes: %r -> %r'
                             % (os.path.basename(path), e['from'], e['to']))
        edges.append({'a': a, 'b': b, 'e': e.get('etype', 'road'),
                      'note': e.get('note', '')})
    return {'title': ds.get('network') or ds.get('title'),
            'sub': ds.get('title', ''), 'years': ds.get('years', ''),
            'summary': ds.get('summary', ''),
            'from': (ds.get('period') or {}).get('from'),
            'nodes': nodes, 'edges': edges}


def main():
    paths = sorted(glob.glob(os.path.join(HERE, '*.network.json')))
    if not paths:
        raise SystemExit('no *.network.json found')
    nets = [load(p) for p in paths]
    nets.sort(key=lambda n: n['from'] if n['from'] is not None else 0)
    for i, n in enumerate(nets):
        n['color'] = NET_COLOR[i % len(NET_COLOR)]
    total_n = sum(len(n['nodes']) for n in nets)
    total_e = sum(len(n['edges']) for n in nets)
    print('%d networks, %d nodes, %d edges' % (len(nets), total_n, total_e))
    for n in nets:
        print('   %-26s %-14s %3d nodes %3d edges'
              % (n['title'][:26], n['years'], len(n['nodes']), len(n['edges'])))

    raw = open(DONOR, encoding='utf-8').read()
    three_start = raw.find('<script>/**')
    three_end = raw.find('</script>', three_start) + len('</script>')
    if three_start < 0:
        raise SystemExit('donor structure changed')
    head = raw[:three_end]
    head = head.replace(
        '<div id="hint">' + head.split('<div id="hint">')[1].split('</div>')[0] + '</div>',
        '<div id="hint"><b>&uarr;/&darr;</b> network &nbsp;&middot;&nbsp; '
        '<b>&larr;/&rarr;</b> member &nbsp;&middot;&nbsp; <b>A</b> next placeless '
        '&nbsp;&middot;&nbsp; drag to turn &nbsp;&middot;&nbsp; scroll to zoom</div>', 1)

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
    print('coast arcs: %d, lake rings: %d' % (len(coast_lines), len(lake_lines)))

    data = ('const COAST = ' + json.dumps(coast_lines, separators=(',', ':')) + ';\n'
            'const LAKES = ' + json.dumps(lake_lines, separators=(',', ':')) + ';\n'
            'const NETS = ' + json.dumps(nets, separators=(',', ':'),
                                         ensure_ascii=False) + ';\n'
            'const ECOLOR = ' + json.dumps(ETYPE_COLOR) + ';\n'
            'const NCOLOR = ' + json.dumps(NTYPE_COLOR) + ';')

    # The donor slice begins at <style> and carries no doctype or charset, so we
    # must emit them or every en-dash arrives as mojibake.
    html = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<title>Atlas II &middot; the networks</title>'
            + head + '\n<script>' + data + '</script>\n<script>' + APP + '</script>\n')
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write(html)
    print('wrote %s (%d KB)' % (OUT, os.path.getsize(OUT) // 1024))


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
  (function(){ const g=new THREE.BufferGeometry(), M=1400, a=new Float32Array(M*3);
    for(let i=0;i<M;i++){ const v=new THREE.Vector3(Math.random()-.5,Math.random()-.5,Math.random()-.5).normalize().multiplyScalar(60+Math.random()*40);
      a[i*3]=v.x;a[i*3+1]=v.y;a[i*3+2]=v.z; }
    g.setAttribute('position',new THREE.BufferAttribute(a,3));
    scene.add(new THREE.Points(g,new THREE.PointsMaterial({color:0x8fa3c8,size:0.05,sizeAttenuation:true,transparent:true,opacity:0.7}))); })();

  const globe=new THREE.Group(); scene.add(globe);
  // the atlas's own translucent shell — it is what lets the interior read
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

  // ---- every network gets positions; placeless members get physics --------
  const SURF = R*1.012, INWARD = 0.55;
  NETS.forEach(net=>{
    net.POS = net.nodes.map(n => n.abstract
      ? new THREE.Vector3((Math.random()-.5)*.3,(Math.random()-.5)*.3,(Math.random()-.5)*.3)
      : llv(n.lat,n.lng,SURF));
    net.free = [];
    net.nodes.forEach((n,i)=>{ if(n.abstract) net.free.push({i:i, nbr:[]}); });
    const byI = {}; net.free.forEach(f=>byI[f.i]=f);
    net.edges.forEach(e=>{ if(byI[e.a]) byI[e.a].nbr.push(e.b);
                           if(byI[e.b]) byI[e.b].nbr.push(e.a); });
  });
  // A placeless member is drawn toward the mean of whatever it links to. Those
  // neighbours are pinned ON the sphere, so their mean lies INSIDE it and the
  // member migrates in by itself. A member with a single link would converge
  // exactly onto that neighbour and sit on the surface, so the rest target is
  // pulled toward the centre: having no locus is itself an inward force.
  function relax(dt){
    for(const net of NETS){
      for(const f of net.free){
        if(!f.nbr.length) continue;
        const t=new THREE.Vector3();
        for(const j of f.nbr) t.add(net.POS[j]);
        t.multiplyScalar(1/f.nbr.length).multiplyScalar(INWARD);
        for(const g of net.free){        // keep several of them apart
          if(g===f) continue;
          const d=new THREE.Vector3().subVectors(net.POS[f.i],net.POS[g.i]);
          const l=d.length();
          // a soft shove that fades to nothing at the separation distance,
          // rather than an inverse-square that spikes and rings
          if(l>1e-5 && l<0.13) t.addScaledVector(d.divideScalar(l), (0.13-l)*0.5);
        }
        // Move straight toward the rest point, no velocity. The neighbours are
        // PINNED, so the target barely moves; carrying momentum only made the
        // member overshoot it and swing back forever. Exponential smoothing is
        // critically damped by construction: it converges and then stops.
        net.POS[f.i].lerp(t, 1 - Math.pow(0.02, dt));
      }
    }
  }

  // ---- drawing -------------------------------------------------------------
  const dimGroup=new THREE.Group(); globe.add(dimGroup);
  const selGroup=new THREE.Group(); globe.add(selGroup);
  const dimLines=[], selLines=[];
  NETS.forEach((net,ni)=>{
    const g=new THREE.BufferGeometry();
    g.setAttribute('position',new THREE.BufferAttribute(new Float32Array(net.edges.length*6),3));
    const m=new THREE.LineBasicMaterial({color:new THREE.Color(net.color),transparent:true,opacity:0.13});
    const ls=new THREE.LineSegments(g,m); dimGroup.add(ls); dimLines.push({net:net,geo:g,mat:m});
  });
  let selSeg=null, balls=[], ringMarks=[];
  const bgeoP=new THREE.SphereGeometry(0.0060,14,14);   // placed member
  const bgeoA=new THREE.SphereGeometry(0.0130,16,16);   // placeless member
  let ti=0, idx=0;

  function refreshDim(){
    for(const d of dimLines){
      const arr=d.geo.attributes.position.array; let k=0;
      for(const e of d.net.edges){
        const A=d.net.POS[e.a], B=d.net.POS[e.b];
        arr[k++]=A.x;arr[k++]=A.y;arr[k++]=A.z; arr[k++]=B.x;arr[k++]=B.y;arr[k++]=B.z;
      }
      d.geo.attributes.position.needsUpdate=true;
      d.mat.opacity = (d.net===NETS[ti]) ? 0.0 : 0.13;   // selected drawn brightly below
    }
  }
  function buildSelected(){
    while(selGroup.children.length) selGroup.remove(selGroup.children[0]);
    balls=[]; ringMarks=[];
    const net=NETS[ti];
    const g=new THREE.BufferGeometry();
    g.setAttribute('position',new THREE.BufferAttribute(new Float32Array(net.edges.length*6),3));
    const cols=new Float32Array(net.edges.length*6);
    net.edges.forEach((e,i)=>{
      const c=new THREE.Color(ECOLOR[e.e]||'#8a8f99');
      for(let k=0;k<2;k++){ cols[i*6+k*3]=c.r; cols[i*6+k*3+1]=c.g; cols[i*6+k*3+2]=c.b; }
    });
    g.setAttribute('color',new THREE.BufferAttribute(cols,3));
    const m=new THREE.LineBasicMaterial({vertexColors:true,transparent:true,opacity:0.85});
    selSeg=new THREE.LineSegments(g,m); selGroup.add(selSeg);
    net.nodes.forEach((n,i)=>{
      const mm=new THREE.Mesh(n.abstract?bgeoA:bgeoP,
        new THREE.MeshBasicMaterial({color:new THREE.Color(NCOLOR[n.k]||'#e8b73a')}));
      mm.position.copy(net.POS[i]); mm.userData.i=i; selGroup.add(mm); balls.push(mm);
    });
    $('#titlebar h1').textContent=net.title;
    $('#titlebar p').textContent=(net.years?net.years+' · ':'')+net.sub
      +'  ·  network '+(ti+1)+' of '+NETS.length;
  }
  function refreshSelected(){
    const net=NETS[ti];
    const arr=selSeg.geometry.attributes.position.array; let k=0;
    for(const e of net.edges){
      const A=net.POS[e.a], B=net.POS[e.b];
      arr[k++]=A.x;arr[k++]=A.y;arr[k++]=A.z; arr[k++]=B.x;arr[k++]=B.y;arr[k++]=B.z;
    }
    selSeg.geometry.attributes.position.needsUpdate=true;
    net.nodes.forEach((n,i)=>{ if(balls[i]) balls[i].position.copy(net.POS[i]); });
  }

  const $=s=>document.querySelector(s);
  function esc(t){ const d=document.createElement('div'); d.textContent=t; return d.innerHTML; }
  function yrs(n){
    const y=v=>v==null?null:(v<0?Math.round(-v)+' BCE':''+Math.round(v));
    const a=y(n.b), b=y(n.d);
    if(a&&b) return a===b?a:a+' to '+b;
    if(a) return 'from '+a; if(b) return 'until '+b; return '';
  }
  let target=new THREE.Quaternion();
  function faceNode(i){
    const net=NETS[ti], p=net.POS[i].clone();
    if(p.lengthSq()<1e-6) return;
    target=new THREE.Quaternion().setFromUnitVectors(p.normalize(),D0);
  }
  function setIndex(i){
    const net=NETS[ti];
    idx=Math.max(0,Math.min(net.nodes.length-1,i));
    const n=net.nodes[idx];
    const links=net.edges.filter(e=>e.a===idx||e.b===idx);
    $('#counter').innerHTML='MEMBER '+(idx+1)+' / '+net.nodes.length
      +'  ·  '+links.length+' LINK'+(links.length===1?'':'S');
    $('#chip .dot').style.background=NCOLOR[n.k]||'#e8b73a';
    $('#chip .segname').textContent=n.abstract?(n.k+' · no fixed locus'):n.k;
    $('#place').textContent=n.n;
    $('#date').textContent=yrs(n);
    let body=n.note?esc(n.note):'';
    if(n.r) body+=(body?'<br>':'')+'<i>Region: '+esc(n.r)+'.</i>';
    if(n.m) body+=(body?'<br>':'')+'<i>Today: '+esc(n.m)+'.</i>';
    $('#campa').innerHTML=body;
    const q=$('#quote');
    if(links.length){
      q.hidden=false;
      q.innerHTML=links.slice(0,14).map(e=>{
        const o=(e.a===idx)?e.b:e.a;
        return '<div><span style="color:'+(ECOLOR[e.e]||'#8a8f99')+'">'+esc(e.e)
          +'</span> '+esc(net.nodes[o].n)+'</div>';}).join('')
        +(links.length>14?'<div class="src">and '+(links.length-14)+' more</div>':'');
    } else q.hidden=true;
    const pr=$('#prog i'); if(pr) pr.style.width=(100*(idx+1)/net.nodes.length)+'%';
    balls.forEach((b,i2)=>b.scale.setScalar(i2===idx?2.1:1));
    faceNode(idx);
  }
  function setNet(n){
    ti=(n+NETS.length)%NETS.length;
    buildSelected(); refreshDim(); setIndex(0);
    const ts=document.getElementById('nsel'); if(ts) ts.value=ti;
  }
  function nextAbstract(dir){
    const net=NETS[ti]; const n=net.nodes.length;
    for(let s=1;s<=n;s++){ const j=((idx+dir*s)%n+n)%n; if(net.nodes[j].abstract){ setIndex(j); return; } }
  }

  // ---- the network selector, as the first atlas has its traveller one -----
  (function(){
    const panel=document.getElementById('panel');
    const bar=document.createElement('div'); bar.id='travbar';
    bar.innerHTML='<button id="nprev">&uarr;</button>'
      +'<select id="nsel" aria-label="network"></select>'
      +'<button id="nnext">&darr;</button>';
    panel.insertBefore(bar,panel.firstChild);
    const sel=bar.querySelector('#nsel');
    NETS.forEach((n,i)=>{ const o=document.createElement('option');
      o.value=i; o.textContent=(i+1)+' · '+n.title+(n.years?' ('+n.years+')':'');
      sel.appendChild(o); });
    sel.onchange=e=>setNet(+e.target.value);
    bar.querySelector('#nprev').onclick=()=>setNet(ti-1);
    bar.querySelector('#nnext').onclick=()=>setNet(ti+1);
  })();

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
    const dq=new THREE.Quaternion().setFromEuler(new THREE.Euler(dy*0.005,dx*0.005,0,'XYZ'));
    target.premultiply(dq); });
  const release=e=>{ptrs.delete(e.pointerId);};
  dom.addEventListener('pointerup',release);
  dom.addEventListener('pointercancel',release);
  dom.addEventListener('click',e=>{ if(dragged)return; const r=dom.getBoundingClientRect();
    const m=new THREE.Vector2(((e.clientX-r.left)/r.width)*2-1, -((e.clientY-r.top)/r.height)*2+1);
    const rc=new THREE.Raycaster(); rc.params.Points={threshold:0.02};
    rc.setFromCamera(m,camera); const h=rc.intersectObjects(balls);
    if(h.length) setIndex(h[0].object.userData.i); });
  dom.addEventListener('wheel',e=>{e.preventDefault();
    camDist=Math.max(1.45,Math.min(6,camDist*Math.exp(e.deltaY*0.001))); updateCam();},{passive:false});
  window.addEventListener('keydown',e=>{
    const k=e.code||e.key;
    if(k==='ArrowRight'){e.preventDefault(); setIndex(idx+1);}
    else if(k==='ArrowLeft'){e.preventDefault(); setIndex(idx-1);}
    else if(k==='ArrowDown'){e.preventDefault(); setNet(ti+1);}
    else if(k==='ArrowUp'){e.preventDefault(); setNet(ti-1);}
    else if(k==='KeyA'){e.preventDefault(); nextAbstract(1);}
  });
  const bp=document.getElementById('prev'), bn=document.getElementById('next'),
        bpl=document.getElementById('play'), br=document.getElementById('reset');
  if(bp) bp.onclick=()=>setIndex(idx-1);
  if(bn) bn.onclick=()=>setIndex(idx+1);
  if(bpl){ bpl.textContent='Placeless'; bpl.onclick=()=>nextAbstract(1); }
  if(br) br.onclick=()=>{ camDist=2.7; updateCam(); target=new THREE.Quaternion(); };

  function resize(){ const w=stage.clientWidth||800, h=stage.clientHeight||600;
    renderer.setSize(w,h); camera.aspect=w/h; camera.updateProjectionMatrix(); }
  window.addEventListener('resize',resize); resize(); updateCam();

  setNet(0);
  let lastT=performance.now();
  (function animate(){ requestAnimationFrame(animate);
    const now=performance.now(), dt=Math.min(0.05,(now-lastT)/1000); lastT=now;
    relax(dt); refreshDim(); refreshSelected();
    globe.quaternion.slerp(target,1-Math.pow(0.91,Math.max(1,dt*60)));
    renderer.render(scene,camera); })();
})();
"""


if __name__ == '__main__':
    main()
