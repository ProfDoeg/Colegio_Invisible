#!/usr/bin/env python3
"""Build quipu_out/pulse_story.html — the pulse globe in story mode, for frame capture.

The EXACT page rendering of build_pulse_globe.py (same shader, additive
blending, starfield, ball, coast) reduced to what an Instagram story needs:
1080x1920 portrait composition, the earth tilted 23.5 degrees and turning
about its own axis at 1.25 rpm, the year alone in the upper left. No
interaction, no timeline, no controls. A deterministic window.__frame(i)
hook sets event-time, rotation and year for frame i and renders, so a
headless browser can screenshot the clip frame by frame
(render_pulse_story_web.py).

Timing: 30 fps, 50 s of history + 10 s holding on the finished map (60 s).
"""
import json, glob, os, math

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'quipu_out', 'pulse_story.html')
DONOR = os.path.join(HERE, 'quipu_out', 'joan_globe.html')

FPS = 30
HIST_S, HOLD_S = 50, 10
SPIN_RPM = 1.25
TILT_DEG = -23.5          # south pole toward the camera, as in render_story.py
PHASE0_DEG = 226          # open centered on Mesopotamia, where history starts


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
         'width:100vw!important;height:100vh!important}'
         'body{margin:0;background:#000}</style>')

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
  const FPS=%(fps)d, HIST=%(hist)d*FPS, TOTAL=(%(hist)d+%(hold)d)*FPS;
  const SPIN_RPM=%(rpm)s, TILT=%(tilt)s*Math.PI/180, PHASE0=%(phase0)s*Math.PI/180;
  const stage=document.getElementById('stage');
  function llv(lat,lng,r){
    const la=lat*Math.PI/180, lo=lng*Math.PI/180;
    return new THREE.Vector3(r*Math.cos(la)*Math.cos(lo), r*Math.sin(la), -r*Math.cos(la)*Math.sin(lo));
  }
  const scene=new THREE.Scene();
  const camera=new THREE.PerspectiveCamera(21,1080/1920,0.01,200);
  const camDist=12, yw=0.301;                // near-ortho: globe 80%% of width, centre 830/1920
  camera.position.set(0,0,camDist); camera.lookAt(0,0,0);
  const renderer=new THREE.WebGLRenderer({antialias:true,preserveDrawingBuffer:true});
  renderer.setPixelRatio(1); renderer.setSize(1080,1920); stage.appendChild(renderer.domElement);
  scene.add(new THREE.AmbientLight(0xffffff,0.55));
  const sun=new THREE.DirectionalLight(0xfff2d0,0.9); sun.position.set(3,2,4); scene.add(sun);
  (function(){ const g=new THREE.BufferGeometry(), N=1400, a=new Float32Array(N*3);
    for(let i=0;i<N;i++){ const v=new THREE.Vector3(Math.random()-.5,Math.random()-.5,Math.random()-.5).normalize().multiplyScalar(60+Math.random()*40);
      a[i*3]=v.x;a[i*3+1]=v.y;a[i*3+2]=v.z; }
    g.setAttribute('position',new THREE.BufferAttribute(a,3));
    scene.add(new THREE.Points(g,new THREE.PointsMaterial({color:0x8fa3c8,size:0.05,sizeAttenuation:true,transparent:true,opacity:0.7}))); })();
  const globe=new THREE.Group(); globe.position.y=yw; scene.add(globe);
  globe.add(new THREE.Mesh(new THREE.SphereGeometry(R,64,64),
    new THREE.MeshPhongMaterial({color:0x0b1526,emissive:0x050a14,shininess:6,transparent:true,opacity:0.32,depthWrite:false})));
  (function(){ const segs=[];
    for(const line of COAST){ for(let i=0;i<line.length-1;i++){
      const a=llv(line[i][1],line[i][0],R*1.002), b=llv(line[i+1][1],line[i+1][0],R*1.002);
      segs.push(a.x,a.y,a.z,b.x,b.y,b.z); } }
    const g=new THREE.BufferGeometry(); g.setAttribute('position',new THREE.BufferAttribute(new Float32Array(segs),3));
    globe.add(new THREE.LineSegments(g,new THREE.LineBasicMaterial({color:0x8fd8f4,transparent:true,opacity:0.55}))); })();

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
      ' if(uCyc<0.0){'+
      '   float dt=uNow-vB;'+
      '   float rise=smoothstep(-30.0,30.0,dt);'+
      '   flash=exp(-dt*dt/(2.0*40.0*40.0));'+
      '   base=0.10*rise;'+
      ' } else {'+
      '   float d=fract(uCyc-vA);'+
      '   d=d>0.5?d-1.0:d;'+
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

  const yr=document.createElement('div');
  yr.style.cssText='position:fixed;left:64px;top:300px;transform:translateY(-50%%);z-index:9;'+
    'font:78px Georgia,serif;color:#f2c14e';
  document.body.appendChild(yr);
  function yearLabel(y){ return y<0? (Math.ceil(-y)+' BC') : (Math.floor(y)+''); }

  const qx=new THREE.Quaternion().setFromAxisAngle(new THREE.Vector3(1,0,0), TILT);
  const qy=new THREE.Quaternion(), yAxis=new THREE.Vector3(0,1,0);
  window.__total=TOTAL;
  window.__frame=function(i){
    const now=Math.min(1, i/(HIST-1))*(N-1);
    qy.setFromAxisAngle(yAxis, PHASE0 + SPIN_RPM*2*Math.PI*(i/FPS)/60);
    globe.quaternion.copy(qx).multiply(qy);
    mat.uniforms.uCyc.value=-1.0;
    mat.uniforms.uNow.value=now;
    yr.textContent=yearLabel(YEARS[Math.max(0,Math.min(N-1,Math.floor(now)))]);
    renderer.render(scene,camera);
    return yr.textContent;
  };
  window.__frame(0);
  window.__ready=true;
})();
</script>
""" % {'fps': FPS, 'hist': HIST_S, 'hold': HOLD_S, 'rpm': SPIN_RPM,
       'tilt': TILT_DEG, 'phase0': PHASE0_DEG}

with open(OUT, 'w') as f:
    f.write('<!doctype html><meta charset="utf-8">\n')
    f.write('<meta name="viewport" content="width=device-width,initial-scale=1">\n')
    f.write('<title>pulse story</title>\n')
    f.write(head)
    f.write('\n<script>\nconst LEGS = ' + json.dumps(LEGS, separators=(',', ':')) + ';\n')
    f.write('const YEARS = ' + json.dumps(YEARS, separators=(',', ':')) + ';\n')
    f.write('const COAST = ' + json.dumps(coast_lines, separators=(',', ':')) + ';\n</script>\n')
    f.write(app)
print(f"wrote {OUT} ({os.path.getsize(OUT)//1024} KB)")
