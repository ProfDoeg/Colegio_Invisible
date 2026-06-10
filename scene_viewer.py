#!/usr/bin/env python3
"""
scene_viewer.py — render any 0x3d scene quipu into a self-contained, walkable
WebGL page (three.js), driven entirely by the scene's on-chain glTF body.

This generalises working/cemetery/cemetery.html (whose data was hardcoded)
into a data-driven viewer: give it a scene txid and it

  1. reads the 0x3d glTF body (nodes: planes / celestial / camera),
  2. decodes every referenced 0x03 image quipu to a base64 PNG texture,
  3. decodes the referenced 0xce celestial quipu to star/constellation data,
  4. injects all of it into a three.js template → one self-contained .html.

Nothing external is needed at view time but three.js from CDN. This is the
"OpenGL walkthrough" a quipu: link in a colegio PDF launches.

Reads bodies from data/bodies/<txid>.bin (local dataset; no RPC).
"""
from __future__ import annotations

import os
import io
import sys
import json
import struct
import base64

REPO   = os.path.dirname(os.path.abspath(__file__))
CANON  = os.path.join(REPO, "canonical")
BODIES = os.path.join(REPO, "data", "bodies")
sys.path.insert(0, CANON)

import image as imgmod
from celestial_render import _split_concat
from celestial import read_celestial_quipu

PROTOCOL_MAGIC = b"\xc1\xdd\x00\x01"
TYPE_IMAGE, TYPE_SCENE, TYPE_CELESTIAL = 0x03, 0x3d, 0xce


def local_fetcher(txid):
    with open(os.path.join(BODIES, f"{txid}.bin"), "rb") as f:
        return f.read()


# Canonical dataset: data/quipu_data.csv carries authoritative per-quipu
# `dimensions_json` (W, H, color, bit_depth) — the source of truth for image
# geometry, independent of header quirks (no-pipe titles, the Sabina W/H
# swap, multi-field headers). Prefer it over re-parsing the header bytes.
_DF = None


def _df():
    global _DF
    if _DF is None:
        import pandas as pd
        _DF = pd.read_csv(os.path.join(REPO, "data", "quipu_data.csv"))
    return _DF


def _dims_for(txid):
    df = _df()
    row = df[df["root_txid"] == txid]
    if row.empty:
        row = df[df["join_txid"] == txid]
    if row.empty:
        return None
    dj = row.iloc[0].get("dimensions_json")
    if not isinstance(dj, str):
        return None
    try:
        return json.loads(dj)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# blob splitting + decoders
# ---------------------------------------------------------------------------

def _pipe_header_body_offset(blob):
    if len(blob) <= 6 or blob[6:7] != b"|":
        return 6
    pos = hdr_end = 7
    while pos < len(blob):
        close = blob.find(b"|", pos)
        if close < 0:
            break
        if b"\n" in blob[pos:close]:
            break
        hdr_end = close + 1
        pos = close + 1
        if pos - 6 > 4096:
            break
    return hdr_end


def _header_fields(blob, offset=6):
    """Title + key=value fields from a pipe-delimited header tail."""
    title, fields = "", {}
    start = blob.find(b"|", offset)
    if start < 0:
        return title, fields
    end = _pipe_header_body_offset(blob)
    tail = blob[start:end].decode("utf-8", "replace")
    for i, part in enumerate(p for p in tail.split("|") if p != ""):
        if i == 0 and "=" not in part:
            title = part
        elif "=" in part:
            k, v = part.split("=", 1)
            fields[k.strip()] = v.strip()
    return title, fields


def _scene_gltf(blob):
    if blob[:4] != PROTOCOL_MAGIC or blob[4] != TYPE_SCENE:
        raise ValueError("not a 0x3d scene quipu")
    body = blob[_pipe_header_body_offset(blob):].decode("utf-8", "replace")
    return json.loads(body[body.find("{"):])


def _image_to_png_datauri(blob, txid=None):
    """Decode a 0x03 image inscription blob → 'data:image/png;base64,…'.

    Geometry comes from the dataset's `dimensions_json` (authoritative);
    falls back to the header bytes if the txid isn't in the dataframe. The
    pixel body is EXACTLY W*H*ch*bd/8 bytes, taken off the tail of the blob
    (the header length varies — pipe titles, no-pipe titles, multi-field —
    and pixel bytes can themselves contain '|', so a header scan mis-splits)."""
    from PIL import Image
    dims = _dims_for(txid) if txid else None
    if dims:
        W, H, color, bd = dims["W"], dims["H"], dims["color"], dims["bit_depth"]
    else:
        color = blob[6]
        W = struct.unpack(">H", blob[7:9])[0]
        H = struct.unpack(">H", blob[9:11])[0]
        bd = blob[11]
    ch = {0: 1, 1: 3, 2: 2, 3: 4}.get(color, 1)
    exp = (W * H * ch * bd + 7) // 8
    body = blob[-exp:] if 0 < exp <= len(blob) - 12 else blob[12:12 + exp]
    vals = imgmod.unpack_pixels(body, W * H * ch, bd)
    scale = 255.0 / ((1 << bd) - 1)
    px = bytes(int(round(v * scale)) for v in vals)
    mode = {0: "L", 1: "RGB", 2: "LA", 3: "RGBA"}[color]
    buf = io.BytesIO()
    Image.frombytes(mode, (W, H), px).save(buf, "PNG")
    return ("data:image/png;base64,"
            + base64.b64encode(buf.getvalue()).decode("ascii"))


def _celestial_data(blob):
    """Decode a 0xce celestial inscription blob → {points, lines, groups}."""
    h, b = _split_concat(blob)
    d = read_celestial_quipu(h, b)
    return {
        "title":  d.get("title", ""),
        "points": [{"ra": p["ra"], "dec": p["dec"], "name": p.get("name", "")}
                   for p in d["points"]],
        "groups": [{"name": g["name"],
                    "point_indices": list(g["point_indices"]),
                    "lines": [list(e) for e in g.get("lines", [])]}
                   for g in (d.get("groups") or [])],
    }


# ---------------------------------------------------------------------------
# Scene bundle
# ---------------------------------------------------------------------------

def build_scene_bundle(scene_txid, fetcher=local_fetcher):
    """Resolve a 0x3d scene + all its referenced quipus into one self-contained
    bundle the viewer can render with no further fetches."""
    blob = fetcher(scene_txid)
    gltf = _scene_gltf(blob)
    title, fields = _header_fields(blob)

    bundle = {
        "scene_txid": scene_txid,
        "title": title or (gltf.get("scenes", [{}])[0].get("name", "")),
        "place": fields.get("place", ""),
        "camera": {"position": [0, 1.6, 4], "fov": 68},
        "planes": [],
        "celestial": None,
    }

    for node in gltf.get("nodes", []):
        extras = node.get("extras", {})
        kind = extras.get("object_kind")
        if kind == "camera":
            bundle["camera"] = {
                "position": node.get("translation", [0, 1.6, 4]),
                "fov": extras.get("fov_deg", 68),
            }
        elif kind == "plane":
            ref = extras.get("quipu_ref")
            try:
                tex = _image_to_png_datauri(fetcher(ref), txid=ref)
            except Exception as e:
                tex = None
                sys.stderr.write(f"[scene_viewer] plane {ref[:12]}…: {e}\n")
            bundle["planes"].append({
                "name": node.get("name", ""),
                "label": extras.get("label", ""),
                "quipu_ref": ref,
                "translation": node.get("translation", [0, 0, 0]),
                "rotation": node.get("rotation", [0, 0, 0, 1]),
                "scale": node.get("scale", [1, 1, 1]),
                "texture": tex,
            })
        elif kind == "celestial":
            ref = extras.get("quipu_ref")
            cel = {"quipu_ref": ref,
                   "observer_lat": extras.get("latitude_deg", 0.0),
                   "initial_lst_deg": extras.get("initial_lst_deg", 0.0),
                   "rotation_period_sec": extras.get("rotation_period_sec", 90),
                   "epoch": extras.get("epoch", ""),
                   "epoch_place": extras.get("epoch_place", "")}
            try:
                cel.update(_celestial_data(fetcher(ref)))
            except Exception as e:
                sys.stderr.write(f"[scene_viewer] celestial {str(ref)[:12]}…: {e}\n")
            bundle["celestial"] = cel

    return bundle


def build_scene_viewer(scene_txid, out_html, fetcher=local_fetcher):
    """Build a self-contained walkable WebGL page for a scene quipu."""
    bundle = build_scene_bundle(scene_txid, fetcher)
    html = _TEMPLATE.replace(
        "/*__QUIPU_SCENE__*/",
        "window.QUIPU_SCENE = " + json.dumps(bundle) + ";")
    os.makedirs(os.path.dirname(os.path.abspath(out_html)), exist_ok=True)
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html)
    n_tex = sum(1 for p in bundle["planes"] if p["texture"])
    print(f"scene: {bundle['title']!r}")
    print(f"  planes: {len(bundle['planes'])} ({n_tex} textured)  "
          f"celestial: {'yes' if bundle['celestial'] else 'no'}")
    print(f"  -> {out_html} ({os.path.getsize(out_html)} bytes, self-contained)")
    return out_html


# ---------------------------------------------------------------------------
# Viewer template — three.js, reads window.QUIPU_SCENE. Ported from
# working/cemetery/cemetery.html, generalised to any scene bundle.
# ---------------------------------------------------------------------------

_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Quipu scene</title>
<style>
  body { margin:0; background:#0a0a0a; color:#eaeaea;
         font-family:'Iowan Old Style','Hoefler Text',Georgia,serif; overflow:hidden; }
  canvas { display:block; }
  #overlay { position:absolute; inset:0; display:flex; flex-direction:column;
    align-items:center; justify-content:center; text-align:center;
    background:rgba(8,6,4,0.80); color:#f4e8d4; cursor:pointer; z-index:10;
    transition:opacity .6s; }
  #overlay h1 { font-size:28px; font-weight:500; margin:0 0 6px; }
  #overlay p  { font-size:14px; max-width:480px; line-height:1.6; opacity:.8; margin:4px 0; }
  #overlay .start { margin-top:22px; padding:10px 24px; border:1px solid #c9b285;
    border-radius:2px; font-size:13px; letter-spacing:1px; }
  #hud { position:absolute; bottom:16px; left:16px; z-index:5;
    font:12px/1.5 ui-monospace,monospace; color:rgba(244,232,212,.7);
    padding:8px 12px; background:rgba(8,6,4,.45);
    border:1px solid rgba(201,178,133,.3); border-radius:2px; pointer-events:none; }
  #plaque { position:absolute; top:28px; left:50%; transform:translateX(-50%);
    z-index:8; pointer-events:none; max-width:540px; padding:18px 24px;
    background:rgba(8,6,4,.88); color:#f4e8d4; border:1px solid #c9b285;
    border-radius:3px; line-height:1.55; opacity:0; transition:opacity .4s; }
  #plaque h2 { margin:0 0 8px; font-size:22px; font-weight:500; }
  #plaque p  { margin:6px 0; font-size:14px; color:#d9c9a8; }
  #plaque .txid { font:10px ui-monospace,monospace; color:#8a7a55;
    margin-top:14px; word-break:break-all; }
  #plaque.show { opacity:1; }
</style>
</head>
<body>
<div id="overlay">
  <h1 id="ov-title">Quipu scene</h1>
  <p id="ov-place"></p>
  <p>WASD to walk · mouse to look · approach a plate to read its plaque.</p>
  <div class="start">click to enter</div>
</div>
<div id="hud">WASD walk · mouse look · esc release</div>
<div id="plaque"><h2 id="plaque-name"></h2><p id="plaque-text"></p>
  <div class="txid" id="plaque-txid"></div></div>

<script type="importmap">
{ "imports": {
  "three": "https://cdn.jsdelivr.net/npm/three@0.158.0/build/three.module.js",
  "three/addons/": "https://cdn.jsdelivr.net/npm/three@0.158.0/examples/jsm/"
}}
</script>
<script type="module">
import * as THREE from 'three';
import { PointerLockControls } from 'three/addons/controls/PointerLockControls.js';
import { LineSegments2 }        from 'three/addons/lines/LineSegments2.js';
import { LineSegmentsGeometry } from 'three/addons/lines/LineSegmentsGeometry.js';
import { LineMaterial }         from 'three/addons/lines/LineMaterial.js';

/*__QUIPU_SCENE__*/
const S = window.QUIPU_SCENE;
document.getElementById('ov-title').textContent = S.title || 'Quipu scene';
document.title = S.title || 'Quipu scene';
if (S.place) document.getElementById('ov-place').textContent = S.place;

// ---- scene / camera / renderer ----
const scene = new THREE.Scene();
scene.fog = new THREE.Fog(0xb8a780, 20, 60);
scene.background = new THREE.Color(0xb8a780);
const camera = new THREE.PerspectiveCamera(S.camera.fov || 68,
  innerWidth/innerHeight, 0.05, 400);
camera.position.set(...(S.camera.position || [0,1.6,4]));
const renderer = new THREE.WebGLRenderer({ antialias:true });
renderer.setSize(innerWidth, innerHeight);
renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
document.body.appendChild(renderer.domElement);
addEventListener('resize', () => {
  camera.aspect = innerWidth/innerHeight; camera.updateProjectionMatrix();
  renderer.setSize(innerWidth, innerHeight);
  scene.traverse(o => { if (o.userData && o.userData.isCelestialLine)
    o.material.resolution.set(innerWidth, innerHeight); });
});

// ---- lighting + ground ----
scene.add(new THREE.AmbientLight(0xfff5e8, 1.1));
const sun = new THREE.DirectionalLight(0xfff0d2, 1.4); sun.position.set(-6,9,3);
scene.add(sun);
scene.add(new THREE.HemisphereLight(0xcedce8, 0x9a8a60, 0.85));
const ground = new THREE.Mesh(new THREE.PlaneGeometry(120,120),
  new THREE.MeshStandardMaterial({ color:0x6a7a48, roughness:0.95 }));
ground.rotation.x = -Math.PI/2; scene.add(ground);

// ---- plates: one textured plane per scene node ----
const plates = [];
const loader = new THREE.TextureLoader();
const frameMat = new THREE.MeshStandardMaterial({ color:0x3a2c1c, roughness:0.7 });
for (const p of S.planes) {
  const group = new THREE.Group();
  group.position.set(...p.translation);
  if (p.rotation) group.quaternion.set(...p.rotation);
  const [sx, sy] = p.scale;
  // backboard frame, slightly larger than the photo
  const board = new THREE.Mesh(new THREE.BoxGeometry(sx*1.12, sy*1.12, 0.05), frameMat);
  board.position.z = -0.03; group.add(board);
  if (p.texture) {
    const tex = loader.load(p.texture);
    tex.magFilter = THREE.NearestFilter; tex.colorSpace = THREE.SRGBColorSpace;
    tex.anisotropy = renderer.capabilities.getMaxAnisotropy();
    const mesh = new THREE.Mesh(new THREE.PlaneGeometry(sx, sy),
      new THREE.MeshBasicMaterial({ map:tex, toneMapped:false }));
    group.add(mesh);
  }
  group.userData = { label:p.label || p.name, ref:p.quipu_ref };
  scene.add(group);
  plates.push(group);
}

// ---- celestial sphere (data-driven) ----
let starsGroup = null, starRotSpeed = 0;
if (S.celestial && S.celestial.points && S.celestial.points.length) {
  const C = S.celestial;
  const R = 80;
  starRotSpeed = -(2*Math.PI) / (C.rotation_period_sec || 90);
  const HUE = ['Orion','Taurus','Winter Triangle','Lepus','Canis Minor',
    'Canis Major','Pleiades','Monoceros','Canopus','Perseus'];
  const colorFor = (name) => {
    const i = HUE.indexOf(name);
    return new THREE.Color().setHSL((i<0?0:i)*36/360, 0.42, 0.78);
  };
  const radec = (raDeg, decDeg) => {
    const ra = raDeg*Math.PI/180, dec = decDeg*Math.PI/180;
    return new THREE.Vector3(R*Math.cos(dec)*Math.cos(ra), R*Math.sin(dec),
      -R*Math.cos(dec)*Math.sin(ra));
  };
  const axis = new THREE.Group();
  axis.position.y = 1.6;
  axis.rotation.x = -((90 - (C.observer_lat||0)) * Math.PI/180);
  const spin = new THREE.Group(); axis.add(spin);
  const pos = C.points.map(pt => radec(pt.ra, pt.dec));
  for (const g of (C.groups || [])) {
    const col = colorFor(g.name);
    const sv = new Float32Array(g.point_indices.length*3);
    g.point_indices.forEach((idx,i) => { const p=pos[idx];
      sv[i*3]=p.x; sv[i*3+1]=p.y; sv[i*3+2]=p.z; });
    const sg = new THREE.BufferGeometry();
    sg.setAttribute('position', new THREE.BufferAttribute(sv,3));
    spin.add(new THREE.Points(sg, new THREE.PointsMaterial({ color:col, size:2.0,
      sizeAttenuation:true, depthWrite:false, toneMapped:false, fog:false })));
    if (g.lines && g.lines.length) {
      const flat = [];
      for (const [a,b] of g.lines) { const pa=pos[a], pb=pos[b];
        flat.push(pa.x,pa.y,pa.z, pb.x,pb.y,pb.z); }
      const lg = new LineSegmentsGeometry(); lg.setPositions(flat);
      const lm = new LineMaterial({ color:col, linewidth:2.4, transparent:true,
        opacity:0.85, depthWrite:false, toneMapped:false, fog:false,
        resolution:new THREE.Vector2(innerWidth, innerHeight) });
      const segs = new LineSegments2(lg, lm); segs.computeLineDistances();
      segs.userData.isCelestialLine = true; spin.add(segs);
    }
    // label sprite at the constellation centroid
    const c = new THREE.Vector3();
    for (const idx of g.point_indices) c.add(pos[idx]);
    c.multiplyScalar(1/g.point_indices.length).normalize().multiplyScalar(R*1.02);
    const cv = document.createElement('canvas'); cv.width=512; cv.height=96;
    const cx = cv.getContext('2d');
    cx.font='500 44px Georgia, serif'; cx.textAlign='center'; cx.textBaseline='middle';
    cx.shadowColor='rgba(0,0,0,0.55)'; cx.shadowBlur=8;
    cx.fillStyle='#'+col.getHexString(); cx.fillText(g.name, 256, 48);
    const lt = new THREE.CanvasTexture(cv); lt.colorSpace=THREE.SRGBColorSpace;
    const spr = new THREE.Sprite(new THREE.SpriteMaterial({ map:lt,
      transparent:true, depthWrite:false, toneMapped:false, fog:false }));
    spr.position.copy(c); spr.scale.set(10,1.9,1); spin.add(spr);
  }
  spin.rotation.y = (C.initial_lst_deg||0) * Math.PI/180;
  scene.add(axis); starsGroup = spin;
}

// ---- first-person controls ----
const controls = new PointerLockControls(camera, renderer.domElement);
const overlay = document.getElementById('overlay');
overlay.addEventListener('click', () => controls.lock());
controls.addEventListener('lock',   () => overlay.style.opacity = 0);
controls.addEventListener('unlock', () => overlay.style.opacity = 1);
const move = { f:false, b:false, l:false, r:false }, SPEED = 2.6;
addEventListener('keydown', e => { ({KeyW:'f',ArrowUp:'f',KeyS:'b',ArrowDown:'b',
  KeyA:'l',ArrowLeft:'l',KeyD:'r',ArrowRight:'r'}[e.code]) &&
  (move[{KeyW:'f',ArrowUp:'f',KeyS:'b',ArrowDown:'b',KeyA:'l',ArrowLeft:'l',
  KeyD:'r',ArrowRight:'r'}[e.code]] = true); });
addEventListener('keyup', e => { const k={KeyW:'f',ArrowUp:'f',KeyS:'b',
  ArrowDown:'b',KeyA:'l',ArrowLeft:'l',KeyD:'r',ArrowRight:'r'}[e.code];
  if (k) move[k] = false; });

// ---- proximity plaque ----
const PROX = 2.8;
const pEl=document.getElementById('plaque'), pName=document.getElementById('plaque-name'),
  pText=document.getElementById('plaque-text'), pTxid=document.getElementById('plaque-txid');
let near = null;
function updatePlaque() {
  let best=null, dmin=Infinity;
  for (const g of plates) { const d=camera.position.distanceTo(g.position);
    if (d<dmin){ dmin=d; best=g; } }
  if (best && dmin<PROX) {
    if (near!==best) { near=best;
      pName.textContent = best.userData.label || '';
      pText.textContent = '';
      pTxid.innerHTML = 'quipu:' + best.userData.ref;
      pEl.classList.add('show'); }
  } else if (near) { near=null; pEl.classList.remove('show'); }
}

// ---- render loop ----
const clock = new THREE.Clock();
(function animate(){
  requestAnimationFrame(animate);
  const dt = Math.min(clock.getDelta(), 0.1);
  if (controls.isLocked) {
    const v = SPEED*dt;
    if (move.f) controls.moveForward( v);
    if (move.b) controls.moveForward(-v);
    if (move.r) controls.moveRight  ( v);
    if (move.l) controls.moveRight  (-v);
    controls.getObject().position.y = 1.6;
  }
  updatePlaque();
  if (starsGroup) starsGroup.rotation.y += starRotSpeed * dt;
  renderer.render(scene, camera);
})();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    txid = (sys.argv[1] if len(sys.argv) > 1
            else "1f63558bdee2f5ead118083ff0af0d5e266acaf347938c5ed2722b6ced1248e3")
    out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/scene_viewer/scene.html"
    build_scene_viewer(txid, out)
