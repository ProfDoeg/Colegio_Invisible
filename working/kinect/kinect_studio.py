#!/usr/bin/env python3
"""Kinect capture studio — live 4-panel view + timed recording.

Panels: RGB · depth (B/W, near=bright) · depth-band mask · masked RGB.
Controls: near/far filter (mm), record duration (default 100 s), delayed
start (default 10 s) with an on-screen countdown, cancel.

Depth runs in REGISTERED mode when the device supports it (depth aligned
to the RGB camera, values already in mm) so the mask cuts the RGB cleanly;
falls back to raw 11-bit + the tan() fit otherwise.

Recording streams raw frames straight to disk (no RAM blow-up):
  working/kinect/takes/take_<stamp>/depth.bin  uint16 frames
                                    rgb.bin    uint8 RGB frames
                                    meta.json  shapes/counts/format/ts arrays

Run:  .venv/bin/python working/kinect/kinect_studio.py   → http://localhost:8787
Stop: Ctrl-C (clean shutdown — the 1473 wedges on unclean USB teardown).
"""
import io
import json
import os
import sys
import threading
import time
from ctypes import (CDLL, CFUNCTYPE, POINTER, Structure, byref, c_int8,
                    c_int16, c_int32, c_uint32, c_void_p, string_at)
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import numpy as np
from PIL import Image, ImageDraw

W, H = 640, 480
PORT = 8787
TAKES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "takes")

# ---------------------------------------------------------------- libfreenect
lib = CDLL("/usr/local/lib/libfreenect.dylib")


class FrameMode(Structure):
    _fields_ = [("reserved", c_uint32), ("resolution", c_int32),
                ("fmt", c_int32), ("bytes", c_int32),
                ("width", c_int16), ("height", c_int16),
                ("data_bits_per_pixel", c_int8), ("padding_bits_per_pixel", c_int8),
                ("framerate", c_int8), ("is_valid", c_int8)]


lib.freenect_find_depth_mode.restype = FrameMode
lib.freenect_set_depth_mode.argtypes = [c_void_p, FrameMode]
lib.freenect_find_video_mode.restype = FrameMode
lib.freenect_set_video_mode.argtypes = [c_void_p, FrameMode]

RAW11_MAX = 2047


def raw11_to_mm(raw):
    mm = 1000.0 * 0.1236 * np.tan(raw / 2842.5 + 1.1863)
    mm[(raw <= 0) | (raw >= RAW11_MAX)] = 0
    return mm


# ---------------------------------------------------------------- shared state
class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.depth_mm = None          # float32 mm, 0 = no data
        self.rgb = None               # uint8 (H,W,3)
        self.near = 1200.0
        self.far = 2600.0
        self.mirror = True
        self.record_rgb = False        # RGB stream pauses during a take by
                                       # default — halves USB load (the 1473
                                       # drops the bus under depth+RGB while
                                       # recording); dancer needs depth only
        self.depth_fmt = "?"
        self.fps = 0.0
        # recording state machine: idle | armed | recording
        self.mode = "idle"
        self.t_start = 0.0
        self.t_end = 0.0
        self.take_dir = None
        self.depth_f = None
        self.rgb_f = None
        self.n_depth = 0
        self.n_rgb = 0
        self.ts_depth = []
        self.ts_rgb = []
        self.last_take = None
        self.error = None
        self.video_req = None         # "stop"|"start" — applied by the capture
                                      # loop OUTSIDE the lock (a blocked USB
                                      # control call must never hold S.lock)


S = State()


def _arm(duration, delay):
    with S.lock:
        if S.mode != "idle":
            return False
        # refuse to record unless BOTH streams are live — never silently
        # capture a depth-only (or rgb-only) take again
        if S.depth_mm is None or S.rgb is None:
            S.error = "not recording: waiting for both depth AND rgb frames"
            return False
        S.error = None
        stamp = time.strftime("%Y%m%d_%H%M%S")
        S.take_dir = os.path.join(TAKES, f"take_{stamp}")
        os.makedirs(S.take_dir, exist_ok=True)
        S.t_start = time.monotonic() + max(delay, 0)
        S.t_end = S.t_start + max(duration, 1)
        S.n_depth = S.n_rgb = 0
        S.ts_depth, S.ts_rgb = [], []
        S.mode = "armed"
        return True


def _begin_recording():
    # Record EVERYTHING raw — both streams, full res, no filtering. The
    # near/far band is a PREVIEW aid only; it never touches saved bytes.
    # Both streams run together (nodus's direct USB handles the load).
    S.depth_f = open(os.path.join(S.take_dir, "depth.bin"), "wb")
    S.rgb_f = open(os.path.join(S.take_dir, "rgb.bin"), "wb")
    S.mode = "recording"


def _finish_recording():
    S.depth_f.close()
    if S.rgb_f is not None:
        S.rgb_f.close()
    meta = {"width": W, "height": H, "depth_format": S.depth_fmt,
            "rgb_format": "rgb_uint8_640x480",
            "depth_frames": S.n_depth, "rgb_frames": S.n_rgb,
            "near_mm_preview": S.near, "far_mm_preview": S.far,
            "duration_s": round(S.t_end - S.t_start, 1),
            "ts_depth": S.ts_depth, "ts_rgb": S.ts_rgb,
            "note": "RAW capture, no filtering. depth.bin = uint16 frames "
                    "(mm if depth_format=registered); rgb.bin = uint8 RGB "
                    "640x480x3. depth & rgb are registered (pixel-aligned). "
                    "ts_* are device timestamps for pairing frames."}
    with open(os.path.join(S.take_dir, "meta.json"), "w") as f:
        json.dump(meta, f)
    S.last_take = S.take_dir
    S.mode = "idle"
    S.take_dir = None


def _cancel():
    with S.lock:
        if S.mode == "recording":
            _finish_recording()           # keep the partial take
        elif S.mode == "armed":
            S.mode = "idle"
            S.take_dir = None


# ---------------------------------------------------------------- capture thread
def capture_loop():
    """Open → stream → on USB loss, clean up and retry every 5 s, so a
    replug heals the session without restarting the server."""
    while not _stop.is_set():
        _stream_once()
        if _stop.is_set():
            break
        with S.lock:
            if S.mode == "recording":
                _finish_recording()
            S.mode = "idle"
            S.fps = 0.0
        for _ in range(50):
            if _stop.is_set():
                return
            time.sleep(0.1)


def _stream_once():
    ctx = c_void_p()
    if lib.freenect_init(byref(ctx), None) < 0:
        S.error = "freenect_init failed — retrying"
        return
    lib.freenect_select_subdevices(ctx, 2)               # CAMERA only (1473!)
    dev = c_void_p()
    if lib.freenect_open_device(ctx, byref(dev), 0) < 0:
        S.error = "cannot open Kinect — replug USB (retrying every 5 s)"
        lib.freenect_shutdown(ctx)
        return
    _DEV[0] = dev

    DepthCB = CFUNCTYPE(None, c_void_p, c_void_p, c_uint32)
    VideoCB = CFUNCTYPE(None, c_void_p, c_void_p, c_uint32)
    times = []

    def on_depth(_d, data, ts):
        raw = np.frombuffer(string_at(data, W * H * 2), dtype=np.uint16).reshape(H, W)
        now = time.monotonic()
        with S.lock:
            if S.depth_fmt == "registered":
                S.depth_mm = raw.astype(np.float32)
            else:
                S.depth_mm = raw11_to_mm(raw.astype(np.float32))
            times.append(now)
            if len(times) > 30:
                del times[0]
            if len(times) > 1:
                S.fps = (len(times) - 1) / (times[-1] - times[0])
            if S.mode == "armed" and now >= S.t_start:
                _begin_recording()
            if S.mode == "recording":
                S.depth_f.write(raw.tobytes())
                S.n_depth += 1
                S.ts_depth.append(ts)
                if now >= S.t_end:
                    _finish_recording()

    def on_video(_d, data, ts):
        rgb = np.frombuffer(string_at(data, W * H * 3), dtype=np.uint8).reshape(H, W, 3)
        with S.lock:
            S.rgb = rgb.copy()
            if S.mode == "recording" and S.rgb_f is not None:
                S.rgb_f.write(rgb.tobytes())
                S.n_rgb += 1
                S.ts_rgb.append(ts)

    dcb, vcb = DepthCB(on_depth), VideoCB(on_video)
    lib.freenect_set_depth_callback(dev, dcb)
    lib.freenect_set_video_callback(dev, vcb)

    dm = lib.freenect_find_depth_mode(1, 4)              # MEDIUM, REGISTERED (mm)
    if dm.is_valid:
        S.depth_fmt = "registered"
    else:
        dm = lib.freenect_find_depth_mode(1, 0)          # MEDIUM, 11-bit raw
        S.depth_fmt = "raw11"
    lib.freenect_set_depth_mode(dev, dm)
    vm = lib.freenect_find_video_mode(1, 0)              # MEDIUM, RGB
    lib.freenect_set_video_mode(dev, vm)
    lib.freenect_start_depth(dev)
    lib.freenect_start_video(dev)
    S.error = None
    print(f"[capture] streaming — depth mode: {S.depth_fmt}")

    try:
        while not _stop.is_set():
            if lib.freenect_process_events(ctx) < 0:
                S.error = "USB stream lost — replug the Kinect (auto-reconnecting)"
                break
            with S.lock:
                req, S.video_req = S.video_req, None
            if req == "stop":
                lib.freenect_stop_video(dev)
            elif req == "start":
                lib.freenect_start_video(dev)
    finally:
        with S.lock:
            if S.mode == "recording":
                _finish_recording()
        _DEV[0] = None
        lib.freenect_stop_depth(dev)
        lib.freenect_stop_video(dev)
        lib.freenect_close_device(dev)
        lib.freenect_shutdown(ctx)
        print("[capture] clean shutdown")


_stop = threading.Event()
_DEV = [None]                          # live device handle (capture thread)


# ---------------------------------------------------------------- rendering
_last_jpeg = [b""]


def composite_jpeg():
    if not S.lock.acquire(timeout=0.5):
        return _last_jpeg[0]           # capture thread stuck — serve last frame
    try:
        mm = None if S.depth_mm is None else S.depth_mm.copy()
        rgb = None if S.rgb is None else S.rgb.copy()
        near, far, mirror = S.near, S.far, S.mirror
    finally:
        S.lock.release()

    panels = []
    if rgb is None:
        rgb = np.zeros((H, W, 3), np.uint8)
    panels.append(("RGB", rgb))

    if mm is None:
        mm = np.zeros((H, W), np.float32)
    valid = mm > 0
    bw = np.zeros((H, W), np.uint8)
    if valid.any():
        t = np.clip((mm - 500.0) / 4000.0, 0, 1)         # 0.5–4.5 m window
        bw = ((1.0 - t) * 255).astype(np.uint8)
        bw[~valid] = 0
    panels.append(("DEPTH near=bright", np.stack([bw] * 3, axis=-1)))

    mask = valid & (mm >= near) & (mm <= far)
    panels.append((f"MASK {int(near)}–{int(far)}mm",
                   (mask[..., None] * np.uint8(255)).repeat(3, axis=2)))

    panels.append(("MASKED RGB", np.where(mask[..., None], rgb, 0)))

    grid = Image.new("RGB", (W, H))
    half = (W // 2, H // 2)
    for i, (label, arr) in enumerate(panels):
        im = Image.fromarray(arr)
        if mirror:
            im = im.transpose(Image.FLIP_LEFT_RIGHT)
        im = im.resize(half)
        d = ImageDraw.Draw(im)
        d.text((6, 5), label, fill=(255, 220, 80))
        grid.paste(im, ((i % 2) * half[0], (i // 2) * half[1]))

    buf = io.BytesIO()
    grid.save(buf, "JPEG", quality=75)
    _last_jpeg[0] = buf.getvalue()
    return _last_jpeg[0]


# ---------------------------------------------------------------- web app
PAGE = """<!doctype html><html><head><title>Kinect studio</title><style>
body{background:#111;color:#ddd;font-family:Menlo,monospace;margin:14px}
#wrap{position:relative;display:inline-block}
img{width:960px;image-rendering:pixelated;border:1px solid #333}
#overlay{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
 font-size:110px;color:#ff5050;text-shadow:0 0 18px #000;pointer-events:none;
 font-variant-numeric:tabular-nums}
#reclamp{position:absolute;top:10px;left:10px;width:18px;height:18px;border-radius:50%;
 background:#ff3030;box-shadow:0 0 12px #ff3030;display:none;animation:blink 1s infinite}
@keyframes blink{50%{opacity:.25}}
.controls{margin:10px 0}label{margin-right:4px;color:#999}
input{width:70px;background:#222;color:#eee;border:1px solid #444;padding:3px}
button{padding:8px 20px;margin-right:8px;background:#2a2a2a;color:#eee;border:1px solid #555;
 cursor:pointer;font-size:15px;border-radius:4px}
button#rec{background:#5a1111}button#stop{background:#1a4a1a;display:none}
#status{color:#8c8}
</style></head><body>
<div class=wrap id=wrap><img id=v src=/stream><div id=reclamp></div><div id=overlay></div></div>
<div class=controls>
 <label>near mm</label><input id=near type=number value=1200 step=50>
 <label>far mm</label><input id=far type=number value=2600 step=50>
 <label>max s</label><input id=dur type=number value=600>
 <label>delay s</label><input id=delay type=number value=5>
 <label><input id=mir type=checkbox checked style="width:auto">mirror</label>
</div>
<div class=controls>
 <button id=rec onclick=rec()>● record</button>
 <button id=stop onclick=stopRec()>■ stop &amp; save</button>
 <span id=status></span>
</div>
<script>
const $=id=>document.getElementById(id);
function setFilter(){fetch(`/set?near=${$('near').value}&far=${$('far').value}&mirror=${$('mir').checked?1:0}`)}
['near','far','mir'].forEach(id=>$(id).addEventListener('change',setFilter));
function rec(){fetch(`/record?duration=${$('dur').value}&delay=${$('delay').value}`)}
function stopRec(){fetch('/cancel')}
function fmt(t){t=Math.floor(t);return (t/60|0)+':'+String(t%60).padStart(2,'0')}
setInterval(async()=>{const s=await(await fetch('/status')).json();
 let o='',msg=`${s.depth_fmt} ${s.fps.toFixed(0)}fps`,rec=false;
 if(s.error){msg='⚠ '+s.error}
 else if(s.mode=='armed'){o=Math.ceil(s.starts_in);msg=`get ready — starting in ${o}s`}
 else if(s.mode=='recording'){o=fmt(s.elapsed);rec=true;
   msg=`REC ${fmt(s.elapsed)} / max ${fmt(s.total)} · ${s.frames} frames`}
 else if(s.last_take){msg=`saved: ${s.last_take.split('/').pop()} (${s.frames} frames) · `+msg}
 $('overlay').textContent=o;$('status').textContent=msg;
 $('reclamp').style.display=rec?'block':'none';
 $('rec').style.display=(s.mode=='idle')?'inline-block':'none';
 $('stop').style.display=(s.mode=='recording'||s.mode=='armed')?'inline-block':'none';
},300);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/":
            b = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        elif u.path == "/stream":
            self.send_response(200)
            self.send_header("Content-Type",
                             "multipart/x-mixed-replace; boundary=frame")
            self.end_headers()
            try:
                while not _stop.is_set():
                    jpg = composite_jpeg()
                    self.wfile.write(b"--frame\r\nContent-Type: image/jpeg\r\n"
                                     + f"Content-Length: {len(jpg)}\r\n\r\n".encode()
                                     + jpg + b"\r\n")
                    time.sleep(1 / 12)
            except (BrokenPipeError, ConnectionResetError):
                pass
        elif u.path == "/status":
            now = time.monotonic()
            if not S.lock.acquire(timeout=0.5):
                self._json({"mode": "stalled", "fps": 0, "depth_fmt": "?",
                            "near": 0, "far": 0, "frames": 0, "starts_in": 0,
                            "elapsed": 0, "total": 0, "last_take": None,
                            "error": "capture thread stalled — replug the Kinect"})
                return
            try:
                self._json({"mode": S.mode, "fps": S.fps, "depth_fmt": S.depth_fmt,
                            "near": S.near, "far": S.far, "error": S.error,
                            "starts_in": max(0, S.t_start - now),
                            "elapsed": max(0, now - S.t_start),
                            "total": max(0, S.t_end - S.t_start),
                            "frames": S.n_depth,
                            "last_take": S.last_take})
            finally:
                S.lock.release()
        elif u.path == "/set":
            with S.lock:
                S.near = float(q.get("near", S.near))
                S.far = float(q.get("far", S.far))
                S.mirror = q.get("mirror", "1") == "1"
                S.record_rgb = q.get("rgbrec", "0") == "1"
            self._json({"ok": True})
        elif u.path == "/record":
            ok = _arm(float(q.get("duration", 100)), float(q.get("delay", 10)))
            self._json({"ok": ok})
        elif u.path == "/cancel":
            _cancel()
            self._json({"ok": True})
        else:
            self.send_error(404)


def main():
    os.makedirs(TAKES, exist_ok=True)
    t = threading.Thread(target=capture_loop, daemon=True)
    t.start()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Kinect studio: http://localhost:{PORT}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        _stop.set()
        t.join(timeout=5)
        srv.server_close()


if __name__ == "__main__":
    main()
