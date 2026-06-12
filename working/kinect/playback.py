#!/usr/bin/env python3
"""Loop a recorded take as an MJPEG depth video. View at http://<nodus>:8788"""
import io, sys, time, json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import numpy as np
from PIL import Image, ImageDraw

TAKE = sys.argv[1] if len(sys.argv)>1 else "/home/drdoeg/kinect/takes/take_20260611_183624"
NEAR, FAR = 2200.0, 3300.0
W,H = 640,480
meta = json.load(open(os.path.join(TAKE,"meta.json")))
N = meta["depth_frames"]
mm = np.memmap(os.path.join(TAKE,"depth.bin"),dtype=np.uint16,mode="r",shape=(N,H,W))
PORT=8788

def render(i):
    f = mm[i].astype(np.float32)
    valid = f>0
    band = valid & (f>=NEAR) & (f<=FAR)
    # left panel: full depth grayscale; right: masked figure, depth-shaded
    g = np.zeros((H,W),np.uint8)
    t = np.clip((f-500)/4000,0,1); g[valid]=((1-t[valid])*255).astype(np.uint8)
    fig = np.zeros((H,W),np.uint8)
    tb = np.clip((f-NEAR)/(FAR-NEAR),0,1); fig[band]=((1-tb[band])*255).astype(np.uint8)
    grid = Image.new("RGB",(W,H//2*1))
    a = Image.fromarray(g).resize((W//2,H//2))
    b = Image.fromarray(fig).resize((W//2,H//2))
    out = Image.new("RGB",(W,H//2))
    out.paste(a,(0,0)); out.paste(b,(W//2,0))
    d=ImageDraw.Draw(out); d.text((6,5),"DEPTH",fill=(255,220,80))
    d.text((W//2+6,5),"DANCER %.1fs"%(i/30),fill=(255,220,80))
    buf=io.BytesIO(); out.save(buf,"JPEG",quality=80); return buf.getvalue()

PAGE=b"<html><body style='background:#111;margin:0'><img src='/stream' style='width:100%'></body></html>"

class Hdlr(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        if self.path=="/":
            self.send_response(200); self.send_header("Content-Type","text/html")
            self.send_header("Content-Length",str(len(PAGE))); self.end_headers()
            self.wfile.write(PAGE); return
        self.send_response(200)
        self.send_header("Content-Type","multipart/x-mixed-replace; boundary=frame"); self.end_headers()
        i=0
        try:
            while True:
                j=render(i)
                self.wfile.write(b"--frame\r\nContent-Type: image/jpeg\r\n"+
                    ("Content-Length: %d\r\n\r\n"%len(j)).encode()+j+b"\r\n")
                i=(i+1)%N; time.sleep(1/30)
        except (BrokenPipeError,ConnectionResetError): pass

print("playback on :%d  (%d frames, %.0fs)"%(PORT,N,N/30))
ThreadingHTTPServer(("0.0.0.0",PORT),Hdlr).serve_forever()
