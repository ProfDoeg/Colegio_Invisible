import json, os, random, subprocess
import numpy as np
try: import scipy.ndimage as ndi; SC=True
except: SC=False

TAKE="/home/drdoeg/kinect/takes/take_20260612_092840"
W,Hh=640,480
m=json.load(open(TAKE+"/meta.json")); ND=m["depth_frames"]; NR=m["rgb_frames"]; N=min(ND,NR)
depth=np.memmap(TAKE+"/depth.bin",dtype=np.uint16,mode="r",shape=(ND,Hh,W))
rgb=np.memmap(TAKE+"/rgb.bin",dtype=np.uint8,mode="r",shape=(NR,Hh,W,3))
crumbs=sorted(json.load(open(TAKE+"/breadcrumbs.json")),key=lambda x:x["frame"])
NEAR,FAR=1150,3100
BG=np.load("/tmp/bg.npy")
MARGIN=300.0

# --- bounded motion graph: nodes = crumbs; edges = fwd/rev spans + same-label cuts
nodes=[{"ord":c["frame"],"label":c["label"],"sym":c["sym"]} for c in crumbs]
NN=len(nodes); first,last=0,NN-1
same={}
for i,nd in enumerate(nodes): same.setdefault(nd["label"],[]).append(i)

def edges(i):
    e=[]
    if i<last: e.append(("fwd",i+1))      # play footage ord[i]..ord[i+1]
    if i>first: e.append(("rev",i-1))     # play it backward
    for j in same[nodes[i]["label"]]:     # cut to another instance of the same pose
        if j!=i: e.append(("cut",j))
    return e

# --- uniform random walk, collecting played footage frames (bounded to [first,last])
random.seed(7)
SECONDS=45; TARGET=SECONDS*30
seq=[]; i=first
while len(seq)<TARGET:
    kind,j=random.choice(edges(i))
    a,b=nodes[i]["ord"],nodes[j]["ord"]
    if kind=="fwd": seq+=list(range(a,b))
    elif kind=="rev": seq+=list(range(a,b,-1))
    # cut: emit nothing (same pose → seamless), just relocate
    i=j
seq=[f for f in seq if first<= f] and [max(nodes[first]["ord"],min(nodes[last]["ord"],f)) for f in seq]
print("walk: %d frames (%.1fs), %d nodes, clusters=%s"%(len(seq),len(seq)/30,NN,
      {k:len(v) for k,v in same.items()}))

def mask(d):
    mm=(d>NEAR)&(d<=FAR)&(d>0)&(d<(BG-MARGIN))   # band AND closer than static bg
    if SC:
        mm=ndi.binary_closing(mm,iterations=2)
        mm=ndi.binary_fill_holes(mm)
        if mm.any():
            lb,n=ndi.label(mm)
            if n>1: mm=lb==(1+int(np.argmax(ndi.sum(mm,lb,range(1,n+1)))))
        mm=ndi.binary_opening(mm,iterations=1)
    return mm

# --- render masked colour to mp4 via ffmpeg stdin (raw rgb24)
ff=subprocess.Popen(["ffmpeg","-y","-loglevel","error","-f","rawvideo","-pix_fmt","rgb24",
  "-s","%dx%d"%(W,Hh),"-r","30","-i","-","-pix_fmt","yuv420p","-movflags","faststart",
  "/tmp/walk.mp4"],stdin=subprocess.PIPE)
for f in seq:
    d=depth[f].astype(np.float32); mk=mask(d)
    out=np.where(mk[...,None],rgb[f],0).astype(np.uint8)
    ff.stdin.write(out.tobytes())
ff.stdin.close(); ff.wait()
print("wrote /tmp/walk.mp4", os.path.getsize("/tmp/walk.mp4"),"bytes")
