#!/usr/bin/env python3
"""Kinect 1473 depth capture via the async libfreenect C API (ctypes),
camera subdevice ONLY — replicates the code path of freenect-camtest
(the one tool proven to stream on this sensor) minus the motor claim.
Clean stop/close/shutdown so the device never wedges."""
import sys
import time
from ctypes import (CDLL, CFUNCTYPE, POINTER, Structure, byref, c_int,
                    c_int8, c_int16, c_int32, c_uint32, c_void_p, string_at)

import numpy as np

OUT = sys.argv[1] if len(sys.argv) > 1 else "/tmp/kinect_depth.npy"
SECONDS = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0
W, H = 640, 480

lib = CDLL("/usr/local/lib/libfreenect.dylib")


class FrameMode(Structure):
    _fields_ = [("reserved", c_uint32), ("resolution", c_int32),
                ("fmt", c_int32), ("bytes", c_int32),
                ("width", c_int16), ("height", c_int16),
                ("data_bits_per_pixel", c_int8), ("padding_bits_per_pixel", c_int8),
                ("framerate", c_int8), ("is_valid", c_int8)]


lib.freenect_find_depth_mode.restype = FrameMode
lib.freenect_set_depth_mode.argtypes = [c_void_p, FrameMode]

ctx = c_void_p()
if lib.freenect_init(byref(ctx), None) < 0:
    sys.exit("freenect_init failed")
lib.freenect_select_subdevices(ctx, 2)          # FREENECT_DEVICE_CAMERA only

dev = c_void_p()
if lib.freenect_open_device(ctx, byref(dev), 0) < 0:
    lib.freenect_shutdown(ctx)
    sys.exit("freenect_open_device failed")

frames, stamps = [], []
DepthCB = CFUNCTYPE(None, c_void_p, c_void_p, c_uint32)


def on_depth(_dev, data, ts):
    frames.append(np.frombuffer(string_at(data, W * H * 2), dtype=np.uint16).reshape(H, W).copy())
    stamps.append(ts)


cb = DepthCB(on_depth)
lib.freenect_set_depth_callback(dev, cb)
mode = lib.freenect_find_depth_mode(1, 0)        # MEDIUM res, 11-bit depth
if not mode.is_valid:
    sys.exit("no valid depth mode")
lib.freenect_set_depth_mode(dev, mode)
if lib.freenect_start_depth(dev) < 0:
    lib.freenect_close_device(dev)
    lib.freenect_shutdown(ctx)
    sys.exit("freenect_start_depth failed")

t0 = time.time()
while time.time() - t0 < SECONDS:
    if lib.freenect_process_events(ctx) < 0:
        print("process_events error")
        break
dur = time.time() - t0

lib.freenect_stop_depth(dev)
lib.freenect_close_device(dev)
lib.freenect_shutdown(ctx)

if frames:
    stack = np.stack(frames)
    np.save(OUT, stack)
    valid = stack[(stack > 0) & (stack < 2047)]
    d = lambda r: int(1000 * 0.1236 * np.tan(r / 2842.5 + 1.1863))
    print(f"captured {len(frames)} frames in {dur:.1f}s ({len(frames)/dur:.1f} fps) -> {OUT}")
    print(f"valid-depth coverage: {100*valid.size/stack.size:.1f}%")
    print(f"raw range {valid.min()}..{valid.max()}  (~{d(valid.min())}mm..~{d(valid.max())}mm)")
else:
    print("no frames captured")
    sys.exit(1)
