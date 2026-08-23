#!/usr/bin/env python3
"""Capture quipu_out/pulse_story.html frame by frame with headless Chromium.

The page (build_pulse_story_page.py) exposes window.__frame(i) and
window.__total; this driver steps every frame and screenshots 1080x1920
PNGs into pulse_web_frames/. Encoding happens on nodus, which has ffmpeg.

  python3 render_pulse_story_web.py [--test]
"""
import os, sys
from playwright.sync_api import sync_playwright

HERE = os.path.dirname(os.path.abspath(__file__))
PAGE = os.path.join(HERE, 'quipu_out', 'pulse_story.html')
OUT = os.path.join(HERE, 'pulse_web_frames')


def main():
    test = '--test' in sys.argv
    os.makedirs(OUT, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(args=['--force-color-profile=srgb',
                                          '--disable-lcd-text'])
        page = browser.new_page(viewport={'width': 1080, 'height': 1920},
                                device_scale_factor=1)
        page.goto('file://' + PAGE)
        page.wait_for_function('window.__ready === true', timeout=60000)
        total = page.evaluate('window.__total')
        frames = [0, total // 2, total - 1] if test else range(total)
        for i in frames:
            year = page.evaluate(f'window.__frame({i})')
            page.screenshot(path=os.path.join(OUT, 'f%04d.png' % i))
            if test or i % 100 == 0:
                print('frame', i, year, flush=True)
        browser.close()
    print('wrote frames to', OUT)


if __name__ == '__main__':
    main()
