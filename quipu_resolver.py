#!/usr/bin/env python3
"""
quipu_resolver.py — the publication platform's front door.

Given a quipu txid (or a `quipu:<txid>` / `quipu://<txid>` URI), detect the
inscription's type and render it with the matching renderer, producing a
viewable artifact:

    0x3d scene      → self-contained WebGL walkthrough  (scene_viewer.py)
    0x09 book       → typeset PDF                        (colegio_pipeline)
    0x5c latex      → typeset PDF                        (colegio_pipeline)
    0x01 essay      → typeset PDF                        (colegio_pipeline)
    0x03 image      → PNG
    0xce celestial  → star-chart PNG
    0x00 text       → HTML
    0xab binding    → HTML (source)

Three front doors, one core (`build_artifact`):

    serve   — a localhost gateway: GET /q/<txid> resolves + serves the
              artifact. The dev substrate; works in any browser now.
    uri     — the scheme-handler entry point: parse a quipu: URI, build,
              and OS-open the artifact. (macOS .app installed by
              `install-macos` registers the `quipu` scheme to call this.)
    build   — build the artifact and print its path.

Reads bodies from data/bodies/<txid>.bin (local dataset; no RPC).
The robust link in a colegio PDF stays `quipu:<txid>` — this resolver is
what gives that permanent address something to launch.
"""
from __future__ import annotations

import os
import re
import sys
import base64
import subprocess

REPO = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO)

import colegio_pipeline as P
import scene_viewer as SV

CACHE = os.path.join(REPO, "working", "pipeline", "quipu_cache")
_TXID_RE = re.compile(r"[0-9a-fA-F]{64}")

# type byte → (label, artifact extension)
_KIND = {
    0x3d: ("scene",     "scene.html",     "text/html"),
    0x09: ("book",      "doc.pdf",        "application/pdf"),
    0x5c: ("latex",     "doc.pdf",        "application/pdf"),
    0x01: ("essay",     "doc.pdf",        "application/pdf"),
    0x03: ("image",     "image.png",      "image/png"),
    0xce: ("celestial", "celestial.png",  "image/png"),
    0x00: ("text",      "text.html",      "text/html"),
    0xab: ("binding",   "binding.html",   "text/html"),
}


def extract_txid(s):
    """Pull a 64-hex txid out of a bare id or a quipu:/quipu:// URI."""
    m = _TXID_RE.search(s or "")
    if not m:
        raise ValueError(f"no txid found in {s!r}")
    return m.group(0).lower()


_ADDR_RE = re.compile(r"[A-Za-z0-9]{26,40}")   # base58 Dogecoin address shape
_HEXKEY_RE = re.compile(r"[0-9a-fA-F]{16,}")    # a public-key hex run


def scheme_of(uri):
    """The URL scheme of a quipu/addr/key URI, lowercased. '' if bare."""
    m = re.match(r"^([a-z]+):", (uri or "").strip(), re.I)
    return m.group(1).lower() if m else ""


def extract_addr(s):
    """Pull a base58 address out of an `addr:<address>` URI (or bare addr)."""
    body = re.sub(r"^addr:/*", "", (s or "").strip(), flags=re.I)
    m = _ADDR_RE.search(body)
    if not m:
        raise ValueError(f"no address found in {s!r}")
    return m.group(0)


def extract_key(s):
    """Pull a hex public key out of a `key:<pubkey>` URI (or bare hex)."""
    body = re.sub(r"^key:/*", "", (s or "").strip(), flags=re.I)
    m = _HEXKEY_RE.search(body)
    if not m:
        raise ValueError(f"no key found in {s!r}")
    return m.group(0).lower()


def _text_html(title, body_text, kind_label, txid):
    import html
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>{html.escape(title or kind_label)}</title>"
        "<style>body{max-width:42rem;margin:3rem auto;padding:0 1.5rem;"
        "font:16px/1.6 Georgia,serif;color:#1a1a1a;background:#faf6ec}"
        "pre{white-space:pre-wrap;word-wrap:break-word}"
        ".meta{font:12px ui-monospace,monospace;color:#8a7a55}</style></head><body>"
        f"<div class='meta'>{kind_label} · quipu:{txid}</div>"
        f"<h1>{html.escape(title or '')}</h1>"
        f"<pre>{html.escape(body_text)}</pre></body></html>"
    )


def resolve(txid, fetcher=None):
    """Lightweight metadata for a txid: {txid, type_byte, type, title}."""
    fetcher = fetcher or P.chained_fetcher()
    blob = fetcher(txid)
    t = P.type_of(blob)
    return {"txid": txid, "type_byte": t,
            "type": _KIND.get(t, ("?", "", ""))[0],
            "title": SV._header_fields(blob)[0] or P.title_of(blob)}


def build_artifact(txid, work_dir=None, fetcher=None):
    """Render `txid` to a viewable file. Returns (path, content_type)."""
    fetcher = fetcher or P.chained_fetcher()
    work_dir = work_dir or os.path.join(CACHE, txid)
    os.makedirs(work_dir, exist_ok=True)
    blob = fetcher(txid)
    t = P.type_of(blob)

    if t == 0x3d:
        out = os.path.join(work_dir, "scene.html")
        SV.build_scene_viewer(txid, out, fetcher=fetcher)
        return out, "text/html"

    if t == 0x09:
        return P.render_book(txid, work_dir, fetcher=fetcher), "application/pdf"

    if t == 0x5c:
        return P.render_latex_quipu(txid, work_dir, fetcher=fetcher), "application/pdf"

    if t == 0x01:
        figdir = os.path.join(work_dir, "figures")
        tex = P.essay_to_tex(txid, fetcher=fetcher, figdir=figdir)
        for ft in set(P._QFIG_RE.findall(tex)) | set(P._IMG_MACRO_TXID_RE.findall(tex)):
            try:
                P.target_to_png(ft, fetcher, figdir)
            except Exception:
                pass
        return P.compile_tex(tex, work_dir, figdir=figdir), "application/pdf"

    if t == 0x03:
        out = os.path.join(work_dir, "image.png")
        uri = SV._image_to_png_datauri(blob, txid=txid)
        with open(out, "wb") as f:
            f.write(base64.b64decode(uri.split(",", 1)[1]))
        return out, "image/png"

    if t == 0xce:
        from celestial_render import render_celestial_quipu
        out = os.path.join(work_dir, "celestial.png")
        h, b = SV._split_concat(blob)
        render_celestial_quipu(h, b, output_path=out)
        return out, "image/png"

    if t in (0x00, 0xab):
        out = os.path.join(work_dir, "view.html")
        title, _ = SV._header_fields(blob)
        body = blob[P._pipe_header_body_offset(blob):].decode("utf-8", "replace")
        label = _KIND.get(t, ("quipu",))[0]
        with open(out, "w", encoding="utf-8") as f:
            f.write(_text_html(title, body, f"0x{t:02x} {label}", txid))
        return out, "text/html"

    # unknown type → info page
    out = os.path.join(work_dir, "view.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(_text_html("", f"(no renderer for type 0x{t:02x})",
                           f"0x{t:02x}", txid))
    return out, "text/html"


# ---------------------------------------------------------------------------
# addr: and key: resolution — index pages built from the local dataset
#
# The Reference Index in a colegio book links inscribing addresses as
# addr:<address> and signing keys as key:<pubkey>. These resolve to small
# index pages: an address lists every inscription it signed (each a
# quipu: link); a key lists the certificates that name it and the human
# name it is bound to. Both read from data/quipu_data.csv + the cert
# bodies — no chain access needed.
# ---------------------------------------------------------------------------

def _index_html(title, rows_html, subtitle=""):
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>{title}</title>"
        "<style>body{max-width:46rem;margin:3rem auto;padding:0 1.5rem;"
        "font:16px/1.6 Georgia,serif;color:#1a1a1a;background:#faf6ec}"
        ".meta{font:12px ui-monospace,monospace;color:#8a7a55;word-break:break-all}"
        "table{border-collapse:collapse;width:100%;margin-top:1rem}"
        "td{padding:.3rem .6rem;border-bottom:1px solid #e6dcc2;vertical-align:top}"
        "td.t{font:12px ui-monospace,monospace;color:#8a7a55}"
        "a{color:#1a1a1a}</style></head><body>"
        f"<h1>{title}</h1>"
        f"<div class='meta'>{subtitle}</div>"
        f"<table>{rows_html}</table></body></html>"
    )


def build_addr_artifact(addr, work_dir=None):
    """An HTML index of every inscription signed by `addr`. Reads
    data/quipu_data.csv. Returns (path, 'text/html')."""
    import csv as _csv, html as _html
    work_dir = work_dir or os.path.join(CACHE, "addr", addr)
    os.makedirs(work_dir, exist_ok=True)
    csv_path = os.path.join(REPO, "data", "quipu_data.csv")
    label, rows = "", []
    if os.path.exists(csv_path):
        with open(csv_path, newline="", encoding="utf-8") as f:
            for r in _csv.DictReader(f):
                if r.get("address") == addr:
                    label = label or r.get("label", "")
                    rows.append(r)
    rows.sort(key=lambda r: (r.get("blockheight") or "", r.get("root_txid", "")))
    body = "".join(
        "<tr>"
        f"<td class='t'>0x{r.get('type_byte','').lstrip('0x'):>2}</td>"
        f"<td>{_html.escape(r.get('title') or '(untitled)')}"
        f"<br><a href='quipu:{r['root_txid']}' class='t'>"
        f"quipu:{r['root_txid'][:24]}…</a></td>"
        "</tr>"
        for r in rows
    ) or "<tr><td>(no inscriptions found for this address)</td></tr>"
    out = os.path.join(work_dir, "addr.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(_index_html(
            f"Address · {_html.escape(label or addr)}",
            body, subtitle=f"addr:{addr} — {len(rows)} inscription(s)"))
    return out, "text/html"


def build_key_artifact(pubkey, work_dir=None):
    """An HTML page naming `pubkey`: the human name it is bound to and the
    certificate(s) that name it. Walks cert bodies in data/bodies. Returns
    (path, 'text/html')."""
    import csv as _csv, html as _html
    work_dir = work_dir or os.path.join(CACHE, "key", pubkey[:16])
    os.makedirs(work_dir, exist_ok=True)
    fetcher = P.chained_fetcher()
    csv_path = os.path.join(REPO, "data", "quipu_data.csv")
    key_re = re.compile(r"([A-Z][A-Za-z]*)_Public\s*[:=]\s*(?:0x)?([0-9a-fA-F]{8,})")
    name, certs = "", []
    if os.path.exists(csv_path):
        with open(csv_path, newline="", encoding="utf-8") as f:
            for r in _csv.DictReader(f):
                if r.get("type_byte") != "0xcc":
                    continue
                try:
                    blob = fetcher(r["root_txid"])
                    text = blob[8:].decode("utf-8", "ignore")
                except Exception:
                    continue
                for m in key_re.finditer(text):
                    if m.group(2).lower().startswith(pubkey[:16]):
                        name = name or m.group(1)
                        certs.append((r["root_txid"], r.get("title") or ""))
    body = "".join(
        "<tr>"
        f"<td>{_html.escape(title or '(untitled cert)')}"
        f"<br><a href='quipu:{txid}' class='t'>quipu:{txid[:24]}…</a></td>"
        "</tr>"
        for txid, title in certs
    ) or "<tr><td>(no certificate names this key in the local dataset)</td></tr>"
    out = os.path.join(work_dir, "key.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(_index_html(
            f"Key · {_html.escape(name or 'unknown')}",
            body, subtitle=f"key:{pubkey[:32]}… — named in {len(certs)} cert(s)"))
    return out, "text/html"


# ---------------------------------------------------------------------------
# Front door 1 — localhost gateway
# ---------------------------------------------------------------------------

def serve(port=8723):
    """Run the localhost gateway. GET /q/<txid> resolves + serves."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            sys.stderr.write("[gateway] " + (a[0] % a[1:]) + "\n")

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(200, "text/html",
                           b"<h1>quipu gateway</h1><p>GET /q/&lt;txid&gt;</p>")
                return
            m = re.match(r"/q/([0-9a-fA-F]{64})", self.path)
            if not m:
                self._send(404, "text/plain", b"not found")
                return
            txid = m.group(1).lower()
            try:
                path, ctype = build_artifact(txid)
                with open(path, "rb") as f:
                    self._send(200, ctype, f.read())
            except Exception as e:
                self._send(500, "text/plain",
                           f"resolve error: {e}".encode("utf-8"))

        def _send(self, code, ctype, body):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    print(f"quipu gateway on http://127.0.0.1:{port}/q/<txid>  (ctrl-c to stop)")
    srv.serve_forever()


# ---------------------------------------------------------------------------
# Front door 2 — quipu: scheme handler (OS-open the artifact)
# ---------------------------------------------------------------------------

def os_open(path):
    if sys.platform == "darwin":
        subprocess.run(["open", path])
    elif sys.platform.startswith("linux"):
        subprocess.run(["xdg-open", path])
    else:
        os.startfile(path)  # type: ignore[attr-defined]


def open_uri(uri):
    """Scheme-handler entry: dispatch a quipu: / addr: / key: URI to the
    right builder and OS-open the resulting artifact."""
    scheme = scheme_of(uri)
    if scheme == "addr":
        path, _ = build_addr_artifact(extract_addr(uri))
    elif scheme == "key":
        path, _ = build_key_artifact(extract_key(uri))
    else:                                   # quipu: (or a bare txid)
        path, _ = build_artifact(extract_txid(uri))
    os_open(path)
    return path


# ---------------------------------------------------------------------------
# macOS quipu: scheme registration (AppleScript .app handler)
# ---------------------------------------------------------------------------

_APPLESCRIPT = '''on open location this_URL
\tdo shell script {py} & " " & {script} & " uri " & quoted form of this_URL
end open location
on run
\tdisplay dialog "Quipu handler installed. It opens quipu:, addr:, and key: links." buttons {{"OK"}} default button 1
end run
'''

# The single handler app claims all three corpus schemes; open_uri
# dispatches by scheme. quipu: → the inscription's rendered artifact;
# addr: → an index of that address's inscriptions; key: → the certs
# that name that key.
_HANDLER_SCHEMES = ("quipu", "addr", "key")


def install_macos(app_dir=None):
    """Build a QuipuHandler.app that registers the `quipu`, `addr`, and
    `key` URL schemes and routes their clicks to `open_uri`. macOS only."""
    if sys.platform != "darwin":
        raise SystemExit("install-macos is macOS-only")
    import shutil
    app_dir = app_dir or os.path.join(REPO, "working", "pipeline")
    app = os.path.join(app_dir, "QuipuHandler.app")
    src = os.path.join(app_dir, "_quipu_handler.applescript")
    py = sys.executable
    script = os.path.join(REPO, "quipu_resolver.py")
    os.makedirs(app_dir, exist_ok=True)
    with open(src, "w") as f:
        f.write(_APPLESCRIPT.replace("{py}", f'"{py}"').replace("{script}", f'"{script}"'))
    if os.path.exists(app):
        shutil.rmtree(app)
    subprocess.run(["osacompile", "-o", app, src], check=True)
    plist = os.path.join(app, "Contents", "Info.plist")
    pb = "/usr/libexec/PlistBuddy"
    cmds = ["Add :CFBundleURLTypes array"]
    for i, scheme in enumerate(_HANDLER_SCHEMES):
        cmds += [
            f"Add :CFBundleURLTypes:{i}:CFBundleURLName string Colegio-{scheme}",
            f"Add :CFBundleURLTypes:{i}:CFBundleURLSchemes array",
            f"Add :CFBundleURLTypes:{i}:CFBundleURLSchemes:0 string {scheme}",
        ]
    for c in cmds:
        subprocess.run([pb, "-c", c, plist], check=True)
    # register with LaunchServices
    lsreg = ("/System/Library/Frameworks/CoreServices.framework/Versions/A/"
             "Frameworks/LaunchServices.framework/Versions/A/Support/lsregister")
    if os.path.exists(lsreg):
        subprocess.run([lsreg, "-f", app])
    print(f"built + registered {app}  (schemes: {', '.join(_HANDLER_SCHEMES)})")
    print('test:  open "quipu:1f63558bdee2f5ead118083ff0af0d5e266acaf347938c5ed2722b6ced1248e3"')
    print('       open "addr:9xth7DcLGb1nACScMBeSfDCfghhLKF7yqs"')
    print('       open "key:505d743671977487"')
    return app


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return
    cmd = argv[0]
    if cmd == "serve":
        serve(int(argv[1]) if len(argv) > 1 else 8723)
    elif cmd == "uri":
        print(open_uri(argv[1]))
    elif cmd == "open":
        print(open_uri(argv[1]))
    elif cmd == "build":
        path, ctype = build_artifact(extract_txid(argv[1]),
                                     argv[2] if len(argv) > 2 else None)
        print(f"{ctype}\t{path}")
    elif cmd == "addr":
        path, ctype = build_addr_artifact(extract_addr(argv[1]))
        print(f"{ctype}\t{path}")
    elif cmd == "key":
        path, ctype = build_key_artifact(extract_key(argv[1]))
        print(f"{ctype}\t{path}")
    elif cmd == "resolve":
        print(resolve(extract_txid(argv[1])))
    elif cmd == "install-macos":
        install_macos(argv[1] if len(argv) > 1 else None)
    else:
        raise SystemExit(f"unknown command {cmd!r}")


if __name__ == "__main__":
    _main(sys.argv[1:])
