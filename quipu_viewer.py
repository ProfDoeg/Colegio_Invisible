"""
quipu_viewer.py — Streamlit viewer for the Colegio Invisible quipu corpus.

Reads data/quipu_data.csv + data/quipu_edges.csv + data/bodies/*.bin.
No RPC. Run with:

    .venv/bin/streamlit run quipu_viewer.py

Force-directed graph (Barnes-Hut physics via pyvis). One node per quipu.
Hover any node — the popup contains the decoded content inline:
  text: full prose
  essay: markdown with citations + binding blocks resolved via the
         canonical/essay substitution engine, rendered to HTML
  image: rendered at native resolution
  cert: text body + inlined images referenced via <<txid>> citations
  encrypted: sub_family / variant; if keydrop, also shows each drop's
             decrypted target inline
  celestial: rendered constellation via canonical/celestial_render
  scene: glTF-shaped node list with object_kind, transform, and clickable
         quipu_ref per node (full walkable rendering lives in
         working/cemetery/cemetery.html)
  estandarte: parsed registry via canonical/estandarte
"""

from __future__ import annotations

import os
import sys
import re
import json
import base64
import html as html_lib
import io

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

REPO = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(REPO, "canonical"))
sys.path.insert(0, REPO)

TYPE_COLORS = {
    "text":       "#e6c97a",
    "essay":      "#d8b48a",
    "image":      "#7eb4d8",
    "encrypted":  "#9b86c7",
    "cert":       "#86c786",
    "celestial":  "#86c7b4",
    "scene":      "#c97e6e",
    "estandarte": "#d4a373",
    "identity":   "#c78686",
    "binding":    "#b0b0b0",
    "book":       "#b08a4a",
    "latex":      "#4a6b8a",
}
DEFAULT_COLOR = "#cccccc"

ADDRESS_COLORS = {
    "bordado":        "#c2a500",
    "apocrypha":      "#5d8aa8",
    "ha":             "#a86b91",
    "ca":             "#6ba891",
    "multiman":       "#a8716b",
    "test_multisig3": "#7a7aa8",
    "test1":          "#9b9b9b",
    "test2":          "#9b9b9b",
    "test3":          "#9b9b9b",
}

CITATION_RE = re.compile(r"<<\s*([0-9a-fA-F]{64})\s*>>(?:\s*<<\s*([^>]+?)\s*>>)?")

# Registry: scene root_txid → walkable WebGL renderer that knows how to
# stage that specific scene. Each renderer is a self-contained HTML file
# served by a local static server (since three.js needs HTTP, not file://).
SCENE_RENDERERS = {
    "1f63558bdee2f5ead118083ff0af0d5e266acaf347938c5ed2722b6ced1248e3": {
        "url":    "http://localhost:8765/cemetery.html",
        "label":  "Open walkable cemetery in 3D",
        "note":   "requires `python3 -m http.server 8765` in working/cemetery/",
    },
}

# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@st.cache_data
def _load_quipus_cached(mtime: float):
    df = pd.read_csv(os.path.join(REPO, "data", "quipu_data.csv"))
    df = df[df["root_txid"].notna()].copy()
    df["title"] = df["title"].fillna("")
    df["label"] = df["label"].fillna("(unknown)")
    return df

def load_quipus():
    """Mtime-keyed cache: edits to data/quipu_data.csv auto-invalidate
    without needing a Streamlit restart."""
    path = os.path.join(REPO, "data", "quipu_data.csv")
    return _load_quipus_cached(os.path.getmtime(path))

@st.cache_data
def _load_edges_cached(mtime: float):
    path = os.path.join(REPO, "data", "quipu_edges.csv")
    if not os.path.exists(path):
        return pd.DataFrame(columns=["source_quipu", "consumer_quipu", "kind"])
    return pd.read_csv(path)

def load_edges():
    """Mtime-keyed cache: edits to data/quipu_edges.csv auto-invalidate."""
    path = os.path.join(REPO, "data", "quipu_edges.csv")
    mtime = os.path.getmtime(path) if os.path.exists(path) else 0
    return _load_edges_cached(mtime)

def load_body(root_txid: str) -> bytes:
    path = os.path.join(REPO, "data", "bodies", f"{root_txid}.bin")
    if not os.path.exists(path):
        return b""
    return open(path, "rb").read()

# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def _image_blob_to_pil(blob: bytes, dims: dict):
    """Decode bit-packed image bytes -> PIL Image at native resolution."""
    import numpy as np
    from PIL import Image
    W, H = dims["W"], dims["H"]
    color = dims["color"]
    bd = dims["bit_depth"]
    ch = 1 if color == 0 else 3
    expected_body = (W * H * ch * bd + 7) // 8
    body_offset = len(blob) - expected_body
    if body_offset < 12:
        return None
    body = blob[body_offset:body_offset + expected_body]
    bits = []
    for byte in body:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    n_vals = W * H * ch
    values = []
    for i in range(n_vals):
        v = 0
        for j in range(bd):
            idx = i*bd + j
            v = (v << 1) | (bits[idx] if idx < len(bits) else 0)
        values.append(v)
    max_val = max((1 << bd) - 1, 1)
    arr = (pd.Series(values, dtype="uint64") * 255 // max_val).astype("uint8").to_numpy()
    if ch == 1:
        return Image.fromarray(arr.reshape((H, W)), mode="L")
    return Image.fromarray(arr.reshape((H, W, 3)), mode="RGB")


def _pil_to_data_url(img, fmt: str = "PNG") -> str:
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return f"data:image/{fmt.lower()};base64," + base64.b64encode(buf.getvalue()).decode("ascii")


def _img_tag(data_url: str, caption: str = "", max_dim: int = 360) -> str:
    return (
        f"<img src='{data_url}' style='display:block;max-width:{max_dim}px;"
        f"max-height:{max_dim}px;width:auto;height:auto;margin:6px auto;"
        f"border:1px solid #ccc'/>"
        + (f"<div style='font:11px ui-monospace;color:#888;text-align:center'>{caption}</div>"
           if caption else "")
    )


def render_image_html(blob: bytes, dims: dict) -> str:
    img = _image_blob_to_pil(blob, dims)
    if img is None:
        return "<div style='color:#a00'>image body math failed</div>"
    caption = (
        f"{dims.get('W')}×{dims.get('H')} · "
        f"{'grayscale' if dims.get('color')==0 else 'RGB'} · "
        f"{dims.get('bit_depth')}-bit"
    )
    return _img_tag(_pil_to_data_url(img), caption=caption)


def render_celestial_html(header: bytes, body: bytes) -> str:
    """Render a celestial quipu via the canonical matplotlib renderer
    (canonical/celestial_render.py), embed as a base64 PNG."""
    try:
        from celestial_render import render_celestial_quipu
        import matplotlib
        matplotlib.use("Agg")
        fig, ax = render_celestial_quipu(header, body)
        buf = io.BytesIO()
        fig.savefig(buf, format="PNG", bbox_inches="tight", dpi=120,
                    facecolor=fig.get_facecolor())
        import matplotlib.pyplot as plt
        plt.close(fig)
        data_url = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")
        return _img_tag(data_url, max_dim=460)
    except Exception as e:
        return f"<div style='color:#a00'>celestial render failed: {html_lib.escape(str(e))}</div>"


def _txid_to_row(df: pd.DataFrame, txid: str):
    matches = df[df["root_txid"] == txid]
    if matches.empty:
        # Try join_txid match
        matches = df[df["join_txid"] == txid]
    if matches.empty:
        return None
    return matches.iloc[0]


def render_text_with_citations(text: str, df_all: pd.DataFrame) -> str:
    """Render text with <<txid>> citations resolved to inline image previews."""
    out_parts = []
    last_end = 0
    for m in CITATION_RE.finditer(text):
        # Preserve text before this citation
        chunk = text[last_end:m.start()]
        out_parts.append(html_lib.escape(chunk))
        txid = m.group(1).lower()
        ref_row = _txid_to_row(df_all, txid)
        if ref_row is not None and ref_row["type_name"] == "image":
            ref_blob = load_body(ref_row["root_txid"])
            ref_dims = json.loads(ref_row["dimensions_json"] or "{}")
            ref_title = html_lib.escape(ref_row['title'] or '(no title)')
            click = f"window.showQuipuFor && window.showQuipuFor('{ref_row['root_txid']}')"
            out_parts.append(
                f"<div style='margin:8px 0;padding:6px;background:#f4f4f4;"
                f"border-left:3px solid #888'>"
                f"<div style='font:11px ui-monospace;color:#666'>"
                f"&lt;&lt;{txid[:12]}…&gt;&gt; → "
                f"<a onclick=\"{click}\" "
                f"style='color:#3a6ea6;cursor:pointer;text-decoration:underline'>"
                f"image: {ref_title}</a></div>"
                + render_image_html(ref_blob, ref_dims)
                + "</div>"
            )
        elif ref_row is not None:
            click = f"window.showQuipuFor && window.showQuipuFor('{ref_row['root_txid']}')"
            ref_title = html_lib.escape(ref_row['title'] or '(no title)')
            out_parts.append(
                f"<a onclick=\"{click}\" "
                f"style='cursor:pointer;text-decoration:none'>"
                f"<span style='font:11px ui-monospace;color:#3a6ea6;background:#eef4ff;"
                f"padding:1px 4px;border-radius:2px;border:1px solid #c0d4e8'>"
                f"&lt;&lt;{txid[:12]}…&gt;&gt; "
                f"<b>{html_lib.escape(ref_row['type_name'])}</b>"
                f": {ref_title}"
                f"</span></a>"
            )
        else:
            out_parts.append(
                f"<span style='font:11px ui-monospace;color:#aaa'>"
                f"&lt;&lt;{txid[:12]}…&gt;&gt;</span>"
            )
        last_end = m.end()
    out_parts.append(html_lib.escape(text[last_end:]))
    return (
        "<pre style='white-space:pre-wrap;font:12px/1.5 ui-sans-serif;"
        "margin:6px 0;padding:8px;"
        "background:#fafafa;border:1px solid #eee'>"
        + "".join(out_parts)
        + "</pre>"
    )


def render_encrypted_html(q: pd.Series, blob: bytes, df_all: pd.DataFrame) -> str:
    """For keydrops, inline each released target's decoded content."""
    if len(blob) < 8:
        return "<div style='color:#a00'>encrypted header too short</div>"
    sub = blob[6]
    var = blob[7]
    sub_name = {0xae: "AES", 0xec: "ECIES", 0x0d: "keydrop"}.get(sub, f"unknown_0x{sub:02x}")
    parts = [
        f"<div style='font:12px/1.4 system-ui;margin:8px 0'>"
        f"<b>sub_family:</b> 0x{sub:02x} ({sub_name}) · "
        f"<b>variant:</b> 0x{var:02x} · "
        f"<b>body:</b> {len(blob)-8} B"
        f"</div>"
    ]

    if sub == 0x0d:  # keydrop — list each released target
        try:
            from encrypted import read_encrypted_quipu, SUB_AES, SUB_ECIES
            parsed = read_encrypted_quipu(blob[:8], blob[8:])
            drops = parsed.get("drops", [])
            parts.append(f"<div style='font:600 12px system-ui;margin:8px 0 4px 0'>"
                         f"Drops ({len(drops)}):</div>")
            for d in drops:
                name = d.get("name") or "(anonymous)"
                ref_txid = d.get("ref_txid")
                key = d.get("key")
                ref_row = _txid_to_row(df_all, ref_txid)
                parts.append(
                    f"<div style='margin:6px 0;padding:6px;"
                    f"background:#f4f4f4;border-left:3px solid #9b86c7'>"
                    f"<div style='font:600 12px system-ui'>"
                    f"&laquo;{html_lib.escape(name)}&raquo;</div>"
                    f"<div style='font:11px ui-monospace;color:#666'>"
                    f"→ {ref_txid[:24]}…</div>"
                )
                if ref_row is None:
                    parts.append("<div style='color:#888;font-size:11px'>(target not in local corpus)</div>")
                else:
                    # Try to decrypt with the released key
                    try:
                        target_blob = load_body(ref_row["root_txid"])
                        # Split target into header/body based on its type
                        if target_blob[:4] == b"\xc1\xdd\x00\x01" and target_blob[4] == 0x0e:
                            hdr_end = 8
                            if hdr_end < len(target_blob) and target_blob[hdr_end:hdr_end+1] == b"|":
                                close = target_blob.find(b"|", hdr_end + 1)
                                if close > 0: hdr_end = close + 1
                            tgt_header = target_blob[:hdr_end]
                            tgt_body   = target_blob[hdr_end:]
                            sub_target = tgt_header[6]
                            if sub_target == SUB_AES:
                                tgt_parsed = read_encrypted_quipu(tgt_header, tgt_body, key=key)
                            elif sub_target == SUB_ECIES:
                                tgt_parsed = read_encrypted_quipu(tgt_header, tgt_body, session_key=key)
                            else:
                                tgt_parsed = None
                            if tgt_parsed and tgt_parsed.get("magic_ok"):
                                inner_h = tgt_parsed["inner_header"]
                                inner_b = tgt_parsed["inner_body"]
                                inner_type = inner_h[4]
                                if inner_type == 0x00:  # text
                                    from text import read_text_quipu
                                    inner = read_text_quipu(inner_h, inner_b)
                                    parts.append(
                                        f"<div style='font:12px system-ui;margin:6px 0 0 0'>"
                                        f"<b>recovered:</b> {html_lib.escape(inner.get('title',''))}</div>"
                                        f"<pre style='white-space:pre-wrap;font:12px ui-sans-serif;"
                                        f"max-height:160px;overflow:auto;margin:4px 0;padding:4px;"
                                        f"background:#fff;border:1px solid #ddd'>"
                                        + html_lib.escape(inner.get("body", ""))
                                        + "</pre>"
                                    )
                                else:
                                    parts.append(
                                        f"<div style='font:11px;color:#888;margin:4px 0'>"
                                        f"recovered inner type 0x{inner_type:02x} "
                                        f"({len(inner_b)} B body)</div>"
                                    )
                            else:
                                parts.append("<div style='color:#a00;font-size:11px'>decrypt failed</div>")
                    except Exception as e:
                        parts.append(f"<div style='color:#a00;font-size:11px'>decrypt error: "
                                     f"{html_lib.escape(str(e))}</div>")
                parts.append("</div>")
        except Exception as e:
            parts.append(f"<div style='color:#a00'>keydrop parse: {html_lib.escape(str(e))}</div>")
    else:
        parts.append("<div style='color:#888;font-size:11px'>encrypted — body sealed</div>")
    return "".join(parts)


def find_body_offset(blob: bytes) -> int:
    """For text (0x00) and essay (0x01), find where the body starts.

    Header format is `c1dd0001 + type + tone + |f0|f1|...|fN|` where each
    field is one of: title (first, no `=`) or key=value pair. The header
    ends at the last `|` before the body markdown. We walk pipes; a segment
    containing a newline marks where the body has started.
    """
    if len(blob) <= 6 or blob[6:7] != b"|":
        return 6
    pos = 7
    hdr_end = 7
    while pos < len(blob):
        close = blob.find(b"|", pos)
        if close < 0:
            break
        segment = blob[pos:close]
        if b"\n" in segment:
            # body markdown started — `close` is the first pipe inside the body
            break
        hdr_end = close + 1
        pos = close + 1
        if pos - 6 > 2048:  # sanity bound
            break
    return hdr_end


_BINDING_BLOCK_RE = re.compile(r"```binding\s*\n(.*?)\n```\s*", re.DOTALL)
_BINDING_IMPORT_RE = re.compile(r"<<\s*([0-9a-fA-F]{64})\s*>>")
_BINDING_SUBST_RE  = re.compile(r'^"((?:[^"\\]|\\.)*)"="((?:[^"\\]|\\.)*)"$')
_BARE_CITATION_RE = re.compile(r"<<\s*([0-9a-fA-F]{64})\s*>>")

def _try_transclude_thin_republish(body_md, df_all, depth=0):
    """If body is the "thin republish via binding" pattern — fenced
    ```binding``` block(s) importing 0xab bindings + a single bare
    <<essay_txid>> citation, nothing else — fetch the target essay,
    apply the imported bindings' substitution rules to its body, and
    return that substituted body to be rendered in place. Otherwise
    return None.

    Recursion depth is bounded so chained republishes terminate."""
    if depth > 4:
        return None

    # Pull out fenced binding blocks
    binding_txids = []
    stripped = body_md
    for m in _BINDING_BLOCK_RE.finditer(body_md):
        block = m.group(1)
        for im in _BINDING_IMPORT_RE.finditer(block):
            binding_txids.append(im.group(1).lower())
    stripped = _BINDING_BLOCK_RE.sub("", stripped).strip()

    if not binding_txids:
        return None  # no binding to apply; not a thin republish

    # The remaining body must be exactly one bare <<txid>> citation
    cites = _BARE_CITATION_RE.findall(stripped)
    non_citation = _BARE_CITATION_RE.sub("", stripped).strip()
    if len(cites) != 1 or non_citation:
        return None  # mixed content; not a clean republish

    target_txid = cites[0].lower()

    # Target must be an essay (type 0x01)
    target_row = df_all[df_all["root_txid"].astype(str).str.lower() == target_txid]
    if target_row.empty:
        return None
    if target_row.iloc[0]["type_name"] != "essay":
        return None

    target_blob = load_body(target_row.iloc[0]["root_txid"])
    if target_blob is None:
        return None

    target_body = target_blob[find_body_offset(target_blob):].decode("utf-8", errors="replace")

    # Apply each imported binding's substitution rules to the target body
    for btxid in binding_txids:
        bpath = os.path.join(REPO, "data", "bodies", f"{btxid}.bin")
        if not os.path.exists(bpath):
            continue
        bblob = open(bpath, "rb").read()
        if len(bblob) < 6 or bblob[4] != 0xab:
            continue
        bbody = bblob[6:].decode("utf-8", errors="replace")
        for line in bbody.splitlines():
            line = line.strip()
            m = _BINDING_SUBST_RE.match(line)
            if not m:
                continue
            find, replace = m.group(1), m.group(2)
            target_body = target_body.replace(find, replace)

    # The target body may itself be a thin republish — recurse
    nested = _try_transclude_thin_republish(target_body, df_all, depth=depth+1)
    if nested is not None:
        return nested
    return target_body


def _inject_annotations_html(html: str, bd, df_all) -> str:
    """Walk bd.annotations and inject sidenotes / endnotes / inline-brackets
    into `html` (post-markdown-render HTML). The renderer dispatches by the
    inscriber's per-note mode flag (@margin / @endnote / @inline).

    On the viewer's narrow popup widths, all modes effectively collapse to
    inline-below; full Tufte-style sidenote layout is for the standalone
    HTML build (`working/golem/built/book.html`-style artifacts) where
    horizontal space allows."""
    annotations = getattr(bd, "annotations", None)
    if not annotations:
        return html

    try:
        import markdown as md
    except ImportError:
        return html

    def render_note_md(note_md: str) -> str:
        try:
            return md.markdown(note_md, extensions=["extra", "sane_lists"])
        except Exception:
            return f"<p>{html_lib.escape(note_md)}</p>"

    used_anchors = set()
    counter = 0
    endnotes = []   # list of (n, anchor, note_html) for the endnotes section
    unattached = []

    for entry in annotations:
        anchor, note_md, position, flags = entry
        if not anchor or anchor in used_anchors:
            continue
        modes = [f for f in flags if f in ("margin", "endnote", "inline")]
        mode = modes[0] if modes else "margin"

        # Find anchor in html. Try direct first; loose fallback allows
        # markdown emphasis/code tags between anchor words.
        pos = html.find(anchor)
        end = pos + len(anchor) if pos >= 0 else -1
        if pos < 0:
            esc = re.escape(anchor)
            loose = esc.replace(r"\ ", r"\s*(?:<[^>]+>)*\s*")
            m = re.search(loose, html)
            if m:
                pos, end = m.start(), m.end()
        if pos < 0:
            unattached.append((anchor, render_note_md(note_md)))
            continue
        used_anchors.add(anchor)

        counter += 1
        n = counter
        note_html = render_note_md(note_md)
        ref = f'<sup class="ann-ref">{n}</sup>'

        if mode == "inline":
            marker = (
                f'{ref}<span class="annotation annotation-inline">'
                f'[<span class="ann-num">{n}</span>{note_html}]'
                f'</span>'
            )
        elif mode == "endnote":
            ref = (
                f'<sup class="ann-ref"><a href="#ann-end-{n}" '
                f'id="ann-ref-{n}">{n}</a></sup>'
            )
            marker = ref
            endnotes.append((n, anchor, note_html))
        else:  # margin (default)
            marker = (
                f'{ref}<span class="annotation annotation-margin">'
                f'<span class="ann-num">{n}</span>{note_html}'
                f'</span>'
            )

        html = html[:end] + marker + html[end:]

    # Append endnotes section if any @endnote annotations were emitted
    if endnotes:
        items = "".join(
            f'<li id="ann-end-{n}"><sup class="ann-num">{n}</sup> '
            f'<span class="ann-anchor-ref">on “{html_lib.escape(anchor)}”</span>'
            f' {note_html} <a href="#ann-ref-{n}" class="ann-back">↩</a></li>'
            for (n, anchor, note_html) in endnotes
        )
        html += (
            '<section class="endnotes"><h3>Notes</h3>'
            f'<ol class="endnotes-list">{items}</ol></section>'
        )

    # Surface unattached annotations in a colophon block (the inscriber's
    # intent is preserved even when the anchor doesn't match)
    if unattached:
        items = "".join(
            f'<li><em>{html_lib.escape(anchor)!s}</em>: {note_html}</li>'
            for (anchor, note_html) in unattached
        )
        html += (
            '<section class="unattached-notes">'
            '<h4>Unattached annotations</h4>'
            f'<ul>{items}</ul></section>'
        )

    # Always include the annotation CSS once the function has emitted markers
    if counter > 0 or unattached:
        html = _ANNOTATION_CSS + html

    return html


# CSS for annotation rendering. Inlined into the essay's HTML so the
# Streamlit popup styles correctly. Keep it self-contained — no external
# fonts or framework dependencies.
_ANNOTATION_CSS = """
<style scoped>
  sup.ann-ref { font: 600 0.7rem/1 ui-monospace,monospace;
                color: #8a4a3a; vertical-align: super; margin-left: 0.1em; }
  sup.ann-ref a { color: #8a4a3a; text-decoration: none; }
  .annotation { display: inline-block; vertical-align: top;
                font: 0.85rem/1.4 ui-sans-serif,system-ui,sans-serif;
                color: #444; margin: 0.2em 0 0.2em 0.4em;
                padding: 0.3em 0.6em; border-left: 2px solid #c2a76b;
                background: rgba(244,234,216,0.6); border-radius: 2px;
                max-width: 32em; }
  .annotation.annotation-margin { background: rgba(244,234,216,0.7); }
  .annotation.annotation-inline { background: rgba(244,234,216,0.4);
                                  display: inline; padding: 0.1em 0.35em;
                                  border-left: none;
                                  border-radius: 2px; }
  .annotation .ann-num { font: 600 0.7rem/1 ui-monospace,monospace;
                         color: #8a4a3a; margin-right: 0.4em; }
  .annotation p { margin: 0.2em 0; }
  .annotation em { font-style: italic; }
  .annotation code { font-size: 0.85em;
                     background: rgba(255,255,255,0.5); padding: 0 0.2em; }
  section.endnotes { margin-top: 1.5em; padding-top: 0.8em;
                     border-top: 1px solid #c2a76b;
                     font: 0.88rem/1.5 ui-sans-serif,system-ui,sans-serif; }
  section.endnotes h3 { font-size: 0.85rem; letter-spacing: 0.08em;
                        text-transform: uppercase; color: #888;
                        margin: 0 0 0.5em; }
  .endnotes-list { padding-left: 1.6em; }
  .endnotes-list li { margin-bottom: 0.5em; }
  .ann-anchor-ref { color: #888; font-style: italic; }
  .ann-back { color: #8a4a3a; text-decoration: none; margin-left: 0.4em; }
  section.unattached-notes { margin-top: 1.2em; padding: 0.6em 0.8em;
                              background: rgba(232,200,200,0.2);
                              border: 1px dashed #c08080; border-radius: 3px;
                              font-size: 0.82rem; color: #844; }
  section.unattached-notes h4 { margin: 0 0 0.4em; font-size: 0.78rem;
                                 letter-spacing: 0.06em;
                                 text-transform: uppercase; color: #844; }
  section.unattached-notes ul { margin: 0; padding-left: 1.4em; }
</style>
"""


def render_essay_html(blob: bytes, df_all: pd.DataFrame, extra_bd=None) -> str:
    """Run the canonical 0x01 essay substitution pipeline and render to HTML.

    Pipeline: extract fenced binding blocks → evaluate → resolve <<txid>>
    citations → emit plain markdown → convert to HTML. quipu:<txid> URLs
    inside the resolved markdown are rewritten to onclick handlers so they
    navigate to the target quipu in the viewer.

    If the body is a "thin republish via binding" (fenced binding-block
    imports + single citation to another essay, nothing else), transclude
    the target essay's body with the binding's substitutions applied,
    then render that. Implements the user-facing semantic that v2 of an
    essay should display as v1's full prose with corrections applied,
    not as a link to v1.
    """
    body_offset = find_body_offset(blob)
    body_md = blob[body_offset:].decode("utf-8", errors="replace")

    # Detect + apply thin-republish transclusion
    transcluded = _try_transclude_thin_republish(body_md, df_all)
    if transcluded is not None:
        body_md = transcluded

    # Build fetcher + title_lookup from the local corpus
    title_map = {
        str(r["root_txid"]).lower(): (r["title"] if isinstance(r["title"], str) else "")
        for _, r in df_all.iterrows()
        if isinstance(r.get("root_txid"), str)
    }
    def _fetcher(txid: str) -> bytes:
        path = os.path.join(REPO, "data", "bodies", f"{txid}.bin")
        if os.path.exists(path):
            return open(path, "rb").read()
        raise FileNotFoundError(f"{txid} not in local corpus")
    def _title_lookup(txid: str) -> str:
        return title_map.get(txid.lower(), "")

    try:
        from essay import substitute_body
        resolved_md, bd = substitute_body(body_md, fetcher=_fetcher,
                                           title_lookup=_title_lookup,
                                           extra_bd=extra_bd,
                                           return_bindings=True)
    except Exception as e:
        return (f"<div style='color:#a00'>essay substitution failed: "
                f"{html_lib.escape(str(e))}</div>"
                f"<pre style='white-space:pre-wrap;font:12px/1.5 ui-sans-serif;"
                f"margin:6px 0;padding:8px;background:#fafafa;border:1px solid #eee;"
                f"max-height:320px;overflow:auto'>"
                + html_lib.escape(body_md[:2000])
                + "</pre>")

    # Render the resolved markdown to HTML
    try:
        import markdown as md
        html = md.markdown(resolved_md, extensions=["extra", "tables", "sane_lists"])
    except Exception as e:
        html = f"<pre>{html_lib.escape(resolved_md[:3000])}</pre>"

    # v3 annotation primitive: walk bd.annotations, find anchors in rendered
    # HTML, inject sidenotes / endnotes / inline brackets per the inscriber's
    # chosen mode.
    html = _inject_annotations_html(html, bd, df_all)

    # Rewrite <img src="quipu:<txid>"> to inline data URLs (markdown image
    # syntax pointing at an image quipu). Must run BEFORE the link rewriter,
    # since <img> tags carry src= not href=.
    def _rewrite_img(m):
        txid = m.group(1).lower()
        target = df_all[df_all["root_txid"].astype(str).str.lower() == txid]
        if target.empty or target.iloc[0]["type_name"] != "image":
            return m.group(0)  # leave unchanged
        row = target.iloc[0]
        img_blob = load_body(row["root_txid"])
        if img_blob is None:
            return m.group(0)
        dims = json.loads(row["dimensions_json"] or "{}")
        pil = _image_blob_to_pil(img_blob, dims)
        if pil is None:
            return m.group(0)
        return f'src="{_pil_to_data_url(pil)}"'
    html = re.sub(r'src="quipu:([0-9a-fA-F]{64})"', _rewrite_img, html)

    # Rewrite quipu:<txid> URLs (and #subobj fragments) to onclick handlers
    def _rewrite(m):
        href = m.group(1)
        txid = href.split("#", 1)[0]
        click = f"window.showQuipuFor && window.showQuipuFor('{txid}')"
        return f'href="javascript:void(0)" onclick="{click}" style="color:#3a6ea6;text-decoration:underline;cursor:pointer"'
    html = re.sub(r'href="quipu:([0-9a-fA-F]{64}(?:#[^"]*)?)"', _rewrite, html)

    return (
        "<div style='font:13px/1.55 ui-sans-serif,system-ui,sans-serif;"
        "max-height:380px;overflow:auto;margin:8px 0;padding:10px;"
        "background:#fafafa;border:1px solid #eee;border-radius:4px'>"
        + html
        + "</div>"
    )


def render_scene_html(header: bytes, body: bytes, df_all: pd.DataFrame) -> str:
    """Render a 0x3d scene quipu: header fields + node list with clickable refs."""
    try:
        from scene import read_scene_quipu, scene_quipu_refs
        parsed = read_scene_quipu(header, body)
    except Exception as e:
        return (f"<div style='color:#a00'>scene parse failed: "
                f"{html_lib.escape(str(e))}</div>")

    nodes = parsed.get("nodes", [])
    title_map = {
        str(r["root_txid"]).lower(): (r["title"] if isinstance(r["title"], str) else "")
        for _, r in df_all.iterrows()
        if isinstance(r.get("root_txid"), str)
    }

    n_refs = len(scene_quipu_refs(parsed))
    summary_html = (
        f"<div style='font:12px/1.5 ui-sans-serif;color:#555;margin:6px 0'>"
        f"<b>{len(nodes)} nodes</b> · {n_refs} quipu references"
        f"</div>"
    )

    rows = []
    for i, node in enumerate(nodes):
        name = html_lib.escape(node.get("name", f"node[{i}]"))
        extras = node.get("extras") or {}
        kind = html_lib.escape(extras.get("object_kind", "—"))
        label = html_lib.escape(extras.get("label", ""))
        ref = extras.get("quipu_ref")
        if ref:
            ref_lo = ref.lower()
            ref_title = html_lib.escape(title_map.get(ref_lo, "")[:32])
            click = f"window.showQuipuFor && window.showQuipuFor('{ref_lo}')"
            ref_cell = (f"<a href='javascript:void(0)' onclick=\"{click}\" "
                        f"style='color:#3a6ea6;text-decoration:underline;cursor:pointer;"
                        f"font:11px ui-monospace'>{ref_lo[:12]}…</a>"
                        f" <span style='color:#888'>{ref_title}</span>")
        else:
            extras_summary = ""
            if extras.get("object_kind") == "camera" and extras.get("fov_deg"):
                extras_summary = f"fov {extras['fov_deg']}°"
            elif extras.get("object_kind") == "celestial":
                lat, lon = extras.get("latitude_deg"), extras.get("longitude_deg")
                if lat is not None and lon is not None:
                    extras_summary = f"lat {lat}° lon {lon}°"
            ref_cell = f"<span style='color:#aaa'>{html_lib.escape(extras_summary or '(no ref)')}</span>"

        t = node.get("translation")
        t_str = (f"({t[0]:.1f}, {t[1]:.1f}, {t[2]:.1f})"
                 if isinstance(t, list) and len(t) == 3 else "")

        rows.append(
            f"<tr><td style='color:#888;font:10px ui-monospace;padding:2px 6px'>{i}</td>"
            f"<td style='padding:2px 6px'>{name}</td>"
            f"<td style='color:#666;padding:2px 6px;font:11px'>{kind}</td>"
            f"<td style='color:#888;font:10px ui-monospace;padding:2px 6px'>{t_str}</td>"
            f"<td style='padding:2px 6px'>{ref_cell}"
            f"{(' — ' + label) if label else ''}</td></tr>"
        )

    table_html = (
        "<table style='border-collapse:collapse;font:11px/1.4 ui-sans-serif;"
        "margin:6px 0;background:#fafafa;width:100%;border:1px solid #eee'>"
        "<thead><tr style='background:#f0f0f0;border-bottom:1px solid #ddd'>"
        "<th style='text-align:left;padding:3px 6px;color:#777'>#</th>"
        "<th style='text-align:left;padding:3px 6px;color:#777'>name</th>"
        "<th style='text-align:left;padding:3px 6px;color:#777'>kind</th>"
        "<th style='text-align:left;padding:3px 6px;color:#777'>xyz</th>"
        "<th style='text-align:left;padding:3px 6px;color:#777'>ref / extras</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )

    return (
        "<div style='font:13px/1.55 ui-sans-serif,system-ui,sans-serif;"
        "max-height:380px;overflow:auto;margin:8px 0;padding:10px;"
        "background:#fafafa;border:1px solid #eee;border-radius:4px'>"
        + summary_html + table_html
        + "</div>"
    )


def _split_typographic_header_body(blob: bytes, type_byte: int) -> tuple:
    """Locate the byte boundary between a pipe-delimited header tail and
    the body for text/essay/latex-style headers (any type that uses the
    text-derived header grammar). Walks every '|' until the closing pipe,
    then body begins at the next byte."""
    pos = 6
    if len(blob) > 6 and blob[6] == ord('|'):
        # Header is `|field1|field2|...|`; final '|' is followed by body
        nxt = pos
        while True:
            nxt = blob.find(b'|', nxt + 1)
            if nxt < 0:
                break
            # If the next byte after this pipe is NOT in the header tail's
            # printable-pipe vocabulary, the body has started here.
            # For typographic types, the body starts immediately after the
            # last pipe — keep walking until we find a pipe followed by a
            # non-printable byte or another pipe-like-but-empty-field.
            pos = nxt
            # Heuristic: header tail's fields can contain UTF-8 chars but no
            # newlines; if the next chunk before another '|' contains \n or
            # we're at the last '|', we're done.
            tail_until_next = blob[nxt+1:blob.find(b'|', nxt+1) if blob.find(b'|', nxt+1) > 0 else len(blob)]
            if b'\n' in tail_until_next or blob.find(b'|', nxt+1) < 0:
                pos = nxt + 1
                break
    return blob[:pos], blob[pos:]


def render_latex_html(blob: bytes) -> str:
    """Render a 0x5c latex quipu by compiling the body to PDF via the
    declared engine, rasterizing to PNG via ghostscript, and embedding
    as a data URL. The rendered PNG is cached by SHA-256 of the body
    bytes so re-renders are free."""
    import hashlib
    import shutil
    import subprocess
    import tempfile

    try:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "canonical"))
        from latex import read_latex_quipu, compile_to_pdf
    except Exception as e:
        return f"<div style='color:#a00'>latex module import failed: {html_lib.escape(str(e))}</div>"

    header, body = _split_typographic_header_body(blob, 0x5c)
    try:
        parsed = read_latex_quipu(header, body)
    except Exception as e:
        return (f"<div style='color:#a00'>latex parse failed: {html_lib.escape(str(e))}</div>"
                f"<pre style='font:11px ui-monospace;color:#666;max-height:200px;overflow:auto'>"
                f"{html_lib.escape(blob[:512].hex())}…</pre>")

    fields_html = ""
    if parsed["fields"]:
        rows = "".join(
            f"<tr><td style='color:#888;padding-right:8px'>{html_lib.escape(k)}</td>"
            f"<td>{html_lib.escape(v)}</td></tr>"
            for k, v in parsed["fields"].items()
        )
        fields_html = (
            f"<table style='font:11px/1.4 ui-monospace;margin:4px 0 8px 0'>{rows}</table>"
        )

    cache_dir = os.path.join(REPO, "data", "latex_cache")
    os.makedirs(cache_dir, exist_ok=True)
    digest = hashlib.sha256(body).hexdigest()
    png_path = os.path.join(cache_dir, f"{digest}.png")

    if not os.path.exists(png_path):
        try:
            pdf_bytes = compile_to_pdf(parsed["tex_source"], engine=parsed["engine"])
        except Exception as e:
            err = html_lib.escape(str(e)[:1500])
            return (fields_html
                    + f"<div style='color:#a00;font:11px ui-monospace;"
                      f"background:#fef0f0;border:1px solid #e8b0b0;"
                      f"padding:6px;border-radius:3px'>"
                      f"<b>latex compile failed</b><br>"
                      f"<pre style='white-space:pre-wrap;font-size:10px;"
                      f"max-height:240px;overflow:auto'>{err}</pre></div>")
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            f.write(pdf_bytes)
            pdf_path = f.name
        try:
            if shutil.which("gs"):
                subprocess.run(
                    ["gs", "-sDEVICE=pngalpha", "-r150", "-dNOPAUSE", "-dBATCH",
                     f"-sOutputFile={png_path}", pdf_path],
                    capture_output=True, timeout=30,
                )
            else:
                return (fields_html
                        + "<div style='color:#a00'>ghostscript (gs) not on PATH; "
                        + "cannot rasterize latex output</div>")
        finally:
            try:
                os.remove(pdf_path)
            except OSError:
                pass

    if os.path.exists(png_path):
        with open(png_path, "rb") as f:
            data_url = "data:image/png;base64," + base64.b64encode(f.read()).decode("ascii")
        return (fields_html
                + f"<img src='{data_url}' style='display:block;max-width:100%;"
                  f"height:auto;margin:6px auto;border:1px solid #ddd'/>"
                + f"<div style='font:10px ui-monospace;color:#aaa;text-align:center'>"
                  f"compiled {len(body):,} B of {html_lib.escape(parsed['engine'])} source"
                  f"</div>")
    return fields_html + "<div style='color:#a00'>no rendered PNG produced</div>"


def _split_book_header_body(blob: bytes) -> tuple:
    """Locate the byte boundary between a book's pipe-delimited header tail
    and the version-prefixed body. Mirrors parse_dims's logic in NB 60."""
    pos = 6
    if len(blob) > 6 and blob[6] == ord('|'):
        while True:
            nxt = blob.find(b'|', pos + 1)
            if nxt < 0:
                break
            if nxt + 1 < len(blob) and blob[nxt + 1] == 0x01:
                pos = nxt + 1
                break
            pos = nxt
    return blob[:pos], blob[pos:]


def _evaluate_book_bindings(parsed_book: dict, df_all: pd.DataFrame):
    """Walk a parsed book's tag=binding entries, fetch each binding quipu's
    bytes from the local corpus, and accumulate their rules into a single
    BindingDict. Returns None if there are no binding entries or canonical
    bindings module is unavailable."""
    binding_entries = [e for e in parsed_book["entries"] if e["tag"] == "binding"]
    if not binding_entries:
        return None
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "canonical"))
        from bindings import BindingDict, evaluate as evaluate_binding
    except Exception:
        return None

    def _fetcher(txid: str) -> bytes:
        path = os.path.join(REPO, "data", "bodies", f"{txid}.bin")
        if os.path.exists(path):
            return open(path, "rb").read()
        raise FileNotFoundError(f"{txid} not in local corpus")

    merged = BindingDict()
    visited = {}
    for entry in binding_entries:
        try:
            child = evaluate_binding(entry["ref_txid"], _fetcher, visited=visited)
            merged.merge(child)
        except Exception:
            # Skip unresolvable bindings silently — caller falls back to
            # rendering essays without the book's overlay
            continue
    return merged


def render_book_html(blob: bytes, df_all: pd.DataFrame) -> str:
    """Render a 0x09 book as an expandable manifest. Each tag=essay/* entry
    gets a `<details>` block; expanding it renders that essay's body with
    the book's tag=binding entries merged into the substitution pipeline
    (so bindings declared at the book level tunnel into each essay's
    render)."""
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "canonical"))
        from book import read_book_quipu
    except Exception as e:
        return f"<div style='color:#a00'>book module import failed: {html_lib.escape(str(e))}</div>"

    header, body = _split_book_header_body(blob)
    try:
        parsed = read_book_quipu(header, body)
    except Exception as e:
        return f"<div style='color:#a00'>book parse failed: {html_lib.escape(str(e))}</div>"

    fields_html = ""
    if parsed["fields"]:
        rows = "".join(
            f"<tr><td style='color:#888;padding-right:8px'>{html_lib.escape(k)}</td>"
            f"<td>{html_lib.escape(v)}</td></tr>"
            for k, v in parsed["fields"].items()
        )
        fields_html = (
            f"<table style='font:11px/1.4 ui-monospace;margin:4px 0 10px 0'>{rows}</table>"
        )

    # Evaluate book-level bindings ONCE; they tunnel into every essay render
    book_bd = _evaluate_book_bindings(parsed, df_all)
    book_bindings_note = ""
    if book_bd is not None and (book_bd.aliases or book_bd.substitutions or book_bd.citations):
        n_a = len(book_bd.aliases)
        n_s = len(book_bd.substitutions)
        n_c = len(book_bd.citations)
        book_bindings_note = (
            f"<div style='font:11px/1.4 ui-monospace;color:#8a4a3a;"
            f"background:#fdf3ef;border-left:3px solid #c97e6e;"
            f"padding:6px 10px;margin:6px 0'>"
            f"book carries {n_a} alias{'es' if n_a != 1 else ''}, "
            f"{n_s} substitution{'s' if n_s != 1 else ''}, "
            f"{n_c} citation rule{'s' if n_c != 1 else ''} — "
            f"these tunnel into each essay's render below"
            f"</div>"
        )

    entry_blocks = []
    for e in parsed["entries"]:
        tag      = html_lib.escape(e["tag"])
        name     = html_lib.escape(e["name"] or "(no name)")
        ref_txid = e["ref_txid"]
        ref_row  = _txid_to_row(df_all, ref_txid)
        ref_type = ref_row["type_name"] if ref_row is not None else None
        short_id = f"{ref_txid[:12]}…"

        # Compact header line for every entry
        if ref_row is not None:
            click = f"window.showQuipuFor && window.showQuipuFor('{ref_row['root_txid']}')"
            header_line = (
                f"<div style='display:flex;align-items:baseline;gap:8px;padding:4px 0'>"
                f"<span style='font:11px ui-monospace;color:#555;min-width:70px'>{tag}</span>"
                f"<a onclick=\"{click}\" "
                f"style='cursor:pointer;color:#3a6ea6;text-decoration:none;font-size:13px;flex:1'>"
                f"{name}</a>"
                f"<span style='color:#888;font-size:10px'>{html_lib.escape(ref_type or '?')}</span>"
                f"<span style='font:10px ui-monospace;color:#aaa'>{short_id}</span>"
                f"</div>"
            )
        else:
            header_line = (
                f"<div style='display:flex;align-items:baseline;gap:8px;padding:4px 0;opacity:0.6'>"
                f"<span style='font:11px ui-monospace;color:#555;min-width:70px'>{tag}</span>"
                f"<span style='font-size:13px;flex:1'>{name}</span>"
                f"<span style='font:10px ui-monospace;color:#aaa'>{short_id}</span>"
                f"</div>"
            )

        # Inline expandable rendering for essay entries (the read-through view)
        if ref_row is not None and ref_type == "essay" and tag.startswith("essay/"):
            essay_blob = load_body(ref_row["root_txid"])
            if essay_blob:
                inline = render_essay_html(essay_blob, df_all, extra_bd=book_bd)
                entry_blocks.append(
                    f"<details style='margin:2px 0;border:1px solid #eee;border-radius:3px'>"
                    f"<summary style='cursor:pointer;padding:0 6px'>{header_line}</summary>"
                    f"<div style='padding:6px 10px;background:#fafafa;"
                    f"border-top:1px solid #eee;max-height:480px;overflow:auto'>"
                    f"{inline}"
                    f"</div></details>"
                )
                continue

        # Default: just the header line, no expansion
        entry_blocks.append(
            f"<div style='border:1px solid #eee;border-radius:3px;margin:2px 0;"
            f"padding:0 6px'>{header_line}</div>"
        )

    table_html = (
        f"<div style='font:11px ui-monospace;color:#666;margin-top:4px'>"
        f"version 0x{parsed['version']:02x} · {len(parsed['entries'])} entries</div>"
        + book_bindings_note
        + "".join(entry_blocks)
    )
    return fields_html + table_html


def render_content_html(q: pd.Series, blob: bytes, df_all: pd.DataFrame) -> str:
    """Build the full per-node HTML popup."""
    t = q["type_name"]
    title = html_lib.escape(q["title"] or "(no title)")
    header_meta = (
        f"<div style='font:11px/1.4 ui-monospace,monospace;color:#666'>"
        f"type {q['type_byte']} ({t}) · tone {q['tone']} ({q['tone_name']})<br>"
        f"{q['label']} · block {q.get('blockheight', '?')} · "
        f"{q['total_bytes']} B · {q['canonical_status']}"
        f"</div>"
    )
    title_html = f"<div style='font:600 14px/1.3 system-ui,sans-serif;margin:0 0 6px 0'>{title}</div>"

    body_html = ""
    if t == "text":
        text_body = blob[find_body_offset(blob):].decode("utf-8", errors="replace")
        body_html = render_text_with_citations(text_body, df_all)
    elif t == "essay":
        body_html = render_essay_html(blob, df_all)
    elif t == "book":
        body_html = render_book_html(blob, df_all)
    elif t == "latex":
        body_html = render_latex_html(blob)
    elif t == "image":
        dims = json.loads(q["dimensions_json"] or "{}")
        if dims.get("W"):
            body_html = render_image_html(blob, dims)
    elif t == "cert":
        cert_body = blob[8:].decode("utf-8", errors="replace")
        body_html = render_text_with_citations(cert_body, df_all)
    elif t == "encrypted":
        body_html = render_encrypted_html(q, blob, df_all)
    elif t == "celestial":
        # Celestial has variable header length (12 + T); read_celestial_quipu
        # needs the proper split, so we re-derive from the structural bytes.
        if len(blob) >= 12:
            T = blob[11]
            header_len = 12 + T
            body_html = render_celestial_html(blob[:header_len], blob[header_len:])
    elif t == "scene":
        body_start = blob.find(b"|{", 6)
        if body_start > 0:
            body_html = render_scene_html(blob[:body_start+1], blob[body_start+1:], df_all)
            renderer = SCENE_RENDERERS.get(q["root_txid"])
            if renderer:
                body_html = (
                    "<div style='margin:8px 0;padding:8px 10px;background:#fdf3ef;"
                    "border:1px solid #c97e6e;border-radius:4px'>"
                    f"<a href='{renderer['url']}' target='_blank' "
                    "style='font:600 13px/1.4 system-ui;color:#8a4a3a;"
                    "text-decoration:none'>"
                    f"{html_lib.escape(renderer['label'])} &rarr;</a>"
                    "<div style='font:10px/1.3 ui-monospace;color:#888;"
                    "margin-top:4px'>"
                    f"{html_lib.escape(renderer['note'])}"
                    "</div></div>"
                ) + body_html
    elif t == "estandarte":
        try:
            from estandarte import read_estandarte_quipu, format_estandarte
            parsed = read_estandarte_quipu(blob[:6], blob[6:])
            body_html = (
                "<pre style='font:11px/1.3 ui-monospace;max-height:320px;"
                "overflow:auto;margin:6px 0;padding:6px;background:#fafafa;"
                "border:1px solid #eee'>"
                + html_lib.escape(format_estandarte(parsed)[:3500])
                + "</pre>"
            )
        except Exception as e:
            body_html = f"<div style='color:#a00'>estandarte parse: {html_lib.escape(str(e))}</div>"
    else:
        body_html = (
            f"<pre style='font:11px ui-monospace;color:#888;margin:6px 0'>"
            f"{blob[:64].hex()}…</pre>"
        )

    return (
        "<div style='max-width:440px;padding:8px;font-family:system-ui,sans-serif'>"
        + title_html + header_meta + body_html
        + f"<div style='font:10px ui-monospace;color:#aaa;margin-top:6px;"
          f"word-break:break-all'>{q['root_txid']}</div>"
        + "</div>"
    )

# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------

def render_graph(df: pd.DataFrame, edges: pd.DataFrame, df_all: pd.DataFrame,
                 height_px: int = 820) -> str:
    from pyvis.network import Network

    net = Network(
        height=f"{height_px}px",
        width="100%",
        bgcolor="#fafafa",
        font_color="#222",
        directed=True,
        notebook=False,
    )
    net.barnes_hut(
        gravity=-3500,
        central_gravity=0.3,
        spring_length=160,
        spring_strength=0.03,
        damping=0.5,
    )

    visible = set(df["root_txid"])
    contents = {}  # txid -> HTML for popup

    # Populate popup contents for EVERY quipu in df_all, not just the
    # filtered visible set, so clickable citations in essay popups
    # always resolve — even when the target quipu is currently filtered
    # out of the graph. The graph still only shows `visible` nodes;
    # filtering hides nodes but doesn't disable click-through navigation.
    for _, q in df_all.iterrows():
        if not isinstance(q.get("root_txid"), str):
            continue
        blob = load_body(q["root_txid"])
        if blob is None:
            continue
        contents[q["root_txid"]] = render_content_html(q, blob, df_all)

    for _, q in df.iterrows():
        is_pre = q["canonical_status"] == "pre_canonical"
        color  = TYPE_COLORS.get(q["type_name"], DEFAULT_COLOR)
        size   = 22 + min(28, (q["total_bytes"] or 0) ** 0.32)

        title_text = q["title"] or f"({q['type_name']})"
        label_short = title_text[:22] + "…" if len(title_text) > 22 else title_text

        kwargs = {
            "n_id":  q["root_txid"],
            "label": label_short,
            "title": f"{q['type_name']} · {title_text[:60]}",
            "color": {"background": color, "border": "#444"},
            "size":  size,
            "borderWidth": 1,
            "shape": "dot",
            "font":  {"size": 14, "face": "system-ui"},
            "group": q["label"],  # used by the cellular-hull overlay
        }
        if is_pre:
            kwargs["color"] = {"background": "#dcdcdc", "border": "#888"}
            kwargs["borderWidth"] = 2
        net.add_node(**kwargs)

    for _, e in edges.iterrows():
        kind = e.get("kind")
        src = e.get("source_quipu", "")
        dst = e.get("consumer_quipu", "")
        if src not in visible or dst not in visible:
            continue
        if kind == "funding":
            net.add_edge(src, dst, color="#888", width=1.5, arrows="to")
        elif kind == "keydrop":
            net.add_edge(src, dst, color="#9b86c7", width=2.0,
                         arrows="to", dashes=[6, 6])
        elif kind == "citation_image":
            # solid teal — the embodied subject of a cert
            net.add_edge(src, dst, color="#3aa6a6", width=2.5, arrows="to")
        elif kind == "citation_auth":
            # red dot-dash — certificate authority (parent of trust chain)
            net.add_edge(src, dst, color="#c45050", width=2.0,
                         arrows="to", dashes=[2, 6])
        elif kind == "citation":
            # generic prose citation — thin orange
            net.add_edge(src, dst, color="#d4a373", width=1.2,
                         arrows="to", dashes=[3, 3])
        elif isinstance(kind, str) and kind.startswith("citation_scene"):
            # scene composition: this scene quipu places that quipu's
            # content into walkable space. Solid terracotta — same hue
            # as the scene node color.
            net.add_edge(src, dst, color="#c97e6e", width=2.0, arrows="to")
        elif kind == "binding_import":
            # an essay imports an 0xab binding's rules into its scope
            # via a fenced ```binding block. Warm tan, solid, medium.
            net.add_edge(src, dst, color="#a89860", width=2.0, arrows="to")
        elif kind == "previous":
            # essay header `previous=<txid>` field marks supersession.
            # Long-dashed muted purple, arrow pointing back at the
            # predecessor.
            net.add_edge(src, dst, color="#6b5b8a", width=1.6,
                         arrows="to", dashes=[8, 4])

    html = net.generate_html()

    # Inject a fixed-position popup + click handler that renders the
    # pre-computed HTML for whichever quipu node the user clicks.
    # Escape </script> in the embedded HTML so the browser's HTML parser
    # doesn't close the outer <script> early — classic XSS-style pitfall.
    contents_js = json.dumps(contents).replace("</script>", "<\\/script>")
    overlay = """
<div id="quipu-popup" style="display:none; position:fixed; top:12px; right:12px;
     max-width:520px; max-height:calc(100vh - 24px); overflow-y:auto;
     background:white; border:2px solid #999; border-radius:10px;
     padding:6px; z-index:9999;
     box-shadow:0 8px 24px rgba(0,0,0,0.25);
     font-family:-apple-system,Helvetica,Arial,sans-serif;"></div>
<script>
var QUIPU_CONTENTS = """ + contents_js + """;
(function() {
    function closePopup() {
        document.getElementById('quipu-popup').style.display = 'none';
    }
    // Expose so inline onclick="..." in citation links can call it
    window.showQuipuFor = function(nodeId) { showFor(nodeId); };
    function showFor(nodeId) {
        var popup = document.getElementById('quipu-popup');
        if (QUIPU_CONTENTS[nodeId]) {
            popup.innerHTML = QUIPU_CONTENTS[nodeId] +
                '<div style="text-align:right;margin:6px 8px 4px 8px">' +
                '<button onclick="document.getElementById(\\'quipu-popup\\').style.display=\\'none\\'" ' +
                'style="padding:4px 12px;cursor:pointer;border:1px solid #888;' +
                'background:#f5f5f5;border-radius:4px;font-size:11px">close</button>' +
                '</div>';
            popup.style.display = 'block';
            popup.scrollTop = 0;
            /* innerHTML does not auto-execute inserted scripts; recreate them */
            popup.querySelectorAll('script').forEach(function(oldScript) {
                var s = document.createElement('script');
                s.text = oldScript.text;
                oldScript.parentNode.replaceChild(s, oldScript);
            });
        } else {
            popup.style.display = 'none';
        }
    }
    function bind() {
        if (typeof network !== 'undefined' && network) {
            // Click to pin a popup (scrollable). Click empty space or the
            // close button to dismiss.
            network.on('click', function(params) {
                if (params.nodes && params.nodes.length > 0) {
                    showFor(params.nodes[0]);
                } else {
                    closePopup();
                }
            });
            attachCellularHull();
        } else {
            setTimeout(bind, 120);
        }
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bind);
    } else {
        bind();
    }
})();

// ===== Cellular convex-hull overlay by address group =====
var ADDRESS_COLORS = """ + json.dumps(ADDRESS_COLORS) + """;

function _convexHull(pts) {
    if (pts.length < 3) return pts.slice();
    var sorted = pts.slice().sort(function(a, b) {
        return a.x === b.x ? a.y - b.y : a.x - b.x;
    });
    function cross(O, A, B) {
        return (A.x - O.x) * (B.y - O.y) - (A.y - O.y) * (B.x - O.x);
    }
    var lower = [];
    for (var i = 0; i < sorted.length; i++) {
        while (lower.length >= 2 && cross(lower[lower.length-2], lower[lower.length-1], sorted[i]) <= 0) lower.pop();
        lower.push(sorted[i]);
    }
    var upper = [];
    for (var i = sorted.length - 1; i >= 0; i--) {
        while (upper.length >= 2 && cross(upper[upper.length-2], upper[upper.length-1], sorted[i]) <= 0) upper.pop();
        upper.push(sorted[i]);
    }
    return lower.slice(0, -1).concat(upper.slice(0, -1));
}

function _expandHull(hull, pad) {
    var cx = 0, cy = 0;
    hull.forEach(function(p) { cx += p.x; cy += p.y; });
    cx /= hull.length; cy /= hull.length;
    return hull.map(function(p) {
        var dx = p.x - cx, dy = p.y - cy;
        var d = Math.sqrt(dx*dx + dy*dy) || 1;
        return { x: p.x + dx / d * pad, y: p.y + dy / d * pad };
    });
}

function _drawSmoothPolygon(ctx, pts) {
    if (pts.length < 3) return;
    ctx.beginPath();
    var n = pts.length;
    var midX = (pts[0].x + pts[n-1].x) / 2;
    var midY = (pts[0].y + pts[n-1].y) / 2;
    ctx.moveTo(midX, midY);
    for (var i = 0; i < n; i++) {
        var p = pts[i];
        var pn = pts[(i + 1) % n];
        var mx = (p.x + pn.x) / 2;
        var my = (p.y + pn.y) / 2;
        ctx.quadraticCurveTo(p.x, p.y, mx, my);
    }
    ctx.closePath();
}

function attachCellularHull() {
    if (typeof network === 'undefined' || !network) return;

    var hullCache = {};      // group -> {hull: [...], centroid: {x, y}}
    function recomputeHulls() {
        var groups = {};
        network.body.data.nodes.getIds().forEach(function(id) {
            var nd = network.body.data.nodes.get(id);
            if (!nd) return;
            var grp = nd.group;
            if (!grp || !ADDRESS_COLORS[grp]) return;
            var pos = network.getPositions([id])[id];
            if (!pos) return;
            if (!groups[grp]) groups[grp] = [];
            groups[grp].push(pos);
        });
        var next = {};
        Object.keys(groups).forEach(function(grp) {
            var pts = groups[grp];
            var cx = 0, cy = 0;
            pts.forEach(function(p) { cx += p.x; cy += p.y; });
            cx /= pts.length; cy /= pts.length;
            if (pts.length === 1) {
                next[grp] = { hull: null, centroid: { x: cx, y: cy }, single: true, point: pts[0] };
            } else if (pts.length === 2) {
                // Capsule perpendicular to the line through the two points
                var p0 = pts[0], p1 = pts[1];
                var dx = p1.x - p0.x, dy = p1.y - p0.y;
                var d = Math.sqrt(dx*dx + dy*dy) || 1;
                var ux = dx / d, uy = dy / d;          // unit along the line
                var nx = -uy, ny = ux;                  // perpendicular
                var width = 50;                          // half-thickness of capsule
                var endpad = 40;                         // extension past each endpoint
                var corners = [
                    { x: p0.x - ux*endpad + nx*width, y: p0.y - uy*endpad + ny*width },
                    { x: p1.x + ux*endpad + nx*width, y: p1.y + uy*endpad + ny*width },
                    { x: p1.x + ux*endpad - nx*width, y: p1.y + uy*endpad - ny*width },
                    { x: p0.x - ux*endpad - nx*width, y: p0.y - uy*endpad - ny*width },
                ];
                next[grp] = { hull: corners, centroid: { x: cx, y: cy } };
            } else {
                next[grp] = { hull: _expandHull(_convexHull(pts), 40), centroid: { x: cx, y: cy } };
            }
        });
        hullCache = next;
    }

    var recomputeTimer = setInterval(recomputeHulls, 250);
    network.on('stabilizationIterationsDone', function() {
        recomputeHulls();
        clearInterval(recomputeTimer);
        recomputeTimer = setInterval(recomputeHulls, 1500);
    });
    network.on('dragEnd', recomputeHulls);

    network.on('afterDrawing', function(ctx) {
        Object.keys(hullCache).forEach(function(grp) {
            var entry = hullCache[grp];
            if (!entry) return;
            var color = ADDRESS_COLORS[grp];
            // Tinted hull
            if (entry.hull && entry.hull.length >= 3) {
                ctx.save();
                _drawSmoothPolygon(ctx, entry.hull);
                ctx.fillStyle = color + "1a";   // ~10% alpha
                ctx.fill();
                ctx.strokeStyle = color + "66"; // ~40% alpha
                ctx.lineWidth = 1.5;
                ctx.stroke();
                ctx.restore();
            } else if (entry.single) {
                // Lone node — draw a small ring around it
                ctx.save();
                ctx.beginPath();
                ctx.arc(entry.point.x, entry.point.y, 40, 0, Math.PI * 2);
                ctx.fillStyle = color + "1a";
                ctx.fill();
                ctx.strokeStyle = color + "66";
                ctx.lineWidth = 1.2;
                ctx.stroke();
                ctx.restore();
            }
            // Label at centroid
            ctx.save();
            ctx.font = "600 16px system-ui, sans-serif";
            ctx.textAlign = "center";
            ctx.textBaseline = "middle";
            ctx.fillStyle = color;
            ctx.fillText(grp, entry.centroid.x, entry.centroid.y);
            ctx.restore();
        });
    });
}
</script>
"""
    html = html.replace("</body>", overlay + "</body>")
    return html

# ---------------------------------------------------------------------------
# Streamlit
# ---------------------------------------------------------------------------

st.set_page_config(page_title="Quipu Viewer", layout="wide")
st.title("Colegio Invisible — Quipu Viewer")

df_all = load_quipus()
edges_all = load_edges()

with st.sidebar:
    st.header("Filter")
    labels = sorted(df_all["label"].unique())
    sel_labels = st.multiselect("address", labels, default=labels)
    types = sorted(df_all["type_name"].unique())
    sel_types = st.multiselect("type", types, default=types)
    statuses = sorted(df_all["canonical_status"].unique())
    sel_statuses = st.multiselect("canonical status", statuses, default=statuses)

df = df_all[
    df_all["label"].isin(sel_labels)
    & df_all["type_name"].isin(sel_types)
    & df_all["canonical_status"].isin(sel_statuses)
].copy()

with st.sidebar:
    st.markdown(f"**{len(df)} of {len(df_all)} inscriptions shown**")
    st.markdown("---")
    st.caption(
        "Hover any node to see its decoded content (text, image, "
        "constellation, decrypted keydrop targets, etc). "
        "Drag to rearrange · scroll-wheel to zoom."
    )

if df.empty:
    st.info("No inscriptions match the current filters.")
else:
    html = render_graph(df, edges_all, df_all)
    components.html(html, height=850, scrolling=False)
