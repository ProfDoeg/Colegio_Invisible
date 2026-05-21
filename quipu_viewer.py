"""
quipu_viewer.py — Streamlit viewer for the Colegio Invisible quipu corpus.

Reads data/quipu_data.csv + data/quipu_edges.csv + data/bodies/*.bin.
No RPC. Run with:

    .venv/bin/streamlit run quipu_viewer.py

Force-directed graph (Barnes-Hut physics via pyvis). One node per quipu.
Hover any node — the popup contains the decoded content inline:
  text: full prose
  image: rendered at native resolution
  cert: text body + inlined images referenced via <<txid>> citations
  encrypted: sub_family / variant; if keydrop, also shows each drop's
             decrypted target inline
  celestial: rendered constellation via canonical/celestial_render
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
    "image":      "#7eb4d8",
    "encrypted":  "#9b86c7",
    "cert":       "#86c786",
    "celestial":  "#86c7b4",
    "estandarte": "#d4a373",
    "identity":   "#c78686",
    "binding":    "#b0b0b0",
}
DEFAULT_COLOR = "#cccccc"

CITATION_RE = re.compile(r"<<\s*([0-9a-fA-F]{64})\s*>>(?:\s*<<\s*([^>]+?)\s*>>)?")

# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@st.cache_data
def load_quipus():
    df = pd.read_csv(os.path.join(REPO, "data", "quipu_data.csv"))
    df = df[df["root_txid"].notna()].copy()
    df["title"] = df["title"].fillna("")
    df["label"] = df["label"].fillna("(unknown)")
    return df

@st.cache_data
def load_edges():
    path = os.path.join(REPO, "data", "quipu_edges.csv")
    if not os.path.exists(path):
        return pd.DataFrame(columns=["source_quipu", "consumer_quipu", "kind"])
    return pd.read_csv(path)

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
    """Render a celestial quipu's constellation as a base64 PNG."""
    try:
        from celestial_render import render_celestial_quipu
        import matplotlib
        matplotlib.use("Agg")
        fig, ax = render_celestial_quipu(header, body)
        buf = io.BytesIO()
        fig.savefig(buf, format="PNG", bbox_inches="tight", dpi=110)
        import matplotlib.pyplot as plt
        plt.close(fig)
        data_url = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")
        return _img_tag(data_url, max_dim=420)
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
        "max-height:340px;overflow:auto;margin:6px 0;padding:8px;"
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
        body_offset = 6
        if len(blob) > 6 and blob[6:7] == b"|":
            close = blob.find(b"|", 7)
            if close > 0:
                body_offset = close + 1
        text_body = blob[body_offset:].decode("utf-8", errors="replace")
        body_html = render_text_with_citations(text_body, df_all)
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

    for _, q in df.iterrows():
        is_pre = q["canonical_status"] == "pre_canonical"
        color  = TYPE_COLORS.get(q["type_name"], DEFAULT_COLOR)
        size   = 22 + min(28, (q["total_bytes"] or 0) ** 0.32)

        title_text = q["title"] or f"({q['type_name']})"
        label_short = title_text[:22] + "…" if len(title_text) > 22 else title_text

        blob = load_body(q["root_txid"])
        contents[q["root_txid"]] = render_content_html(q, blob, df_all)

        kwargs = {
            "n_id":  q["root_txid"],
            "label": label_short,
            "title": f"{q['type_name']} · {title_text[:60]}",
            "color": {"background": color, "border": "#444"},
            "size":  size,
            "borderWidth": 1,
            "shape": "dot",
            "font":  {"size": 14, "face": "system-ui"},
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

    html = net.generate_html()

    # Inject a fixed-position popup + click handler that renders the
    # pre-computed HTML for whichever quipu node the user clicks.
    contents_js = json.dumps(contents)
    overlay = """
<div id="quipu-popup" style="display:none; position:fixed; top:16px; right:16px;
     max-width:480px; max-height:90vh; overflow-y:auto;
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
