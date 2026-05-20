"""
quipu_viewer.py — Streamlit viewer for the Colegio Invisible quipu corpus.

Reads data/quipu_data.csv + data/quipu_edges.csv + data/bodies/*.bin.
No RPC. Run with:

    .venv/bin/streamlit run quipu_viewer.py

Force-directed graph (Barnes-Hut physics via pyvis). One node per quipu.
Click a node to see its decoded content in the right column.
"""

from __future__ import annotations

import os
import sys
import json
import datetime as dt

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

REPO = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(REPO, "canonical"))
sys.path.insert(0, REPO)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

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

ADDRESS_LABELS = {
    "9xth7DcLGb1nACScMBeSfDCfghhLKF7yqs": "bordado",
    "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX": "apocrypha",
    "A7pfCe2Cw9JD2C4vEZbpDmUZJy7B2TaefV": "ha",
    "AD28bxzxyrd3a4Qgad2VNQ2eN5Leg8ozuw": "ca",
    "A3ShjwjsAE4ysM66EZJM3A28tPnL2jNDgC": "multiman",
    "A3ABo52FjMJ57KSjbKyfe9aiKkH2jntXHY": "test_multisig3",
}

# ---------------------------------------------------------------------------
# Data loading
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
# Topology — pyvis force-directed
# ---------------------------------------------------------------------------

def render_graph(df: pd.DataFrame, edges: pd.DataFrame, height_px: int = 720) -> str:
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
        gravity=-3000,
        central_gravity=0.3,
        spring_length=140,
        spring_strength=0.04,
        damping=0.5,
    )

    visible = set(df["root_txid"])

    for _, q in df.iterrows():
        is_pre = q["canonical_status"] == "pre_canonical"
        color  = TYPE_COLORS.get(q["type_name"], DEFAULT_COLOR)
        size   = 18 + min(20, (q["total_bytes"] or 0) ** 0.3)

        title = q["title"] or "(no title)"
        title_short = title[:24] + "…" if len(title) > 24 else title
        date_str = ""
        if pd.notna(q.get("blocktime")):
            try:
                date_str = dt.datetime.fromtimestamp(int(q["blocktime"])).strftime("%Y-%m-%d")
            except Exception:
                pass

        tooltip = (
            f"{q['type_name']} · {q['tone_name']}\n"
            f"{q['label']}\n"
            f"{title}\n"
            f"{q['total_bytes']} B · {date_str}\n"
            f"root: {q['root_txid'][:24]}…"
        )

        kwargs = {
            "n_id":  q["root_txid"],
            "label": f"{title_short or q['type_name']}",
            "title": tooltip,
            "color": {"background": color, "border": "#444"},
            "size":  size,
            "borderWidth": 1,
        }
        if is_pre:
            kwargs["color"] = {"background": "#e0e0e0", "border": "#999"}
            kwargs["borderWidth"] = 2
            kwargs["borderWidthSelected"] = 4
            kwargs["shape"] = "dot"
            kwargs["title"] = "PRE-CANONICAL\n" + tooltip
        # No pre-funded broomheads in this corpus yet; the pre-funded La Verna
        # and third bordado roots aren't in quipu_data.csv (they have no
        # strands inscribed) — they'd appear as hexagons here if/when added.
        net.add_node(**kwargs)

    for _, e in edges.iterrows():
        src = e.get("source_quipu", "")
        dst = e.get("consumer_quipu", "")
        if e.get("kind") != "funding": continue
        if src not in visible or dst not in visible: continue
        net.add_edge(src, dst, color="#999", width=1.2, arrows="to")

    # Address clustering hint: subtle group attribute so users can color
    # by address in the UI if desired
    return net.generate_html()

# ---------------------------------------------------------------------------
# Content decoding — per-type
# ---------------------------------------------------------------------------

def decode_content(q: pd.Series, blob: bytes):
    """Return (kind, payload) where kind is one of 'text', 'image', 'cert',
    'encrypted', 'celestial', 'estandarte', 'raw'. Payload is whatever's
    most useful for that kind."""
    t = q["type_name"]
    dims = json.loads(q["dimensions_json"] or "{}")
    if t == "text":
        body_offset = 6
        if len(blob) > 6 and blob[6:7] == b"|":
            close = blob.find(b"|", 7)
            if close > 0:
                body_offset = close + 1
        return "text", blob[body_offset:].decode("utf-8", errors="replace")
    if t == "image" and dims.get("W"):
        try:
            import numpy as np
            W, H, color, bd = dims["W"], dims["H"], dims["color"], dims["bit_depth"]
            ch = 1 if color == 0 else 3
            expected_body = (W * H * ch * bd + 7) // 8
            body_offset = len(blob) - expected_body
            if body_offset < 12:
                return "raw", blob.hex()[:1000]
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
            max_val = (1 << bd) - 1
            arr = np.array(values, dtype=np.float32) / max_val
            if ch == 1:
                arr = arr.reshape((H, W))
            else:
                arr = arr.reshape((H, W, 3))
            return "image", arr
        except Exception as e:
            return "raw", f"image render failed: {e}"
    if t == "cert":
        return "text", blob[8:].decode("utf-8", errors="replace")
    if t == "encrypted":
        return "encrypted", {
            "sub_family": f"0x{blob[6]:02x}" if len(blob) > 6 else "?",
            "variant":    f"0x{blob[7]:02x}" if len(blob) > 7 else "?",
            "body_len":   len(blob) - 8,
        }
    if t == "celestial":
        return "celestial", dims
    if t == "estandarte":
        try:
            from estandarte import read_estandarte_quipu, format_estandarte
            parsed = read_estandarte_quipu(blob[:6], blob[6:])
            return "text", format_estandarte(parsed)
        except Exception as e:
            return "raw", f"estandarte parse failed: {e}"
    return "raw", blob.hex()[:1000]

# ---------------------------------------------------------------------------
# Streamlit layout
# ---------------------------------------------------------------------------

st.set_page_config(page_title="Quipu Viewer", layout="wide")
st.title("Colegio Invisible — Quipu Viewer")

df_all = load_quipus()
edges_all = load_edges()

# Sidebar filters
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
    st.markdown(f"**Showing {len(df)} of {len(df_all)} inscriptions**")
    st.markdown("---")
    st.caption(
        "Node = one quipu (root_txid). Color = type. "
        "Greyed-out nodes are pre-canonical. "
        "Edges show funding flow between quipus."
    )

# Two-column layout: graph + content
col_graph, col_detail = st.columns([3, 2])

with col_graph:
    st.subheader("Topology")
    html = render_graph(df, edges_all)
    components.html(html, height=750, scrolling=False)

with col_detail:
    st.subheader("Inscription detail")

    # Quipu picker — sorted by blockheight
    df_sorted = df.sort_values("blockheight", na_position="last")
    options = []
    label_map = {}
    for _, q in df_sorted.iterrows():
        title = q["title"] or f"(no title — {q['type_name']})"
        label = f"{q['label']}: {title[:50]} [{q['type_name']}]"
        options.append(q["root_txid"])
        label_map[q["root_txid"]] = label

    if not options:
        st.info("No inscriptions match the current filters.")
    else:
        selected = st.selectbox(
            "Pick an inscription:",
            options,
            format_func=lambda t: label_map.get(t, t),
        )

        q = df[df["root_txid"] == selected].iloc[0]
        blob = load_body(selected)

        st.markdown(f"**{q['title'] or '(no title)'}**")
        st.markdown(
            f"`{selected[:32]}…` · type **{q['type_byte']}** ({q['type_name']}) · "
            f"tone {q['tone']} ({q['tone_name']}) · "
            f"**{q['canonical_status']}**"
        )
        st.caption(f"{q['total_bytes']} bytes · {q['label']} · block {q.get('blockheight', '?')}")

        kind, payload = decode_content(q, blob)

        if kind == "text":
            st.text(payload[:5000])
        elif kind == "image":
            import numpy as np
            st.image(payload, use_container_width=True, clamp=True)
            d = json.loads(q["dimensions_json"] or "{}")
            st.caption(
                f"{d.get('W')}×{d.get('H')} · "
                f"{'grayscale' if d.get('color')==0 else 'RGB'} · "
                f"{d.get('bit_depth')}-bit"
            )
        elif kind == "encrypted":
            st.write("**Encrypted quipu — body not decryptable from viewer**")
            st.json(payload)
        elif kind == "celestial":
            st.write("**Celestial quipu**")
            st.json(payload)
            st.caption("Render via canonical/celestial_render in a notebook for full constellation view.")
        elif kind == "raw":
            st.caption("Raw bytes preview:")
            st.code(payload, language="text")
