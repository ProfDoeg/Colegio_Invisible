"""
quipu_console.py — Streamlit interface for inscribing quipus.

Run with:
    streamlit run quipu_console.py

Three tabs:
  Plan      — pick type/title/tone, upload payload, configure encoding,
              see image preview (for image quipus) before committing.
  Inscribe  — two-phase build:
                Phase 1: instantiate (build + broadcast root tx, wait 1 conf)
                Phase 2: fill (precompute all strands, broadcast in parallel)
                Phase 3: close (joining tx, consolidate strand termini)
  Read      — fetch any quipu from chain by txid, decode and display.

Requires a running Dogecoin Core node (RPC creds in .env).
Requires the apocrypha key file (or any key file) accessible via import_privKey.
"""

import io
import os
import sys
import time
from pathlib import Path

import numpy as np
import streamlit as st
from PIL import Image

import eth_keys

sys.path.insert(0, str(Path(__file__).resolve().parent))

import colegio_tools as ct
from quipu_crypto import combine_pubkeys
from quipu_orchestrator import (
    Quipu,
    STATE_INIT, STATE_ROOT_BUILT, STATE_ROOT_BROADCAST, STATE_ROOT_CONFIRMED,
    STATE_STRANDS_PRECOMPUTED, STATE_STRANDS_BROADCAST, STATE_STRANDS_CONFIRMED,
    STATE_JOIN_BUILT, STATE_JOIN_BROADCAST, STATE_DONE,
)


# ----------------------------------------------------------------------
# Page setup
# ----------------------------------------------------------------------

st.set_page_config(page_title="Colegio Invisible — Quipu Console", layout="wide")
st.title("Colegio Invisible — Quipu Console")

# ----------------------------------------------------------------------
# Sidebar — identity and node
# ----------------------------------------------------------------------

with st.sidebar:
    st.header("Identity")
    default_key = str(Path.home() / "Desktop" / "cinv" / "llaves" / "mi_prv.enc")
    key_path = st.text_input("Key file", default_key)
    password = st.text_input("Password", value="", type="password",
                             help="Empty string for the apocrypha test key")

    if st.button("Load key", use_container_width=True):
        try:
            priv = ct.import_privKey(key_path, password)
            priv_hex = priv.to_hex()[2:]
            import cryptos
            doge = cryptos.Doge()
            addr = doge.privtoaddr(priv_hex)
            st.session_state.priv_hex = priv_hex
            st.session_state.addr = addr
            st.success(f"Loaded {addr}")
        except Exception as e:
            st.error(f"Key load failed: {e}")

    if "addr" in st.session_state:
        st.write(f"**Address:**")
        st.code(st.session_state.addr, language=None)
        try:
            ut = ct.rpc_request("listunspent", [0, 9999999, [st.session_state.addr]])
            total = sum(u["amount"] for u in ut)
            st.write(f"**Balance:** {total} DOGE ({len(ut)} UTXOs)")
            st.session_state.utxos = ut
        except Exception as e:
            st.error(f"Balance query failed: {e}")

    st.divider()
    st.header("AES key")
    aes_source = st.radio(
        "Source",
        ["Password string", "Key file"],
        horizontal=True,
        key="aes_source_choice",
        help="Used to read 0x0e 0xae sealed quipus, and as a fallback for "
             "broadcast quipus when the loaded privkey is not a recipient.",
    )

    if aes_source == "Password string":
        st.caption("SHA-256(password) → 32-byte AES key.")
        aes_pw_in = st.text_input(
            "Password",
            value=(st.session_state.get("aes_password", "")
                   if isinstance(st.session_state.get("aes_password"), str) else ""),
            type="password", key="aes_pw_input",
        )
        st.session_state.aes_password = aes_pw_in
    else:
        st.caption(
            "Path to a file containing the 32-byte AES key. The file may "
            "itself be password-protected (same SHA-256 → AES envelope as "
            "the `_prv.enc` keyfiles) — leave the inner password blank if "
            "the file holds the raw key directly."
        )
        aes_key_path = st.text_input(
            "Key file", value=st.session_state.get("aes_key_path", ""),
            key="aes_key_path_input",
        )
        st.session_state.aes_key_path = aes_key_path
        aes_inner_pw = st.text_input(
            "Inner password (empty = unencrypted file)",
            value="", type="password", key="aes_inner_pw_input",
        )
        if st.button("Load AES key", use_container_width=True,
                     disabled=not aes_key_path):
            try:
                with open(aes_key_path, "rb") as _f:
                    raw = _f.read()
                if aes_inner_pw:
                    key_bytes = ct.aes_decrypt_bytes(raw, aes_inner_pw)
                else:
                    key_bytes = raw
                if len(key_bytes) != 32:
                    st.error(
                        f"Expected 32-byte AES key, got {len(key_bytes)} bytes. "
                        f"If the file is password-protected, set the inner "
                        f"password and try again."
                    )
                else:
                    st.session_state.aes_password = key_bytes
                    st.success(
                        f"AES key loaded ({len(key_bytes)} bytes) — "
                        f"fingerprint {key_bytes[:4].hex()}…"
                    )
            except FileNotFoundError:
                st.error(f"No such file: {aes_key_path}")
            except Exception as e:
                st.error(f"AES key load failed: {e}")

    _cur = st.session_state.get("aes_password")
    if isinstance(_cur, (bytes, bytearray)) and len(_cur) == 32:
        st.caption(f"✓ AES key loaded (fingerprint `{bytes(_cur)[:4].hex()}…`)")
    elif isinstance(_cur, str) and _cur:
        st.caption("✓ Password set (will be SHA-256 hashed)")
    else:
        st.caption("(no AES key set)")

    st.divider()
    st.header("Node")
    try:
        info = ct.rpc_request("getblockchaininfo")
        st.write(f"Block: **{info['blocks']:,}**")
        st.write(f"Synced: **{'✓' if not info['initialblockdownload'] else 'syncing'}**")
    except Exception as e:
        st.error(f"Node not reachable: {e}")

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

TYPE_LABELS = {
    0x00: "text",
    0x03: "image",
    0x0e: "encrypted",
    0x1d: "identity",
    0xcc: "certificate",
    0xce: "celestial",
    0xf0: "error",
    0xab: "bindings",
    0xf1: "file",
}

def build_text_header(title, tone):
    return (
        bytes.fromhex("c1dd0001")
        + bytes([0x00, tone])
        + f"|{title}|".encode("utf-8")
    )

def build_image_header(title, tone, L, W, B, color):
    """Build a 0x03 image header. Note: the historical convention stores
    (W, H) in the header, NOT (H, W). The argument names here keep using
    (L, W) to match read_image_data's variable names, but the bytes
    written are width then height — so callers should pass
    L=height-of-image, W=width-of-image and we write them as (W, L)
    on the wire."""
    return (
        bytes.fromhex("c1dd0001")
        + bytes([0x03, tone])
        + bytes([1 if color == "RGB" else 0])
        + W.to_bytes(2, "big")  # width first (historical convention)
        + L.to_bytes(2, "big")  # then height
        + bytes([B])
        + f"|{title}|".encode("utf-8")
    )

def encode_image_bytes(pil_img, dims_wh, bit, color_mode):
    """Returns (body_bytes, preview_pil_img)."""
    img = pil_img.resize(dims_wh)  # PIL: (W, H)
    arr = np.array(img)
    if color_mode == "grayscale":
        grey = arr[:, :, :3].mean(axis=2).astype("uint8")
        bitarray = ct.imgarr2bitarray(grey, bit=bit)
        body_bytes = ct.bit_array_2_byte_str(bitarray)
        # Reconstruct via same path the chain reader will use (no extra scaling)
        bits_back = ct.message_2_bit_array(body_bytes, mode=None)
        preview_arr = ct.bitarray2imgarr(
            bits_back, imgshape=(dims_wh[1], dims_wh[0]), bit=bit, color=1
        ).squeeze()
        preview_pil = Image.fromarray(preview_arr)
    else:  # RGB
        rgb = arr[:, :, :3]
        bitarray = ct.imgarr2bitarray(rgb, bit=bit)
        body_bytes = ct.bit_array_2_byte_str(bitarray)
        bits_back = ct.message_2_bit_array(body_bytes, mode=None)
        preview_arr = ct.bitarray2imgarr(
            bits_back, imgshape=(dims_wh[1], dims_wh[0]), bit=bit, color=3
        ).squeeze()
        preview_pil = Image.fromarray(preview_arr)
    return body_bytes, preview_pil

def split_into_strands(body_bytes, n_body_strands):
    """Split body into n_body_strands roughly equal parts."""
    n = n_body_strands
    chunk = len(body_bytes) // n
    extra = len(body_bytes) % n
    parts = []
    i = 0
    for k in range(n):
        sz = chunk + (1 if k < extra else 0)
        parts.append(body_bytes[i:i + sz])
        i += sz
    return parts

def estimate_strand_txs(payload_bytes):
    return max(1, (len(payload_bytes) + 79) // 80)


# ----------------------------------------------------------------------
# Wallet helpers — UTXO grouping, pattern detection, label persistence
# ----------------------------------------------------------------------

import json as _json

LABELS_PATH = str(Path.home() / "Desktop" / "cinv" / "labels.json")

def load_labels():
    try:
        with open(LABELS_PATH) as f:
            return _json.load(f)
    except FileNotFoundError:
        return {}
    except Exception:
        return {}

def save_labels(labels):
    Path(LABELS_PATH).parent.mkdir(parents=True, exist_ok=True)
    with open(LABELS_PATH, "w") as f:
        _json.dump(labels, f, indent=2, sort_keys=True)

def group_utxos_by_tx(utxos):
    """Return list of (txid, [utxos at that tx, sorted by vout])."""
    groups = {}
    for u in utxos:
        groups.setdefault(u["txid"], []).append(u)
    for txid in groups:
        groups[txid].sort(key=lambda x: x["vout"])
    # Sort groups by total value descending
    return sorted(groups.items(),
                  key=lambda kv: -sum(u["amount"] for u in kv[1]))

def detect_pattern(outputs_at_tx):
    """Heuristic-tag a group of UTXOs at a single tx.
    Returns a short label like 'bordado-cert-root', 'reserve', 'terminus', etc."""
    n = len(outputs_at_tx)
    amounts = [u["amount"] for u in outputs_at_tx]
    total = sum(amounts)
    all_equal = len(set(amounts)) == 1
    if n >= 5 and all_equal and abs(amounts[0] - 456.24666333) < 0.01:
        return "🎀 bordado-cert-root (5×456 DOGE — pre-funded certificate)"
    if n >= 4 and all_equal:
        return f"🪢 multi-strand-root ({n}×{amounts[0]:.4f} DOGE)"
    if n == 1 and amounts[0] >= 100:
        return f"💰 reserve ({amounts[0]:.4f} DOGE)"
    if n == 1 and 0.5 <= amounts[0] < 100:
        return f"🪡 strand-terminus or change ({amounts[0]:.4f} DOGE)"
    if n == 1 and amounts[0] < 0.5:
        return f"· dust ({amounts[0]:.6f} DOGE)"
    return f"({n} outputs, {total:.4f} DOGE)"


# Address → label map for scan_accounts
ADDR_LABELS = {
    "9xth7DcLGb1nACScMBeSfDCfghhLKF7yqs": "hca",
    "A7pfCe2Cw9JD2C4vEZbpDmUZJy7B2TaefV": "ha",
    "AD28bxzxyrd3a4Qgad2VNQ2eN5Leg8ozuw": "ca",
    "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX": "old_inscribe",
}

TYPE_SHORT_LABELS = {
    0x00: "text",
    0x03: "image",
    0x0e: "encrypted",
    0x1d: "identity",
    0xcc: "cert",
    0xce: "celestial",
    0xf0: "error",
    0xab: "bindings",
    0xf1: "file",
}


def read_quipu_bytes(root_txid, df_out=None):
    """Returns (header_bytes, body_bytes) for a quipu by root txid.
    Uses the cached df_out if available (fast); falls back to direct
    chain walks via gettransaction + decoderawtransaction (slower but
    always works)."""
    if df_out is not None:
        try:
            header_hex, body_hex = ct.read_quipu(root_txid, df_out)
            if header_hex:
                return (bytes.fromhex(header_hex),
                        bytes.fromhex(body_hex) if body_hex else b"")
        except Exception:
            pass  # fall through to RPC walk

    def _fetch(txid):
        wt = ct.rpc_request("gettransaction", [txid, True])
        return ct.rpc_request("decoderawtransaction", [wt["hex"]])

    def _walk(start_txid, start_vout):
        parts = []
        cur = (start_txid, start_vout)
        while True:
            spent = ct.rpc_request("gettxout", [cur[0], cur[1], True])
            if spent is not None:
                break
            # Find spender: search recent wallet txs for one whose input
            # references this output. Bounded scan to keep it tractable.
            txs = ct.rpc_request("listtransactions", ["*", 500, 0, True])
            found = None
            for t in reversed(txs):
                try:
                    cand = _fetch(t["txid"])
                    for vin in cand["vin"]:
                        if vin.get("txid") == cur[0] and vin.get("vout") == cur[1]:
                            found = (t["txid"], cand); break
                    if found: break
                except Exception:
                    pass
            if not found:
                break
            for v in found[1]["vout"]:
                if v["scriptPubKey"]["type"] == "nulldata":
                    ob = ct.extract_op_return(v)
                    if ob:
                        parts.append(ob)
                    break
            cur = (found[0], 0)
        return "".join(parts)

    root = _fetch(root_txid)
    n_strands = len(root["vout"])
    header_hex = _walk(root_txid, 0)
    body_hex = "".join(_walk(root_txid, i) for i in range(1, n_strands))
    return (
        bytes.fromhex(header_hex) if header_hex else b"",
        bytes.fromhex(body_hex) if body_hex else b"",
    )


def _coerce_password_input(s):
    """Sidebar AES input → value for colegio_tools._coerce_aes_key.
    Raw 32-byte bytes (from a loaded key file) pass through unchanged;
    any string is treated as a passphrase that the helper will SHA-256."""
    if isinstance(s, (bytes, bytearray)) and len(s) == 32:
        return bytes(s)
    return s if isinstance(s, str) else ""


def parse_recipient_block(text):
    """Parse a multi-line recipient input into resolved slot info.

    Syntax: one recipient slot per line. Within a line, comma-separated
    tokens get combined into a single envelope target via curve point
    addition. Each token is either:
      - 128-hex uncompressed pubkey (eth_keys form)
      - 130-hex pubkey with '04' prefix (Bitcoin form; we strip)
      - a Dogecoin address (P2PKH or P2SH multisig), resolved via
        ct.get_address_pubkeys
    A '#' starts a trailing comment.

    Returns: list of dicts, one per slot:
      {"tokens": [...], "pubkeys": [PublicKey, ...], "combined": PublicKey}

    Raises ValueError on parse/resolution failure. Per-token results are
    cached in st.session_state["pubkey_cache"] to avoid repeated chain
    scans across reruns.
    """
    cache = st.session_state.setdefault("pubkey_cache", {})
    slots = []
    for raw_line in (text or "").splitlines():
        ln = raw_line.split("#", 1)[0].strip()
        if not ln:
            continue
        tokens = [t.strip() for t in ln.split(",") if t.strip()]
        if not tokens:
            continue
        pubs = []
        for tok in tokens:
            if tok in cache:
                pub_hex_list = cache[tok]
            else:
                try:
                    pub_hex_list = [ct._strip_pub_prefix(tok)]
                except ValueError:
                    pub_hex_list = ct.get_address_pubkeys(tok)
                cache[tok] = pub_hex_list
            pubs.extend(
                eth_keys.keys.PublicKey(bytes.fromhex(p)) for p in pub_hex_list
            )
        slots.append({
            "tokens": tokens,
            "pubkeys": pubs,
            "combined": combine_pubkeys(pubs),
        })
    if not slots:
        raise ValueError("no recipients parsed from input")
    return slots


def resolve_encrypted_quipu(header_bytes, body_bytes, *, root_txid=None,
                            df_out=None, quipus=None, priv_hex=None,
                            aes_password=None):
    """Try to decrypt an encrypted (0x0e family) quipu using whatever keys
    are available. Returns None if header is not encrypted at all, else a
    dict describing kind / status / decrypted inner content.

    Resolution order:
      broadcast (0e 03): loaded privkey envelope → keydrop scan
      AES-sealed (0e ae): sidebar password → keydrop scan
      keydrop quipu (0e 0e 0d): parse target txid + released key
    """
    if len(header_bytes) < 6 or header_bytes[4] != 0x0e:
        return None
    sub = header_bytes[5]

    # Keydrop quipu — informational, not decrypted
    if sub == 0x0e:
        if len(header_bytes) >= 7 and header_bytes[6] == 0x0d:
            try:
                target_txid, aes_key = ct.parse_keydrop_quipu(header_bytes, body_bytes)
                return {
                    "kind": "keydrop_quipu", "status": "info",
                    "inner_header": None, "inner_body": None, "via": None,
                    "details": {"target_txid": target_txid, "aes_key": aes_key},
                }
            except Exception as e:
                return {
                    "kind": "keydrop_quipu", "status": "locked",
                    "inner_header": None, "inner_body": None, "via": None,
                    "details": {"error": str(e)},
                }
        return {
            "kind": "unknown", "status": "locked",
            "inner_header": None, "inner_body": None, "via": None,
            "details": {"sub_family": f"0x0e 0x{header_bytes[6]:02x}"
                        if len(header_bytes) > 6 else "0x0e ?"},
        }

    # Broadcast (per-recipient envelopes)
    if sub == 0x03:
        kind = "broadcast"
        if priv_hex and root_txid:
            try:
                pub_hex = ct.get_txn_pub_from_node(root_txid)
                author_pub = eth_keys.keys.PublicKey(bytes.fromhex(pub_hex))
                priv = eth_keys.keys.PrivateKey(bytes.fromhex(priv_hex))
                inner_h, inner_b = ct.read_broadcast_quipu(
                    header_bytes, body_bytes, priv, author_pub
                )
                return {
                    "kind": kind, "status": "decrypted",
                    "inner_header": inner_h, "inner_body": inner_b,
                    "via": "loaded privkey (broadcast envelope)",
                    "details": {},
                }
            except Exception:
                pass
        if quipus is not None and df_out is not None and root_txid:
            try:
                hit = ct.find_keydrop_for(root_txid, quipus, df_out)
            except Exception:
                hit = None
            if hit:
                kd_q, aes_key = hit
                try:
                    inner_h, inner_b = ct.apply_keydrop(header_bytes, body_bytes, aes_key)
                    return {
                        "kind": kind, "status": "decrypted",
                        "inner_header": inner_h, "inner_body": inner_b,
                        "via": f"keydrop {kd_q['root_txid'][:12]}…",
                        "details": {"keydrop_txid": kd_q["root_txid"]},
                    }
                except Exception:
                    pass
        return {
            "kind": kind, "status": "locked",
            "inner_header": None, "inner_body": None, "via": None,
            "details": {"n_recip": header_bytes[12] if len(header_bytes) > 12 else None},
        }

    # AES-sealed (no envelopes)
    if sub == 0xae:
        kind = "aes_sealed"
        if aes_password:
            try:
                key = _coerce_password_input(aes_password)
                inner_h, inner_b = ct.read_aes_sealed_quipu(
                    header_bytes, body_bytes, key
                )
                return {
                    "kind": kind, "status": "decrypted",
                    "inner_header": inner_h, "inner_body": inner_b,
                    "via": "sidebar password / key",
                    "details": {},
                }
            except Exception:
                pass
        if quipus is not None and df_out is not None and root_txid:
            try:
                hit = ct.find_keydrop_for(root_txid, quipus, df_out)
            except Exception:
                hit = None
            if hit:
                kd_q, aes_key = hit
                try:
                    inner_h, inner_b = ct.apply_keydrop(header_bytes, body_bytes, aes_key)
                    return {
                        "kind": kind, "status": "decrypted",
                        "inner_header": inner_h, "inner_body": inner_b,
                        "via": f"keydrop {kd_q['root_txid'][:12]}…",
                        "details": {"keydrop_txid": kd_q["root_txid"]},
                    }
                except Exception:
                    pass
        return {
            "kind": kind, "status": "locked",
            "inner_header": None, "inner_body": None, "via": None,
            "details": {},
        }

    return {
        "kind": "unknown", "status": "locked",
        "inner_header": None, "inner_body": None, "via": None,
        "details": {"sub_byte": f"0x{sub:02x}"},
    }


def compute_address_history(address):
    """Use scan_accounts + find_quipu_roots to enumerate every quipu rooted
    at this address, with header info and strand lengths.
    Returns {'quipus': [...], 'df_tx': df_tx} — df_tx kept so the topology
    view can trace funding lineage without rescanning."""
    label = ADDR_LABELS.get(address)
    if not label:
        raise ValueError(
            f"Address {address} is not one of the known watched addresses"
        )
    df_tx, df_out = ct.scan_accounts({address: label})
    roots = ct.find_quipu_roots(address, df_tx, df_out)
    quipus = []
    for root in roots:
        try:
            tx_row = df_tx[df_tx.txid == root].iloc[0]
        except Exception:
            continue
        num_outputs = int(tx_row["num_outputs"])
        blockheight = int(tx_row["blockheight"]) if tx_row["blockheight"] else 0
        blocktime = int(tx_row["blocktime"]) if tx_row["blocktime"] else 0

        # Walk each strand to count its tx-length and find its terminus
        strand_lengths = []
        strand_termini = []
        for vout in range(num_outputs):
            cur = f"{root}:{vout}"
            length = 0
            last_txid = None
            while True:
                sub = df_out[df_out.txout == cur]
                if sub.empty:
                    break
                spent_in = sub.iloc[0]["spent_in"]
                if not spent_in or (isinstance(spent_in, float) and spent_in != spent_in):
                    break
                # Check if the spending tx has OP_RETURN
                spend_first = df_out[df_out.txout == f"{spent_in}:0"]
                if spend_first.empty:
                    break
                op = spend_first.iloc[0]["op_return"]
                if not op or (isinstance(op, float) and op != op):
                    break
                length += 1
                last_txid = spent_in
                cur = f"{spent_in}:0"
            strand_lengths.append(length)
            strand_termini.append(last_txid)

        # Read header bytes to get type/tone/title
        try:
            header_hex, _body_hex = ct.read_quipu(root, df_out)
            header_bytes = bytes.fromhex(header_hex) if header_hex else b""
        except Exception:
            header_bytes = b""

        type_byte = header_bytes[4] if len(header_bytes) > 4 else None
        tone_byte = header_bytes[5] if len(header_bytes) > 5 else None
        # Extract title (pipe-delimited) — heuristic across types
        title = ""
        if len(header_bytes) > 6:
            try:
                tail = header_bytes[6:].decode("utf-8", errors="replace")
                # Find first |...|
                if "|" in tail:
                    parts = tail.split("|")
                    if len(parts) >= 3:
                        title = parts[1]
            except Exception:
                pass

        quipus.append({
            "root_txid": root,
            "num_outputs": num_outputs,
            "strand_lengths": strand_lengths,
            "strand_termini": strand_termini,
            "blockheight": blockheight,
            "blocktime": blocktime,
            "type_byte": type_byte,
            "tone_byte": tone_byte,
            "title": title,
            "header_bytes_len": len(header_bytes),
        })

    # Sort by blocktime descending (newest first)
    quipus.sort(key=lambda q: -q["blocktime"])
    return {"quipus": quipus, "df_tx": df_tx, "df_out": df_out}


def compute_quipu_topology(address, quipus, df_tx):
    """Trace each quipu's funding lineage. Returns (nodes, edges) for graph.

    Topology nodes:
      - quipu_root  — a quipu's root tx (the broom-head)
      - joining     — consolidation/joining tx (multiple in, fewer out)
      - bridge      — a pass-through wallet tx (single in, single out)
      - external    — funding came from outside our wallet (not in df_tx)
    Edges:
      - (src_txid, dst_txid) means dst_txid spent an output of src_txid
    """
    import ast
    root_set = {q["root_txid"] for q in quipus}
    quipus_by_root = {q["root_txid"]: q for q in quipus}
    df_tx_by_id = df_tx.set_index("txid")

    def coerce_inputs(raw):
        """`inputs` column may be a list, str repr of list, or NaN."""
        if isinstance(raw, list):
            return raw
        if isinstance(raw, str):
            try:
                return ast.literal_eval(raw)
            except Exception:
                return []
        return []

    nodes = {}
    edges = []

    # First pass: every quipu root becomes a node
    for q in quipus:
        nodes[q["root_txid"]] = {
            "kind": "quipu_root",
            "quipu": q,
        }

    # Trace funding chain backwards from each quipu's root.
    # We follow inputs up to 4 hops to find connections to other quipus.
    MAX_HOPS = 5
    to_explore = list(quipus_by_root.keys())
    seen = set()
    while to_explore:
        cur_txid = to_explore.pop(0)
        if cur_txid in seen:
            continue
        seen.add(cur_txid)
        if cur_txid not in df_tx_by_id.index:
            # external — note it and stop
            if cur_txid not in nodes:
                nodes[cur_txid] = {"kind": "external", "txid": cur_txid}
            continue
        tx_row = df_tx_by_id.loc[cur_txid]
        inputs = coerce_inputs(tx_row["inputs"])
        for input_ref in inputs:
            input_txid = input_ref.split(":")[0]
            if input_txid not in nodes:
                if input_txid in df_tx_by_id.index:
                    parent_row = df_tx_by_id.loc[input_txid]
                    n_in = int(parent_row["num_inputs"])
                    n_out = int(parent_row["num_outputs"])
                    if input_txid in root_set:
                        # Already added as quipu_root
                        pass
                    elif n_in >= 2 and n_out == 1:
                        nodes[input_txid] = {
                            "kind": "joining",
                            "txid": input_txid,
                            "n_in": n_in, "n_out": n_out,
                            "blocktime": int(parent_row.get("blocktime", 0) or 0),
                        }
                    else:
                        nodes[input_txid] = {
                            "kind": "bridge",
                            "txid": input_txid,
                            "n_in": n_in, "n_out": n_out,
                            "blocktime": int(parent_row.get("blocktime", 0) or 0),
                        }
                else:
                    nodes[input_txid] = {"kind": "external", "txid": input_txid}
            # Edge from parent → cur
            edges.append((input_txid, cur_txid))
            # Walk back further only if we haven't gone too deep
            if input_txid in df_tx_by_id.index and len(seen) < 500:
                if input_txid not in seen and input_txid not in to_explore:
                    to_explore.append(input_txid)

    return nodes, edges


def _render_body_html(type_byte, header_bytes, body_bytes):
    """Per-type HTML body rendering. Returns a list of HTML fragments.
    Called both for plaintext quipus and for the decrypted inner content of
    encrypted ones."""
    import html as _html
    import io as _io
    import base64 as _b64
    parts = []

    if type_byte == 0x03:  # image
        try:
            hh = header_bytes.hex()
            color_flag = int(hh[12:14], 16)
            C = 3 if color_flag == 1 else 1
            W = int(hh[14:18], 16)
            H = int(hh[18:22], 16)
            B = int(hh[22:24], 16)
            parts.append(
                f"<div style='font-size:11px; color:#666; margin-bottom:6px'>"
                f"<b>{H}h × {W}w</b> · {B} bpp · "
                f"{'RGB' if C == 3 else 'grayscale'}</div>"
            )
            bits = ct.message_2_bit_array(body_bytes, mode=None)
            arr = ct.bitarray2imgarr(bits, imgshape=(H, W), bit=B, color=C).squeeze()
            img_pil = Image.fromarray(arr)
            scale = max(1, min(6, 360 // max(W, 1)))
            img_pil_disp = (img_pil.resize((W * scale, H * scale), Image.NEAREST)
                            if scale > 1 else img_pil)
            buf = _io.BytesIO()
            img_pil_disp.save(buf, format="PNG")
            b64 = _b64.b64encode(buf.getvalue()).decode("ascii")
            parts.append(
                f"<img src='data:image/png;base64,{b64}' "
                f"style='max-width:100%; image-rendering: pixelated; "
                f"border: 1px solid #ccc; border-radius: 4px;' />"
            )
        except Exception as e:
            parts.append(f"<p>Image decode failed: {_html.escape(str(e))}</p>")

    elif type_byte == 0x00:  # text
        text = body_bytes.decode("utf-8", errors="replace")
        parts.append(
            f"<pre style='white-space: pre-wrap; font-size:11px; "
            f"max-height: 320px; overflow-y: auto; background:#f8f7f2; "
            f"padding:10px; border-radius:4px; margin:0; "
            f"font-family: ui-monospace, monospace'>"
            f"{_html.escape(text)}</pre>"
        )

    elif type_byte == 0x1d:  # identity (JSON)
        try:
            import json as _json
            text = body_bytes.decode("utf-8")
            try:
                obj = _json.loads(text)
                pretty = _json.dumps(obj, indent=2, ensure_ascii=False)
            except Exception:
                pretty = text
            parts.append(
                f"<pre style='font-size:11px; max-height:320px; "
                f"overflow-y:auto; background:#fbf6e8; padding:10px; "
                f"border-radius:4px; margin:0; font-family: ui-monospace, monospace'>"
                f"{_html.escape(pretty)}</pre>"
            )
        except Exception:
            parts.append(
                f"<pre>{_html.escape(body_bytes.decode('utf-8', errors='replace'))}</pre>"
            )

    elif type_byte == 0xcc:  # certificate
        text = body_bytes.decode("utf-8", errors="replace")
        parts.append(
            f"<pre style='white-space:pre-wrap; font-size:11px; "
            f"max-height:280px; overflow-y:auto; background:#f0f7ec; "
            f"padding:10px; border-radius:4px; margin:0; "
            f"font-family: ui-monospace, monospace'>"
            f"{_html.escape(text)}</pre>"
        )

    else:
        parts.append(
            f"<pre style='font-size:10px; max-height:200px; "
            f"overflow-y:auto; background:#f5f5f5; padding:8px'>"
            f"{_html.escape(body_bytes.hex()[:600])}…</pre>"
        )

    return parts


def render_body_streamlit(type_byte, header_bytes, body_bytes):
    """Per-type Streamlit body rendering. Called for plaintext quipus and
    for the decrypted inner of encrypted ones. Sibling of _render_body_html."""
    if type_byte == 0x00:
        st.markdown("**Body** (UTF-8):")
        st.text(body_bytes.decode("utf-8", errors="replace"))
    elif type_byte == 0x03:
        try:
            hh = header_bytes.hex()
            color_flag = int(hh[12:14], 16)
            C = {0: 1, 1: 3}[color_flag]
            W = int(hh[14:18], 16)
            H = int(hh[18:22], 16)
            B = int(hh[22:24], 16)
            st.markdown(
                f"**Image** — {H} h × {W} w · {B} bpp · "
                f"{'grayscale' if C == 1 else 'RGB'}"
            )
            bits = ct.message_2_bit_array(body_bytes, mode=None)
            arr = ct.bitarray2imgarr(bits, imgshape=(H, W), bit=B, color=C).squeeze()
            st.image(arr, width=min(W * 4, 500))
        except Exception as e:
            st.error(f"Image decode failed: {e}")
            st.code(body_bytes.hex()[:200], language=None)
    elif type_byte == 0x1d:
        try:
            st.markdown("**Identity (JSON):**")
            st.json(body_bytes.decode("utf-8"))
        except Exception:
            st.text(body_bytes.decode("utf-8", errors="replace"))
    elif type_byte == 0xcc:
        st.markdown("**Certificate body:**")
        st.text(body_bytes.decode("utf-8", errors="replace"))
    else:
        st.markdown(f"**Body** (type 0x{type_byte:02x}, no specialized decoder):")
        try:
            st.text(body_bytes.decode("utf-8"))
        except Exception:
            st.code(body_bytes.hex()[:500], language=None)


def render_encrypted_streamlit(header_bytes, body_bytes, *, root_txid,
                               df_out=None, quipus=None):
    """Streamlit-side render for a 0x0e quipu: resolver + inner-or-locked."""
    resolved = resolve_encrypted_quipu(
        header_bytes, body_bytes,
        root_txid=root_txid, df_out=df_out, quipus=quipus,
        priv_hex=st.session_state.get("priv_hex"),
        aes_password=st.session_state.get("aes_password"),
    )
    if resolved is None:
        st.warning("Resolver returned None for 0x0e header")
        return
    if resolved["kind"] == "keydrop_quipu" and resolved["status"] == "info":
        target = resolved["details"]["target_txid"]
        key_hex = resolved["details"]["aes_key"].hex()
        st.markdown("🗝 **Key drop** — releases the AES key for:")
        st.code(target, language=None)
        st.markdown(f"**Released key:** `{key_hex[:32]}…`")
        return
    if resolved["status"] == "decrypted":
        sub_label = ("AES-sealed (0x0e 0xae)" if resolved["kind"] == "aes_sealed"
                     else "broadcast (0x0e 0x03)")
        st.success(f"🔓 unlocked · {sub_label} · via {resolved['via']}")
        inner_h = resolved["inner_header"]
        inner_b = resolved["inner_body"]
        inner_type = inner_h[4] if len(inner_h) > 4 else None
        with st.expander("Inner header bytes", expanded=False):
            st.code(inner_h.hex(), language=None)
        render_body_streamlit(inner_type, inner_h, inner_b)
        return
    sub_label = (
        "AES-sealed (0x0e 0xae)" if resolved["kind"] == "aes_sealed"
        else "broadcast (0x0e 0x03)" if resolved["kind"] == "broadcast"
        else f"unknown ({resolved['details']})"
    )
    st.markdown(f"🔒 **encrypted** · {sub_label}")
    st.caption(
        f"{len(body_bytes)} ciphertext bytes. "
        "No matching privkey loaded, no keydrop found on chain, "
        "and no AES password set in sidebar."
    )


def build_quipu_content_html(q, df_out=None, quipus=None):
    """Build a rich HTML panel for a quipu — header metadata + decoded body.
    Embedded into the pyvis topology page; shown on node click."""
    import html as _html
    import datetime as _dt
    try:
        header_bytes, body_bytes = read_quipu_bytes(q["root_txid"], df_out)
    except Exception as e:
        return f"<p>Read failed: {_html.escape(str(e))}</p>"

    type_byte = q["type_byte"]
    tone_byte = q["tone_byte"]
    type_name = TYPE_SHORT_LABELS.get(
        type_byte, f"0x{type_byte:02x}" if type_byte is not None else "?"
    )
    tone_str = "reverence" if tone_byte == 0xff else "ordinary"
    title = q["title"] or "(no title)"
    date_str = ""
    if q["blocktime"]:
        try:
            date_str = _dt.datetime.fromtimestamp(q["blocktime"]).strftime("%Y-%m-%d")
        except Exception:
            pass

    parts = [
        f"<h3 style='margin:0 0 8px 0; font-size:15px'>{_html.escape(title)}</h3>",
        "<div style='font-size:11px; color:#555; margin-bottom:10px; line-height:1.5'>",
        f"<b>type:</b> {type_name} &middot; <b>tone:</b> {tone_str}<br>",
        f"<b>strands:</b> {q['num_outputs']} &middot; "
        f"<b>strand txs:</b> {sum(q['strand_lengths'])}",
        f" &middot; <b>date:</b> {date_str}<br>" if date_str else "<br>",
        f"<b>body:</b> {len(body_bytes):,} B<br>",
        f"<code style='font-size:9px; word-break:break-all'>"
        f"{_html.escape(q['root_txid'])}</code>",
        "</div>",
    ]

    if type_byte == 0x0e:
        resolved = resolve_encrypted_quipu(
            header_bytes, body_bytes,
            root_txid=q["root_txid"], df_out=df_out, quipus=quipus,
            priv_hex=st.session_state.get("priv_hex"),
            aes_password=st.session_state.get("aes_password"),
        )
        if resolved is None:
            parts.append("<p>(unexpected: 0x0e but resolver returned None)</p>")
        elif resolved["kind"] == "keydrop_quipu" and resolved["status"] == "info":
            target = resolved["details"]["target_txid"]
            key_hex = resolved["details"]["aes_key"].hex()
            parts.append(
                f"<div style='font-size:11px; padding:10px; "
                f"background:#fff8e6; border-radius:4px; color:#5a4a00'>"
                f"🗝 <b>key drop</b> — releases the AES key for:<br>"
                f"<code style='font-size:9px; word-break:break-all'>"
                f"{_html.escape(target)}</code><br>"
                f"<span style='color:#888'>key:</span> "
                f"<code style='font-size:9px'>"
                f"{_html.escape(key_hex[:32])}…</code>"
                f"</div>"
            )
        elif resolved["status"] == "decrypted":
            inner_h = resolved["inner_header"]
            inner_b = resolved["inner_body"]
            inner_type = inner_h[4] if len(inner_h) > 4 else None
            sub_label = ("AES-sealed (0x0e 0xae)" if resolved["kind"] == "aes_sealed"
                         else "broadcast (0x0e 0x03)")
            parts.append(
                f"<div style='font-size:10px; padding:6px 10px; "
                f"background:#eaf4ea; border-radius:4px; color:#2a5d2a; "
                f"margin-bottom:8px'>"
                f"🔓 <b>unlocked</b> · {sub_label}<br>"
                f"via {_html.escape(resolved['via'] or '?')}"
                f"</div>"
            )
            parts.extend(_render_body_html(inner_type, inner_h, inner_b))
        else:  # locked
            sub_label = ("AES-sealed (0x0e 0xae)" if resolved["kind"] == "aes_sealed"
                         else "broadcast (0x0e 0x03)" if resolved["kind"] == "broadcast"
                         else f"unknown ({resolved['details']})")
            parts.append(
                f"<div style='font-size:11px; padding:10px; "
                f"background:#f3eef9; border-radius:4px; color:#555'>"
                f"🔒 <b>encrypted</b> · {sub_label}<br>"
                f"{len(body_bytes):,} ciphertext bytes. "
                f"No matching privkey, keydrop, or password available."
                f"</div>"
            )
    else:
        parts.extend(_render_body_html(type_byte, header_bytes, body_bytes))

    parts.append(
        f"<details style='margin-top:10px; font-size:10px'>"
        f"<summary style='cursor:pointer; color:#888'>header bytes</summary>"
        f"<code style='word-break:break-all; font-size:9px'>"
        f"{_html.escape(header_bytes.hex())}</code></details>"
    )

    return "".join(parts)


def render_topology_pyvis(nodes, edges, labels=None, address=None, height_px=620, df_out=None, quipus=None):
    """Render the topology as a force-directed pyvis network. Returns HTML.
    Each quipu_root node, when clicked, pops up a panel with its decoded
    content (image / text / identity / cert / encrypted) plus full header
    metadata."""
    from pyvis.network import Network
    import json as _json
    import datetime as _dt

    labels = labels or {}

    TYPE_COLORS = {
        0x00: "#e6c97a",   # text — warm yellow
        0x03: "#7eb4d8",   # image — sky blue
        0x0e: "#9b86c7",   # encrypted — violet
        0x1d: "#c78686",   # identity — earth red
        0xcc: "#86c786",   # certificate — bordado green
        0xce: "#86c7b4",   # celestial — celadon
        0xf0: "#d8a3a3",   # error — pale red
    }

    net = Network(
        height=f"{height_px}px",
        width="100%",
        bgcolor="#ffffff",
        font_color="#222222",
        directed=True,
        notebook=False,
    )
    # Force-directed physics — funding sources gravitate toward center,
    # quipus repel each other and drift to the perimeter.
    net.barnes_hut(
        gravity=-3500,
        central_gravity=0.4,
        spring_length=160,
        spring_strength=0.03,
        damping=0.4,
    )

    for txid, info in nodes.items():
        kind = info["kind"]
        if kind == "quipu_root":
            q = info["quipu"]
            color = TYPE_COLORS.get(q["type_byte"], "#cccccc")
            # Size by total tx count, clamped
            total_txs = sum(q["strand_lengths"]) + 1
            size = max(18, min(60, 12 + total_txs ** 0.5 * 3))
            tx_label = labels.get(f"tx:{txid}", "")
            primary = tx_label or q["title"] or txid[:8]
            label = primary[:24]
            date_str = ""
            if q["blocktime"]:
                try:
                    date_str = _dt.datetime.fromtimestamp(
                        q["blocktime"]
                    ).strftime("%Y-%m-%d")
                except Exception:
                    pass
            type_name = TYPE_SHORT_LABELS.get(
                q["type_byte"], f"0x{q['type_byte']:02x}" if q['type_byte'] is not None else "?"
            )
            tone_str = "reverence" if q["tone_byte"] == 0xff else "ordinary"
            title = (
                f"{primary}\n"
                f"type: {type_name} ({tone_str})\n"
                f"{q['num_outputs']} strands · {total_txs - 1} body txs\n"
                f"{date_str}\n"
                f"{txid}"
            )
            net.add_node(txid, label=label, title=title, color=color,
                         size=size, shape="dot", borderWidth=2)
        elif kind == "joining":
            net.add_node(
                txid,
                label=f"join {info['n_in']}→{info['n_out']}",
                title=f"Joining tx — consolidates {info['n_in']} inputs\n{txid}",
                color="#bbbbbb", size=14, shape="diamond",
            )
        elif kind == "bridge":
            net.add_node(
                txid,
                label="·",
                title=f"Bridge tx ({info['n_in']}→{info['n_out']})\n{txid}",
                color="#dddddd", size=8, shape="dot",
            )
        elif kind == "external":
            net.add_node(
                txid,
                label="external",
                title=f"External funding\n{txid}",
                color="#444444", size=10, shape="square",
            )

    for src, dst in edges:
        net.add_edge(src, dst, color="#999999", width=1)

    html = net.generate_html()

    # Pre-compute click-popup content for each quipu_root node
    quipu_contents = {}
    for txid, info in nodes.items():
        if info["kind"] == "quipu_root":
            try:
                quipu_contents[txid] = build_quipu_content_html(
                    info["quipu"], df_out, quipus=quipus
                )
            except Exception as e:
                quipu_contents[txid] = f"<p>render failed: {e}</p>"

    # JS escape: use json.dumps to handle quotes/newlines/unicode
    contents_js = _json.dumps(quipu_contents)

    # Inject a fixed-position popup div + click handler that displays the
    # pre-computed HTML for whichever quipu node the user clicks.
    custom = """
<div id="quipu-popup" style="display:none; position: fixed; top: 16px;
     right: 16px; max-width: 380px; max-height: 85vh; overflow-y: auto;
     background: white; border: 2px solid #999; border-radius: 10px;
     padding: 14px; z-index: 9999;
     box-shadow: 0 8px 24px rgba(0,0,0,0.2);
     font-family: -apple-system, Helvetica, Arial, sans-serif;"></div>
<script>
var QUIPU_CONTENTS = """ + contents_js + """;
(function() {
    function closePopup() {
        document.getElementById('quipu-popup').style.display = 'none';
    }
    function showFor(nodeId) {
        var popup = document.getElementById('quipu-popup');
        if (QUIPU_CONTENTS[nodeId]) {
            popup.innerHTML = QUIPU_CONTENTS[nodeId] +
                '<div style="text-align:right; margin-top:10px">' +
                '<button onclick="document.getElementById(\\'quipu-popup\\').style.display=\\'none\\'" ' +
                'style="padding:4px 14px; cursor:pointer; border:1px solid #888; ' +
                'background:#f5f5f5; border-radius:4px; font-size:11px">close</button>' +
                '</div>';
            popup.style.display = 'block';
        } else {
            popup.style.display = 'none';
        }
    }
    function bind() {
        if (typeof network !== 'undefined' && network) {
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
    html = html.replace("</body>", custom + "</body>")
    return html


def build_history_dot(address, quipus, labels):
    """Generate a graphviz DOT string showing all quipus inscribed at address
    as a forest of broom-heads. Collapses:
      - if > 5 strands: shows first 3 + ellipsis + last
      - if a strand has > 4 txs: shows first 2 + ellipsis + last tx"""
    import datetime

    addr_short = address[:8] + "…"
    total = len(quipus)
    dot = [
        'digraph history {',
        '  rankdir=TB;',
        '  graph [bgcolor="white", pad="0.4", nodesep="0.2", ranksep="0.6", '
        'splines="curved"];',
        '  node [fontname="Helvetica", fontsize=9];',
        '  edge [arrowhead=none, color="#999999"];',
        '',
        f'  addr [label="{addr_short}\\n{total} quipus", shape=hexagon, '
        f'style="filled,bold", fillcolor="#dcc5e8", fontsize=12];',
        '',
    ]

    # Color by quipu type
    TYPE_COLORS = {
        0x00: "#f5e6c0",   # text — paper
        0x03: "#c7ddef",   # image — sky
        0x0e: "#d4c5e0",   # encrypted — violet
        0x1d: "#e0c5c5",   # identity — earth
        0xcc: "#a3d5a3",   # certificate — bordado green
        0xce: "#c5e0d4",   # celestial — celadon
        0xf0: "#e8d4d4",   # error — pale red
    }

    def render_strand(s_idx, strand_length, parent_id, qi, dot, terminus_label=None):
        """Render a vertical strand of nodes hanging from parent_id."""
        # If strand has no length (just the output, never spent), show a leaf
        if strand_length == 0:
            leaf_id = f"q{qi}_s{s_idx}_unspent"
            dot.append(
                f'  {leaf_id} [label="(unspent)", shape=ellipse, '
                f'style="filled,dashed", fillcolor="#f5f5f5", fontsize=8];'
            )
            dot.append(f'  {parent_id} -> {leaf_id};')
            return

        # Decide if we collapse
        if strand_length <= 4:
            # Show all txs
            prev = parent_id
            for ti in range(strand_length):
                n_id = f"q{qi}_s{s_idx}_t{ti}"
                dot.append(
                    f'  {n_id} [label="{ti+1}", shape=circle, '
                    f'style=filled, fillcolor="#e8e8e8", '
                    f'width=0.3, height=0.3, fontsize=8];'
                )
                dot.append(f'  {prev} -> {n_id};')
                prev = n_id
        else:
            # Collapse: first 2 + … + last
            prev = parent_id
            for ti in (0, 1):
                n_id = f"q{qi}_s{s_idx}_t{ti}"
                dot.append(
                    f'  {n_id} [label="{ti+1}", shape=circle, '
                    f'style=filled, fillcolor="#e8e8e8", '
                    f'width=0.3, height=0.3, fontsize=8];'
                )
                dot.append(f'  {prev} -> {n_id};')
                prev = n_id
            e_id = f"q{qi}_s{s_idx}_ellipsis"
            dot.append(
                f'  {e_id} [label="…\\n{strand_length-3}", shape=plaintext, '
                f'fontsize=8];'
            )
            dot.append(f'  {prev} -> {e_id};')
            last_id = f"q{qi}_s{s_idx}_tlast"
            dot.append(
                f'  {last_id} [label="{strand_length}", shape=circle, '
                f'style=filled, fillcolor="#b0d090", '
                f'width=0.32, height=0.32, fontsize=8];'
            )
            dot.append(f'  {e_id} -> {last_id};')

    for qi, q in enumerate(quipus):
        # Quipu root node
        root_id = f"qroot_{qi}"
        type_name = TYPE_SHORT_LABELS.get(q["type_byte"], f"0x{q['type_byte']:02x}" if q['type_byte'] is not None else "?")
        tone_name = "🕯" if q["tone_byte"] == 0xff else "·"
        date_str = ""
        if q["blocktime"]:
            try:
                date_str = datetime.datetime.fromtimestamp(
                    q["blocktime"]
                ).strftime("%Y-%m-%d")
            except Exception:
                pass

        tx_user_label = labels.get(f"tx:{q['root_txid']}", "")
        primary_label = (
            tx_user_label or q["title"] or f"{q['root_txid'][:10]}…"
        )
        node_lines = [
            f"{tone_name} {type_name}",
            primary_label[:32],
            f"{q['num_outputs']} strand{'s' if q['num_outputs'] != 1 else ''} · "
            f"{sum(q['strand_lengths'])} tx · {date_str}",
        ]
        fill = TYPE_COLORS.get(q["type_byte"], "#e0e0e0")
        node_lbl = "\\n".join(node_lines).replace('"', '\\"')
        dot.append(
            f'  {root_id} [label="{node_lbl}", shape=box, '
            f'style="filled,rounded", fillcolor="{fill}", '
            f'tooltip="{q["root_txid"]}"];'
        )
        dot.append(f'  addr -> {root_id};')

        # Strand fan-out — collapse if > 5 strands
        n = q["num_outputs"]
        if n <= 5:
            for s in range(n):
                render_strand(s, q["strand_lengths"][s], root_id, qi, dot)
        else:
            # First 3 + ellipsis + last
            for s in (0, 1, 2):
                render_strand(s, q["strand_lengths"][s], root_id, qi, dot)
            e_id = f"qroot_{qi}_strand_ellipsis"
            dot.append(
                f'  {e_id} [label="… {n-4} more strands …", '
                f'shape=plaintext, fontsize=9];'
            )
            dot.append(f'  {root_id} -> {e_id};')
            render_strand(n - 1, q["strand_lengths"][n - 1], root_id, qi, dot)

    dot.append('}')
    return "\n".join(dot)

# ----------------------------------------------------------------------
# Tabs
# ----------------------------------------------------------------------

tab_plan, tab_inscribe, tab_read, tab_wallet = st.tabs(
    ["📝 Plan", "📡 Inscribe", "🔍 Read", "💼 Wallet"]
)

# ----------------------------------------------------------------------
# Plan tab
# ----------------------------------------------------------------------

with tab_plan:
    st.subheader("Plan a new quipu")

    col_l, col_r = st.columns([1, 1])
    with col_l:
        qtype = st.radio("Content type", ["text", "image"], horizontal=True)
        title = st.text_input("Title", "Untitled")
        tone_label = st.radio("Tone", ["ordinary (0x00)", "reverence (0xff)"], horizontal=True)
        tone = 0xff if tone_label.startswith("reverence") else 0x00
        n_body_strands = st.slider("Body strands", 1, 8, 3,
                                   help="Body bytes get split across this many strands. "
                                        "More strands = wider quipu, more parallelism in Phase 2.")

    body_bytes = None
    preview_pil = None

    if qtype == "text":
        with col_r:
            text_body = st.text_area(
                "Body text",
                height=300,
                placeholder="Write the body of the inscription here…",
            )
            if text_body:
                body_bytes = text_body.encode("utf-8")
                header_bytes = build_text_header(title, tone)
                st.caption(f"Header bytes ({len(header_bytes)} B): `{header_bytes.hex()}`")
                st.metric("Body bytes", len(body_bytes))

    else:  # image
        with col_r:
            uploaded = st.file_uploader(
                "Source image", type=["jpg", "jpeg", "png", "webp", "bmp", "gif"],
            )
            if uploaded:
                src_img = Image.open(uploaded)
                st.caption(f"Source: {src_img.size[0]} × {src_img.size[1]}")

                cc1, cc2 = st.columns(2)
                with cc1:
                    width = st.number_input("Width (W)", 8, 1024, 50, step=2)
                    bit = st.slider("Bit depth", 1, 8, 5)
                with cc2:
                    height = st.number_input("Height (L)", 8, 1024, 100, step=2)
                    color_mode = st.radio(
                        "Color", ["grayscale", "RGB"], horizontal=True
                    )

                # Encode and preview
                body_bytes, preview_pil = encode_image_bytes(
                    src_img, (width, height), bit, color_mode,
                )
                header_bytes = build_image_header(
                    title, tone, height, width, bit, color_mode
                )

                pcols = st.columns(2)
                with pcols[0]:
                    st.caption("Source (resized)")
                    st.image(src_img.resize((width, height)),
                             width=min(width * 3, 300))
                with pcols[1]:
                    st.caption(f"As inscribed ({bit}-bit {color_mode})")
                    st.image(preview_pil, width=min(width * 3, 300))

                st.metric("Body bytes", len(body_bytes),
                          delta=f"L×W×B×C/8 = {height}×{width}×{bit}×{1 if color_mode=='grayscale' else 3}/8")

    # Encryption (optional) — transforms (header_bytes, body_bytes) into
    # an encrypted-quipu pair before strand planning.
    if body_bytes is not None:
        st.divider()
        st.subheader("Encryption")
        enc_mode = st.radio(
            "Mode", ["None", "AES", "ECIES Broadcast"],
            horizontal=True,
            help="None = plaintext quipu. AES = sealed with the sidebar "
                 "key/password (anyone with the same key decrypts). "
                 "ECIES Broadcast = sealed with per-recipient envelopes; "
                 "only listed recipients (or a later key-drop holder) "
                 "decrypt. Broadcast is image-only.",
        )

        encryption_meta = {"mode": "none"}

        if enc_mode == "AES":
            sb_key = st.session_state.get("aes_password")
            has_key = (
                (isinstance(sb_key, str) and sb_key)
                or (isinstance(sb_key, (bytes, bytearray)) and len(sb_key) == 32)
            )
            if not has_key:
                st.info(
                    "Set the AES key in the sidebar (Password string or "
                    "Key file) — that key is used to seal this quipu."
                )
            else:
                key = _coerce_password_input(sb_key)
                outer_h, outer_b = ct.build_aes_sealed_quipu(
                    header_bytes, body_bytes, key
                )
                header_bytes = outer_h
                body_bytes = outer_b
                encryption_meta = {
                    "mode": "aes_sealed",
                    "outer_size": len(outer_h) + len(outer_b),
                }
                kind = "key file" if isinstance(sb_key, (bytes, bytearray)) else "password"
                st.success(
                    f"AES-sealed (via sidebar {kind}) · "
                    f"outer header {len(outer_h)} B · "
                    f"ciphertext body {len(outer_b)} B"
                )
                st.caption(f"Outer header bytes: `{outer_h.hex()}`")

        elif enc_mode == "ECIES Broadcast":
            if "priv_hex" not in st.session_state:
                st.warning(
                    "Load a key in the sidebar first — the author privkey "
                    "is needed to seal envelopes for each recipient."
                )
            elif qtype != "image":
                st.warning(
                    "ECIES Broadcast (0x0e 0x03) is the image-specific "
                    "format from nb17. For text/essay use AES."
                )
            else:
                st.caption(
                    "One recipient slot per line. Within a line, "
                    "comma-separated tokens are **combined** into a single "
                    "envelope (curve point addition). Each token is a "
                    "pubkey hex (128 or 130 chars) or a Dogecoin address "
                    "(P2PKH or P2SH multisig — resolved via chain scan). "
                    "`#` starts a trailing comment."
                )
                recip_text = st.text_area(
                    "Recipients",
                    value=st.session_state.get("plan_recipients_text", ""),
                    placeholder=(
                        "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX   # apocrypha (P2PKH)\n"
                        "04abc…def, 04def…ghi                  # combined 2-key group\n"
                        "9xth7DcLGb1nACScMBeSfDCfghhLKF7yqs   # bordado 3-of-3 multisig"
                    ),
                    key="plan_recipients_input",
                    height=140,
                )
                st.session_state["plan_recipients_text"] = recip_text

                bc1, bc2 = st.columns([1, 4])
                with bc1:
                    do_resolve = st.button("Resolve recipients",
                                           use_container_width=True)
                if do_resolve:
                    try:
                        with st.spinner("Resolving recipients (chain scan "
                                        "for addresses)…"):
                            slots = parse_recipient_block(recip_text)
                        st.session_state["plan_resolved_slots"] = slots
                        st.session_state["plan_resolved_for_text"] = recip_text
                        st.session_state["plan_resolve_error"] = None
                    except Exception as e:
                        st.session_state["plan_resolve_error"] = str(e)
                        st.session_state["plan_resolved_slots"] = None

                err = st.session_state.get("plan_resolve_error")
                slots = st.session_state.get("plan_resolved_slots")
                stale = (
                    slots is not None
                    and st.session_state.get("plan_resolved_for_text") != recip_text
                )
                if err:
                    st.error(f"Resolve failed: {err}")
                if stale:
                    st.info("Recipient text changed — click **Resolve "
                            "recipients** to refresh before encrypting.")
                if slots and not stale:
                    st.markdown(f"**Resolved {len(slots)} recipient slot(s):**")
                    for i, slot in enumerate(slots, 1):
                        n = len(slot["pubkeys"])
                        kind = "combined" if n > 1 else "single"
                        fpr = slot["combined"].to_bytes()[:4].hex()
                        tokens_str = ", ".join(t[:16] + "…" if len(t) > 18 else t
                                               for t in slot["tokens"])
                        st.markdown(
                            f"&nbsp;&nbsp;{i}. **{kind}** · {n} key(s) → "
                            f"combined fingerprint `{fpr}…`<br>"
                            f"&nbsp;&nbsp;&nbsp;&nbsp;<span style='color:#888'>"
                            f"tokens: `{tokens_str}`</span>",
                            unsafe_allow_html=True,
                        )

                    inner_struct = header_bytes[4:header_bytes.index(b"|")]
                    title_field = header_bytes[header_bytes.index(b"|"):]
                    priv = eth_keys.keys.PrivateKey(
                        bytes.fromhex(st.session_state.priv_hex)
                    )
                    combined_pubs = [s["combined"] for s in slots]
                    outer_h, outer_b = ct.build_broadcast_quipu(
                        inner_struct, title_field, body_bytes,
                        priv, combined_pubs,
                    )
                    header_bytes = outer_h
                    body_bytes = outer_b
                    encryption_meta = {
                        "mode": "broadcast",
                        "n_recip": len(slots),
                        "outer_size": len(outer_h) + len(outer_b),
                    }
                    st.success(
                        f"ECIES Broadcast · {len(slots)} recipient slot(s) · "
                        f"body (envelopes + ciphertext) {len(outer_b)} B"
                    )
                    st.caption(f"Outer header bytes: `{outer_h.hex()}`")

    # Strand planning summary
    if body_bytes is not None:
        st.divider()
        st.subheader("Strand plan")

        body_parts = split_into_strands(body_bytes, n_body_strands)
        all_payloads = [header_bytes] + body_parts
        strand_tx_counts = [estimate_strand_txs(p) for p in all_payloads]
        total_strand_txs = sum(strand_tx_counts)
        # Mempool feasibility: each strand ≤ 25, no constraint across strands once root confirms
        max_strand_len = max(strand_tx_counts)
        single_wave_ok = max_strand_len <= 25
        total_txs = 1 + total_strand_txs + 1  # root + strands + join

        scols = st.columns(2)
        with scols[0]:
            st.write("**Strand breakdown:**")
            rows = []
            for i, (p, n) in enumerate(zip(all_payloads, strand_tx_counts)):
                name = "header (cabeza)" if i == 0 else f"body {i}"
                rows.append({"vout": i, "strand": name, "bytes": len(p), "txs": n})
            st.dataframe(rows, hide_index=True, use_container_width=True)
        with scols[1]:
            st.metric("Total transactions",
                      f"{total_txs}",
                      delta="1 root + strands + 1 join")
            st.metric("Estimated fees",
                      f"{(total_txs) * 0.05:.4f} DOGE",
                      delta=f"@ 0.05 DOGE/tx")
            if single_wave_ok:
                st.success(f"All strands ≤ 25 txs. Single-wave fill possible "
                           f"(longest strand: {max_strand_len} txs).")
            else:
                st.warning(f"Longest strand has {max_strand_len} txs (> 25 mempool ancestor limit). "
                           f"Wave splitting would be needed within that strand.")

        # Store the plan in session state for the Inscribe tab
        st.session_state.plan = {
            "qtype": qtype,
            "title": title,
            "tone": tone,
            "header_bytes": header_bytes,
            "body_bytes": body_bytes,
            "all_payloads": all_payloads,
            "n_strands": len(all_payloads),
            "encryption": encryption_meta,
            "preview_pil_bytes": (
                _pil_to_png_bytes(preview_pil) if preview_pil else None
            ) if False else None,
        }
        if preview_pil:
            buf = io.BytesIO()
            preview_pil.save(buf, format="PNG")
            st.session_state.plan["preview_pil_bytes"] = buf.getvalue()

        st.success("Plan stored. Switch to **📡 Inscribe** to commit.")

# ----------------------------------------------------------------------
# Inscribe tab
# ----------------------------------------------------------------------

with tab_inscribe:
    st.subheader("Inscribe")

    if "priv_hex" not in st.session_state:
        st.warning("Load a key in the sidebar first.")
    elif "plan" not in st.session_state:
        st.warning("Build a plan in the **📝 Plan** tab first.")
    else:
        plan = st.session_state.plan
        st.write(f"**Type:** {plan['qtype']}  |  **Title:** `{plan['title']}`  "
                 f"|  **Tone:** {'reverence' if plan['tone'] == 0xff else 'ordinary'}  "
                 f"|  **Strands:** {plan['n_strands']}")

        # Pick UTXO
        utxos = st.session_state.get("utxos", [])
        if not utxos:
            st.error("No UTXOs at this address. Send some DOGE first.")
        else:
            utxo_choices = [
                f"{u['txid'][:12]}...:{u['vout']}  ({u['amount']} DOGE, {u['confirmations']} conf)"
                for u in utxos
            ]
            picked = st.selectbox("Funding UTXO", options=range(len(utxos)),
                                  format_func=lambda i: utxo_choices[i])
            u = utxos[picked]
            utxo_dict = {"output": f"{u['txid']}:{u['vout']}",
                         "value": int(round(u["amount"] * 10**8))}

            # Quipu instance lives in session state
            if "quipu" not in st.session_state or st.button("↻ Start over"):
                if "quipu" in st.session_state:
                    del st.session_state["quipu"]
                if st.session_state.get("priv_hex"):
                    st.session_state.quipu = Quipu(
                        st.session_state.priv_hex,
                        utxo_dict,
                        plan["all_payloads"],
                    )

            q = st.session_state.get("quipu")
            if q is None:
                st.info("Click ↻ Start over to initialize.")
            else:
                st.code(f"state: {q.state}", language=None)

                # Phase 1 — Instantiate
                with st.expander("**Phase 1 — Instantiate (root tx)**", expanded=q.state in (STATE_INIT, STATE_ROOT_BUILT, STATE_ROOT_BROADCAST)):
                    if st.button("1a. Build root tx", disabled=q.state != STATE_INIT):
                        try:
                            root_txid = q.build_root()
                            st.success(f"Built root tx: `{root_txid}`")
                        except Exception as e:
                            st.error(f"Build failed: {e}")
                    if q.root_txid:
                        st.code(f"root txid: {q.root_txid}", language=None)
                        st.write(f"Strand seeds (DOGE): "
                                 f"{[s/10**8 for s in q.strand_seeds]}")

                    if st.button("1b. Broadcast root tx",
                                 disabled=q.state != STATE_ROOT_BUILT):
                        try:
                            q.broadcast_root()
                            st.success("Broadcast. Waiting for confirmation…")
                        except Exception as e:
                            st.error(f"Broadcast failed: {e}")

                    if st.button("1c. Wait for root confirmation",
                                 disabled=q.state != STATE_ROOT_BROADCAST):
                        with st.status("Waiting for root tx to confirm…",
                                       expanded=True) as status:
                            placeholder = st.empty()
                            def cb(elapsed, confs):
                                placeholder.write(
                                    f"t+{elapsed}s: confirmations = {confs}"
                                )
                            ok = q.wait_root_confirmed(on_poll=cb)
                            if ok:
                                status.update(label="✓ Root confirmed", state="complete")
                            else:
                                status.update(label="Timed out", state="error")

                # Phase 2 — Fill
                with st.expander("**Phase 2 — Fill (parallel strand broadcast)**",
                                 expanded=q.state in (STATE_ROOT_CONFIRMED, STATE_STRANDS_PRECOMPUTED, STATE_STRANDS_BROADCAST)):
                    if st.button("2a. Precompute all strands",
                                 disabled=q.state != STATE_ROOT_CONFIRMED):
                        try:
                            meta = q.precompute_strands()
                            st.success(f"Precomputed {sum(m[1] for m in meta)} txs "
                                       f"across {len(meta)} strands.")
                        except Exception as e:
                            st.error(f"Precompute failed: {e}")

                    if q.strands:
                        rows = []
                        for i, c in enumerate(q.strands):
                            rows.append({
                                "strand": "header" if i == 0 else f"body {i}",
                                "vout": i,
                                "txs": len(c.txns),
                                "first_txid": c.txn_ids[0][:16] + "…",
                                "terminus_txid": c.txn_ids[-1][:16] + "…",
                            })
                        st.dataframe(rows, hide_index=True, use_container_width=True)

                    if st.button("2b. Broadcast all strands (parallel)",
                                 disabled=q.state != STATE_STRANDS_PRECOMPUTED):
                        progress = st.progress(0)
                        log = st.empty()
                        total_txs = sum(len(c.txns) for c in q.strands)
                        counter = [0]
                        def on_tx(si, ti, txid):
                            counter[0] += 1
                            progress.progress(counter[0] / total_txs)
                            log.write(f"strand {si} tx {ti+1}: {txid[:16]}…")
                        try:
                            q.broadcast_strands(on_tx=on_tx)
                            st.success(f"All {total_txs} strand txs in mempool.")
                        except Exception as e:
                            st.error(f"Broadcast failed: {e}")

                    if st.button("2c. Wait for strand confirmation",
                                 disabled=q.state != STATE_STRANDS_BROADCAST):
                        with st.status("Waiting for all strand termini to confirm…",
                                       expanded=True) as status:
                            placeholder = st.empty()
                            def cb(elapsed, n_done, n_total):
                                placeholder.write(
                                    f"t+{elapsed}s: {n_done}/{n_total} confirmed"
                                )
                            ok = q.wait_strands_confirmed(on_poll=cb)
                            if ok:
                                status.update(label="✓ All strands confirmed",
                                              state="complete")
                            else:
                                status.update(label="Timed out", state="error")

                # Phase 3 — Close
                with st.expander("**Phase 3 — Close (joining tx, optional)**",
                                 expanded=q.state in (STATE_STRANDS_CONFIRMED, STATE_JOIN_BUILT, STATE_JOIN_BROADCAST)):
                    if st.button("3a. Build joining tx",
                                 disabled=q.state != STATE_STRANDS_CONFIRMED):
                        try:
                            jtxid = q.build_join()
                            st.success(f"Built joining tx: `{jtxid}`")
                        except Exception as e:
                            st.error(f"Build failed: {e}")
                    if q.join_txid:
                        st.code(f"join txid: {q.join_txid}", language=None)

                    if st.button("3b. Broadcast joining tx",
                                 disabled=q.state != STATE_JOIN_BUILT):
                        try:
                            q.broadcast_join()
                            st.success("Joining tx broadcast.")
                        except Exception as e:
                            st.error(f"Broadcast failed: {e}")

                    if st.button("3c. Wait for joining confirmation",
                                 disabled=q.state != STATE_JOIN_BROADCAST):
                        with st.status("Waiting for joining tx to confirm…",
                                       expanded=True) as status:
                            placeholder = st.empty()
                            def cb(elapsed, confs):
                                placeholder.write(
                                    f"t+{elapsed}s: confirmations = {confs}"
                                )
                            ok = q.wait_join_confirmed(on_poll=cb)
                            if ok:
                                status.update(label="✓ Joining tx confirmed",
                                              state="complete")
                            else:
                                status.update(label="Timed out", state="error")

                if q.state == STATE_DONE:
                    st.balloons()
                    st.success(f"**Quipu inscribed and closed.**")
                    st.code(f"root:  {q.root_txid}\njoin:  {q.join_txid}",
                            language=None)

# ----------------------------------------------------------------------
# Read tab
# ----------------------------------------------------------------------

with tab_read:
    st.subheader("Read a quipu from chain")

    txid_in = st.text_input("Quipu root txid")
    if st.button("Fetch and decode", disabled=not txid_in):
        try:
            with st.spinner("Walking strands…"):
                root = ct.rpc_request("gettransaction", [txid_in, True])
                root_dec = ct.rpc_request("decoderawtransaction", [root["hex"]])
                n_strands = len(root_dec["vout"])

                # Walk each strand
                def walk(start_txid, start_vout):
                    parts = []
                    cur = (start_txid, start_vout)
                    while True:
                        spent = ct.rpc_request("gettxout", [cur[0], cur[1], True])
                        if spent is not None:
                            break
                        txs = ct.rpc_request("listtransactions", ["*", 200, 0, True])
                        found = None
                        for t in reversed(txs):
                            try:
                                cand_wt = ct.rpc_request("gettransaction", [t["txid"], True])
                                cand = ct.rpc_request("decoderawtransaction", [cand_wt["hex"]])
                                for vin in cand["vin"]:
                                    if vin.get("txid") == cur[0] and vin.get("vout") == cur[1]:
                                        found = (t["txid"], cand); break
                                if found: break
                            except Exception:
                                pass
                        if not found: break
                        for v in found[1]["vout"]:
                            if v["scriptPubKey"]["type"] == "nulldata":
                                ob = ct.extract_op_return(v)
                                if ob: parts.append(ob)
                                break
                        cur = (found[0], 0)
                    return "".join(parts)

                header_hex = walk(txid_in, 0)
                body_hex = "".join(walk(txid_in, i) for i in range(1, n_strands))
            header_bytes = bytes.fromhex(header_hex)
            body_bytes = bytes.fromhex(body_hex)

            # Decode header
            t_byte = header_bytes[4]
            tone_byte = header_bytes[5]
            st.write(f"**Type:** `0x{t_byte:02x}` ({TYPE_LABELS.get(t_byte, '?')}) "
                     f" **Tone:** `0x{tone_byte:02x}` "
                     f"({'reverence' if tone_byte == 0xff else 'ordinary' if tone_byte == 0x00 else '?'})")
            st.write(f"**Header bytes ({len(header_bytes)}):** `{header_bytes.hex()}`")
            st.write(f"**Body bytes:** {len(body_bytes)}")

            # Aggregate all cached address scans (history::*) so the Read
            # tab can use any of them for keydrop lookup. If no address has
            # been scanned, falls back to None — encrypted quipus will then
            # need a sidebar password or a loaded privkey to unlock.
            quipus_for_keydrop = []
            df_out_for_keydrop = None
            for k, v in st.session_state.items():
                if isinstance(k, str) and k.startswith("history::") and isinstance(v, dict):
                    quipus_for_keydrop.extend(v.get("quipus", []) or [])
                    if df_out_for_keydrop is None:
                        df_out_for_keydrop = v.get("df_out")
            if not quipus_for_keydrop:
                quipus_for_keydrop = None

            if t_byte == 0x0e:
                render_encrypted_streamlit(
                    header_bytes, body_bytes,
                    root_txid=txid_in,
                    df_out=df_out_for_keydrop, quipus=quipus_for_keydrop,
                )
            else:
                render_body_streamlit(t_byte, header_bytes, body_bytes)
        except Exception as e:
            st.error(f"Read failed: {e}")


# ----------------------------------------------------------------------
# Wallet tab — visual UTXO browser with labels
# ----------------------------------------------------------------------

with tab_wallet:
    st.subheader("UTXOs at an address")

    # Address picker — default to loaded apocrypha, with quick-jump buttons.
    # Streamlit requires using on_click callbacks for state changes that
    # need to propagate into widgets (can't reassign a widget's key after
    # it's rendered).
    if "wallet_addr_choice" not in st.session_state:
        st.session_state["wallet_addr_choice"] = st.session_state.get(
            "addr", "9xth7DcLGb1nACScMBeSfDCfghhLKF7yqs"
        )

    def _set_addr_choice(a):
        st.session_state["wallet_addr_choice"] = a
        # Drop cached utxos so refresh fetches the new address
        st.session_state.pop("wallet_utxos", None)

    canonical_addrs = [
        ("hca (bordado)", "9xth7DcLGb1nACScMBeSfDCfghhLKF7yqs"),
        ("ha", "A7pfCe2Cw9JD2C4vEZbpDmUZJy7B2TaefV"),
        ("ca", "AD28bxzxyrd3a4Qgad2VNQ2eN5Leg8ozuw"),
        ("apocrypha (old_inscribe)", "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX"),
    ]
    qb = st.columns(4)
    for i, (label, a) in enumerate(canonical_addrs):
        qb[i].button(
            label, use_container_width=True, key=f"jump_{i}",
            on_click=_set_addr_choice, args=(a,),
        )

    addr_to_view = st.text_input(
        "Address", value=st.session_state["wallet_addr_choice"]
    )
    # If user types a new address, update the choice too so jumps don't
    # silently override an in-progress edit.
    st.session_state["wallet_addr_choice"] = addr_to_view
    st.code(addr_to_view, language=None)

    view_mode = st.radio(
        "View",
        ["History (every quipu rooted here)", "Unspent only"],
        horizontal=True,
        key="wallet_view_mode",
        help="History computes the full broom-head forest for this address "
             "(slow first run, cached after). Unspent shows only currently-"
             "spendable outputs.",
    )

    # Fetch UTXOs
    if st.button("Refresh", key="wallet_refresh"):
        try:
            utxos = ct.rpc_request(
                "listunspent", [0, 9999999, [addr_to_view]]
            )
            st.session_state["wallet_utxos"] = utxos
        except Exception as e:
            st.error(f"Fetch failed: {e}")

    # ----------------------------------------------------------------
    # History view — full broom-head forest
    # ----------------------------------------------------------------
    if view_mode.startswith("History"):
        labels = load_labels()

        hist_cache_key = f"history::{addr_to_view}"
        cached = st.session_state.get(hist_cache_key)
        # Invalidate any cache from before the format change (list → dict)
        if cached is not None and not isinstance(cached, dict):
            st.session_state.pop(hist_cache_key, None)
            cached = None

        cc1, cc2 = st.columns([1, 4])
        with cc1:
            recompute = st.button(
                "↻ Compute / refresh history",
                key=f"refresh_history_{addr_to_view}",
            )
        with cc2:
            if cached:
                st.caption(f"Cached: {len(cached)} quipu(s). "
                           f"Click ↻ to rescan.")

        if recompute or (cached is None and addr_to_view in ADDR_LABELS):
            try:
                with st.spinner("Scanning address history "
                                "(this can take 30-60 sec on first run)…"):
                    result = compute_address_history(addr_to_view)
                st.session_state[hist_cache_key] = result
                cached = result
            except ValueError as e:
                st.error(str(e))
            except Exception as e:
                st.error(f"History scan failed: {e}")

        if cached is None:
            if addr_to_view not in ADDR_LABELS:
                st.warning(
                    f"`{addr_to_view}` is not in the watched-address set. "
                    f"History view only works for addresses imported into the "
                    f"wallet ({', '.join(ADDR_LABELS.values())})."
                )
            else:
                st.info("Click ↻ to compute history.")
        else:
            quipus = cached["quipus"]
            df_tx = cached["df_tx"]
            df_out = cached.get("df_out")
            st.markdown(f"**{len(quipus)} quipus rooted at `{addr_to_view[:12]}…`**")

            # Summary table
            if quipus:
                import datetime
                rows = []
                for q in quipus:
                    date_str = (
                        datetime.datetime.fromtimestamp(q["blocktime"]).strftime("%Y-%m-%d")
                        if q["blocktime"] else "?"
                    )
                    type_name = TYPE_SHORT_LABELS.get(
                        q["type_byte"],
                        f"0x{q['type_byte']:02x}" if q['type_byte'] is not None else "?",
                    )
                    tone_str = "reverence" if q["tone_byte"] == 0xff else "ordinary"
                    user_label = labels.get(f"tx:{q['root_txid']}", "")
                    rows.append({
                        "date": date_str,
                        "type": type_name,
                        "tone": tone_str,
                        "title": q["title"] or "(none)",
                        "label": user_label,
                        "strands": q["num_outputs"],
                        "total_txs": sum(q["strand_lengths"]),
                        "root": q["root_txid"][:16] + "…",
                    })
                st.dataframe(rows, hide_index=True, use_container_width=True)

            # Topology — force-directed network showing funding lineage
            st.markdown("### Topology (force-directed)")
            st.caption(
                "Quipus and joining txs as a network. Quipus repel each other "
                "and drift outward; funding-source txs gravitate to the centre "
                "via the spring forces along the edges. Drag any node to "
                "reposition. Each edge means *this tx spent an output of that one*. "
                "Color of quipu nodes follows type "
                "(image · text · encrypted · identity · cert · …). Diamond = "
                "consolidation/joining tx. Tiny dot = bridge. Black square = "
                "external funding."
            )
            try:
                with st.spinner("Building topology (decoding all quipus for click-popups)…"):
                    nodes, edges = compute_quipu_topology(
                        addr_to_view, quipus, df_tx
                    )
                    topo_html = render_topology_pyvis(
                        nodes, edges, labels=labels, address=addr_to_view,
                        height_px=620, df_out=df_out, quipus=quipus,
                    )
                import streamlit.components.v1 as components
                components.html(topo_html, height=650, scrolling=False)
            except Exception as e:
                st.error(f"Topology render failed: {e}")

            # --- Quipu inspector ---
            st.markdown("### Inspect a quipu")
            st.caption(
                "Pick any quipu from this address. Its content is decoded "
                "directly from the cached dataframes (no extra chain queries)."
            )
            import datetime as _dt
            q_by_root = {q["root_txid"]: q for q in quipus}
            def _q_label(txid):
                if txid is None:
                    return "— pick one —"
                q = q_by_root[txid]
                type_name = TYPE_SHORT_LABELS.get(
                    q["type_byte"],
                    f"0x{q['type_byte']:02x}" if q['type_byte'] is not None else "?",
                )
                date = (
                    _dt.datetime.fromtimestamp(q["blocktime"]).strftime("%Y-%m-%d")
                    if q["blocktime"] else "?"
                )
                user_label = labels.get(f"tx:{txid}", "")
                title = user_label or q["title"] or "(no title)"
                return f"{date}  ·  {type_name}  ·  {title[:36]}  ·  {txid[:10]}…"

            selected_root = st.selectbox(
                "Quipu",
                options=[None] + [q["root_txid"] for q in quipus],
                format_func=_q_label,
                key=f"inspector_{addr_to_view}",
            )

            if selected_root:
                q = q_by_root[selected_root]
                type_byte = q["type_byte"]
                tone_byte = q["tone_byte"]
                type_name = TYPE_SHORT_LABELS.get(
                    type_byte,
                    f"0x{type_byte:02x}" if type_byte is not None else "?",
                )
                tone_str = "reverence" if tone_byte == 0xff else "ordinary"

                # Metadata panel
                meta_cols = st.columns([1, 1, 1, 1])
                meta_cols[0].metric("Type", type_name)
                meta_cols[1].metric("Tone", tone_str)
                meta_cols[2].metric("Strands", q["num_outputs"])
                meta_cols[3].metric("Total txs", sum(q["strand_lengths"]) + 1)

                st.code(f"root: {selected_root}", language=None)
                if q["title"]:
                    st.markdown(f"**Title:** {q['title']}")

                # Read header + body (prefers cached df_out, falls back to RPC walk)
                if df_out is None:
                    st.info("Reading from chain directly (cache from earlier "
                            "scan was missing df_out). Click ↻ Compute / "
                            "refresh history to enable instant inspection.")
                try:
                    with st.spinner("Decoding…"):
                        header_bytes, body_bytes = read_quipu_bytes(
                            selected_root, df_out
                        )
                except Exception as e:
                    st.error(f"read failed: {e}")
                    header_bytes, body_bytes = b"", b""

                with st.expander("Header bytes", expanded=False):
                    st.code(header_bytes.hex(), language=None)
                    st.caption(f"{len(header_bytes)} bytes total")

                # Type-aware content rendering
                if type_byte == 0x0e:
                    render_encrypted_streamlit(
                        header_bytes, body_bytes,
                        root_txid=selected_root,
                        df_out=df_out, quipus=quipus,
                    )
                else:
                    render_body_streamlit(type_byte, header_bytes, body_bytes)

            # Broom-head forest (secondary view — useful for seeing strand depth)
            with st.expander("Broom-head forest (hierarchical view of strands)",
                             expanded=False):
                try:
                    dot_str = build_history_dot(addr_to_view, quipus, labels)
                    st.graphviz_chart(dot_str, use_container_width=True)
                    st.caption(
                        "Each tx with multiple outputs is a **broom-head**: "
                        "the root fans out into strands of OP_RETURN-bearing "
                        "transactions. Numbers in circles = position within "
                        "the strand. Strands longer than 4 txs are collapsed "
                        "as `1, 2, …, N`. Quipus with more than 5 strands are "
                        "collapsed as `strand 0, 1, 2, … last`. The last circle "
                        "(slightly green) is the strand terminus."
                    )
                except Exception as e:
                    st.error(f"Render failed: {e}")
                    with st.expander("DOT source (debug)"):
                        st.code(dot_str if 'dot_str' in dir() else "", language="dot")

    # ----------------------------------------------------------------
    # Unspent-only view (default)
    # ----------------------------------------------------------------
    elif True:  # view_mode == "Unspent only"
        utxos = st.session_state.get("wallet_utxos", [])
        if not utxos:
            st.info("Click **Refresh** to load UTXOs for this address.")
        else:
            labels = load_labels()
            groups = group_utxos_by_tx(utxos)
            total_doge = sum(u["amount"] for u in utxos)

            # Summary metrics
            m1, m2, m3 = st.columns(3)
            m1.metric("Total UTXOs", len(utxos))
            m2.metric("Source txs", len(groups))
            m3.metric("Total DOGE", f"{total_doge:,.4f}")

            # Broom-head tree: address → tx → outputs
            # Each tx with multiple outputs fans out like a broom-head, exactly
            # the shape of a pre-funded quipu (5 strand-seeds dangling from
            # one funding tx).
            def _color_for_tx_pattern(outs):
                n = len(outs)
                amounts = [u["amount"] for u in outs]
                all_equal = len(set(amounts)) == 1
                if n >= 5 and all_equal and abs(amounts[0] - 456.24666333) < 0.01:
                    return "#a3d5a3"   # cert-root: green
                if n >= 4 and all_equal:
                    return "#a3c5e8"   # multi-strand root: blue
                if n == 1 and amounts[0] >= 100:
                    return "#f0d878"   # reserve: gold
                if n == 1 and 0.5 <= amounts[0] < 100:
                    return "#d0d0d0"   # terminus / change: gray
                if n == 1 and amounts[0] < 0.5:
                    return "#f5d5d5"   # dust: pale red
                return "#e8e8e8"

            def _color_for_output(u, parent_amounts):
                amt = u["amount"]
                all_equal = len(set(parent_amounts)) == 1 and len(parent_amounts) >= 4
                if all_equal and abs(amt - 456.24666333) < 0.01:
                    return "#7fc97f"   # cert-seed: stronger green
                if all_equal:
                    return "#a3c5e8"   # other strand seed: blue
                if amt >= 100:
                    return "#f0d878"
                if amt < 0.5:
                    return "#f5d5d5"
                return "#ffffff"

            # Build DOT string
            dot_lines = [
                'digraph utxos {',
                '  rankdir=TB;',
                '  graph [bgcolor="white", pad="0.3", nodesep="0.15", ranksep="0.55"];',
                '  node [fontname="Helvetica", fontsize=10];',
                '  edge [arrowhead=none, color="#888888"];',
                '',
                f'  addr [label="{addr_to_view[:8]}…\\n{total_doge:,.2f} DOGE", '
                f'shape=hexagon, style="filled,bold", fillcolor="#dcc5e8", '
                f'fontsize=11];',
                '',
            ]
            for ti, (txid, outs) in enumerate(groups):
                tx_color = _color_for_tx_pattern(outs)
                tx_label_key = f"tx:{txid}"
                tx_user_label = labels.get(tx_label_key, "")
                pattern = detect_pattern(outs)
                tx_total = sum(u["amount"] for u in outs)
                # Strip emoji from pattern for cleaner DOT label
                pattern_clean = pattern.split(" ", 1)[-1] if " " in pattern else pattern
                display_lines = [
                    tx_user_label if tx_user_label else f"tx {txid[:10]}…",
                    f"{len(outs)} out · {tx_total:,.2f} DOGE",
                ]
                tx_label = "\\n".join(display_lines).replace('"', '\\"')
                tx_node_id = f"tx_{ti}"
                dot_lines.append(
                    f'  {tx_node_id} [label="{tx_label}", shape=box, '
                    f'style="filled,rounded", fillcolor="{tx_color}", '
                    f'tooltip="{txid}"];'
                )
                dot_lines.append(f'  addr -> {tx_node_id};')

                # Each output as a leaf
                parent_amounts = [u["amount"] for u in outs]
                for u in outs:
                    utxo_key = f"{txid}:{u['vout']}"
                    user_label = labels.get(utxo_key, "")
                    out_color = _color_for_output(u, parent_amounts)
                    leaf_lines = [
                        f"vout {u['vout']}",
                        f"{u['amount']:,.3f}",
                    ]
                    if user_label:
                        leaf_lines.insert(0, user_label[:24])
                    leaf_label = "\\n".join(leaf_lines).replace('"', '\\"')
                    leaf_id = f"o_{ti}_{u['vout']}"
                    shape = "ellipse" if len(outs) > 1 else "box"
                    vout_n = u["vout"]
                    dot_lines.append(
                        f'  {leaf_id} [label="{leaf_label}", shape={shape}, '
                        f'style=filled, fillcolor="{out_color}", '
                        f'tooltip="{txid}:{vout_n}"];'
                    )
                    dot_lines.append(f'  {tx_node_id} -> {leaf_id};')
                dot_lines.append('')
            dot_lines.append('}')
            dot_str = "\n".join(dot_lines)

            st.graphviz_chart(dot_str, use_container_width=True)
            st.caption(
                "Each fan-out from a tx is a **broom-head**. Green broom = "
                "bordado-cert-root (5×456 DOGE). Blue broom = other "
                "multi-strand root. Gold leaf = reserve. Gray = strand terminus "
                "or change. Pale red = dust."
            )

            st.divider()
            st.subheader("Edit labels")
            st.caption(
                f"Labels persist to `{LABELS_PATH}`. "
                f"Use them to mark certificate roots (\"La Verna funding\"), "
                f"reserves, expected destinations for strand termini, etc."
            )

            labels_changed = False
            for txid, outs in groups:
                pattern = detect_pattern(outs)
                with st.expander(
                    f"{pattern}  ·  `{txid[:16]}…`  "
                    f"({len(outs)} output{'s' if len(outs) != 1 else ''}, "
                    f"{sum(u['amount'] for u in outs):,.4f} DOGE total)",
                    expanded=(len(outs) >= 4),  # auto-expand multi-output (likely cert roots)
                ):
                    # Tx-level label
                    tx_label_key = f"tx:{txid}"
                    old_tx_label = labels.get(tx_label_key, "")
                    new_tx_label = st.text_input(
                        "Tx label (applies to the funding transaction)",
                        value=old_tx_label,
                        key=f"label_tx_{txid}",
                        placeholder="e.g. 'La Verna funding', 'reserve', 'change'",
                    )
                    if new_tx_label != old_tx_label:
                        if new_tx_label:
                            labels[tx_label_key] = new_tx_label
                        else:
                            labels.pop(tx_label_key, None)
                        labels_changed = True

                    # Per-output labels
                    for u in outs:
                        utxo_key = f"{txid}:{u['vout']}"
                        cols = st.columns([1, 2, 4, 2])
                        cols[0].markdown(f"**vout {u['vout']}**")
                        cols[1].markdown(f"{u['amount']:,.4f} DOGE")
                        old_label = labels.get(utxo_key, "")
                        new_label = cols[2].text_input(
                            "label",
                            value=old_label,
                            key=f"label_{utxo_key}",
                            label_visibility="collapsed",
                            placeholder=(
                                f"strand seed / terminus / "
                                f"label for {u['vout']}"
                            ),
                        )
                        cols[3].caption(f"{u['confirmations']:,} confs")
                        if new_label != old_label:
                            if new_label:
                                labels[utxo_key] = new_label
                            else:
                                labels.pop(utxo_key, None)
                            labels_changed = True

                    st.code(f"Full txid: {txid}", language=None)

            if labels_changed:
                save_labels(labels)
                st.toast(f"Labels saved to {LABELS_PATH}")
