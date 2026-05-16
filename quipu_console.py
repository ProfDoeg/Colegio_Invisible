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
import hashlib
from pathlib import Path

import numpy as np
import streamlit as st
from PIL import Image

import eth_keys

sys.path.insert(0, str(Path(__file__).resolve().parent))

import colegio_tools as ct
from quipu_crypto import combine_pubkeys
import essay_renderer
from quipu_orchestrator import (
    Quipu,
    STATE_INIT, STATE_ROOT_BUILT, STATE_ROOT_BROADCAST, STATE_ROOT_CONFIRMED,
    STATE_STRANDS_PRECOMPUTED, STATE_STRANDS_BROADCAST, STATE_STRANDS_CONFIRMED,
    STATE_JOIN_BUILT, STATE_JOIN_BROADCAST, STATE_DONE,
)


# Diagnostic: increment a rerun counter on every script execution and
# print to stderr if reruns happen faster than 2/sec — that indicates a
# pathological loop somewhere.
def _diag_rerun_counter():
    import sys as _sys
    now = time.time()
    last = st.session_state.get("_last_rerun_ts")
    n = st.session_state.get("_rerun_count", 0) + 1
    st.session_state["_rerun_count"] = n
    st.session_state["_last_rerun_ts"] = now
    if last and (now - last) < 0.5:
        print(f"[rerun-counter] fast rerun #{n} ({(now-last)*1000:.0f}ms "
              f"since last)", file=_sys.stderr, flush=True)


def _cached_rpc(method, params=None, ttl=10.0):
    """Return a cached RPC result for `method(*params)`, refetching only
    when the cached value is older than `ttl` seconds. Streamlit reruns
    the whole script on every widget interaction; without this, idle
    sidebar reads (`getblockchaininfo`, `listunspent`) hammer the node
    and macOS proxy-config layer enough to peg CPU at ~80%.
    """
    cache = st.session_state.setdefault("_rpc_cache", {})
    # repr() is always hashable, handles nested lists/dicts in params
    # (e.g. listunspent's address list arg) without converting them.
    cache_key = (method, repr(params))
    now = time.time()
    entry = cache.get(cache_key)
    if entry and (now - entry[0]) < ttl:
        return entry[1]
    result = ct.rpc_request(method, params)
    cache[cache_key] = (now, result)
    return result


def _pick_folder_native(prompt="Pick a folder"):
    """Open a native macOS folder picker via osascript and return the
    chosen POSIX path, or None if the user cancelled (or this isn't a
    Mac). Streamlit runs locally so the dialog opens on the user's
    screen — no thread/Tk fragility, just a subprocess."""
    import subprocess
    try:
        result = subprocess.run(
            [
                "osascript",
                "-e", 'tell application "System Events" to activate',
                "-e", f'POSIX path of (choose folder with prompt "{prompt}")',
            ],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode == 0:
            picked = result.stdout.strip()
            # AppleScript appends a trailing slash; strip it for clean paths
            return picked.rstrip("/") or None
    except Exception:
        return None
    return None


def _folder_input_with_browse(label, key, default):
    """Render a folder-path text_input with a "📂 Browse…" button
    stacked below that pops a native picker. Returns the current path
    string."""
    if key not in st.session_state:
        st.session_state[key] = default
    st.text_input(label, key=key)
    if st.button("📂 Browse…", key=f"{key}__browse",
                 use_container_width=True):
        picked = _pick_folder_native(label)
        if picked:
            st.session_state[key] = picked
            st.rerun()
    return st.session_state[key]


# ----------------------------------------------------------------------
# Page setup
# ----------------------------------------------------------------------

st.set_page_config(page_title="Colegio Invisible — Quipu Console", layout="wide")
st.title("Colegio Invisible — Quipu Console")

# ----------------------------------------------------------------------
# Sidebar — identity and node
# ----------------------------------------------------------------------

_diag_rerun_counter()

with st.sidebar:
    st.header("Identity")

    if "priv_keys" not in st.session_state:
        st.session_state.priv_keys = []
    # Track addresses we've called importaddress for in this session,
    # so we don't re-import them on every rerun.
    _imported_set = st.session_state.setdefault("_imported_addresses", set())

    def _auto_import(addr, label):
        """Quietly importaddress (rescan=False) once per session. Fast,
        only tracks future txs — pair with the 🔄 Rescan button when
        catching an already-sent tx.

        Mark the address as attempted BEFORE the RPC call so a thrown
        exception ("already in wallet" etc.) doesn't put us in a
        retry-on-every-rerun loop — which is what made the Load-multisig
        rerun storm happen.
        """
        if addr in _imported_set:
            return
        _imported_set.add(addr)
        try:
            ct.add_address_to_node(addr, label or "auto-imported", False)
        except Exception:
            pass  # already in wallet, or other benign

    # ─── Refresh button ──────────────────────────────────────────────
    # One-tap re-poll of balances + node-state. Clears just the RPC
    # cache for listunspent / getblockchaininfo / getreceivedbyaddress —
    # NOT the history scan dataframes (which are heavy to rebuild and
    # rarely change).
    if st.button("↻ Refresh balances", use_container_width=True,
                 key="sidebar_refresh_btn",
                 help="Re-poll the node for current UTXOs at every "
                      "loaded address. Keeps the topology history "
                      "dataframes intact (those only rebuild on "
                      "↻ Compute / refresh history in the Wallet tab)."):
        cache = st.session_state.get("_rpc_cache", {})
        for ckey in list(cache.keys()):
            method = ckey[0] if isinstance(ckey, tuple) else ""
            if method in ("listunspent", "getblockchaininfo",
                          "getreceivedbyaddress"):
                cache.pop(ckey, None)
        st.rerun()

    def _mirror_first_key():
        """Keep legacy `priv_hex` / `addr` / `utxos` in sync with priv_keys[0]
        so existing code paths (Inscribe tab, single-key reader) still work."""
        if st.session_state.priv_keys:
            first = st.session_state.priv_keys[0]
            st.session_state.priv_hex = first["priv_hex"]
            st.session_state.addr = first["addr"]
        else:
            st.session_state.pop("priv_hex", None)
            st.session_state.pop("addr", None)
            st.session_state.pop("utxos", None)

    # Loaded keys list — each row has a QR popover + a remove button
    for i, k in enumerate(st.session_state.priv_keys):
        c1, c2, c3 = st.columns([5, 1, 1])
        with c1:
            st.markdown(
                f"**{i+1}.** `{k['addr']}`",
                help=k.get("label", ""),
            )
        with c2:
            with st.popover("📷", help="Show QR code for this address"):
                try:
                    _qr = ct.make_qr(k["addr"])
                    _buf = io.BytesIO()
                    _qr.save(_buf, format="PNG")
                    st.image(_buf.getvalue(), width=240)
                    st.code(k["addr"], language=None)
                except Exception as _e:
                    st.error(f"QR failed: {_e}")
        with c3:
            if st.button("✕", key=f"remove_key_{i}",
                         help="Remove this key from the session"):
                st.session_state.priv_keys.pop(i)
                _mirror_first_key()
                st.rerun()

    # When 2+ keys loaded, compute BOTH group addresses — they serve
    # different purposes:
    #   - Multisig P2SH: inscribe FROM this address (m-of-n cosigning).
    #     Defaults to m=N which matches the project's canonical shapes
    #     (HA/CA = 2-of-2, bordado = 3-of-3). For non-default m, use
    #     Keys tab → Make multisig.
    #   - Combined-key (curve sum): receive encrypted-to-group ECIES
    #     envelopes; decrypted by combining all N privkeys.
    if len(st.session_state.priv_keys) >= 2:
        try:
            import cryptos as _cr
            from quipu_crypto import combine_privkeys as _combine_priv
            privs = [
                eth_keys.keys.PrivateKey(bytes.fromhex(k["priv_hex"]))
                for k in st.session_state.priv_keys
            ]
            pubs_hex = ["04" + p.public_key.to_hex()[2:] for p in privs]
            n = len(privs)

            # Multisig — for inscribing (writing)
            try:
                redeem_hex, ms_addr = _cr.Doge().mk_multisig_address(
                    *pubs_hex, num_required=n,
                )
                # Auto-import so listunspent at this address works
                _auto_import(ms_addr, f"sidebar_{n}of{n}_multisig")
                st.caption(
                    f"**{n}-of-{n} multisig address** — fund + inscribe FROM "
                    f"this with cosigning:"
                )
                ms_cols = st.columns([5, 1])
                with ms_cols[0]:
                    st.code(ms_addr, language=None)
                with ms_cols[1]:
                    with st.popover("📷", help="QR + Rescan"):
                        try:
                            _qr = ct.make_qr(ms_addr)
                            _buf = io.BytesIO()
                            _qr.save(_buf, format="PNG")
                            st.image(_buf.getvalue(), width=240)
                            st.code(ms_addr, language=None)
                        except Exception as _e:
                            st.error(f"QR failed: {_e}")
                        if st.button("🔄 Rescan chain for this address",
                                     use_container_width=True,
                                     key="rescan_sidebar_ms",
                                     help="Slow — only needed once to "
                                          "catch a tx that was sent "
                                          "before the address joined the "
                                          "watch set."):
                            try:
                                with st.spinner("Rescanning… this can take "
                                                "a few minutes."):
                                    ct.add_address_to_node(
                                        ms_addr,
                                        f"sidebar_{n}of{n}_multisig",
                                        True,
                                    )
                                st.success("Rescan complete.")
                                cache = st.session_state.get("_rpc_cache", {})
                                for ckey in list(cache.keys()):
                                    if (isinstance(ckey, tuple)
                                            and ckey[0] == "listunspent"
                                            and ms_addr in repr(ckey[1])):
                                        cache.pop(ckey, None)
                            except Exception as e:
                                st.error(f"Rescan failed: {e}")

                # Save the multisig bundle (addr, redeem, manifest, QR)
                with st.expander("💾 Save multisig", expanded=False):
                    sidebar_ms_basename = st.text_input(
                        "Basename", value="multisig",
                        key="sidebar_ms_basename",
                    )
                    sidebar_ms_save_dir = _folder_input_with_browse(
                        "Save folder",
                        key="sidebar_ms_save_dir",
                        default=str(Path.home() / "Desktop" / "cinv" / "llaves"),
                    )
                    if st.button("Save to folder",
                                 use_container_width=True,
                                 key="sidebar_ms_save_btn"):
                        try:
                            import json as _json
                            folder = Path(sidebar_ms_save_dir).expanduser()
                            folder.mkdir(parents=True, exist_ok=True)
                            base = sidebar_ms_basename or "multisig"
                            manifest = {
                                "address": ms_addr,
                                "redeem_script_hex": redeem_hex,
                                "m": n, "n": n,
                                "pubkeys": pubs_hex,
                                "labels": [
                                    k.get("label", k["addr"])
                                    for k in st.session_state.priv_keys
                                ],
                                "basename": base,
                            }
                            (folder / f"{base}_multisig_addr.bin").write_bytes(
                                ms_addr.encode("utf-8")
                            )
                            (folder / f"{base}_multisig_redeem.bin").write_bytes(
                                bytes.fromhex(redeem_hex)
                            )
                            (folder / f"{base}_multisig.json").write_text(
                                _json.dumps(manifest, indent=2)
                            )
                            try:
                                ct.make_qr(
                                    ms_addr,
                                    str(folder / f"{base}_multisig_addr.png"),
                                )
                            except Exception:
                                pass
                            st.success(
                                f"Wrote {base}_multisig_addr.bin / "
                                f"_redeem.bin / .json (and _addr.png) to "
                                f"{folder}"
                            )
                        except Exception as e:
                            st.error(f"Save failed: {e}")
            except Exception as _e:
                st.caption(f"(multisig calc failed: {_e})")

            # Combined pubkey — for ECIES envelopes addressed to the
            # group. (Showing a derived address would be misleading —
            # ECIES recipients are identified by pubkey, not by address;
            # the address has no role in the encryption primitive.)
            try:
                from quipu_crypto import combine_pubkeys as _combine_pub
                combined_pub = _combine_pub([p.public_key for p in privs])
                combined_pub_hex = "04" + combined_pub.to_hex()[2:]
                st.caption(
                    f"**Combined pubkey** (curve sum) — paste this as a "
                    f"single recipient in ECIES Broadcast to seal envelopes "
                    f"to the whole group:"
                )
                st.code(combined_pub_hex, language=None)
            except Exception as _e:
                st.caption(f"(combined-pubkey calc failed: {_e})")
        except Exception as _e:
            st.caption(f"(group-address calcs failed: {_e})")

    # Make a fresh key — configure destination BEFORE clicking, so the
    # one click both creates+loads the key AND writes it to disk.
    with st.expander(
        "✨ Make a key",
        expanded=False,
    ):
        st.caption(
            "Generate a fresh Dogecoin keypair, immediately add it to "
            "the loaded set, and (if a folder path is set) write the "
            "encrypted `_prv.enc` to that folder. Same envelope as the "
            "Keys tab."
        )
        mk_name = st.text_input(
            "Basename", value="new_key", key="sidebar_make_name",
        )
        mk_pw = st.text_input(
            "Password (empty = unprotected, matches apocrypha test key)",
            type="password", value="", key="sidebar_make_pw",
        )
        mk_save_dir = _folder_input_with_browse(
            "Save folder (leave blank for download-only)",
            key="sidebar_make_save_dir",
            default=str(Path.home() / "Desktop" / "cinv" / "llaves"),
        )
        if st.button("Make and load", use_container_width=True,
                     key="sidebar_make_btn"):
            try:
                import ecies as _ecies
                import cryptos as _cryptos
                priv = _ecies.utils.generate_eth_key()
                priv_hex = priv.to_hex()[2:]
                addr = _cryptos.Doge().pubtoaddr(
                    "04" + priv.public_key.to_hex()[2:]
                )
                enc_bytes = _ecies.sym_encrypt(
                    key=hashlib.sha256((mk_pw or "").encode()).digest(),
                    plain_text=priv.to_bytes(),
                )
                if any(k["priv_hex"] == priv_hex for k in st.session_state.priv_keys):
                    st.warning(
                        f"This key already happens to be loaded (??): {addr}"
                    )
                else:
                    st.session_state.priv_keys.append({
                        "priv_hex": priv_hex,
                        "addr": addr,
                        "label": f"{mk_name or 'new_key'}_prv.enc",
                    })
                    _mirror_first_key()
                    st.session_state["sidebar_make_result"] = {
                        "basename": mk_name or "new_key",
                        "addr": addr,
                        "enc_bytes": enc_bytes,
                    }
                    # If a save folder was provided, write the file now.
                    save_note = ""
                    if mk_save_dir.strip():
                        try:
                            folder = Path(mk_save_dir).expanduser()
                            folder.mkdir(parents=True, exist_ok=True)
                            target = folder / f"{mk_name or 'new_key'}_prv.enc"
                            target.write_bytes(enc_bytes)
                            save_note = f" · wrote {target}"
                        except Exception as save_err:
                            save_note = (
                                f" · save to {mk_save_dir!r} FAILED: "
                                f"{save_err}"
                            )
                    st.success(f"Made and loaded {addr}{save_note}")
            except Exception as e:
                st.error(f"Key creation failed: {e}")

        # After creation, still offer the browser download as a fallback
        # (e.g., in case the on-disk save failed).
        mk_result = st.session_state.get("sidebar_make_result")
        if mk_result:
            st.download_button(
                f"↓ Download {mk_result['basename']}_prv.enc",
                data=mk_result["enc_bytes"],
                file_name=f"{mk_result['basename']}_prv.enc",
                mime="application/octet-stream",
                use_container_width=True,
                key="sidebar_make_dl",
            )

    # Load an existing key from file
    with st.expander(
        "➕ Load a key" if st.session_state.priv_keys else "Load a key",
        expanded=not st.session_state.priv_keys,
    ):
        st.caption("Drop a `_prv.enc` keyfile, or use the file picker.")
        key_upload = st.file_uploader(
            "Key file (drag-drop or browse)",
            type=None, accept_multiple_files=False,
            key="add_key_upload",
        )
        password = st.text_input(
            "Password", value="", type="password", key="add_key_pw",
            help="Empty string for the apocrypha test key",
        )
        if st.button("Load key", use_container_width=True,
                     disabled=key_upload is None, key="add_key_btn"):
            try:
                priv = ct.import_privKey_from_bytes(
                    key_upload.getvalue(), password,
                )
                priv_hex = priv.to_hex()[2:]
                import cryptos
                addr = cryptos.Doge().privtoaddr(priv_hex)
                if any(k["priv_hex"] == priv_hex for k in st.session_state.priv_keys):
                    st.warning(f"Key for {addr} is already loaded.")
                else:
                    st.session_state.priv_keys.append({
                        "priv_hex": priv_hex,
                        "addr": addr,
                        "label": key_upload.name,
                    })
                    _mirror_first_key()
                    st.success(f"Loaded {addr}")
                    st.rerun()
            except Exception as e:
                st.error(f"Key load failed: {e}")

    # Balance per loaded key (first is also published as session.utxos for
    # the existing single-key inscribe flow). RPC results cached 10s so
    # idle reruns don't hammer the node.
    for i, k in enumerate(st.session_state.priv_keys):
        try:
            ut = _cached_rpc("listunspent", [0, 9999999, [k["addr"]]], ttl=10.0)
            total = sum(u["amount"] for u in ut)
            st.caption(
                f"`{k['addr'][:12]}…` — **{total} DOGE** "
                f"({len(ut)} UTXO{'s' if len(ut) != 1 else ''})"
            )
            if i == 0:
                st.session_state.utxos = ut
        except Exception as e:
            st.error(f"Balance query failed for key {i+1}: {e}")

    # ---------------- Loaded multisigs ------------------------------
    st.divider()
    st.subheader("Loaded multisigs")

    if "loaded_multisigs" not in st.session_state:
        st.session_state.loaded_multisigs = []

    # Each loaded multisig: address + QR popover + remove + balance
    for i, ms in enumerate(st.session_state.loaded_multisigs):
        # Auto-import so listunspent works at this address
        _auto_import(ms["address"], ms.get("basename", "loaded_multisig"))

        c1, c2, c3 = st.columns([5, 1, 1])
        with c1:
            st.markdown(
                f"**{i+1}.** `{ms['address']}` &nbsp; "
                f"<span style='font-size:10px; color:#888'>"
                f"{ms.get('m','?')}-of-{ms.get('n','?')}</span>",
                help=ms.get("basename", ""),
                unsafe_allow_html=True,
            )
        with c2:
            with st.popover("📷", help="QR + Rescan"):
                try:
                    _qr = ct.make_qr(ms["address"])
                    _buf = io.BytesIO()
                    _qr.save(_buf, format="PNG")
                    st.image(_buf.getvalue(), width=240)
                    st.code(ms["address"], language=None)
                    st.caption(
                        f"{ms.get('m','?')}-of-{ms.get('n','?')} · "
                        f"{len(ms.get('pubkeys',[]))} participant pubkeys"
                    )
                except Exception as _e:
                    st.error(f"QR failed: {_e}")
                # Per-multisig rescan — catches past txs sent before
                # the address was first imported
                if st.button("🔄 Rescan chain for this address",
                             use_container_width=True,
                             key=f"rescan_ms_{i}",
                             help="Slow (minutes) — only needed once to "
                                  "catch a tx that was sent before the "
                                  "address joined the watch set."):
                    try:
                        with st.spinner("Rescanning… this can take a few "
                                        "minutes. RPC blocks until done."):
                            ct.add_address_to_node(
                                ms["address"],
                                ms.get("basename", "rescan"),
                                True,
                            )
                        st.success("Rescan complete.")
                        # Force balance refresh
                        cache = st.session_state.get("_rpc_cache", {})
                        for ckey in list(cache.keys()):
                            if (isinstance(ckey, tuple)
                                    and ckey[0] == "listunspent"
                                    and ms["address"] in repr(ckey[1])):
                                cache.pop(ckey, None)
                    except Exception as e:
                        st.error(f"Rescan failed: {e}")
        with c3:
            if st.button("✕", key=f"remove_ms_{i}",
                         help="Remove this multisig from the session"):
                st.session_state.loaded_multisigs.pop(i)
                st.rerun()
        # Balance lookup (cached)
        try:
            ut = _cached_rpc(
                "listunspent", [0, 9999999, [ms["address"]]], ttl=10.0,
            )
            total = sum(u["amount"] for u in ut)
            st.caption(
                f"&nbsp;&nbsp;`{ms['address'][:12]}…` — **{total} DOGE** "
                f"({len(ut)} UTXO{'s' if len(ut) != 1 else ''})",
                unsafe_allow_html=True,
            )
        except Exception as e:
            st.caption(f"&nbsp;&nbsp;(balance query failed: {e})",
                       unsafe_allow_html=True)

    # Load a multisig from a .json manifest
    with st.expander(
        "📥 Load multisig",
        expanded=not st.session_state.loaded_multisigs,
    ):
        st.caption(
            "Drop a `_multisig.json` manifest (saved earlier via 💾 "
            "Save multisig). Reconstitutes the address, redeem script, "
            "and participant pubkeys — does NOT load any privkeys."
        )
        ms_upload = st.file_uploader(
            "Multisig manifest (.json)",
            type=["json"], accept_multiple_files=False,
            key="load_ms_upload",
        )
        if st.button("Load multisig", use_container_width=True,
                     disabled=ms_upload is None, key="load_ms_btn"):
            try:
                import json as _json
                manifest = _json.loads(ms_upload.getvalue().decode("utf-8"))
                # Sanity check shape
                required = {"address", "redeem_script_hex", "m", "n", "pubkeys"}
                missing = required - set(manifest.keys())
                if missing:
                    raise ValueError(
                        f"manifest missing required fields: "
                        f"{', '.join(sorted(missing))}"
                    )
                addr = manifest["address"]
                if any(m["address"] == addr
                       for m in st.session_state.loaded_multisigs):
                    st.warning(f"Multisig {addr} is already loaded.")
                else:
                    st.session_state.loaded_multisigs.append(manifest)
                    st.success(
                        f"Loaded {manifest.get('m','?')}-of-"
                        f"{manifest.get('n','?')} multisig: {addr}"
                    )
                    st.rerun()
            except Exception as e:
                st.error(f"Multisig load failed: {e}")

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
            "Drop a 32-byte AES key file. The file may itself be "
            "password-protected (same SHA-256 → AES envelope as the "
            "`_prv.enc` keyfiles) — leave the inner password blank if the "
            "file holds the raw key directly."
        )
        aes_key_upload = st.file_uploader(
            "AES key file (drag-drop or browse)",
            type=None, accept_multiple_files=False,
            key="aes_key_upload",
        )
        aes_inner_pw = st.text_input(
            "Inner password (empty = unencrypted file)",
            value="", type="password", key="aes_inner_pw_input",
        )
        if st.button("Load AES key", use_container_width=True,
                     disabled=aes_key_upload is None):
            try:
                raw = aes_key_upload.getvalue()
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
        info = _cached_rpc("getblockchaininfo", ttl=10.0)
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

# Per-address accent colours used to tint each quipu's border in the
# multi-address topology, and to fill the "cellular surface" hull around
# each address's cluster of quipus. Soft pastels so the type-coded fill
# colour of the quipu node remains the dominant visual.
ADDRESS_COLORS = {
    "9xth7DcLGb1nACScMBeSfDCfghhLKF7yqs": "#3a7a3a",   # hca / bordado — green
    "A7pfCe2Cw9JD2C4vEZbpDmUZJy7B2TaefV": "#7a3a7a",   # ha — magenta
    "AD28bxzxyrd3a4Qgad2VNQ2eN5Leg8ozuw": "#7a5a3a",   # ca — amber
    "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX": "#3a5a7a",   # apocrypha — blue
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


def filter_quipus(quipus, types=None, tone=None, date_from=None, date_to=None,
                  title_substr=None):
    """Apply UI filters to the quipus list. None values disable that filter.

      types        : iterable of type bytes (ints) — keep only matching
      tone         : "any" | "ordinary" | "reverence"
      date_from    : datetime.date — keep quipus inscribed on/after this date
      date_to      : datetime.date — keep quipus inscribed on/before this date
      title_substr : str — case-insensitive substring match against title
    """
    import datetime
    out = []
    types_set = set(types) if types else None
    sub = (title_substr or "").strip().lower()
    for q in quipus:
        if types_set is not None and q.get("type_byte") not in types_set:
            continue
        if tone == "reverence" and q.get("tone_byte") != 0xff:
            continue
        if tone == "ordinary" and q.get("tone_byte") == 0xff:
            continue
        if (date_from or date_to) and q.get("blocktime"):
            d = datetime.date.fromtimestamp(q["blocktime"])
            if date_from and d < date_from:
                continue
            if date_to and d > date_to:
                continue
        if sub and sub not in (q.get("title") or "").lower():
            continue
        out.append(q)
    return out


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
                            priv_hex_list=None, aes_password=None):
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
        # Build candidate privkeys: each individual key + the combined-all
        # (covers single-key envelopes AND combined-key envelopes targeted at
        # the curve-sum of the loaded keys).
        priv_hex_list = priv_hex_list if priv_hex_list else (
            [priv_hex] if priv_hex else []
        )
        if priv_hex_list and root_txid:
            try:
                pub_cache = st.session_state.get("author_pub_hex_cache", {})
                pub_hex = pub_cache.get(root_txid)
                if not pub_hex:
                    pub_hex = ct.get_txn_pub_from_node(root_txid)
                    pub_cache[root_txid] = pub_hex
                author_pub = eth_keys.keys.PublicKey(bytes.fromhex(pub_hex))
            except Exception:
                author_pub = None
            if author_pub is not None:
                candidates = []
                # individual keys
                for i, ph in enumerate(priv_hex_list):
                    try:
                        candidates.append(
                            (f"key {i+1}",
                             eth_keys.keys.PrivateKey(bytes.fromhex(ph)))
                        )
                    except Exception:
                        pass
                # combined of all loaded
                if len(priv_hex_list) >= 2:
                    try:
                        from quipu_crypto import combine_privkeys
                        combined = combine_privkeys([c[1] for c in candidates])
                        candidates.append(
                            (f"combined key ({len(candidates)} → 1)", combined)
                        )
                    except Exception:
                        pass
                for label, priv in candidates:
                    try:
                        inner_h, inner_b = ct.read_broadcast_quipu(
                            header_bytes, body_bytes, priv, author_pub
                        )
                        return {
                            "kind": kind, "status": "decrypted",
                            "inner_header": inner_h, "inner_body": inner_b,
                            "via": f"loaded {label} (broadcast envelope)",
                            "details": {},
                        }
                    except Exception:
                        continue
        if root_txid:
            # Cache check first — topology build precomputes the keydrop
            # resolutions and stuffs them in session_state so popups
            # don't rescan per quipu.
            cache = st.session_state.get("keydrop_resolutions_cache", {})
            hit = cache.get(root_txid)
            if hit is None and quipus is not None and df_out is not None:
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
        if root_txid:
            # Cache check first — topology build precomputes the keydrop
            # resolutions and stuffs them in session_state so popups
            # don't rescan per quipu.
            cache = st.session_state.get("keydrop_resolutions_cache", {})
            hit = cache.get(root_txid)
            if hit is None and quipus is not None and df_out is not None:
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
    roots_inscribed = ct.find_quipu_roots(address, df_tx, df_out)
    roots_pre = ct.find_pre_funded_quipu_roots(address, df_tx, df_out)
    # Merge — pre-funded roots are quipus that haven't been written yet
    roots = list(roots_inscribed)
    inscribed_set = set(roots_inscribed)
    for r in roots_pre:
        if r not in inscribed_set:
            roots.append(r)
    quipus = []
    for root in roots:
        pre_funded = root not in inscribed_set
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
        # Robust title extraction — uses essay_renderer's per-type-aware
        # parser (handles pipe-less headers like Monte Veritá and
        # whitespace-padded ones like La Verna).
        try:
            title = essay_renderer.first_title(header_bytes)
        except Exception:
            title = ""

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
            "pre_funded": pre_funded,
        })

    # Sort by blocktime descending (newest first)
    quipus.sort(key=lambda q: -q["blocktime"])
    return {"quipus": quipus, "df_tx": df_tx, "df_out": df_out}


def compute_quipu_topology(address, quipus, df_tx, df_out=None):
    """Build a clean topology of quipus and how they connect.

    Each quipu = ONE node. For each of a quipu's N strand outputs we draw
    ONE edge to whatever consumed it (another quipu, a consolidation tx,
    or an external exit). Genuinely-unspent strands get an explicit open
    "tendril" marker — the only place dangling lines appear. Internal
    OP_RETURN-bridge plumbing inside strands is invisible.

    Node kinds:
      - quipu_root      — a quipu's root tx (the broom-head)
      - consolidation   — a wallet tx that consumed strand terminus
                          output(s) but isn't itself a quipu
      - exit            — strand terminus left the watched address space
                          (spender not in df_tx)
      - external_in     — synthetic node representing "funding from
                          outside the quipu graph" for quipus whose root
                          wasn't funded by another quipu's strand
      - unspent_tendril — synthetic node marking an unspent strand output
                          (pre-funded but not yet inscribed, OR strand
                          inscribed but terminus still sitting unspent)

    Edges are 3-tuples (src, dst, kind):
      - kind="forward"  — quipu_root → consumer (or quipu_root → tendril)
      - kind="funding"  — external_in → quipu_root
      - kind="keydrop"  — keydrop quipu → encrypted quipu it unlocks

    Returns (nodes, edges, keydrop_resolutions) where keydrop_resolutions
    is a {encrypted_txid: (keydrop_quipu, aes_key)} map — cached at
    topology time and reused by popups so they don't rescan.
    """
    root_set = {q["root_txid"] for q in quipus}
    df_tx_by_id = df_tx.set_index("txid") if df_tx is not None else None

    nodes = {}
    edges = []
    keydrop_resolutions = {}

    # 1. Quipu nodes
    for q in quipus:
        nodes[q["root_txid"]] = {"kind": "quipu_root", "quipu": q}

    if df_out is None:
        return nodes, edges, keydrop_resolutions

    # 2. Each strand's onward spend (or tendril if truly unspent).
    # Classification per strand output:
    #   df_out has spent_in populated   → wallet-internal spender (consolidation/quipu)
    #   df_out empty + gettxout = UTXO  → genuinely unspent (tendril)
    #   df_out empty + gettxout = null  → spent off-wallet (exit) — collapse
    #                                     per-quipu so 129 off-wallet strands
    #                                     don't render as 129 separate edges
    # gettxout calls are cached in session_state and batched via ThreadPool
    # because they're the topology-build bottleneck (~50 ms each on a local
    # node, multiplied by ~129 for the aa0c3ea6 quipu alone).
    try:
        gettxout_cache = st.session_state.setdefault("topology_gettxout_cache", {})
    except (NameError, AttributeError):
        gettxout_cache = {}

    # --- Pass 2a: collect strand-by-strand classifications ----------------
    # We build a list of plans:
    #   ("spent", root, spend_tx)                — already known from df_out
    #   ("needs_rpc", root, s_idx, lookup_txout) — need gettxout to classify
    plans = []
    rpc_pending = []  # list of (txid, int(vout)) keys for batched gettxout
    for q in quipus:
        root = q["root_txid"]
        num_outputs = q.get("num_outputs") or len(q.get("strand_termini") or [])
        strand_termini = q.get("strand_termini") or []
        strand_lengths = q.get("strand_lengths") or []
        for s_idx in range(num_outputs):
            s_len = strand_lengths[s_idx] if s_idx < len(strand_lengths) else 0
            terminus = strand_termini[s_idx] if s_idx < len(strand_termini) else None
            lookup_txout = f"{terminus}:0" if (s_len > 0 and terminus) else f"{root}:{s_idx}"
            rows = df_out[df_out["txout"] == lookup_txout]
            spend_tx = None
            if not rows.empty:
                v = rows.iloc[0]["spent_in"]
                if v and not (isinstance(v, float) and v != v):
                    spend_tx = v
            if spend_tx:
                plans.append(("spent", root, s_idx, s_len, spend_tx))
            else:
                plans.append(("needs_rpc", root, s_idx, s_len, lookup_txout))
                # Queue gettxout if not already cached
                if lookup_txout not in gettxout_cache:
                    ltx, lvout = lookup_txout.split(":")
                    rpc_pending.append((ltx, int(lvout)))

    # --- Pass 2b: batch the pending gettxout calls ------------------------
    if rpc_pending:
        from concurrent.futures import ThreadPoolExecutor
        def _do_gettxout(arg):
            txid, vout = arg
            try:
                return ct.rpc_request("gettxout", [txid, vout, True])
            except Exception:
                return "ERR"
        # 16 workers is well within local-node RPC capacity and turns ~129
        # serial calls into ~8 batches of parallel I/O.
        with ThreadPoolExecutor(max_workers=16) as _ex:
            results = list(_ex.map(_do_gettxout, rpc_pending))
        for (txid, vout), res in zip(rpc_pending, results):
            gettxout_cache[f"{txid}:{vout}"] = res

    # --- Pass 2c: realize nodes and edges using the now-populated cache ---
    for plan in plans:
        if plan[0] == "spent":
            _, root, s_idx, s_len, spend_tx = plan
            if spend_tx not in nodes:
                if df_tx_by_id is not None and spend_tx in df_tx_by_id.index:
                    parent_row = df_tx_by_id.loc[spend_tx]
                    n_in = int(parent_row["num_inputs"])
                    n_out = int(parent_row["num_outputs"])
                    nodes[spend_tx] = {
                        "kind": "consolidation",
                        "txid": spend_tx,
                        "n_in": n_in, "n_out": n_out,
                        "blocktime": int(parent_row.get("blocktime", 0) or 0),
                    }
                else:
                    nodes[spend_tx] = {"kind": "exit", "txid": spend_tx}
            edges.append((root, spend_tx, "forward"))
            continue

        # plan[0] == "needs_rpc"
        _, root, s_idx, s_len, lookup_txout = plan
        utxo = gettxout_cache.get(lookup_txout)
        if utxo == "ERR" or utxo is not None:
            # ERR (treat conservatively as tendril) or unspent UTXO
            tendril_id = f"unspent::{root}::{s_idx}"
            nodes[tendril_id] = {
                "kind": "unspent_tendril",
                "of_quipu": root,
                "strand_index": s_idx,
                "inscribed": s_len > 0,
            }
            edges.append((root, tendril_id, "forward"))
        else:
            # utxo is None → output is spent, spender is off-wallet
            exit_id = f"exit::{root}"
            if exit_id not in nodes:
                nodes[exit_id] = {
                    "kind": "exit_offwallet",
                    "of_quipu": root,
                    "count": 0,
                }
            nodes[exit_id]["count"] += 1
            edges.append((root, exit_id, "forward"))

    # 3. Backward funding trace per quipu. Walk back from each quipu's
    # root through 1-in-1-out bridges until we hit either:
    #   - another quipu_root         → add forward edge between them
    #   - a consolidation node       → add forward edge consolidation → quipu
    #   - a wallet tx with ≥2 inputs (a consolidation not yet seen) → add it
    #     as a consolidation node + edge
    #   - the wallet boundary        → add an external_in node
    # Bridges themselves are silent (not added as nodes).
    import ast as _ast
    funded_by_known = set()  # quipus we attached upstream

    def _inputs_of(txid):
        if txid not in df_tx_by_id.index:
            return None
        v = df_tx_by_id.loc[txid]["inputs"]
        if isinstance(v, list):
            return v
        if isinstance(v, str):
            try:
                return _ast.literal_eval(v)
            except Exception:
                return []
        return []

    for q in quipus:
        root = q["root_txid"]
        inputs = _inputs_of(root)
        if not inputs:
            continue
        # Walk back via the first input's tx (heuristic — Cadena strands
        # are mostly 1-in-1-out so the first input drives the lineage).
        cur = inputs[0].split(":")[0]
        seen_walk = set()
        attached = False
        for _hop in range(40):
            if cur in seen_walk:
                break
            seen_walk.add(cur)
            # Known node already? Attach there.
            if cur in nodes and cur != root:
                kind = nodes[cur].get("kind")
                if kind in ("quipu_root", "consolidation"):
                    edges.append((cur, root, "forward"))
                    funded_by_known.add(root)
                    attached = True
                    break
            # Is this a wallet tx?
            parent_inputs = _inputs_of(cur)
            if parent_inputs is None:
                # cur is outside the wallet — funding boundary
                break
            # Is cur a new consolidation we should surface? (≥2 inputs)
            if cur in df_tx_by_id.index:
                row = df_tx_by_id.loc[cur]
                n_in = int(row["num_inputs"])
                n_out = int(row["num_outputs"])
                if n_in >= 2:
                    if cur not in nodes:
                        nodes[cur] = {
                            "kind": "consolidation",
                            "txid": cur,
                            "n_in": n_in, "n_out": n_out,
                            "blocktime": int(row.get("blocktime", 0) or 0),
                        }
                    edges.append((cur, root, "forward"))
                    funded_by_known.add(root)
                    attached = True
                    break
            if not parent_inputs:
                break
            cur = parent_inputs[0].split(":")[0]
        if not attached:
            # Couldn't pin to a known node — funding came from outside the
            # quipu graph (or beyond the wallet scan).
            ext_id = f"external_in::{root}"
            nodes[ext_id] = {
                "kind": "external_in",
                "for_quipu": root,
            }
            edges.append((ext_id, root, "funding"))

    # 4. Keydrop dashed edges + cache for popup reuse
    for q in quipus:
        if q.get("type_byte") != 0x0e:
            continue
        try:
            head_hex, body_hex = ct.read_quipu(q["root_txid"], df_out)
        except Exception:
            continue
        head = bytes.fromhex(head_hex) if head_hex else b""
        if len(head) < 7 or head[4:7] != b"\x0e\x0e\x0d":
            continue
        body = bytes.fromhex(body_hex) if body_hex else b""
        if len(body) < 64:
            continue
        target_txid = body[:32].hex()
        aes_key = body[32:64]
        keydrop_resolutions[target_txid] = (q, aes_key)
        if target_txid in root_set and target_txid != q["root_txid"]:
            edges.append((q["root_txid"], target_txid, "keydrop"))

    # 5. Pre-fetch author pubkeys for all 0x0e quipus in parallel so the
    # popup pre-render (which calls get_txn_pub_from_node for each
    # encrypted quipu) doesn't pay sequential RPC latency.
    try:
        pub_hex_cache = st.session_state.setdefault("author_pub_hex_cache", {})
    except (NameError, AttributeError):
        pub_hex_cache = {}
    pub_pending = [
        q["root_txid"] for q in quipus
        if q.get("type_byte") == 0x0e and q["root_txid"] not in pub_hex_cache
    ]
    if pub_pending:
        from concurrent.futures import ThreadPoolExecutor
        def _do_pub(txid):
            try:
                return ct.get_txn_pub_from_node(txid)
            except Exception:
                return None
        with ThreadPoolExecutor(max_workers=8) as _ex:
            results = list(_ex.map(_do_pub, pub_pending))
        for txid, result in zip(pub_pending, results):
            if result is not None:
                pub_hex_cache[txid] = result

    # Cap parallel edges at 54. A quipu with 199 strands all flowing
    # into one consolidation otherwise renders 199 superimposed
    # springs — cumulative force yanks the consolidation INSIDE the
    # quipu_root, attractive + repulsive forces fight, layout never
    # settles, browser pegs CPU. Keeping up to 54 preserves the
    # spindle/mitotic-fiber aesthetic; the first drawn edge carries
    # a "N strands" label when the true count exceeds the cap.
    MAX_PARALLEL = 54
    grouped = {}  # (src, dst, kind) → count
    for src, dst, ekind in edges:
        grouped[(src, dst, ekind)] = grouped.get((src, dst, ekind), 0) + 1
    capped_edges = []
    for (src, dst, ekind), count in grouped.items():
        drawn = min(count, MAX_PARALLEL)
        for i in range(drawn):
            # Label only on the first edge of a group, and only when
            # the cap actually truncated something
            label = (f"{count} strands"
                     if (i == 0 and count > MAX_PARALLEL) else None)
            capped_edges.append((src, dst, ekind, label))
    edges = capped_edges

    return nodes, edges, keydrop_resolutions


def _render_body_html(type_byte, header_bytes, body_bytes, *,
                       root_txid=None, quipus=None, df_out=None):
    """Per-type HTML body rendering. Returns a list of HTML fragments.
    Called both for plaintext quipus and for the decrypted inner content of
    encrypted ones. Typographic types (text/essay, identity, cert) dispatch
    to essay_renderer; image stays a leaf renderer."""
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
            buf = _io.BytesIO()
            img_pil.save(buf, format="PNG")
            b64 = _b64.b64encode(buf.getvalue()).decode("ascii")
            parts.append(
                f"<img src='data:image/png;base64,{b64}' "
                f"width='{W}' height='{H}' "
                f"style='display:block; max-width:100%; height:auto; "
                f"image-rendering: pixelated; "
                f"border: 1px solid #ccc; border-radius: 4px;' />"
            )
        except Exception as e:
            parts.append(f"<p>Image decode failed: {_html.escape(str(e))}</p>")

    elif type_byte in (0x00, 0x04, 0x1d, 0x0c, 0xcc):
        # Typographic — text/essay, identity, or cert
        try:
            parts.append(essay_renderer.render_typographic(
                type_byte, header_bytes, body_bytes,
                root_txid=root_txid, quipus=quipus, df_out=df_out,
            ))
        except Exception as e:
            parts.append(
                f"<p style='color:#a06060'>Typographic render failed: "
                f"{_html.escape(str(e))}</p>"
            )

    else:
        parts.append(
            f"<pre style='font-size:10px; max-height:200px; "
            f"overflow-y:auto; background:#f5f5f5; padding:8px'>"
            f"{_html.escape(body_bytes.hex()[:600])}…</pre>"
        )

    return parts


def render_body_streamlit(type_byte, header_bytes, body_bytes, *,
                          root_txid=None, quipus=None, df_out=None):
    """Per-type Streamlit body rendering. Typographic types (text/essay,
    identity, cert) dispatch to essay_renderer and render as HTML. Image
    stays a native Streamlit render."""
    if type_byte == 0x03:
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
            # Direct pixel mapping — width=W
            st.image(arr, width=W)
        except Exception as e:
            st.error(f"Image decode failed: {e}")
            st.code(body_bytes.hex()[:200], language=None)
    elif type_byte in (0x00, 0x04, 0x1d, 0x0c, 0xcc):
        try:
            html = essay_renderer.render_typographic(
                type_byte, header_bytes, body_bytes,
                root_txid=root_txid, quipus=quipus, df_out=df_out,
            )
            st.markdown(html, unsafe_allow_html=True)
        except Exception as e:
            st.error(f"Typographic render failed: {e}")
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
    priv_hex_list = [k["priv_hex"] for k in st.session_state.get("priv_keys", [])]
    resolved = resolve_encrypted_quipu(
        header_bytes, body_bytes,
        root_txid=root_txid, df_out=df_out, quipus=quipus,
        priv_hex=st.session_state.get("priv_hex"),
        priv_hex_list=priv_hex_list,
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
        render_body_streamlit(
            inner_type, inner_h, inner_b,
            root_txid=root_txid, quipus=quipus, df_out=df_out,
        )
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
        priv_hex_list = [k["priv_hex"] for k in st.session_state.get("priv_keys", [])]
        resolved = resolve_encrypted_quipu(
            header_bytes, body_bytes,
            root_txid=q["root_txid"], df_out=df_out, quipus=quipus,
            priv_hex=st.session_state.get("priv_hex"),
            priv_hex_list=priv_hex_list,
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
            parts.extend(_render_body_html(
                inner_type, inner_h, inner_b,
                root_txid=q["root_txid"], quipus=quipus, df_out=df_out,
            ))
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
        parts.extend(_render_body_html(
            type_byte, header_bytes, body_bytes,
            root_txid=q["root_txid"], quipus=quipus, df_out=df_out,
        ))

    parts.append(
        f"<details style='margin-top:10px; font-size:10px'>"
        f"<summary style='cursor:pointer; color:#888'>header bytes</summary>"
        f"<code style='word-break:break-all; font-size:9px'>"
        f"{_html.escape(header_bytes.hex())}</code></details>"
    )

    return "".join(parts)


def render_topology_pyvis(nodes, edges, labels=None, address=None, height_px=620, df_out=None, quipus=None, address_groups=None):
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
            pre_funded = q.get("pre_funded", False)
            total_txs = sum(q["strand_lengths"]) + 1
            tx_label = labels.get(f"tx:{txid}", "")
            date_str = ""
            if q["blocktime"]:
                try:
                    date_str = _dt.datetime.fromtimestamp(
                        q["blocktime"]
                    ).strftime("%Y-%m-%d")
                except Exception:
                    pass
            if pre_funded:
                # Broomhead waiting to be inscribed — hexagon, pale colour,
                # bordered to distinguish from filled quipu_roots.
                color = {"background": "#fff7d6", "border": "#c2a500"}
                size = max(20, min(40, 14 + q["num_outputs"] ** 0.5 * 2))
                primary = tx_label or f"✎ ready ({q['num_outputs']} strands)"
                label = primary[:24]
                title = (
                    f"{primary}\n"
                    f"pre-funded broomhead — {q['num_outputs']} strand "
                    f"outputs, none inscribed yet\n"
                    f"{date_str}\n{txid}"
                )
                net.add_node(txid, label=label, title=title, color=color,
                             size=size, shape="hexagon", borderWidth=2)
            else:
                color = TYPE_COLORS.get(q["type_byte"], "#cccccc")
                size = max(18, min(60, 12 + total_txs ** 0.5 * 3))
                primary = tx_label or q["title"] or txid[:8]
                label = primary[:24]
                type_name = TYPE_SHORT_LABELS.get(
                    q["type_byte"],
                    f"0x{q['type_byte']:02x}" if q['type_byte'] is not None else "?",
                )
                tone_str = "reverence" if q["tone_byte"] == 0xff else "ordinary"
                title = (
                    f"{primary}\n"
                    f"type: {type_name} ({tone_str})\n"
                    f"{q['num_outputs']} strands · {total_txs - 1} body txs\n"
                    f"{date_str}\n"
                    f"{txid}"
                )
                src_addr = (address_groups or {}).get(txid) or address
                addr_color = ADDRESS_COLORS.get(src_addr, "#222222")
                node_color = {
                    "background": color,
                    "border": addr_color,
                }
                net.add_node(
                    txid, label=label, title=title, color=node_color,
                    size=size, shape="dot", borderWidth=3,
                    group=src_addr or "_orphan",
                )
        elif kind == "consolidation":
            net.add_node(
                txid,
                label=f"⇲ {info.get('n_in', '?')}",
                title=(f"Consolidation — strand termini merged here, "
                       f"output stays in the watched address space\n{txid}"),
                color="#8eb88e", size=14, shape="diamond",
            )
        elif kind == "exit":
            net.add_node(
                txid,
                label="↗ exit",
                title=(f"Exit — strand termini spent to an address "
                       f"outside the watched set\n{txid}"),
                color="#c78686", size=12, shape="triangle",
            )
        elif kind == "exit_offwallet":
            cnt = info.get("count", 1)
            net.add_node(
                txid,
                label=f"↗ off-wallet ×{cnt}",
                title=(f"Off-wallet exit — {cnt} strand output(s) of "
                       f"{info.get('of_quipu','?')[:12]}… spent to a "
                       f"non-watched address (the wallet didn't see the "
                       f"spender, but gettxout confirms the output is "
                       f"consumed on chain)"),
                color="#c78686", size=12, shape="triangle",
            )
        elif kind == "external_in":
            net.add_node(
                txid,
                label="ext",
                title=f"External funding source for "
                      f"{info.get('for_quipu','?')[:12]}…",
                color="#444444", size=8, shape="square",
            )
        elif kind == "unspent_tendril":
            of_q = info.get("of_quipu", "?")[:8]
            s_idx = info.get("strand_index", "?")
            inscribed = info.get("inscribed", False)
            net.add_node(
                txid,
                label="○",
                title=(f"Unspent strand {s_idx} of {of_q}…\n"
                       f"{'inscribed, terminus unspent' if inscribed else 'not yet inscribed'}"),
                color={"background": "#ffffff", "border": "#888888"},
                size=6, shape="dot", borderWidth=1,
            )

    EDGE_STYLE = {
        "funding":  {"color": "#777777", "width": 1, "dashes": False},
        "forward":  {"color": "#7eb47e", "width": 1, "dashes": False},
        "keydrop":  {"color": "#b88ec7", "width": 2, "dashes": True},
    }
    for edge in edges:
        # edges are 4-tuples (src, dst, kind, label) from the
        # cap-at-MAX_PARALLEL pass. Backwards-compat: shorter forms.
        if len(edge) == 4:
            src, dst, ekind, label = edge
        elif len(edge) == 3:
            src, dst, ekind = edge
            label = None
        else:
            src, dst, ekind, label = edge[0], edge[1], "funding", None
        style = EDGE_STYLE.get(ekind, EDGE_STYLE["funding"])
        net.add_edge(
            src, dst,
            color=style["color"], width=style["width"],
            dashes=style["dashes"],
            label=label,
            font={"size": 9, "color": "#888"} if label else None,
        )

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

// ===== Cellular surface overlay =====
// Draws a soft enclosing blob around each address's cluster of quipu
// nodes. Updates each frame via the network's `afterDrawing` hook, so it
// follows the force-directed layout as nodes move.
var ADDRESS_COLORS = """ + _json.dumps(ADDRESS_COLORS) + """;

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
        while (lower.length >= 2 && cross(lower[lower.length-2], lower[lower.length-1], sorted[i]) <= 0) {
            lower.pop();
        }
        lower.push(sorted[i]);
    }
    var upper = [];
    for (var i = sorted.length - 1; i >= 0; i--) {
        while (upper.length >= 2 && cross(upper[upper.length-2], upper[upper.length-1], sorted[i]) <= 0) {
            upper.pop();
        }
        upper.push(sorted[i]);
    }
    return lower.slice(0, -1).concat(upper.slice(0, -1));
}

function _expandHull(hull, pad) {
    // Move each hull vertex outward from the polygon centroid by `pad` px
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
    // Catmull-Rom-ish smoothing for a more cellular feel
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
    if (typeof network === 'undefined' || !network) { return; }
    // Cache the computed hulls; only rebuild on stabilisation or when
    // node membership changes. Drawing happens every frame from the
    // cache — cheap. This avoids hammering the CPU while the
    // force-directed layout is settling (hundreds of redraws/sec).
    var hullCache = {};

    function recomputeHulls() {
        var groups = {};
        var nodeIds = network.body.data.nodes.getIds();
        nodeIds.forEach(function(id) {
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
            if (pts.length < 2) return;
            next[grp] = _expandHull(_convexHull(pts), 36);
        });
        hullCache = next;
    }

    // Recompute periodically while physics is still moving things;
    // stop once the layout has stabilised.
    var recomputeTimer = setInterval(recomputeHulls, 250);
    network.on('stabilizationIterationsDone', function() {
        recomputeHulls();
        clearInterval(recomputeTimer);
        recomputeTimer = setInterval(recomputeHulls, 1500);
    });
    network.on('dragEnd', recomputeHulls);

    network.on('afterDrawing', function(ctx) {
        Object.keys(hullCache).forEach(function(grp) {
            var padded = hullCache[grp];
            if (!padded || padded.length < 3) return;
            ctx.save();
            _drawSmoothPolygon(ctx, padded);
            ctx.fillStyle = ADDRESS_COLORS[grp] + "1a";
            ctx.fill();
            ctx.strokeStyle = ADDRESS_COLORS[grp] + "66";
            ctx.lineWidth = 1.5;
            ctx.stroke();
            ctx.restore();
        });
    });
}
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

tab_plan, tab_inscribe, tab_read, tab_wallet, tab_keys = st.tabs(
    ["📝 Plan", "📡 Inscribe", "🔍 Read", "💼 Wallet", "🔑 Keys"]
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
        n_body_strands = st.number_input(
            "Body strands", min_value=1, max_value=256, value=3, step=1,
            help="Body bytes get split across this many strands. "
                 "More strands = wider quipu, more parallelism in Phase 2. "
                 "Type a number or use the steppers.",
        )
        strand_size_hint = st.empty()
        enc_mode = st.radio(
            "Encryption", ["None", "AES", "ECIES Broadcast"],
            horizontal=True,
            help="None = plaintext quipu. AES = sealed with the sidebar "
                 "key/password (anyone with the same key decrypts). "
                 "ECIES Broadcast = per-recipient envelopes from nb17 "
                 "(image-only on the wire). Encryption is applied after "
                 "you complete the body below.",
        )

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
    # an encrypted-quipu pair before strand planning. The mode radio is
    # rendered at the top of the Plan tab; here we apply it.
    encryption_meta = {"mode": "none"}
    if body_bytes is not None and enc_mode != "None":
        st.divider()
        st.subheader(f"Encryption — {enc_mode}")

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

    # Populate the strand-size hint left empty in the left column above.
    # body_bytes here is the *final* payload — post-encryption if AES or
    # broadcast was applied, so the strand-size estimate is accurate.
    if body_bytes is not None and len(body_bytes) > 0:
        n = int(n_body_strands)
        per_strand = len(body_bytes) // n + (1 if len(body_bytes) % n else 0)
        txs_per_strand = max(1, (per_strand + 79) // 80)
        enc_note = (
            f" · {encryption_meta['mode']}"
            if encryption_meta["mode"] != "none" else ""
        )
        strand_size_hint.caption(
            f"≈ {per_strand:,} B/strand · ~{txs_per_strand} tx"
            f"{'s' if txs_per_strand != 1 else ''}/strand "
            f"(80 B/OP_RETURN{enc_note})"
        )
    else:
        strand_size_hint.caption("(strand size shown once body is set)")

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
                render_body_streamlit(
                    t_byte, header_bytes, body_bytes,
                    root_txid=txid_in,
                    df_out=df_out_for_keydrop, quipus=quipus_for_keydrop,
                )
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
            quipus_all = cached["quipus"]
            df_tx = cached["df_tx"]
            df_out = cached.get("df_out")

            # ----- Filter UI ------------------------------------------------
            import datetime as _dt
            available_types = sorted(
                {q["type_byte"] for q in quipus_all if q.get("type_byte") is not None}
            )
            with st.expander(
                f"Filter ({len(quipus_all)} quipus total)", expanded=False,
            ):
                fc1, fc2, fc3 = st.columns([2, 1, 2])
                with fc1:
                    type_labels = {
                        t: f"0x{t:02x} · {TYPE_SHORT_LABELS.get(t, '?')}"
                        for t in available_types
                    }
                    selected_types = st.multiselect(
                        "Type", options=available_types,
                        default=available_types,
                        format_func=lambda t: type_labels[t],
                        key="filter_types",
                    )
                with fc2:
                    selected_tone = st.radio(
                        "Tone", ["any", "ordinary", "reverence"],
                        index=0, key="filter_tone",
                    )
                with fc3:
                    title_substr = st.text_input(
                        "Title contains", value="",
                        key="filter_title",
                    )
                bts = [q["blocktime"] for q in quipus_all if q.get("blocktime")]
                if bts:
                    min_d = _dt.date.fromtimestamp(min(bts))
                    max_d = _dt.date.fromtimestamp(max(bts))
                    dc1, dc2 = st.columns(2)
                    with dc1:
                        d_from = st.date_input(
                            "From", value=min_d, min_value=min_d,
                            max_value=max_d, key="filter_date_from",
                        )
                    with dc2:
                        d_to = st.date_input(
                            "To", value=max_d, min_value=min_d,
                            max_value=max_d, key="filter_date_to",
                        )
                else:
                    d_from = d_to = None

            quipus = filter_quipus(
                quipus_all,
                types=selected_types or None,
                tone=selected_tone,
                date_from=d_from, date_to=d_to,
                title_substr=title_substr,
            )

            shown = len(quipus)
            total = len(quipus_all)
            if shown == total:
                st.markdown(
                    f"**{total} quipus rooted at `{addr_to_view[:12]}…`**"
                )
            else:
                st.markdown(
                    f"**Showing {shown} of {total} quipus** "
                    f"rooted at `{addr_to_view[:12]}…`"
                )

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

            # Topology — force-directed network showing funding lineage.
            # Default OFF — the force-directed physics + cellular hull
            # overlay was driving repeated reruns / hot CPU. The data
            # path (compute_quipu_topology, find_keydrop_for, etc.) is
            # still computed when this toggle is ON; off = no render
            # work at all.
            st.markdown("### Topology (force-directed)")
            topo_enabled = st.checkbox(
                "Render topology",
                value=False,
                key="topology_render_enabled",
                help="Off by default — the force-directed layout was "
                     "burning CPU. Turn on to render; turn off to free "
                     "the browser if it gets hot.",
            )
            if not topo_enabled:
                st.info(
                    "Topology rendering is paused. Tick the box above "
                    "to render. (Inscribing, multisig, reading, and key "
                    "management all work without it.)"
                )
                # Make `extra_selected` defined for downstream code paths
                extra_selected = []

            # Multi-address selection: any watched address with a cached
            # history can be folded into the same topology view.
            if topo_enabled:
                extra_options = [a for a in ADDR_LABELS.keys() if a != addr_to_view]
                default_extra = [
                    a for a in extra_options
                    if f"history::{a}" in st.session_state
                ]
                extra_selected = st.multiselect(
                    "Include other addresses (must have a cached history — go "
                    "to that address and ↻ Compute history first)",
                    options=extra_options,
                    default=default_extra,
                    format_func=lambda a: f"{ADDR_LABELS[a]} · {a[:12]}…",
                    key="topology_extra_addrs",
                )

            # Combine current address's data with each selected extra
            address_groups = {q["root_txid"]: addr_to_view for q in quipus}
            quipus_combined = list(quipus)
            df_tx_combined = df_tx
            df_out_combined = df_out
            included_addrs = [addr_to_view]
            for extra in extra_selected:
                extra_cached = st.session_state.get(f"history::{extra}")
                if not isinstance(extra_cached, dict):
                    st.warning(f"`{extra}` has no cached history — "
                               f"skipping. Visit that address first.")
                    continue
                extra_quipus = extra_cached["quipus"]
                quipus_combined.extend(extra_quipus)
                for q in extra_quipus:
                    address_groups[q["root_txid"]] = extra
                if extra_cached.get("df_tx") is not None and df_tx_combined is not None:
                    import pandas as _pd
                    df_tx_combined = _pd.concat(
                        [df_tx_combined, extra_cached["df_tx"]],
                        ignore_index=True,
                    ).drop_duplicates(subset=["txid"], keep="first")
                if extra_cached.get("df_out") is not None and df_out_combined is not None:
                    import pandas as _pd
                    df_out_combined = _pd.concat(
                        [df_out_combined, extra_cached["df_out"]],
                        ignore_index=True,
                    ).drop_duplicates(subset=["txout"], keep="first")
                included_addrs.append(extra)

            # Legend chips above the topology
            legend = " &nbsp; ".join(
                f"<span style='display:inline-block; vertical-align:middle; "
                f"width:10px; height:10px; border-radius:50%; "
                f"background:{ADDRESS_COLORS.get(a, '#222')}; "
                f"margin-right:4px'></span>"
                f"<code style='font-size:11px'>{ADDR_LABELS[a]}</code>"
                for a in included_addrs
            )
            st.markdown(
                f"<div style='margin:6px 0 10px 0'>{legend}</div>",
                unsafe_allow_html=True,
            )

            st.caption(
                "Quipus repel each other; funding sources gravitate to the "
                "centre via spring forces on edges. Drag any node to "
                "reposition. Each quipu's border colour is its source "
                "address; a soft cell-membrane hull surrounds each "
                "address's cluster. Diamond = consolidation. Triangle = "
                "exit. Black square = external funding. Dashed purple "
                "edge = keydrop ↔ encrypted-quipu link."
            )
            # Heavy work only when the user opted in via the checkbox.
            # The iframe + vis.js physics + cellular hull JS is what
            # was burning CPU; with topo_enabled=False none of this
            # runs and the page stays cool.
            if topo_enabled:
                topo_cache_key = "topology_html_cache"
                topo_signature = (
                    addr_to_view,
                    tuple(sorted(extra_selected or [])),
                    tuple(sorted(q["root_txid"] for q in quipus_combined)),
                    tuple(sorted(q["root_txid"] for q in quipus)),
                )
                cached_topo = st.session_state.get(topo_cache_key)
                if cached_topo and cached_topo.get("signature") == topo_signature:
                    topo_html = cached_topo["html"]
                else:
                    try:
                        with st.spinner("Building topology (decoding all quipus for click-popups)…"):
                            nodes, edges, keydrop_resolutions = compute_quipu_topology(
                                addr_to_view, quipus_combined, df_tx_combined, df_out=df_out_combined,
                            )
                            st.session_state["keydrop_resolutions_cache"] = keydrop_resolutions
                            topo_html = render_topology_pyvis(
                                nodes, edges, labels=labels, address=addr_to_view,
                                height_px=620, df_out=df_out_combined, quipus=quipus_combined,
                                address_groups=address_groups,
                            )
                        st.session_state[topo_cache_key] = {
                            "signature": topo_signature, "html": topo_html,
                        }
                    except Exception as e:
                        st.error(f"Topology render failed: {e}")
                        topo_html = None
                if topo_html:
                    import streamlit.components.v1 as components
                    components.html(topo_html, height=650, scrolling=False)

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
                    render_body_streamlit(
                        type_byte, header_bytes, body_bytes,
                        root_txid=selected_root,
                        df_out=df_out, quipus=quipus,
                    )

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


# ----------------------------------------------------------------------
# Keys tab — generate Dogecoin and AES keys, save them as downloads
# ----------------------------------------------------------------------

with tab_keys:
    st.subheader("Generate & save keys")
    st.caption(
        "Fresh keypairs for testing — Dogecoin single keys "
        "(combinable via curve point addition for multisig-style "
        "envelopes), and raw 32-byte AES keys (for 0x0e 0xae "
        "sealed quipus). Saved files use the same `_prv.enc`-style "
        "envelope as the existing key files."
    )

    key_l, key_r = st.columns(2)

    # ----- Dogecoin keypair generation --------------------------------
    with key_l:
        st.markdown("### Dogecoin keypair")
        st.caption(
            "Generates a new random eth_keys / coincurve secp256k1 key, "
            "derives the Dogecoin address, and offers the encrypted "
            "private key file for download."
        )
        doge_name = st.text_input(
            "Basename (no extension)", value="test_key",
            key="keygen_doge_name",
            help="Used in the suggested filename: <basename>_prv.enc, "
                 "<basename>_pub.bin, <basename>_addr.bin",
        )
        doge_pw = st.text_input(
            "Password (empty = unprotected, matches apocrypha test key)",
            type="password", value="", key="keygen_doge_pw",
        )
        if st.button("Generate Dogecoin keypair", use_container_width=True,
                     key="keygen_doge_btn"):
            try:
                import ecies as _ecies
                import cryptos as _cryptos
                priv = _ecies.utils.generate_eth_key()
                priv_hex = priv.to_hex()[2:]
                pub_hex = priv.public_key.to_hex()[2:]
                addr = _cryptos.Doge().pubtoaddr("04" + pub_hex)
                # Build the encrypted _prv.enc payload using the
                # project's existing convention
                enc_bytes = _ecies.sym_encrypt(
                    key=hashlib.sha256((doge_pw or "").encode()).digest(),
                    plain_text=priv.to_bytes(),
                )
                # Stash so the download buttons survive reruns
                st.session_state["keygen_doge_result"] = {
                    "basename": doge_name or "key",
                    "addr": addr,
                    "pub_hex": pub_hex,
                    "priv_hex": priv_hex,
                    "enc_bytes": enc_bytes,
                }
            except Exception as e:
                st.error(f"Generation failed: {e}")

        result = st.session_state.get("keygen_doge_result")
        if result:
            st.success(f"Address: `{result['addr']}`")
            with st.expander("Public key (uncompressed, 128 hex)", expanded=False):
                st.code(result["pub_hex"], language=None)
            with st.expander("Private key hex — handle carefully", expanded=False):
                st.code(result["priv_hex"], language=None)
                st.caption("Treat this like cash.")

            d1, d2, d3 = st.columns(3)
            with d1:
                st.download_button(
                    "↓ _prv.enc",
                    data=result["enc_bytes"],
                    file_name=f"{result['basename']}_prv.enc",
                    mime="application/octet-stream",
                    use_container_width=True,
                )
            with d2:
                st.download_button(
                    "↓ _pub.bin",
                    data=bytes.fromhex(result["pub_hex"]),
                    file_name=f"{result['basename']}_pub.bin",
                    mime="application/octet-stream",
                    use_container_width=True,
                )
            with d3:
                st.download_button(
                    "↓ _addr.bin",
                    data=result["addr"].encode("utf-8"),
                    file_name=f"{result['basename']}_addr.bin",
                    mime="text/plain",
                    use_container_width=True,
                )

            # Save all three to a local folder
            doge_save_dir = _folder_input_with_browse(
                "Save folder",
                key="keygen_doge_save_dir",
                default=str(Path.home() / "Desktop" / "cinv" / "llaves"),
            )
            if st.button("Save all three to folder",
                         use_container_width=True,
                         key="keygen_doge_save_btn"):
                try:
                    folder = Path(doge_save_dir).expanduser()
                    folder.mkdir(parents=True, exist_ok=True)
                    base = result["basename"]
                    (folder / f"{base}_prv.enc").write_bytes(result["enc_bytes"])
                    (folder / f"{base}_pub.bin").write_bytes(
                        bytes.fromhex(result["pub_hex"])
                    )
                    (folder / f"{base}_addr.bin").write_bytes(
                        result["addr"].encode("utf-8")
                    )
                    # QR too, matches existing gen_save_keys_addr behaviour
                    try:
                        ct.make_qr(result["addr"], str(folder / f"{base}_addr.png"))
                    except Exception:
                        pass
                    st.success(
                        f"Wrote {base}_prv.enc / _pub.bin / _addr.bin "
                        f"(and _addr.png) to {folder}"
                    )
                except Exception as e:
                    st.error(f"Save failed: {e}")

            try:
                qr_img = ct.make_qr(result["addr"])
                _buf = io.BytesIO()
                qr_img.save(_buf, format="PNG")
                st.image(_buf.getvalue(), caption="address QR", width=140)
            except Exception as _e:
                st.caption(f"(QR render skipped: {_e})")

    # ----- AES key generation -----------------------------------------
    with key_r:
        st.markdown("### AES key")
        st.caption(
            "Generates a fresh random 32-byte AES key. Optionally seals "
            "it under a password — same envelope as `_prv.enc`. Use the "
            "result with the sidebar's 'Key file' AES source, or to "
            "encrypt a `0x0e 0xae` sealed quipu."
        )
        aes_name = st.text_input(
            "Basename", value="aes_key",
            key="keygen_aes_name",
        )
        aes_outer_pw = st.text_input(
            "Outer password (empty = save raw 32 bytes)",
            type="password", value="", key="keygen_aes_outer_pw",
        )
        if st.button("Generate AES key", use_container_width=True,
                     key="keygen_aes_btn"):
            try:
                key_bytes = os.urandom(32)
                if aes_outer_pw:
                    saved = ct.aes_encrypt_bytes(key_bytes, aes_outer_pw)
                    ext = ".enc"
                else:
                    saved = key_bytes
                    ext = ".key"
                st.session_state["keygen_aes_result"] = {
                    "basename": aes_name or "aes_key",
                    "key_bytes": key_bytes,
                    "saved": saved,
                    "extension": ext,
                    "is_encrypted": bool(aes_outer_pw),
                }
            except Exception as e:
                st.error(f"AES generation failed: {e}")

        result = st.session_state.get("keygen_aes_result")
        if result:
            fpr = result["key_bytes"][:4].hex()
            st.success(
                f"AES key generated · fingerprint `{fpr}…` · "
                f"{'password-encrypted' if result['is_encrypted'] else 'raw'} "
                f"({len(result['saved'])} bytes on disk)"
            )
            with st.expander("Raw key hex — handle carefully", expanded=False):
                st.code(result["key_bytes"].hex(), language=None)
                st.caption("Anyone with this key can decrypt sealed quipus.")
            st.download_button(
                f"↓ {result['basename']}{result['extension']}",
                data=result["saved"],
                file_name=f"{result['basename']}{result['extension']}",
                mime="application/octet-stream",
                use_container_width=True,
            )

            aes_save_dir = _folder_input_with_browse(
                "Save folder",
                key="keygen_aes_save_dir",
                default=str(Path.home() / "Desktop" / "cinv" / "llaves"),
            )
            if st.button(f"Save to folder",
                         use_container_width=True,
                         key="keygen_aes_save_btn"):
                try:
                    folder = Path(aes_save_dir).expanduser()
                    folder.mkdir(parents=True, exist_ok=True)
                    fname = f"{result['basename']}{result['extension']}"
                    (folder / fname).write_bytes(result["saved"])
                    st.success(f"Wrote {fname} to {folder}")
                except Exception as e:
                    st.error(f"Save failed: {e}")

    # ----- Make multisig (key picker wizard) -------------------------
    st.divider()
    st.markdown("### Make multisig")
    st.caption(
        "Pick which keys to combine into an `m`-of-`n` P2SH multisig "
        "address. Available keys include any loaded in the sidebar and "
        "the most-recently-generated keypair from above. The bordado "
        "3-of-3 reproduces from its three pubkeys (`9xth7DcLGb1n…`); "
        "the HA / CA addresses are both 2-of-2 — pick the matching shape."
    )

    # Gather available keys from the session (sidebar-loaded + just-made)
    available = []
    for k in st.session_state.get("priv_keys", []):
        try:
            priv = eth_keys.keys.PrivateKey(bytes.fromhex(k["priv_hex"]))
            pub_hex = "04" + priv.public_key.to_hex()[2:]
            available.append({
                "source": "sidebar",
                "label": k.get("label", k["addr"]),
                "addr": k["addr"],
                "pub_hex": pub_hex,
            })
        except Exception:
            continue
    recent = st.session_state.get("keygen_doge_result")
    if recent and not any(a["addr"] == recent["addr"] for a in available):
        available.append({
            "source": "just made",
            "label": recent.get("basename", "new_key"),
            "addr": recent["addr"],
            "pub_hex": "04" + recent["pub_hex"],
        })

    if not available:
        st.info(
            "No keys available. Generate one above (or load one in the "
            "sidebar), or paste pubkeys in the 'extra pubkeys' textarea "
            "below."
        )

    st.markdown("**Pick participants:**")
    picked_pubs = []
    picked_labels = []
    for i, k in enumerate(available):
        if st.checkbox(
            f"`{k['addr']}` &nbsp; *{k['source']}* &nbsp; ({k['label']})",
            key=f"ms_pick_{i}",
        ):
            picked_pubs.append(k["pub_hex"])
            picked_labels.append(k["label"])

    with st.expander("Extra pubkeys (paste, not in session)", expanded=False):
        ms_extra_text = st.text_area(
            "One per line (128-hex eth_keys form or 130-hex `04…`)",
            value="", height=100, key="ms_extra_pubs",
        )
        for line in (ms_extra_text or "").splitlines():
            s = line.strip().lower()
            if not s:
                continue
            if len(s) == 128:
                s = "04" + s
            if len(s) == 130 and s.startswith("04"):
                picked_pubs.append(s)
                picked_labels.append(f"pasted {s[2:14]}…")
            else:
                st.warning(
                    f"Skipping unrecognised pubkey: `{line[:24]}…` "
                    f"({len(line)} chars)"
                )

    n_picked = len(picked_pubs)
    msc1, msc2 = st.columns([1, 3])
    with msc1:
        ms_m = st.number_input(
            "Required signatures (m)",
            min_value=1, max_value=max(1, n_picked),
            value=min(2, n_picked) if n_picked else 1,
            step=1, key="multisig_threshold",
        )
    with msc2:
        st.caption(
            f"**{int(ms_m)}-of-{n_picked}** — {int(ms_m)} signature(s) "
            f"required from {n_picked} participant key(s)"
        )

    ms_basename = st.text_input(
        "Multisig basename", value="multisig",
        key="multisig_basename",
        help="Used in saved filenames: <basename>_multisig.{addr,redeem,json}",
    )

    if st.button("Derive multisig address", use_container_width=True,
                 disabled=n_picked < 2, key="multisig_derive_btn"):
        try:
            import cryptos as _cryptos
            redeem_hex, addr = _cryptos.Doge().mk_multisig_address(
                *picked_pubs, num_required=int(ms_m),
            )
            st.session_state["multisig_result"] = {
                "addr": addr,
                "redeem_hex": redeem_hex,
                "m": int(ms_m),
                "n": n_picked,
                "pubkeys": picked_pubs,
                "labels": picked_labels,
                "basename": ms_basename or "multisig",
            }
        except Exception as e:
            st.error(f"Multisig derivation failed: {e}")

    ms_result = st.session_state.get("multisig_result")
    if ms_result:
        st.success(
            f"{ms_result['m']}-of-{ms_result['n']} multisig address derived"
        )
        st.code(ms_result["addr"], language=None)

        st.markdown("**Participants** (signing order = listed order):")
        for label, pub in zip(ms_result.get("labels", []),
                              ms_result["pubkeys"]):
            st.markdown(
                f"&nbsp;&nbsp;`{pub[2:14]}…`  &nbsp; *{label}*"
            )

        with st.expander("Redeem script hex", expanded=False):
            st.code(ms_result["redeem_hex"], language=None)
            st.caption(
                f"OP_{ms_result['m']} <pubkeys…> OP_{ms_result['n']} "
                f"OP_CHECKMULTISIG"
            )

        try:
            qr = ct.make_qr(ms_result["addr"])
            _buf = io.BytesIO()
            qr.save(_buf, format="PNG")
            st.image(_buf.getvalue(), caption="address QR", width=140)
        except Exception as _e:
            st.caption(f"(QR render skipped: {_e})")

        # Save the multisig as a folder bundle
        import json as _json
        ms_save_dir = _folder_input_with_browse(
            "Save folder",
            key="multisig_save_dir",
            default=str(Path.home() / "Desktop" / "cinv" / "llaves"),
        )
        manifest = {
            "address": ms_result["addr"],
            "redeem_script_hex": ms_result["redeem_hex"],
            "m": ms_result["m"],
            "n": ms_result["n"],
            "pubkeys": ms_result["pubkeys"],
            "labels": ms_result.get("labels", []),
            "basename": ms_result["basename"],
        }
        manifest_json = _json.dumps(manifest, indent=2)

        d1, d2, d3 = st.columns(3)
        with d1:
            st.download_button(
                "↓ _multisig_addr.bin",
                data=ms_result["addr"].encode("utf-8"),
                file_name=f"{ms_result['basename']}_multisig_addr.bin",
                mime="text/plain",
                use_container_width=True,
            )
        with d2:
            st.download_button(
                "↓ _multisig_redeem.bin",
                data=bytes.fromhex(ms_result["redeem_hex"]),
                file_name=f"{ms_result['basename']}_multisig_redeem.bin",
                mime="application/octet-stream",
                use_container_width=True,
            )
        with d3:
            st.download_button(
                "↓ _multisig.json (manifest)",
                data=manifest_json.encode("utf-8"),
                file_name=f"{ms_result['basename']}_multisig.json",
                mime="application/json",
                use_container_width=True,
            )

        if st.button("Save all three to folder",
                     use_container_width=True,
                     key="multisig_save_btn"):
            try:
                folder = Path(ms_save_dir).expanduser()
                folder.mkdir(parents=True, exist_ok=True)
                base = ms_result["basename"]
                (folder / f"{base}_multisig_addr.bin").write_bytes(
                    ms_result["addr"].encode("utf-8")
                )
                (folder / f"{base}_multisig_redeem.bin").write_bytes(
                    bytes.fromhex(ms_result["redeem_hex"])
                )
                (folder / f"{base}_multisig.json").write_text(manifest_json)
                try:
                    ct.make_qr(ms_result["addr"],
                               str(folder / f"{base}_multisig_addr.png"))
                except Exception:
                    pass
                st.success(
                    f"Wrote {base}_multisig_addr.bin / _redeem.bin / "
                    f".json (and _addr.png) to {folder}"
                )
            except Exception as e:
                st.error(f"Save failed: {e}")

        st.caption(
            "Fund this address from apocrypha (or anywhere) to use it. "
            "Inscribing from a multisig address requires PSBT-style "
            "round-robin signing — that orchestrator is the next build."
        )
