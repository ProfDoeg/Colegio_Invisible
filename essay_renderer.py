"""
essay_renderer.py — Typographic HTML renderer for quipu bodies.

Handles four body conventions found on chain (or designed for):

    0x00, 0x04   text / essay
        Pipe-bracketed title in the header, prose body. Body may contain
        `<<txid>>` references (citation when inline, embed when standalone
        on its own line) and `<<NAME>> = <<txid>>` binding definitions.

    0x1d         identity
        Pipe-bracketed title, JSON body. Rendered as a typographic profile
        (name, field, socials, embedded portrait image, attested addr/HD
        entries with sig verification badges).

    0xcc, 0x0c   cert
        Pipe-bracketed title plus optional metadata pipe-fields (`|SHA256|hash`),
        `Field: value` body. Recognised fields (Title, Artist, Image, Text,
        CertificateAuthority, *_Public) get typographic treatment. Unknown
        fields fall to a small footer block so nothing is lost.

Reference resolution priority for `<<name>>`:
    1. global bindings (from an imported 0xab abecedario quipu — stub for now)
    2. inline bindings defined in the same essay body
    3. direct txid (full 64-hex or unique prefix) against the known quipus set
"""

import re
import json
import html as _html
import io as _io
import base64 as _b64

from PIL import Image

import colegio_tools as ct


# ---------------------------------------------------------------------------
# Pipe-header parsing
# ---------------------------------------------------------------------------

# Per-type byte offset where the text/title portion of the header starts.
# Anything before this is structural (length/width/bit depth/version
# bytes etc.) and isn't part of the title text.
TITLE_OFFSETS = {
    0x00: 6,   # text — type tone, then |TITLE| ...
    0x04: 6,   # essay (proposed) — same shape
    0x1d: 6,   # identity — type 00 00, then |TITLE|
    0x03: 12,  # image — type tone color L L W W B, then |TITLE|
    0x0c: 8,   # cert old — type tone version_hi version_lo, then |TITLE|
    0xcc: 8,   # cert — same
    0x0e: 6,   # encrypted (fallback — sub-family varies)
}


def parse_pipe_header(header_bytes):
    """Returns (type_byte, tone_byte, [fields...]).

    `fields` is the list of UTF-8 strings extracted from the header tail:
    - If pipe characters are present, split on them and drop empty parts
      (leading/trailing pipes leave empty segments we discard).
    - If NO pipes are present, the printable text from the type-specific
      offset onwards is returned as a single field. Lets readers handle
      inscriptions like Monte Veritá that wrote a multi-line caption
      directly without the pipe convention.
    """
    if len(header_bytes) < 6:
        return None, None, []
    type_byte = header_bytes[4]
    tone_byte = header_bytes[5]
    text_start = TITLE_OFFSETS.get(type_byte, 6)
    tail = header_bytes[text_start:].rstrip(b" \x00")
    if not tail:
        return type_byte, tone_byte, []
    try:
        text = tail.decode("utf-8", errors="replace")
    except Exception:
        return type_byte, tone_byte, []
    if "|" in text:
        parts = text.split("|")
        fields = [p for p in parts if p != ""]
    else:
        # No pipes — treat the whole printable tail as one field
        fields = [text]
    return type_byte, tone_byte, fields


def first_title(header_bytes):
    """Return the first non-whitespace field in the header, stripped of
    leading/trailing whitespace. Skips empty-ish padding fields like the
    leading `| |` wrapper on the La Verna image header."""
    _, _, fields = parse_pipe_header(header_bytes)
    for f in fields:
        s = f.strip()
        if s:
            return s
    return ""


# ---------------------------------------------------------------------------
# Reference resolution
# ---------------------------------------------------------------------------

# A reference token <<X>> where X has no whitespace or < > = characters.
REF_RE = re.compile(r"<<([^<>=\s]+)>>")
# A binding definition line: <<NAME>> = <<txid>>
BINDING_RE = re.compile(r"^\s*<<([^<>=\s]+)>>\s*=\s*<<([^<>=\s]+)>>\s*$")


def _is_hex(s):
    if not s:
        return False
    s = s.lower()
    return all(c in "0123456789abcdef" for c in s)


def _resolve_txid_prefix(prefix, known_txids):
    """Match a hex prefix against the set of known txids. Returns the full
    txid if exactly one matches, or the prefix itself if it's already a
    full 64-char hex (even if unknown — caller decides what to do)."""
    if not prefix or not _is_hex(prefix):
        return None
    prefix = prefix.lower()
    if len(prefix) == 64:
        return prefix
    matches = [t for t in (known_txids or ()) if t.startswith(prefix)]
    if len(matches) == 1:
        return matches[0]
    return None


def resolve_reference(token, *, global_bindings=None, inline_bindings=None,
                      known_txids=None):
    """Resolve a `<<X>>` reference token to a full txid (or None).

    Priority — global → inline → direct-txid (full or unique prefix).
    """
    if global_bindings and token in global_bindings:
        return global_bindings[token]
    if inline_bindings and token in inline_bindings:
        return inline_bindings[token]
    return _resolve_txid_prefix(token, known_txids)


# ---------------------------------------------------------------------------
# Body pre-pass — collect bindings, leave binding-definition lines out
# ---------------------------------------------------------------------------

def collect_inline_bindings(body_text):
    """Returns (inline_bindings, body_without_binding_lines)."""
    inline = {}
    kept = []
    for line in body_text.splitlines():
        m = BINDING_RE.match(line)
        if m:
            inline[m.group(1)] = m.group(2).lower()
            continue
        kept.append(line)
    return inline, "\n".join(kept)


# ---------------------------------------------------------------------------
# Image embed — direct-pixel rendering (matches the popup image convention)
# ---------------------------------------------------------------------------

def _render_image_inline_html(target_txid, quipus, df_out, caption=""):
    """If target_txid resolves to an image quipu (0x03), decode and embed
    inline (1:1 pixel mapping). Centred, with optional caption. Returns
    an HTML fragment. If resolution fails, returns a small placeholder."""
    if quipus is None or df_out is None:
        return _placeholder_embed(target_txid, "no scan context")
    target = next((q for q in quipus if q["root_txid"] == target_txid), None)
    if target is None:
        return _placeholder_embed(target_txid, "not in scanned quipu set")
    if target.get("type_byte") != 0x03:
        return _placeholder_embed(target_txid,
                                  f"type 0x{target['type_byte']:02x}, not image")
    try:
        head_hex, body_hex = ct.read_quipu(target_txid, df_out)
        header = bytes.fromhex(head_hex)
        body = bytes.fromhex(body_hex)
        hh = head_hex
        color_flag = int(hh[12:14], 16)
        C = 3 if color_flag == 1 else 1
        W = int(hh[14:18], 16)
        H = int(hh[18:22], 16)
        B = int(hh[22:24], 16)
        bits = ct.message_2_bit_array(body, mode=None)
        arr = ct.bitarray2imgarr(bits, imgshape=(H, W), bit=B, color=C).squeeze()
        img = Image.fromarray(arr)
        buf = _io.BytesIO()
        img.save(buf, format="PNG")
        b64 = _b64.b64encode(buf.getvalue()).decode("ascii")
        # Use target's own title as caption if none provided
        cap = caption or target.get("title") or ""
        cap_html = (f"<div style='text-align:center; font-size:11px; "
                    f"color:#666; font-style:italic; margin-top:4px'>"
                    f"{_html.escape(cap)}</div>") if cap else ""
        return (f"<figure style='text-align:center; margin:14px 0'>"
                f"<img src='data:image/png;base64,{b64}' "
                f"width='{W}' height='{H}' "
                f"style='max-width:100%; height:auto; "
                f"image-rendering: pixelated; "
                f"border: 1px solid #ccc; border-radius: 4px;' />"
                f"{cap_html}</figure>")
    except Exception as e:
        return _placeholder_embed(target_txid, f"decode error: {e}")


def _placeholder_embed(target, reason):
    return (f"<div style='text-align:center; margin:10px 0; "
            f"color:#999; font-size:11px; font-style:italic'>"
            f"[embed unresolved: <code>{_html.escape(str(target)[:16])}…</code> "
            f"— {_html.escape(reason)}]</div>")


# ---------------------------------------------------------------------------
# Identity sig verification
# ---------------------------------------------------------------------------

def verify_addr_sig(addr_entry, identity_txid):
    """Verify the sig_trans on an addr-style identity entry.
    Returns True if the recovered pubkey's Doge address matches the claimed
    address. False on any failure."""
    if not isinstance(addr_entry, dict):
        return False
    sig_hex = addr_entry.get("sig_trans")
    claimed = addr_entry.get("addr")
    if not (sig_hex and claimed and identity_txid):
        return False
    try:
        import eth_keys
        import cryptos
        sig = eth_keys.datatypes.Signature(bytes.fromhex(sig_hex))
        utterance = b"\x1d\x00\x00" + bytes.fromhex(identity_txid)
        recovered_pub = sig.recover_public_key_from_msg(utterance)
        recovered_addr = cryptos.Doge().pubtoaddr(
            "04" + recovered_pub.to_hex()[2:]
        )
        return recovered_addr == claimed
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Prose rendering — paragraph splitting + reference rewriting
# ---------------------------------------------------------------------------

def _render_prose_html(body_text, *, quipus, df_out, depth, global_bindings,
                       inline_bindings, known_txids):
    """Render free-prose text, recognising:
      - blank-line-separated paragraphs
      - standalone <<txid>> lines as embeds (image inline OR recursive render)
      - inline <<txid>> as citation pills

    Bindings lines have already been stripped by the caller.
    """
    out = []
    # Group lines into blocks by blank-line separation
    paragraphs = re.split(r"\n[ \t]*\n", body_text.strip("\n"))
    for para in paragraphs:
        if not para.strip():
            continue
        # Standalone embed = single non-blank line that's nothing but a <<ref>>
        stripped = para.strip()
        m_full = re.fullmatch(r"<<([^<>=\s]+)>>(?:\s*\|\s*as:\s*\"([^\"]+)\")?", stripped)
        if m_full:
            ref = m_full.group(1)
            override_title = m_full.group(2)
            txid = resolve_reference(
                ref,
                global_bindings=global_bindings,
                inline_bindings=inline_bindings,
                known_txids=known_txids,
            )
            out.append(_render_standalone_embed(
                ref, txid, override_title,
                quipus=quipus, df_out=df_out, depth=depth,
                global_bindings=global_bindings,
            ))
            continue
        # Otherwise treat as a paragraph; rewrite inline refs as citation pills
        para_html = _render_inline_refs_html(
            para,
            inline_bindings=inline_bindings,
            global_bindings=global_bindings,
            known_txids=known_txids,
        )
        out.append(
            f"<p style='font-family:Georgia,serif; line-height:1.55; "
            f"margin:0 0 12px 0'>{para_html}</p>"
        )
    return "\n".join(out)


def _render_inline_refs_html(para_text, *, inline_bindings, global_bindings,
                             known_txids):
    """Rewrite each <<X>> in the paragraph as a small citation pill."""
    def _sub(m):
        token = m.group(1)
        txid = resolve_reference(
            token,
            global_bindings=global_bindings,
            inline_bindings=inline_bindings,
            known_txids=known_txids,
        )
        if txid:
            label = token if token != txid else txid[:12] + "…"
            return (
                f"<span title='{_html.escape(txid)}' "
                f"style='background:#f4eef9; color:#5a4a7a; "
                f"font-size:0.85em; padding:1px 6px; border-radius:3px; "
                f"font-family:ui-monospace,monospace'>"
                f"{_html.escape(label)}</span>"
            )
        return (
            f"<span style='background:#f5f5f5; color:#999; font-size:0.85em; "
            f"padding:1px 6px; border-radius:3px; font-style:italic'>"
            f"&lt;&lt;{_html.escape(token)}&gt;&gt;</span>"
        )
    safe = _html.escape(para_text)
    # Re-substitute on the escaped form: tokens may be lost if the < > were
    # already escaped, so undo the escape on the reference markers only.
    safe = safe.replace("&lt;&lt;", "<<").replace("&gt;&gt;", ">>")
    return REF_RE.sub(_sub, safe)


def _render_standalone_embed(ref, txid, override_title, *, quipus, df_out,
                             depth, global_bindings):
    """A standalone <<ref>> on its own line → embed inline."""
    if not txid:
        return _placeholder_embed(ref, "binding not defined")
    target = (
        next((q for q in (quipus or []) if q["root_txid"] == txid), None)
    )
    if target is None:
        return _placeholder_embed(txid, "txid not in scanned set")
    tb = target.get("type_byte")
    if tb == 0x03:
        return _render_image_inline_html(
            txid, quipus, df_out, caption=override_title or ""
        )
    if tb in (0x00, 0x04, 0x1d, 0x0c, 0xcc):
        try:
            head_hex, body_hex = ct.read_quipu(txid, df_out)
        except Exception as e:
            return _placeholder_embed(txid, f"read failed: {e}")
        inner_html = render_typographic(
            tb,
            bytes.fromhex(head_hex),
            bytes.fromhex(body_hex),
            root_txid=txid,
            quipus=quipus,
            df_out=df_out,
            depth=depth + 1,
            global_bindings=global_bindings,
        )
        return (f"<blockquote style='border-left:3px solid #d4c5e0; "
                f"padding:6px 14px; margin:14px 0; background:#fbfaff'>"
                f"{inner_html}</blockquote>")
    if tb == 0xab:
        # bindings quipu — would import its names. Stub for now.
        return (
            f"<div style='font-size:10px; color:#888; font-style:italic; "
            f"margin:8px 0'>(bindings import: <code>{_html.escape(txid[:16])}…</code> "
            f"— 0xab loader not implemented yet)</div>"
        )
    return _placeholder_embed(txid, f"type 0x{tb:02x} not embeddable")


# ---------------------------------------------------------------------------
# Per-type renderers
# ---------------------------------------------------------------------------

def _render_text(header_bytes, body_bytes, *, quipus, df_out, depth,
                 global_bindings):
    body_text = body_bytes.decode("utf-8", errors="replace")
    inline_bindings, prose_text = collect_inline_bindings(body_text)
    known_txids = {q["root_txid"] for q in (quipus or [])}
    return _render_prose_html(
        prose_text,
        quipus=quipus, df_out=df_out, depth=depth,
        global_bindings=global_bindings,
        inline_bindings=inline_bindings,
        known_txids=known_txids,
    )


def _render_identity(header_bytes, body_bytes, *, root_txid, quipus, df_out,
                     depth, global_bindings):
    try:
        data = json.loads(body_bytes.decode("utf-8"))
    except Exception:
        return (f"<pre style='font-size:11px'>"
                f"{_html.escape(body_bytes.decode('utf-8', errors='replace'))}"
                f"</pre>")
    if not isinstance(data, dict):
        return f"<pre>{_html.escape(json.dumps(data))}</pre>"

    out = []

    name = data.pop("name", None)
    if name:
        out.append(
            f"<h3 style='font-family:Georgia,serif; "
            f"margin:8px 0 4px 0; font-size:18px'>{_html.escape(name)}</h3>"
        )

    subtitle = []
    if "field" in data:
        subtitle.append(f"<i>{_html.escape(str(data.pop('field')))}</i>")
    for social_key in ("twitter", "x", "github", "mastodon", "email", "url"):
        if social_key in data:
            v = data.pop(social_key)
            prefix = "" if social_key in ("email", "url") else "@"
            subtitle.append(
                f"{prefix}{_html.escape(str(v))}"
            )
    if subtitle:
        out.append(
            f"<p style='font-size:12px; color:#666; "
            f"margin:0 0 10px 0'>{' &middot; '.join(subtitle)}</p>"
        )

    image_ref = data.pop("image", None)
    if image_ref:
        known_txids = {q["root_txid"] for q in (quipus or [])}
        target_txid = _resolve_txid_prefix(image_ref, known_txids) or image_ref
        out.append(_render_image_inline_html(target_txid, quipus, df_out))

    # addr / hd_pub attestation blocks
    addr_keys = sorted(k for k in data if k.startswith("addr_"))
    hd_keys = sorted(k for k in data if k.startswith("hd_pub_"))
    if addr_keys or hd_keys:
        out.append(
            "<div style='margin-top:14px; padding-top:8px; "
            "border-top:1px solid #eee'>"
        )
        for ak in addr_keys:
            entry = data.pop(ak)
            out.append(_render_addr_attestation(ak, entry, root_txid))
        for hk in hd_keys:
            entry = data.pop(hk)
            out.append(_render_hdpub_attestation(hk, entry))
        out.append("</div>")

    # Prev-id reference, if present
    prev = data.pop("prev_id", None)
    if prev:
        out.append(
            f"<p style='font-size:10px; color:#888; margin-top:10px'>"
            f"Previous identity: <code>{_html.escape(str(prev)[:16])}…</code></p>"
        )

    # Anything left → small grey footer, key:value pairs
    if data:
        out.append("<div style='font-size:10px; color:#999; "
                   "margin-top:10px; line-height:1.5'>")
        for k, v in data.items():
            out.append(
                f"<b>{_html.escape(k)}:</b> "
                f"{_html.escape(str(v))[:120]}<br>"
            )
        out.append("</div>")

    return "\n".join(out)


def _render_addr_attestation(key, entry, identity_txid):
    if isinstance(entry, str):
        # Old shape: just a plain address string, no sig
        return (f"<div style='font-size:11px; color:#555; margin:4px 0'>"
                f"<b>{_html.escape(key)}:</b> "
                f"<code>{_html.escape(entry)}</code></div>")
    addr = entry.get("addr", "")
    verified = verify_addr_sig(entry, identity_txid)
    badge = (
        "<span style='color:#2a7a2a; font-size:10px'>✓ signed</span>"
        if verified
        else "<span style='color:#a06060; font-size:10px'>✗ sig invalid</span>"
        if entry.get("sig_trans")
        else "<span style='color:#999; font-size:10px'>no sig</span>"
    )
    return (
        f"<div style='font-size:11px; color:#555; margin:6px 0'>"
        f"<b>{_html.escape(key)}:</b> "
        f"<code>{_html.escape(addr)}</code> &nbsp; {badge}</div>"
    )


def _render_hdpub_attestation(key, entry):
    if isinstance(entry, str):
        return (f"<div style='font-size:11px; color:#555; margin:4px 0'>"
                f"<b>{_html.escape(key)}:</b> "
                f"<code>{_html.escape(entry[:24])}…</code></div>")
    path = next(
        (k for k in entry if k.startswith("pub/") or k.startswith("priv/")),
        None,
    )
    xpub = entry.get(path, "") if path else ""
    has_sig = bool(entry.get("sig_trans"))
    badge = (
        "<span style='color:#999; font-size:10px'>"
        "sig present (HD verify pending)</span>"
        if has_sig
        else "<span style='color:#999; font-size:10px'>no sig</span>"
    )
    return (
        f"<div style='font-size:11px; color:#555; margin:6px 0'>"
        f"<b>{_html.escape(key)}</b> "
        f"<span style='color:#888'>({_html.escape(path or 'unknown path')}):</span><br>"
        f"&nbsp;&nbsp;<code style='font-size:10px'>"
        f"{_html.escape(xpub[:48])}…</code> &nbsp; {badge}</div>"
    )


def _parse_field_value(body_text):
    """Parse `Field: value` body into a dict-of-lists (preserving order)."""
    fields = {}
    for line in body_text.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        fields[k.strip()] = v.strip()
    return fields


def _render_cert(header_bytes, body_bytes, *, quipus, df_out, depth,
                 global_bindings):
    _, _, header_fields = parse_pipe_header(header_bytes)
    metadata = header_fields[1:] if len(header_fields) > 1 else []

    body_text = body_bytes.decode("utf-8", errors="replace")
    inline_bindings, _stripped = collect_inline_bindings(body_text)
    known_txids = {q["root_txid"] for q in (quipus or [])}
    parsed = _parse_field_value(_stripped)

    out = []

    if metadata:
        # Pairwise: |LABEL|VALUE| convention (e.g. |SHA256|hash). Display
        # in pairs; if odd, list as single items.
        chips = []
        i = 0
        while i < len(metadata):
            if i + 1 < len(metadata):
                chips.append(
                    f"<span style='font-family:ui-monospace,monospace; "
                    f"font-size:10px; color:#666'>"
                    f"{_html.escape(metadata[i])}: "
                    f"{_html.escape(metadata[i+1][:16])}"
                    f"{'…' if len(metadata[i+1]) > 16 else ''}</span>"
                )
                i += 2
            else:
                chips.append(
                    f"<span style='font-size:10px; color:#666'>"
                    f"{_html.escape(metadata[i])}</span>"
                )
                i += 1
        out.append(
            f"<div style='margin:0 0 10px 0'>{' · '.join(chips)}</div>"
        )

    body_title = parsed.pop("Title", None)
    if body_title:
        out.append(
            f"<h3 style='font-family:Georgia,serif; margin:8px 0 4px 0; "
            f"font-size:18px'>{_html.escape(body_title)}</h3>"
        )

    artist = parsed.pop("Artist", None)
    if artist:
        out.append(
            f"<p style='font-style:italic; color:#555; "
            f"margin:0 0 12px 0; font-size:13px'>"
            f"by {_html.escape(artist)}</p>"
        )

    image_ref = parsed.pop("Image", None)
    if image_ref:
        # image_ref may be `<<txid>>` form
        m = REF_RE.search(image_ref)
        token = m.group(1) if m else image_ref
        txid = resolve_reference(
            token, global_bindings=global_bindings,
            inline_bindings=inline_bindings, known_txids=known_txids,
        )
        out.append(_render_image_inline_html(
            txid or token, quipus, df_out,
        ))

    text_field = parsed.pop("Text", None)
    if text_field:
        out.append(_render_prose_html(
            text_field,
            quipus=quipus, df_out=df_out, depth=depth,
            global_bindings=global_bindings,
            inline_bindings=inline_bindings,
            known_txids=known_txids,
        ))

    # *_Public lines: gather as Signatories
    sigs = []
    for k in list(parsed):
        if k.endswith("_Public"):
            sigs.append((k[: -len("_Public")], parsed.pop(k)))

    ca = parsed.pop("CertificateAuthority", None)
    if ca:
        m = REF_RE.search(ca)
        if m:
            token = m.group(1)
            txid = resolve_reference(
                token, global_bindings=global_bindings,
                inline_bindings=inline_bindings, known_txids=known_txids,
            )
            disp = txid[:16] + "…" if txid else token
        else:
            disp = ca[:16] + "…" if len(ca) > 16 else ca
        out.append(
            f"<p style='font-size:11px; color:#666; margin-top:12px'>"
            f"Authority: <code>{_html.escape(disp)}</code></p>"
        )

    if sigs:
        out.append(
            "<div style='border-top:1px solid #eee; margin-top:14px; "
            "padding-top:8px'>"
            "<div style='font-size:11px; color:#666; font-weight:bold; "
            "margin-bottom:4px'>Signatories</div>"
        )
        for name, pub in sigs:
            short = pub[2:18] if pub.startswith("0x") else pub[:16]
            out.append(
                f"<div style='font-size:11px; color:#555; margin:2px 0'>"
                f"{_html.escape(name)} &nbsp; "
                f"<code style='font-size:10px'>{_html.escape(short)}…</code>"
                f"</div>"
            )
        out.append("</div>")

    if parsed:
        out.append(
            "<div style='font-size:10px; color:#999; margin-top:10px; "
            "line-height:1.5'>"
        )
        for k, v in parsed.items():
            out.append(
                f"<b>{_html.escape(k)}:</b> "
                f"{_html.escape(v[:140])}{'…' if len(v) > 140 else ''}<br>"
            )
        out.append("</div>")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

def render_typographic(type_byte, header_bytes, body_bytes, *, root_txid=None,
                       quipus=None, df_out=None, depth=0,
                       global_bindings=None):
    """Render a quipu body as typographic HTML.

    type_byte / header_bytes / body_bytes — what to render
    root_txid       — the quipu's own txid (needed for identity sig verify)
    quipus          — full list of quipus in scope (for binding/embed lookup)
    df_out          — dataframe of outputs (for reading embedded quipus' bodies)
    depth           — recursion guard for nested embeds
    global_bindings — optional dict NAME→txid (from imported 0xab quipus)
    """
    if depth > 16:
        return ("<p style='color:#999; font-style:italic'>"
                "(embed depth cap reached)</p>")

    title = first_title(header_bytes)
    out = []
    if title and depth == 0:
        # Preserve newlines so multi-line captions (e.g. Monte Veritá's
        # "Monte Verità / Mountain of Truth / Lebensreform Colony / Ascona")
        # render as a stanza rather than collapsing onto one line.
        safe = _html.escape(title).replace("\n", "<br>")
        out.append(
            f"<h2 style='font-family:Georgia,serif; "
            f"margin:0 0 12px 0; font-size:22px; line-height:1.25'>"
            f"{safe}</h2>"
        )

    if type_byte in (0x00, 0x04):
        out.append(_render_text(
            header_bytes, body_bytes,
            quipus=quipus, df_out=df_out, depth=depth,
            global_bindings=global_bindings,
        ))
    elif type_byte == 0x1d:
        out.append(_render_identity(
            header_bytes, body_bytes,
            root_txid=root_txid,
            quipus=quipus, df_out=df_out, depth=depth,
            global_bindings=global_bindings,
        ))
    elif type_byte in (0x0c, 0xcc):
        out.append(_render_cert(
            header_bytes, body_bytes,
            quipus=quipus, df_out=df_out, depth=depth,
            global_bindings=global_bindings,
        ))
    else:
        out.append(
            f"<pre style='font-size:11px; color:#666'>"
            f"{_html.escape(body_bytes.decode('utf-8', errors='replace')[:1000])}"
            f"</pre>"
        )

    return "\n".join(out)
