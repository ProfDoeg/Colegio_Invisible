#!/usr/bin/env python3
"""
colegio_pipeline.py — render quipu prose into Tufte-style PDFs via colegio.cls,
and (round-trip) inscribe a colegio .tex as a 0x5c latex quipu and compile it
back from chain.

Two directions compose into one pipeline:

    0x01 essay / 0x09 book  ──convert──▶  colegio .tex  ──xelatex+colegio.cls──▶ PDF
                                               │
                                               └──inscribe──▶ 0x5c latex quipu
                                                                    │
    0x5c latex quipu  ──fetch──▶ .tex  ──(materialize colegio.cls + figs)──▶ PDF

References are *cited* or *shown*, decided LOCALLY (only from the token — never
from document position), so the render is a pure function of the bytes and a
live MD/PDF editor can preview it. See docs/quipu-types/essay.md §"Referencing
& display".

    <<TXID>>            cite — a link to quipu:<TXID> (+ bibliography)
    [text](<<TXID>>)    cite with custom anchor text
    ![cap](<<TXID>>)    SHOW — the content appears here, where written
    <<TXID render="…">> explicit treatment override (margin|full|inline|thumb|embed)

A shown IMAGE's default placement is shape-aware (one local rule on its own
W/H): landscape (W/H ≥ 1.2) → full-column figure; portrait/square → margin
figure; celestial → full. Figures are UNNUMBERED and in-context (Tufte) — no
"Fig. N", no cross-references. A shown ESSAY/TEXT embeds its prose
(`render="margin"` → a "see also" margin card instead). Every shown image
carries a quipu:<txid> credit. Curated full-page art is a `plate` (numbered).

Reads use the local dataset (data/bodies/<txid>.bin); no RPC.

Engine: xelatex (colegio.cls is xelatex-only).
"""
from __future__ import annotations

import os
import re
import sys
import math
import struct
import base64
import subprocess
import html as _htmllib

REPO   = os.path.dirname(os.path.abspath(__file__))
CANON  = os.path.join(REPO, "canonical")
BODIES = os.path.join(REPO, "data", "bodies")
CLASS_PATH = os.path.join(REPO, "latex", "colegio", "colegio.cls")
sys.path.insert(0, CANON)

import image as imgmod                                   # 0x03
from celestial_render import _split_concat, render_celestial_quipu  # 0xce
from book import read_book_quipu, build_book_quipu, _find_body_start   # 0x09
from essay import (                                       # 0x01
    read_essay_quipu, parse_citation_inner,
    extract_binding_blocks, evaluate_blocks,
)
import structure as STRUCT                                # title/heading convention
from bindings import (
    BindingDict, resolve as resolve_alias,
    apply_substitutions, apply_annotations,
)
from latex import build_latex_quipu, read_latex_quipu, compile_to_pdf  # 0x5c

PROTOCOL_MAGIC = b"\xc1\xdd\x00\x01"
_TXID_RE = re.compile(r"^[0-9a-fA-F]{64}$")


# =====================================================================
#  Fetch + blob splitting + small readers
# =====================================================================

def local_fetcher(txid):
    """Return the full inscription blob (header||body) for a txid from the
    local dataset. Raises FileNotFoundError if absent."""
    path = os.path.join(BODIES, f"{txid}.bin")
    with open(path, "rb") as f:
        return f.read()


def type_of(blob):
    if blob[:4] != PROTOCOL_MAGIC:
        raise ValueError("not a quipu (magic missing)")
    return blob[4]


def _pipe_header_body_offset(blob):
    """Body offset for pipe-header types (text/essay/latex/binding): header
    is `c1dd0001 TT tone |f|f|…|`, body begins after the last header pipe.
    A pipe-field containing a newline marks that the body has begun."""
    if len(blob) <= 6 or blob[6:7] != b"|":
        return 6
    pos = 7
    hdr_end = 7
    while pos < len(blob):
        close = blob.find(b"|", pos)
        if close < 0:
            break
        if b"\n" in blob[pos:close]:
            break
        hdr_end = close + 1
        pos = close + 1
        if pos - 6 > 4096:
            break
    return hdr_end


def _image_header_body_offset(blob):
    """0x03: 12 structural bytes + optional |title|; body is pixels."""
    rest = blob[12:]
    if rest[:1] == b"|":
        j = rest.find(b"|", 1)
        if j != -1:
            return 12 + j + 1
    return 12


def split_blob(blob):
    """Split header||body for any supported type. Returns (header, body)."""
    t = type_of(blob)
    if t == 0x03:
        off = _image_header_body_offset(blob)
    elif t == 0xCE:
        return _split_concat(blob)
    elif t == 0x09:
        off = _find_body_start(blob)
    else:                       # 0x00 text, 0x01 essay, 0x5c latex, 0xab binding
        off = _pipe_header_body_offset(blob)
    return blob[:off], blob[off:]


def title_of(blob):
    """Best-effort title for any supported quipu type."""
    t = type_of(blob)
    try:
        if t == 0xCE:
            from celestial import read_celestial_quipu
            h, b = _split_concat(blob)
            return read_celestial_quipu(h, b).get("title", "")
        if t == 0x09:
            h, b = split_blob(blob)
            return read_book_quipu(h, b).get("title", "")
        if t == 0x03:
            h, b = split_blob(blob)
            return imgmod.read_image_quipu(h, b).get("title", "")
        # pipe-header text-like: first field after byte 6
        start = blob.find(b"|", 6)
        if start < 0:
            return ""
        end = blob.find(b"|", start + 1)
        if end < 0:
            return ""
        field = blob[start + 1:end].decode("utf-8", "replace")
        return field if "=" not in field else ""
    except Exception:
        return ""


# =====================================================================
#  Target → PNG (rasterise an image / celestial quipu)
# =====================================================================

_FIGURE_CACHE_VERSION = 8  # bump when the renderer changes; busts the on-disk cache


def target_to_png(txid, fetcher, figdir):
    """Rasterise a 0x03 or 0xce target to figdir/<txid8>_v<N>.png; return
    basename. Returns None if the target type is not rasterisable.

    The version stamp in the filename is what invalidates a stale cache.
    Bumping _FIGURE_CACHE_VERSION causes the next render to write fresh
    PNGs without anyone needing to remember to delete the old ones — and
    older-version PNGs are left on disk as a record (small cost). A
    one-line stash sweeps them away if desired.
    """
    os.makedirs(figdir, exist_ok=True)
    blob = fetcher(txid)
    t = type_of(blob)
    base = f"q{txid[:12]}_v{_FIGURE_CACHE_VERSION}"
    out = os.path.join(figdir, base + ".png")
    if os.path.exists(out):
        return base + ".png"

    if t == 0x03:
        # Canonical image decode (scene_viewer._image_to_png_datauri): geometry
        # from the dataset's authoritative dimensions_json, and the pixel body
        # taken off the TAIL of the blob. This is robust to variable header
        # lengths — a header scan mis-splits images whose title has no pipe
        # delimiters (e.g. an all-emoji title), which silently garbles the
        # decode. Don't hand-roll read_image_quipu here.
        if REPO not in sys.path:
            sys.path.insert(0, REPO)
        import scene_viewer as _SV
        uri = _SV._image_to_png_datauri(blob, txid=txid)
        with open(out, "wb") as f:
            f.write(base64.b64decode(uri.split(",", 1)[1]))
        return base + ".png"

    if t == 0xCE:
        if len(blob) > 6 and blob[6] == 0x03:        # kind=genealogy → family-tree render
            if REPO not in sys.path:
                sys.path.insert(0, REPO)
            import genealogy_to_tikz as _GT
            return _GT.genealogy_to_png(txid, fetcher, figdir)
        h, b = _split_concat(blob)
        render_celestial_quipu(h, b, output_path=out)
        return base + ".png"

    if t == 0x3D:
        # A scene's render is a projected camera-view (vector TikZ → PNG),
        # built by scene_to_tikz. The scene is the inscription; this is its
        # view, the way a 0x03's render is its pixels and a 0xce's is its
        # chart. Returns its own versioned basename.
        if REPO not in sys.path:
            sys.path.insert(0, REPO)
        import scene_to_tikz as _ST
        return _ST.scene_to_png(txid, fetcher, figdir)

    return None


# =====================================================================
#  LaTeX escaping
# =====================================================================

_LATEX_SPECIALS = {
    "\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$",
    "#": r"\#", "_": r"\_", "{": r"\{", "}": r"\}",
    "~": r"\textasciitilde{}", "^": r"\textasciicircum{}",
}
_LATEX_ESC_RE = re.compile(r"[\\&%$#_{}~^]")


def latex_escape(s):
    return _LATEX_ESC_RE.sub(lambda m: _LATEX_SPECIALS[m.group(0)], s)


def _short_quipu(txid):
    return f"{txid[:8]}\\dots{txid[-6:]}"


# =====================================================================
#  Conversion context
# =====================================================================

class Ctx:
    """Carries per-document conversion state."""
    def __init__(self, *, fetcher, figdir, bd, mode="essay",
                 depth=0, title_lookup=None):
        self.fetcher = fetcher
        self.figdir  = figdir
        self.bd      = bd
        self.mode    = mode          # 'essay' | 'book'
        self.depth   = depth
        self.title_lookup = title_lookup or (lambda t: title_of(fetcher(t)) if _is_txid(t) else "")
        self.unattached = []         # (anchor, note_latex) for the colophon
        self.figures = []            # txids of embedded image/celestial quipus
        self.references = {}         # txid -> (title, type_byte) for the bibliography


def _is_txid(s):
    return bool(_TXID_RE.match(s or ""))


# =====================================================================
#  Render directive: resolve a <<…>> reference to LaTeX
# =====================================================================

_SHOW_TREATMENTS = ("margin", "marginplate", "full", "inline", "thumb", "embed", "certificate")
_FULL_ASPECT = 1.2   # image W/H at/above this → full-column figure; below → margin


def resolve_reference(name, attrs, ctx, *, alt="", from_image=False):
    """Turn a parsed reference into LaTeX. Two intents, decided LOCALLY — a
    reference's meaning depends only on the token itself, never on what else is
    in the document (so the render is a pure function of the bytes and a live
    editor can preview it):

      * CITE — `<<txid>>` / `[text](<<txid>>)` → a link to quipu:<txid>
               (+ bibliography). Never shows content.
      * SHOW — `![cap](<<txid>>)`, or any explicit `render=` treatment → the
               content appears HERE, where written.

    For a shown image the default placement is shape-aware: landscape
    (W/H ≥ 1.2) → full-column figure, portrait/square → margin figure.
    `render="margin|full|inline|thumb|embed"` always overrides. `from_image`
    is True when the call came from the `![]` image syntax. See
    docs/quipu-types/essay.md §"Referencing & display"."""
    explicit = (attrs.get("render") or "").lower() or None
    width    = attrs.get("width")
    caption  = attrs.get("caption") or alt or ""
    title    = attrs.get("title") or alt or ""

    # Resolve alias chain → terminal txid (or unresolved name).
    try:
        target = resolve_alias(name, ctx.bd)
    except ValueError:
        target = name
    if not _is_txid(target):
        return f"\\quipucite[{latex_escape(title or name)}]{{{latex_escape(target)}}}"

    try:
        tbyte = type_of(ctx.fetcher(target))
    except Exception:
        tbyte = None

    # Record for the book bibliography (whether cited or shown).
    reftitle = ctx.title_lookup(target) or title or ""
    ctx.references.setdefault(target, (reftitle, tbyte))
    anchor = title or ctx.title_lookup(target)

    # CITE unless this is the image syntax or an explicit show treatment.
    show = (explicit in _SHOW_TREATMENTS) or (from_image and explicit != "link")
    if not show:
        return _cite(target, anchor)

    # ---- SHOW: text / essay -----------------------------------------------
    if tbyte in (0x00, 0x01):
        if explicit == "margin":
            return _marginsee_latex(target, ctx, anchor)
        return _embed_prose(target, ctx, caption or ctx.title_lookup(target))

    # ---- SHOW: certificate (0xcc) -----------------------------------------
    if tbyte == 0xCC:
        return _render_cert_quipu(target, ctx, caption or anchor, attrs=attrs)

    # ---- SHOW: genealogy (0xce kind=03) → NATIVE TikZ family graph --------
    if tbyte == 0xCE:
        try:
            isgen = ctx.fetcher(target)[6] == 0x03
        except Exception:
            isgen = False
        if isgen:
            import family_graph as _FG
            return _FG.family_graph_tikz(target, ctx.fetcher, caption or ctx.title_lookup(target) or "")

    # ---- SHOW: image / celestial / scene-view -----------------------------
    if tbyte in (0x03, 0xCE, 0x3D):
        png = target_to_png(target, ctx.fetcher, ctx.figdir)
        if not png:
            return _cite(target, anchor)
        ctx.figures.append(target)                       # round-trip manifest
        cap = caption or ctx.title_lookup(target) or ""
        # A scene-view is a wide camera projection — always full-column.
        if tbyte == 0x3D:
            treatment = explicit or "full"
        else:
            treatment = explicit or _auto_image_treatment(target, tbyte, ctx.fetcher)
        if treatment == "full":
            return _wide_figure_latex(png, target, cap, width or "\\linewidth")
        if treatment == "inline":
            return "\\imagequipuinline[%s]{%s}{%s}" % (width or "\\linewidth", png[:-4], target)
        if treatment == "thumb":
            return "\\imagequiputhumb[%s]{%s}{%s}" % (width or "12mm", png[:-4], target)
        if treatment == "marginplate":
            # absolute-positioned full-height margin art — no flow disturbance,
            # with a clickable quipu: link beneath it
            return "\\marginplate[%s]{figures/%s}" % (target, png)
        return _margin_figure_latex(png, target, cap)    # margin (default)

    # ---- SHOW: latex plate (0x5c) — small, in-flow ------------------------
    # A plate shown inline in prose renders SMALL where it is summoned (the
    # full-page version lives in the `art/NN` gallery). The caption comes
    # from the show's own caption or the plate's header caption; the quipu
    # credit is the plate's txid. Compiles the standalone 0x5c to a PDF in
    # figdir, exactly as the gallery does, but places it via \plateinline.
    if tbyte == 0x5C:
        base = _compile_latex_plate(target, ctx.figdir, ctx.fetcher)
        if not base:
            return _cite(target, anchor)
        base_noext = base[:-4] if base.endswith(".pdf") else base
        if explicit == "marginplate":
            # a 0x5c art plate filling the outer margin, with a quipu: link
            return "\\marginplate[%s]{figures/%s}" % (target, base_noext)
        cap = caption or _plate_caption(target, ctx.fetcher, "") \
            or ctx.title_lookup(target) or ""
        return "\\plateinline{%s}{%s}{%s}" % (base_noext, latex_escape(cap), target)

    # ---- SHOW requested on a type we can't display → cite -----------------
    return _cite(target, anchor)


def _image_aspect(txid, fetcher):
    """W/H of a 0x03 image, for shape-aware placement. None if unknown."""
    try:
        blob = fetcher(txid)
        if type_of(blob) == 0x03:
            header, body = split_blob(blob)
            meta = imgmod.read_image_quipu(header, body)
            h = meta["height"]
            return (meta["width"] / h) if h else None
    except Exception:
        pass
    return None


def _auto_image_treatment(txid, tbyte, fetcher):
    """Default placement for a shown image — one local rule on its own shape:
    landscape (W/H ≥ _FULL_ASPECT) → full-column figure; portrait/square →
    margin. Celestial charts default to full (they want the width)."""
    if tbyte == 0xCE:
        return "full"
    asp = _image_aspect(txid, fetcher)
    return "full" if (asp is not None and asp >= _FULL_ASPECT) else "margin"


def _cite(target, anchor):
    """A plain citation link to quipu:<target>, with optional anchor text."""
    if anchor:
        return f"\\quipucite[{latex_escape(anchor)}]{{{target}}}"
    return f"\\quipucite{{{target}}}"


def _subobject_cite(obj_name, sub_name, anchor, ctx):
    """A two-segment reference `<<object>><<SubObject>>` → a cite into a NAMED
    element of a structured quipu: quipu:<txid>#<SubObject> (a star in a
    celestial chart, a field in a cert, a drop in a keydrop). The parent object
    is recorded in the bibliography; the anchor defaults to the element name."""
    try:
        target = resolve_alias(obj_name, ctx.bd)
    except ValueError:
        target = obj_name
    label = anchor or sub_name
    if not _is_txid(target):
        return "\\quipucite[%s]{%s}" % (latex_escape(label), latex_escape(target))
    try:
        tbyte = type_of(ctx.fetcher(target))
    except Exception:
        tbyte = None
    ctx.references.setdefault(target, (ctx.title_lookup(target) or "", tbyte))
    return "\\quipusubcite{%s}{%s}{%s}" % (target, latex_escape(sub_name), latex_escape(label))


def _margin_figure_latex(png, txid, caption):
    if not png:
        return "\\quipucite{%s}" % txid
    return "\\imagequipu{%s}{%s}{%s}" % (png[:-4], txid, latex_escape(caption))


def _wide_figure_latex(png, txid, caption, width):
    if not png:
        return "\\quipucite{%s}" % txid
    return "\\imagequipuwide[%s]{%s}{%s}{%s}" % (width, png[:-4], txid, latex_escape(caption))


# Image-pair / diptych: an image target of the form `<<txidA>> <<txidB>>` (two
# adjacent references inside the `![]` show form) is rendered as one full-width
# figure with two subimages side by side, both credited in the caption block.
_PAIR_TARGET_RE = re.compile(r"^\s*<<([^<>]+)>>\s+<<([^<>]+)>>\s*$")


def _pair_show(left_ref, right_ref, caption, ctx):
    """Render two image quipus as one side-by-side full-width figure.
    Returns the LaTeX string, or None if either ref isn't a renderable image."""
    pngs, txids = [], []
    for ref in (left_ref, right_ref):
        name, _attrs = parse_citation_inner(ref)
        try:
            target = resolve_alias(name, ctx.bd)
        except ValueError:
            target = name
        if not _is_txid(target):
            return None
        try:
            tbyte = type_of(ctx.fetcher(target))
        except Exception:
            tbyte = None
        if tbyte not in (0x03, 0xCE):
            return None
        png = target_to_png(target, ctx.fetcher, ctx.figdir)
        if not png:
            return None
        ctx.figures.append(target)
        ctx.references.setdefault(target, (ctx.title_lookup(target) or "", tbyte))
        pngs.append(png[:-4])
        txids.append(target)
    return "\\imagequipupair{%s}{%s}{%s}{%s}{%s}" % (
        pngs[0], pngs[1], latex_escape(caption), txids[0], txids[1])


# Embedded `<<txid>>` finder, used for picking out citations carried inside a
# cert's Field: value lines (e.g. Image: <<…>>, CertificateAuthority: <<…>>).
_CERT_INLINE_REF = re.compile(r"<<\s*([0-9a-fA-F]{64})\s*>>")


# Known multisig inscribing addresses and what kind of multisig sits at each.
# The NAMES of the keys that signed are resolved separately, by reading a hash
# cert: this cert if it IS a hash cert (its *_Public fields name the keys),
# or its CertificateAuthority for an all-in-one.
_MULTISIG_KIND = {
    "9xth7DcLGb1nACScMBeSfDCfghhLKF7yqs": "3-of-3 multisig",   # bordado
    "AD28bxzxyrd3a4Qgad2VNQ2eN5Leg8ozuw": "2-of-2 multisig",   # ca
    "A7pfCe2Cw9JD2C4vEZbpDmUZJy7B2TaefV": "2-of-2 multisig",   # ha
    "A3ShjwjsAE4ysM66EZJM3A28tPnL2jNDgC": "2-of-2 multisig",   # multiman
}

_PIPELINE_DIR = os.path.dirname(os.path.abspath(__file__))
_ADDR_CACHE = None  # lazy: txid → inscribing-address from data/quipu_data.csv
_ADDR_LABELS = None  # lazy: address → human label, same source


# ----------------------------------------------------------------------
#   Logging — stderr channel for swallowed exceptions
#
#   The pipeline has many `except Exception` blocks that fall back to a
#   safe default (no inscription, no figure, no thumbnail) to keep a
#   render going when one inscription's strand data is missing. Without
#   a log they hide real regressions. _logwarn writes a one-line marker
#   to stderr so a CI run or a manual rebuild surfaces "I tried to do X
#   and Y went wrong" without aborting.
#
#   Suppress with env COLEGIO_QUIET=1 if a noisy run is unwanted.
# ----------------------------------------------------------------------
def _logwarn(where, exc, *, txid=None):
    """Log a swallowed exception to stderr without aborting the render.
    Returns None so a caller can write `except: _logwarn(...); return None`."""
    if os.environ.get("COLEGIO_QUIET"):
        return None
    target = (" " + txid[:12]) if txid else ""
    sys.stderr.write("[colegio_pipeline] %s%s: %s: %s\n"
                     % (where, target, type(exc).__name__, exc))
    return None


def _load_addr_caches():
    global _ADDR_CACHE, _ADDR_LABELS
    if _ADDR_CACHE is not None:
        return
    _ADDR_CACHE = {}
    _ADDR_LABELS = {}
    path = os.path.join(_PIPELINE_DIR, "data", "quipu_data.csv")
    if not os.path.exists(path):
        return
    import csv as _csv
    with open(path, newline="", encoding="utf-8") as f:
        reader = _csv.DictReader(f)
        for row in reader:
            txid = row.get("root_txid", "")
            addr = row.get("address", "")
            label = row.get("label", "")
            if len(txid) == 64 and addr:
                _ADDR_CACHE[txid] = addr
                if addr not in _ADDR_LABELS and label:
                    _ADDR_LABELS[addr] = label


def _address_of(txid):
    """Inscribing address of a quipu, read from data/quipu_data.csv (lazily
    cached on first call). Returns None if unknown."""
    _load_addr_caches()
    return _ADDR_CACHE.get(txid)


def _label_for_address(addr):
    """Human label for an inscribing address (e.g. 'bordado', 'apocrypha')."""
    _load_addr_caches()
    return _ADDR_LABELS.get(addr, "")


def _resolve_signer_names(cert_parsed, ctx):
    """Human names of the keys whose multisig signed this cert's inscribing
    transaction. A hash cert names them directly via *_Public fields; an
    all-in-one resolves them by following CertificateAuthority to a hash cert."""
    fields = cert_parsed.get("fields") or {}
    names = [k[: -len("_Public")] for k in fields if k.endswith("_Public")]
    if names:
        return names
    ca = fields.get("CertificateAuthority", "")
    m = _CERT_INLINE_REF.search(ca)
    if not m:
        return []
    try:
        from cert import read_cert as _read_cert
        blob = ctx.fetcher(m.group(1))
        if type_of(blob) != 0xCC:
            return []
        ca_cert = _read_cert(blob[:8], blob[8:])
        return [k[: -len("_Public")]
                for k in (ca_cert.get("fields") or {})
                if k.endswith("_Public")]
    except Exception:
        return []


def _render_cert_quipu(txid, ctx, caption="", *, attrs=None):
    """Render a 0xcc certificate as a formatted CARD — header chips, body
    title, "by Artist", optional embedded image, prose Text, signatories
    (name + public-key fragment for each *_Public field), and an authority
    footer. Mirrors essay_renderer._render_cert (the quipu browser's HTML
    popup design). Falls back to a plain cite if the body can't be parsed.

    `attrs.get("title")` overrides the auto-detected card name (useful for a
    hash cert that has no |TITLE| preamble — author can label it from the
    markup, e.g. <<txid render="certificate" title="Bordado Key Declaration">>).
    """
    try:
        from cert import read_cert as _read_cert
    except Exception:
        return _cite(txid, caption)
    try:
        # Cert headers are 8 bytes flat (magic + type + tone + 2-byte subtype);
        # split_blob's pipe-based split would chop off the subtype bytes.
        blob = ctx.fetcher(txid)
        c = _read_cert(blob[:8], blob[8:])
    except Exception:
        return _cite(txid, caption)

    fields = dict(c.get("fields") or {})           # preserves insertion order (3.7+)
    out = ["\\begin{certquipu}",
           "\\certheader{%s}" % txid]               # credit + clickable quipu: link

    # Hash certs carry HASH_ALGO + hash_hex in the body preamble. Show the
    # FULL digest as a labeled feature of the card (it's the cert's whole
    # substance — naming it requires showing it whole).
    if c.get("subtype_name") == "hash":
        algo = c.get("hash_algo", "")
        hh = c.get("hash_hex", "")
        out.append("\\certhash{%s}{%s}" % (latex_escape(algo), latex_escape(hh)))

    # Card title — fallback chain. Explicit `title=` attr first, then the
    # cert's own bytes (|TITLE| preamble, then body `Title:` field), then the
    # caller's caption/alt as a last resort. The caption fallback lets an
    # author name a hash cert that has no |TITLE| from the image-form alt,
    # e.g. `![Bordado Key Declaration](<<MAIER>>)`.
    body_title = fields.pop("Title", None)
    title = ((attrs or {}).get("title") or c.get("title")
             or body_title or caption)
    if title:
        out.append("\\certtitle{%s}" % latex_escape(title))

    artist = fields.pop("Artist", None)
    if artist:
        out.append("\\certartist{%s}" % latex_escape(artist))

    # Embedded image — all-in-one's `Image: <<txid>>`.
    image_ref = fields.pop("Image", None)
    if image_ref:
        m = _CERT_INLINE_REF.search(image_ref)
        if m:
            img_txid = m.group(1)
            try:
                tbyte_img = type_of(ctx.fetcher(img_txid))
            except Exception:
                tbyte_img = None
            if tbyte_img in (0x03, 0xCE):
                png = target_to_png(img_txid, ctx.fetcher, ctx.figdir)
                if png:
                    ctx.figures.append(img_txid)
                    ctx.references.setdefault(
                        img_txid,
                        (ctx.title_lookup(img_txid) or "", tbyte_img))
                    out.append("\\certimage{%s}{%s}" % (png[:-4], img_txid))

    # Prose Text block — pass through the standard inline converter so any
    # `<<txid>>` citations resolve to links and join the bibliography.
    text_field = fields.pop("Text", None)
    if text_field:
        out.append("\\certtextblock{%s}" % convert_inline(text_field, ctx))

    # Signatories — every `*_Public` field becomes a "name + pubkey-fragment" row.
    sigs = []
    for k in list(fields):
        if k.endswith("_Public"):
            sigs.append((k[: -len("_Public")], fields.pop(k)))
    if sigs:
        out.append("\\certsectionhead{Signatories}")
        for name, pub in sigs:
            if pub.startswith("0x") and len(pub) > 18:
                short = "0x" + pub[2:10] + ".." + pub[-6:]
            else:
                short = pub[:18]
            out.append("\\certsignatory{%s}{%s}" % (
                latex_escape(name), latex_escape(short)))

    # CertificateAuthority footer.
    ca = fields.pop("CertificateAuthority", None)
    if ca:
        m = _CERT_INLINE_REF.search(ca)
        if m:
            ca_txid = m.group(1)
            try:
                tbyte_ca = type_of(ctx.fetcher(ca_txid))
            except Exception:
                tbyte_ca = None
            ctx.references.setdefault(
                ca_txid, (ctx.title_lookup(ca_txid) or "", tbyte_ca))
            label = ca_txid[:8] + ".." + ca_txid[-8:]
            out.append("\\certauthority{%s}{%s}" % (label, ca_txid))

    # Inscription footer — the multisig address, its kind, and the resolved
    # names of the signing keys. The names are taken from this cert's own
    # *_Public fields when it's a hash cert; for an all-in-one they are
    # resolved by following CertificateAuthority to a hash cert that does.
    addr = _address_of(txid)
    if addr:
        kind = _MULTISIG_KIND.get(addr, "")
        signers = _resolve_signer_names(c, ctx)
        if kind and signers:
            out.append("\\certinscription{%s}{%s}{%s}" % (
                latex_escape(addr), latex_escape(kind),
                latex_escape(" + ".join(signers))))

    # Record the cert itself in the bibliography.
    cert_title = c.get("title") or title or c.get("hash_algo") or ""
    ctx.references.setdefault(
        txid, (ctx.title_lookup(txid) or cert_title, 0xCC))

    out.append("\\end{certquipu}")
    return "\n".join(out)


def _marginsee_latex(target, ctx, title):
    """A Tufte 'see also' margin card for a text/essay/book target: the work's
    title (linked to quipu:<txid>), a short excerpt, and the quipu credit."""
    title = title or _short_quipu(target)
    return "\\marginsee{%s}{%s}{%s}" % (
        latex_escape(title), target, latex_escape(_excerpt_of(target, ctx)))


def _excerpt_of(target, ctx, maxlen=140):
    """First clean paragraph of a text/essay target, for a see-also card."""
    try:
        blob = ctx.fetcher(target)
        h, b = split_blob(blob)
        t = type_of(blob)
        if t == 0x01:
            parsed = read_essay_quipu(h, b)
            md, htitle = parsed["body"], parsed["title"]
        elif t == 0x00:
            md, htitle = b.decode("utf-8", "replace"), title_of(blob)
        else:
            return ""
        md, _ = STRUCT.normalize_body(md, htitle)        # drop the title H1
        for para in re.split(r"\n\s*\n", md):
            p = para.strip()
            if not p or p[0] in "#>`<|":
                continue
            p = re.sub(r"<<[^>]+>>", "", p)              # strip citations
            p = re.sub(r"[*_`]", "", p)                  # strip simple md marks
            p = " ".join(p.split())
            if not p:
                continue
            if len(p) > maxlen:
                p = p[:maxlen].rsplit(" ", 1)[0] + "…"
            return p
    except Exception:
        pass
    return ""


def _embed_prose(txid, ctx, heading):
    """Recursively render a text/essay target's prose inline, in a quote-like
    block. Depth-bounded."""
    if ctx.depth >= 3:
        return f"\\quipucite[{latex_escape(heading or '')}]{{{txid}}}"
    blob = ctx.fetcher(txid)
    header, body = split_blob(blob)
    t = type_of(blob)
    if t == 0x01:
        parsed = read_essay_quipu(header, body)
        md = parsed["body"]
    else:
        md = body.decode("utf-8", "replace")
    # Resolve this target's own bindings + v1 subs.
    cleaned, blocks = extract_binding_blocks(md)
    sub_bd = evaluate_blocks(blocks, fetcher=ctx.fetcher)
    cleaned = apply_substitutions(cleaned, sub_bd)
    sub_ctx = Ctx(fetcher=ctx.fetcher, figdir=ctx.figdir, bd=sub_bd,
                  mode=ctx.mode, depth=ctx.depth + 1,
                  title_lookup=ctx.title_lookup)
    inner = convert_markdown(_html_to_md(cleaned), sub_ctx)
    for k, v in sub_ctx.references.items():
        ctx.references.setdefault(k, v)       # bubble embedded refs up to the book bib
    head = ("\\textsc{%s}\\par\\nopagebreak\n" % latex_escape(heading)) if heading else ""
    return ("\n\\begin{quote}\\small\n%s%s\n\\end{quote}\n" % (head, inner))


# =====================================================================
#  Annotation weaving (v3 → \margin / \backnote / \inlinenote)
# =====================================================================

_ANN_SENTINEL = "\x00ANN%d\x00"
_ANN_SENTINEL_RE = re.compile("\x00ANN(\\d+)\x00")


def weave_annotations(text, ctx):
    """Insert annotation sentinels into `text` at anchor positions; return
    (text_with_sentinels, notes) where notes[i] = (mode, anchor, note_md).
    Unattached annotations are recorded on ctx.unattached."""
    placements = apply_annotations(text, ctx.bd)
    notes = []
    inserts = []   # (offset, sentinel)
    for p in placements:
        if p.get("unattached"):
            note_latex = convert_inline(p["note"], ctx)
            ctx.unattached.append((p["anchor"], note_latex))
            continue
        idx = len(notes)
        notes.append((p["mode"], p["anchor"], p["note"]))
        inserts.append((p["end"], _ANN_SENTINEL % idx))
    # Insert from the end so offsets stay valid.
    for off, sent in sorted(inserts, key=lambda x: -x[0]):
        text = text[:off] + sent + text[off:]
    return text, notes


def _expand_ann_sentinel(m, ctx, notes):
    mode, anchor, note_md = notes[int(m.group(1))]
    note_latex = convert_inline(note_md, ctx)
    if mode == "endnote":
        return "\\backnote{%s}{%s}" % (latex_escape(anchor), note_latex)
    if mode == "inline":
        return "\\inlinenote{%s}" % note_latex
    return "\\margin{%s}" % note_latex      # default margin


# =====================================================================
#  HTML → markdown preprocessing
#
#  Some inscribed essay bodies embed raw HTML (figures, images, <pre>
#  blocks, <br>) for the web viewer. We fold the common constructs back
#  into render-directive markdown so the rest of the pipeline handles
#  them uniformly: <figure>/<img src="quipu:txid"> → a margin image,
#  <pre> → a fenced code block.
# =====================================================================

_FIGURE_RE  = re.compile(r"<figure\b[^>]*>(.*?)</figure>", re.DOTALL | re.IGNORECASE)
_IMG_TAG_RE = re.compile(
    r"""<img\b[^>]*?\bsrc\s*=\s*["']quipu:([0-9a-fA-F]{64})["'][^>]*?>""",
    re.IGNORECASE)
_IMG_ALT_RE = re.compile(r"""\balt\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_FIGCAP_RE  = re.compile(r"<figcaption\b[^>]*>(.*?)</figcaption>", re.DOTALL | re.IGNORECASE)
_PRE_RE     = re.compile(r"<pre\b[^>]*>(.*?)</pre>", re.DOTALL | re.IGNORECASE)
_ANCHOR_RE  = re.compile(r"<a\b[^>]*>(.*?)</a>", re.DOTALL | re.IGNORECASE)
# Real HTML tags only. The negative look-behind/-ahead keep this from
# matching the protocol's `<<…>>` citation delimiters: a real tag's `<`
# is never preceded by another `<`, and its `>` never followed by `>`.
_ANY_TAG_RE = re.compile(r"(?<!<)</?[A-Za-z][^>]*?>(?!>)")


def _strip_tags_text(s):
    s = _ANCHOR_RE.sub(r"\1", s)           # <a href=…>X</a> → X
    s = _ANY_TAG_RE.sub("", s)
    return _htmllib.unescape(s).strip()


def _html_to_md(md):
    def fig_repl(m):
        inner = m.group(1)
        im = _IMG_TAG_RE.search(inner)
        if not im:
            return "\n\n" + _strip_tags_text(inner) + "\n\n"
        txid = im.group(1)
        cap_m = _FIGCAP_RE.search(inner)
        alt_m = _IMG_ALT_RE.search(im.group(0))
        cap = _strip_tags_text(cap_m.group(1)) if cap_m else (alt_m.group(1) if alt_m else "")
        cap = cap.replace("[", "(").replace("]", ")")     # keep md alt well-formed
        return '\n\n![%s](<<%s>>)\n\n' % (cap, txid)
    md = _FIGURE_RE.sub(fig_repl, md)

    def img_repl(m):
        txid = m.group(1)
        alt_m = _IMG_ALT_RE.search(m.group(0))
        alt = (alt_m.group(1) if alt_m else "").replace("[", "(").replace("]", ")")
        return '\n\n![%s](<<%s>>)\n\n' % (alt, txid)
    md = _IMG_TAG_RE.sub(img_repl, md)

    md = _PRE_RE.sub(lambda m: "\n\n```\n%s\n```\n\n" % _strip_tags_text(m.group(1)), md)
    md = re.sub(r"<br\s*/?>", " ", md, flags=re.IGNORECASE)
    md = _ANY_TAG_RE.sub("", md)            # drop any stray tags
    return _htmllib.unescape(md)


# =====================================================================
#  Markdown → LaTeX  (block level)
# =====================================================================

_HEADING_RE   = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_HR_RE        = re.compile(r"^\s*([-*_])(?:\s*\1){2,}\s*$")
_ULIST_RE     = re.compile(r"^[ \t]*[-*+]\s+(.*)$")
_OLIST_RE     = re.compile(r"^[ \t]*\d+[.)]\s+(.*)$")
_BLOCKQUOTE_RE = re.compile(r"^>\s?(.*)$")
_FENCE_RE     = re.compile(r"^[ \t]*```")
_TABLE_SEP_RE = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$")
# A quotation attribution line inside a blockquote: "— Author, *Work*, Year".
_ATTRIB_RE    = re.compile(r"^\s*(?:—|–|--)\s*(.+)$")


def _attribution_latex(attr, ctx, notes=None):
    """Render a quotation attribution (`— Author, *Work*, Year`): the author
    (up to the first comma) in small caps, the rest as inline markdown — so a
    *Work* italicises and a <<quipu>> in the citation becomes a quipu: link."""
    author, _, rest = attr.partition(",")
    a = "\\textsc{%s}" % convert_inline(author.strip(), ctx, notes=notes)
    r = (", " + convert_inline(rest.strip(), ctx, notes=notes)) if rest.strip() else ""
    return "\\quoteby{%s%s}" % (a, r)


def _code_block_latex(code, lang=""):
    """A fenced ``` block → a verbatim quipucode box. Lines are emitted RAW
    (listings reads them verbatim), so code prints literally — essential for
    LaTeX / glTF / Python / markdown source. The fence language, if any, becomes
    a small label above the box."""
    lab = ("\\quipucodelang{%s}\n" % latex_escape(lang)) if lang else ""
    return "%s\\begin{quipucode}\n%s\n\\end{quipucode}\n" % (lab, "\n".join(code))


def _heading_command(level):
    """Map an absolute markdown heading level to a colegio sectioning command.

    Heading levels are absolute to the document tree (see canonical/structure.py):
    level 1 is the title, level 2 the first section, etc. The title is owned by
    metadata and is stripped upstream by STRUCT.normalize_body, so the body that
    reaches here starts at `##`. A stray level-1 heading that the title shim left
    in place (an unmatched leading H1 → drift) is rendered as a section rather
    than dropped, so no authored content is lost."""
    _role, depth = STRUCT.structural_role(level)
    return ("section", "subsection", "subsubsection")[min(depth, 2)]


def convert_markdown(md, ctx, *, notes=None):
    """Convert a markdown body (already binding-stripped + v1-substituted,
    optionally annotation-woven) to LaTeX. If `notes` is None, this call
    also weaves annotations from ctx.bd."""
    own_notes = False
    if notes is None:
        md, notes = weave_annotations(md, ctx)
        own_notes = True

    lines = md.split("\n")
    out = []
    i = 0
    n = len(lines)

    def flush_para(buf):
        if not buf:
            return
        text = " ".join(s.strip() for s in buf).strip()
        if text:
            out.append(convert_inline(text, ctx, notes=notes))

    para = []
    while i < n:
        line = lines[i]

        if not line.strip():
            flush_para(para); para = []
            i += 1
            continue

        # Fenced code block → a verbatim code box (raw, NOT latex-escaped, so
        # backslashes/braces/indentation survive — markdown, LaTeX, glTF, Python).
        if _FENCE_RE.match(line):
            flush_para(para); para = []
            lang = line.strip().lstrip("`").strip()      # ```python → "python"
            code = []
            i += 1
            while i < n and not _FENCE_RE.match(lines[i]):
                code.append(lines[i]); i += 1
            i += 1  # skip closing fence
            out.append(_code_block_latex(code, lang))
            continue

        # Heading — the title (level 1) is metadata-owned and stripped upstream
        # by STRUCT.normalize_body, so what reaches here is a section or deeper.
        m = _HEADING_RE.match(line)
        if m:
            flush_para(para); para = []
            level = len(m.group(1))
            text = m.group(2)
            cmd = _heading_command(level)
            out.append("\\%s{%s}\n" % (cmd, convert_inline(text, ctx, notes=notes)))
            i += 1
            continue

        # Horizontal rule
        if _HR_RE.match(line):
            flush_para(para); para = []
            out.append("\\par\\medskip\\noindent\\hrulefill\\par\\medskip\n")
            i += 1
            continue

        # Blockquote (optionally a cited quotation: a trailing `— …` line is
        # treated as the attribution — author, *work*, year — and may itself
        # carry a <<quipu>> citation).
        if _BLOCKQUOTE_RE.match(line):
            flush_para(para); para = []
            q = []
            while i < n and _BLOCKQUOTE_RE.match(lines[i]):
                q.append(_BLOCKQUOTE_RE.match(lines[i]).group(1)); i += 1
            attribution = None
            while q and not q[-1].strip():
                q.pop()
            if q:
                ma = _ATTRIB_RE.match(q[-1])
                if ma:
                    attribution = ma.group(1).strip()
                    q = q[:-1]
            # collapse internal blank lines into paragraph breaks
            qtext = "\n".join(q)
            qparas = [p for p in re.split(r"\n\s*\n", qtext)]
            body = "\\par\n".join(convert_inline(p.replace("\n", " ").strip(), ctx, notes=notes)
                                  for p in qparas if p.strip())
            attr = ("\n" + _attribution_latex(attribution, ctx, notes)) if attribution else ""
            out.append("\\begin{quote}\n%s%s\n\\end{quote}\n" % (body, attr))
            continue

        # GFM table: a header row followed by a separator row
        if "|" in line and i + 1 < n and _TABLE_SEP_RE.match(lines[i + 1]):
            flush_para(para); para = []
            i, tbl = _convert_table(lines, i, ctx, notes)
            out.append(tbl)
            continue

        # Lists
        if _ULIST_RE.match(line) or _OLIST_RE.match(line):
            flush_para(para); para = []
            i, lst = _convert_list(lines, i, ctx, notes)
            out.append(lst)
            continue

        # Standalone reference on its own line → its own block (a cite, or a
        # shown figure when an explicit render= treatment is given).
        s = line.strip()
        mref = re.fullmatch(r"<<\s*([^<>]+?)\s*>>", s)
        if mref:
            flush_para(para); para = []
            name, attrs = parse_citation_inner(mref.group(1))
            out.append(resolve_reference(name, attrs, ctx) + "\n")
            i += 1
            continue

        para.append(line)
        i += 1

    flush_para(para)
    # Separate every block with a blank line so LaTeX sees paragraph breaks
    # (a single newline is just a space in LaTeX).
    result = "\n\n".join(p.strip("\n") for p in out if p.strip("\n"))
    if own_notes:
        result = _ANN_SENTINEL_RE.sub(
            lambda m: _expand_ann_sentinel(m, ctx, notes), result)
    return result


def _convert_table(lines, i, ctx, notes):
    n = len(lines)

    def cells(row):
        row = row.strip()
        if row.startswith("|"):
            row = row[1:]
        if row.endswith("|"):
            row = row[:-1]
        return [c.strip() for c in row.split("|")]

    header = cells(lines[i])
    sep    = cells(lines[i + 1])
    aligns = []
    for s in sep:
        l, r = s.startswith(":"), s.endswith(":")
        aligns.append("c" if l and r else "r" if r else "l")
    i += 2
    rows = []
    while i < n and "|" in lines[i] and lines[i].strip():
        rows.append(cells(lines[i])); i += 1
    ncol = len(header)
    aligns = (aligns + ["l"] * ncol)[:ncol]

    def fmt(cell):
        return convert_inline(cell, ctx, notes=notes)

    # Render with tabularx at \linewidth so the table never exceeds the
    # measure. The LAST column becomes an `X` column — a paragraph column
    # that wraps and absorbs the leftover width — because the corpus's
    # tables put the wide free-text description last (type catalogs, tone
    # catalogs, sub-family lists). Earlier columns keep their markdown
    # alignment (l/c/r). For a single-column table there is no fixed
    # column to spread against, so fall back to a centered tabular.
    # \footnotesize keeps multi-column tables compact.
    def _xcolspec(aligns):
        if len(aligns) <= 1:
            return None  # signal: use plain tabular
        head = " ".join(aligns[:-1])
        # X column, left-justified, ragged so wrapped lines don't justify
        return "%s >{\\raggedright\\arraybackslash}X" % head

    xspec = _xcolspec(aligns)
    if xspec is None:
        buf = ["\\begin{table}[ht]\\centering\\footnotesize",
               "\\begin{tabular}{%s}" % " ".join(aligns), "\\toprule",
               " & ".join(fmt(c) for c in header) + " \\\\", "\\midrule"]
        close = ["\\bottomrule", "\\end{tabular}", "\\end{table}", ""]
    else:
        buf = ["\\begin{table}[ht]\\footnotesize",
               "\\begin{tabularx}{\\linewidth}{%s}" % xspec, "\\toprule",
               " & ".join(fmt(c) for c in header) + " \\\\", "\\midrule"]
        close = ["\\bottomrule", "\\end{tabularx}", "\\end{table}", ""]
    for r in rows:
        r = (r + [""] * ncol)[:ncol]
        buf.append(" & ".join(fmt(c) for c in r) + " \\\\")
    buf += close
    return i, "\n".join(buf) + "\n"


def _convert_list(lines, i, ctx, notes):
    """Consume a bullet/numbered list block. Each item starts with the bullet
    marker on its own line; *continuation* lines (subsequent lines indented
    by at least two spaces, with no fresh bullet) are appended to the
    current item's text rather than spilling out into the surrounding flow.
    A blank line ends the list. This matches CommonMark's loose-list
    behaviour just enough that a wrapped bullet renders as one bullet,
    not as a bullet followed by a stray paragraph."""
    n = len(lines)
    ordered = bool(_OLIST_RE.match(lines[i]))
    env = "enumerate" if ordered else "itemize"
    items = []
    rx = _OLIST_RE if ordered else _ULIST_RE
    current = None
    while i < n:
        line = lines[i]
        m = rx.match(line)
        if m:
            if current is not None:
                items.append(current)
            current = m.group(1)
            i += 1
            continue
        # Blank line ends the list.
        if line.strip() == "":
            break
        # Continuation line: starts with at least one whitespace AND we have
        # a current item to attach it to. Append, collapsing surrounding
        # whitespace so the joined text reads as one paragraph.
        if current is not None and line[:1] in (" ", "\t"):
            current = current.rstrip() + " " + line.strip()
            i += 1
            continue
        # Anything else (a non-indented, non-bullet line) ends the list.
        break
    if current is not None:
        items.append(current)
    buf = ["\\begin{%s}" % env]
    for it in items:
        buf.append("  \\item " + convert_inline(it, ctx, notes=notes))
    buf.append("\\end{%s}" % env)
    return i, "\n".join(buf) + "\n"


# =====================================================================
#  Markdown → LaTeX  (inline level)
# =====================================================================

_INLINE_CODE_RE = re.compile(r"`([^`]+)`")
_IMG_RE         = re.compile(r"!\[([^\]]*)\]\(\s*(.+?)\s*\)")
_LINK_RE        = re.compile(r"(?<!!)\[([^\]]+)\]\(\s*([^)]+?)\s*\)")
_REF_RE         = re.compile(r"<<\s*([^<>]+?)\s*>>")
# Two adjacent refs `<<object>><<SubObject>>` = a sub-object reference (a named
# element inside a structured quipu, e.g. a star in a celestial chart).
_SUBREF_RE      = re.compile(r"<<\s*([^<>]+?)\s*>><<\s*([^<>]+?)\s*>>")
_STRONG_RE      = re.compile(r"\*\*([^*]+)\*\*|__([^_]+)__")
_EM_RE          = re.compile(r"\*([^*]+)\*|(?<!\w)_([^_]+)_(?!\w)")
# Mathematics: $$display$$ and $inline$ pass through RAW to LaTeX (not escaped).
_MATH_DISP_RE   = re.compile(r"\$\$(.+?)\$\$", re.S)
_MATH_INLINE_RE = re.compile(r"\$(?!\$)([^$]+?)\$")


def _inner_ref(target):
    """If a link/image target is `<<…>>`, return its inner; else None."""
    m = re.fullmatch(r"<<\s*([^<>]+?)\s*>>", target.strip())
    return m.group(1) if m else None


def convert_inline(text, ctx, *, notes=None):
    """Convert inline markdown to LaTeX. Scans left-to-right, emitting macros
    for protected spans and escaping literal runs."""
    out = []
    pos = 0
    L = len(text)
    while pos < L:
        # annotation sentinel
        ms = _ANN_SENTINEL_RE.match(text, pos)
        if ms:
            out.append(ms.group(0)); pos = ms.end(); continue   # expanded later
        # mathematics — $$display$$ then $inline$, passed through raw (unescaped)
        m = _MATH_DISP_RE.match(text, pos)
        if m:
            out.append("\\[%s\\]" % m.group(1)); pos = m.end(); continue
        m = _MATH_INLINE_RE.match(text, pos)
        if m:
            out.append("$%s$" % m.group(1)); pos = m.end(); continue
        # inline code
        m = _INLINE_CODE_RE.match(text, pos)
        if m:
            out.append("\\texttt{%s}" % latex_escape(m.group(1))); pos = m.end(); continue
        # image  ![alt](target)  —  target may be one <<txid>> (single image),
        #                            two `<<txid>> <<txid>>` (a diptych pair),
        #                            or `<<A>><<B>>` (a sub-object cite anchored
        #                            on `alt`, e.g. ![the hash](<<MAIER>><<hex>>)).
        m = _IMG_RE.match(text, pos)
        if m:
            alt, target = m.group(1), m.group(2)
            sm = _SUBREF_RE.match(target)
            if sm and sm.end() == len(target):
                oname, _oa = parse_citation_inner(sm.group(1))
                sname, _sa = parse_citation_inner(sm.group(2))
                out.append(_subobject_cite(oname, sname, alt, ctx))
                pos = m.end(); continue
            pm = _PAIR_TARGET_RE.match(target)
            if pm:
                pair = _pair_show(pm.group(1), pm.group(2), alt, ctx)
                if pair:
                    out.append(pair); pos = m.end(); continue
            inner = _inner_ref(target)
            if inner is not None:
                # The markdown image form means "show this here"; placement is
                # the shape-aware default unless render= overrides.
                name, attrs = parse_citation_inner(inner)
                out.append(resolve_reference(name, attrs, ctx, alt=alt, from_image=True))
            else:
                out.append("\\emph{[%s]}" % latex_escape(alt or "image"))
            pos = m.end(); continue
        # link [text](target) — possibly [anchor](<<…>>) or sub-object form
        # [anchor](<<A>><<B>>) → a cite into A's named element, anchored `anchor`.
        m = _LINK_RE.match(text, pos)
        if m:
            anchor, target = m.group(1), m.group(2)
            sm = _SUBREF_RE.match(target)
            if sm and sm.end() == len(target):
                oname, _oa = parse_citation_inner(sm.group(1))
                sname, _sa = parse_citation_inner(sm.group(2))
                out.append(_subobject_cite(oname, sname, anchor, ctx))
                pos = m.end(); continue
            inner = _inner_ref(target)
            if inner is not None:
                name, attrs = parse_citation_inner(inner)
                if "title" not in attrs and anchor:
                    attrs = dict(attrs); attrs["title"] = anchor
                out.append(resolve_reference(name, attrs, ctx, alt=anchor))
            elif target.startswith(("quipu:", "#")):
                out.append(latex_escape(anchor))      # quipu: link → just text
            else:
                out.append("\\href{%s}{%s}" % (target.replace("%", "\\%"),
                                               convert_inline(anchor, ctx, notes=notes)))
            pos = m.end(); continue
        # sub-object reference <<object>><<SubObject>> → quipu:<txid>#<SubObject>
        m = _SUBREF_RE.match(text, pos)
        if m:
            oname, _oa = parse_citation_inner(m.group(1))
            sname, sa  = parse_citation_inner(m.group(2))
            out.append(_subobject_cite(oname, sname, sa.get("title"), ctx))
            pos = m.end(); continue
        # bare reference <<…>>
        m = _REF_RE.match(text, pos)
        if m:
            name, attrs = parse_citation_inner(m.group(1))
            out.append(resolve_reference(name, attrs, ctx))
            pos = m.end(); continue
        # strong
        m = _STRONG_RE.match(text, pos)
        if m:
            inner = m.group(1) or m.group(2)
            out.append("\\textbf{%s}" % convert_inline(inner, ctx, notes=notes))
            pos = m.end(); continue
        # emphasis
        m = _EM_RE.match(text, pos)
        if m:
            inner = m.group(1) or m.group(2)
            out.append("\\emph{%s}" % convert_inline(inner, ctx, notes=notes))
            pos = m.end(); continue
        # literal char run up to the next special
        nxt = L
        for ch in ("`", "!", "[", "<", "*", "_", "$", "\x00"):
            k = text.find(ch, pos + 1)
            if k != -1:
                nxt = min(nxt, k)
        out.append(latex_escape(text[pos:nxt]))
        pos = nxt
    result = "".join(out)
    if notes is not None:
        result = _ANN_SENTINEL_RE.sub(
            lambda m: _expand_ann_sentinel(m, ctx, notes), result)
    return result


# =====================================================================
#  Document assembly  (preamble + metadata + body → full .tex)
# =====================================================================

TONE_NAMES = {0x00: "ordinary", 0x01: "affection", 0x0d: "demonic",
              0xa1: "ai", 0xff: "reverence"}
TONE_HEX   = {v: f"{k:02x}" for k, v in TONE_NAMES.items()}

TYPE_LABELS = {
    0x00: "text", 0x01: "essay", 0x03: "image", 0x07: "audio",
    0x09: "book", 0x0e: "encrypted", 0x1d: "identity", 0x3d: "scene",
    0x5c: "latex", 0xab: "binding", 0xcc: "cert", 0xce: "celestial",
    0xda: "dancer", 0xee: "estandarte",
}


def _bibliography(references):
    """Build a \\begin{quipubibliography} block from a {txid: (title, type)}
    map. Entries are sorted by title (untitled last). Returns '' if empty."""
    if not references:
        return ""
    def sort_key(item):
        txid, (title, _t) = item
        return (0, title.lower()) if title else (1, txid)
    rows = []
    for txid, (title, tbyte) in sorted(references.items(), key=sort_key):
        label = TYPE_LABELS.get(tbyte, "quipu")
        label = "0x%02x %s" % (tbyte, label) if tbyte is not None else "quipu"
        disp  = title or "(untitled)"
        rows.append("  \\quipubibitem{%s}{%s}{%s}"
                    % (latex_escape(disp), label, txid))
    return "\\begin{quipubibliography}\n" + "\n".join(rows) + "\n\\end{quipubibliography}"


def _meta_from_parsed(parsed, txid, type_byte):
    f = parsed.get("fields", {})
    tone_name = TONE_NAMES.get(parsed.get("tone", 0), "ordinary")
    proto = "c1 dd 00 01 \\,%02x %s\\, |%s|" % (
        type_byte, TONE_HEX.get(tone_name, "00"),
        latex_escape(parsed.get("title", "")))
    for k in ("author", "institution", "date", "lang"):
        if f.get(k):
            proto += "%s=%s|" % (k, latex_escape(f[k]))
    return {
        "title":       parsed.get("title", ""),
        "tone":        tone_name,
        "author":      f.get("author", ""),
        "institution": f.get("institution", ""),   # title-page "{Institution}: {Author}"
        "date":        f.get("date", ""),
        "lang":        f.get("lang", ""),
        "epigraph":    f.get("epigraph", ""),   # title-page quote (small caps)
        "rootxid":     txid or "",
        "proto":       proto,
    }


def _preamble(mode, meta):
    L = [
        "%% generated by colegio_pipeline.py — do not edit by hand",
        "\\documentclass[%s,tone=%s]{colegio}" % (mode, meta["tone"]),
        "\\usepackage{booktabs}",
        __import__("family_graph").PREAMBLE,     # tikz + family-graph styles (native render)
        "\\title{%s}" % latex_escape(meta["title"]),
    ]
    if meta.get("author"):
        L.append("\\persona{%s}" % latex_escape(meta["author"]))
    if meta.get("institution"):
        L.append("\\institution{%s}" % latex_escape(meta["institution"]))
    if meta.get("date"):
        L.append("\\date{%s}" % latex_escape(meta["date"]))
    if meta.get("epigraph"):
        L.append("\\titleepigraph{%s}" % latex_escape(meta["epigraph"]))
    if meta.get("rootxid"):
        L.append("\\rootxid{%s}" % meta["rootxid"])
    if meta.get("jointxid"):
        L.append("\\jointxid{%s}" % meta["jointxid"])
    if meta.get("block"):
        L.append("\\blockheight{%s}" % meta["block"])
    L.append("\\protocolheader{%s}" % meta["proto"])
    return "\n".join(L)


# ======================================================================
#   Reference Index (back-matter appendix)
#
#   Walks the book's manifest tree recursively (every cover, chapter,
#   plate, sub-volume, and inline `<<txid>>` citation found inside any
#   essay body), plus follows certs to extract `*_Public` keys, then
#   emits three sorted sub-tables — quipus, addresses, keys — each with
#   clickable links via the quipu: / addr: / key: scheme handlers.
#
#   Triggered by a manifest entry with tag == "index". The pipeline
#   replaces that entry's content with the generated appendix.
# ======================================================================

_INDEX_PLACEHOLDER = "<<<<COLEGIO_REFERENCE_INDEX_HERE>>>>"
_INDEX_CITE_RE = re.compile(r"<<([0-9a-fA-F]{64})(?:[^>]*)>>")
_INDEX_KEY_RE  = re.compile(
    # Name starts with a capital letter then runs of letters, then
    # `_Public`, then `:` or `=`, then optional `0x`, then 8+ hex chars.
    # The capital-start anchor is what stops the name capture from
    # greedily consuming a preceding hash-digest run in cert bodies
    # where SHA256 (all-lowercase hex) sits immediately before the
    # first `*_Public` field with no separator.
    r"([A-Z][A-Za-z]*)_Public\s*[:=]\s*(?:0x)?([0-9a-fA-F]{8,})"
)


def _collect_full_reference_set(root_txid, fetcher):
    """Recursively walk a 0x09 book and all nested books, plus essays' inline
    `<<txid>>` citations and certs' `*_Public:0x…` fields, and return:
        {
          'quipus':    {txid: (type_byte, title)},
          'addresses': {address: label},
          'keys':      {pubkey: name},
        }
    """
    quipus  = {}
    addrs   = {}
    keys    = {}
    visited = set()

    def visit(txid):
        if not txid or txid in visited or len(txid) != 64:
            return
        visited.add(txid)
        try:
            blob = fetcher(txid)
        except Exception as e:
            _logwarn("index/fetch", e, txid=txid)
            return
        try:
            tbyte = type_of(blob)
        except Exception as e:
            _logwarn("index/type_of", e, txid=txid); tbyte = 0
        try:
            title = title_of(blob)
        except Exception as e:
            _logwarn("index/title_of", e, txid=txid); title = ""
        quipus[txid] = (tbyte, title)
        a = _address_of(txid)
        if a:
            addrs.setdefault(a, _label_for_address(a) or "")

        # 0x09 book → recurse into its entries
        if tbyte == 0x09:
            try:
                h, b = split_blob(blob)
                parsed = read_book_quipu(h, b)
                for e in parsed["entries"]:
                    visit(e["ref_txid"])
            except Exception as e:
                _logwarn("index/book recurse", e, txid=txid)

        # 0x01 essay / 0x00 text → scan body for inline citations
        if tbyte in (0x00, 0x01):
            try:
                body_str = blob.decode("utf-8", errors="ignore")
            except Exception as e:
                _logwarn("index/body decode", e, txid=txid); body_str = ""
            for m in _INDEX_CITE_RE.finditer(body_str):
                visit(m.group(1))

        # 0xcc cert → parse *_Public:0x… field lines
        if tbyte == 0xCC:
            try:
                text = blob[8:].decode("utf-8", errors="ignore")
            except Exception as e:
                _logwarn("index/cert decode", e, txid=txid); text = ""
            for m in _INDEX_KEY_RE.finditer(text):
                name = m.group(1).replace("_", " ")
                pubkey = m.group(2).lower()
                if pubkey not in keys:
                    keys[pubkey] = name

    visit(root_txid)
    return {"quipus": quipus, "addresses": addrs, "keys": keys}


def _render_reference_index(root_txid, fetcher, extra_refs=None):
    """Generate the LaTeX for the back-matter Reference Index, walking the
    full manifest tree from `root_txid`. `extra_refs` is an optional
    {txid: (title, type_byte)} dict (e.g. ctx.references) merged in so any
    inline citations the structural walk missed are caught. Returns ''
    when no references resolved (the appendix is suppressed)."""
    refs = _collect_full_reference_set(root_txid, fetcher)
    if extra_refs:
        for txid, (title, tbyte) in extra_refs.items():
            if txid not in refs["quipus"]:
                refs["quipus"][txid] = (tbyte or 0, title or "")
                a = _address_of(txid)
                if a:
                    refs["addresses"].setdefault(a, _label_for_address(a) or "")

    if not (refs["quipus"] or refs["addresses"] or refs["keys"]):
        return ""

    out = ["\\chapter*{Reference Index}",
           "\\addcontentsline{toc}{chapter}{Reference Index}",
           "\\begin{refindex}"]

    if refs["quipus"]:
        out.append("\\refindexsection{Quipu Inscriptions}")
        # The quipu list is the dense one — extend into the outer sidenote
        # margin (full-page-width measure) so each row's txid+type+title
        # fits on one line without the title wrapping.
        out.append("\\begin{widequipuindex}")
        for txid in sorted(refs["quipus"].keys()):
            tbyte, title = refs["quipus"][txid]
            type_label = "0x%02x %s" % (tbyte, TYPE_LABELS.get(tbyte, "?"))
            # Empty-title fallback so every row has a name.
            display_title = title.strip() if title else ""
            if not display_title:
                display_title = "untitled"
            out.append("\\quipurefitem{%s}{%s}{%s}" % (
                txid, type_label, latex_escape(display_title)))
        out.append("\\end{widequipuindex}")

    # Quipu section is the longest by far — break to a new page before the
    # Addresses + Keys sections so the second half of the index reads as
    # its own opening.
    if refs["quipus"] and (refs["addresses"] or refs["keys"]):
        out.append("\\clearpage")

    if refs["addresses"]:
        out.append("\\refindexsection{Inscribing Addresses}")
        for addr in sorted(refs["addresses"].keys()):
            label = refs["addresses"][addr] or ""
            out.append("\\addrrefitem{%s}{%s}" % (
                addr, latex_escape(label)))

    if refs["keys"]:
        out.append("\\refindexsection{Keys}")
        for pubkey in sorted(refs["keys"].keys()):
            name = refs["keys"][pubkey] or ""
            # Pubkeys are typically 128 hex chars — split into two halves
            # so the cls macro can stack them onto two lines under the
            # name, preventing the string from running off the page.
            half = len(pubkey) // 2
            line1, line2 = pubkey[:half], pubkey[half:]
            out.append("\\keyrefitem{%s}{%s}{%s}" % (
                line1, line2, latex_escape(name)))

    out.append("\\end{refindex}")
    return "\n".join(out)


def _figure_manifest(txids):
    """A LaTeX comment block listing the image/celestial quipus the document
    embeds, so a reader compiling the inscribed .tex can re-derive (decode)
    the figures from chain. Harmless to the compiler."""
    seen = list(dict.fromkeys(t for t in txids if _is_txid(t)))
    if not seen:
        return ""
    return "\n".join(["%%QUIPU-FIGURES-BEGIN"]
                     + ["%%QFIG " + t for t in seen]
                     + ["%%QUIPU-FIGURES-END"])


def _colophon(meta, ctx, type_label):
    rows = []
    if meta.get("institution"):
        rows.append("  \\colophonentry{organization}{%s}"
                    % latex_escape(meta["institution"]))
    for label, key in (("author", "author"), ("date", "date"), ("lang", "lang")):
        if meta.get(key):
            rows.append("  \\colophonentry{%s}{%s}" % (label, latex_escape(meta[key])))
    rows.append("  \\colophonentry{tone byte}{0x%s %s}"
                % (TONE_HEX.get(meta["tone"], "00"), meta["tone"]))
    rows.append("  \\colophonentry{type}{%s}" % type_label)
    if meta.get("rootxid"):
        rows.append("  \\colophonentry{root txid}{%s}" % meta["rootxid"])
    rows.append("  \\colophonentry{rendering}{xelatex via \\texttt{colegio.cls} "
                "(colegio\\_pipeline)}")
    for anchor, note in ctx.unattached:
        rows.append("  \\unattached{%s}{%s}" % (latex_escape(anchor), note))
    return "\\begin{colophon}\n" + "\n".join(rows) + "\n\\end{colophon}"


_BARE_TXID_CITE_RE = re.compile(r"<<\s*([0-9a-fA-F]{64})\s*>>")
_META_PREFIX_RE    = re.compile(r"^[\w-]+=[^|]*\|")


def _strip_leading_metadata(md):
    """Drop a leading `key=value|…|` metadata line some bodies carry before
    the prose (e.g. `place=…|previous=…|# Title`). Splits it off the first
    line only."""
    nl = md.find("\n")
    first = md if nl < 0 else md[:nl]
    if _META_PREFIX_RE.match(first) and "|" in first:
        # find the last pipe in the leading metadata run on this line
        # (prose like `# Title` begins after the final field pipe)
        cut = first.rfind("|")
        rest = first[cut + 1:]
        return (rest + (md[nl:] if nl >= 0 else "")).lstrip("\n")
    return md


def _thin_republish_target(cleaned):
    """If `cleaned` (binding blocks already removed) is exactly one bare
    <<64-hex>> citation plus at most a leading metadata line, return that
    target txid; else None."""
    text = _strip_leading_metadata(cleaned).strip()
    cites = _BARE_TXID_CITE_RE.findall(text)
    residual = _BARE_TXID_CITE_RE.sub("", text).strip()
    if len(cites) == 1 and not residual:
        return cites[0].lower()
    return None


def _resolve_thin_republish(cleaned, bd, ctx, depth=0):
    """If `cleaned` is a thin v2-republish wrapper (a bare <<essay_txid>>
    plus imported bindings), fetch the target essay, merge the wrapper's
    bindings over it, apply substitutions, and return (target_md, merged_bd).
    Recurses for chained republishes. Returns None if not a republish."""
    if depth > 4:
        return None
    target = _thin_republish_target(cleaned)
    if not target:
        return None
    try:
        blob = ctx.fetcher(target)
    except Exception:
        return None
    if type_of(blob) != 0x01:
        return None
    h, b = split_blob(blob)
    tmd = read_essay_quipu(h, b)["body"]
    tcleaned, tblocks = extract_binding_blocks(tmd)
    tbd = evaluate_blocks(tblocks, fetcher=ctx.fetcher)
    tbd.merge(bd)                      # wrapper bindings override/add (republish intent)
    nested = _resolve_thin_republish(tcleaned, tbd, ctx, depth + 1)
    if nested:
        return nested
    tcleaned = _strip_leading_metadata(tcleaned)
    tcleaned = apply_substitutions(tcleaned, tbd)
    return tcleaned, tbd


def _essay_body_latex(txid, ctx, *, extra_bd=None):
    """Resolve + convert an essay/text quipu's body to LaTeX (no preamble).
    Returns (body_latex, parsed, type_byte)."""
    blob = ctx.fetcher(txid)
    type_byte = type_of(blob)
    header, body = split_blob(blob)
    if type_byte == 0x01:
        parsed = read_essay_quipu(header, body)
        md = parsed["body"]
    else:
        parsed = {"title": title_of(blob), "tone": blob[5], "fields": {},
                  "body": body.decode("utf-8", "replace")}
        md = parsed["body"]
    cleaned, blocks = extract_binding_blocks(md)
    bd = evaluate_blocks(blocks, fetcher=ctx.fetcher)
    if extra_bd is not None:
        bd.merge(extra_bd)
    # Thin v2-republish wrapper → transclude the cited essay with bindings.
    trans = _resolve_thin_republish(cleaned, bd, ctx)
    if trans:
        cleaned, bd = trans
    else:
        cleaned = _strip_leading_metadata(cleaned)
        # Title convention (canonical/structure.py): the title is header-owned.
        # Absorb a leading body H1 that restates it BEFORE substitutions run,
        # so a content rewrite (e.g. hebreo→yiddish) can't desync the H1 from
        # the header title. A mismatched leading H1 is left in place + warned.
        cleaned, drift = STRUCT.normalize_body(cleaned, parsed.get("title", ""))
        if drift:
            sys.stderr.write(
                "[colegio] %s: body opens with H1 %r not matching header title %r; "
                "left in place as a section.\n"
                % ((txid or "")[:12], drift, parsed.get("title", "")))
        cleaned = apply_substitutions(cleaned, bd)
    ctx.bd = bd
    cleaned = _html_to_md(cleaned)
    return convert_markdown(cleaned, ctx), parsed, type_byte


def essay_to_tex(txid, *, fetcher=local_fetcher, figdir=None, extra_bd=None):
    """Render a 0x01 essay (or 0x00 text) quipu to a full colegio .tex."""
    figdir = figdir or os.path.join("/tmp", "colegio_figs")
    ctx = Ctx(fetcher=fetcher, figdir=figdir, bd=BindingDict(), mode="essay")
    body_latex, parsed, tb = _essay_body_latex(txid, ctx, extra_bd=extra_bd)
    meta = _meta_from_parsed(parsed, txid, tb)
    parts = [
        _preamble("essay", meta),
        _figure_manifest(ctx.figures), "",
        "\\begin{document}", "\\maketitle", "",
        body_latex, "",
        "\\printbacknotes", "",
        _colophon(meta, ctx, "0x%02x %s" % (tb, "essay" if tb == 0x01 else "text")),
        "\\end{document}", "",
    ]
    return "\n".join(p for p in parts if p is not None)


# Front-matter entry tags (rendered before the main chapters).
# Structural zones, by manifest tag prefix (the part before any "/NN").
# Local + order-faithful: each entry's zone is a pure function of its tag, and
# the renderer only flips a forward-only switch front → body → back. It never
# reorders, so manifest order is the reading order within each zone.
#   front → unnumbered \chapter* (roman pages), before the numbered chapters
#   body  → part/NN dividers, numbered chapter/essay, art plates, sub-volumes
#   back  → unnumbered \chapter* (afterword, etc.) + auto References + colophon
_FRONT_TAGS = ("dedication", "foreword", "forward", "preface", "prologo",
               "prologue", "introduction", "acknowledgments", "author_note",
               "publisher_note")
_BACK_TAGS  = ("afterword", "appendix", "glossary", "notes", "index",
               "errata", "credits")


def _tag_zone(tag):
    """front | body | back for a manifest entry tag (matches on the prefix)."""
    base = (tag or "").split("/", 1)[0]
    if base in _FRONT_TAGS:
        return "front"
    if base in _BACK_TAGS:
        return "back"
    return "body"


# =====================================================================
#  LaTeX-by-pointer: \quiputikz{<<txid>>} transclusion
#
#  A 0x5c body may carry \quiputikz{<<TXID>>} directives. Before compiling,
#  the pipeline fetches the referenced quipu and inlines its DATA as native
#  TikZ (draw commands only — the host supplies the tikzpicture + colours).
#  The inscribed 0x5c keeps the POINTER; expansion is transient at render,
#  and deterministic because the referenced bytes are immutable on chain.
#  This makes a LaTeX plate a transcluding consumer of the reference graph
#  like an essay — data lives once, the plate points at it.
# =====================================================================

_QTIKZ_RE = re.compile(
    r"\\quiputikz(\[[^\]]*\])?\{\s*(?:<<)?\s*([0-9a-fA-F]{64})\s*(?:>>)?\s*\}")


def earth_atlas_tikz_body(txid, fetcher, *, mode="route", lat_a=1.481, lat_b=-64.68,
                          lng_c=12.5, lng_scale=0.413, x_half=2.6, dot=0.07, palette=None):
    """Render an earth-kind 0xce atlas as a TikZ BODY (draw commands only, 1cm frame).
    FIXED equirectangular projection so layers register:
        y = lat_a*lat + lat_b           (locked to the latitude grid)
        x = (lng - lng_c)*lng_scale
    mode='route' → lat/lng gridlines + route legs (palette per group) + dots per leg.
    mode='coast' → fill sea over the window, fill the closed land rings, stroke the
    coast. Host must define kb/kp/kgold/kr/kg/ki/kw/ksea."""
    import math
    from collections import defaultdict
    from canonical.celestial import read_celestial_quipu
    h, b = split_blob(fetcher(txid))
    parsed = read_celestial_quipu(h, b)
    pts = parsed["points"]
    lats = [p["lat"] for p in pts]; lngs = [p["lng"] for p in pts]
    X = lambda v: (v - lng_c) * lng_scale
    Y = lambda v: lat_a * v + lat_b
    pal = palette or ["kb", "kp", "kgold", "kr", "kg"]

    if mode == "coast":                       # land/sea base: trace closed rings, fill
        adj = defaultdict(list)
        for (i, j) in parsed.get("lines", []):
            adj[i].append(j); adj[j].append(i)
        seen, rings = set(), []
        for s in range(len(pts)):
            if s in seen or not adj[s]:
                continue
            ring, prev, cur = [s], None, s; seen.add(s)
            while True:
                nb = [n for n in adj[cur] if n != prev]
                nxt = nb[0] if nb else None
                if nxt is None or nxt == s or nxt in seen:
                    break
                ring.append(nxt); seen.add(nxt); prev, cur = cur, nxt
            if len(ring) >= 3:
                rings.append(ring)
        L = ["\\fill[ksea] (%.2f,%.2f) rectangle (%.2f,%.2f);"
             % (-x_half - 0.7, Y(36) - 1, x_half + 0.7, Y(52) + 1)]
        for ring in rings:
            path = " -- ".join("(%.3f,%.3f)" % (X(pts[i]["lng"]), Y(pts[i]["lat"])) for i in ring)
            L.append("\\fill[kw] %s -- cycle;" % path)
            L.append("\\draw[kgold,opacity=0.6,line width=0.35pt] %s -- cycle;" % path)
        return "\n".join(L)

    groups = parsed.get("groups") or []
    latmin, latmax = min(lats), max(lats)
    lngmin, lngmax = min(lngs), max(lngs)
    pcol = {}                                  # point index -> leg colour
    for gi, g in enumerate(groups[:len(pal)]):
        for pidx in g.get("point_indices", []):
            pcol[pidx] = pal[gi]
    L = []
    # latitude gridlines (labels are baked outside the clip, as in the original)
    for la in range(5 * int(math.floor(latmin / 5)), 5 * int(math.ceil(latmax / 5)) + 1, 5):
        y = Y(la)
        L.append("\\draw[kgold,opacity=0.22,line width=0.2pt] (%.2f,%.2f) -- (%.2f,%.2f);"
                 % (-x_half, y, x_half, y))
    # longitude gridlines (every 2°)
    for lng in range(int(math.ceil(lngmin)), int(math.floor(lngmax)) + 1, 2):
        x = X(lng)
        L.append("\\draw[kgold,opacity=0.16,line width=0.2pt] (%.2f,%.2f) -- (%.2f,%.2f);"
                 % (x, Y(latmin) - 0.3, x, Y(latmax) + 0.3))
    # route legs — palette per group; the 6th 'lacuna' group is skipped
    for gi, g in enumerate(groups[:len(pal)]):
        edges = g.get("lines") or []
        if not edges:
            continue
        seq = [(X(lngs[i]), Y(lats[i])) for (i, _j) in edges]
        seq.append((X(lngs[edges[-1][1]]), Y(lats[edges[-1][1]])))
        L.append("\\draw[%s,line width=1.0pt,opacity=0.85] %s;"
                 % (pal[gi], " -- ".join("(%.3f,%.3f)" % c for c in seq)))
    # waypoint dots, coloured by leg
    for idx, p in enumerate(pts):
        L.append("\\fill[%s,opacity=0.9] (%.3f,%.3f) circle (%.3f);"
                 % (pcol.get(idx, "ki"), X(p["lng"]), Y(p["lat"]), dot))
    return "\n".join(L)


def _quipu_to_tikz(txid, fetcher, opts=""):
    """Dispatch a referenced quipu to a TikZ-body renderer by type/kind. `opts`
    is the bracket content of \\quiputikz[...] (e.g. 'coast')."""
    h, b = split_blob(fetcher(txid))
    if type_of(h + b) == 0xCE:
        from canonical.celestial import read_celestial_quipu
        if read_celestial_quipu(h, b).get("kind") == "earth":
            mode = "coast" if "coast" in (opts or "") else "route"
            return earth_atlas_tikz_body(txid, fetcher, mode=mode)
    raise ValueError("no \\quiputikz renderer for type 0x%02x" % type_of(h + b))


def resolve_quiputikz(tex, fetcher):
    """Expand every \\quiputikz[opts]{<<txid>>} in `tex` by inlining the referenced
    quipu's TikZ body. Unresolvable refs become a LaTeX comment (never break the
    build). The 0x5c body itself is unchanged on chain — this is render-time only."""
    def repl(m):
        txid = m.group(2)
        try:
            return _quipu_to_tikz(txid, fetcher, (m.group(1) or "")[1:-1])
        except Exception as e:
            return "%% quiputikz unresolved %s…: %s" % (txid[:12], e)
    return _QTIKZ_RE.sub(repl, tex)


def _compile_latex_plate(txid, figdir, fetcher):
    """Compile a 0x5c latex quipu (cover / art plate — a standalone document)
    to a PDF in figdir/. Returns the basename, or None on failure. The PDF is
    embedded into the colegio book with \\includegraphics (xelatex includes
    PDFs natively)."""
    os.makedirs(figdir, exist_ok=True)
    base = f"plate_{txid[:12]}.pdf"
    out = os.path.join(figdir, base)
    if os.path.exists(out):
        return base
    try:
        h, b = split_blob(fetcher(txid))
        parsed = read_latex_quipu(h, b)
        tex = resolve_quiputikz(parsed["tex_source"], fetcher)   # LaTeX-by-pointer
        pdf = compile_to_pdf(tex, engine=parsed.get("engine", "pdflatex"))
        with open(out, "wb") as f:
            f.write(pdf)
        return base
    except Exception as e:
        sys.stderr.write(f"[plate] {txid[:12]}…: {e}\n")
        return None


def _plate_caption(txid, fetcher, fallback=""):
    """A plate's descriptive caption, read from its OWN 0x5c header: the
    `caption=` field, else the header title, else `fallback` (the manifest
    entry name). Lets the description ride with the art, on chain."""
    try:
        h, b = split_blob(fetcher(txid))
        parsed = read_latex_quipu(h, b)
        return parsed.get("fields", {}).get("caption") or parsed.get("title") or fallback
    except Exception:
        return fallback


def _cover_page_latex(plate_base):
    """A true full-bleed, whole-page cover from a compiled 0x5c plate PDF:
    the art fills the entire page edge-to-edge (no margins), via eso-pic's
    absolute page-background layer at \\paperwidth × \\paperheight.

    The leading \\clearpage flushes any preceding content first, so the cover
    background lands on its OWN fresh page — essential for a nested-volume
    cover, which otherwise shares a page with the previous chapter's tail."""
    if not plate_base:
        return ""
    return ("\\clearpage\\thispagestyle{empty}%%\n"
            "\\AddToShipoutPictureBG*{\\put(0,0){"
            "\\includegraphics[width=\\paperwidth,height=\\paperheight]"
            "{figures/%s}}}%%\n\\null\\clearpage" % plate_base)


def _plate_page_latex(caption, plate_base, txid):
    """An art plate presented as a full-width figure (Tufte's widest measure:
    text column + outer margin), numbered "Plate N" with a descriptive caption
    (from the plate's own header — see _plate_caption) and a quipu credit. The
    compiled 0x5c plate is placed via \\platequipu on its own page."""
    if not plate_base:
        return "\\quipucite[%s]{%s}" % (latex_escape(caption), txid)
    return "\\platequipu{%s}{%s}{%s}" % (plate_base, latex_escape(caption), txid)


def _plate_gallery_blocks(plates):
    """The plate gallery, headed by a single 'Art Plates' entry in the TOC (at
    chapter level, like the Afterword) — so the Contents names the gallery once
    rather than listing every plate. The \\clearpage lands the TOC entry on the
    same page the first \\platequipu fills."""
    if not plates:
        return []
    return ["\\clearpage\\addcontentsline{toc}{chapter}{Art Plates}%"] + plates


def _volume_titlepage_latex(meta, *, toc_level=None):
    """A nested volume's single frontispiece — the volume half-title divider and
    the protocol title page combined onto ONE page: the on-chain header stamp,
    the volume number (Volume N), the title, author, date, tone byte, and the
    inscribed-book quipu line. Kept as a `titlepage` so a nested volume reads as
    its own bound book (and so per-volume pagination is unchanged)."""
    # Byline: "{Institution}: {Author}" when an institution is set, else author.
    _inst, _auth = meta.get("institution", ""), meta.get("author", "")
    _byline = ("%s: %s" % (_inst, _auth)) if (_inst and _auth) else (_inst or _auth)
    author = (("\\vspace{4mm}{\\fontsize{14}{17}\\selectfont\\itshape"
               "\\color{colegio@soft}%s\\par}\n" % latex_escape(_byline))
              if _byline else "")
    # Each book — including a nested volume — may carry its own title-page
    # epigraph (header `epigraph=` field), set in small caps like the top level.
    epigraph = (("\\vspace{12mm}{\\scshape\\fontsize{9}{13}\\selectfont"
                 "\\color{colegio@soft}\\rightskip=2em\\relax %s\\par}\n"
                 % latex_escape(meta["epigraph"])) if meta.get("epigraph") else "")
    foot = "%s\\,\\;$\\cdot$\\;\\,tone byte 0x%s" % (
        meta["tone"].upper(), TONE_HEX.get(meta["tone"], "00"))
    # A plain \clearpage page (NOT the titlepage environment), so the volume's
    # frontispiece does NOT reset the page counter — the anthology paginates
    # continuously straight through all volumes. (A standalone volume's own page
    # 1 still comes from book_to_tex's \mainmatter, which this never touches.)
    # The volume's TOC line is written ON this frontispiece page, so the link
    # lands on the half-title rather than the following content page.
    toc = (("\\addcontentsline{toc}{%s}{%s}%%\n" % (toc_level, latex_escape(meta["title"])))
           if toc_level else "")
    return ("\\clearpage\\thispagestyle{empty}\\refstepcounter{colegiovol}%%\n"
            + toc +
            "\\begingroup\\color{colegio@ink}\\raggedright\n"
            "\\null\\vspace*{16mm}\n"
            "{\\ttfamily\\fontsize{7}{9}\\selectfont\\color{colegio@soft}%s\\par}\n"
            "\\vspace*{24mm}\n"
            "{\\sffamily\\footnotesize\\color{colegio@soft}"
            "\\textsc{Volume \\Roman{colegiovol}}\\par}\n"
            "\\vspace{5mm}\n"
            "{\\fontsize{26}{30}\\selectfont\\itshape %s\\par}\n"
            "%s%s"
            "\\vfill\n{\\sffamily\\fontsize{8}{11}\\selectfont\\color{colegio@soft}\n"
            "%s\\par %s\\par an inscribed book \\,---\\, quipu:%s\\par}\n"
            "\\par\\endgroup\\clearpage"
            % (meta["proto"], latex_escape(meta["title"]), author, epigraph,
               foot, latex_escape(meta.get("date", "")), meta.get("rootxid", "")))


def _partition_entries(entries, *, fetcher, figdir, render_chapter, render_subbook):
    """Walk a book's entries once and sort them into structural zones.

    Returns (cover_base, front, body, back, plates) — all in manifest order.
    Each entry's zone is a pure function of its tag (see _tag_zone); body
    entries dispatch on the tag prefix: `part/NN` → a \\part divider,
    `subbook`/`volume` → a nested volume, everything else → a numbered chapter.
    `art/NN` plates are gathered SEPARATELY (returned in `plates`) so the caller
    can render them as a gallery at the end — after the text, before the
    References — rather than inline. `render_chapter(ref, name) -> latex`
    converts an essay/text body (and bubbles its figures/references into the
    caller's context); `render_subbook(ref) -> latex` renders a nested 0x09
    book as a bound volume."""
    cover = None
    front, body, back, plates = [], [], [], []

    def _section_star(ref, name):
        return ("\\chapter*{%s}\\addcontentsline{toc}{chapter}{%s}\n\n%s"
                % (latex_escape(name), latex_escape(name), render_chapter(ref, name)))

    for e in entries:
        tag, ref, name = e["tag"], e["ref_txid"], e["name"]
        base = (tag or "").split("/", 1)[0]
        if base == "binding":
            continue
        if tag == "cover":
            cover = _compile_latex_plate(ref, figdir, fetcher)
            continue
        if base == "index":                                   # back-matter Reference
            back.append(_INDEX_PLACEHOLDER)                   # Index — pipeline fills
            continue                                          # in after rendering
        zone = _tag_zone(tag)
        if zone == "front":
            front.append(_section_star(ref, name))
        elif zone == "back":
            back.append(_section_star(ref, name))
        elif base == "art":                                   # 0x5c art plate → gallery
            plates.append(_plate_page_latex(_plate_caption(ref, fetcher, name),
                                            _compile_latex_plate(ref, figdir, fetcher), ref))
        elif base == "part":                                  # SKIPPED — books
            continue                                          # carry chapter/section
                                                              # /subsection only
                                                              # (no \part dividers).
        elif base in ("subbook", "volume"):                   # nested 0x09
            body.append(render_subbook(ref))
        else:                                                 # chapter/NN, essay/NN, default
            body.append("\\chapter{%s}\n\n%s" % (latex_escape(name), render_chapter(ref, name)))
    return cover, front, body, back, plates


def _render_subbook(sub_txid, *, fetcher, figdir, parent_extra_bd, union_ctx,
                    depth=1):
    """Render a nested 0x09 sub-book as a COMPLETE BOUND VOLUME: its own cover
    (if any), a combined frontispiece, its own front matter, numbered chapters
    (restarting at 1) / parts / plates / deeper volumes, its own back matter,
    References, and colophon. The book type carries structure; the essay type
    carries content. Bindings merge over the parent's."""
    if depth > 3:
        return "\\quipucite{%s}" % sub_txid
    from bindings import evaluate as ev
    h, b = split_blob(fetcher(sub_txid))
    sb = read_book_quipu(h, b)
    meta = _meta_from_parsed(sb, sub_txid, 0x09)
    meta["jointxid"] = sb["fields"].get("join", "")
    extra_bd = BindingDict()
    extra_bd.merge(parent_extra_bd)
    for e in sb["entries"]:
        if e["tag"].startswith("binding"):
            try:
                extra_bd.merge(ev(e["ref_txid"], fetcher))
            except Exception:
                pass

    vol_ctx = Ctx(fetcher=fetcher, figdir=figdir, bd=BindingDict(), mode="book")

    def _render_essay_chapter(ref, name):
        ch = Ctx(fetcher=fetcher, figdir=figdir, bd=BindingDict(), mode="book")
        bl, _, _ = _essay_body_latex(ref, ch, extra_bd=extra_bd)
        vol_ctx.unattached.extend(ch.unattached)
        union_ctx.figures.extend(ch.figures)          # figures are global (manifest)
        for k, v in ch.references.items():            # refs stay in the volume's own bib
            vol_ctx.references.setdefault(k, v)
        return bl

    cover, front, flow, back, plates = _partition_entries(
        sb["entries"], fetcher=fetcher, figdir=figdir,
        render_chapter=_render_essay_chapter,
        render_subbook=lambda ref: _render_subbook(
            ref, fetcher=fetcher, figdir=figdir,
            parent_extra_bd=extra_bd, union_ctx=union_ctx, depth=depth + 1))

    out = []
    if cover:
        out.append(_cover_page_latex(cover))
    # A volume is a book: list it in the enclosing TOC by TITLE (at the
    # colegiovolume level, one notch ABOVE its inner \part), then let its OWN
    # parts/chapters/sections flow into that TOC too, so the anthology's Contents
    # shows the full nested hierarchy (xelatex builds it natively over two
    # passes). The TOC entry rides ON the frontispiece page so the link lands on
    # the volume's half-title.
    out.append(_volume_titlepage_latex(meta, toc_level="colegiovolume"))
    out.append("\\begingroup")
    # Set the running-header volume mark so every page of this volume
    # surfaces its title above the chapter mark — distinguishing
    # duplicate "Prologue / Introduction / Afterword" chapters across
    # the library's eight volumes. The mark is reset to empty on the
    # \endgroup below, so master-level pages outside any volume show
    # only the chapter mark.
    vol_title = meta.get("title") or ""
    if vol_title:
        out.append("\\volumemark{%s}" % latex_escape(vol_title))

    # A nested volume is its own book: restart chapter, plate AND part numbering
    # at 1, stashing the parent's counts in depth-keyed slots and restoring after.
    sfx = {1: "A", 2: "B", 3: "C"}.get(depth, "C")
    out.append("\\setcounter{colegiochapsave%s}{\\value{chapter}}\\setcounter{chapter}{0}"
               "\\setcounter{colegioplatesave%s}{\\value{plate}}\\setcounter{plate}{0}"
               "\\setcounter{colegiopartsave%s}{\\value{part}}\\setcounter{part}{0}"
               % (sfx, sfx, sfx))
    out += front
    out.append("\n\n".join(flow))
    out += back
    out += _plate_gallery_blocks(plates)               # the volume's plate gallery, at the end
    bib = _bibliography(vol_ctx.references)            # the volume's own References
    if bib:
        out.append(bib)
    out.append(_colophon(meta, vol_ctx, "0x09 book · bound volume"))
    out.append("\\setcounter{chapter}{\\value{colegiochapsave%s}}"
               "\\setcounter{plate}{\\value{colegioplatesave%s}}"
               "\\setcounter{part}{\\value{colegiopartsave%s}}" % (sfx, sfx, sfx))
    # Clear the volume mark so the outer book's pages don't keep showing
    # the nested volume's title.
    out.append("\\volumemark{}")
    out.append("\\endgroup")                           # restore TOC writing
    union_ctx.unattached.extend(vol_ctx.unattached)
    return "\n\n".join(out)


def book_to_tex(txid, *, fetcher=local_fetcher, figdir=None):
    """Render a 0x09 book quipu to a full colegio .tex — each essay entry
    becomes a chapter; binding-tagged entries tunnel into every essay."""
    figdir = figdir or os.path.join("/tmp", "colegio_figs")
    blob = fetcher(txid)
    header, body = split_blob(blob)
    parsed_book = read_book_quipu(header, body)

    # Book-level bindings tunnel into each essay (last-write-wins).
    extra_bd = BindingDict()
    for e in parsed_book["entries"]:
        if e["tag"].startswith("binding"):
            try:
                b = fetcher(e["ref_txid"])
                h2, bd2 = split_blob(b)
                from bindings import read_binding_quipu, evaluate as ev
                extra_bd.merge(ev(e["ref_txid"], fetcher))
            except Exception:
                pass

    meta = _meta_from_parsed(parsed_book, txid, 0x09)
    meta["jointxid"] = parsed_book["fields"].get("join", "")
    union_ctx = Ctx(fetcher=fetcher, figdir=figdir, bd=BindingDict(), mode="book")

    def _render_essay_chapter(ref, name):
        ch_ctx = Ctx(fetcher=fetcher, figdir=figdir, bd=BindingDict(), mode="book")
        body_latex, _, _ = _essay_body_latex(ref, ch_ctx, extra_bd=extra_bd)
        union_ctx.unattached.extend(ch_ctx.unattached)
        union_ctx.figures.extend(ch_ctx.figures)
        for k, v in ch_ctx.references.items():
            union_ctx.references.setdefault(k, v)
        return body_latex

    cover, front, flow, back, plates = _partition_entries(
        parsed_book["entries"], fetcher=fetcher, figdir=figdir,
        render_chapter=_render_essay_chapter,
        render_subbook=lambda ref: _render_subbook(
            ref, fetcher=fetcher, figdir=figdir,
            parent_extra_bd=extra_bd, union_ctx=union_ctx))

    body_blocks = []
    if cover:
        body_blocks.append(_cover_page_latex(cover))
    body_blocks += ["\\maketitle", "", "\\frontmatter", "\\tableofcontents", ""]
    body_blocks += front
    body_blocks += ["\\mainmatter", "", "\n\n".join(flow), "",
                    "\\backmatter", "\\printbacknotes", ""]
    body_blocks += back
    body_blocks += _plate_gallery_blocks(plates)       # plate gallery: after the text…
    body_blocks += ["", _bibliography(union_ctx.references), "",   # …before the References
                    _colophon(meta, union_ctx, "0x09 book")]

    parts = [
        _preamble("book", meta),
        _figure_manifest(union_ctx.figures), "",
        "\\begin{document}", "",
        *body_blocks,
        "\\end{document}", "",
    ]
    out = "\n".join(parts)
    # Pipeline-emitted Reference Index — replace any placeholder the
    # _partition_entries step left in place. The index walks the full
    # manifest tree from the root book; extra_refs picks up any inline
    # citations the structural walk missed.
    if _INDEX_PLACEHOLDER in out:
        rendered_index = _render_reference_index(
            txid, fetcher, extra_refs=union_ctx.references)
        out = out.replace(_INDEX_PLACEHOLDER, rendered_index)
    return out


# =====================================================================
#  Compile  (.tex + colegio.cls + figures → PDF)
# =====================================================================

def compile_tex(tex, build_dir, *, class_src=None, figdir=None,
                engine="xelatex", passes=2):
    """Write doc.tex + colegio.cls (+ figures/) into build_dir and compile.
    Returns the path to the produced PDF. `class_src` is the .cls source
    string; if None, the on-disk CLASS_PATH is copied."""
    import shutil
    os.makedirs(build_dir, exist_ok=True)
    with open(os.path.join(build_dir, "doc.tex"), "w", encoding="utf-8") as f:
        f.write(tex)
    cls_dst = os.path.join(build_dir, "colegio.cls")
    if class_src is not None:
        with open(cls_dst, "w", encoding="utf-8") as f:
            f.write(class_src)
    else:
        shutil.copyfile(CLASS_PATH, cls_dst)
    # figures
    fig_dst = os.path.join(build_dir, "figures")
    if figdir and os.path.isdir(figdir) and os.path.abspath(figdir) != os.path.abspath(fig_dst):
        os.makedirs(fig_dst, exist_ok=True)
        for fn in os.listdir(figdir):
            shutil.copyfile(os.path.join(figdir, fn), os.path.join(fig_dst, fn))
    last = None
    for _ in range(passes):
        last = subprocess.run(
            [engine, "-interaction=nonstopmode", "doc.tex"],
            cwd=build_dir, capture_output=True, timeout=180)
    pdf = os.path.join(build_dir, "doc.pdf")
    if not os.path.exists(pdf):
        log = (last.stdout or b"").decode("utf-8", "replace")[-2500:]
        raise RuntimeError("compile failed:\n" + log)
    return pdf


# =====================================================================
#  Round-trip: inscribe .tex / class as 0x5c quipus, then fetch + compile
#
#  Class delivery (per design): colegio.cls is inscribed once as its own
#  0x5c quipu; a document 0x5c carries `class=<class_txid>` and the reader
#  fetches + materialises the class at compile time. Figures are decoded
#  from the image/celestial quipus named in the document's %%QFIG manifest.
#
#  Inscriptions are stored locally (working/pipeline/inscriptions) under a
#  content-hash pseudo-txid; on chain the real join txid would address them.
# =====================================================================

import hashlib

INSCR_STORE = os.path.join(REPO, "working", "pipeline", "inscriptions")
_QFIG_RE = re.compile(r"%%QFIG ([0-9a-fA-F]{64})")


def pseudo_txid(header, body):
    return hashlib.sha256(bytes(header) + bytes(body)).hexdigest()


def write_inscription(header, body, store_dir=INSCR_STORE):
    """Persist a (header, body) inscription locally; return its pseudo-txid."""
    os.makedirs(store_dir, exist_ok=True)
    txid = pseudo_txid(header, body)
    with open(os.path.join(store_dir, f"{txid}.bin"), "wb") as f:
        f.write(bytes(header) + bytes(body))
    return txid


def chained_fetcher(*extra_dirs):
    """Fetcher that looks in extra dirs, then the inscription store, then the
    canonical dataset (data/bodies)."""
    dirs = list(extra_dirs) + [INSCR_STORE, BODIES]
    def fetch(txid):
        for d in dirs:
            p = os.path.join(d, f"{txid}.bin")
            if os.path.exists(p):
                with open(p, "rb") as f:
                    return f.read()
        raise FileNotFoundError(f"no local body for {txid}")
    return fetch


def inscribe_class(cls_path=CLASS_PATH, *, name="colegio.cls", tone=0xa1,
                   store_dir=INSCR_STORE):
    """Inscribe colegio.cls as its own 0x5c latex quipu. Returns
    (txid, header, body)."""
    with open(cls_path, encoding="utf-8") as f:
        src = f.read()
    header, body = build_latex_quipu(
        name, src, tone=tone,
        fields={"role": "class", "name": name, "engine": "xelatex"})
    return write_inscription(header, body, store_dir), header, body


def inscribe_tex(tex, title, *, class_txid=None, tone=0x00, fields=None,
                 store_dir=INSCR_STORE):
    """Inscribe a colegio .tex as a 0x5c latex quipu, carrying
    `class=<class_txid>` + `engine=xelatex`. Returns (txid, header, body)."""
    f = dict(fields or {})
    f.setdefault("engine", "xelatex")
    if class_txid:
        f["class"] = class_txid
    header, body = build_latex_quipu(title, tex, tone=tone, fields=f)
    return write_inscription(header, body, store_dir), header, body


def render_latex_quipu(txid, build_dir, *, fetcher=None):
    """Read a 0x5c latex quipu from chain and compile it to PDF.

    Resolves the `class=<txid>` field by fetching that class quipu and
    materialising colegio.cls; decodes every image/celestial quipu named
    in the document's %%QFIG manifest (or via \\imagequipu macros) into
    build_dir/figures. Returns the PDF path."""
    fetcher = fetcher or chained_fetcher()
    blob = fetcher(txid)
    if type_of(blob) != 0x5C:
        raise ValueError(f"{txid[:12]} is not a 0x5c latex quipu")
    header, body = split_blob(blob)
    parsed = read_latex_quipu(header, body)
    tex    = resolve_quiputikz(parsed["tex_source"], fetcher)   # LaTeX-by-pointer
    engine = parsed.get("engine", "xelatex")

    # Class delivery — fetch + materialise the referenced class quipu.
    class_src = None
    class_txid = parsed["fields"].get("class")
    if class_txid:
        ch, cb = split_blob(fetcher(class_txid))
        class_src = read_latex_quipu(ch, cb)["tex_source"]

    # Figure delivery — decode each referenced image/celestial quipu.
    figdir = os.path.join(build_dir, "figures")
    fig_txids = set(_QFIG_RE.findall(tex)) | set(_IMG_MACRO_TXID_RE.findall(tex))
    for ft in fig_txids:
        try:
            target_to_png(ft, fetcher, figdir)
        except Exception:
            pass

    return compile_tex(tex, build_dir, class_src=class_src,
                       figdir=figdir, engine=engine)


_IMG_MACRO_TXID_RE = re.compile(
    r"\\imagequipu(?:wide)?(?:\[[^\]]*\])?\{[^}]*\}\{([0-9a-fA-F]{64})\}")


# =====================================================================
#  Typeset edition as an optional part of book publication
#
#  A book MAY publish its intended typesetting by carrying a manifest
#  entry tagged `render/latex` pointing at a 0x5c document quipu (the
#  rendered .tex, which in turn carries class=<colegio.cls txid>).
#  Content readers ignore render/* entries; a LaTeX reader follows the
#  entry to compile the exact inscribed book. If a book has no such
#  entry, the typeset form is regenerated from content by the pipeline.
# =====================================================================

RENDER_TAG = "render/latex"


def build_typeset_edition(book_txid, *, fetcher=local_fetcher, figdir=None,
                          class_txid=None, store_dir=INSCR_STORE):
    """Produce a book's typeset edition as a 0x5c document quipu and return
    the manifest entry that publishes it.

    Inscribes colegio.cls as a class quipu (unless `class_txid` is supplied)
    and the rendered .tex as a doc quipu carrying class=<class_txid> + the
    %%QFIG figure manifest. Returns (entry, doc_txid, class_txid), where
    `entry` is the dict to append to the book's entries list before
    building the 0x09 book."""
    figdir = figdir or os.path.join("/tmp", "colegio_typeset_figs")
    if class_txid is None:
        class_txid, _, _ = inscribe_class(store_dir=store_dir)
    h, b = split_blob(fetcher(book_txid))
    title = read_book_quipu(h, b).get("title", "Book")
    tex = book_to_tex(book_txid, fetcher=fetcher, figdir=figdir)
    doc_txid, _, _ = inscribe_tex(tex, f"{title} — typeset edition",
                                  class_txid=class_txid, tone=0x00,
                                  store_dir=store_dir)
    entry = {"ref_txid": doc_txid, "tag": RENDER_TAG,
             "name": "Typeset edition (colegio)"}
    return entry, doc_txid, class_txid


def book_typeset_entry(parsed_book):
    """Return a book's typeset-edition entry (tag render/latex) or None."""
    for e in parsed_book["entries"]:
        if e["tag"] == RENDER_TAG or e["tag"].startswith("render/"):
            return e
    return None


def render_book(book_txid, build_dir, *, fetcher=None):
    """Render a 0x09 book to PDF. If the book publishes a typeset edition
    (a render/latex entry → 0x5c doc quipu), compile THAT exactly as
    inscribed — class and figures materialised from their quipus. Otherwise
    regenerate the .tex from content via the pipeline and compile."""
    fetcher = fetcher or chained_fetcher()
    h, b = split_blob(fetcher(book_txid))
    parsed = read_book_quipu(h, b)
    entry = book_typeset_entry(parsed)
    if entry:
        return render_latex_quipu(entry["ref_txid"], build_dir, fetcher=fetcher)
    # Fallback: regenerate from content, decoding figures from their quipus.
    figdir = os.path.join(build_dir, "figures")
    tex = book_to_tex(book_txid, fetcher=fetcher, figdir=figdir)
    for ft in set(_QFIG_RE.findall(tex)) | set(_IMG_MACRO_TXID_RE.findall(tex)):
        try:
            target_to_png(ft, fetcher, figdir)
        except Exception:
            pass
    return compile_tex(tex, build_dir, figdir=figdir)


# =====================================================================
#  Self-test
# =====================================================================

_SAMPLE = """# On Rendering

A paragraph with *emphasis*, **strength**, and `code`.

## A section

Cite a quipu as a link: <<DichtungWahrheit>>. Put a portrait in the
margin: <<03a08c378859100c7caad72b808cc46874b026673bc3c04831282fe56690357b render="margin" caption="A portrait">>.
And a full-width plate: <<03a08c378859100c7caad72b808cc46874b026673bc3c04831282fe56690357b render="full">>.

> A blockquote line.
> Second line.

- one
- two

| letra | valor |
|:------|------:|
| alef  | 1     |
| bet   | 2     |
"""


def _selftest():
    bd = BindingDict(aliases={
        "DichtungWahrheit":
            "a4bb23790cc0bbcbcf7436a379c687d52c45e10904e769a08d4df71fd54bd8ae"})
    ctx = Ctx(fetcher=local_fetcher, figdir="/tmp/colegio_pipeline_test_figs",
              bd=bd, mode="essay")
    latex = convert_markdown(_SAMPLE, ctx)
    print(latex)
    assert "\\section{On Rendering}" in latex      # essay-mode H1 → section
    assert "\\subsection{A section}" in latex       # essay-mode H2 → subsection
    assert "\\emph{emphasis}" in latex and "\\textbf{strength}" in latex
    assert "\\quipucite[" in latex                 # link form
    assert "\\imagequipu{" in latex                # margin form
    assert "\\imagequipuwide[" in latex            # full form
    assert "\\begin{tabular}" in latex
    print("\n[selftest] convert_markdown OK")


if __name__ == "__main__":
    _selftest()
