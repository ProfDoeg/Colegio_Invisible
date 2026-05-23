"""Build HTML and LaTeX versions of El Libro del Gólem from local sources.

Inputs:
  forward.md, tone.md, mythology.md, diamonds.md, weaving.md, multisig.md
                  — six El Gólem essays (markdown source)
  commentary.ab   — substitution + citation rules applied during render
  cover.png       — title-page image
  art/0{1..4}_*.png  — four full-page TikZ artworks
  data/bodies/84fbbb17….bin  — Goethe essay (already on chain)
  data/bodies/d442073b….bin  — Cementerio v1 essay (already on chain)

Outputs (under working/golem/built/):
  book.html      — self-contained HTML with embedded images
  book.tex       — LaTeX source
  book.pdf       — compiled via xelatex

The book's substitutions and citation chains live in commentary.ab.
They are applied to every essay's body (mine AND El Ermitaño's) before
rendering, exactly as the on-chain renderer would tunnel them when the
meta-book is opened.
"""
import base64
import os
import re
import subprocess
import sys
from pathlib import Path

THIS = Path(__file__).parent
REPO = THIS.parent.parent
sys.path.insert(0, str(REPO / "canonical"))

from bindings import parse_body as parse_binding_body
from essay    import read_essay_quipu
from image    import read_image_quipu

# ---------------------------------------------------------------------------
# Image decoder — produces a PIL Image from any 0x03 image quipu's raw bytes
# ---------------------------------------------------------------------------
def decode_image_to_pil(blob: bytes):
    """Return (PIL.Image, dims_dict, title). Returns (None, {}, '') on failure."""
    import io
    try:
        import numpy as np
        from PIL import Image
    except ImportError:
        return None, {}, ""
    if len(blob) < 12 or blob[4] != 0x03:
        return None, {}, ""
    color     = blob[6]
    W         = (blob[7] << 8) | blob[8]
    H         = (blob[9] << 8) | blob[10]
    bd        = blob[11]
    channels  = {0: 1, 1: 3, 2: 2, 3: 4}.get(color, 1)
    expected_body = (W * H * channels * bd + 7) // 8
    body_offset = len(blob) - expected_body
    if body_offset < 12:
        return None, {}, ""
    # Title from header tail
    tail = blob[12:body_offset]
    title = ""
    if tail:
        text = tail.decode("utf-8", errors="replace")
        if "|" in text:
            parts = [p.strip() for p in text.split("|") if p.strip()]
            title = parts[0] if parts else ""
        else:
            cut = text.find('�')
            title = (text[:cut] if cut >= 0 else text).strip()
    body = blob[body_offset:body_offset + expected_body]
    # Unpack bits
    bits = []
    for byte in body:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    n_vals = W * H * channels
    vals = []
    for i in range(n_vals):
        v = 0
        for j in range(bd):
            idx = i * bd + j
            v = (v << 1) | (bits[idx] if idx < len(bits) else 0)
        vals.append(v)
    max_val = max((1 << bd) - 1, 1)
    arr = (np.array(vals, dtype=np.uint64) * 255 // max_val).astype(np.uint8)
    if channels == 1:
        img = Image.fromarray(arr.reshape((H, W)), mode="L")
    elif channels == 3:
        img = Image.fromarray(arr.reshape((H, W, 3)), mode="RGB")
    elif channels == 4:
        img = Image.fromarray(arr.reshape((H, W, 4)), mode="RGBA")
    else:
        return None, {}, ""
    return img, {"W": W, "H": H, "bit_depth": bd, "color": color}, title


def pil_to_b64(img, fmt="PNG"):
    import io, base64 as _b64
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return _b64.b64encode(buf.getvalue()).decode("ascii")

OUT  = THIS / "built"
OUT.mkdir(exist_ok=True)

ESSAYS = [
    ("forward.md",   "The Glossator's Forward",        "forward"),
    ("tone.md",      "On the Tone Byte",               "essay/01"),
    ("mythology.md", "On Mythology and Identity",      "essay/02"),
    ("diamonds.md",  "On Diamonds and Capital",        "essay/03"),
    ("weaving.md",   "On Weaving",                     "essay/04"),
    ("multisig.md",  "On the Multisig and the AI",     "essay/05"),
]

# El Ermitaño's essays included via the book's tag=essay/06 + essay/07
# entries. These are read from the local body files (data/bodies/{txid}.bin)
# rather than from a markdown source. Each tuple:
#   (root_txid, fallback_title, tag, transclude_from_txid_or_None)
#
# transclude: when the inscribed essay is a "thin republish via binding"
# (e.g. Cementerio v2 = binding-import + single citation to v1), the
# actual prose to render lives in the cited v1 essay, with the binding's
# rules applied as overlay. The viewer does this automatically; here we
# do it explicitly with the transclude_from_txid field.
EMBEDDED_ESSAYS = [
    ("84fbbb17718523edf373630e68239fa9abda85297ba2aca8a69ace04f0ad5fb5",
     "El yiddish del joven Goethe",
     "essay/06",
     None),
    ("449e67f4a2e948f044e1a32662b58ccedad3cf8e85a742cc45b6b6541e47b5d7",
     "Cementerio de los Animales",
     "essay/07",
     "d442073b33f2a4d04292853abb39e171ae593fcc288a1e4fc2518d5d7a7e5985"),
]


def _split_essay_header_body(blob: bytes) -> tuple:
    """Find the byte boundary between an essay's pipe-delimited header
    tail and its markdown body. Same algorithm as
    quipu_viewer.find_body_offset: walk pipe segments forward; the first
    segment containing a newline means the body has started — that
    pipe is body content, not header."""
    if len(blob) < 6 or blob[4] != 0x01:
        raise ValueError(f"not an essay (type 0x{blob[4]:02x})")
    if len(blob) <= 6 or blob[6:7] != b"|":
        return blob[:6], blob[6:]
    pos = 7
    hdr_end = 7
    while pos < len(blob):
        close = blob.find(b"|", pos)
        if close < 0:
            break
        segment = blob[pos:close]
        if b"\n" in segment:
            # body markdown has started; `close` is a pipe inside the body
            break
        hdr_end = close + 1
        pos = close + 1
        if pos - 6 > 2048:  # sanity bound
            break
    return blob[:hdr_end], blob[hdr_end:]


def load_embedded_essay(txid: str, transclude_from: str = None) -> str:
    """Load an essay's markdown body from data/bodies/{txid}.bin.
    If transclude_from is set, the loaded essay's body is treated as a
    thin republish and the transclude target's body is returned instead
    (with the original's binding imports kept as a leading comment for
    provenance)."""
    bin_path = REPO / "data" / "bodies" / f"{txid}.bin"
    blob = bin_path.read_bytes()
    _, body_bytes = _split_essay_header_body(blob)
    body = body_bytes.decode("utf-8", errors="replace").lstrip("\n")
    if transclude_from:
        target_path = REPO / "data" / "bodies" / f"{transclude_from}.bin"
        if target_path.exists():
            target_blob = target_path.read_bytes()
            _, target_body_bytes = _split_essay_header_body(target_blob)
            body = target_body_bytes.decode("utf-8", errors="replace").lstrip("\n")
    return body

ART = [
    ("art/01_cord.png",    "Composition I — Cord"),
    ("art/02_diamond.png", "Composition II — Diamond"),
    ("art/03_page.png",    "Composition III — Page"),
    ("art/04_tone.png",    "Composition IV — Tone"),
]

COVER_PNG = THIS / "cover.png"


# ---------------------------------------------------------------------------
# Load binding rules
# ---------------------------------------------------------------------------
def load_binding(path):
    """Return (substitutions, citations) parsed from a 0xab binding file."""
    substitutions = []
    citations     = []
    for line in parse_binding_body(path.read_text(encoding="utf-8")):
        kind = line[0]
        if kind == "substitution":
            substitutions.append((line[1], line[2]))
        elif kind == "citation":
            citations.append((tuple(line[1]), line[2], frozenset(line[3])))
    return substitutions, citations


def apply_subs(text, substitutions):
    for find, replace in sorted(substitutions, key=lambda p: -len(p[0])):
        text = text.replace(find, replace)
    return text


# ---------------------------------------------------------------------------
# HTML output
# ---------------------------------------------------------------------------
_IMAGE_CACHE = {}
def _resolve_quipu_image_src(txid: str) -> str:
    """Return a data:image/png;base64,... URL for an inscribed 0x03 image
    quipu, or empty string if not found / not an image. Cached."""
    if txid in _IMAGE_CACHE:
        return _IMAGE_CACHE[txid]
    p = REPO / "data" / "bodies" / f"{txid}.bin"
    if not p.exists():
        _IMAGE_CACHE[txid] = ""
        return ""
    blob = p.read_bytes()
    if len(blob) < 12 or blob[4] != 0x03:
        _IMAGE_CACHE[txid] = ""
        return ""
    img, dims, title = decode_image_to_pil(blob)
    if img is None:
        _IMAGE_CACHE[txid] = ""
        return ""
    url = f"data:image/png;base64,{pil_to_b64(img)}"
    _IMAGE_CACHE[txid] = url
    return url


def rewrite_quipu_img_srcs(html: str) -> str:
    """Replace src="quipu:TXID" on <img> tags with inline data: URLs for
    inscribed image quipus. Mirrors the on-chain viewer's behavior. Links
    of the form [text](quipu:TXID) are NOT touched — only explicit
    <img src="quipu:TXID"> (typically inside a <figure>) becomes inline."""
    def repl(m):
        txid = m.group(1).lower()
        data_url = _resolve_quipu_image_src(txid)
        if not data_url:
            return m.group(0)
        return f'src="{data_url}"'
    return re.sub(r'src="quipu:([0-9a-fA-F]{64})"', repl, html)


def render_html(substitutions, citations):
    import markdown as md

    # Citation rules → markdown anchor wrappers applied to first occurrence per
    # block. We use the same default semantics as canonical/bindings.apply_citations.
    trigger_to_target = {}
    for triggers, target, _flags in citations:
        for t in triggers:
            trigger_to_target[t] = target
    cite_re = re.compile(
        r"\b(" + "|".join(re.escape(t)
                           for t in sorted(trigger_to_target.keys(),
                                            key=len, reverse=True)) + r")\b"
    ) if trigger_to_target else None

    def apply_citations_block(html_block, block_seen):
        if cite_re is None:
            return html_block
        def repl(m):
            matched = m.group(1)
            if matched in block_seen:
                return matched
            block_seen.add(matched)
            tgt = trigger_to_target[matched]
            return f'<a href="quipu:{tgt}" class="cite">{matched}</a>'
        # Only operate outside existing <a>, <code>, <pre>, attribute values.
        # Cheap heuristic: skip stretches inside angle brackets.
        out, pos = [], 0
        for tag in re.finditer(r"<[^>]+>", html_block):
            seg = html_block[pos:tag.start()]
            out.append(cite_re.sub(repl, seg))
            out.append(tag.group(0))
            pos = tag.end()
        out.append(cite_re.sub(repl, html_block[pos:]))
        return "".join(out)

    cover_b64 = base64.b64encode(COVER_PNG.read_bytes()).decode()
    art_b64 = [(base64.b64encode((THIS / p).read_bytes()).decode(), caption)
               for p, caption in ART]

    body_parts = []

    # Cover (title page)
    body_parts.append(
        '<section class="cover">'
        f'<img src="data:image/png;base64,{cover_b64}" alt="El Libro del Gólem cover" />'
        '</section>'
    )

    # TOC — six Gólem essays + the two embedded Ermitaño essays + artworks
    toc_items = []
    for _path, title, tag in ESSAYS:
        toc_items.append(
            f'<li><a href="#{tag.replace("/", "-")}">{title}</a> '
            f'<span class="toc-tag">{tag}</span></li>'
        )
    toc_items.append('<li class="toc-section">From the apocryphal corpus</li>')
    for txid, title, tag, _ in EMBEDDED_ESSAYS:
        toc_items.append(
            f'<li><a href="#{tag.replace("/", "-")}">{title}</a> '
            f'<span class="toc-tag">{tag}</span></li>'
        )
    toc_items.append(
        '<li><a href="#artworks">Four Compositions</a> '
        '<span class="toc-tag">art/01–04</span></li>'
    )
    body_parts.append(
        '<nav class="toc"><h2>Contents</h2>'
        f'<ol>{"".join(toc_items)}</ol></nav>'
    )

    def render_essay_html_block(src_md, title, tag, kicker=None):
        """Apply substitutions, strip first heading, render md→html, apply citations.

        Honors the essay's OWN fenced ```binding``` blocks (e.g. aliases
        defined inline at the top of the essay), so <<AliasName>>
        references resolve to their declared txids. This matches the
        on-chain renderer's behavior."""
        src = src_md

        # 1. Extract any ```binding``` fenced blocks from the essay body and
        # parse them to harvest LOCAL aliases (alias → txid maps declared
        # inline by the essay). Remove the blocks from the rendered output.
        local_aliases = {}      # name -> target_txid_hex
        def _capture_binding(m):
            for line in parse_binding_body(m.group(1)):
                if line[0] == "alias":
                    names, target = line[1], line[2]
                    if re.fullmatch(r"[0-9a-fA-F]{64}", target):
                        for n in names:
                            local_aliases[n] = target.lower()
                # Could also pick up substitution + citation rules here; for
                # now we trust the meta-book's overlay for those.
            return ""
        src = re.sub(r"^[ \t]*```binding[ \t]*\n(.*?)\n[ \t]*```[ \t]*$",
                     _capture_binding, src,
                     flags=re.MULTILINE | re.DOTALL)

        # 2. Resolve <<AliasName>> and <<AliasName title="…">> in the body
        # (uses local aliases). The title= attribute, if present, becomes
        # the anchor text used in the rendered link.
        def _resolve_alias(m):
            name  = m.group(1).strip()
            attrs = m.group(2) or ""
            if name not in local_aliases:
                return m.group(0)
            txid = local_aliases[name]
            t = re.search(r'title\s*=\s*"([^"]*)"', attrs)
            if t:
                # Pre-render as a markdown link so the title attribute survives
                # citation post-processing.
                return f"[{t.group(1)}](quipu:{txid})"
            # Bare alias → standardize to <<txid>> for later processing
            return f"<<{txid}>>"
        src = re.sub(
            r"<<\s*([A-Za-z_][A-Za-z0-9_]*)((?:\s+[^>]*)?)\s*>>",
            _resolve_alias, src,
        )

        # 3. Apply meta-book level substitutions (hebreo→yiddish, dogechain→quipu)
        src = apply_subs(src, substitutions)

        # 4. Strip the first heading line; we'll use our own <h1>
        lines = src.split("\n")
        if lines and lines[0].startswith("# "):
            lines = lines[1:]
        body_md = "\n".join(lines).strip()

        # 5. Resolve `![alt](<<TXID>>)` markdown image embeds → `![alt](quipu:TXID)`
        # so the downstream <img src="quipu:..."> rewriter can inline them.
        body_md = re.sub(
            r"\]\(<<\s*([0-9a-fA-F]{64})\s*>>\)",
            lambda m: f"](quipu:{m.group(1).lower()})",
            body_md,
        )
        # Also resolve `[text](<<TXID>>)` link form similarly.
        # (Already covered by the same pattern above.)

        # 6. Convert any remaining standalone <<txid>> citations into
        # bracketed quipu: links so markdown keeps them as text.
        body_md = re.sub(
            r"<<\s*([0-9a-fA-F]{64})\s*>>",
            lambda m: f"[`{m.group(1)[:12]}…`](quipu:{m.group(1).lower()})",
            body_md,
        )
        html = md.markdown(body_md, extensions=["extra", "sane_lists"])

        # 7. Resolve `<img src="quipu:TXID">` to inline base64 PNGs
        # (covers both raw <figure><img> blocks in the prose AND ![alt](quipu:TXID)
        # markdown image syntax which markdown converts to <img src="quipu:TXID">).
        html = rewrite_quipu_img_srcs(html)

        # Apply v2 citations per block
        blocks = re.split(r"(</p>|</blockquote>|</li>|</h\d>)", html)
        processed = []
        for i in range(0, len(blocks), 2):
            block_seen = set()
            chunk = apply_citations_block(blocks[i], block_seen)
            processed.append(chunk)
            if i + 1 < len(blocks):
                processed.append(blocks[i + 1])
        html = "".join(processed)
        anchor = tag.replace("/", "-")
        kicker_html = (
            f'<p class="kicker">{kicker}</p>' if kicker else ""
        )
        return (
            f'<article class="essay" id="{anchor}">'
            f'<header class="essay-head">'
            f'<div class="tag">{tag}</div>'
            f'<h1>{title}</h1>'
            f'{kicker_html}'
            f'</header>'
            f'{html}'
            f'</article>'
        )

    # El Gólem's six essays
    for path, title, tag in ESSAYS:
        src = (THIS / path).read_text(encoding="utf-8")
        body_parts.append(render_essay_html_block(src, title, tag))

    # El Ermitaño's two essays embedded as essay/06 and essay/07
    body_parts.append(
        '<section class="ermitano-divider">'
        '<h2>From the apocryphal corpus</h2>'
        '<p class="lead">The two essays of <em>Dos ensayos</em> by El Ermitaño, '
        'embedded here through the meta-book and rendered with the commentary '
        "binding's overlay applied: the Goethe essay's historical title is "
        'corrected on render; the Cementerio essay\'s external '
        'block-explorer URLs are rewritten to <code>quipu:</code> references.</p>'
        '</section>'
    )
    for txid, fallback_title, tag, transclude_from in EMBEDDED_ESSAYS:
        src = load_embedded_essay(txid, transclude_from=transclude_from)
        # The fallback_title is what the book entry names this essay AFTER
        # corrections (e.g. "El yiddish del joven Goethe" not "hebreo")
        kicker = (
            f'Inscribed by El Ermitaño at <code>quipu:{txid[:16]}…</code>. '
            f'Rendered through <em>El Libro del Gólem</em>\'s binding overlay.'
        )
        body_parts.append(render_essay_html_block(
            src, fallback_title, tag, kicker=kicker,
        ))

    # Four compositions
    body_parts.append('<section class="artworks" id="artworks">'
                      '<h1>Four Compositions</h1>')
    for src_b64, caption in art_b64:
        body_parts.append(
            f'<figure class="art">'
            f'<img src="data:image/png;base64,{src_b64}" alt="{caption}" />'
            f'<figcaption>{caption}</figcaption>'
            f'</figure>'
        )
    body_parts.append('</section>')

    # Colophon
    body_parts.append(
        '<section class="colophon">'
        '<h2>Colophon</h2>'
        '<p>El Libro del Gólem, by El Gólem. Inscribed 2026-05-23 from '
        'the <code>multiman</code> 2-of-2 multisig at '
        '<code>A3ShjwjsAE4ysM66EZJM3A28tPnL2jNDgC</code>, '
        'Dogecoin block 6,218,023. Book root txid '
        '<code>7b19fb2bf42e8882ae7bc71ef0f4095f2b2982885728b761101d96efdb338811</code>. '
        '13 quipus, 63 strands, 1102 multisig-signed knot transactions. '
        'This HTML rendering was generated from the same source bodies '
        'that were inscribed; the binding’s substitutions and citation '
        'chains have been applied here as the on-chain renderer would '
        'tunnel them.</p>'
        '</section>'
    )

    css = r"""
    @import url('https://fonts.googleapis.com/css2?family=Crimson+Pro:ital,wght@0,400;0,600;1,400&family=JetBrains+Mono:wght@400;600&display=swap');
    html { font-size: 16px; }
    body {
      font: 16px/1.65 'Crimson Pro', 'Iowan Old Style', Palatino, Georgia, serif;
      color: #1a1a1a;
      background: #faf6ec;
      max-width: 720px;
      margin: 0 auto;
      padding: 2.5rem 1.5rem 4rem;
    }
    .cover { text-align: center; margin: -1rem 0 3rem; padding-top: 1rem; }
    .cover img { max-width: 100%; height: auto;
                 box-shadow: 0 2px 18px rgba(0,0,0,0.15);
                 border: 1px solid #c2a76b; }
    .toc { margin: 0 0 4rem; padding: 1.5rem 2rem;
            background: #f4ead8; border-left: 3px solid #c2a76b; }
    .toc h2 { margin: 0 0 0.6rem; font-size: 1.1rem; letter-spacing: 0.04em;
              text-transform: uppercase; color: #555; font-weight: 600; }
    .toc ol { margin: 0; padding-left: 1.5rem; font-size: 0.95rem; }
    .toc li { padding: 0.15rem 0; }
    .toc a { color: #1a1a1a; text-decoration: none; }
    .toc a:hover { text-decoration: underline; }
    .essay { margin: 4rem 0; }
    .essay-head { margin: 0 0 2rem; padding-bottom: 1rem;
                   border-bottom: 1px solid #d4c9a8; }
    .tag { font: 600 0.7rem/1 'JetBrains Mono', monospace;
           letter-spacing: 0.12em; color: #888; text-transform: uppercase;
           margin-bottom: 0.4rem; }
    h1 { font-size: 1.8rem; line-height: 1.2; margin: 0;
         font-weight: 600; letter-spacing: -0.01em; }
    .essay p { margin: 0 0 1.1rem; text-align: justify; hyphens: auto; }
    .essay p:first-of-type::first-line {
      font-variant: small-caps; letter-spacing: 0.04em;
    }
    em { font-style: italic; }
    strong { font-weight: 600; }
    code { font: 0.86em/1 'JetBrains Mono', monospace;
           background: rgba(194,167,107,0.16); padding: 0.05em 0.32em;
           border-radius: 3px; word-break: break-all; }
    .cite { color: #8a4a3a; text-decoration: underline dotted #c2a76b;
            text-underline-offset: 3px; }
    .artworks { margin: 6rem 0 4rem; }
    .artworks > h1 { text-align: center; margin-bottom: 2.5rem;
                     border-bottom: 1px solid #c2a76b; padding-bottom: 1rem; }
    .art { margin: 0 0 3rem; text-align: center; }
    .art img { max-width: 100%; height: auto; border: 1px solid #d4c9a8; }
    .art figcaption { font: italic 0.95rem/1.4 'Crimson Pro', serif;
                       color: #555; margin-top: 0.6rem; }
    .colophon { margin-top: 5rem; padding-top: 2rem;
                 border-top: 1px solid #c2a76b;
                 font-size: 0.85rem; color: #555; }
    .colophon h2 { font-size: 0.9rem; letter-spacing: 0.1em;
                    text-transform: uppercase; color: #888; font-weight: 600;
                    margin: 0 0 0.6rem; }
    .colophon code { font-size: 0.78em; }

    .toc-tag { float: right; font: 0.7rem/1.3 'JetBrains Mono', monospace;
               color: #888; padding-top: 0.15rem; }
    .toc-section { list-style: none; margin-left: -1.5rem;
                   margin-top: 0.8rem; padding-top: 0.6rem;
                   border-top: 1px dashed #c2a76b;
                   font: italic 0.85rem/1.3 'Crimson Pro', serif;
                   color: #555; }
    .kicker { font: italic 0.88rem/1.5 'Crimson Pro', serif;
              color: #555; margin: 0.6rem 0 1.2rem;
              padding: 0.4rem 0.6rem; border-left: 2px solid #c2a76b;
              background: rgba(194,167,107,0.08); }
    .kicker code { font-size: 0.85em; }
    .ermitano-divider { margin: 5rem 0 3rem; padding: 1.8rem 2rem;
                        background: #f4ead8;
                        border-top: 2px solid #c2a76b;
                        border-bottom: 2px solid #c2a76b;
                        text-align: center; }
    .ermitano-divider h2 { margin: 0 0 0.6rem; font-size: 1.4rem;
                            font-weight: 400; font-style: italic;
                            letter-spacing: 0.02em; }
    .ermitano-divider .lead { font-size: 0.95rem; color: #555;
                               max-width: 540px; margin: 0 auto; }

    /* Inline figures embedded inside essay prose (e.g. document scans).
       Mirrors the on-chain viewer: <img src="quipu:TXID"> becomes a
       base64 PNG; we just provide reasonable typography around it. */
    figure.document-scan, .essay figure {
      margin: 1.8rem auto;
      text-align: center;
      max-width: 100%;
    }
    figure.document-scan img, .essay figure img {
      max-width: 100%;
      max-height: 460px;
      width: auto;
      height: auto;
      image-rendering: pixelated;
      border: 1px solid #c9bb95;
      background: #fff;
      padding: 4px;
    }
    figure.document-scan figcaption, .essay figure figcaption {
      font: italic 0.82rem/1.4 'Crimson Pro', serif;
      color: #555;
      margin-top: 0.6rem;
      max-width: 520px;
      margin-left: auto;
      margin-right: auto;
      text-align: center;
    }

    """

    html_full = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<meta name="author" content="El Gólem" />
<title>El Libro del Gólem</title>
<style>{css}</style>
</head>
<body>
{''.join(body_parts)}
</body>
</html>
"""
    (OUT / "book.html").write_text(html_full, encoding="utf-8")
    print(f"  wrote {OUT / 'book.html'} ({len(html_full):,} bytes)")


# ---------------------------------------------------------------------------
# LaTeX output (minimal markdown→LaTeX for the prose subset used here)
# ---------------------------------------------------------------------------
def md_to_latex(text):
    # Escape LaTeX specials first (order matters)
    out = []
    in_code_block = False
    for raw_line in text.split("\n"):
        if raw_line.strip().startswith("```"):
            in_code_block = not in_code_block
            out.append("\\begin{verbatim}" if in_code_block else "\\end{verbatim}")
            continue
        if in_code_block:
            out.append(raw_line)
            continue
        line = raw_line

        # Heading
        if line.startswith("# "):
            # Skip — we use the essay title separately
            continue
        if line.startswith("## "):
            heading = _esc(line[3:].strip())
            out.append(f"\\section*{{{heading}}}")
            continue
        if line.startswith("### "):
            heading = _esc(line[4:].strip())
            out.append(f"\\subsection*{{{heading}}}")
            continue

        # Inline code first (so we don't escape its contents)
        pieces = re.split(r"(`[^`]+`)", line)
        rendered_pieces = []
        for p in pieces:
            if p.startswith("`") and p.endswith("`") and len(p) >= 2:
                rendered_pieces.append(f"\\texttt{{{_esc(p[1:-1])}}}")
            else:
                # Escape, then handle bold/italic
                e = _esc(p)
                # **bold** (greedy non-newline)
                e = re.sub(r"\*\*([^*]+)\*\*", r"\\textbf{\1}", e)
                # *italic* (single)
                e = re.sub(r"(?<![\\*])\*([^*\n]+)\*", r"\\emph{\1}", e)
                rendered_pieces.append(e)
        out.append("".join(rendered_pieces))

    return "\n".join(out)


def _esc(s):
    """Escape LaTeX special characters in a plain text fragment."""
    # Order matters: handle \ first
    s = s.replace("\\", "\\textbackslash{}")
    repl = {
        "&": "\\&", "%": "\\%", "$": "\\$", "#": "\\#",
        "_": "\\_", "{": "\\{", "}": "\\}",
        "~": "\\~{}", "^": "\\^{}",
    }
    for k, v in repl.items():
        s = s.replace(k, v)
    return s


def render_latex(substitutions):
    def _make_chapter(src, title, tag, kicker=None):
        src = apply_subs(src, substitutions)
        # strip fenced binding blocks (engine artifacts, not for reading)
        src = re.sub(r"^[ \t]*```binding[ \t]*\n.*?\n[ \t]*```[ \t]*$",
                     "", src, flags=re.MULTILINE | re.DOTALL)
        # collapse standalone <<txid>> into a typewriter citation
        src = re.sub(
            r"<<\s*([0-9a-fA-F]{64})\s*>>",
            lambda m: f"`{m.group(1)[:12]}…`",
            src,
        )
        body = md_to_latex(src)
        kicker_block = ""
        if kicker:
            kicker_block = (
                f"\\noindent\\itshape\\small\\textcolor{{soft}}{{{kicker}}}"
                f"\\normalfont\\par\\vspace{{0.8em}}\n"
            )
        return (
            f"\\chapter*{{{_esc(title)}}}\n"
            f"\\addcontentsline{{toc}}{{chapter}}{{{_esc(title)}}}\n"
            f"\\markboth{{{_esc(title)}}}{{{_esc(tag)}}}\n"
            f"\\noindent\\textcolor{{soft}}{{\\small\\texttt{{{_esc(tag)}}}}}\\par\\vspace{{0.5em}}\n"
            f"{kicker_block}"
            f"{body}\n"
        )

    chapters = []
    for path, title, tag in ESSAYS:
        src = (THIS / path).read_text(encoding="utf-8")
        chapters.append(_make_chapter(src, title, tag))

    # Divider page before El Ermitaño's essays
    chapters.append(
        "\\clearpage\n"
        "\\thispagestyle{empty}\n"
        "\\null\\vfill\n"
        "\\begin{center}\n"
        "{\\Large\\itshape From the apocryphal corpus}\\\\[1.5em]\n"
        "\\begin{minipage}{0.75\\textwidth}\\centering\\small\\itshape\n"
        "The two essays of \\emph{Dos ensayos} by El Ermita\\~no, "
        "embedded here through the meta-book and rendered with the commentary "
        "binding's overlay applied: the Goethe essay's historical title is "
        "corrected on render; the Cementerio essay's external block-explorer "
        "URLs are rewritten to \\texttt{quipu:} references.\n"
        "\\end{minipage}\n"
        "\\end{center}\n"
        "\\vfill\\null\n"
        "\\clearpage\n"
    )

    for txid, title, tag, transclude_from in EMBEDDED_ESSAYS:
        src = load_embedded_essay(txid, transclude_from=transclude_from)
        kicker = (
            f"Inscribed by El Ermita\\~no at \\texttt{{quipu:{txid[:16]}\\ldots}}. "
            f"Rendered through \\emph{{El Libro del G\\'olem}}'s binding overlay."
        )
        chapters.append(_make_chapter(src, title, tag, kicker=kicker))

    art_includes = "\n".join(
        f"\\begin{{figure}}[p]\n"
        f"  \\centering\n"
        f"  \\includegraphics[width=0.92\\textwidth,keepaspectratio]{{{(THIS / p).resolve()}}}\n"
        f"  \\caption*{{\\itshape {caption}}}\n"
        f"\\end{{figure}}"
        for p, caption in ART
    )

    cover_path = COVER_PNG.with_suffix(".pdf").resolve()
    if not cover_path.exists():
        cover_path = COVER_PNG.resolve()  # fallback to png

    tex = r"""\documentclass[11pt,openany]{book}
% xelatex — native UTF-8, no inputenc/fontenc needed
\usepackage{fontspec}
\setmainfont{Hoefler Text}
\setmonofont{Menlo}[Scale=0.86]
\usepackage[a5paper,margin=20mm]{geometry}
\usepackage{xcolor}
\usepackage{microtype}
\usepackage{graphicx}
\usepackage{caption}
\usepackage{titlesec}
\usepackage{fancyhdr}
\usepackage{hyperref}

\definecolor{ink}{HTML}{1a1a1a}
\definecolor{soft}{HTML}{555555}
\definecolor{rule}{HTML}{c2a76b}
\definecolor{wash}{HTML}{faf6ec}

\hypersetup{
  colorlinks=true, linkcolor=ink, urlcolor=ink, citecolor=ink,
  pdftitle={El Libro del G\'olem},
  pdfauthor={El G\'olem},
}

\pagecolor{wash}
\color{ink}

\titleformat{\chapter}[display]
  {\normalfont\Huge\bfseries}
  {}
  {0pt}
  {\Huge}

\pagestyle{fancy}
\fancyhf{}
\fancyhead[LE,RO]{\small\itshape\leftmark}
\fancyhead[LO,RE]{\small\rmfamily El Libro del G\'olem}
\renewcommand{\headrulewidth}{0pt}

\begin{document}

\frontmatter
\thispagestyle{empty}
\begin{titlepage}
\centering
\null\vfill
\includegraphics[width=\textwidth,keepaspectratio]{""" + str(cover_path) + r"""}
\vfill
\null
\end{titlepage}

\tableofcontents
\clearpage

\mainmatter

""" + "\n\\clearpage\n".join(chapters) + r"""

\clearpage
\chapter*{Four Compositions}
\addcontentsline{toc}{chapter}{Four Compositions}
\markboth{Four Compositions}{}

""" + art_includes + r"""

\clearpage
\chapter*{Colophon}
\addcontentsline{toc}{chapter}{Colophon}
\markboth{Colophon}{}

\noindent
\textit{El Libro del G\'olem}, by El G\'olem. Inscribed 2026-05-23 from
the \texttt{multiman} 2-of-2 multisig at
\texttt{A3ShjwjsAE4ysM66EZJM3A28tPnL2jNDgC}, Dogecoin block 6{,}218{,}023.
Book root txid:

\smallskip
\noindent\small\texttt{7b19fb2bf42e8882ae7bc71ef0f4095f}\\
\noindent\texttt{2b2982885728b761101d96efdb338811}

\medskip
\noindent\normalsize
13 quipus, 63 strands, 1102 multisig-signed knot transactions, 56.10 DOGE total
inscription cost. This printed rendering was generated from the same source
bodies that were inscribed; the binding's substitutions and citation chains
were applied as the on-chain renderer would tunnel them.

\end{document}
"""
    tex_path = OUT / "book.tex"
    tex_path.write_text(tex, encoding="utf-8")
    print(f"  wrote {tex_path} ({len(tex):,} bytes)")

    # Compile with xelatex (Unicode-native; no inputenc surprises)
    for pass_n in (1, 2):  # two passes for TOC
        proc = subprocess.run(
            ["xelatex", "-interaction=nonstopmode", "-halt-on-error",
             "-output-directory", str(OUT), str(tex_path)],
            capture_output=True, cwd=OUT,
        )
        if proc.returncode != 0:
            print(f"  *** pdflatex pass {pass_n} failed (returncode {proc.returncode}):")
            tail = proc.stdout.decode("utf-8", errors="replace").split("\n")[-40:]
            print("\n".join("    " + l for l in tail))
            return
    pdf_path = OUT / "book.pdf"
    if pdf_path.exists():
        print(f"  wrote {pdf_path} ({pdf_path.stat().st_size:,} bytes)")
    else:
        print("  *** no PDF produced")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--html-only", action="store_true",
                    help="skip LaTeX/PDF rendering (faster iteration)")
    args = p.parse_args()

    substitutions, citations = load_binding(THIS / "commentary.ab")
    print(f"binding: {len(substitutions)} substitutions, {len(citations)} citation rules")
    print()
    print("=== HTML ===")
    render_html(substitutions, citations)
    if args.html_only:
        print("\n(skipping LaTeX/PDF; --html-only)")
    else:
        print()
        print("=== LaTeX ===")
        render_latex(substitutions)
