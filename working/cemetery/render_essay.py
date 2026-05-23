"""Render cementerio_de_los_animales.md to a static, self-contained HTML
file with serif typography appropriate for an academic essay.

Output goes to the same directory and is served by the existing
http.server on port 8765 as cementerio_de_los_animales.html.

The essay's `<img>` tags use `quipu:<txid>` URLs (the canonical on-chain
reference form). For local preview before inscription, the renderer
rewrites known placeholder txids to local file paths via QUIPU_PREVIEW_MAP.
After inscription, the build script (build_consolidated.py) substitutes the
real on-chain root_txids into the markdown body before signing; readers
that resolve `quipu:<real_txid>` against the chain will then fetch the
actual image quipu.
"""
import re
from pathlib import Path
import markdown

THIS_DIR = Path(__file__).parent
SRC = THIS_DIR / "cementerio_de_los_animales.md"
OUT = THIS_DIR / "cementerio_de_los_animales.html"

# Placeholder txids in the markdown source. Replaced by build_consolidated.py
# with real root_txids before inscription; for local preview, these point at
# the corresponding compressed image files in figures/.
QUIPU_PREVIEW_MAP = {
    "dededededededededededededededededededededededededededededededede":
        "figures/pinochet_320x400_3bit.png",
    "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0":
        "figures/condor_invite_320x420_3bit.png",
}

CSS = """
:root {
    color-scheme: light;
    --bg: #faf7f2;
    --text: #1f1d1a;
    --muted: #6b665e;
    --accent: #8a4a3a;
    --rule: #d8d2c6;
    --quote-bg: #f3eee5;
    --code-bg: #efe9dd;
}
html { font-size: 18px; }
body {
    background: var(--bg);
    color: var(--text);
    font-family: "Iowan Old Style", "Charter", "Source Serif Pro",
                 "Georgia", "Times New Roman", serif;
    line-height: 1.62;
    margin: 0;
    padding: 0;
    text-rendering: optimizeLegibility;
    -webkit-font-smoothing: antialiased;
}
main {
    max-width: 38rem;
    margin: 0 auto;
    padding: 4rem 1.5rem 6rem;
}
h1 {
    font-size: 2.1rem;
    font-weight: 600;
    letter-spacing: -0.01em;
    margin: 0 0 2.5rem;
    color: var(--accent);
    text-align: left;
    line-height: 1.15;
}
p {
    margin: 0 0 1.3em;
    text-align: justify;
    hyphens: auto;
    -webkit-hyphens: auto;
}
blockquote {
    background: var(--quote-bg);
    border-left: 3px solid var(--accent);
    margin: 1.6em 0;
    padding: 0.9em 1.2em;
    color: var(--text);
    font-style: normal;
}
blockquote p {
    margin: 0;
    text-align: left;
    hyphens: none;
    font-size: 0.96em;
    line-height: 1.5;
}
blockquote strong {
    font-weight: 600;
    color: var(--muted);
    display: block;
    font-size: 0.85em;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    margin-bottom: 0.4em;
}
em { font-style: italic; }
code {
    font-family: "SF Mono", "JetBrains Mono", "Menlo", monospace;
    font-size: 0.86em;
    background: var(--code-bg);
    padding: 0.08em 0.32em;
    border-radius: 2px;
    color: #4a3829;
}
pre {
    background: var(--code-bg);
    color: #2a2218;
    padding: 1em 1.2em;
    border-radius: 4px;
    overflow-x: auto;
    font-family: "SF Mono", "JetBrains Mono", "Menlo", monospace;
    font-size: 0.82em;
    line-height: 1.5;
    margin: 1.6em 0;
}
pre code {
    background: transparent;
    padding: 0;
    border-radius: 0;
    color: inherit;
    font-size: inherit;
}
hr {
    border: 0;
    border-top: 1px solid var(--rule);
    margin: 2.5em 0;
}
a { color: var(--accent); text-decoration: underline; }
a:hover { color: #6b3528; }

/* Footer with provenance + on-chain pointer */
.colophon {
    margin-top: 4em;
    padding-top: 1.6em;
    border-top: 1px solid var(--rule);
    color: var(--muted);
    font-size: 0.82em;
    line-height: 1.5;
    font-family: "SF Mono", "JetBrains Mono", "Menlo", monospace;
}
.colophon a { color: var(--muted); }
.colophon .row { margin: 0.25em 0; }

figure.document-scan {
    margin: 2.4em auto;
    padding: 0;
    text-align: center;
}
figure.document-scan img {
    display: block;
    max-width: 100%;
    width: 22rem;
    margin: 0 auto;
    background: #fff;
    box-shadow: 0 1px 3px rgba(0,0,0,0.18),
                0 6px 18px rgba(0,0,0,0.10);
    border: 1px solid var(--rule);
}
figure.document-scan figcaption {
    margin: 0.9em auto 0;
    max-width: 32rem;
    font-size: 0.82em;
    line-height: 1.5;
    color: var(--muted);
    text-align: left;
    font-style: normal;
}

/* Side-by-side figure pair. Each child <figure> sits in a flex column;
   captions align at the top under each image, regardless of caption
   length. On narrow viewports the pair stacks vertically. */
.figure-pair {
    display: flex;
    gap: 1.4rem;
    align-items: flex-start;
    margin: 2.4em -2rem;  /* allow slight bleed past the prose column */
    justify-content: center;
}
.figure-pair > figure.document-scan {
    flex: 1 1 0;
    margin: 0;
    min-width: 0;
}
.figure-pair > figure.document-scan img {
    width: 100%;
    max-width: 18rem;
}
.figure-pair > figure.document-scan figcaption {
    max-width: 100%;
}

@media (max-width: 520px) {
    html { font-size: 16px; }
    main { padding: 2.5rem 1.1rem 4rem; }
    h1 { font-size: 1.7rem; }
    figure.document-scan img { width: 100%; }
    .figure-pair {
        flex-direction: column;
        gap: 1.8rem;
        margin: 2em 0;
    }
    .figure-pair > figure.document-scan img { max-width: 100%; }
}
"""

COLOPHON = """
<div class="colophon">
  <div class="row">cementerio_de_los_animales.md &middot; El Ermitaño &middot; 2026</div>
  <div class="row">scene quipu (0x3d): <a href="https://dogechain.info/tx/1f63558bdee2f5ead118083ff0af0d5e266acaf347938c5ed2722b6ced1248e3">1f63558bdee2f5ead118083ff0af0d5e266acaf347938c5ed2722b6ced1248e3</a></div>
  <div class="row">block 6,217,246 &middot; apocrypha &middot; D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX</div>
  <div class="row"><a href="cemetery.html">open walkable scene &rarr;</a></div>
</div>
"""


def render():
    src = SRC.read_text(encoding="utf-8")
    body_html = markdown.markdown(
        src,
        extensions=["extra", "sane_lists", "smarty"],
        output_format="html5",
    )

    # Local preview: rewrite quipu:<placeholder> img srcs to figures/...
    # In the actual on-chain markdown source, these stay as quipu:<txid>.
    def _rewrite_preview(m):
        attr, txid = m.group(1), m.group(2)
        local = QUIPU_PREVIEW_MAP.get(txid.lower())
        return f'{attr}="{local}"' if local else m.group(0)
    body_html = re.sub(
        r'(src|href)="quipu:([0-9a-fA-F]{64})"',
        _rewrite_preview,
        body_html,
    )
    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cementerio de los Animales</title>
<style>{CSS}</style>
</head>
<body>
<main>
{body_html}
{COLOPHON}
</main>
</body>
</html>
"""
    OUT.write_text(page, encoding="utf-8")
    print(f"wrote {OUT}  ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    render()
