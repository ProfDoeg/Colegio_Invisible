#!/usr/bin/env bash
# build_formula.sh — typeset the atlas description and key it to transparency.
#
# The story card carries a formula, not a tally: a scene (0x3d) taken against
# the indexed family of celestial quipu (0xce). The index set I is deliberately
# left unnamed, so the card says what the atlas IS rather than how many entries
# it happens to hold today.
#
# Writes story_formula.png next to render_story.py, which picks it up if present.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/formula.tex" <<'TEX'
\documentclass[border=8pt]{standalone}
\usepackage{amsmath,amssymb}
\begin{document}
$\mathtt{0x3d} \times \left\{ \mathtt{0xce}_{i} \right\}_{i \in I}$
\end{document}
TEX

cd "$WORK"
xelatex -interaction=nonstopmode formula.tex >/dev/null 2>&1
mutool draw -r 600 -o formula.png formula.pdf >/dev/null 2>&1

python3 - "$WORK/formula.png" "$HERE/story_formula.png" <<'PY'
import sys
import numpy as np
from PIL import Image

src, dst = sys.argv[1], sys.argv[2]
a = np.array(Image.open(src).convert('RGB')).astype(np.int16)
# TeX renders black on white; key the white out to alpha and recolour the glyphs
alpha = (255 - a.mean(axis=2)).clip(0, 255).astype(np.uint8)
rgb = np.zeros(a.shape, dtype=np.uint8)
rgb[:, :] = (206, 216, 234)
img = Image.fromarray(np.dstack([rgb, alpha]), 'RGBA')
img = img.crop(img.getbbox())
img.save(dst)
print('wrote', dst, img.size)
PY
