#!/usr/bin/env python3
"""family_graph.py — render a genealogy quipu (combined with referenced houses)
as the FULL family graph: parents, spouses, children, siblings, across houses,
with the apocryphal cross-house paternity as a dashed edge.

Data-driven: people, dates, houses and descent edges come from the quipu(s).
Layout is computed by Graphviz `dot` (a couple-union family-tree graph); the
positions are then drawn in TikZ with the colegio styling — so it regenerates
itself from the data and keeps the look. Falls back to the ancestry pedigree
(genealogy_to_tikz) when `dot` is unavailable.

  family_graph_to_png(txid, fetcher, figdir) -> basename | None
"""
import os, subprocess, shutil, tempfile
import genealogy_to_tikz as G

# LaTeX preamble the colegio document needs so an inline family-graph
# tikzpicture compiles natively (vector — no rasterisation).
PREAMBLE = r"""\usepackage{tikz}\usepackage{pdflscape}\usetikzlibrary{backgrounds}
\definecolor{fgink}{HTML}{1a1a1a}\definecolor{fggold}{HTML}{9a7b3f}
\definecolor{fgbox}{HTML}{efe7d4}\definecolor{fgsubj}{HTML}{e9d9a8}
\definecolor{fghouse}{HTML}{dde6f0}\definecolor{fgedge}{HTML}{5a6a86}
\tikzset{
  gnode/.style={draw=fggold,line width=0.5pt,fill=fgbox,rounded corners=1.5pt,
                font=\sffamily\fontsize{7.5}{9}\selectfont,align=center,
                text width=2.5cm,inner sep=2.2pt,text=fgink},
  ghouse/.style={gnode,fill=fghouse,draw=fgedge},
  gsubject/.style={gnode,fill=fgsubj,line width=0.9pt},
  geneline/.style={draw=fggold,line width=0.55pt},
  natline/.style={draw=fgink,line width=0.6pt,dash pattern=on 2pt off 1.6pt},
  natlabel/.style={font=\sffamily\fontsize{6}{7}\selectfont,text=fgink,fill=white,
                   inner sep=1pt,sloped},
}
"""


def family_graph_tikz(txid, fetcher, caption=""):
    """Return an inline LaTeX block that draws the family graph as a NATIVE
    tikzpicture (dot computes positions; TikZ draws it — vector, not a PNG),
    scaled to the full content width. Used by the colegio pipeline when the
    essay SHOWs a genealogy quipu. Requires PREAMBLE in the document preamble."""
    body = family_graph_tikz_body(fetcher(txid), fetcher, _dot_bin())
    cap = ("\\\\[1.4ex]{\\sffamily\\footnotesize\\itshape %s}" % G._tex(caption)) if caption else ""
    # a wide genealogy wants the page turned: its own landscape plate, native TikZ at full width
    return ("\n\\begin{landscape}\\thispagestyle{empty}\\null\\vfill\\begin{center}\n"
            "\\resizebox{0.96\\linewidth}{!}{\\begin{tikzpicture}[x=1cm,y=1cm]\n%s\n"
            "\\end{tikzpicture}}%s\n\\end{center}\\vfill\\null\\end{landscape}\n" % (body, cap))


def _dot_bin():
    return (shutil.which("dot")
            or next((p for p in (os.path.expanduser("~/anaconda3/envs/gv/bin/dot"),
                                 os.path.expanduser("~/anaconda3/bin/dot"),
                                 "/usr/local/bin/dot", "/opt/homebrew/bin/dot")
                     if os.path.exists(p)), None))

BOX_W_IN, BOX_H_IN = 1.15, 0.52          # dot reserves this per person (≈ TikZ box)
SCALE = 2.54                              # dot inches → TikZ cm (1:1 inch→cm*2.54)


def _nid(key):
    return "n_" + ("%s__%s" % key).replace("-", "_").replace(".", "_")


def _couples(parents, cross):
    """child -> legal parents; group children by their legal-parent set."""
    couples = {}
    for c, ps in parents.items():
        legal = [p for p in ps if (c, p) not in cross]
        if not legal:
            continue
        couples.setdefault(tuple(legal[:2]), set()).add(c)
    return couples


def _build_dot(nodes, parents, cross):
    out = ["digraph F {",
           "  graph [rankdir=TB, nodesep=0.30, ranksep=0.75, splines=line];",
           '  node [shape=box, fixedsize=true, width=%g, height=%g, label=""];' % (BOX_W_IN, BOX_H_IN),
           "  edge [arrowhead=none];"]
    for k in nodes:
        out.append("  %s;" % _nid(k))
    unions = {}
    for i, (cp, kids) in enumerate(_couples(parents, cross).items()):
        u = "u%d" % i; unions[u] = (cp, kids)
        out.append('  %s [shape=point, width=0.02, height=0.02];' % u)
        for p in cp:
            out.append("  %s -> %s;" % (_nid(p), u))
        for c in kids:
            out.append("  %s -> %s;" % (u, _nid(c)))
        if len(cp) == 2:
            out.append("  {rank=same; %s; %s; %s;}" % (_nid(cp[0]), u, _nid(cp[1])))
    for (c, p) in cross:                       # cross-house: rank-constrain only
        out.append("  %s -> %s [style=invis];" % (_nid(p), _nid(c)))
    out.append("}")
    return "\n".join(out), unions


def _positions(dot_src, dot_bin):
    r = subprocess.run([dot_bin, "-Tplain"], input=dot_src, capture_output=True,
                       text=True, timeout=60)
    pos = {}
    for line in r.stdout.splitlines():
        t = line.split()
        if t and t[0] == "node":
            pos[t[1]] = (float(t[2]) * SCALE, float(t[3]) * SCALE)
    return pos


def family_graph_tikz_body(blob, fetcher, dot_bin):
    nodes, parents, cross, subject, title, _house_titles = G.build_combined(blob, fetcher)
    dot_src, unions = _build_dot(nodes, parents, cross)
    pos = _positions(dot_src, dot_bin)
    if not pos:
        raise RuntimeError("dot produced no positions")
    L = []
    for u, (cp, kids) in unions.items():
        if u not in pos:
            continue
        ux, uy = pos[u]
        for p in cp:
            if _nid(p) in pos:
                px, py = pos[_nid(p)]; L.append("\\draw[geneline] (%.2f,%.2f) -- (%.2f,%.2f);" % (px, py - 0.45, ux, uy))
        for c in kids:
            if _nid(c) in pos:
                cx, cy = pos[_nid(c)]; L.append("\\draw[geneline] (%.2f,%.2f) -- (%.2f,%.2f);" % (ux, uy, cx, cy + 0.45))
    for (c, p) in cross:
        if _nid(c) in pos and _nid(p) in pos:
            cx, cy = pos[_nid(c)]; px, py = pos[_nid(p)]
            L.append("\\draw[natline] (%.2f,%.2f) -- (%.2f,%.2f);" % (px, py - 0.45, cx, cy + 0.45))
    from collections import Counter
    cnt = Counter(G._short(nodes[k]["name"]) for k in nodes if _nid(k) in pos)
    for k in nodes:
        if _nid(k) not in pos:
            continue
        x, y = pos[_nid(k)]; nm = nodes[k]
        full = nm["name"]; sh = G._short(full)
        lab = full if (cnt[sh] > 1 and " (" in full) else sh
        sty = "gsubject" if k == subject else ("ghouse" if k[0] != "self" else "gnode")
        body = G._tex(lab)
        if nm["born"] or nm["died"]:
            body += "\\\\{\\footnotesize %s--%s}" % (nm["born"] or "", nm["died"] or "")
        L.append("\\node[%s] at (%.2f,%.2f) {%s};" % (sty, x, y, body))
    return "\n".join(L)


def family_graph_to_png(txid, fetcher, figdir):
    dot_bin = _dot_bin()
    if not dot_bin:
        return None
    try:
        import colegio_pipeline as P
        ver = getattr(P, "_FIGURE_CACHE_VERSION", 0)
    except Exception:
        ver = 0
    os.makedirs(figdir, exist_ok=True)
    base = "fam_%s_v%s.png" % (txid[:12], ver)
    out = os.path.join(figdir, base)
    if os.path.exists(out):
        return base
    tex = G._DOC % family_graph_tikz_body(fetcher(txid), fetcher, dot_bin)
    work = tempfile.mkdtemp(prefix="quipu_fam_")
    try:
        with open(os.path.join(work, "f.tex"), "w", encoding="utf-8") as f:
            f.write(tex)
        subprocess.run(["xelatex", "-interaction=nonstopmode", "-halt-on-error", "f.tex"],
                       cwd=work, capture_output=True, text=True, timeout=120)
        pdf = os.path.join(work, "f.pdf")
        if not os.path.exists(pdf):
            return None
        return base if G._rasterise(pdf, out) else None
    except Exception:
        return None
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    import sys, hashlib
    blob = open(sys.argv[1], "rb").read()
    fetcher = None
    if len(sys.argv) > 2:
        gb = open(sys.argv[2], "rb").read()
        gtx = hashlib.sha256(("goethe-quipu-standin:" + gb.hex()[:32]).encode()).hexdigest()
        fetcher = lambda t, _g=gb, _x=gtx: _g if t == _x else b""
    print(G._DOC % family_graph_tikz_body(blob, fetcher, _dot_bin()))
