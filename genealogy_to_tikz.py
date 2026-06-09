#!/usr/bin/env python3
"""genealogy_to_tikz.py — render a 0xce kind=genealogy quipu as a TikZ pedigree.

The genealogy quipu is the inscription; this is its rendered view (cf.
scene_to_tikz for 0x3d). Data-driven: the ancestry tree is built from the
quipu's people + descent edges, and CROSS-QUIPU parent refs are resolved through
the fetcher and grafted in — so a House-of-Jung genealogy that names Goethe as
the elder Jung's natural father renders the COMBINED ancestry, climbing on into
the House of Goethe. The illegitimate cross-edge is drawn dashed and labelled;
the two houses are tinted differently.

  genealogy_to_png(txid, fetcher, figdir) -> basename   (mirrors target_to_png)
"""
import os, struct

MAGIC = b"\xc1\xdd\x00\x01"
TYPE_CELESTIAL, KIND_GENEALOGY = 0xCE, 0x03


# --------------------------------------------------------------------------
#  Reader (matches working/lineage/genealogy_quipu.py build_genealogy)
# --------------------------------------------------------------------------
def read_genealogy(blob):
    assert blob[:4] == MAGIC and blob[4] == TYPE_CELESTIAL and blob[6] == KIND_GENEALOGY
    o = 9                                            # magic4 + type + tone + kind + 2 reserved
    K = struct.unpack(">H", blob[o:o+2])[0]; o += 2
    T = blob[o]; o += 1
    title = blob[o:o+T].decode("utf-8"); o += T
    people = []
    for _ in range(K):
        born = struct.unpack(">f", blob[o:o+4])[0]; o += 4
        died = struct.unpack(">f", blob[o:o+4])[0]; o += 4
        nl = blob[o]; o += 1; name = blob[o:o+nl].decode("utf-8"); o += nl
        ml = struct.unpack(">H", blob[o:o+2])[0]; o += 2 + ml
        people.append({"name": name,
                       "born": None if born != born else int(born),
                       "died": None if died != died else int(died)})
    Nref = struct.unpack(">H", blob[o:o+2])[0]; o += 2
    refs = []
    for _ in range(Nref):
        txid = blob[o:o+32].hex(); o += 32
        ridx = struct.unpack(">H", blob[o:o+2])[0]; o += 2
        nl = blob[o]; o += 1; name = blob[o:o+nl].decode("utf-8"); o += nl
        refs.append({"txid": txid, "remote_idx": ridx, "name": name})
    lines = []
    while o + 4 <= len(blob):
        a = struct.unpack(">H", blob[o:o+2])[0]; o += 2
        c = struct.unpack(">H", blob[o:o+2])[0]; o += 2
        lines.append((a, c))
    return {"title": title, "K": K, "people": people, "refs": refs, "lines": lines}


# --------------------------------------------------------------------------
#  Combined model: merge the primary genealogy with any referenced ones
#  (keys are (source, idx); source 'self' for the primary, else the ref txid).
# --------------------------------------------------------------------------
def build_combined(blob, fetcher, *, max_depth=4):
    nodes, parents, cross, houses = {}, {}, set(), {}

    def ingest(g, src, depth):
        for i, p in enumerate(g["people"]):
            nodes.setdefault((src, i), {"name": p["name"], "born": p["born"], "died": p["died"]})
            houses[(src, i)] = src
        # map ref-array index -> resolved (txid, remote_idx); pull in each ref'd house
        refmap = {}
        for j, r in enumerate(g["refs"]):
            key = (r["txid"], r["remote_idx"])
            refmap[g["K"] + j] = key
            nodes.setdefault(key, {"name": r["name"].split("«")[0].strip(), "born": None, "died": None})
            houses.setdefault(key, r["txid"])
            if fetcher and depth < max_depth:
                try:
                    ingest(read_genealogy(fetcher(r["txid"])), r["txid"], depth + 1)
                except Exception:
                    pass
        for a, c in g["lines"]:
            ck = (src, c)
            if a < g["K"]:
                pk = (src, a)
            else:
                pk = refmap.get(a)
                if pk is None:
                    continue
                cross.add((ck, pk))                  # inter-house (illegitimate) edge
            parents.setdefault(ck, []).append(pk)

    g0 = read_genealogy(blob)
    ingest(g0, "self", 0)

    # focal subject = the primary parent-node with the deepest (combined) ancestry
    def depth(key, seen=frozenset()):
        if key in seen or key not in parents:
            return 0
        seen = seen | {key}
        return 1 + max((depth(p, seen) for p in parents[key]), default=0)

    prim_parents = {("self", a) for a, _ in g0["lines"] if a < g0["K"]}
    subject = max(prim_parents, key=depth, default=("self", 0))
    return nodes, parents, cross, subject, g0["title"]


def _shown_parents(key, parents, cross):
    ps = parents.get(key, [])
    locs = [p for p in ps if (key, p) not in cross]
    crs = [p for p in ps if (key, p) in cross]
    # a cross-house (biological) parent displaces the same-role legal parent
    return (crs[:1] + locs[1:][:1]) if crs else locs[:2]


# --------------------------------------------------------------------------
#  Tidy layout + TikZ
# --------------------------------------------------------------------------
def genealogy_tikz_body(blob, fetcher=None):
    nodes, parents, cross, subject, title = build_combined(blob, fetcher)
    ROW, COL = 2.55, 3.5
    gen, X = {}, {}
    nxt = [0.0]

    def layout(key, d, seen):
        if key in seen:
            return X.get(key, nxt[0])
        seen = seen | {key}
        gen[key] = d
        ps = [p for p in _shown_parents(key, parents, cross) if p in nodes]
        if not ps:
            x = nxt[0]; nxt[0] += 1.0
        else:
            xs = [layout(p, d + 1, seen) for p in ps]
            x = sum(xs) / len(xs)
        X[key] = x
        return x

    layout(subject, 0, frozenset())
    xs = [X[k] for k in X]; x0 = (min(xs) + max(xs)) / 2 if xs else 0

    # disambiguate nodes that share a short label (e.g. the two Sophie Jungs)
    # by keeping their née name; unique names stay short.
    from collections import Counter
    cnt = Counter(_short(nodes[k]["name"]) for k in X)

    def label_for(k):
        full = nodes[k]["name"]; sh = _short(full)
        return full if (cnt[sh] > 1 and " (" in full) else sh

    L = []
    for ck in list(X):
        for pk in _shown_parents(ck, parents, cross):
            if pk not in X:
                continue
            x1 = (X[ck] - x0) * COL; y1 = gen[ck] * ROW
            x2 = (X[pk] - x0) * COL; y2 = gen[pk] * ROW
            isx = (ck, pk) in cross
            L.append("\\draw[%s] (%.2f,%.2f) -- (%.2f,%.2f);"
                     % ("natline" if isx else "geneline", x1, y1 + 0.5, x2, y2 - 0.5))
            if isx:
                L.append("\\node[natlabel] at (%.2f,%.2f) {natural son};"
                         % ((x1 + x2) / 2, (y1 + y2) / 2))
    for key in X:
        x = (X[key] - x0) * COL; y = gen[key] * ROW
        nm = nodes[key]
        sty = "gsubject" if key == subject else ("ghouse" if houses_of(key) else "gnode")
        body = _tex(label_for(key))
        if nm["born"] or nm["died"]:
            body += "\\\\{\\footnotesize %s--%s}" % (nm["born"] or "", nm["died"] or "")
        L.append("\\node[%s] at (%.2f,%.2f) {%s};" % (sty, x, y, body))
    L.append("\\node[gtitle] at (0,%.2f) {%s};" % (-ROW * 0.95, _tex(title) + " \\& House of Goethe"))
    return "\n".join(L)


# a node belongs to another house (the referenced genealogy) if its source != 'self'
def houses_of(key):
    return key[0] != "self"


def _short(name):
    return name.split(" (")[0]


def _tex(s):
    for a, b in [("\\", "\\textbackslash "), ("&", "\\&"), ("%", "\\%"), ("#", "\\#"),
                 ("_", "\\_"), ("{", "\\{"), ("}", "\\}"), ("~", "\\textasciitilde "),
                 ("^", "\\textasciicircum ")]:
        s = s.replace(a, b)
    return s


_DOC = r"""\documentclass[tikz,border=5mm]{standalone}
\usepackage[utf8]{inputenc}\usepackage[T1]{fontenc}\usepackage{tikz}\usepackage{xcolor}
\usetikzlibrary{backgrounds}
\definecolor{paper}{HTML}{faf7ef}\definecolor{ink}{HTML}{1a1a1a}
\definecolor{gold}{HTML}{9a7b3f}\definecolor{box}{HTML}{efe7d4}\definecolor{subj}{HTML}{e9d9a8}
\definecolor{house}{HTML}{dde6f0}\definecolor{houseedge}{HTML}{5a6a86}
\tikzset{
  gnode/.style={draw=gold,line width=0.5pt,fill=box,rounded corners=1.5pt,
                font=\sffamily\fontsize{7.5}{9}\selectfont,align=center,
                text width=2.5cm,inner sep=2.2pt,text=ink},
  ghouse/.style={gnode,fill=house,draw=houseedge},
  gsubject/.style={gnode,fill=subj,line width=0.9pt},
  geneline/.style={draw=gold,line width=0.55pt},
  natline/.style={draw=ink,line width=0.6pt,dash pattern=on 2pt off 1.6pt},
  natlabel/.style={font=\sffamily\fontsize{6}{7}\selectfont,text=ink,fill=paper,
                   inner sep=1pt,sloped},
  gtitle/.style={font=\sffamily\itshape\fontsize{9}{11}\selectfont,text=gold},
}
\begin{document}\begin{tikzpicture}[x=1cm,y=1cm,background rectangle/.style={fill=paper},
  show background rectangle]
%s
\end{tikzpicture}\end{document}
"""


def _rasterise(pdf, out):
    """PDF → PNG via whatever backend is present: PyMuPDF, else Ghostscript, else sips."""
    import subprocess, shutil
    try:
        import fitz
        fitz.open(pdf)[0].get_pixmap(dpi=220).save(out); return True
    except Exception:
        pass
    gs = shutil.which("gs")
    if gs:
        subprocess.run([gs, "-q", "-dSAFER", "-dBATCH", "-dNOPAUSE", "-sDEVICE=png16m",
                        "-r220", "-dGraphicsAlphaBits=4", "-dTextAlphaBits=4",
                        "-sOutputFile=" + out, pdf], capture_output=True, timeout=120)
        if os.path.exists(out):
            return True
    sips = shutil.which("sips")
    if sips:
        subprocess.run([sips, "-s", "format", "png", pdf, "--out", out], capture_output=True)
        if os.path.exists(out):
            return True
    return False


def genealogy_to_png(txid, fetcher, figdir):
    """Render a 0xce genealogy (combined with referenced houses) to figdir/<…>.png."""
    import subprocess, tempfile, shutil
    try:
        import colegio_pipeline as P
        ver = getattr(P, "_FIGURE_CACHE_VERSION", 0)
    except Exception:
        ver = 0
    os.makedirs(figdir, exist_ok=True)
    base = "gen_%s_v%s.png" % (txid[:12], ver)
    out = os.path.join(figdir, base)
    if os.path.exists(out):
        return base
    tex = _DOC % genealogy_tikz_body(fetcher(txid), fetcher)
    work = tempfile.mkdtemp(prefix="quipu_gen_")
    try:
        with open(os.path.join(work, "g.tex"), "w", encoding="utf-8") as f:
            f.write(tex)
        subprocess.run(["xelatex", "-interaction=nonstopmode", "-halt-on-error", "g.tex"],
                       cwd=work, capture_output=True, text=True, timeout=120)
        pdf = os.path.join(work, "g.pdf")
        if not os.path.exists(pdf):
            return None
        return base if _rasterise(pdf, out) else None
    except Exception:
        return None
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    import sys, hashlib
    blob = open(sys.argv[1], "rb").read()
    fetcher = None
    if len(sys.argv) > 2:                     # arg2 = dir of <txid>.bin files / a goethe bin
        gb = open(sys.argv[2], "rb").read()
        gtx = hashlib.sha256(("goethe-quipu-standin:" + gb.hex()[:32]).encode()).hexdigest()
        fetcher = lambda t, _g=gb, _x=gtx: _g if t == _x else b""
    print(_DOC % genealogy_tikz_body(blob, fetcher))
