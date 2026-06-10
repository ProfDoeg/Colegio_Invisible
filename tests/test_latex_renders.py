"""LaTeX render layer — colegio.cls compiles, and the pipeline's macro
emission paths actually typeset.

Three tests, three guarantees:
  1+2. The shipped class examples (essay mode, book mode) compile clean
       with xelatex — colegio.cls regressions fail here by name.
  3.   The annotation primitive's full live path: essay + 0xab binding +
       book built locally, rendered through book_to_tex, all three
       presentation modes (\\margin / \\backnote / \\inlinenote) emitted,
       and the result compiles. Ported from working/tests/test_annotations.py.

Marked `latex`; skipped wholesale when xelatex is absent. Deselect with
`-m "not latex"` for the fast loop.
"""
import os
import re
import shutil
import subprocess

import pytest

pytestmark = [
    pytest.mark.latex,
    pytest.mark.slow,
    pytest.mark.skipif(shutil.which("xelatex") is None, reason="xelatex not on PATH"),
]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLS = os.path.join(REPO, "latex", "colegio", "colegio.cls")
EXAMPLES = os.path.join(REPO, "latex", "colegio", "examples")


def _xelatex(tex_name, cwd, passes=2):
    for _ in range(passes):
        r = subprocess.run(
            ["xelatex", "-interaction=nonstopmode", "-halt-on-error", tex_name],
            cwd=cwd, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, f"xelatex failed:\n{r.stdout[-2500:]}"
    log = open(os.path.join(cwd, tex_name.replace(".tex", ".log")),
               encoding="utf-8", errors="replace").read()
    m = re.search(r"Output written on .*\((\d+) pages?", log)
    assert m, "no 'Output written' line in the log"
    return int(m.group(1))


def _compile_example(name, tmp_path):
    """Copy an example + the class into tmp, point the docclass at the
    local copy, compile, return the page count."""
    tex = open(os.path.join(EXAMPLES, f"{name}.tex"), encoding="utf-8").read()
    tex = tex.replace("{../colegio}", "{colegio}")
    (tmp_path / f"{name}.tex").write_text(tex, encoding="utf-8")
    shutil.copy(CLS, tmp_path / "colegio.cls")
    return _xelatex(f"{name}.tex", str(tmp_path))


def test_example_essay_compiles(tmp_path):
    pages = _compile_example("example_essay", tmp_path)
    assert pages >= 2, f"essay example produced only {pages} page(s)"


def test_example_book_compiles(tmp_path):
    pages = _compile_example("example_book", tmp_path)
    assert pages >= 3, f"book example produced only {pages} page(s)"


def test_annotation_modes_emit_and_compile(tmp_path):
    """The 0xab live path: three anchors, three presentation modes, one
    compiled PDF. Failure modes covered: a dead rendering branch (macro
    not emitted) and a macro that emits but no longer typesets."""
    import colegio_pipeline as P
    from bindings import build_binding_quipu
    from book import build_book_quipu
    from essay import build_essay_quipu

    store = str(tmp_path / "store")
    auth = {"author": "El Gólem", "date": "2026-06-10", "lang": "en"}

    eh, eb = build_essay_quipu("A Test of Annotation", (
        "This paragraph mentions the *primal plant* once, early.\n\n"
        "A second paragraph speaks of the *turning sky*, chosen to carry\n"
        "an endnote.\n\n"
        "A third paragraph names the *sealed cord*, glossed inline.\n"),
        tone=0xA1, fields=dict(auth))
    essay_txid = P.write_inscription(eh, eb, store_dir=store)

    bh, bb = build_binding_quipu(
        "@@primal plant @margin\nGoethe's *Urpflanze*.\n@@\n\n"
        "@@turning sky @endnote\nThe rotating celestial sphere.\n@@\n\n"
        "@@sealed cord @inline\nthe 0x0e family.\n@@\n", tone=0xA1)
    binding_txid = P.write_inscription(bh, bb, store_dir=store)

    kh, kb = build_book_quipu("Annotation Render Test", [
        {"tag": "binding", "ref_txid": binding_txid, "name": ""},
        {"tag": "chapter/01", "ref_txid": essay_txid, "name": "A Test of Annotation"},
    ], tone=0xA1, fields={**auth, "institution": "Colegio Invisible"})
    book_txid = P.write_inscription(kh, kb, store_dir=store)

    figdir = str(tmp_path / "figures")
    tex = P.book_to_tex(book_txid, fetcher=P.chained_fetcher(store), figdir=figdir)

    for macro in ("\\margin{", "\\backnote{", "\\inlinenote{"):
        assert macro in tex, f"annotation branch dead: {macro} not emitted"

    pdf = P.compile_tex(tex, str(tmp_path / "build"), figdir=figdir)
    assert os.path.getsize(pdf) > 10_000, "suspiciously small PDF"


CEMETERY = "1f63558bdee2f5ead118083ff0af0d5e266acaf347938c5ed2722b6ced1248e3"


def test_scene_vista_composes_and_compiles(tmp_path):
    """The vista plate's contract: from the on-chain cemetery scene, one
    rectilinear view holds the full Winter Triangle (all 3 stars), all 10
    Orion stars, and all 5 photo quads — and the TikZ compiles. Guards the
    composition that was tuned by eye from regressing geometrically."""
    import colegio_pipeline as P
    body_file = os.path.join(REPO, "data", "bodies", CEMETERY + ".bin")
    if not os.path.exists(body_file):
        pytest.skip("cemetery scene body not in data/bodies")
    import scene_to_tikz as S

    figdir = str(tmp_path / "figures")
    os.makedirs(figdir, exist_ok=True)
    tex, meta = S.build_plate_tex(CEMETERY, P.chained_fetcher(),
                                  mode="vista", figdir=figdir)
    assert meta["wt_in_frame"] == 3, "Winter Triangle incomplete in frame"
    assert meta["orion_in_frame"] == 10, "Orion incomplete in frame"
    assert meta["quads_drawn"] == 5, "a photo quad fell out of frame"
    assert meta["lines_partial"] >= 1, \
        "edge-crossing constellation lines dropped (one-endpoint clipping regressed)"
    assert tex.count("includegraphics") >= 5, "photos missing from the plate"

    work = tmp_path / "build"
    work.mkdir()
    (work / "scene.tex").write_text(tex, encoding="utf-8")
    shutil.copytree(figdir, work / "figures")
    pages = _xelatex("scene.tex", str(work), passes=1)
    assert pages == 1
