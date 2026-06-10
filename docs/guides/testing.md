# Testing — the suite and what each layer protects

```bash
.venv/bin/python -m pytest            # everything offline: ~7s, no node, no funds
QUIPU_RPC_TESTS=1 .venv/bin/python -m pytest   # + the node smoke test
```

The protocol's inscriptions are permanent; the readers are the living
half. The suite is organized around what a regression would *cost*:

## 1. Corpus regression — `tests/test_corpus_regression.py`

The gold layer. Every quipu actually on chain (mirrored in
`data/quipu_data.csv` + `data/bodies/*.bin`) must keep decoding:

- `canonical_v1` rows decode strictly — split, magic, type byte, full
  reader, title equality against the dataset, registered tone byte.
- `pre_canonical` / `not_yet_canonicalized` rows are checked leniently
  (bytes present; structural type byte agrees when the magic is there) —
  deviating is what pre-canonical means.

A failure here names the txid: the exact inscription that just became
unreadable. Refresh the mirror with `update_quipu_data.py` after new
inscriptions so this layer grows with the corpus.

## 2. Canonical self-tests — `tests/test_canonical_selftests.py`

Every `_selftest_*` function in every `canonical/*.py` module, collected
as individual pytest cases (~68 of them). These carry the embedded
on-chain test vectors (Mi Perrito, the Domrémy bordado, the Maier cert)
and the validation/error-path checks. They were always runnable as
`python canonical/<mod>.py`; now a regression fails by name in CI-shaped
output.

## 3. Toolkit suites — `tests/test_toolkit_selftests.py`

The standalone offline scripts, run as subprocesses with their pass
banners as the contract:

- `test_quipu_crypto.py` — 23 seal tests (ECIES key-combining, AES,
  key-drop, negative cases)
- `quipu_centinela.py` — HTLC lock construction, claim/refund scriptSigs
- `quipu_tags.py` — the 7-stage tag lifecycle (engine → reader →
  specialization → claim → thread → review nub → economics)

## 4. Splitting + accounting invariants — `tests/test_split_invariants.py`

The places where a silent mistake becomes a permanently mis-inscribed
quipu:

- `split_body` contiguity (re-concatenation is identity), knot
  alignment, and an explicit anti-round-robin case — the Jeremy lesson,
  pinned so it cannot regress quietly.
- `split_quipu`: strand 0 is exactly the header.
- Diamond accounting: every koinu conserved (fees + tags + residual =
  funding), bodies round-trip byte-identical, tag outputs ride the root
  and are ignored by the join, dust tags and insufficient funding raise.

## 5. LaTeX renders — `tests/test_latex_renders.py`

Marked `latex` + `slow` (skipped when xelatex is absent; deselect with
`-m "not latex"` for the fast loop, ~14s when included):

- Both shipped class examples (essay mode, book mode) compile clean —
  a colegio.cls regression fails here by name, with a page-count floor.
- The annotation primitive's full live path: essay + `0xab` binding +
  book built into a tmp inscription store, rendered via `book_to_tex`,
  all three presentation modes (`\margin` / `\backnote` /
  `\inlinenote`) asserted in the emitted TeX, and the result compiled.
  Catches both failure modes: a dead rendering branch and a macro that
  emits but no longer typesets. (Supersedes
  `working/tests/test_annotations.py`, retained as scratch.)

## Markers

- `rpc` — needs a reachable Dogecoin node; skipped unless
  `QUIPU_RPC_TESTS=1`.
- `latex` — needs xelatex on PATH; auto-skipped otherwise.
- `slow` — the render tests; deselect with `-m "not slow"`.

## What is deliberately NOT here

- On-chain end-to-end (real funds) — that gate stays manual and
  deliberate; see `docs/guides/broadcasting.md`.
- Streamlit UI flows (`quipu_console.py`, `quipu_viewer.py`) — exercised
  by use; automating them buys little for their cost.
