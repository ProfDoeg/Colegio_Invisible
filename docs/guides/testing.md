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

## Markers

- `rpc` — needs a reachable Dogecoin node; skipped unless
  `QUIPU_RPC_TESTS=1`.
- `slow`, `latex` — reserved for broadcast simulations and xelatex
  render tests as they get added.

## What is deliberately NOT here

- On-chain end-to-end (real funds) — that gate stays manual and
  deliberate; see `docs/guides/broadcasting.md`.
- Streamlit UI flows (`quipu_console.py`, `quipu_viewer.py`) — exercised
  by use; automating them buys little for their cost.
- LaTeX renders — `working/tests/test_annotations.py` exists as a
  starting point; fold it in under the `latex` marker when the render
  pipeline stabilizes.
