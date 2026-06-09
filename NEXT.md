# Next — open threads

Updated 2026-06-09. The previous version of this file was the
QuipuMulti handoff (2026-05-16); that build shipped — `QuipuMulti` in
`quipu_orchestrator.py`, proven on chain by El Libro del Gólem
(multiman 2-of-2, block 6,218,023). Current state of everything is in
`STATUS.md`; this file lists what's open, roughly nearest-first.

## Housekeeping

- **Refresh `data/quipu_data.csv`** — current through block 6,218,023.
  Caity, the Gana forest, El Centinela, and the sale txs are missing.
  Run `update_quipu_data.py` with the node up.
- **Commit the notebook move** — the 20 cuadernos sit deleted at root
  and untracked under `notebooks/`. Decide and commit (the .ipynb files
  carry 11–15 MB of embedded outputs each; stage them explicitly).
- **`tag-architecture` branch** — design docs for tag architecture and
  corrected sale choreography. Review and merge or fold into main.
- **Archive `recover_bowie.py` / `recover_bowie_continue.py`** —
  incident-specific recovery scripts with hardcoded txids and key
  paths; not toolkit code.
- **Test harness** — wire `test_quipu_crypto.py` and the canonical
  module self-tests into a single pytest target that runs before any
  broadcast session.

## Protocol

- **Estandarte v1 inscription** — `0xee` is implemented and documented
  but the registry itself is not on chain. The v1 inscription should
  mark the two pre-canonical inscriptions (`20db7d45…` hash-cert
  precursor, `a2e9f2eb…` non-structural image) as deprecated, and
  decide whether the diamond convention is documented in it.
- **`0xda` dancer spec finalization** — data model converged (frames +
  per-frame centroid + per-frame displacement + named-transition
  graph; mirror+reverse gives 4× expansion per clip). Waiting on new
  dancer datasets.

## Publications

- **Museum / wilds / pet cemetery** — three-zone walkable corpus on
  `0x3d` (HCA museum / El Ermitaño wilds / pet cemetery). The
  Cementerio validated the primitive; the museum and wilds zones are
  unbuilt.
- **Book of 108** — 108 essays + textile photos + apparatus in one
  consolidated fractal-diamond inscription. ~21,000 DOGE budget.
  Design in `docs/design/book-108-cathedral.md`.

## Substrate

- **Nostr, beyond primitives** — signing/transport and the persona
  npubs shipped 2026-06-08 (`canonical/nostr.py`,
  `docs/guides/nostr-integration.md`). The doorbell / DM / negotiation
  flows described in the guide are designed, not built.
