# Status — Colegio Invisible toolkit

Last updated: 2026-05-14

## Where the corpus is

**25 quipus on chain.** 23 historical (2022-2024) plus 2 inscribed during
the May 2026 resurrection sprint:

- **Atom** (`424538b815be4cdf85e4b74e3b222bb79c2f8b87ca125ba6f231cf2cabcc711c`)
  — text quipu on apocrypha, 2026-05-11. Khamsa description in 4 strands
  (1 cabeza + 3 body). First production use of `CadenaAtom`'s precompute-then-
  broadcast pattern.

- **Sabina** (`c50b4881bb224b8f6a2d2ff7924dc10b3a9078ab5d50532309d5517f10a62f6b`)
  — image quipu on apocrypha, 2026-05-11. 100×50 grayscale 5-bit portrait,
  reverence tone, 4 strands closed by joining tx
  `b2532785620ee7750631b24cb382948913751cc0b093d51285e3a07a71ac1002`.
  First inscription using the multi-wave broadcast + joining-tx termination
  pattern. **Note**: the dimensions in Sabina's header are stored
  `(H, W)` rather than the historical `(W, H)` — so it renders transposed
  through any decoder following the canonical convention. Apocrypha-style
  documented exception, not a convention.

## What works end-to-end

- **Read pipeline**: `colegio_tools.scan_accounts` + `find_quipu_roots` +
  `read_quipu` decode every historical quipu correctly. Validated against
  all 23 historical inscriptions.
- **Write pipeline**: `Cadena`, `CadenaAtom` (single strand), and the new
  `Quipu` orchestrator (multi-strand, two-phase) — all proven on chain.
- **Two-phase quipu pattern (the diamond)**: consolidation → root tx →
  parallel strand broadcast → joining tx → consolidated UTXO. Each quipu
  opens from one input and closes to one output. Implemented in
  `quipu_orchestrator.py:Quipu`.
- **Streamlit interface (`quipu_console.py`)**: four tabs covering
  - Plan (text or image authoring with live encoding preview)
  - Inscribe (two-phase build, with phase buttons and confirm-waits)
  - Read (any quipu by txid)
  - Wallet (UTXO tree + force-directed history topology with click-to-popup
    showing decoded content for every quipu rooted at the address)
- **Address-history view**: every quipu rooted at an address rendered as a
  force-directed network with click-to-inspect popups containing the
  decoded image / text / identity / cert body and full header metadata.
- **Pruned-mode RPC**: connection-pooled via `requests.Session()` so
  scan_accounts on bordado (15k+ wallet txs) doesn't exhaust ephemeral
  ports.

## What's still open

- **La Verna bordado certificate** (`a90fb985f7c12eb4abb2cb4d9e77e1636902df1fb203e7f13e0a367e20e9d019`)
  — 5 outputs at 456 DOGE each, awaiting strands. cc 0002 type.
- **Third bordado certificate** (`891126982a29a5eda4d67e1d0f45279c1d109a7fc5351e932bafb89c1aa9cd9c`)
  — also 5 outputs at 456 DOGE each, awaiting strands.
- Both need: the bordado witness keys (Hayagriva + Christophia + Anthony,
  files in `~/Desktop/cinv/`, password-protected unlike apocrypha) and a
  multisig version of the two-phase Quipu orchestrator. `CadenaMultiAtom`
  exists in colegio_tools but the orchestrator wrapper and PSBT-style
  signer-coordination workflow aren't yet built.
- **Spec docs** for: text essay markup with bindings, celestial figures
  (`0xce`), bindings type (`0xab`), encryption + strand termination — all
  drafted in `docs/quipu-syntax/` and `docs/quipu-types/`. Not yet
  implemented in `colegio_tools.py`.

## How to launch

```bash
# 1. Confirm node is up + synced
~/Desktop/dogecoin/src/dogecoin-cli getblockchaininfo

# 2. Start the Streamlit console
cd ~/Desktop/Colegio_Invisible
.venv/bin/streamlit run quipu_console.py
# Opens at http://localhost:8501
```

In the sidebar: load the apocrypha key (default path is
`~/Desktop/cinv/llaves/mi_prv.enc`, empty-string password).

## Apocrypha balance

After Sabina's joining tx: **1 UTXO of 16.85 DOGE** at apocrypha
(`D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX`). Single clean input ready for the
next inscription's Phase 1 root tx.

## Files of record

- `colegio_tools.py` — main library (RPC + cryptography + image bit-codec +
  Cadena writers + scan_accounts/find_quipu_roots/read_quipu readers)
- `quipu_orchestrator.py` — `Quipu` class for two-phase build with
  state machine (INIT → ROOT_BUILT → ROOT_BROADCAST → ROOT_CONFIRMED →
  STRANDS_PRECOMPUTED → STRANDS_BROADCAST → STRANDS_CONFIRMED →
  JOIN_BUILT → JOIN_BROADCAST → DONE)
- `quipu_console.py` — Streamlit UI
- `quipu_crypto.py` — five seal mechanisms (password / key-drop / ECIES with
  combined keys for multi-keyholder thresholds), validated by 23/23 tests
- `requirements.txt` — pinned dependencies
- `docs/quipu-types/` and `docs/quipu-syntax/` — DRAFT specs (celestial,
  bindings, essay markup, encryption + strand termination)
- `quipu_header_bytes.md` — observed header byte conventions across the corpus
