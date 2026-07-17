# Status — Colegio Invisible toolkit

Last updated: 2026-06-09

## Where the corpus is

The May 2026 resurrection sprint (Atom, Sabina — see git history for
details) grew into a sustained inscription campaign. Milestones since,
in chain order:

- **Encrypted family `0x0e`** (2026-05-14) — keydrop auto-resolution plus
  the `0xae` AES-sealed sub-family, with test pairs on apocrypha.
  *(2026-07-17: the two-implementation wire fork was reconciled —
  `canonical/encrypted.py` is the single parser for both eras, writers
  emit canonical only; see `docs/design/encrypted-wire-reconciliation.md`
  and `tests/test_encrypted_wire.py`.)*
- **Cementerio de los Animales** — first `0x3d` scene on chain, root
  `1f63558bdee2f5ead118083ff0af0d5e266acaf347938c5ed2722b6ced1248e3`
  (block 6,217,246, apocrypha). A companion essay followed at block
  6,217,650.
- **Dos ensayos** — first `0x09` book, root
  `26671514416913719c560a4ac1246e333e410d2503e298a8a6852031c3285888`
  (block 6,217,912, apocrypha). Shipped together with the v2 binding
  grammar.
- **El Libro del Gólem** — meta-book from the multiman 2-of-2 multisig,
  root `7b19fb2bf42e8882ae7bc71ef0f4095f2b2982885728b761101d96efdb338811`
  (block 6,218,023). 13 quipus. The multisig write path (`QuipuMulti`)
  is proven here.
- **Jeremy** — first `0xda` dancer, root
  `6de4688a945fb03f41f9b1139c83f5099dd309378348398d4b52ce1c1d12a489`,
  22,377 knots. Inscribed with round-robin strand interleaving — a
  documented exception; the canonical convention is contiguous
  knot-aligned ranges and reading Jeremy requires the interleaver in
  `load_from_chain.py`.
- **Caity** — second `0xda` dancer, root
  `fcff6aa28113cfa1a0323dd41f8a65a88d0bc372601fdff0eb177825023e7826`
  (block 6,232,978). 255 strands / 29,082 knots, contiguous — reads
  directly.
- **Gana forest** — 17 quipus inscribed as one consolidated diamond
  (block 6,237,154, 2026-06-06): essays, margin banners, images around
  the Goethe / Italian Journey lineage. 178 strands / 3,714 knots /
  ~96 DOGE. First production run of the `quipu_diamond.py` engine.
- **El Centinela** — cryptographic-canary primitive (`0x0e 0xca`):
  an AES-sealed secret unlocks a bait UTXO, so a spend is on-chain
  tamper evidence. Three lock modes validated on mainnet at block
  6,237,951.
- **Verified-key sale** (2026-06-08) — `0x0e 0xcb` sealed box +
  `0xcc 0x0003` sale offer bound by ECDSA adaptor signatures
  (`canonical/adaptor.py`).
- **Nostr personas** (2026-06-08) — El Gólem and El Ermitaño npubs
  declared and verified against the multiman keys; signing/transport
  in `canonical/nostr.py`, design in `docs/guides/nostr-integration.md`.

`data/quipu_data.csv` holds 58 decoded quipus and is current through
block 6,218,023 (El Libro del Gólem). Caity, the Gana forest, the
Centinela txs, and the sale txs are not in it yet — refresh with
`update_quipu_data.py` (or notebook 60) next time the node is up.

## What works end-to-end

- **Read pipeline**: `data/quipu_data.csv` + `data/bodies/{txid}.bin` is
  the working dataset for any read; `update_quipu_data.py` refreshes it
  from the node. `colegio_tools` retains the live RPC readers.
- **Write pipeline**: `Cadena` / `CadenaAtom` (single strand), `Quipu` /
  `QuipuMulti` orchestrators (two-phase, single-sig and m-of-n), and
  `quipu_diamond.py` (many quipus in one funding tree, every tx priced
  by measured size). All proven on chain.
- **Broadcast at scale**: sign offline, then keyless resumable broadcast
  under a supervisor (`quipu_broadcast.py`), watched live by
  `quipu_loom.py`. Procedure in `docs/guides/broadcasting.md`. When a
  long broadcast stalls, relaunch and let it resume.
- **Canonical spec package**: `canonical/` implements builder + reader
  pairs for all twelve type bytes, with `tone.py` as the single tone
  source and embedded on-chain test vectors.
- **Publication**: `quipu_resolver.py` dispatches any txid to its
  renderer (scene walkthrough, book/essay PDF, image/celestial PNG) and
  registers the `quipu:` URI scheme; `colegio_pipeline.py` renders
  essays and books through `latex/colegio/colegio.cls`.
- **Streamlit interfaces**: `quipu_console.py` (plan / inscribe / read /
  wallet) and `quipu_viewer.py` (corpus graph with decode popups).

## What's still open

- **Dataset refresh** — see above; the CSV trails the chain by ~19,000
  blocks of inscriptions.
- **Estandarte v1** — the `0xee` registry type is implemented and
  documented but not yet inscribed. When it goes up it should flag the
  two pre-canonical inscriptions (`20db7d45…`, `a2e9f2eb…`) as
  deprecated.
- **0xda spec finalization** — deferred until new dancer datasets are
  ready; data model converged (frames + per-frame centroid +
  displacement + named-transition graph).
- **Book of 108** — the long-term consolidated fractal-diamond
  publication; design in `docs/design/book-108-cathedral.md`.
- **Museum / wilds / pet cemetery** — three-zone walkable corpus on
  `0x3d`; the cemetery validated the primitive.
- **Test harness** — `test_quipu_crypto.py` (23/23) and the canonical
  self-tests exist but are not wired into a pytest runner or CI.
- **Notebook reorganization** — the 20 cuadernos are moved to
  `notebooks/` in the working tree but the move is not committed.
- **`tag-architecture` branch** — design docs for tag architecture and
  corrected sale choreography, unmerged.

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

For a large inscription, read `docs/guides/broadcasting.md` first; for
many quipus at once, `docs/guides/consolidated-diamond.md`.

## Files of record

- `canonical/` — the protocol: builder/reader pairs for every type byte,
  `tone.py`, `structure.py`, `adaptor.py`, `nostr.py`
- `colegio_tools.py` — RPC, keys, Cadena writers, legacy readers
- `quipu_diamond.py` — consolidated-diamond builder (size-priced fees)
- `quipu_orchestrator.py` — `Quipu` / `QuipuMulti` two-phase state machines
- `quipu_broadcast.py` — keyless idempotent broadcast primitives
- `quipu_console.py`, `quipu_viewer.py`, `quipu_loom.py` — interfaces
- `quipu_resolver.py`, `scene_viewer.py`, `colegio_pipeline.py` — publication
- `update_quipu_data.py` — dataset refresh; `data/quipu_data.csv` +
  `data/bodies/` — the working dataset
- `docs/quipu-types/`, `docs/quipu-syntax/`, `docs/guides/` — specs and
  operating procedures
- `quipu_header_bytes.md` — observed header byte conventions
