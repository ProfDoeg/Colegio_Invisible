# Estandarte inscription staging — constitution + legislation

**Two inscriptions, strict order.** The old single-payload
`estandarte_payload.json` (one parentless monolith carrying all 16 types +
conventions) is superseded by the constitution/legislation split
(docs/design/c1dd0000.md) and has been removed.

1. **`estandarte_v0_constitution.json`** — `c1dd0000ee`, version 0,
   reverence. The founding standard: the `0xee` self-entry + the nine
   cross-cutting conventions (incl. `tag` and `ripcord`). A root (no
   parent). Its bytes are final as staged and MUST equal
   `tests/golden/constitution_c1dd0000ee.hex`. Inscribed FIRST, under the
   ACH 3-of-3 — **with its ripcord armed** (below).

2. **`estandarte_v1_registry.json`** — `c1dd0001ee`, version 1, ordinary.
   The legislation: 15 type entries; the `0xee` entry and all conventions
   inherit from the constitution. The staged bytes are the ROOT FORM
   (parentless) for content review only — they match
   `tests/golden/registry_v1_c1dd0001ee.hex` and are NOT inscription-ready.
   At the ceremony, after the constitution confirms, REBUILD with its root
   txid:

       from registry_v1 import build_registry_v1, preflight_inscription_form
       h, b = build_registry_v1(parent_txid=<constitution root txid>)
       preflight_inscription_form(h, b)   # refuses the parentless form

   The rebuilt bytes differ from the staged root form ONLY by the 33-byte
   parent prefix (`0x01` + txid replacing `0x00`).

## The ripcord (constitutional amendment cord)

The constitution's `ripcord` convention requires every registry root to
carry an amendment cord: its **first non-strand output**, encumbered to the
then-current authority. The successor's root spends it as **input 0** —
succession unique by the double-spend rule (`constitution.RIPCORD`,
`quipu_tags.follow_ripcord`, `quipu_preflight.check_ripcord`).

**v0 build:** compute the 3-of-3 P2SH from the ACH pubkeys at ceremony,
then pass the cord to the diamond engine:

    tags_of={"v0": [{"value": RIPCORD["seed_sat"], "address": <P2SH 3-of-3>}]}

The cord lands at `vout = n_strands` (engine convention), never consumed
by the join, sitting intact after inscription.

**v1 build:** the v1 root takes v0's cord outpoint as **input 0**, seeds
its strands, and emits its OWN fresh cord (first non-strand output,
re-encumbered to the current authority).

> **TOOLING TO BUILD (honesty flag — audit 2026-07-12):** no builder can
> construct this root today. `build_consolidated_diamond` gives every
> root exactly one input (its splitter output) and accepts no external
> input; the 3-of-3 CHECKMULTISIG spend needs
> `cryptos.apply_multisignatures` (the N-sig path used by
> `quipu_orchestrator.build_root`), NOT `multisign` (single-sig IF-branch
> HTLC machinery). Required before any ceremony: a **ceremony root
> builder** — [cord P2SH input 0 + funding input] → [strand seeds +
> fresh cord], N-of-N signed, with the strand weave continuing from the
> hand-built root. The mandatory rehearsal below exists precisely to
> force this tool into existence at throwaway stakes.

Before signing, BOTH gates must pass:

    check_ripcord(v0_root_hex, v0_n_strands, v1_root_hex, v1_n_strands,
                  successor_blob=h + b)      # thread + text agree
    # and preflight_inscription_form(h, b) — already inside check_ripcord

**MANDATORY REHEARSAL (before the real ceremony):** one throwaway mainnet
diamond with a 3-of-3 cord → spend it into a tiny successor root emitting
a continuation cord → `follow_ripcord` must resolve both hops. Proves
relay acceptance of the script class end-to-end for under a DOGE. The
constitution is never the first performance of anything.

A resolver walking leaf(v1) → root(v0) composes the full registry:
16 types + 9 conventions (`tests/test_registry_v1.py` proves composition,
coverage of every on-chain type byte, and the freeze;
`tests/test_ripcord.py` proves the cord walk and the ceremony gate).

Neither is inscribed yet. No estandarte exists on chain; until inscription
the goldens are the groundtruth.
