# Consolidated-diamond inscription — the canonical recipe

How to put **many quipus on chain together** in one funding tree (a "forest"),
so they can reference each other — including in cycles — and all confirm cleanly.
This is the codification of the cemetery / Gana-forest broadcasts. Read this
instead of reverse-engineering an old stage.

Engine: [`quipu_diamond.py`](../../quipu_diamond.py). Robust send/resume
primitives it builds on: [`quipu_broadcast.py`](../../quipu_broadcast.py).
Worked example: [`working/lineage/`](../../working/lineage) (the Gana forest,
on chain at block 6237154).

## The shape

```
one funder UTXO
  → splitter            1 in  → P outs (one per piece-root)
  → P per-quipu roots   1 in  → 1+N outs (header strand + body strands)
  → all strands         CadenaAtom chains, header = strand 0, body = strands 1..N, ≤24 knots each
  → mega-join           Σ strand-termini in → 1 out (residual back to funder)
```

`read_quipu` reconstructs each piece as **root:0 = header, root:1..N = body**.
So the engine splits every full quipu blob with `colegio_pipeline.split_blob`
into `(header, body)`, makes the **header strand 0**, and cuts the body into
contiguous ≤24-knot strands. (24 < the mempool ancestor limit of 25, so each
strand confirms in one wave.)

## Cross-references, even cycles

A piece references another by the other's **root txid**. A root txid is a
function of the body's **knot count (size)**, not its content, and a txid is
fixed length — so resolving a placeholder to a real txid never changes a size.
Therefore:

1. Build every body with **placeholder** refs (any 64-hex stand-in, right size).
2. Compute **all P roots at once** (none depends on content).
3. **Backfill** the real root txids into the referencing bodies — ASCII-hex in
   markdown/essay bodies, raw-32-byte in binary (0xce/0x3d) bodies. Sizes are
   preserved, so knot counts and roots are unchanged.

No build order, no cycle-breaking. The engine does the backfill generically:
give it `placeholder_of(pid)` (and `extra_placeholders` for any non-pid alias a
body embeds, e.g. an internal genealogy cross-link); it replaces every embedded
placeholder, in both forms, and asserts none remain.

## Fees — always the appropriate amount

**Every transaction pays `FeePolicy.rate_kb` DOGE per kilobyte of its ACTUAL
serialized size**, measured by signing a same-shape dummy (`_measure_tx_size`,
accurate to ±6 bytes), floored at `floor_doge`. Knots, splitter, every root, and
the mega-join are all priced the same way, by their own size.

Why this is canon: the first forest priced the mega-join *flat* (0.27 DOGE). It
was a 32 KB tx, so that worked out to **0.0084 DOGE/KB** — and it sat unmined for
many blocks while size-capping miners took smaller, higher-per-byte txs. The
**join is not replace-by-fee** (sequence `0xffffffff`), so it can't be bumped
after the fact — it must be priced right the first time. Size-pricing it (≈0.10
DOGE/KB → ~3 DOGE for 32 KB) makes it confirm in the next block.

Choosing `rate_kb` (DOGE/KB):

| reference | value | note |
|---|---|---|
| node relayfee | 0.001 | hard floor; nothing relays below it |
| observed miner inclusion floor | ~0.01–0.02 | full blocks descended to here |
| **economical** | **0.05** | ~3× the floor; reliable, cheapest sane |
| **default (reliable)** | **0.10** | ~5× the floor; prompt next-block confirmation |

Default is **0.10**. For a budget-tight inscription pass `FeePolicy(rate_kb=0.05)`
or set `RATE_KB=0.05`. The engine **refuses to underfund** (raises if the residual
would fall below dust). Calibrate `knot_tx_bytes` once (Gana: a knot tx is 315 B).

## The four steps

```bash
# 1. SIGN — you run this; getpass for the funder key. Spends nothing; writes artifacts/.
[RATE_KB=0.10] .venv/bin/python working/<stage>/build_consolidated.py
#    (DRY_RUN=1 first to validate the structure with a throwaway key.)

# 2. WATCH — textile loom, reads artifacts/, polls the node, never broadcasts.
.venv/bin/python working/<stage>/loom_monitor.py        # http://localhost:8765/ (or 8767)

# 3. BROADCAST — keyless, resumable, under a supervisor that relaunches on stall.
nohup .venv/bin/python working/<stage>/supervise_consolidated.py \
    > working/<stage>/supervise.log 2>&1 &

# 4. done when the loom shows the mega-join in a block / broadcast.log says "diamond closed".
```

Steps 1 and 3 are separate processes by design: **signing is reversible**
(nothing on chain), **broadcasting spends real DOGE** and needs an explicit go.

## API

```python
from quipu_diamond import FeePolicy, build_consolidated_diamond, write_artifacts, \
                          broadcast_consolidated_diamond

# SIGN (touches the key)
pieces = [(pid, full_quipu_blob_bytes), ...]          # order fixes splitter output index
art = build_consolidated_diamond(
    pieces, placeholder_of, utxo, priv, address,
    fee_policy=FeePolicy(rate_kb=0.10),
    extra_placeholders={some_alias_hex: "target_pid"})
write_artifacts(art, "working/<stage>/artifacts")

# BROADCAST (keyless)
broadcast_consolidated_diamond("working/<stage>/artifacts", log=...)
```

`build_consolidated_diamond` asserts, before returning: every backfill is
length-preserving, no placeholder survives, each piece's strands reconstruct its
backfilled blob (what the chain reader will rebuild), and all fee accounting
balances. `broadcast_consolidated_diamond` is idempotent — re-running only
(re)sends what the node has forgotten (`find_resume_index` / `send_if_needed`),
so kill+relaunch is always safe.

## Starting a new forest

Copy a stage (e.g. `working/lineage/{build,broadcast,supervise}_consolidated.py`
+ `loom_monitor.py`), then edit only:

- the **manifest** (`forest_manifest.py`): the pieces, their body files, the
  reference graph;
- **`placeholder_of`** + `extra_placeholders` to match the stand-in txids your
  bodies actually embed (`render_from_quipus.py` uses the same map);
- the funder address / key path.

Everything else — the split, the backfill, the size-priced fees, the weave —
comes from the engine.

## Gotchas (learned the hard way)

- **Header is strand 0.** Not optional — `read_quipu` requires it.
- **The join is not RBF.** Price it correctly the first time (this engine does).
  If one ever does get stuck, a CPFP only helps *ancestor-aware* miners; the
  durable fix is the right fee up front.
- **Strands ≤ 24 knots** so each is one ancestor wave (limit 25).
- **The corpus is readable without the join** — the join only consolidates the
  residual. Content lives under the roots, which confirm first.
- **Measure, don't guess, tx sizes.** The original underestimate (148 B/input;
  real ~180) is exactly how the join got underpriced.
```
