# Book of 108 — Cathedral Inscription Pattern

> **STATUS: DESIGN.** No book-of-108 inscription exists yet. This document
> records the intended topology so the build-time code, fee math, and
> protocol semantics can be implemented when the corpus is ready.

A future inscription will publish **108 essays plus a book-level apparatus
(forward, introduction, structure description, concept-map analysis)** as
a single consolidated cathedral diamond on Dogecoin. Each essay is paired
with a photograph of a handwritten copy of the essay against a shared
textile background.

This document describes the inscription topology, the fee math, and the
two structural principles that distinguish the cathedral from a simple
list-of-quipus pattern.

---

## The two structural principles

**1. Each essay is a self-contained pair.** Every one of the 108 essays
is inscribed alongside a photograph of its handwritten copy. The pair
(prose + image) is bound by a small wrapping `0x09` book quipu whose
two entries are the prose and the image — the **per-essay-pair**. The
pair's root txid is the essay's canonical identifier.

**2. The book grows out of the essays.** The book-level apparatus —
forward, introduction, structure description, concept-map analysis —
is funded entirely by the **collective tails of the 108 essay-joins**.
There is no separate splitter share for the book. The meta-text
literally cannot exist without the essays sustaining it.

A reader walking the chain backward from the grand-join encounters
forward → intro → structure → concept-map → and at every step learns
that this apparatus is sustained by the 108 below. Each essay can stand
alone (its per-essay-join is a valid quipu identity), but the
apparatus depends on all of them.

---

## Topology — the cascade

```
                       apocrypha utxo
                              │
                              ▼
                      GRAND-SPLITTER         1 in → 108 out
                              │
            (108 per-essay-splitters in parallel)
                              │
                     essay-roots + photo-roots
                              │
                     all strands (modulo-distributed)
                              │
                     (108 per-essay-joins)
                              │
                       108 tails total
                              │
                              ▼
                  BOOK-FUNDING-CONSOLIDATOR    108 in → 4 out
                              │
                  (4 book-essay-roots: forward, intro,
                   structure, concept-map analysis)
                              │
                       (book-essay strands)
                              │
                              ▼
                       GRAND-JOIN             8 in → 1 DOGE residual
```

Three "splits" (grand, per-essay, book-funding) and one final join. Two
confirmation-wait checkpoints punctuate the broadcast (after all
per-essay-joins; after all book-essay strand termini), each required
to avoid Doge's `too-long-mempool-chain` rejection.

### Per-essay diamond (108 of these)

Each one inscribed identically:

```
   per-essay-splitter (1 in → 2 out)
     ├─ essay-root (0x01 essay quipu)
     │    └─ cabeza strand + body strands
     └─ photo-root (0x03 image quipu)
          └─ cabeza strand + body strands (modulo-distributed)
   …all strands run in parallel…
   per-essay-join (essay+photo strand termini → 1 out tail)
```

The per-essay-join's output ("the tail") flows downstream into the
book-funding-consolidator.

### Book-funding-consolidator

A single transaction with **108 inputs and 4 outputs**. It is structurally
both a join (for the 108 essay tails) and a root (for the 4 book-essays).
Its 4 outputs fund:

1. **forward** — the author's voice opening the book
2. **introduction** — frames the corpus
3. **structure** — explains the topology, why 108, how to read
4. **concept-map analysis** — describes the citation graph of the 108

Each book-essay is itself a 0x01 essay quipu with its own root, strands,
and strand-termini. Their termini feed the grand-join.

### Grand-join

The final transaction. Inputs: all book-essay strand termini (8 if each
book-essay has cabeza + body, more if bodies are split). One output: the
**1.00 DOGE residual** flowing back to the source address.

---

## Fee budget

Assuming each essay ≈ 150 knots and each photo @ 800×600 grey 5-bit
≈ 3,750 knots, so each essay-pair = ~3,900 strand knots:

### Per essay-pair

```
   strand fees  (~3,900 knots × 0.05 DOGE)        195.00
   per-essay-splitter fee                            0.05
   2 per-quipu-root fees                             0.10
   per-essay-join fee                                0.05
                                                ────────
   total spent per essay-pair                      195.20
   per-essay-join TAIL output                        0.55  ← flows downstream
   per-essay-splitter input from grand-splitter =  195.75
```

### Aggregated

| component                            | count | DOGE   |
|--------------------------------------|-------|--------|
| essay+photo strands                  | 108×3,900 | 21,060 |
| grand-splitter + per-essay-splitters | 109   |     5.45 |
| per-quipu-roots                      | 216   |    10.8  |
| per-essay-joins                      | 108   |     5.4  |
| book-funding-consolidator            | 1     |     0.05 |
| book-essay-roots                     | 4     |     0.2  |
| book-essay strands                   | ~800  |    40    |
| grand-join                           | 1     |    ~37   |
| **total fees**                       |       | **~21,158** |
| **+ residual**                       |       |       1.00 |

Total funding budget: **~21,159 DOGE**.

### Tuning knobs

- **Photo bit-depth / resolution** dominates cost. 5-bit grey at 800×600
  is the recommended baseline (~187 DOGE/photo); 4-bit grey halves photo
  detail and saves ~13%; 664×500 saves ~30% but compresses textile texture.

- **Grand-join fee** absorbs final tuning slack. The aggregate of 108
  essay tails is fixed once per-essay-pair sizing is chosen; everything
  downstream — book-essay strand fees, grand-join fee, residual — is
  determined by what those tails carry. The grand-join fee can be dialed
  ±30 DOGE without changing total cost.

---

## Broadcast sequence

```
   1.  grand-splitter
   2.  108 per-essay-splitters (parallel)
   3.  216 per-quipu roots (parallel)
   4.  ~21,000 strand knots (modulo, parallel waves of 25)
   5.  WAIT for all strand termini to confirm in a block
   6.  108 per-essay-joins (parallel)
   7.  WAIT for all 108 per-essay-joins to confirm  ← critical
   8.  book-funding-consolidator (108 in → 4 out)
   9.  4 book-essay-roots (parallel)
   10. ~800 book-essay strand knots (parallel waves)
   11. WAIT for book-essay strand termini to confirm
   12. grand-join (8 in → 1 DOGE residual)
```

**Why the step-7 wait is required:** the book-funding-consolidator
spends 108 essay-join outputs. Each essay-join was *itself* the
descendant of ~3,900 strand knots + roots + splitters. If even one
of those ancestors is still unconfirmed in mempool when we try to
broadcast the consolidator, Doge rejects it with `too-long-mempool-chain`
(the 25-unconfirmed-ancestor limit). The wait forces all essay-join
ancestors to mine before the consolidator's broadcast attempt.

Approximate wall time, with wide modulo-distributed strands and parallel
broadcast: **15-30 minutes**, dominated by block-confirmation waits at
steps 5, 7, and 11 — not by RPC throughput or signing.

---

## What this reuses

Every primitive is already in the codebase as of `c209d3c`. The build
script needs to extend the single-level consolidated diamond pattern
(from the [Goethe Hebrew corpus](../../working/goethe_hebrew/)) to a
two-level cascade.

- **0x01 essay type** with citation aliases + fenced binding blocks
  (`canonical/essay.py`, `docs/quipu-types/essay.md`).
- **Multi-quipu consolidated diamond** (`working/goethe_hebrew/build_consolidated.py`,
  `broadcast_consolidated.py`) — one splitter, parallel per-quipu roots,
  parallel strands, one mega-join. The cathedral nests this pattern.
- **Modulo strand distribution** (`knots[i::N]`) — required for the
  photos to keep per-strand wave counts low and broadcast time tractable.
- **Idempotent/resumable broadcast** — `broadcast_consolidated.py` already
  detects on-chain state and resumes from any interruption point.
- **Build-then-substitute-real-txids** — placeholders during deterministic
  build, real values substituted into binding blocks after roots are
  known but before strand precompute.

---

## What's still TBD

1. **Recursive build script** — extend the single-level pattern to two
   levels. The build computes txids in dependency order:
   apocrypha-utxo → grand-splitter-txid → per-essay-splitter-txids →
   per-quipu-root-txids → strand-txids → per-essay-join-txids →
   book-funding-consolidator-txid → book-essay-root-txids → book-essay-strand-txids
   → grand-join-txid.

2. **Handwriting photo pipeline** — a notebook that accepts raw photographs,
   does crop / denoise / white-balance / downsample / bit-quantize, and
   emits inscription-ready bit-packed bodies.

3. **Concept-map analysis quipu** — decide the form:
   - 0x01 essay with structured binding-block glossary + prose commentary
   - 0xab binding (canonical glossary, no commentary)
   - new 0x05 graph type (structured nodes + edges)
   - 0x03 image rendering of the force-directed graph

4. **Book TOC / structure quipu** — probably a 0x01 essay with a markdown
   ordered list. Could be a new structured type if queryable TOC is wanted.

5. **The 108 essays themselves** — Anthony writes them. The 108 number is
   load-bearing (Hindu/Buddhist tradition: 108 desires, 108 beads, 9×12);
   don't second-guess it. The relative ordering and the chosen essays are
   Anthony's call.

---

## Cross-references

- [`docs/quipu-types/essay.md`](../quipu-types/essay.md) — the 0x01 essay type spec
- [`docs/quipu-types/text.md`](../quipu-types/text.md) — the 0x00 text type spec
- [`docs/quipu-syntax/citations.md`](../quipu-syntax/citations.md) — citation grammar
- [`docs/guides/writing-essays.md`](../guides/writing-essays.md) — practical guide for inscribers
- [`working/goethe_hebrew/`](../../working/goethe_hebrew/) — the first consolidated multi-quipu
  inscription, prototype for the cathedral

## Zero errata — the engineering gates

> Mandated 2026-06-10, after the Dantean Cosmos shipped with a phantom
> reference that passed every byte-fidelity check. The cathedral gets
> the discipline the forest lacked. ~21,000 DOGE buys no second chances.

Failure taxonomy, each class with its gate; a class without a gate does
not fly:

| failure class | worked example | gate |
|---|---|---|
| dangling reference (stand-in never backfilled) | the orrery phantom | `quipu_preflight.check_refs_resolve` — every 64-hex token resolves or is declared; runs at BUILD and at BROADCAST |
| wrong-but-existing reference (swapped targets) | two essays showing each other's plates | `check_ref_graph` — the extracted citation graph must EQUAL the declared manifest exactly; default-deny, every piece declares |
| bytes diverge from what was signed | — | preflight reassembles every body FROM THE SIGNED TX HEXES and compares |
| body that will not decode from chain | — | every reassembled body parses through its canonical reader |
| content errors a machine cannot judge (wrong draft, typo, wrong photo) | — | **the galley seal**: the full book is rendered from the reassembled signed bytes, proofread by a human, and `approve_galley` binds the sign-off to a SHA256 of those bytes; broadcast with `require_approval=True` refuses a missing or stale seal |
| non-contiguous strand distribution | Jeremy's interleave | canonical `split_body` + the anti-round-robin test |
| fee underpricing (join sits unmined) | the first forest's flat join | `FeePolicy` prices every tx by measured size |
| stalled broadcast | — | keyless resumable supervisor (proven at 22,377 knots) |
| stale knowledge of the chain | the gate refusing Bode's real root | refresh the dataset before build; `known_txids` only for roots verified out-of-band |

The 108 build therefore REQUIRES, mechanically:

1. A **reference manifest**: every piece's expected citations declared
   in the build script; `expected_refs` passed to build AND broadcast.
2. A **content freeze**: source files hashed into the manifest before
   signing; any change re-runs everything downstream.
3. The **galley seal**: proofread the render of the reassembled signed
   bytes — not the working drafts — then `approve_galley`. The approval
   is a hash; touching anything voids it.
4. A **mainnet rehearsal**: a pilot mini-book (3 essays + photos, same
   pipeline, same gates, same scripts) inscribed end-to-end before the
   cathedral. Cathedrals are built by crews that have built a chapel.
5. **Corrections doctrine stands regardless**: if something still slips
   through, the 0xab overwrite layer at the cathedral's own address is
   the named remedy (bindings.md § Corrections) — but it is the fire
   escape, not the plan.
