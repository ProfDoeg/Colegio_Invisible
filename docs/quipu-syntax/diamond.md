# The Diamond Pattern

> **STATUS: CANONICAL.** Every quipu of non-trivial length on Dogecoin
> is inscribed as a *diamond* of transactions. The shape is fundamental
> to the protocol and is referenced by every type spec.

A single Dogecoin OP_RETURN holds at most 80 bytes of payload. To
inscribe more than 80 bytes, the protocol splits the payload across
many transactions arranged in a **diamond** shape:

```
                         root
                  (1 tx, N outputs)
                  /     |       \
                 /      |        \
            strand_0  strand_1  …  strand_{N-1}
            (chain)   (chain)      (chain)
                 \      |        /
                  \     |       /
                         join
                  (1 tx, ≤2 outputs)
```

- The **root** transaction has N outputs of equal value, each seeding
  the start of one strand.
- Each **strand** is a linear chain of transactions, each carrying one
  OP_RETURN with ≤ 80 bytes of payload, spending forward to the next
  tx in the strand.
- The **join** transaction consumes the terminal output of every
  strand into a single tx, marking the diamond closed.

## Numbering

Strands are numbered `0..N-1` by the output index of the root that
seeds them. Strand 0 is the **cabeza** ("head") — it carries the
inscription's structural header. Strands `1..N-1` are **cuerpos**
("bodies") — they carry the inscription's body in order.

## Reading a diamond

A reader walks the diamond by:

1. Starting from either the root txid or the join txid
2. Locating the root (root has N≥2 outputs of equal value; join has 1)
3. For each output `0..N-1` of the root, walking the strand forward
   collecting OP_RETURN payloads until the join is reached
4. Concatenating cabeza bytes (strand 0) followed by cuerpos bytes
   (strands 1..N-1, in order) yields the full inscription payload

The canonical walker is `colegio_tools.read_quipu(root_txid)` for the
forward walk from a known root, and `colegio_tools.fetch_quipu_bytes(txid)`
for the auto-classifying walker that accepts either root or join.

## Citation

A diamond is identified by **its root transaction txid** — that's the
canonical reference for the inscription as a whole. The citation
syntax `<<txid>>` always means the root txid.

This is structural, not stylistic. The root txid is determined the
moment the root tx is signed; the join txid only comes into existence
after every strand has closed. In a consolidated-diamond forest (where
many quipus are inscribed in one funding tree and may cross-reference
each other) no join exists at the time any body is being written —
the only txid available to cross-reference is the root. Citation by
root is therefore the only convention that works for both standalone
and consolidated inscriptions.

The join txid is real and recorded, but it is an artifact of the
diamond closing, not the inscription's identity.

## Why this shape

- Per-tx OP_RETURN cap: 80 bytes. A diamond of N strands × K
  transactions per strand carries up to N × K × 80 bytes of payload.
- Mempool ancestor cap: Dogecoin Core enforces a maximum of 25
  unconfirmed ancestor transactions per chain. A single linear
  inscription chain is capped at 25 txs (~2 KB); a 5-strand diamond
  raises the ceiling to 5 × 25 = 125 txs (~10 KB) without waiting
  on confirmations between them.
- Parallel inscription: each strand can be broadcast independently,
  cutting wall-clock inscription time for large payloads.
- Atomicity at the join: an inscription is "complete" exactly when
  the join confirms. A reader who sees the join can be sure the
  whole payload is final on chain.

## Fee policy

Each strand transaction pays a tip large enough to clear the
effective mining floor (currently ~0.2–1 DOGE/KB depending on the
pool). The orchestrator's `scaled_fee` helper computes per-tx fees
from a target DOGE/KB rate. The root and join transactions are
typically larger than strand interior txs (the root because of its
N outputs, the join because of its N inputs) and use the same rate.

If strands stall in mempool, CPFP via the join is the canonical
recovery move — a high-fee join lifts the entire `{strands + join}`
package above the mining floor by package-fee policy.

## Broadcasting one

This spec is the *shape*. For the *operational* side — signing the
diamond offline, broadcasting it keylessly, surviving dropped mempool
entries and stalled RPCs, resuming a half-finished weave, and watching
it land block by block — see the guide at
[`../guides/broadcasting.md`](../guides/broadcasting.md).

## Historical note

The diamond shape was settled before the canonical type formalization
and is observed across every multi-tx inscription on chain (the
La Verna and Domremy certificates, Sabina, Monte Veritá, Sky of
al-Jawza, the encrypted family test suite, every essay-length text
quipu). The pattern is not part of any single type's spec — it lives
at the protocol level and applies uniformly to all types.
