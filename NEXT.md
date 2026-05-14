# Next session — handoff: topology strand-terminus consolidation

The previous task (keydrop display + AES-sealed sub-family + broadcast
write path) shipped in commit `0c3b039`. Encrypted quipus now decrypt
inline in all three reader sites; Plan tab supports `None / AES /
ECIES Broadcast` with address-and-combined-key recipients.

The **next build** is a focused visual improvement to the quipu map:
**show strand-terminus consolidation/export so the topology accurately
reflects the in-and-out flow of the address space.**

## The problem

`compute_quipu_topology` in `quipu_console.py` traces only **backwards**
from each quipu's root (funding lineage). It draws `quipu_root`,
`joining`, `bridge`, `external` nodes for the funding ancestors but
never looks **forward** from the strand termini.

Result: when a quipu's N strand termini are all consumed in a single
outgoing transaction (consolidation or export), the visual still shows
them as N dangling tails — as if unspent. Same in the broom-head/forest
view (`build_history_dot`), which only marks `(unspent)` for
strand_length == 0 and otherwise just leaves the terminus node hanging.

Example: txid
`014123b21a99b50e28219522af50a7a970dd3f8feeb0dd1d07e4ab2d384b40d1`
("Paco's quipu") — all strand termini are spent in the same outgoing
tx, but the map renders them as separate tendrils.

## What "consolidation" vs "export" mean here

For each strand terminus T:
- T's last output (typically `T:0`, since strand chains are 1-in/1-out)
  is spent in some transaction S.
- If **S's outputs land back in the watched address(es)** → consolidation.
  S is a "joining" tx — same kind we already model for funding.
- If **S's outputs land at addresses not in the watched set** → export.
  The quipu's outputs have left the embroidery space.
- If no S exists → the terminus is genuinely unspent.

If multiple strand termini share the same S, they should converge into
ONE node, not appear as separate tendrils.

## Data already available

Each quipu dict already carries:
- `"strand_termini": [txid, txid, ...]` — last OP_RETURN tx in each strand
  (computed at [quipu_console.py:592–615](quipu_console.py:592))
- `"strand_lengths": [n, n, ...]` — strand depths

`df_out` columns: `txout`, `spent_in`, `value`, `op_return`,
`blockheight`, `blocktime`, `txid`, `n`. The `spent_in` field is exactly
what we need — for `<terminus_txid>:0` it points to the tx S that
consumed it (or is empty if unspent).

To distinguish consolidation vs export, look up S in `df_tx`:
- If S is in `df_tx` (i.e., the wallet has seen it as wallet-relevant
  via `listtransactions`), then its outputs touch watched addresses
  somewhere — **consolidation**.
- If S is NOT in `df_tx` but `gettxout` returns nothing for the
  terminus (meaning it IS spent, just not by a wallet-relevant tx),
  then S has gone to addresses outside the watched set — **export**.
  In practice `df_out`'s `spent_in` only gets populated for wallet-
  visible spends, so absent `spent_in` plus a spent UTXO = export.

For a true export, we still want to draw a node — labeled differently
so the user sees "this quipu's outputs left the address."

## Implementation plan

### 1. Extend `compute_quipu_topology` with a forward pass

After the existing backward funding-trace loop, add a **forward**
pass: for each quipu, walk each strand terminus's spend.

```python
# Forward pass: trace strand-terminus consolidation/export
for q in quipus:
    root = q["root_txid"]
    for s_idx, terminus in enumerate(q["strand_termini"]):
        if not terminus:
            continue  # unspent strand — leave it dangling
        # Find what spent terminus:0
        spent_in_rows = df_out[df_out["txout"] == f"{terminus}:0"]
        if spent_in_rows.empty:
            continue
        spend_tx = spent_in_rows.iloc[0]["spent_in"]
        if not spend_tx or (isinstance(spend_tx, float) and spend_tx != spend_tx):
            continue
        # The terminus is spent in spend_tx. Classify:
        if spend_tx in df_tx_by_id.index:
            parent_row = df_tx_by_id.loc[spend_tx]
            n_in = int(parent_row["num_inputs"])
            n_out = int(parent_row["num_outputs"])
            if spend_tx not in nodes:
                # Consolidation = ≥2 inputs, ≤ inputs outputs
                # Could also be a 1-in-1-out bridge if a strand was
                # spent alone (rare for quipus). Use joining-like
                # classification:
                kind = "consolidation" if n_in >= 2 else "bridge"
                nodes[spend_tx] = {
                    "kind": kind, "txid": spend_tx,
                    "n_in": n_in, "n_out": n_out,
                    "blocktime": int(parent_row.get("blocktime", 0) or 0),
                }
        else:
            # Spend tx not in df_tx → outputs leave the address space
            if spend_tx not in nodes:
                nodes[spend_tx] = {
                    "kind": "export", "txid": spend_tx,
                }
        # Edge: terminus → spend_tx (forward)
        # But terminus may not be a node yet — strand interior is
        # not in the topology. Edge from quipu root would skip the
        # strand. Better: add terminus as a "strand_terminus" node.
        terminus_id = f"term::{root}::{s_idx}"
        if terminus_id not in nodes:
            nodes[terminus_id] = {
                "kind": "strand_terminus",
                "txid": terminus,
                "of_quipu": root,
                "strand_index": s_idx,
                "spent": True,
            }
        edges.append((root, terminus_id))   # synthetic root → terminus
        edges.append((terminus_id, spend_tx))
```

Caveat: for unspent strands, you may still want to add a terminus
node (kind `strand_terminus`, `spent: False`) so the visual stays
consistent — N strand stubs per quipu. Or just leave them implied
(empty).

### 2. Render the new node kinds in `render_topology_pyvis`

Add cases for `consolidation`, `export`, `strand_terminus`:

```python
elif kind == "consolidation":
    net.add_node(txid, label=f"join←{info['n_in']}",
        title=f"Consolidation: {info['n_in']} strand termini "
              f"merged here\n{txid}",
        color="#8eb88e", size=14, shape="diamond")
elif kind == "export":
    net.add_node(txid, label="↗ out",
        title=f"Export: spend left the address space\n{txid}",
        color="#c78686", size=12, shape="triangle")
elif kind == "strand_terminus":
    spent = info.get("spent", False)
    net.add_node(txid, label="·",
        title=f"Strand {info['strand_index']} terminus of "
              f"{info['of_quipu'][:8]}…\n{info['txid']}",
        color="#bbbbbb" if spent else "#eeeeee",
        size=6, shape="dot")
```

Color scheme suggestion:
- consolidation (back to watched address) = same green as cert quipus
  to suggest "remains in the embroidery"
- export (leaves watched space) = red-tone, suggests "departed"

### 3. Update broom-head forest similarly (optional)

`build_history_dot` draws a tree per quipu. For each terminus add a
sink node downstream, labeled "→ consolidation" or "→ exported" or
"(unspent)". When N strand termini share the same spend_tx, point all
of them to a single sink node (graphviz handles this naturally — same
`{spend_id}` referenced by multiple edges).

### 4. Test against the real chain

- Apocrypha has multiple quipus; pick one where you've explicitly
  consolidated (Sabina was joined into a Cadena join tx per memory).
  Expected: all strand termini converge at the join node.
- The Paco quipu
  (`014123b21a99b50e28219522af50a7a970dd3f8feeb0dd1d07e4ab2d384b40d1`)
  — verify its strand termini all merge at one node, no tendrils.
- For an unspent quipu (newer inscriptions) — strand termini render
  as faint stubs, no join node.

## Caveats

1. **`df_out` is wallet-scoped.** If a strand terminus is spent by a
   tx involving only non-watched addresses, `spent_in` is empty.
   `gettxout` is the authoritative "is it spent" check but doesn't tell
   you the spender. For a full picture you'd need a chain-wide forward
   index. For v1, "wallet-visible spend → consolidation, otherwise
   either unspent or export" is a fine heuristic — the visual just
   needs to be honest about which it is. Possibly add a separate
   `gettxout`-driven pass to distinguish "unspent" from
   "spent-but-spender-not-watched".

2. **Strand termini may already exist as `bridge` nodes.** The backward
   pass adds nodes for any funding ancestor. If one quipu's terminus
   funds another quipu's root, the terminus is already a node (kind
   `bridge` or `joining`). Be careful not to overwrite — check
   `nodes` membership and pick the more-informative label
   (`strand_terminus` should win over generic `bridge`).

3. **Edge multiplicity.** Adding root → terminus → spend creates two
   new edges per strand. For a 5-strand quipu that's 10 new edges.
   Pyvis handles this fine but the force-directed layout may need
   tuning (the `spring_length` in `barnes_hut` may want to drop a
   touch).

4. **Performance.** The forward pass is O(quipus × strands), each step
   one `df_out` lookup. Cheap compared to `scan_accounts`. No new RPC
   calls.

## Files to touch

- [quipu_console.py](quipu_console.py) — `compute_quipu_topology`
  (forward pass), `render_topology_pyvis` (new node kinds),
  optionally `build_history_dot` for the forest view
- No `colegio_tools.py` changes expected — all the data is already in
  `df_out` / `df_tx`.

## Beyond this build

Once consolidation is visible, these become natural follow-ups (from
the discussion earlier):

- **Address space boundary** — a soft enclosure around watched-
  address nodes; everything outside is funding-source or export.
- **Keydrop ↔ encrypted edges** — dashed edge between a keydrop quipu
  node and the encrypted quipu it unlocks. `find_keydrop_for` already
  detects these.
- **Time-aware layout** — fix Y positions by blocktime so the topology
  is also a timeline.
- **Cross-quipu funding edges** — when a strand terminus funds another
  quipu's root, label that edge as "→ quipu N+1" explicitly.

## Where state currently is (2026-05-14, post-encryption build)

- 25 quipus on apocrypha; broadcast/keydrop pairs `d0209a…↔89b51b…`
  and `d68175…↔f278e4…` decrypt inline in the console
- No `0x0e 0xae` quipu inscribed on chain yet — first-light AES-sealed
  inscription on apocrypha is also a natural next task (smaller in
  scope than the topology rework)
- Streamlit console runs at http://localhost:8501; launch with:
  ```
  cd ~/Desktop/Colegio_Invisible
  .venv/bin/streamlit run quipu_console.py
  ```
- Latest commit on `main`: `0c3b039` (encrypted-quipu support)
