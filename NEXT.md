# Next session — handoff: multisig writing (QuipuMulti orchestrator)

This is a handoff to a fresh session of Claude, opened in the project
repository. The user has been working with me through several sessions
and we've built a lot. Read **Where state currently is** before diving
into the new work.

## The new build — write quipus from a multisig address

The user has a fresh 2-of-2 P2SH multisig at
`A3ShjwjsAE4ysM66EZJM3A28tPnL2jNDgC` (apocrypha test), funded with
**40 DOGE** at tx
`2ea5daa18ae73e13ec9c9fb3f2bab306bccaa3a98fed449092051cd9d22ef395:1`
(confirmed live via `gettxout`). They want to **inscribe a quipu from
that multisig** — end to end, through the Streamlit console.

This is the multisig orchestrator build that's been deferred across
several sessions. The infrastructure exists in part but is broken; the
end-to-end orchestrator is missing.

### Step 1 — fix the broken multisig signing primitive

`colegio_tools.py` already defines `CadenaMulti` (line 250) and
`CadenaMultiAtom` (line 420), modelled on `Cadena` / `CadenaAtom`.
**Both have a typo bug:** they call `self.doge.mk_multsig_address(...)`
(missing the second `i`), which does not exist in the current `cryptos`
library version. The classes have never run successfully.

Fix:

```python
# OLD (broken):
self.script, self.addr = self.doge.mk_multsig_address(
    self.pubs, len(self.pubs)
)

# NEW (works — verified against the bordado 3-of-3 in this session):
self.script, self.addr = self.doge.mk_multisig_address(
    *self.pubs, num_required=len(self.pubs)
)
```

The pubkeys here need to be the `04`-prefixed uncompressed form
(130 hex) — `cryptos.Doge().privtopub(priv_hex)` already returns this.

The `script_magicbyte = 22` override line in those classes is no longer
necessary with the new API (the Doge() class handles P2SH magic on its
own) but leave it for safety.

### Step 2 — prove signing works

Standalone test (don't broadcast, just validate):

```python
import cryptos, colegio_tools as ct
# Use freshly generated test keys (not the user's real ones)
import ecies
k1 = ecies.utils.generate_eth_key().to_hex()[2:]
k2 = ecies.utils.generate_eth_key().to_hex()[2:]

# Sanity: confirm the address derives
doge = cryptos.Doge()
pubs = [doge.privtopub(k) for k in [k1, k2]]
script, addr = doge.mk_multisig_address(*pubs, num_required=2)
print(f"derived multisig: {addr}")

# CadenaMulti driving with a fake utxo (just to exercise signing)
fake_utxo = {"output": "0"*64 + ":1", "value": 100_000_000}
cm = ct.CadenaMulti([k1, k2], b"hello multisig", fake_utxo, 5_000_000)
cm.make_tx()  # should succeed silently — produces self.signed_inscribed_tx
print("multisig signing path works:", cm.signed_inscribed_tx is not None)
# Decode to confirm structure
import cryptos as _cs
decoded = _cs.deserialize(_cs.serialize(cm.signed_inscribed_tx))
print(f"  ins: {len(decoded['ins'])}, outs: {len(decoded['outs'])}")
```

If that prints `True` and you see the expected ins/outs, the primitive
is unblocked. **Do not broadcast** — the fake_utxo doesn't exist on
chain.

### Step 3 — write `QuipuMulti` orchestrator

In `quipu_orchestrator.py`, the existing `Quipu` class (line 46) is
single-key — it uses `self.priv` and calls `self.doge.signall(tx,
self.priv)` for root and join, and `CadenaAtom(self.priv, ...)` for
each strand.

Add a sibling class `QuipuMulti` that mirrors it, with these
differences:

```python
class QuipuMulti:
    """Multisig variant of Quipu. All listed private keys sign every tx
    (m=n cosigning). Mirrors Quipu's three-phase lifecycle exactly."""
    DOGE_P2SH_MAGIC = 22

    def __init__(self, privkeys_hex, utxo, strand_payloads,
                 tip=5_000_000, root_fee=5_000_000, join_fee=5_000_000):
        # ... same shape as Quipu.__init__ but:
        self.prvs = privkeys_hex       # list of priv hex
        self.doge = cryptos.Doge()
        self.doge.script_magicbyte = self.DOGE_P2SH_MAGIC
        self.pubs = [self.doge.privtopub(p) for p in privkeys_hex]
        self.script, self.addr = self.doge.mk_multisig_address(
            *self.pubs, num_required=len(self.pubs),
        )
        # ... rest unchanged

    def build_root(self):
        # Same shape as Quipu.build_root, but instead of
        #   signed = self.doge.signall(tx, self.priv)
        # do:
        n_inputs = 1  # root spends exactly one utxo
        for i in range(n_inputs):
            sigs = [
                self.doge.multisign(tx=tx, i=i, script=self.script, pk=p)
                for p in self.prvs
            ]
            tx = cryptos.apply_multisignatures(tx, i, self.script, *sigs)
        signed = tx
        # ... rest unchanged

    def precompute_strands(self):
        # Same as Quipu.precompute_strands but use CadenaMultiAtom:
        for i, payload in enumerate(self.strand_payloads):
            cad = CadenaMultiAtom(
                self.prvs, payload,
                {"output": f"{self.root_txid}:{i}", "value": self.strand_seeds[i]},
                self.tip,
            )
            cad.precompute()
            self.strands.append(cad)
        # ... rest unchanged

    def build_join(self):
        # N inputs (one per strand terminus) — must multisign EACH
        # input individually.
        tx = self.doge.mktx(inputs, [{"value": output_value, "address": self.addr}])
        for i in range(len(inputs)):
            sigs = [
                self.doge.multisign(tx=tx, i=i, script=self.script, pk=p)
                for p in self.prvs
            ]
            tx = cryptos.apply_multisignatures(tx, i, self.script, *sigs)
        # ... rest unchanged
```

The other methods (`broadcast_root`, `wait_root_confirmed`,
`broadcast_strands`, `wait_strands_confirmed`, `broadcast_join`) don't
care about signing — they just push hex to `sendrawtransaction`. They
can be inherited or copy-pasted unchanged.

### Step 4 — wire into the Inscribe tab

`quipu_console.py` Inscribe tab currently instantiates `Quipu(priv_hex,
utxo, all_payloads, ...)` using the loaded single privkey.

Pattern to add:

1. When the user picks a funding UTXO, check whether its address is at
   a multisig the session knows about — either:
   - The auto-computed multisig from currently-loaded 2+ keys, or
   - A loaded multisig from `st.session_state["loaded_multisigs"]`
2. If it's a multisig AND we have all the participants' privkeys
   loaded, use `QuipuMulti(prvs_list, utxo, ...)` instead of `Quipu`
3. If it's a multisig but we DON'T have all the participants' keys,
   surface a clear error: "Loaded only N of M required keys for this
   multisig; cannot cosign."

For your specific test case (2-of-2 with both keys loaded), the
detection is: `utxo.address == sidebar_multisig_addr` AND
`len(priv_keys) == 2` → use `QuipuMulti([k1, k2], ...)`.

### Step 5 — actually inscribe one

Once wired up:

1. Open Inscribe tab
2. Pick the multisig UTXO (`2ea5daa18ae73e13…:1`, 40 DOGE)
3. Pick a small Plan (e.g., a text quipu titled "Multisig test")
4. Run Phase 1 (build_root + broadcast_root + wait 1 conf)
5. Run Phase 2 (precompute_strands + broadcast_strands + wait)
6. Run Phase 3 (build_join + broadcast_join)
7. New quipu rooted at `<some_txid>`, multisig-cosigned, on chain

This is the **first end-to-end multisig inscription** in the project's
history. La Verna and Third Cert pre-funded roots can use the same
machinery once you scope the bordado 3-of-3 cosigning (which means H,
C, A all need to load their keys in the same session, or PSBT-style
round-robin between sessions).

## Known issues from the previous session

These weren't fully resolved and might bite you:

1. **Streamlit rerun storm + 80–116% CPU** under some conditions —
   diagnosed as fast reruns (113–373 ms apart), captured by an
   in-script `_diag_rerun_counter` that logs to stderr. The topology
   view (force-directed pyvis + cellular hull overlay) was the
   strongest suspect; it's now **off by default** behind a `☐ Render
   topology` checkbox in the Wallet tab. With the toggle off, fresh
   restarts sit at 0% CPU.

   Was *also* suspected to be triggered by an auto-import retry loop —
   that bug is fixed (`_imported_set.add(addr)` now happens *before*
   the RPC call, so a thrown exception doesn't keep us retrying every
   rerun). But the spin sometimes recurred even after the fix, so
   there may be another driver. The diagnostic counter is still in
   place at the top of the sidebar block — watch `/tmp/*.log` for
   `[rerun-counter] fast rerun` lines.

2. **Pruned-mode node** means `importaddress` with `rescan=true`
   fails. The "🔄 Rescan chain for this address" button surfaces the
   error but can't recover. The workaround: `gettxout <txid> <vout>`
   for known funding txs. There's a `_find_utxos_pruned_safe` helper
   I started writing but the user interrupted before it landed — see
   conversation transcript. The user's existing UTXO at the multisig
   was found this way (above).

3. **Notebook diffs** in `16_cuaderno.ipynb`–`19_cuaderno.ipynb` are
   Jupyter auto-save metadata noise and are deliberately *not*
   committed across sessions. Leave them alone unless the user asks.

## Where state currently is (2026-05-16, post-multisig-UI)

What was committed in `816f81e` (the previous big commit):
- Topology overhaul (strand-terminus consolidation, keydrop edges,
  multi-address combined view, cellular hull overlay, edge dedup +
  ×N labels with cap=54)
- `essay_renderer.py` typographic body renderer for text/identity/cert
  with `<<txid>>` references, embedded images, sig verification
- Multi-key sidebar with combined-key reader
- File upload / drag-drop for keyfiles
- Keys tab with Dogecoin keypair generation, AES key generation,
  multisig P2SH derivation
- Direct-pixel image rendering

What's still uncommitted (the in-flight work that this handoff
preserves):
- Folder picker (`_folder_input_with_browse` with macOS-native
  `osascript`-based 📂 Browse… button) in 4 sites
- "✨ Make a key" expander in sidebar with auto-load + folder-save
- "💾 Save multisig" expander in sidebar for the auto-computed multisig
- Sidebar "Loaded multisigs" section with 📥 Load expander, QR
  popovers, balance lookup, 🔄 Rescan (pruned-mode-fragile) button
- 📷 QR popovers on each loaded key row and the multisig address
- Combined pubkey hex (replaced the misleading derived address)
- ↻ Refresh balances button at sidebar top
- `_cached_rpc(method, params, ttl=10)` helper wrapping every sidebar
  RPC
- `_auto_import(addr, label)` that calls `importaddress(addr, label,
  False)` once per session — with the retry-loop fix
- Topology toggle (default OFF)
- Edge dedup with `×N` strand-count labels (capped at 54 for physics
  stability)
- `_diag_rerun_counter` diagnostic at top of sidebar

All committed together as one handoff commit (with this NEXT.md).

## Quick environment reminders

- Streamlit launch: `cd ~/Desktop/Colegio_Invisible && .venv/bin/streamlit run quipu_console.py --server.headless=true --browser.gatherUsageStats=false`
- The user's Dogecoin node is **pruned** — assume `rescan` doesn't work
- Git identity for this repo is **Christophia Hayagriva (ProfDoeg)** —
  never Anthony Schultz, never the Claude default
- The user prefers to commit specific files explicitly (skip the
  `16-19_cuaderno.ipynb` auto-save noise)
- Apocrypha is the test address (`D6zKNn…`); bordado is sacred
  (`9xth7D…`) — never test against bordado
