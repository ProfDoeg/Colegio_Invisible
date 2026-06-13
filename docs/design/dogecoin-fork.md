# Dogecoin Core fork: native quipu — design plan

*Loose design, 2026-06-13. A fork of dogecoin/dogecoin (1.14) that understands
quipu natively: reading, writing, scanning as first-class node features, with
literature (LaTeX) and 3D rendering as a client layer on top.*

---

## The shape: three layers

The instinct "port as much to C++ as possible" is right, but the daemon should
stay an **engine**, not an everything-machine. Three layers, by what each is:

```
  L3  CLIENT     rendering · LaTeX · 3D · UI        Python / JS / a desktop app
                 (talks to L1 over RPC)             — stays OUT of the daemon
  ─────────────────────────────────────────────────────────────────────────
  L1  ENGINE     quipuread / quipuwrite / scan      native C++ in dogecoind
                 + crypto, wallet, broadcast        (new src/rpc/quipu.cpp)
  ─────────────────────────────────────────────────────────────────────────
  L2  FORMAT     libquipu — every type's            C++ library, linked by L1
                 parse/build (the wire format)      ported from canonical/*
```

L2 is the bulk of the port and the heart of the protocol; L1 wires it to the
chain; L3 is what we already have, repointed at the native RPC. The reason
LaTeX and 3D do **not** go in the daemon: a consensus node has no business
shelling out to xelatex or rasterizing scenes — those are client concerns, and
keeping them out keeps the fork lean, auditable, and mergeable-upstream-shaped.

---

## The central decision (RESOLVED): the purse and the catalog

A quipu is read by walking a chain of self-spending transactions, collecting
each OP_RETURN. At every step you hold an outpoint `(txid, vout)` and must find
**the transaction that spends it**. That reverse lookup is the whole ballgame —
and Dogecoin 1.14 does **not** have it out of the box:

- `GetTransaction()` (validation.cpp:1073) gives txid → tx (via `-txindex`).
- There is **no** spent-index / address-index — confirmed by the scout
  (no `spentindex`, `addressindex`, `GetSpentIndex`, `fAddressIndex` anywhere).
- The UTXO set (`pcoinsTip`) tracks what's *unspent*, not who spent what.

One *could* lean on the wallet for this — `CWallet::mapTxSpends` already maps
outpoint → spending wtx for watched coins, which is exactly what the Python
toolkit does today (watch the quipu addresses, read their txs via
`listtransactions`). **We reject this.** The symptom of that approach is already
on disk: the current node's wallet holds **88,882 transactions / 65 MB**,
because every knot of every inscription at a watched address lands in
`mapWallet` — `<<coasts>>` alone added ~13,774. The wallet is accumulating
*public data pretending to be money*.

**The decision: separate the purse from the catalog.**

- **The wallet is a purse** — only what you *sign*: your own keys and the UTXOs
  you spend to fund inscriptions. It stops watching quipu addresses; the dust
  knots leave it. Lean again.
- **A purpose-built quipu index is the catalog** — what you *read*: public
  quipu, anyone's, by txid, with nothing imported. This is the read substrate.

The index is the Dash / Bitcoin-ABC-style pair, written in `ConnectBlock` and
unwound in `DisconnectBlock`, behind a `-quipuindex` flag (needs a one-time
`-reindex` to populate):

| Index | Maps | Powers |
|---|---|---|
| **spentindex** | outpoint → spending txid | the strand walk (`quipuread`) |
| **addressindex** | address → txids (+ heights) | quipu discovery (`quipuscan`, `quipuroots`) |

This is what makes it a **true quipu node**: the *node* understands quipu, not
"your wallet happens to watch the right addresses." Reading is a property of the
chain, not of your keys — which is correct, because quipu are public.

> Cost accepted: ~500–1000 lines (a known patch to port from reference) + a
> one-time reindex of the 210 GB archive (hours, once, on the M5 Max).
> Migration win: after the index lands, the main wallet can be replaced with a
> fresh lean one (or the watched addresses dropped) — the 88k dust txs retire.
>
> Optional throwaway: a 2-day wallet-scoped `quipuread` via `mapTxSpends` can
> prove the L1↔L2 decode path *before* the index is built, then be discarded.
> It is scaffolding, not the design.

---

## Layer 1 — the native engine (C++ RPC)

New file `src/rpc/quipu.cpp`, registered via `RegisterQuipuRPCCommands` in
`src/rpc/register.h`, added to `src/Makefile.am` (after `rpc/net.cpp`). The
registration pattern is the standard static `CRPCCommand commands[]` table
(model on `rpc/blockchain.cpp:1857`).

### Read path  →  `quipuread`, `quipuscan`, `quipuroots`
- **Strand walk:** start at root `txid:vout`; at each step look up the spender
  via **spentindex**, fetch the tx (`GetTransaction`, txindex), extract its
  OP_RETURN, advance to its `:0`. No wallet involved.
- **OP_RETURN extraction:** `CScript::GetOp()` loop, detect `OP_RETURN (0x6a)`,
  collect pushed data (script.h:475).
- **Decode:** hand the assembled bytes to **L2/libquipu** → typed result
  (header magic `c1dd`, type byte, tone, body) → `UniValue` JSON out.
- `quipuread <txid>` → the decoded content; `quipuscan <address>` → all quipus
  at an address; `quipuroots <address>` → root txids (port `identify_quipus`:
  txs with no own OP_RETURN whose `:0` spender carries `c1dd`).

### Write path  →  `quipuwrite`, later `quipuinscribe`
- **OP_RETURN outputs:** `CTxOut(0, CScript() << OP_RETURN << data)`
  (rawtransaction.cpp:442).
- **Build + fund + sign:** `CWallet::CreateTransaction(vecSend, …)` with a
  `CRecipient` carrying the OP_RETURN script (wallet.cpp:2449); native signing
  via `CKey::Sign` → bundled **libsecp256k1** (key.cpp:169). No external lib.
- **Broadcast:** `AcceptToMemoryPool` + `RelayTransaction`
  (rawtransaction.cpp:909) — or `CWallet::CommitTransaction`.
- `quipuwrite` = one strand; **`quipuinscribe`** = the full multi-strand
  orchestration (root → strands → join), i.e. the diamond, native. Port
  `quipu_diamond` / `quipu_orchestrator` last — it's the most intricate piece
  (fee-accurate sizing, placeholder-txid backfill, the join tree).

### Crypto — **all in-tree**, this is the happy surprise
The scout confirmed everything the encrypted quipu types need is already in
`src/crypto/` and `src/secp256k1/`:
- **ECDH** — `secp256k1_ecdh()` (+ SHA256 hash) → the `shared_key` primitive.
- **AES256-CBC + PKCS7** — `src/crypto/aes.h` (ctaes) → the AES seal.
- **SHA256 / RIPEMD160 / HMAC-SHA256/512** → headers, KDFs, ids.
Only the *composition* (the exact KDF wrapping ECDH→AES key) must be written, to
match the Python `_shared_key` (HKDF-SHA256) byte-for-byte. So the **encrypted
family (0x0e: AES-seal `0xae`, broadcast `0xec`, keydrop `0x0d`) ports natively**
— and `cryptos`, `eciespy`, `pycryptodome` all **drop**.

---

## Layer 2 — the format core (the SPEC port; the bulk of the work)

`canonical/*` is the wire format — ~16 type modules, each a struct + serializer
to port into **libquipu** (a C++ static lib with no chain dependency, so it's
unit-testable in isolation and linkable by L1).

| Quipu type | byte | canonical module | port priority |
|---|---|---|---|
| text | 0x00 | text.py | **M1 (first)** |
| essay | 0x01 | essay.py (citations, binding blocks) | M2 |
| image | 0x03 | image.py (+ the bit-codec) | M3 |
| latex | 0x5c | latex.py | M2 |
| binding | 0xab | bindings.py (alias/sub/import eval) | M2 |
| celestial | 0xce | celestial.py (earth/star, grouped) | M2 |
| cert | 0xcc | cert.py | M3 |
| book | 0x09 | book.py | M3 |
| encrypted | 0x0e | encrypted.py (ae/ec/0d sub-families) | M3 (with crypto) |
| scene | 0x3d | scene.py (glTF) | M4 |
| dancer | 0xd4 | dancer.py (keyframes) | M4 |
| estandarte | 0x5e | estandarte.py (vector layers) | M4 |
| — shared — | — | structure.py, tone.py, quipu_refs.py, adaptor.py | M1 (foundation) |

Shared foundation first: `structure.py` (the magic+type+tone+pipe-field header)
→ `header.cpp`; `tone.py` → a constants header.

**Test strategy — Python is the gold oracle** (the coincurve pattern, scaled up):
for every type, the Python `build_*`/`read_*` emits reference vectors, and the
C++ must reproduce them byte-for-byte. Two vector sources:
1. **The real corpus** — `data/bodies/*.bin` (81 inscriptions, including the new
   1.1 MB `<<coasts>>`) → round-trip each through C++ libquipu, assert identical.
2. **Synthesized edge cases** — per type, mirroring each canonical module's own
   selftests.

This is exactly why **packagify matters**: each clean Python module becomes one
C++ porting unit *with its own oracle*. Packagify is step zero of the port, not
busywork — it draws the seams the C++ cuts along.

---

## Layer 3 — the client (stays out of the daemon)

Unchanged in spirit; repointed from "walk the chain in Python" to "call the
native RPC." What lives here and why it must:

| Tool | tech | renders |
|---|---|---|
| `scene_to_tikz.py` | TikZ/LaTeX | 3D scene → vector perspective plate |
| `colegio_pipeline.py` | XeLaTeX | essays/books → PDF (the literature) |
| `essay_renderer.py` | HTML | typographic essay/cert/identity views |
| `celestial_render.py` | SVG/matplotlib | 0xce figures |
| `scene_viewer.py` | Three.js/WebGL | interactive 3D |
| `quipu_console.py` | Streamlit | the authoring/reading UI |
| `quipu_loom.py`, `loom_monitor.py` | HTML/HTTP | live broadcast weave |

These call `quipuread`/`quipuscan` instead of `scan_accounts` + dataframes —
faster (no RPC storms, the node walks in-process) and simpler (no pandas). The
eventual "Colegio app that does everything" is this layer, packaged: a desktop
shell (Tauri/Electron/PyQt — open question) wrapping the renderers + a stock
forked node. The daemon stays lean; the app is where LaTeX and 3D live.

---

## What the fork lets us drop

- **`cryptos` (pybitcointools)** — tx construction + signing become native
  (`CWallet` + libsecp256k1). The fragile, unmaintained, pinned dependency that
  bit us twice this week simply isn't needed in C++.
- **`eciespy`, `pycryptodome`** — ECIES + AES become native (in-tree secp256k1
  ECDH + ctaes).
- The Python **NODE** layer (reading/writing/crypto/orchestration) thins to RPC
  clients or retires; **SPEC** stays as the oracle; **CLIENT** stays as the app.

---

## Milestone sequence

- **M0 — now:** packagify the toolkit (the porting map) + this design.
- **M1 — toolchain proof:** `libquipu` skeleton + shared header (`structure`,
  `tone`) + **one type (text 0x00)** ported, byte-identity oracle harness green
  against the corpus. Proves the Python-gold → C++ workflow end to end.
  *(Optional: a throwaway wallet-scoped `quipuread` here to prove the decode
  path before the index exists — scaffolding, discarded after M2.)*
- **M2 — the catalog (the real-fork moment):** the **quipuindex**
  (spentindex + addressindex) in ConnectBlock/DisconnectBlock + reindex; then
  `quipuread` / `quipuscan` / `quipuroots` reading *any* quipu by txid, wallet-
  free; text + essay + celestial + latex + binding types. `dogecoin-cli
  quipuread <txid>` returns inscribed content from a node that understands
  quipu. This is the milestone that makes it a *fork*.
- **M3 — write + crypto (the purse):** native ECIES/AES (drops the crypto deps);
  the 0x0e encrypted family; `quipuwrite` (single strand) funded + signed from
  the lean wallet. The wallet stops watching quipu addresses.
- **M4 — inscription + the rest:** `quipuinscribe` (the diamond, native) +
  scene/dancer/estandarte types. Repoint the client renderers at native RPC.
- **M5 — the everything-app + UI:** a Qt wallet tab showing quipus + the desktop
  app shell wrapping the renderers over native RPC.

---

## Risks / watch-items

- **Index correctness across reorgs** — the spentindex/addressindex must unwind
  cleanly in `DisconnectBlock` (port the reference patch's reorg handling
  carefully; a stale spent-entry would corrupt a strand walk). One-time reindex
  to populate; budget hours on the archive.
- **The diamond port is consensus-adjacent money** — fee-accurate sizing,
  placeholder-txid backfill, and the join-tree (incl. the 100 KB
  MAX_STANDARD_TX_SIZE limit we hit) are subtle. Port last, oracle hard.
- **Key encoding** — apocrypha is an *uncompressed* key (180 B inputs); Core
  defaults to compressed. The port must preserve key encoding or txids diverge.
- **Format port is large** (~16 types) — phase by real usage (text/essay/
  celestial/latex/binding first; scene/dancer/estandarte later).
- **Upstream-merge shape** — keeping L1 lean and L2 a clean library keeps the
  door open to one day proposing quipu RPC upstream, rather than a hard fork
  that drifts forever.
</content>
