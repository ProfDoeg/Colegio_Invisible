# Dogecoin Core fork: native quipu — design plan

*Loose design, 2026-06-13 (revised through the day's discussion). A fork of
dogecoin/dogecoin (1.14) split by verb: the node is the chain-actuator —
**read · write · pay · receive** (bytes & value, on and off the chain); the
Python client is the mind — **compose · interpret · buy · sell** (meaning &
intent), holding the format, the rendering, and the sale logic. Offers stay
off-chain; there is no marketplace.*

---

## The shape: two halves, split by verb

The instinct "port as much to C++ as possible" is right in spirit but wrong in
extent: the daemon should be the **chain-actuator**, not an everything-machine.
The clean factoring is by verb — meaning-side vs chain-side:

| Client (Python) — *meaning & intent* | Fork (C++) — *bytes & value on the chain* |
|---|---|
| **compose** a quipu | **write** it to chain |
| **interpret** a quipu | **read** it from chain |
| **sell** / **buy** | **receive** / **pay** |

The boundary is one question: **does it move bytes or value on the chain?** →
fork. **Does it decide meaning or intent?** → client. Nothing crosses: the node
never interprets a quipu's meaning; the client never touches the chain directly.

```
  CLIENT (Python app)   compose · interpret · buy · sell        the mind
    canonical/* codecs · adaptor crypto · LaTeX · 3D · UI       — meaning & intent
    ───────────────────────────  RPC (bytes & value)  ───────────────────────────
  FORK (C++ dogecoind)  read · write · pay · receive            the actuator
    read-index + in-process walk · in-process diamond+sign      — chain I/O only
    · stock wallet (pay/receive) · stock script (HTLC)
```

**The format (`canonical/*`) stays Python, in the client — it is NOT ported to
C++.** Decoding is cheap (the 1.1 MB `<<coasts>>` parses in well under a second);
only the *walk* was ever slow, and that's the node's job. So the node treats
quipu payloads as **opaque bytes** — it assembles them (read) and chunks/signs/
broadcasts them (write) without ever understanding celestial vs scene vs essay.
This keeps the rich, fast-iterating work (formats, rendering, sale logic) in
Python where you can change it without recompiling a daemon, and keeps **one**
implementation of the format (no C++/Python byte-identity oracle to maintain).

The genuinely *new* native code is therefore just **two subsystems**: the
**read** index (spentindex + addressindex + in-process walk) and the **write**
engine (in-process diamond + native signing). **Pay and receive come free** with
Dogecoin Core — it is already a wallet that sends, receives, and validates the
HTLC script. The fork stays tiny.

LaTeX and 3D do **not** go in the daemon: a consensus node has no business
shelling out to xelatex or rasterizing scenes. Keeping them out keeps the fork
lean, auditable, and mergeable-upstream-shaped.

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
> prove the walk → bytes path (the Python client decodes the result) *before*
> the index is built, then be discarded. It is scaffolding, not the design.

---

## The fork (the node) — read · write · pay · receive  (C++ RPC)

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
- **Returns `{header, body, tags}`, not decoded meaning:**
  - `header` — the parsed **universal envelope** (magic, version, type, tone,
    title): type-agnostic, shared by every quipu, stable across format evolution
    (the node reads it anyway to find the magic).
  - `body` — the assembled body bytes, **opaque** (hex). The Python client
    decodes these per type (celestial, scene, essay, …); the node never does.
  - `tags` — the **chain-state of the quipu's tag outputs**: each tag outpoint,
    value, and whether it is spent (and by what). This is the node's unique
    contribution — pure chain data, and exactly the *edition / correction-thread*
    status: an unspent tag = "this is the current edition"; a spent tag points at
    the successor. The client gets it free, in the same call as the walk.
- So one call yields: *what kind* (header), *raw content to decode* (body), and
  *is-this-the-latest* (tags) — the first two cheap-and-universal, the third
  uniquely the node's to know.
- `quipuread <txid>` → `{header, body, tags}`; `quipuscan <address>` → the same
  for every quipu at an address; `quipuroots <address>` → root txids
  (`identify_quipus`: no own OP_RETURN, `:0` spender carries `c1dd`).
- *Open sub-choice:* `tags` reports immediate spend-state; following a spent tag
  to its successor (thread resolution) can be the node's job or the client's —
  lean client (it orchestrates editions), node offers the raw state.

### Write path  →  `quipuwrite`, later `quipuinscribe`
- **OP_RETURN outputs:** `CTxOut(0, CScript() << OP_RETURN << data)`
  (rawtransaction.cpp:442).
- **Build + fund + sign:** `CWallet::CreateTransaction(vecSend, …)` with a
  `CRecipient` carrying the OP_RETURN script (wallet.cpp:2449); native signing
  via `CKey::Sign` → bundled **libsecp256k1** (key.cpp:169). No external lib.
- **Broadcast:** `AcceptToMemoryPool` + `RelayTransaction`
  (rawtransaction.cpp:909) — or `CWallet::CommitTransaction`.
- **Opaque payload:** the client *composes* the quipu blob (Python
  `canonical/*`) and hands the bytes to the node; the node chunks them into the
  diamond without understanding the format.
- `quipuwrite` = one strand; **`quipuinscribe`** = the full multi-strand
  orchestration (root → strands → join), i.e. the diamond, native. Port the
  chain mechanics of `quipu_diamond` last — it's the most intricate piece
  (fee-accurate sizing, placeholder-txid backfill, and the join *tree* for the
  100 KB MAX_STANDARD_TX_SIZE limit we hit this week).

### Crypto — the node signs natively; box-crypto stays in the client
Transaction signing — write, pay, the HTLC claim/refund legs — uses Core's
bundled **libsecp256k1** (`CKey::Sign`, key.cpp:169): fast, native, no external
library. That is the *only* crypto the node needs, and it retires `cryptos`'s
pure-Python ECDSA entirely.
The **box crypto** — ECIES sealing/unsealing, the AES content seal, the adaptor
binding — is *composing/interpreting/selling*, so it **stays in the Python
client**: cheap (a handful of EC ops), delicate (money-grade, with a deployed
mainnet reference), single implementation. The node never needs it. *(Latent
capability, not used: `src/crypto/` + `src/secp256k1/` already carry ECDH,
AES256-CBC, SHA256, HMAC — so the node could do box crypto someday, but there's
no speed reason to reimplement proven money-crypto.)*

---

## The format: stays Python in the client (NOT ported)

`canonical/*` — the ~16 type modules (text, essay, image, latex, binding,
celestial, cert, book, encrypted, scene, dancer, estandarte, plus the shared
`structure` / `tone` / `quipu_refs` / `adaptor`) — is the wire format, and it
**stays exactly where it is: Python, in the client.** It is not ported to C++.

Why: encode/decode is cheap (the 1.1 MB `<<coasts>>` parses in well under a
second), and the node treats payloads as opaque bytes — so there is no speed
reason and no node reason to port it. Keeping it Python buys:
- **one implementation** — no C++/Python divergence, *no byte-identity oracle to
  maintain* (the oracle only made sense when two implementations had to agree);
- **fast iteration** — add a type or change a decode without recompiling a
  daemon;
- the format lives next to the rendering and authoring that consume it.

The node reads only the *universal header* (magic, version, type, tone, title) —
the magic alone identifies roots, and `quipuread` returns the parsed envelope
alongside the opaque body and the chain-state tags. It never parses type-specific
content. What a celestial figure or a scene or an essay *means* is the client's,
forever.

---

## The client (the app) — compose · interpret · buy · sell

The Python side, repointed from "walk the chain myself" to "call the node's
RPC." It holds the meaning and the intent.

**Interpret / compose** — `canonical/*` codecs + the renderers:

| Tool | tech | renders |
|---|---|---|
| `scene_to_tikz.py` | TikZ/LaTeX | 3D scene → vector perspective plate |
| `colegio_pipeline.py` | XeLaTeX | essays/books → PDF (the literature) |
| `essay_renderer.py` | HTML | typographic essay/cert/identity views |
| `celestial_render.py` | SVG/matplotlib | 0xce figures |
| `scene_viewer.py` | Three.js/WebGL | interactive 3D (OpenGL-class) |
| `quipu_console.py` | Streamlit | the authoring/reading UI |
| `quipu_loom.py`, `loom_monitor.py` | HTML/HTTP | live broadcast weave |

These call `quipuread` (get bytes) → decode in Python → render; and compose in
Python → `quipuwrite` (hand bytes to the node). No more `scan_accounts` rescans,
no pandas.

**Buy / sell** — entirely client-side, on standard script, **no marketplace.**
Your verified-key sale (deployed mainnet 2026-06-08: HTLC + ECDSA adaptor
signatures + `0x0e 0xcb` sealed box) runs here unchanged:
- **Offers stay off-chain** (Nostr gossip, or quieter). There is **no on-chain
  offer index and no order book** — a storefront nailed to the cathedral door
  would betray the whole register. The invisible college sells a manuscript by
  private correspondence, not from a stall.
- The **adaptor/DLEQ binding** (`canonical/adaptor.py`) — buyer-verifies-before-
  paying — stays Python: cheap, delicate, one implementation.
- The HTLC is **standard Dogecoin Script** (`OP_SHA256`, `OP_CHECKLOCKTIMEVERIFY`)
  — every node already validates it. **The daemon never knows a sale is
  happening**: it sees a P2SH like any other. Constitutionally incapable of
  being a marketplace, which is exactly right.
- Settlement (fund the bond, claim revealing the key, refund) is *pay/receive* —
  the fork's stock wallet, broadcasting standard txs.

### Why on-chain at all, and not everything on Nostr
The line: **the chain carries only what needs money, atomicity, or permanence;
everything ephemeral is Nostr.** A sale's *settlement* is irreducibly on-chain —
atomic exchange of value for a secret needs a ledger with both coins and script,
which Nostr is not. And on-chain, the key-reveal is permanent and public: the
first buyer pays to *unseal the box for the world*, recorded forever — patronage
of revelation, not DRM (a Nostr "sale" would be a retractable private password-
pass, a lesser and different act). So: **settlement on-chain, always; offers and
identity on Nostr; the box on-chain by artistic choice** (permanence is the
medium — same reason we fork the node instead of running an indexer).

The eventual "Colegio app that does everything" is this whole client layer,
packaged: a desktop shell (Tauri / Electron / PyQt — open question) over the
renderers + sale logic + a stock forked node. The daemon stays lean; the app is
where LaTeX, 3D, and commerce live.

---

## Why it's faster — and where it isn't

The speed comes from two architectural facts, not from "C++ is fast" per se: the
**index replaces rescans**, and the **in-process walk replaces RPC round-trips.**
The `{header, body, tags}` return stacks on top by collapsing several queries
into one. Reading one quipu (e.g. the 1.1 MB `<<coasts>>`):

| step | today (Python) | fork |
|---|---|---|
| find the address's txs | wallet rescan (hours, first time) + RPC | addressindex lookup, instant |
| walk the strand | thousands of `getrawtransaction` round-trips + pandas | in-process, no round-trips |
| learn edition status | separate UTXO/spent queries | **included in `tags`, free** |
| round-trips per read | many | **one** |

Three independent speedups: no rescan, no per-knot round-trips, and three
questions (what-kind / content / is-latest) answered in a single call.

**Honestly scoped — where the speed does and doesn't matter:**
- It's **steady-state** speed, bought with one upfront **reindex** (hours, once
  over the archive). Not "free fast" — "fast after the one-time index."
- It pays off most where you read **a lot**: the everything-app rendering a
  gallery/browse over many quipus, or reading others' corpora at scale. For an
  occasional one-off read, the Python toolkit was already fine.
- **Writing** is also fast (the diamond's 20-min pure-Python signing → seconds),
  but that win was *already* available via `coincurve` in Python; the fork keeps
  it native, it doesn't newly unlock it.
- Net: the strongest reasons for the fork are (1) the app's responsiveness,
  (2) reading anyone's quipu instantly and retroactively, and (3) the symbolic
  weight of a node that natively understands quipu — with raw single-read latency
  a real but secondary gain. Faster, yes; but better *by design* first.

---

## What changes in the Python deps

- **`cryptos` (pybitcointools) leaves the client** — its job (tx construction +
  ECDSA signing) moves to the node (`CWallet` + libsecp256k1). The fragile,
  unmaintained, pinned dependency that bit us twice this week is retired from the
  write/pay path; any residual address-derivation need is trivial to replace.
- **`pandas` leaves the read path** — the node walks in-process and returns
  bytes; no dataframes to assemble an address's history.
- **Kept on purpose:** `eciespy` / `pycryptodome` / `coincurve` **stay** in the
  client — they do the box crypto (ECIES/AES seal) and the adaptor signatures,
  which are *compose / interpret / sell*, not chain I/O. One implementation, in
  Python, where the money-crypto already has a mainnet-proven reference. (Earlier
  drafts said these drop; that was when we imagined porting crypto to C++ — we
  don't.)

---

## Milestone sequence

Each step is independently useful; the client keeps working against a stock node
until each native piece lands. No format is ported — `canonical/*` stays Python
throughout.

- **M0 — now:** packagify the toolkit into a clean `colegio` package. *(Reframed:
  its value is now "the app's engine" + isolating `cryptos`, not "the C++ porting
  map" — since the format isn't ported. Still the right first move: the client
  becomes the importable core the app and the RPC clients sit on.)*
- **M1 — read, the real-fork moment:** the **quipuindex** (spentindex +
  addressindex) in `ConnectBlock`/`DisconnectBlock` + a one-time reindex; then
  `quipuread` / `quipuscan` / `quipuroots` returning assembled **bytes** for
  *any* quipu by txid, wallet-free. The client's existing Python `canonical/*`
  decodes them. `dogecoin-cli quipuread <txid>` → bytes from a node that
  understands quipu structure. This is what makes it a *fork*.
- **M2 — write:** the in-process diamond + native signing → `quipuwrite` (one
  strand) and `quipuinscribe` (the full diamond, incl. the join-tree close). The
  client *composes* the blob (Python) and hands bytes to the node. The wallet
  stops watching quipu addresses; the 88k dust txs retire.
- **M3 — wire the app:** repoint every client renderer/tool from `scan_accounts`
  to the native RPC. Confirm buy/sell still runs end-to-end on standard script
  against the fork (it should — verify against the deployed 2026-06-08 sale).
- **M4 — the everything-app:** the desktop shell (Tauri / Electron / PyQt) over
  the renderers + sale logic + the forked node; optional Qt wallet tab showing
  quipus.

---

## Risks / watch-items

- **Index correctness across reorgs** — the spentindex/addressindex must unwind
  cleanly in `DisconnectBlock` (port the reference patch's reorg handling
  carefully; a stale spent-entry would corrupt a strand walk). One-time reindex
  to populate; budget hours on the archive.
- **The diamond port is consensus-adjacent money** — fee-accurate sizing,
  placeholder-txid backfill, and the join-tree (incl. the 100 KB
  MAX_STANDARD_TX_SIZE limit we hit) are subtle. Port last; verify the native
  diamond builds txids identical to what the Python signer would have.
- **Key encoding** — apocrypha is an *uncompressed* key (180 B inputs); Core
  defaults to compressed. The port must preserve key encoding or txids diverge.
- **Upstream-merge shape** — keeping the daemon's new surface to two clean
  subsystems (read-index + write-diamond) and treating payloads as opaque bytes
  keeps the door open to one day proposing quipu RPC upstream, rather than a hard
  fork that drifts forever.
- **No format port = no format-port risk** — the whole class of "did the C++
  decode match Python byte-for-byte?" bugs is designed out by keeping one
  implementation. The remaining byte-exactness that *does* matter is the write
  path (the node must build txids identical to what the Python signer would have
  — esp. apocrypha's uncompressed key, above).
</content>
