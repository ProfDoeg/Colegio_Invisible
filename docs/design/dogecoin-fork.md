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

**The node holds NO private keys, and does NOT build transactions.** Building —
the diamond (chunk the blob into OP_RETURNs, lay out root→strands→join, backfill
cross-reference txids, preflight) — is intricate, *interleaved with signing*
(legacy txids include the signature, so a piece's root must be **signed** before
the bodies that reference it can be built), and **already proven in Python.** It
stays whole in the client, on **`pydoge`** (the owned Doge-tx library — below).
The client builds, the client signs (coincurve + `cinv` keys), and the node only
**broadcasts** the finished signed txs. The node never holds a key and never
assembles a transaction — it cannot unilaterally write, pay, or decrypt, because
every authorization and the whole construction live in the client. This is
already how you operate (watch-only node, keys in `cinv`, client-side build+sign,
keyless broadcast); the fork keeps it. A network-exposed daemon — especially
nodus, on the LAN with weak RPC creds — with **no keys** is the only safe daemon.

```
  CLIENT (Python)   compose · build · sign · interpret · decrypt · buy · sell
    canonical/* · pydoge (tx) · coincurve (sign) · cinv keys       the mind
    · adaptor crypto · LaTeX · 3D · UI            — meaning, keys, construction
    ──────  RPC:  quipuread (data in)  ·  sendrawtransaction (txs out)  ──────
  FORK (dogecoind)   ACCESS data  ·  BROADCAST txs                  the actuator
    read-index + in-process walk (NEW)  ·  relay (inherited)    — chain I/O, NO keys
```

**The format (`canonical/*`) stays Python, in the client — it is NOT ported to
C++.** Decoding is cheap (the 1.1 MB `<<coasts>>` parses in well under a second);
only the *walk* was ever slow, and that's the node's job. So the node treats
quipu payloads as **opaque bytes** — for *reading* it assembles the strand into a
blob and returns it; it never decodes the format, never builds a write tx, never
signs.
This keeps the rich, fast-iterating work (formats, rendering, sale logic) in
Python where you can change it without recompiling a daemon, and keeps **one**
implementation of the format (no C++/Python byte-identity oracle to maintain).

The genuinely *new* native code is therefore just **one subsystem**: the **read
index** (spentindex + addressindex + in-process walk) — the eye that accesses the
data. **Broadcasting is inherited** — every Dogecoin node already relays txs; the
fork is just the point you broadcast through. Building, signing, and the HTLC are
the client's (on `pydoge` + coincurve + standard script). So the fork is, exactly:

> **Dogecoin + the eye that reads quipu.** It *accesses the data* (the index, new)
> and *broadcasts transactions* (relay, inherited). Nothing else. Keyless, tiny.

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

**The decision: separate the purse from the catalog — and the purse isn't the
node's.**

- **The purse is yours, in the client** — the keys (`cinv`) and the UTXOs you
  spend to fund inscriptions. The node's wallet stops watching quipu addresses
  (the 88k dust knots leave) and holds no keys — it ends up vestigial, since
  reading is the index and signing is `cinv`/client.
- **The catalog is the node** — a purpose-built quipu index: what you *read*,
  public quipu, anyone's, by txid, nothing imported. With broadcast, this is the
  node's whole job.

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

### Broadcast path  →  `sendrawtransaction` (stock; no new node code)
Writing a quipu is a **client** operation; the node's only role is to relay.
- The client **composes** the blob (`canonical/*`), **builds** the diamond on
  **`pydoge`** (chunk into OP_RETURNs, root→strands→join, backfill cross-reference
  txids, preflight — the proven pipeline, untouched), and **signs** with `cinv`
  keys (coincurve). This is interleaved (legacy txids include the signature, so a
  root must be signed before referencing bodies are built) — which is exactly why
  it stays one whole Python pipeline and is *not* split across the node boundary.
- The node **broadcasts** the finished signed txs — `sendrawtransaction` →
  `AcceptToMemoryPool` + `RelayTransaction` (rawtransaction.cpp:909). Stock.
- *Optional convenience (not required):* a campaign-aware relay RPC accepting an
  ordered batch (parents before children) with per-tx confirm status — nicer than
  13,774 bare `sendrawtransaction` calls — but `quipu_broadcast.py` already does
  this client-side (resumable, re-weaving dropped knots), so it's polish.

There is **no** `quipuwrite`/`quipuinscribe` node RPC: the node can't build (no
tx construction) or sign (no keys), and shouldn't — the diamond's interleaved
build/sign/backfill is proven in Python and stays there, on `pydoge`.

### Crypto — the node holds no keys; all key-crypto is the client's
The node does **no** cryptography that needs a private key. Transaction signing
(write, pay, the HTLC claim/refund legs) happens in the **client**, with `cinv`
keys via **coincurve** (the fast signer proven this week) — never in the daemon.
The **box crypto** — ECIES sealing/unsealing, the AES content seal, the adaptor
binding, *decryption* of received quipu — is also the client's (*compose /
interpret / sell / decrypt*): cheap, delicate (money-grade, mainnet-proven), one
implementation. The daemon's only crypto is what consensus already does —
verifying signatures in the blocks it validates — which needs no private keys.
*(`src/crypto/` + `src/secp256k1/` carry ECDH/AES/SHA/HMAC, so the node *could*
do key-crypto someday — but it must not: keys on a network-exposed daemon are
precisely the thing we are avoiding.)*

### Encrypted quipu (`0x0e`) — where "no keys" has teeth
The encrypted family (`0x0e`: `0xae` AES-seal, `0xec` ECIES-broadcast, `0x0d`
keydrop, `0xcb` sale box, `0xca` centinela, `0x55` Shamir share) is exactly where
the keyless line matters most. Reading one splits cleanly:

- **The node returns ciphertext + the chain-context to decrypt — and decrypts
  nothing.** `quipuread` on a `0x0e` quipu returns the usual `{header, body,
  tags}` where `body` is the **ciphertext** (all `0x0e`-specific framing — the
  sub-family byte, recipient/session pubkeys, the M×64 session-key copies, the
  AES body — lives *inside* the body, parsed by the client), **plus one extra
  field: `sender_pubkey`**, extracted from the inscribing tx's **input scriptSig**
  (`get_txn_pub_from_node`). The static-ECDH scheme uses the sender's on-chain
  pubkey as half of every shared secret, and it sits in the scriptSig — pure
  chain data the node surfaces trivially, *not* a decryption.
- **The client decrypts**, entirely: `shared = HKDF(ECDH(my_cinv_priv,
  sender_pubkey))` → try each session-key slot → AES-decrypt the body → the inner
  framed quipu → recurse the decode. The private key is `cinv`, client-side; the
  node never sees it.

**Keydrops** (`0x0d`) — where the AES key is delivered by a *separate* quipu —
resolve client-side: the client finds the keydrop (the node's index/`quipuscan`
helps), fetches both blobs, and combines them (`apply_keydrop`) locally. Node
serves blobs + discovery; the client does the join.

**Sale boxes** (`0x0e 0xcb`) become readable once the seller's claim reveals
`session_priv` on chain. Post-sale reading: the node surfaces the **claim tx**
(it sees the bond's spend and can return the revealed preimage as chain-context);
the client derives `session_key` and decrypts. The one place read and buy/sell
touch — and it touches through *chain data the node already has* (a spend, a
revealed preimage), never through a key.

So encrypted quipu don't bend the architecture — they **prove** it: everything
the node hands over is public chain material (ciphertext, sender pubkey, revealed
preimages, tag-state); everything secret (private keys, decryption, plaintext) is
the client's *structurally* — the node has no keys to do it with even if asked.

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
Python → build on `pydoge` → sign (coincurve) → `sendrawtransaction`. No more
`scan_accounts` rescans, no pandas.

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
- Settlement (fund the bond, claim revealing the key, refund) is client-built
  (`pydoge`) + client-signed (coincurve + `cinv`), broadcast through the node —
  no node wallet, no node keys.

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

## What changes in the Python deps — fork `cryptos` into `pydoge`

We don't *remove* cryptos by moving its work elsewhere — we **own** it. Fork it,
gut it, test it, make it ours:

- **`cryptos` (pybitcointools) → `pydoge`** — extract the ~18 functions actually
  used (tx build/serialize, address/key derivation, multisig, base58/hash) and
  **cut everything else** (other coins, the network/API clients, the BIP wallet
  machinery, the slow pure-Python ECDSA). Add a real test suite — and the oracle
  is free and enormous: *every tx on chain is a gold vector*, rebuilt by `pydoge`
  and asserted byte-identical (same rigor as the coincurve proof). The fragility
  (unmaintained upstream, oversized surface, version-pinned, bit us twice this
  week) is gone — not by living with it, not by moving to C++, but by owning a
  small, tested, maintained Dogecoin-tx library.
- **`pandas` leaves the read path** — `quipuread` returns assembled bytes; no
  dataframes to rebuild an address's history.
- **Kept:** `coincurve` (ECDSA, under `pydoge`), `eciespy` / `pycryptodome` /
  `eth_keys` (box crypto + `cinv` key loading). All client-side.

The owned stack, layered (one-way deps):

```
  colegio   (quipu: canonical/*, the diamond, readers, renderers, sale logic)
     │ imports
     ▼
  pydoge    (Dogecoin tx: build · serialize · address · multisig)   ← knows no quipu
     │ imports
     ▼
  coincurve (ECDSA)
```

`pydoge` is a **sibling package to `colegio` in the same repo** — its own tests,
a hard one-way boundary (it knows nothing about quipu), extractable to its own
repo/PyPI later if ever useful to anyone else (pybitcointools is MIT — the fork
is clean).

---

## Milestone sequence

Each step is independently useful; the client keeps working against a stock node
until each native piece lands. No format is ported — `canonical/*` stays Python
throughout.

- **M0 — now (useful immediately, independent of the fork):**
  - **packagify** the toolkit into a clean `colegio` package — the importable
    engine the app and RPC-clients sit on;
  - **`pydoge`** — fork/gut/test cryptos into the owned Doge-tx library.
  Both de-fragilize the *current* toolkit today; neither needs the C++ fork.
- **M1 — read, the real-fork moment (the fork's ONLY new subsystem):** the
  **quipuindex** (spentindex + addressindex) in `ConnectBlock`/`DisconnectBlock`
  + a one-time reindex; then `quipuread` / `quipuscan` / `quipuroots` returning
  `{header, body, tags}` for *any* quipu by txid, wallet-free. The client's Python
  `canonical/*` decodes them. The wallet stops watching quipu addresses; the 88k
  dust txs retire. `dogecoin-cli quipuread <txid>` → data from a node that
  understands quipu. This is what makes it a *fork*.
- **M2 — wire the app to the fork:** repoint every client renderer/tool from
  `scan_accounts` to `quipuread`; broadcast through the node
  (`sendrawtransaction`). Build/sign stay client-side on `pydoge` + coincurve,
  unchanged. Confirm buy/sell still runs end-to-end on standard script (verify
  against the deployed 2026-06-08 sale).
- **M3 — the everything-app:** the desktop shell (Tauri / Electron / PyQt) over
  the renderers + sale logic + the forked node; optional Qt tab showing quipus.

---

## Risks / watch-items

- **Index correctness across reorgs** — the spentindex/addressindex must unwind
  cleanly in `DisconnectBlock` (port the reference patch's reorg handling
  carefully; a stale spent-entry would corrupt a strand walk). One-time reindex
  to populate; budget hours on the archive.
- **`pydoge` is money code** — it builds txs that spend real DOGE, so the
  fork/gut must be **byte-exact**: every tx the old cryptos built (the whole
  on-chain corpus) must rebuild identically, including apocrypha's *uncompressed*
  key (180 B inputs — Doge convention, not Core's compressed default). The free
  chain-oracle test covers this; treat any single-byte divergence as a stop.
- **Upstream-merge shape** — keeping the daemon's new surface to **one** clean
  subsystem (the read-index) and treating payloads as opaque bytes keeps the door
  open to proposing quipu RPC upstream one day, rather than a fork that drifts.
- **No format port, no C++ tx code = whole risk classes designed out** — there is
  no "did the C++ decode match Python?" and no "did the C++ signer build the same
  txid?", because neither exists. The only byte-exactness that matters lives in
  `pydoge` — one Python implementation, tested against the chain. The safest place
  for it.
