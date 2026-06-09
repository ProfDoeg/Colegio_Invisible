# Broadcasting a quipu (the loom toolkit)

A practical guide to getting a large inscription **onto the Dogecoin chain**:
sign the diamond offline, broadcast it keylessly, survive dropped mempool
entries and stalled RPCs, and watch it weave in real time. Aimed at:

- Anyone (you, or a future Claude session) publishing a multi-thousand-tx
  inscription — the Book of 108, another dancer, a scene, anything big.
- Recovering a broadcast that stalled partway and resuming it losslessly.

This guide is about the *operational* side. For the **shape** of an inscription
(root → strands → join, numbering, why 80-byte knots) see
[`../quipu-syntax/diamond.md`](../quipu-syntax/diamond.md). This guide is how you
actually push that shape onto live blocks without losing the key or the work.

> **The split that makes this safe: signing touches the private key; broadcasting
> never does.** You run the signer yourself (it `getpass`-prompts for the
> password, uses the key in memory, and writes only public hexes/txids).
> Broadcasting reads those public artifacts and pushes bytes — no key, no
> password, nothing to leak. You can hand the broadcast step to an automated
> supervisor and walk away.

---

## TL;DR — the four moves

```bash
# 0. build the body bytes (type-specific; produces the .bin to inscribe)
.venv/bin/python working/<stage>/build_body.py

# 1. SIGN OFFLINE — you run this; it prompts for the apocrypha password.
#    Decrypts the key in memory, splits the body into N modulo strands,
#    signs root + every knot + join, writes ONLY public artifacts. Spends nothing.
.venv/bin/python working/<stage>/sign_jeremy.py        # -> artifacts/

# 2. WATCH — open the loom on the staged artifacts (read-only by default)
MODE=progress LOOM_ARTIFACTS=working/<stage>/artifacts \
  .venv/bin/python quipu_loom.py                       # http://localhost:8799/

# 3. BROADCAST under a supervisor — keyless, resumable, hang-proof.
nohup .venv/bin/python working/<stage>/supervise_jeremy.py \
  > working/<stage>/supervise.log 2>&1 &
```

Steps 1 and 3 are deliberately separate processes. **Signing is reversible**
(nothing on chain); **broadcasting spends real DOGE** and needs your explicit
go-ahead. Never fold them into one script.

---

## The pipeline, stage by stage

```
build_body.py   →   sign_*.py    →   artifacts/   →   broadcast_*.py   →   chain
  (public)         (uses key,         (public         (keyless,            (root → knots
                    in memory)         signed hexes)    resumable)           → join)
                                          ↑                  ↓
                                       quipu_loom.py  ←  progress.json
                                       (watch only)      (per-round state)
```

### 1. Build — `working/<stage>/build_body.py`

Produces the raw body bytes for the inscription (`<name>.bin`). Type-specific —
for Jeremy it assembles the `0x01` dancer performance (delta footage + graph +
controller). Prints size, knot count, and a cost estimate. **Public; key-free.**

### 2. Sign — `working/<stage>/sign_jeremy.py`  *(you run this)*

The only step that touches the private key:

- `getpass`-prompts for the password, calls `quipu_crypto.decrypt_password` on
  `~/Desktop/cinv/llaves/mi_prv.enc`, verifies the derived address equals the
  funder, **all in memory**.
- Splits the body into `N` strands by **modulo stride** (`knots[i::N]`, see
  [the modulo note](#why-modulo-strands)).
- Builds + signs the whole diamond via the two-phase
  [`Quipu`](../../quipu_orchestrator.py) orchestrator: `build_root()`,
  `precompute_strands()`, `build_join()`. Every txid is known locally — no node
  needed to sign.
- Writes **only public artifacts** to `artifacts/`. Drops the key + password
  from memory. **Spends nothing.**

```
artifacts/
  root.txid   root.txn          # the 1→N seed transaction
  join.txid   join.txn          # the N→1 closing transaction
  strand_<i>.txns               # knot hexes for strand i (one per line)
  strand_<i>.txids              # local txids (cosmetic; broadcaster recomputes)
  utxo.json                     # the funding outpoint
  progress.json                 # written by the broadcaster each round
```

### 3. Broadcast — `working/<stage>/broadcast_jeremy.py`  *(keyless)*

Reads `artifacts/` and weaves the diamond onto chain. It holds **no key** — it
only re-sends pre-signed hexes. The shape of its run:

```
root → wait for root to confirm
     → scan the frontier to resume (find_resume_index + frontier per strand)
     → fill: ancestor-safe rounds, sending each strand forward until it hits
       the unconfirmed-ancestor cap, re-checking the confirmed frontier
     → join (only once every knot is confirmed) → wait → done
```

Writes `progress.json` every round so the loom (and you) can see exactly where
it is. Idempotent at every step: re-running it never double-spends — it only
(re)sends knots the node has forgotten.

### 4. Supervise — `working/<stage>/supervise_jeremy.py`  *(set-and-forget)*

Keeps the broadcaster alive until `phase=="done"`. Restarts it if the process
exits early **or** if `progress.json` goes stale (no write within `STALL_S`).
Because the broadcaster resumes losslessly from on-chain state, a kill+relaunch
is always safe. This is what lets you start a multi-hour weave and go to dinner.

### Watch — `quipu_loom.py`

Live view at **http://localhost:8799/**: knots as circles per strand
(uncolored = pending on top, then colored by the block that confirmed them),
plus chain stats. Three modes:

| `MODE` | what it does |
|---|---|
| `sim` | demo weave, no chain — for showing the pattern |
| `rpc` | reads `artifacts/`, checks each knot's real status. **Watch-only** unless `LOOM_BROADCAST=1` |
| `progress` | tails `progress.json` from a running broadcaster (the usual choice) |

> The loom defaults to **watch-only**. It will not broadcast anything unless you
> explicitly set `LOOM_BROADCAST=1`. Keep the loom and the broadcaster as
> separate concerns: one watches, one weaves.

---

## The robustness model (why it survives a long campaign)

A 22,000-tx broadcast runs for hours. Over that span, mempool entries get
dropped, the node's work queue backs up, an RPC stalls. The toolkit
([`quipu_broadcast.py`](../../quipu_broadcast.py)) is built around the
assumption that **any single send or query can fail or vanish**, and recovers
without losing place:

- **Chain-scoped status, not wallet-scoped.** `tx_status(txid)` reads the chain
  directly via `getrawtransaction` → `confirmed | mempool | unknown`. It is
  robust to (a) the wallet not knowing `sendraw`'d txs and (b) a tx dropping out
  of mempool — which reads as `unknown`, the signal to re-broadcast.
- **Idempotent re-broadcast.** `send_if_needed(hex, txid)` sends **only** when
  the node has forgotten the tx. A dropped knot gets re-woven; a known one is
  left alone.
- **Backed-off, concurrency-capped sends.** `send_with_retry` treats "already in
  mempool/chain" as success and backs off on transient work-queue/connection
  errors. Concurrency is capped by `SEND_CONCURRENCY` (default 4).
- **Binary-search resume.** `find_resume_index(txids)` finds how far a previous
  run got (highest contiguous known knot, +1). The broadcaster's `frontier(s)`
  does the same for the *confirmed* edge. On restart it picks up exactly where
  the chain actually is — no re-sending confirmed knots, no skipping gaps.
- **Socket timeout.** Every RPC has a 45 s socket timeout
  (`socket.setdefaulttimeout(45)` at the top of the broadcaster) so a stalled
  node can't freeze the weave forever.
- **Supervisor restarts on stall.** If progress stops moving, the supervisor
  kills and relaunches; the resume logic makes that lossless.

### Drop-recovery, carefully

Each strand is a *chain*: knot `K` spends knot `K-1`. If a middle knot drops,
everything after it is unconfirmable until it's re-sent. The broadcaster tracks
a per-strand `stuck` counter and only resets a strand's send-frontier back to
its confirmed edge after **~10 rounds** of zero progress — high enough not to
misfire during normal slow confirmation (the threshold-3 version thrashed). When
in doubt, **trust the resume scan**: kill the broadcaster and let it restart; it
reads the true on-chain frontier and continues.

---

## Resuming a stalled or interrupted broadcast

This is the common real-world case. It is safe and boring:

```bash
# just relaunch — under the supervisor, or the broadcaster directly.
nohup .venv/bin/python working/<stage>/supervise_jeremy.py \
  > working/<stage>/supervise.log 2>&1 &

# watch it pick up:
tail -f working/<stage>/broadcast.log         # look for "resumed: sent X · confirmed Y"
```

On launch it re-confirms the root, scans every strand's frontier from the chain,
and continues from there. Knots already confirmed stay confirmed; knots the node
forgot get re-sent; the join fires only once all knots are confirmed. **Nothing
is double-spent** because the funding UTXO is consumed exactly once by the root,
and every downstream tx is pre-signed to spend a specific output.

To check state at any time:

```bash
python3 -c "import json;d=json.load(open('working/<stage>/artifacts/progress.json'));\
print(d['phase'], d['confirmed'],'/',d['total'])"
```

---

## Environment knobs

| var | default | where | meaning |
|---|---|---|---|
| `ANCESTOR` | `24` | broadcaster | max unconfirmed ancestors per strand (stay under the 25 cap) |
| `POLL` | `20` | broadcaster | seconds between fill rounds / confirm polls |
| `SEND_CONCURRENCY` | `4` | quipu_broadcast | parallel `sendrawtransaction` cap |
| `STALL_S` | `150` | supervisor | restart if `progress.json` not written within this |
| `MODE` | `sim` | loom | `sim` / `rpc` / `progress` |
| `LOOM_ARTIFACTS` | — | loom | staged `artifacts/` dir to watch |
| `LOOM_BROADCAST` | unset | loom | `1` to let the loom send (default: watch-only) |
| `PORT` | `8799` | loom | loom HTTP port |
| `STRANDS` | `64` | loom (sim/display) | strand count for the sim weave |

---

## Why modulo strands

Split the body with a **modulo stride** — strand `i` gets `knots[i::N]` — not
contiguous byte chunks. Same on-chain cost for any `N`, zero rounding waste, and
you can scale parallelism freely (more strands = wider diamond = faster
wall-clock, same fee). The signer already does this; default to it for any
multi-strand body.

---

## Fees & timing

- Per-knot tip is set in the signer (`TIP_SAT`). Jeremy used **0.02 DOGE/knot**,
  a deliberate floor-fee bet during a quiet network — it cleared because blocks
  were near-empty. In a busier mempool, bump the tip.
- Root and join are larger txs (N outputs / N inputs) and are fee'd by byte size
  (`FEE_KB`). The signer warns if either looks below the ~0.01/kB min relay.
- Wall-clock is gated by **confirmation**, not sending: a strand can only get
  ~24 knots deep before it must wait for a block. More strands → more knots land
  per block → faster overall.

---

## Worked example — Jeremy (2026-05-31)

The dancer that proved this toolkit end to end:

- **Body:** `0x01` dancer performance, 1,790,082 B (delta footage 16-color/128px/30fps + motion graph + 7-method controller).
- **Diamond:** 255 strands · 22,377 knots · 22,379 tx.
- **Funder:** apocrypha `D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX`.
- **Root:** `6de4688a945fb03f41f9b1139c83f5099dd309378348398d4b52ce1c1d12a489` (1→255).
- **Join:** `e1be6faa4eb5750cbd4d96f5328d0d007a7b6288162e3667f82f6dd565080439` (255→1), block 6,230,020.
- **Spend:** 450.10 DOGE total (root fee + 22,377 × 0.02 + join fee); 194.25 DOGE returned.
- **Incidents survived:** one drop-recovery misfire (fixed: stuck threshold 3→10) and one RPC hang at ~97% (fixed: 45 s socket timeout + supervisor). On relaunch the resume scan found all 22,377 knots already confirmed and fired the join one round later. **Nothing lost, nothing double-spent.**

The lesson baked into the tooling: when a long broadcast looks stuck, the
recovery is almost always **relaunch and let it resume** — not manual surgery.

---

## Security rules (do not bend)

- The apocrypha private key (`~/Desktop/cinv/llaves/mi_prv.enc`) is **never**
  written to any file the tooling creates. The password is provided at signing
  time via `getpass`, used in memory, and never persisted.
- Only the **signer** ever sees the key. The broadcaster, supervisor, and loom
  are all keyless — they move public hexes.
- **Broadcasting spends real funds.** It runs only with explicit authorization
  (funder, tip, and go-ahead). Signing is safe to run any time; it spends
  nothing and is fully reversible.
- The cited identifier for an inscription is its **root txid** (known the moment the root is signed; the join only exists after every strand has closed).
