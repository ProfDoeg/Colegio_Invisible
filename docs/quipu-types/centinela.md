# El Centinela — cryptographic canary (sub-family `0e ca`)

> **STATUS: CANONICAL v1** (June 2026). Container implemented in
> [`canonical/encrypted.py`](../../canonical/encrypted.py) as sub-family
> `0e ca`; the value-layer locks + tooling in
> [`quipu_centinela.py`](../../quipu_centinela.py). All three lock modes were
> validated end-to-end on Dogecoin mainnet (block **6237951**, 2026-06-06).

A centinela is a **tamper-evidence tripwire**. You cannot observe whether an
encrypted blob has been *decrypted* — decryption is silent and offline. The
centinela converts that un-observable event into a **public, timestamped,
irreversible** one: the secret needed to claim a bait UTXO is sealed inside the
quipu, so a greedy opener moves the coins, and **the spend is the evidence**.

> Watch the bait outpoint. **Unspent = intact. Spent = the seal was opened**,
> and the spending block tells you *when*.

It lives on two layers:

| layer | what | the centinela's piece |
|---|---|---|
| **data** (quipu type) | OP_RETURN payload formats | the `0e ca` quipu — public descriptor + sealed secret |
| **value** (Bitcoin Script) | spending conditions on UTXOs | the lock (hashlock / HTLC) — *not* a quipu, just script |

The `0e ca` quipu (see [encrypted.md](encrypted.md#sub-family-0e-ca--centinela-canary))
is the data half: a public header descriptor (mode, outpoint, redeem, refund)
anyone can read to watch/verify, plus an AES-sealed body holding the claim
secret. This doc specifies the **value half** — the locks — and the lifecycle.

---

## Lock modes

### Mode C — HTLC hybrid (canonical; use this)

A P2SH output whose redeemScript is a hash-lock **AND** a signature, with a CLTV
refund leg:

```
OP_IF
    OP_SHA256 <H(P)> OP_EQUALVERIFY <D_pub> OP_CHECKSIG     # claim: preimage P + D's signature
OP_ELSE
    <T> OP_CHECKLOCKTIMEVERIFY OP_DROP <F_pub> OP_CHECKSIG  # refund: funder F, after height T
OP_ENDIF
```

- **Claim** (the opener, who got `P` and `D_priv` from the seal):
  `scriptSig = <sig_D> <P> OP_1 <redeemScript>`.
- **Refund** (the funder, after height `T`):
  `scriptSig = <sig_F> OP_0 <redeemScript>`, with `nLockTime = T` and a
  non-final input sequence (so CLTV is enforced).

Why C is the one with no asterisks:

| property | how |
|---|---|
| **self-locked / robust** | coins sit in a dedicated P2SH UTXO; can't be passively invalidated |
| **front-run resistant** | the `OP_CHECKSIG` under `SIGHASH_ALL` binds the destination — revealing `P` in the mempool is useless without `D_priv` to re-sign for a different output |
| **fee at claim time** | the opener builds + signs the claim *now*, so no frozen fee |
| **funder key hidden** | funds in from key X; the claim is signed by the throwaway D, never X |
| **recoverable** | the CLTV `ELSE` leg lets the funder reclaim an untripped bait after `T` |

### Mode A — pure hashlock (bearer)

`redeem = OP_SHA256 <H(P)> OP_EQUAL`; claim `scriptSig = <P> <redeem>` (no
signature). Self-locked and simplest, but **front-runnable**: once `P` is public
in the mempool, anyone can redirect the coins. For a canary this is often fine
(the *signal* is "the UTXO moved," not who got it) — but the destination is not
yours to guarantee.

### Mode B — pre-signed sweep

Coins in an ordinary P2PKH address; the seal holds a pre-signed sweep + the
burner key. Plain relay, bundles many outputs, hides the funder key — but
**fragile** (an input spent elsewhere invalidates it) and the **fee is frozen**
at sign time. `mode=A`/`mode=B` are reserved in the `0e ca` descriptor; only C
is wired in v1.

---

## Lifecycle

```
build_centinela(refund_height, funder_pub_hex)   →  P, D, redeemScript, P2SH address     (no key touched)
        │                                            └ fund the P2SH address (YOUR coins)
        ▼
seal_centinela(out_dir, outpoint, key)           →  the 0e ca quipu (descriptor + sealed {P,D_priv})
        │                                            └ inscribe it; hand out / withhold the AES key
        ▼
watch:  check_centinela(txid, vout)              →  intact | TRIPPED      (anyone, no key)
claim:  build_claim_tx(...)                      →  opener: <sig_D> <P> OP_1 <redeem>  → coins move = canary fires
refund: build_refund_tx(...)                     →  you, after T: reclaim an untripped bait
```

The lock must exist before funding (the P2SH address derives from
`H(P)`, `D_pub`, `F_pub`, `T`), and the descriptor's `outpoint` is known only
after funding — so `seal_centinela` is a post-funding step.

---

## Security model (read this before locking real value)

- **`P` must be high-entropy** — 32 random bytes, *not* a human password. A weak
  preimage lets someone brute-force `H(P)` and trip the canary without ever
  opening the seal.
- **It detects the greedy, not the disciplined.** A careful opener can read `P`
  and decline to spend, leaving no trace. A *spent* UTXO proves it was opened; an
  *unspent* one proves only that no greedy party opened it. Bigger bait = stronger
  pull, never a proof of non-access.
- **One-shot.** Trips once; re-arm = a new `P` + new UTXO.
- **Attribution.** One seal tells you *that* it was opened. A distinct `P` + UTXO
  per recipient tells you *which* — canary-per-recipient is traitor-tracing.
- **`SIGHASH_ALL` is load-bearing for Mode C** — the front-run resistance
  evaporates if the claim is signed `NONE`/`ANYONECANPAY`. The tooling signs ALL.
- **Seal credential** (the `0e ca` variant byte): raw 32-byte key (tamper
  tripwire — detects a specific keyholder) vs passphrase (a *puzzle* canary —
  but a weak passphrase is brute-forceable).

---

## Verified Dogecoin Script facts

Read from `~/Desktop/dogecoin/src` and confirmed empirically on mainnet:

- **P2SH redeem relays with no template requirement** — `AreInputsStandard`
  (policy.cpp:124) checks only `redeemScript.GetSigOpCount > MAX_P2SH_SIGOPS`; a
  bare hashlock / HTLC redeem (≤2 sigops) passes. scriptSig must be push-only
  (policy.cpp:90); pushes ≤ `MAX_SCRIPT_ELEMENT_SIZE` 520 B.
- **CLTV/CSV are active** (interpreter.cpp:350/392; validation.cpp:1903/1909).
- **No covenants / introspection** (`OP_CAT` etc. disabled; no
  `OP_CHECKTEMPLATEVERIFY`) — so there is no script-enforced "this output may only
  be spent alongside UTXO Y." Cross-spend coupling is via shared preimage (HTLC)
  or parent→child chaining only.
- **P2SH address version byte = 22** (`9…`/`A…`); `Doge().script_magicbyte`.
- **`sendrawtransaction` does full script verification before acceptance** — so
  relay-acceptance already proves the script executes true; the block just seals
  it.
- This node has **no `scantxoutset` / address index**, and `listunspent` is
  wallet-only — locate a non-wallet UTXO by reading the funding tx
  (`getrawtransaction(txid,1)`).

**Signing a custom redeem** (P2PKH `signall` won't do it):
`multisign(tx, i, redeem_hex, priv, SIGHASH_ALL)` signs against the redeemScript
as scriptCode; assemble the scriptSig manually with `serialize_script([...])` and
set `tx['ins'][i]['script']`. Note `mktx` mutates the input dict — snapshot the
outpoint first.

---

## On-chain validation

Block **6237951** (2026-06-06), all three modes claimed and mined, each ~3.3
DOGE swept back to apocrypha; whole three-mode test cost ~0.10 DOGE:

| mode | claim txid | redeem |
|---|---|---|
| A hashlock | `89e4d337…` | `OP_SHA256 <h> OP_EQUAL` |
| B pre-signed | `7e01ed7d…` | (plain P2PKH) |
| C HTLC | `518d15c7…` | `IF hashlock+CHECKSIG ELSE CLTV+CHECKSIG` |

Mode A's claim confirmed to apocrypha (not front-run, on this quiet protocol —
but the risk stands). Mode C's signature verified against a live UTXO and the
non-template P2SH redeem relayed + mined.

---

## Reference

Builder/reader: `canonical.encrypted.build_centinela_quipu` /
`parse_centinela_header` / `read_encrypted_quipu(…, key=)`. Locks + lifecycle:
`quipu_centinela.py` — `build_centinela` (Mode C), `build_hashlock` (A),
`build_presigned_lock` (B), `seal_centinela`, `build_claim_tx`,
`build_refund_tx`, `check_centinela`. Parallel test harness:
`working/centinela/run_tests.py`. Fees size-priced via
[`quipu_diamond.FeePolicy`](../guides/consolidated-diamond.md).
