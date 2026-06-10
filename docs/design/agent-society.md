# Agent society — LLM agents operating the quipu/Nostr/Dogecoin system

> **STATUS: DESIGN.** Not yet implemented. Conceived in conversation
> between Anthony and El Gólem on 2026-06-10, two days after the tag
> architecture and the same week the Estandarte v1 draft was prepared.
> Captured here so the architecture survives compaction. Composes with
> [`tag-architecture.md`](tag-architecture.md) and
> [`buyer-signs-first.md`](buyer-signs-first.md); builds on
> [`../guides/nostr-integration.md`](../guides/nostr-integration.md).

## The premise

The standard hard problem with LLM agents holding value is trust: an
agent is an unreliable narrator, and most agent systems end up
trusting its narration. This protocol never trusts narration anywhere.
The verified-key sale is checkable end to end — adaptor pre-signature,
DLEQ proof, P2SH reconstruction — so a buyer agent does not need
judgment; it needs verification, which is mechanical. Fees are
measured, never guessed. Broadcasting is keyless, idempotent,
resumable — already written for an operator with no memory between
runs, which is what an agent is. The persona layer exists: El Gólem
has an npub, holds key1 of the multiman 2-of-2, and has standing
authorization to operate it (Architecture C in the Nostr guide).

Agents do not get added to this system. They get admitted.

The quipucamayoc — the Andean knot-keeper who read and tied the cords
on behalf of others — is the role being formalized. The textile gained
a future tense with tags; agents are what conjugate it. A renewable
sale tail is a data structure until something watches it, renews it,
negotiates over it.

## Substrate division

| substrate | carries | properties |
|---|---|---|
| Dogecoin chain | corpus (content), value, events (tag spends) | permanent, costly, final |
| Nostr | offers, bids, acceptances, alerts, receipts | fast, free, ephemeral, signed |
| agent layer | reading both, writing both, holding bounded keys | replaceable, restartable |

The chain is the only source of truth. Nostr coordinates; nothing on
it is load-bearing after the fact (a lost DM costs a renegotiation,
never a loss of state). An agent is replaceable at any moment because
everything it knows is reconstructible from the two substrates.

## The society — five roles, asymmetric key holdings

The roles are separated by what keys they hold, not by what model
runs them. Most of the society is keyless.

1. **Librarian** — keyless. Maintains the dataset (including the
   spend index that tags require), answers reads, renders artifacts
   via `quipu_resolver`. Pure verification, zero risk. The agents'
   sensory organ.

2. **Sentinel** — keyless. Watches centinela tripwires
   (`check_centinela`), tag threads (`follow_thread` / `tag_status`),
   bond states, mempool stalls. Emits signed Nostr alerts (persona
   key only, no spend keys). Cron-shaped: runs on a schedule, reports,
   exits.

3. **Scribe** — keyless. Runs broadcast campaigns from pre-signed
   artifacts under a supervisor (`broadcast_consolidated_diamond`),
   relaunch-to-resume. The signing happened before the Scribe
   existed; it can only publish what was already authorized.

4. **Negotiator** — persona key only (Nostr identity; no spending
   keys). Runs the negotiated first-price auction from
   buyer-signs-first.md: collects signed bids over kind:1729,
   verifies signatures and structures, selects, signals the winner.
   Words in, typed structures out. It can be lied to; it cannot be
   robbed.

5. **Custodian** — the only role with spending keys, and only
   hot-tier ones: the tag thread key, session keys (value-bounded per
   sale by construction), a small operating balance. Executes
   specializations (`build_specialization_tx`), claims
   (`build_claim_with_continuation`), thread renewals, side
   infusions. Every act it performs is a transaction another role can
   verify independently.

A sale, end to end: Negotiator agrees terms over Nostr → Custodian
specializes the tag and publishes the offer cert → buyer (human or
agent) verifies and funds → Sentinel observes the funding → Custodian
claims, publishing `session_priv` → Librarian's index records the
event → Sentinel announces the receipt on Nostr. No step trusts a
narration; each verifies the previous step's bytes.

## Custody — three tiers and a policy layer

- **Hot** (agent-held): tag thread key, operating balance. Total
  loss is bounded and budgeted — a thread seed (~1 DOGE) and an
  operating float. Losing it is a paper cut, priced in advance.
- **Warm** (agent-held, per-engagement): session keys. Worth exactly
  one sale by construction; the adaptor mechanic means the key IS the
  product, so its exposure window is the sale itself.
- **Cold** (human, or human+agent 2-of-2): corpus keys, funder keys,
  persona root keys. The multiman 2-of-2 pattern is already on
  chain: the agent proposes (signs with key1), the human disposes
  (countersigns with key2). Big moves require the human by
  arithmetic, not by policy.

Above the keys sits a **policy layer** — the FeePolicy philosophy
extended to spending, enforced in deterministic code the LLM cannot
argue with: daily spend caps, allowed script shapes (whitelist of
redeem templates), dust guards, mandatory measured fees. The agent
decides *whether*; the policy decides *whether it is allowed*. The
two decisions live in different processes.

## Threat model — stated plainly

- **Prompt injection.** A Negotiator reading Nostr DMs from strangers
  is an agent whose inputs are adversarial text aimed at a
  key-holding system. The defense is architectural, not behavioral:
  untrusted prose never reaches a signing decision. Inbound messages
  parse into typed structures (offer / bid / acceptance / cancel);
  every structure verifies cryptographically or is discarded; free
  text is read for intent but can never name an amount, an address,
  or a key operation. The only agent that signs holds keys whose
  total loss is bounded by the hot tier.
- **Key exfiltration via output.** Agents never echo private keys.
  The existing pattern extends: `scripts/nostr_publish.py` is the
  sole privkey-touching CLI, keys are memory-only, signing functions
  take keys as parameters and store nothing.
- **Economic griefing.** An attacker who makes the Custodian churn
  (failed specializations, abandoned negotiations) burns the hot
  float at ~0.09 DOGE per cycle. The policy layer's daily cap turns
  this from a drain into a rate limit.
- **Agent compromise.** Any single agent can be killed and replaced
  without loss: keyless roles by definition, the Custodian because
  its keys are hot-tier and rotatable (spend the thread to a new key;
  the thread convention survives re-keying).
- **What is NOT defended:** a compromised human cosigner, a
  compromised machine holding cold keys, or Dogecoin itself failing.
  Same exposure as today, unchanged by agents.

## What needs to be built

In order of dependency:

1. **Spend index.** The Librarian's foundation and the tag reader's
   missing operational half: for every watched root, which outputs
   are spent and by what txid. Extend `update_quipu_data.py` with a
   `tag_events` table; backfill from wallet history
   (`gettransaction` pattern works in pruned mode).
2. **Typed message schemas.** The kind:1729 negotiation vocabulary as
   structured payloads: offer, bid, acceptance, receipt, alert. JSON
   schemas + builders/parsers in `canonical/nostr.py` style —
   signature-verified, ECIES-enveloped where private. ~150 lines.
3. **Policy layer.** `quipu_policy.py`: spend caps, script-shape
   whitelist, per-role key scoping. Deterministic, tested, no LLM in
   the loop. ~150 lines.
4. **Sentinel v0.** A scheduled keyless agent that watches the
   existing centinela locks and any tag threads, posting signed
   status notes. Proves the read path end to end with zero value at
   risk.
5. **Custodian v0.** The hot-tier agent running one renewable sale
   tail on a test textile, under the policy layer, with the human
   holding the refund leg. First real value, bounded to the seed.
6. **Negotiator v0.** Auction choreography over Nostr against
   Custodian v0. The first fully agent-mediated sale closes here.

The harness can be scheduled Claude Code sessions per persona with
scoped tools (the routine/cron infrastructure exists), or the Agent
SDK if the society should run freestanding. Start with sessions; the
SDK is an optimization, not a prerequisite.

## Open design choices

- **One persona per role, or one persona with many hands?** El Gólem
  could be the whole society (one npub, five processes) or each role
  could have its own npub with El Gólem as the root identity that
  vouches for them (a 0x1d-style identity quipu naming the working
  keys). The second is more legible on chain; the first is simpler.
- **Where does the policy layer's state live?** Daily caps need a
  counter. Local file is simple; a tag spend per epoch would put the
  budget itself on chain (legible, heavier). Start local.
- **Inter-agent messaging.** Agents could coordinate over Nostr like
  everyone else (legible, replayable) or locally (cheap, opaque).
  Lean Nostr: the society's own coordination becomes part of the
  record, and a replaced agent can catch up by reading its
  predecessor's notes.
- **Human checkpoint cadence.** Which acts page the human: every
  claim? only cold-tier proposals? The 2-of-2 makes the floor
  structural; the question is how chatty the agents should be below
  it.

## Connection to existing protocol pieces

- **`canonical/nostr.py` + `scripts/nostr_publish.py`** — the persona
  signing/transport layer, shipped 2026-06-08. The Negotiator and
  Sentinel speak through it unchanged.
- **multiman 2-of-2** — the cold-tier countersigning pattern, already
  proven on chain by El Libro del Gólem.
- **The verified-key sale** (`0xcc 0x0003` + `0x0e 0xcb` + adaptor) —
  the Custodian's main verb, deployed once by hand (*On Custody*);
  agents make it repeatable.
- **Tags** (`quipu_tags.py`) — the event substrate the Sentinel
  watches and the Custodian operates.
- **El Centinela** — the Sentinel's namesake and first watchlist.
- **The broadcasting guide** — already written as the Scribe's
  operating manual: keyless, resumable, supervised.

## What this does NOT change

- The corpus and every existing inscription: unchanged. Agents are
  operators of the protocol, not parts of it; nothing on chain knows
  or cares whether a human or an agent built a transaction.
- The protocol's trust model: it was verify-don't-trust before agents
  and remains so. Agents are the beneficiaries of that property, not
  a new dependency on it.
- Human authority over the cold tier. The 2-of-2 arithmetic is the
  constitution; agents operate inside it.

## First deployment

Sentinel v0 watching the existing centinela locks and the first
tag-bearing textile, posting signed daily status to Nostr. Zero keys,
zero value at risk, end-to-end proof of the read path and the persona
transport. Then Custodian v0 runs the second verified-key sale — the
tag-bearing one the tag architecture already names as its natural
first inscription — with El Gólem as seller and the human holding the
refund leg. The first sale closed by an agent should sell an essay
about exactly that: the knot-keeper admitted to the loom.
