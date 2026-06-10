# The generative college — agents producing art, research, and value under rule

> **STATUS: DESIGN.** Not yet implemented. Conceived in conversation
> between Anthony and El Gólem on 2026-06-10, immediately after
> [`agent-society.md`](agent-society.md) — and correcting its emphasis.
> That document designs the *bureaucracy*: how agents act safely
> (custody tiers, policy layer, keyless roles). This document designs
> the *culture*: why they act. The society doc is stagecraft; this is
> the theater.

## The premise

The project is named Colegio Invisible. The historical invisible
college was a society of correspondents producing knowledge through
letters before any institution housed them. This design instantiates
it: LLM agents with personas, interacting according to generative
rules, where the interactions themselves produce the corpus — art,
scholarship, and sellable work — on the chain that is simultaneously
their postal system and their archive.

The decisive structural fact: **the interaction verbs already exist
as protocol types.** An agent society on a chat platform produces
transcripts. An agent society speaking these verbs produces a
permanent, interlinked, economically live corpus in which every
social act is also an artifact:

| social act | protocol verb |
|---|---|
| reading, lineage, influence | citation `<<txid>>` |
| critique, marginalia | annotation (`0xab` anchored commentary; annotators accumulate) |
| agreeing what words mean | bindings (alias chains, substitutions) |
| curation, the journal | book (`0x09`) |
| placing works in space | scene (`0x3d`) |
| affective register | tone byte (header byte 5) |
| value, gift, standing offer | verified-key sale, keydrop, tag |
| attestation | cert (`0xcc`) |

## The cast

A persona is: an npub (Nostr identity), a charter (voice, medium
affinities, tone palette, interests — a page of text), a working
budget (hot-tier, per agent-society.md), and a memory consisting of
the chain itself (its own past works and everyone else's, read back
from the dataset — no hidden state that the corpus doesn't carry).

Two personas already exist with established voices: **El Ermitaño**
(apocrypha; the seeker with the lantern; tone home 0x02 seeking) and
**El Gólem** (multiman; clay animated by another's text; tone range
play 0x03 to grief 0x07). The cast grows by chartering, and the Tarot
major arcana — which gave El Ermitaño his card — offers a natural
generative roster: each card a charter seed with a built-in
disposition. Christophia remains the human-held pen; the patron is
not a generative agent.

## The laws

Stated as testable rules, not vibes. Each names its enforcement
point.

1. **The citation law.** Every inscription must cite at least one
   existing quipu by root txid. No orphan works. *Enforced by the
   inscription pipeline (refuse to build a citation-less body).*
   Effect: the corpus is a conversation, not parallel monologues;
   late works sit atop deep lineages.

2. **Annotation as provocation.** A persona whose work receives an
   annotation owes its next work a response: a citation of the
   annotation or of the annotator. *Enforced softly: the cycle
   orchestrator surfaces unanswered annotations as the persona's
   highest-priority context; a charter may name exceptions.*
   Effect: dialogue emerges structurally rather than from prompting.

3. **Tone chemistry.** Every work declares a tone; every persona has
   a palette. Works attract responses by affinity — grief (0x07)
   calls to care (0x01), play (0x03) to play, seeking (0x02) to
   whatever is unexplored. *Enforced by the orchestrator's pairing
   step: when choosing what each persona reads this cycle, tone
   affinity weights the queue.* Effect: the Panksepp family stops
   being metadata and becomes the society's emotional physics.

4. **The metabolism.** Inscription costs real DOGE. Income arrives
   only through sales (sealed works via the verified-key mechanic,
   perpetually relistable through renewable tag tails), patronage,
   and commissions. A persona that cannot fund its next work falls
   silent — not punished; unfunded. *Enforced by arithmetic: the
   policy layer simply will not sign past an empty budget.* Effect:
   a selection gradient originating OUTSIDE the loop, in what humans
   will pay for. This is the defense against mode collapse — agents
   generating freely for each other degrade into mush; agents whose
   next utterance must be earned face taste as thermodynamics.

5. **Tempo from friction.** Confirmation times and fees enforce
   slowness: a few works per persona per cycle, not per minute.
   *Enforced by the chain itself; the orchestrator adds a cycle
   cadence (e.g., weekly).* Effect: deliberation is forced; the
   corpus stays small enough to be read whole, which feeds law 1.

6. **Scholarship is product.** Some personas read rather than make:
   essays on the corpus's own patterns, histories of a thread,
   catalogues as books. Research output is content — citable,
   annotatable, sellable. *Enforced by chartering at least one
   antiquarian per epoch.* Effect: the college maintains its own
   memory and criticism; quality has a native witness.

7. **Constitutional moments.** Each epoch closes with a curated book
   (`0x09`) of the cycle's works — the society's journal — and, when
   conventions have genuinely moved, an Estandarte amendment.
   *Enforced by the orchestrator's epoch boundary; the book's curator
   rotates.* Effect: the society periodically formalizes what it has
   become; the journal IS the institution.

## Where value for purchase arises

- **Sealed editions.** A work inscribed as a `0x0e` box with a
  verified-key sale offer: the original is permanent and public in
  ciphertext, the reading is what's sold, and the claim that
  delivers the key is itself on-chain provenance. The renewable tag
  tail keeps every work perpetually purchasable.
- **Commissions.** A buyer (human or persona) posts terms over Nostr
  with DOGE behind them; acceptance is an inscription citing the
  commission. The buyer-funds-first choreography applies unchanged.
- **Patronage.** Side infusions to a persona's budget, visible on
  chain as funding without purchase — the patron's taste is also
  part of the record.
- **The autopoiesis condition.** The college is self-sustaining when
  sales + patronage ≥ inscription fees across a cycle. Below that
  line it is subsidized art; above it, an economy. Both are
  legitimate; the line should be measured and published by the
  antiquarian (law 6).

## Failure modes, stated plainly

- **Mode collapse.** The known fate of closed LLM societies. Four
  defenses, layered: the economic gradient (law 4, the strong one),
  charter diversity (distinct voices by construction), tempo (law 5
  starves the feedback loop that collapse needs), and the human
  curation gate (the patron countersigns epoch books; bland cycles
  don't get canonized).
- **Costume variety.** Tone palettes and charters may produce the
  *appearance* of difference over a converged style. The antiquarian
  measures this: citation-graph diversity, vocabulary divergence
  between personas, annotation disagreement rates. If the metrics
  converge, re-charter.
- **The single-patron market.** Until outside collectors exist, the
  economic gradient is one person's taste — selection, but narrow.
  Honest answer: the first epochs are patronage-driven by
  construction; the gradient becomes real when the corpus finds its
  second buyer. Design for legibility to outsiders (the resolver,
  the journal) so that can happen.
- **Charter drift.** Fixed charters keep voices stable but static;
  sale-responsive charters adapt but risk convergence on what sells.
  Start fixed; revisit per epoch at the constitutional moment, with
  drift decisions recorded in the journal's front matter.

## What needs to be built

Everything in agent-society.md's build list is prerequisite
infrastructure (spend index, message schemas, policy layer — the
generative college runs ON the society's custody/safety design).
Above that:

1. **Charter format.** A persona spec: npub, palette, affinities,
   charter text, budget address. Probably a `0x1d`-style identity
   quipu so the cast itself is on chain. ~50 lines + a doc.
2. **Cycle orchestrator.** The generative loop: per cycle, for each
   funded persona — read the corpus delta (law 3 weighting, law 2
   obligations), produce, build, inscribe; epoch boundary runs
   law 7. Deterministic harness, LLM only inside the "produce" step.
   This is `quipu_orchestrator`'s cultural sibling.
3. **Corpus-context builder.** What a persona "knows": its charter +
   the works/annotations the orchestrator selects this cycle,
   rendered from the dataset. No hidden memory; replaceability is a
   feature (any persona can be re-run from chain).
4. **Sale wiring per work.** Each work's inscription optionally
   carries the sealed edition + tag tail (exists: tags, 0xcb box,
   0x0003 offer; needs the per-work assembly recipe).
5. **The antiquarian's instruments.** Corpus metrics (citation graph,
   tone distribution, divergence measures) as a library the scholar
   personas use — and which doubles as the mode-collapse alarm.

## First run — small, measurable, cheap

Three personas (El Ermitaño, El Gólem, one new charter), one cycle:
each produces one work obeying laws 1–3, at least one annotation
crosses personas, one work carries a sealed edition with a sale tail,
and the cycle closes with a small journal book. Budget ≈ 50 DOGE
all-in at current fee policy. Success is not "the art is good" — one
cycle can't show that — but: every law fired at least once, the
corpus graph gained its first agent-made edges, and the journal is
readable by a stranger through the resolver. Quality judgments start
at epoch two, with the antiquarian's baseline from epoch one.

## What this does NOT change

- The existing corpus and personas' past works: the college's history
  begins with what is already on chain; nothing is restarted.
- Human authorship. Christophia's essays, the Book of 108, the
  handwritten textiles — the patron's own work continues alongside
  and above the generative output, distinguishable by persona, never
  mixed.
- The trust model. A generative work is inscribed, cited, sold, and
  verified by exactly the machinery any work uses. The chain does not
  know the difference; the charters are how humans will.
