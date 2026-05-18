# Quipu type `0x00` — Text

> **STATUS: CANONICAL v1.** Implemented in
> [`canonical/text.py`](../../canonical/text.py). The simplest quipu
> type; many existing on-chain inscriptions use it.

A *text quipu* is plain UTF-8 prose with a pipe-bracketed title. No
other structural fields. Bodies may use the citation convention
(`<<txid>>` and `<<txid>><<name>>`) and the essay-renderer field
convention (`Field: value\n`), but those are body conventions —
the protocol-level definition of `0x00` is just "UTF-8 in, UTF-8 out."

---

## Byte layout

### Header — 6 + (title) bytes

```
offset  bytes        meaning
0..3    c1 dd 00 01  magic + protocol version 0.1
4       00           type byte = text
5       <tone>       00 ordinary, 01 affection, ff reverence
6..     | TITLE |    UTF-8 between pipe sentinels (optional — may be absent)
```

### Tone vocabulary

| `<tone>` | name | when to use |
|---|---|---|
| `0x00` | ordinary | the default; descriptive, academic, neutral, or literary content about the living |
| `0x01` | affection | paired / intimate / addressed to a specific other |
| `0xff` | reverence | the dead, ancestors, formal commemoration |

`0xff` is *strict*: only for content that refers to the dead. Inscriptions
about the future, generational change, or imagined coming things use `0x00`,
not `0xff`. (Two Bowie "Oh! You Pretty Things" inscriptions on chain used
`0xff` and that's now a documented mis-tagging that stands — they should
have been `0x00`.)

`0x01` was first observed on the paired pair_HA / pair_CA inscriptions Mi
Caballo and Mi Perrito — short Spanish poems addressed to a beloved.

Any other tone byte is rejected by the canonical builder. A reader will
still parse a quipu with an unknown tone (the byte is passed through
unchanged) so future tone values won't break existing readers.

Empty title is permitted: the header is just 6 bytes
(`c1dd0001 00 <tone>`), with no pipes.

### Body — arbitrary UTF-8

No structural constraints. Length limited only by the diamond's
strand capacity (each strand carries up to 25 OP_RETURN knots × 80
bytes = 2000 bytes; a 4-cuerpo diamond holds ~8 KB of body, etc.).

---

## Title-field convention

The title is enclosed by literal `|` (`0x7C`) bytes. Runs of `|` are
equivalent — the parser splits on `|` and keeps only non-empty parts.
So `|TITLE|`, `||TITLE||`, and `|TITLE||` all yield `['TITLE']`.

If the header has multiple pipe fields, all are surfaced; the title is
the first non-empty one:

```
| TITLE | FIELD2 | FIELD3 |
```

→ `title = "TITLE"`, `fields = ["TITLE", "FIELD2", "FIELD3"]`.

---

## Body conventions (not protocol)

The following are conventions used by `essay_renderer.py` and the
abecedario/binding mechanism. A reader that doesn't recognize them
still gets valid UTF-8 prose back:

### Citations

- `<<txid>>` — refers to a whole inscription (the join txid).
- `<<txid>><<name>>` — refers to a named group or point inside another
  celestial quipu (resolved via `quipu_refs.resolve_ref`).
- `<<alias>>` — refers to an alias that must be resolved against an
  imported abecedario (`0xab`) or an inline binding.

### Inline bindings

```
<<sky>> = <<2ae7fe909e19c0e4646f7981d0feffc96f4a3b286539f3da8caf19aebcf93bb2>>
```

Establishes `sky` as an alias for the given txid within this document's
scope (and any document that imports it transitively).

### Field-value lines

```
Author: ProfDoeg
Date:   2026-05-17
```

Recognized by `essay_renderer.py` as typographic-promotable fields.
Unknown fields fall to a small footer block so nothing is lost.

---

## Worked example

A minimal text quipu titled "Mi Perrito":

```
header (18 bytes):
  c1 dd 00 01                         magic + version
  00                                  type = text
  00                                  tone = ordinary
  7c 4d 69 20 50 65 72 72 69 74 6f 7c   | Mi Perrito |

body (26 bytes):
  41 20 73 68 6f 72 74 20 6e 6f 74 65   "A short note "
  20 61 62 6f 75 74 20 6d 79 20 64 6f   "about my do"
  67 2e                                  "g."
```

Total: 44 bytes. Easily fits in a single OP_RETURN (≤ 80 bytes) — one
knot, no strand chaining required for short texts.

---

## Reference parser

See [`canonical/text.py`](../../canonical/text.py) for the authoritative
builder + reader. Round-trip self-tests cover:

- Basic ASCII title + body
- Reverence tone + Unicode title (Domrémy with `é`) and Unicode body
- Empty title (no pipes in header)
- Multiple pipe fields
- 3 validation cases (title-with-pipe, bad tone, bad body type)

---

## Why `0x00`

The type byte that costs nothing to think about. Default. The base case.
Every quipu the protocol can carry is, structurally, an elaboration of
this one. Reading a binary as a text quipu by mistake yields garbled
UTF-8 (loud failure), so the implicit "no type byte set" position can
never silently masquerade as something else.
