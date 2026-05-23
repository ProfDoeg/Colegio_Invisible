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

### Header — 6 + (header tail) bytes

```
offset  bytes        meaning
0..3    c1 dd 00 01  magic + protocol version 0.1
4       00           type byte = text
5       <tone>       tone byte — see tone.md for the canonical vocabulary
6..     | header tail |    pipe-delimited title + optional key=value fields
```

The header tail is one or more pipe-delimited fields:

```
| title | key1=value1 | key2=value2 | ... |
```

- The **first** non-empty field is the title (must contain no `=`).
- Every **subsequent** field is `key=value` (must contain `=`).
- All header bytes are UTF-8 (regardless of the body's `encoding=` field
  — only the body honors `encoding`).
- Pipes (`|` / 0x7C) are forbidden inside keys and values.
- Empty title plus fields is legal: `||key=value|...|`.
- Empty header tail is legal: `c1dd0001 00 <tone>` with no further bytes.

### Reserved field names with canonical formats

None are required. If any of these is present, it must follow the form:

| field      | format                                                | Python interop |
|------------|-------------------------------------------------------|---------------|
| `encoding` | IANA codec name (any alias `codecs.lookup` accepts)    | `bytes.decode(encoding=...)` |
| `date`     | ISO 8601 / RFC 3339: `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SS{Z\|±HH:MM}` | `datetime.fromisoformat(...)` |
| `lang`     | BCP 47 tag: `en`, `es`, `la`, `en-US`, …               | `langcodes.Language.get(...)` |
| `author`   | free UTF-8 string (no canonical format)                | —             |

Only `encoding` is **protocol-significant**: the canonical reader uses it
to decode the body bytes. Default `utf-8` if absent. Other reserved
fields are display-oriented — readers should render them but aren't
required to.

Unreserved keys pass through opaquely. Inscribers may use any key they
like; readers display what they recognize and ignore the rest.
Conventions can settle later via Estandarte's conventions block.

### Multi-value handling

Each key appears at most once in a header. For naturally multi-valued
fields, use comma-separated values within one entry
(`author=Frank Johnson, Mary Lee`) or distinct keys (`composed=…`
plus `inscribed=…`). The canonical builder rejects duplicate keys;
if a reader encounters them, last-write-wins.

### Backward compatibility

The bare `|TITLE|` form used by the five canonical text inscriptions
already on chain (Mi Perrito, Mi Caballo, Atom, both "Oh! You Pretty
Things" Bowie texts) parses cleanly under this extended grammar —
they're just "one field, no key=value pairs."

### Tone vocabulary

The tone byte is transverse across all quipu types — its full value
table, semantics, and history live in [tone.md](tone.md). Text quipus
accept the same four canonical values that every other type does.

The bare `|TITLE|` form (no key=value fields) plus an empty title is
permitted: the header is just 6 bytes (`c1dd0001 00 <tone>`), with no
pipes. The two Bowie "Oh! You Pretty Things" text inscriptions on
chain that carry tone `0xff` are documented in tone.md as
mis-tagged-but-preserved precedents.

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
