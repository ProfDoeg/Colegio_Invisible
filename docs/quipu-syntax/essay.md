# Quipu syntax — Essay

> **STATUS: DRAFT, version 1.** The pipe-delimited byte header is
> already in use across multiple on-chain inscriptions (Mi Perrito,
> Mi Caballo, Maier, Domremy, the image quipus, the encrypted-image
> quipus). The body markup conventions (paragraphs, references,
> bindings, embed dispatch, book TOC) are forward-looking — not yet
> instantiated on chain, but defined here for new inscriptions to
> follow. **If something doesn't work in practice, this spec gets
> updated.**

An **essay** is the project's structured-text format. Any quipu of
type `0x00` (text) following this convention is an essay. The
convention has two parts:

1. A **byte header** of pipe-bracketed fields (title required,
   additional metadata optional) immediately after the protocol bytes.
2. A **markup body** of UTF-8 text supporting paragraphs, references
   to other quipus, and local name bindings.

---

## Byte header — pipe-delimited fields

After the protocol header, one or more pipe-bracketed fields, then the
markup body:

```
c1dd 0001     2B magic + 2B version
00            type — text
TT            tone (00 ordinary, ff reverence)
|TITLE|       pipe-bracketed title field (required)
|FIELD2|...   additional pipe-bracketed fields (optional)
[body bytes]  markup body (UTF-8, see below)
```

The `|` character is the literal byte `0x7C`. Each field is bracketed
by opening and closing `|`. Multiple consecutive fields share their
boundary `|`: `|A|B|C|`. The body begins immediately after the
closing `|` of the last field.

This pipe convention is **already in use** across observed
inscriptions:

| Quipu | Type | Header bytes after type/tone |
|---|---|---|
| Mi Perrito | `0x00` text | `\|Mi Perrito\|` |
| Mi Caballo | `0x00` text | `\|Mi Caballo\|` |
| Maier 3-key declaration | `0xcc` cert | `00 01 \|SHA256\|33709...` |
| Domremy bordado | `0xcc` cert | `00 02 \|Domrémy Bordado Certificate\|` |
| Sun Face | `0x03` image | `[L,W,B params] \|Sun Face\|` |
| Domremy image | `0x03` image | `[L,W,B params] \| Domremy: Campo de Bourlemont \|` |
| Encrypted image #8 | `0x0e` enc | `[L,W,B,N_recip] \|Here is an encrypted image...\|` |
| Identity DrDoeg | `0x1d` id | `00 \|Declaration of Identity\|` |

For an essay (type `0x00`), the minimal header is just `|TITLE|`. No
type-specific structured bytes precede it.

## Optional header fields

Any field after the title is optional. Recommended conventions for
common cases:

| Position | Field | Format |
|---|---|---|
| 1 | TITLE (required) | UTF-8 string, e.g. `The Domremy Bordado` |
| 2+ | AUTHOR | `<<txid>>` reference to identity quipu, or a name |
| 2+ | DATE | ISO 8601 (`2026-05-10`) |
| 2+ | SUBTITLE | UTF-8 |
| 2+ | SERIES | series name (`Mochuelos | Issue 7`) |

Field positions after the title are not fixed — readers identify
fields by content (a date matches `\d{4}-\d{2}-\d{2}`, an identity
reference matches `<<[a-f0-9]+>>`, etc.) rather than by ordinal.

If a publication wants stricter positioning, declare it as a
per-imprint convention. The protocol stays flexible.

---

## Markup body

After the closing `|` of the last header field, the body begins.
UTF-8 text with these conventions.

### Paragraphs

Plain prose, paragraphs separated by one or more blank lines (`\n\n`).
No special formatting markup. Indentation, bullets, and emphasis
follow whatever the inscriber chooses (markdown-style, plain text,
ASCII art) — readers render whatever's there.

### References to other quipus — `<<txid>>`

The `<<txid>>` syntax embeds a reference to another quipu by its
transaction ID. Already in use by Domremy. Two kinds, distinguished
by position:

- **Inline reference** (inside a paragraph) → **citation**. Reader may
  display as a footnote, hyperlink, or annotated mention. Doesn't
  disrupt prose flow.
- **Standalone reference** (alone on a line, blank lines above and
  below) → **embed**. Reader resolves the reference and renders the
  target inline:

| Resolved type | Standalone embed behavior |
|---|---|
| `0x00` text (essay) | render body inline; recursively process markup |
| `0x03` image | render image |
| `0x0e 0x0e 0x0d` key drop | use the released key to decrypt a previously-shown encrypted quipu |
| `0xab` bindings | import all bindings into this essay's namespace (no rendering) |
| `0xce` celestial | render the celestial figure (map / constellation / vigil) |
| anything else | structured fallback display of the referenced type |

Partial txid prefixes work: `<<a90fb98>>` is valid if it uniquely
identifies a transaction. Reader resolves at read time.

### Bindings — local name aliases

Within an essay, the line:

```
<<NAME>> = <<txid>>
```

defines a binding. Anywhere else in the same essay, `<<NAME>>`
resolves to `<<txid>>`. The binding line itself is metadata, stripped
from the rendered output.

Conventions:

- `NAME` is UTF-8 with no whitespace and no `<` or `>` characters.
  Case-sensitive (`DomCert` and `domcert` are different bindings).
- Bindings are **document-scoped** — they don't carry across
  inscriptions.
- Bindings apply throughout the document — define anywhere, use
  anywhere. Reader does a first pass to collect bindings, second pass
  to resolve.
- **No redefinition** — if `<<X>>` is bound twice with different
  txids, the inscription is malformed. Reader's choice whether to
  error or use the first binding.
- Right-hand side is always a literal txid, never another name. No
  transitive chains.
- Partial txid prefixes work in bindings too:
  `<<DomCert>> = <<6da7a9a>>`.

### Importing bindings from a `0xab` quipu

A standalone embed of a `0xab` bindings quipu imports all its
bindings into this essay's namespace:

```
<<bindings_quipu_txid>>

The Domremy bordado at <<DomCert>> was issued under the certificate
authority at <<MaierDecl>>...
```

See `docs/quipu-types/bindings.md` for the bindings quipu spec.

---

## Worked example — a Domremy essay

```
HEADER (byte view):
c1dd 0001 00 ff |The Domremy Bordado|<<christophia_id_txid>>|2026-05-10|

BODY:
<<CommonNames>>

The Domremy bordado at <<DomCert>> was issued under the certificate
authority at <<MaierDecl>>, with all three witnesses (<<Hayagriva>>,
<<Christophia>>, <<Anthony>>) attesting.

<<DomImage>>

This is the bordado proper, whose 5 strands carry the certificate's
five seal mechanisms. Each strand inscribed in turn under the
bordado 3-of-3 multisig.

The bordado's authority is anchored in <<MaierDecl>> — see that
declaration for the witness public keys and their cryptographic
relationships.
```

Header: title, author identity reference, date — three pipe-bracketed
fields. Body: imports common bindings, prose with named references,
an embedded image rendered inline, more prose with a citation.

---

## The book convention

A **book** is structurally an essay where the body is mostly a list
of standalone embeds (one per line), forming a TOC. Each TOC entry
can optionally be annotated with `| as: "..."` to override the
referenced essay's own title for display in this book.

```
HEADER:
c1dd 0001 00 00 |Mochuelos Volume I|<<christophia_id_txid>>|2026-05-10|

BODY:
<<CommonNames>>

<<essay_1_txid>>
<<essay_2_txid>> | as: "Reflections on the Bordado"
<<essay_3_txid>>
<<essay_4_txid>> | as: "On the Apocrypha and the Errors"
<<essay_5_txid>>
```

The reader rendering this book:

1. Reads the book essay's own header (title, author, date, etc.)
2. For each standalone embed line in the body, resolves the txid
3. If `| as: "..."` is present on the line, displays that title in
   this book's TOC instead of the referenced essay's own title
4. Listed in body order — that's the book's reading order
5. Following any TOC entry shows the full referenced essay with its
   original title and content intact

The `| as: "..."` override is purely cosmetic for the TOC. The
referenced essay isn't modified — it lives at its txid with its own
title forever.

A book is just an essay with a particular body shape. No new type
byte. The `| as: "..."` convention is the only addition over normal
essay markup.

---

## Reader algorithm (informal)

```
1. Strip protocol header bytes (c1dd 0001 type tone).
2. Parse pipe-bracketed fields until a non-pipe byte is encountered.
   First field is the title; subsequent fields are optional metadata.
3. Body bytes begin after the closing | of the last field.
4. First pass over body:
   - Collect all <<NAME>> = <<txid>> lines as bindings.
   - Resolve all standalone <<txid>> embeds:
     - If type 0xab (bindings), recursively collect those bindings.
     - Otherwise leave for second pass.
5. Second pass over body:
   - Skip binding-definition lines (already collected).
   - For each paragraph: replace inline <<NAME>> with <<txid>> via
     the binding map; emit the prose as a paragraph element.
   - For each standalone <<txid>>: dispatch by referenced type and
     render in place (recursing for essay/markup, fetching for image,
     decrypting for key drops, etc.).
6. Render the result.
```

Reference parser is ~50 lines of Python. To be implemented in
`colegio_tools.py` as `read_essay()` / `mk_essay()` once this spec
is exercised in practice.

---

## Open questions

1. **Escape syntax for literal `|` in title text.** Vanishingly rare
   in normal titles. Handle case-by-case if it ever happens.

2. **Reference resolution failures.** Reader-side concern, not
   protocol. Reader chooses what to do when a referenced txid
   doesn't exist or isn't accessible (placeholder, error, retry).

3. **Cycle detection in recursive embeds.** Reader-side concern.
   Recommended: cap recursion depth at a reasonable value (say 16),
   or detect cycles by tracking visited txids during resolution.

4. **Field detection in multi-field headers.** v1 lets readers
   identify field types by content (date pattern, `<<txid>>`
   pattern). If this proves too ambiguous in practice, future
   versions could add explicit field tags within each pipe-bracketed
   segment (`title:`, `author:`, etc.).

5. **The `| as: "..."` annotation syntax for books.** Currently uses
   a pipe-prefix on the embed line. If pipes-in-body-lines turn out
   to be confusing to readers (the markup convention vs the header
   convention sharing a delimiter), an alternative annotation syntax
   could be considered.

6. **Series and issue conventions.** Recurring publications probably
   want a stable convention beyond "use the SERIES field." Will
   emerge from use.

7. **Relationship to existing certificates.** Maier and Domremy use
   `0xcc` cert with pipe-delimited bodies that already follow much
   of this convention. A future revision could either fold them into
   the essay convention or keep them as a distinct type. For now,
   they remain `0xcc` certs and are not essays.
