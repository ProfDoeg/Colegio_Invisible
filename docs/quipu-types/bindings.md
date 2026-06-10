# Quipu type `0xab` — Bindings (abecedario)

> **STATUS: v1 + v2 implemented in canonical/bindings.py and integrated
> into the essay-render pipeline in canonical/essay.py.** v1 line kinds
> (import / alias-chain / string-sub) continue to work unchanged; v2
> adds chain grammar + flags. Self-tests cover the parser, the chain
> engine (`apply_citations`), the markdown-safe block applicator, and
> the typo-fix-then-cite pipeline order. v1 bindings on chain
> (≥ 6,217,751) remain valid; v2 will be exercised by the Dos ensayos
> book's correction binding.

A **bindings quipu** (Spanish: *abecedario*) is a flat list of
`NAME → txid` assignments. Other essays import its bindings via a
standalone `<<txid>>` embed. Used to give project-canonical short
names to recurring entities — certificates, identities, places,
images — that would otherwise need to be redefined in every essay
that mentions them.

The byte `0xab` is chosen for *abecedario* (the alphabet, what you
reach for first to name things) and matches the project's bilingual
register.

---

## Byte layout

```
c1dd 0001     2B magic + 2B version
ab            type — bindings
TT            tone byte — see tone.md for the canonical vocabulary
[body bytes]  one binding per line, see below
```

No header fields, no length prefixes, no counters. The body's
structure is per-line.

## Body format

Pure UTF-8 text. Three line kinds. Lines are evaluated in source order;
later assignments override earlier ones (**last-write-wins**).

### 1. Import another binding

A line containing only a `<<txid>>` citation imports another `0xab`
quipu's bindings at this point in the evaluation:

```
<<bbbbbb…txid_of_other_ab_quipu…bbbbbb>>
```

The imported binding's body is evaluated as if its lines appeared
here. Subsequent lines in the importing binding can override anything
the import brought in. Imports may themselves import other bindings,
forming an inheritance chain. Cycle detection is the reader's
responsibility.

### 2. Alias assignment

Bind one or more `<<Alias>>` names to a target txid:

```
<<Alias>>=<<txid235978659817…>>
<<Alias1>>=<<Alias2>>=<<Alias3>>=<<txid235978659817…>>
```

The chained form is shorthand for assigning each alias on the left to
the same target. All three names become independently usable.
`<<Alias3>>` may itself be a previously-defined alias rather than a
raw txid — assignment chains resolve transitively.

### 3. String substitution

A `"quoted"="quoted"` pair specifies a pure text replacement applied
to importing essays:

```
"Sirichinova"="Sinchova"
"Domremy"="Domrémy"
```

No `<<...>>` involved. Useful for spelling variants, transliteration
corrections, terminology updates. Substitutions accumulate across
imports and are applied to essay body text wherever the binding is
imported.

### Comments and whitespace

Empty lines are ignored. Any line that does not match one of the
forms above (v1 or v2) is treated as a comment.

---

## v2 extension — chain grammar

The v1 line kinds (import, alias chain, string substitution) are
three special cases of a more general **chain grammar**. v2 generalizes
the grammar without breaking v1 — every v1 line continues to parse
identically. v2 adds three new line kinds that fill in the missing
combinations.

### Three node types

A chain is one or more nodes separated by `=`. Each node is one of:

| node | syntax | meaning |
|---|---|---|
| string  | `"X"`                       | a literal piece of text |
| alias   | `<<Name>>`                  | a previously-defined name |
| txid    | `<<64-hex>>`                | a 64-char hex transaction id |

The grammar parser distinguishes alias from txid by content: 64 hex
characters → txid; otherwise → alias. Both use `<<...>>` brackets.

### Six chain forms (v1 + v2)

```
   <<txid>>                                  import           (v1)
   <<A>>=<<B>>=…=<<txid>>                    alias chain      (v1)
   "X"="Y"                                    text substitution (v1)
   "X"=<<txid>>                              text-to-citation  (v2 NEW)
   "X"="Y"=<<txid>>                          text-class citation chain (v2 NEW)
   "X"=<<A>>=<<txid>>                        text → alias → terminal (v2 NEW)
```

A chain is **anything** that's nodes separated by `=`, as long as:
- It's not a bare `<<txid>>` (that's an import)
- All nodes use either `"..."` or `<<...>>` syntax (no bare words)

### Chain terminus determines the rendering mode

The **terminus** (last node) determines what happens when a chain is
applied to body text:

| chain ends in | mode | what happens |
|---|---|---|
| `"Y"`     | **text replacement**       | every occurrence of any string-node in the chain is rewritten literally to `Y` |
| `<<txid>>` | **equivalence-class citation** | every occurrence of any string-node in the chain becomes a markdown citation pointing at `txid`; **the matched surface form is preserved as the anchor text** |

So `"Hayagriva"="hayagriva"="HAYAGRIVA"=<<txid_C>>` means: any of those
three strings, wherever found in body text, becomes
`[<matched form>](quipu:txid_C)`. If prose contains "Hayagriva", the
rendered anchor is "Hayagriva". If prose contains "hayagriva", the
rendered anchor is "hayagriva". The chain defines an equivalence class
of triggers; the typography of the prose is preserved.

This is how case-insensitivity is handled in v2: **the author lists
the case variants they care about, explicitly**. No global
case-folding flag — chains make it surgical.

### Default behavior

Chains apply to body text with these defaults:

- **Word-bounded** — string-nodes match on word boundaries (`\b` in
  regex terms). `"art"` matches the word "art" but not "artisan" or
  "cart". An author who wants substring matching must use the `@all`
  flag (see below) and accept the consequences.
- **Surface-form-preserving** — anchor text = matched form, not the
  normalized intermediate.
- **First-per-block** — within one paragraph / heading / list-item,
  the chain fires once. Subsequent occurrences of any matching string
  in the same block render as plain text (assumption: the author
  wants the first mention to be the citation, later mentions are
  prose).
- **Case-sensitive** — `"Hayagriva"` does not match "hayagriva"
  unless both are listed in the chain.

### Flags

Optional per-line flags adjust default behavior. Syntax: trailing
`@flag` tokens after the chain.

| flag | meaning |
|---|---|
| `@all`          | match every occurrence in body text, not just the first per block |
| `@once-per-doc` | match only the first occurrence in the entire document; later occurrences render as plain text |

Examples:

```
"Hayagriva"=<<txid_C>>                   first-per-block (default)
"Christamicus"=<<txid_B>>   @all         every occurrence
"Bordado"=<<txid_X>>        @once-per-doc only first in document
```

Other flags can be added later. The trailing-`@flag` syntax stays
forward-compatible: unrecognized flags emit a warning and are ignored.

### Why these three new forms

`"X"=<<txid>>` — the simplest "text mention → citation" rule. The
common case when an author wants to write prose normally and have the
engine resolve specific names to citations.

`"X"="Y"=<<txid>>` — the equivalence-class case. Lets the author list
multiple surface forms (case variants, spelling variants,
translations, abbreviations) that should all resolve to the same
target, while preserving whichever form the prose actually used.

`"X"=<<A>>=<<txid>>` — combines text trigger + alias for completeness.
Rare in practice; included so the grammar is regular.

### Pipeline order

When an essay body is rendered, the substitution pipeline runs in this
order (see `canonical/essay.py::substitute_body`):

1. `extract_binding_blocks` — pull fenced ```binding blocks out of the
   markdown.
2. `evaluate_blocks` — walk imports, accumulate aliases, substitutions,
   and citation rules into a single `BindingDict`.
3. `resolve_citations` — replace explicit `<<...>>` citations in body
   text with markdown links.
4. `apply_substitutions` — v1 literal text rewrites. Runs **before** v2
   citation matching so typo-fix subs feed cleanly into the citation
   engine (e.g. a binding can write `"hebreo"="yiddish"` on one line
   and `"yiddish"=<<txid>>` on the next — the prose's "hebreo" gets
   rewritten to "yiddish" first, then matched as a citation trigger).
5. `_apply_citations_to_markdown` — v2 chain rules, block-by-block,
   skipping existing markdown links / inline code / fenced code.

### Backward compatibility

Every v1 binding line continues to parse exactly as before. The v2
parser is a superset of v1's. Bindings inscribed under v1
(`<<txid>>` imports, `<<A>>=<<txid>>` alias chains, `"X"="Y"` text
subs) read identically under v2.

The substitution engine's v1 behavior for `"X"="Y"` text subs is
preserved: pure literal replacement, no word-bounding, no flag
support. v1 string-sub semantics did not specify word boundaries, so
adding them would change existing behavior; the v2 word-bounding
default applies **only** to chains ending in `<<txid>>` (the new
forms). The classic `"X"="Y"` form retains v1's all-occurrence
literal-rewrite semantics.

---

## v3 extension — annotation primitive

The substitution and citation primitives both *transform* the text they
match — substitution rewrites the string, citation wraps it in a link.
The annotation primitive does something different: it *attaches a
multi-paragraph note* alongside the matched anchor without modifying
the prose. This is the protocol's equivalent of Talmudic marginal
commentary, scholarly footnotes, or Tufte-style sidenotes.

### Fenced syntax

Annotations are line-spanning so they need a fenced form rather than
a single-line rule:

```
@@anchor phrase here
Note body. Markdown. Multiple paragraphs allowed; the @@…@@ fence is
the boundary, not the blank-line convention.

*Italics*, **bold**, `code`, [links](quipu:txid), inline citations
like <<txid>> — anything markdown supports.
@@
```

The opening fence is a line starting with `@@` followed by the
anchor string (and optional flags, see below). The closing fence
is a line containing only `@@`. Everything between is the note body
as markdown.

The parser emits `('annotation', anchor_str, note_md_str, position_or_None, flags_frozenset)`.

### Anchor matching

Same find-and-replace architecture as substitution and citation:
the renderer finds the literal anchor string in the essay body and
attaches the note at that point.

Default behavior: **first occurrence per block** (paragraph, heading,
list-item).

### Disambiguation flags

```
@@anchor                       first occurrence per block (default)
@@anchor #3                    third occurrence in the essay
@@anchor @all                  attach a copy at every occurrence
@@anchor @once-per-doc         first occurrence in the entire document
```

Same vocabulary as v2 citations (`@all`, `@once-per-doc`), plus the
`#N` positional suffix for picking the nth occurrence when the
anchor isn't unique.

### Presentation flags

Per-note hint to the renderer about *how* to display the note. The
renderer respects when capable, falls back gracefully:

| flag | HTML render | text-only fallback |
|---|---|---|
| `@margin` (default) | Tufte-style sidenote floated to the right column, aligned to the anchor's line; on narrow viewports collapses to inline-below | bracketed `[note]` after anchor sentence |
| `@endnote` | numbered superscript at anchor; full text collected in a "Notes" section at the end of the essay | numbered `[¹]` + endnotes list at end |
| `@inline` | bracketed insertion at the anchor point, `[note]` in the prose flow | identical |

The renderer may also offer a global override (e.g. "render every
annotation as endnote for a print-friendly view") that collapses
inscriber preferences into a single mode. The per-note flag is the
inscriber's first choice; the reader may override.

LaTeX rendering of annotations is **not specified** in v1 — the
project plans a custom document/book class with its own typography
opinions; the spec should not couple to off-the-shelf packages.

### Flag combinations

Disambiguation and presentation flags compose freely on the same
anchor line:

```
@@Beatrice #2 @endnote                second occurrence, as endnote
@@Hayagriva @all @inline              every occurrence, bracketed inline
@@Operation Condor @once-per-doc      first in document, default presentation (margin)
```

Order doesn't matter; the parser scans trailing tokens until it
finds the first non-flag token. Everything before is the anchor.

### Composition across annotators

A book may import multiple annotation bindings (one academic, one
personal, one AI commentary). Annotations from different bindings
**accumulate** rather than overriding — every note appears at its
anchor. The renderer attributes by the binding's tone byte and
author field:

- `0xa1` ai — color-coded as AI commentary
- `0x00` ordinary — neutral
- `0xff` reverence — formal/canonical

This makes the same essay annotatable in multiple registers
simultaneously, with the registers visually distinct but coexistent.

### Composition with substitution and citation

Pipeline order matters. The full pipeline becomes:

1. **v1 substitutions** rewrite the prose (e.g. `"hebreo"="yiddish"`)
2. **`<<...>>` citations** resolve to markdown links
3. **v2 citation chains** wrap prose terms as links
4. **v3 annotations** attach notes against the rewritten prose

Annotation anchors should therefore be expressed against the
*post-substitution* form of the prose. A binding that performs both
a substitution and an annotation on the related phrase should
anchor on the rewritten form:

```
"hebreo"="yiddish"

@@yiddish of the joven Goethe
This phrase is the corrected form; the historical inscription
used "hebreo," which v1 substitution rewrites before this
annotation runs.
@@
```

### Unattached anchors

If an annotation's anchor doesn't exist in the essay body (typo,
paraphrase, anchor matches a phrase the substitution layer removed),
the renderer surfaces it as **unattached** in the essay's colophon
section rather than silently dropping the note. The inscriber's
intent is preserved as visible-but-misplaced, which lets readers
see what was meant.

### Why a new primitive instead of overloading substitution

A substitution could in principle embed an inline note as its
right-hand side (`"X"="X [El Gólem: …note…]"`), and we did consider
this. Reasons annotation is a separate primitive:

1. **Honesty.** Substitution declares "rewrite X to Y." If Y is
   really commentary about X, the binding is lying about its kind.
   Future readers parsing the binding can't distinguish a typo-fix
   from a footnote.
2. **Multi-paragraph notes** don't fit substitution. Right-hand
   sides are single-line quoted strings.
3. **Presentation modes.** Substitution has no concept of margin
   vs endnote vs inline. Annotation declares the rendering hint
   at the primitive level.
4. **Composition.** Multiple substitutions on the same string
   override each other (last-write-wins). Multiple annotations on
   the same anchor accumulate. The semantics are different and
   should be distinct in the protocol.

## Example

```
<<commonNames_v1_txid>>                                  # inherit prior names

<<MaierDecl>>=<<1ec0ee9b27d6ab91…2dba7d0c>>
<<DomCert>>=<<DomremyBordadoCertificate>>=<<6da7a9a9…b2fb4910>>
<<DomImage>>=<<b92bbbf974ad7d1b…5da0b66c>>
<<LaVernaImage>>=<<2b01e2094c52bf99…8a932d6a>>

<<Hayagriva>>=<<hayagriva_identity_txid>>
<<Christophia>>=<<christophia_identity_txid>>
<<Anthony>>=<<anthony_identity_txid>>

"Sirichinova"="Sinchova"
"Domremy"="Domrémy"
```

Body bytes are pure UTF-8. No protocol-level structure beyond the
`c1dd 0001 ab TT` header.

## Importing bindings into an essay

Within an essay (`0x00` text quipu using markup), a standalone embed
of a bindings quipu imports its bindings:

```
<<bindings_quipu_txid>>

The Domremy bordado at <<DomCert>> was issued under <<MaierDecl>>...
```

The reader, encountering a standalone `<<txid>>` and resolving it to
type `0xab`, adds every binding in the quipu's body to the current
essay's namespace. The bindings quipu itself is **not rendered in
place** — its function is to populate names, not to display content.

## Composing multiple bindings quipus

An essay can import multiple bindings quipus by listing each as a
standalone embed at the top:

```
<<CommonNames>>
<<MochuelosNames>>
<<TodaysProjectBindings>>

[essay body uses any defined name]
```

If the same NAME appears in multiple imports with different txids,
**last-write-wins**: the most recent assignment in evaluation order
takes effect. This is consistent with shell-style variable assignment
semantics and lets a binding override a name from an earlier import
just by reassigning it.

## Evaluation algorithm

When a reader compiles an essay (or a binding) that contains imports,
two dicts are at play:

- `P_pristine` — the dict-as-passed-from-parent, frozen for the current
  binding's evaluation. This is what gets passed DOWN to each child
  import.
- `P_render` — the dict used to render the current binding's own body.
  Starts as a COPY of `P_pristine`. Each child import returns a dict;
  the new entries merge into `P_render` (last-write-wins). Local
  assignment and substitution lines also mutate `P_render` in document
  order.

A global `visited` set tracks every txid that has been evaluated during
this compile pass. It prevents both cycles and redundant re-evaluation
of the same binding when it's imported from multiple paths.

### Pseudocode

```python
def evaluate(binding, P_pristine, visited):
    if binding.txid in visited:
        return copy(visited[binding.txid])      # cache hit; return a COPY
    visited[binding.txid] = {}                   # placeholder for cycle break
    P_render = copy(P_pristine)
    for line in binding.body:
        if line is <<txid>>-import:
            child = evaluate(fetch(txid),
                             copy(P_pristine),    # children get their OWN copy
                             visited)
            P_render = merge(P_render, child)    # last-write-wins
        elif line is <<A>>=<<B>>=...=<<target>>:
            for name in (A, B, ...):
                P_render[name] = target
        elif line is "X"="Y":
            P_render.substitutions.append((X, Y))
    visited[binding.txid] = copy(P_render)        # store a COPY in cache
    return copy(P_render)                          # return a COPY to caller
```

### Properties

- **Value semantics throughout.** Every dict that crosses a scope
  boundary is a copy. No shared mutable state between scopes; a child
  cannot reach back into its parent's dict.
- **Cycles terminate.** A→B→A on re-entry hits the placeholder in
  `visited`, returns the empty dict, and the recursion unwinds. The
  inscriber should avoid cycles deliberately; the reader stays safe.
- **Diamond imports are memoized.** If X imports Z and Y also imports Z,
  Z is evaluated once. Both X and Y receive copies of Z's cached
  result.
- **Imports are commutative on `P_pristine`.** Each child sees the
  parent's frozen pre-import state; siblings cannot pollute each
  other's evaluation. Only the parent's `P_render` accumulates across
  imports.
- **Resolution at use-site, not assignment-site.** An alias chain
  `<<A>>=<<B>>=<<txid>>` stores three entries: `A → txid`, `B → txid`,
  and `txid` as the resolved terminal. When an essay later writes
  `<<A>>`, the reader walks the chain at render time, with cycle
  detection limited to 8 hops.

### Failure modes

- **Alias cycle** (`<<A>>=<<B>>; <<B>>=<<A>>`): detected at resolution
  time. Reader raises or marks the citation unresolved.
- **Unresolvable alias** (name never bound to a txid): renders as the
  raw `<<Name>>` literal, with a class flagging it.
- **Deep chain** (> 8 hops): treated as a likely error; resolution
  bails with a warning.

## Render output

When the essay body contains `<<Alias>>` and resolution succeeds, the
renderer emits a hyperlink:

- **Anchor text**: the resolved inscription's `title` (or for two-segment
  `<<Alias>><<SubObj>>`, the sub-object's name).
- **href**: a viewer URL for the resolved txid.

For example, `<<DomCert>>` in essay prose renders as a clickable link
labeled "Domrémy Bordado Certificate" pointing at the cert's viewer
page. String substitutions from `P_render.substitutions` are applied to
the surrounding essay text before citation parsing.

## Versioning

Bindings quipus are immutable on chain. To version, inscribe a new
bindings quipu and reference its new txid:

- `<<CommonNames v1>>` — one quipu's txid
- `<<CommonNames v2>>` — a different quipu's txid

Old essays still resolve under v1; new essays import v2. The chain
itself is the version control. There is no in-protocol way to
deprecate a bindings quipu — they exist forever — but inscribing a
new "v2" and circulating its txid is the project-level mechanism.

## Corrections — bindings are the overwrite layer

> Doctrine settled 2026-06-10, the day the Dantean Cosmos phantom was
> found: the on-chain orrery's fixed-stars ref is an unresolved build
> stand-in (`7e0eab43…` = sha256 of a label phrase), missed by the
> forest backfill.

A permanent corpus will accumulate wrong and dangling references —
build bugs, superseded targets, identifiers that should have pointed
elsewhere. The protocol's posture has three parts, and the third is
why no new machinery is needed:

1. **Identify the failure mode.** Byte round-trips are not reference
   resolution: a body can reassemble perfectly while naming a txid that
   does not exist. The phantom passed every byte check because the
   phantom WAS the bytes.
2. **Prevent it before broadcast.** `quipu_preflight.py` — every 64-hex
   token in every final body must be a root of its own diamond, a known
   txid, or explicitly declared; the build refuses, the broadcaster
   refuses. See `docs/guides/broadcasting.md` § Preflight.
3. **Overwrite it after — at the flawed quipu's own address.** A
   subsequent `0xab` binding, nothing more, published FROM THE SAME ROOT
   ADDRESS as the work it corrects. This is the **locus rule**: the
   correction must be retrievable from local context — a reader holding
   the flawed quipu derives its address from its own transactions and
   scans that address's later inscriptions; no global registry, no
   curated binding list, no corpus-wide sweep. (The sourced keydrop is
   the precedent: the fix-object is the locus for retrieving the data.)
   `<<bad>>=<<good>>` aliases redirect; last-write-wins means the next
   binding at the same address supersedes in turn; alias chains follow.
   References are overridable BY DESIGN: a bundle's cross-references do
   not need to be perfect-and-final at inscription. Reader side:
   `colegio_pipeline.corrected_fetcher` implements the rule (a missing
   ref retries through the source's own later corrections); the worked
   case is the orrery's phantom (`working/heal_orrery/`).

This is deliberately NOT a per-textile mechanism (no special outputs,
no errata channels) and NOT a global one (no project registry a reader
must know about): corrections live at the address level — the one
piece of context every quipu carries in its own bytes.

## Why `0xab` is its own type

A bindings quipu could in principle be a `0x00` text quipu whose body
happens to be `NAME txid` lines. Splitting it out as a distinct type
buys two things:

1. **Dispatch clarity.** When a reader resolves an embed, the type
   byte alone tells it whether to render content in place (`0x00`
   text, `0x03` image) or import names into the namespace (`0xab`
   bindings). One header byte, no body inspection needed.
2. **Intent declaration.** The inscriber says "this is a glossary,
   not prose." Future readers indexing the chain can find all
   bindings quipus with one filter.

The cost is one type byte allocated. Worth it for the clarity.

---

## Open questions

1. **Maximum bindings per quipu.** No explicit limit. A bindings
   quipu spanning many OP_RETURNs is fine; the reader concatenates
   the strand and parses line-by-line.

2. **Escape rules in NAME or txid.** None defined. Names containing
   whitespace, `<`, `>`, or unusual control bytes are unsupported
   in v1.

3. **Optional metadata in the body.** The body is currently just
   binding lines plus comments. A future version could add an
   optional title or description in a header field, like essays.
   For v1: no header fields, body is pure data.

4. **Cross-bindings composition.** A bindings quipu could in
   principle import another bindings quipu (recursive aliases).
   v1 explicitly does **not** support this — bindings quipus
   contain only `NAME txid` lines. If imports-of-imports prove
   useful, a future version can add a directive line.

5. **Tone byte semantics.** `0xff` reverence vs `0x00` ordinary
   on a glossary doesn't have an obvious meaning. Inscribers can
   use either; readers shouldn't infer anything from it for v1.
