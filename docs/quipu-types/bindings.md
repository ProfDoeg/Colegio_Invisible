# Quipu type `0xab` — Bindings (abecedario)

> **STATUS: DRAFT, version 1.** Not yet implemented in `colegio_tools`.
> No inscriptions of this type exist on chain. Designed to support the
> essay markup's name-binding convention by providing stable,
> project-wide aliases that any number of essays can import.

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

Empty lines are ignored. Any line that does not match one of the three
forms above is treated as a comment.

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
