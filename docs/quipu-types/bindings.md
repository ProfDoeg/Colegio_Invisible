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
TT            tone (00 ordinary, ff reverence)
[body bytes]  one binding per line, see below
```

No header fields, no length prefixes, no counters. The body's
structure is per-line.

## Body format

One binding per line. Each line:

```
NAME txid
```

A single space (or `=`) separates the name from the txid. Newline
ends the line.

- **NAME** is UTF-8 with no whitespace and no `<` or `>` characters.
  Case-sensitive. Same naming rules as inline bindings in essay
  markup.
- **txid** is a Dogecoin transaction ID — full 64-character hex, or
  a shorter unique prefix (resolved at lookup time).

Empty lines are ignored. A line not matching the `NAME txid` shape is
treated as a comment (parser ignores it).

## Example

```
DomCert 6da7a9a9d8d651c48e0a979ea6d1f00ce03cd1388ea390c5fa2050f9b2fb4910
MaierDecl 1ec0ee9b27d6ab91169b28f3acdada51cab8eb03af8c2a7e128d122a2dba7d0c
DomImage b92bbbf974ad7d1ba035d03b34ee455dadf4e85c365d841beb4443e55da0b66c
LaVernaRoot a90fb985f7c12eb4abb2cb4d9e77e1636902df1fb203e7f13e0a367e20e9d019
ApocryphaAddr D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX

Hayagriva <hayagriva_identity_txid>
Christophia <christophia_identity_txid>
Anthony <anthony_identity_txid>
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
**first-import-wins**: the first import is authoritative; later
imports add only what wasn't already bound. This is stable and
predictable. To override, omit the name from earlier imports.

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
