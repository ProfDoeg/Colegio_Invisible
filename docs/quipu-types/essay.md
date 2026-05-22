# Quipu type `0x01` — Essay

> **STATUS: CANONICAL v1.** Implemented in
> [`canonical/essay.py`](../../canonical/essay.py). No inscriptions of
> this type exist on chain yet; spec is ready for first inscription.

An *essay* is a CommonMark markdown document with quipu-protocol
extensions. The substitution engine processes the body to resolve
`<<txid>>` citations, fenced `binding` blocks, alias rules, and
string substitutions, emitting plain markdown that any off-the-shelf
renderer can convert to HTML.

The essay type completes a deliberate split with `0x00 text`:

| | type | body interpretation |
|---|---|---|
| `0x00` | text | literal — substitution engine never modifies it |
| `0x01` | essay | interpreted — citations and binding rules are resolved before rendering |

Inscribe under `0x00` when the *exact bytes* matter (quotations, raw
data, historical text); use `0x01` when you want a richer publishing
surface with cross-references to other quipus.

---

## Byte layout

### Header — 6 + (header tail) bytes

```
offset  bytes        meaning
0..3    c1 dd 00 01  magic + protocol version 0.1
4       01           type byte = essay
5       <tone>       00 ordinary, 01 affection, 0d demonic, ff reverence
6..     | header tail |    pipe-delimited title + optional key=value fields
```

The header tail is identical to `0x00 text` — same multi-field
pipe-delimited grammar, same reserved field formats (`encoding`,
`date`, `lang`, `author`). See [`text.md`](./text.md) for the
authoritative header spec. Essays inherit it verbatim.

### Body — CommonMark markdown with protocol extensions

```
| extension                            | what it does                                          |
|--------------------------------------|-------------------------------------------------------|
| `<<txid>>`                            | resolves to `[Target Title](quipu:<txid>)`            |
| `<<Alias>>`                           | resolves through the binding dict, then as above       |
| `<<txid title="Custom">>`             | link with custom anchor text                          |
| `<<txid>><<SubObj>>`                  | sub-object link: `[SubObj](quipu:<txid>#<SubObj>)`    |
| `[anchor](<<txid>>)`                  | standard markdown link form (URL substituted)         |
| `![alt](<<txid>>)`                    | standard markdown image form (URL substituted)         |
| ` ```binding ... ``` `                | fenced block of binding rules (extracted + evaluated) |
```

Everything else is normal CommonMark — headings, emphasis, lists,
tables, blockquotes, code blocks, footnotes, raw HTML.

---

## Citation forms

### Bare citation

```markdown
The certificate at <<DomCert>> was issued in 2023.
```

resolves to:

```markdown
The certificate at [Domrémy Bordado Certificate](quipu:6da7a9a9…) was issued in 2023.
```

Anchor text = the resolved inscription's `title` field. URL =
`quipu:<txid>` (a custom URI scheme; renderers can rewrite to their
own viewer URL).

### Citation with custom anchor (two equivalent forms)

```markdown
…signed by [Hayagriva Christophia](<<MaierDecl>>)
…signed by <<MaierDecl title="Hayagriva Christophia">>
```

Both resolve to:

```markdown
…signed by [Hayagriva Christophia](quipu:1ec0ee9b…)
```

The standard markdown form is more familiar; the citation-attribute
form is more compact. Both produce identical post-substitution markdown.

### Inline images

```markdown
![the bordado at La Verna](<<2b01e2094c52bf99…>>)
```

The URL is substituted (`quipu:2b01e2094c52bf99…`). The downstream
renderer or viewer handles fetching the actual image and rendering it
inline. Standard markdown image syntax — readers without quipu-protocol
awareness still get a clickable image link.

### Sub-object references

For two-segment references into structured quipus (named groups in
celestial, named drops in keydrops, named fields in certs):

```markdown
The brightest star is <<Jawza>><<Sirius>>.
The cert at <<DomCert>><<CertificateAuthority>> grants this work.
```

resolve to:

```markdown
The brightest star is [Sirius](quipu:2ae7fe90…#Sirius).
The cert at [CertificateAuthority](quipu:6da7a9a9…#CertificateAuthority) grants this work.
```

A `title="..."` attribute on either segment overrides the anchor text.

---

## Fenced `binding` blocks

The substitution engine's machinery — imports, alias rules, and string
substitutions — lives inside fenced code blocks tagged `binding`:

```markdown
# Essay title

```binding
<<my_common_names>>                                     # import an 0xab binding
<<DomCert>>=<<6da7a9a9d8d651c4…>>                       # alias
<<MaierDecl>>=<<MaierThreeKey>>=<<1ec0ee9b27d6ab91…>>   # alias chain
"Sirichinova"="Sinchova"                                 # spelling correction
```

Now I can refer to <<DomCert>> by its short name throughout the essay…
```

After substitution the entire block is **removed from the output**.
The line vocabulary inside is identical to a `0xab` binding's body
(see [`bindings.md`](./bindings.md)).

Multiple binding blocks per essay are allowed. They evaluate in
document order. Last-write-wins: a later block can override earlier
definitions. Local definitions go in their own block wherever
convenient.

### Why a fenced block?

- Standard markdown syntax — graceful degradation in tools without
  quipu-protocol awareness (the block renders as a code block).
- Editors get syntax highlighting via the `binding` language tag.
- The substitution engine knows exactly where binding rules start and
  end; citations inside a block are **definitions**, not references
  to resolve.

---

## Substitution pipeline

```
raw essay body (markdown + citations + binding blocks)
    ↓ extract fenced binding blocks
cleaned markdown (binding blocks removed)
   +
list of binding-block bodies
    ↓ evaluate binding blocks (using bindings.py's evaluator)
final BindingDict (aliases + substitutions)
    ↓ resolve citations in cleaned markdown using BindingDict
markdown with all <<>> resolved to standard links
    ↓ apply string substitutions to result
plain markdown (no protocol-specific syntax)
    ↓ pass to CommonMark renderer
HTML
```

The first three steps are protocol-defined and live in
`canonical/essay.py`. Everything downstream is off-the-shelf markdown
tooling.

---

## Tone vocabulary

Inherited from `0x00 text`:

| `<tone>` | when to use |
|---|---|
| `0x00` ordinary | the default — descriptive, academic, neutral prose about the living |
| `0x01` affection | paired / intimate / addressed to a specific other |
| `0xff` reverence | the dead, ancestors, formal commemoration |

The builder rejects other tone values; the reader accepts unknown
tones (passed through) for forward compatibility.

---

## Reserved field formats

Inherited from `0x00 text`. If any of these is present in the header,
it must follow the canonical form:

| field      | format                                                | Python interop |
|------------|-------------------------------------------------------|---------------|
| `encoding` | IANA codec name                                       | `bytes.decode(encoding=...)` |
| `date`     | ISO 8601 / RFC 3339                                   | `datetime.fromisoformat(...)` |
| `lang`     | BCP 47 tag                                            | `langcodes.Language.get(...)` |
| `author`   | free UTF-8 string                                     | — |

See [`text.md`](./text.md) for the authoritative spec.

---

## Worked example

A complete essay inscription, source bytes annotated:

```
c1dd 0001 01 00 |La Verna|author=Christophia Hayagriva|date=2026-05-21|lang=en|
```

Body (markdown):

````markdown
# La Verna

```binding
<<commonNames_2026_05_txid>>
"Domremy"="Domrémy"
```

The certificate at <<DomCert>> was issued under <<MaierDecl>>, which
itself rests on the three-key declaration inscribed by Hayagriva,
Christophia, and Anthony in 2023.

The bordado image:

![the bordado at La Verna](<<2b01e2094c52bf99fb1e0d855af18eabafa0b8a3b331276a87dbefe98a932d6a>>)

> Joffrey Bourlémont, French nobleman turned Crusader, set for Jerusalem...
> — from <<DomCert>>

The brightest star in <<Jawza>>, [Sirius](<<Jawza>><<Sirius>>), is also
referenced in the older Sky of al-Jawza inscription.
````

After substitution (assuming `commonNames_2026_05` defines `DomCert`,
`MaierDecl`, `Jawza` aliases):

```markdown
# La Verna

The certificate at [Domrémy Bordado Certificate](quipu:6da7a9a9…) was
issued under [Maier 3-Key Declaration](quipu:1ec0ee9b…), which itself
rests on the three-key declaration inscribed by Hayagriva, Christophia,
and Anthony in 2023.

The bordado image:

![the bordado at La Verna](quipu:2b01e2094c52bf99…)

> Joffrey Bourlémont, French nobleman turned Crusader, set for Jerusalem...
> — from [Domrémy Bordado Certificate](quipu:6da7a9a9…)

The brightest star in [The Sky of al-Jawza](quipu:2ae7fe909e19c0e4…),
[Sirius](quipu:2ae7fe909e19c0e4…#Sirius), is also referenced in the
older Sky of al-Jawza inscription.
```

A standard markdown renderer converts this to HTML directly.

---

## Reader API

```python
from essay import read_essay_quipu, substitute_body

parsed = read_essay_quipu(header_bytes, body_bytes)
# parsed: {'title', 'tone', 'fields', 'body'} — body is raw markdown

# To resolve citations into plain markdown:
plain_md = substitute_body(
    parsed['body'],
    fetcher=my_fetcher,          # callable(txid) -> bytes, for imports
    title_lookup=my_title_lookup, # callable(txid) -> str, for anchor text
)

# Then pass plain_md to your markdown renderer.
```

For an in-memory fetcher use case (e.g., during a single essay-compile
pass), pass `fetcher=fetch_quipu_bytes` from `colegio_tools.py`. For
`title_lookup`, a closure over `data/quipu_data.csv` works:

```python
import pandas as pd
df = pd.read_csv('data/quipu_data.csv')
title_map = dict(zip(df['root_txid'], df['title'].fillna('')))
title_lookup = lambda t: title_map.get(t, '')
```

---

## Why a custom URI scheme (`quipu:<txid>`)?

Most viewers will rewrite `quipu:<txid>` to their own viewer URL
(e.g., a Streamlit page, a static HTML viewer, a web service). The
canonical scheme stays protocol-agnostic — a single regex picks up
every quipu reference regardless of which viewer is serving it. The
on-chain inscription itself doesn't bake in any one viewer's URL.

---

## Open questions / future extensions

1. **`mode="embed"` attribute** — to inline the target's body content
   instead of linking. Not in v1; needs more design around how to
   render a text quipu's body inside another essay's flow.
2. **Inline language switching beyond `<span lang="...">`** — would
   require a custom typographic extension. Probably not worth it;
   markdown's HTML escape hatch is enough.
3. **Footnotes with quipu citations** — markdown's footnote extension
   already works; citations inside footnotes resolve normally.
4. **Math and code** — markdown handles. Use MathJax/KaTeX-flavored
   markdown or fenced code blocks with language tags. No protocol
   layer needed.
