# Citation syntax

> **STATUS: CANONICAL.** The `<<...>>` citation convention is used
> across multiple quipu types (text, essay, cert, binding) and resolved
> by the substitution engine in `canonical/essay.py` and the binding
> evaluator in `canonical/bindings.py`.

The Colegio Invisible protocol uses a single citation form throughout
its types — `<<...>>`. This document is the cross-cutting reference for
all the shapes it takes and how they resolve.

---

## Forms at a glance

| form                                       | resolves to                                            |
|--------------------------------------------|--------------------------------------------------------|
| `<<txid>>`                                  | link to inscription, anchor = target's title           |
| `<<Alias>>`                                 | resolved through binding dict → above                  |
| `<<txid title="X">>`                        | link with custom anchor `X`                            |
| `<<txid>><<SubObj>>`                        | sub-object link: `[SubObj](quipu:<txid>#<SubObj>)`     |
| `<<txid>><<SubObj title="Y">>`              | sub-object with custom anchor                          |
| `[anchor](<<txid>>)`                        | standard markdown link with citation as URL            |
| `![alt](<<txid>>)`                          | standard markdown image with citation as URL           |
| `<<Alias>>=<<txid>>` (binding-block only)   | alias assignment                                       |
| `<<A>>=<<B>>=<<txid>>` (binding-block only) | alias chain                                            |
| `<<binding_txid>>` (binding-block only)     | import another 0xab binding                            |
| `"X"="Y"` (binding-block only)              | string substitution (not technically a citation form)  |

---

## Where each form is allowed

| form                          | text 0x00 | essay 0x01 prose | binding-block in essay | binding 0xab body |
|-------------------------------|:---------:|:-----------------:|:----------------------:|:------------------:|
| Bare `<<txid>>` reference     | as text   | resolved          | as definition          | as definition      |
| `<<Alias>>` reference         | as text   | resolved          | as definition / target | as definition / target |
| `<<txid title="...">>`        | as text   | resolved          | (rare)                 | (rare)             |
| `<<txid>><<SubObj>>`          | as text   | resolved          | resolved               | resolved           |
| `<<A>>=<<B>>=<<target>>`      | as text   | n/a in prose      | rule                   | rule               |
| `"X"="Y"`                     | as text   | n/a in prose      | rule                   | rule               |

**Key rule:** the substitution engine processes `<<...>>` ONLY in
contexts where the type's spec declares it does. For `0x00 text`, the
body is literal — `<<txid>>` is rendered exactly as written. For
`0x01 essay`, citations in prose ARE resolved. Inside a `binding`
fenced block (whether in an essay or in a 0xab body), citations are
**definitions**, not references — the engine adds them to the dict
instead of resolving them.

---

## Inner grammar

A citation's body is parsed as:

```
citation        := "<<" ws* name ws* (attr ws*)* ">>"
name            := bareword (alphanumeric + _ - . characters)
attr            := key "=" quoted-value
quoted-value    := '"' chars-except-quote-and-greater '"'
```

Where:
- `name` is either a 64-hex-character txid or an alias name.
- `attr` is zero or more `key="value"` pairs.
- The grammar disallows `>>` inside attribute values (would close the
  citation prematurely).

### Attributes reserved by the protocol

| key       | meaning |
|-----------|---------|
| `title`   | override the default anchor text |

Other keys pass through opaquely. Renderers may interpret unknown keys
or ignore them. Conventions will accumulate over time.

---

## Two-segment form

```
<<X>><<Y>>
```

Where `X` resolves to a txid and `Y` is a sub-object label *within* that
inscription. Detection rule:

- The two segments must be adjacent (only whitespace between).
- The second segment must NOT look like a 64-hex txid (those are
  always primary citations, never sub-object labels).
- The second segment becomes the anchor text (unless overridden by a
  `title=` attribute on either segment).

Examples:

```
<<Jawza>><<Sirius>>                              → sub-object "Sirius" in Jawza
<<DomCert>><<CertificateAuthority>>              → sub-object in cert
<<keydrop_txid>><<AES message>>                  → drop entry in keydrop
```

The output URL form is `quipu:<txid>#<SubObj>`. Viewers interpret the
fragment as the sub-object identifier.

---

## Resolution pipeline

For a citation appearing in prose (essay or other interpreted context):

```
parse <<...>> → (name, attrs, optional sub-object segment)
    ↓
resolve `name` through binding dict (alias chain) → terminal txid
    ↓
determine anchor text:
    1. attr title=  → use it
    2. sub-object segment → use that name
    3. lookup target's title via title_lookup callback
    4. fall back to the original `name`
    ↓
determine URL:
    if has sub-object → quipu:<txid>#<SubObj>
    else              → quipu:<txid>
    ↓
emit [anchor](url)
```

Cycle detection in the alias chain: maintained per resolution, max
8 hops, ValueError raised on cycle or depth exceeded.

---

## Examples by quipu type

### 0x00 text — no resolution

```
mi perrito que viene de la calle, <<DomCert>> no significa nada aquí
```

The substitution engine does NOT process 0x00 bodies. `<<DomCert>>` is
rendered as the literal four characters `<<DomCert>>`. Use 0x01 essay
for prose that should resolve citations.

### 0x01 essay — full resolution

```markdown
# Some Essay

```binding
<<DomCert>>=<<6da7a9a9d8d651c4...>>
```

The cert at <<DomCert>> was signed by 3-of-3.
```

After substitution:

```markdown
# Some Essay

The cert at [Domrémy Bordado Certificate](quipu:6da7a9a9d8d651c4...) was signed by 3-of-3.
```

### 0xab binding — definitions

```
<<DomCert>>=<<6da7a9a9d8d651c4...>>
<<MaierDecl>>=<<1ec0ee9b27d6ab91...>>
"Domremy"="Domrémy"
```

No prose to resolve. Every `<<...>>` is part of a definition.

### Cert and celestial sub-object references

`<<txid>><<SubObj>>` works on any structured type with named sub-objects:

| host type       | example sub-object |
|------------------|----|
| celestial (`0xce`) | `<<Jawza>><<Sirius>>` — a star name |
| celestial grouped | `<<some_constellation>><<Orion>>` — a named group |
| keydrop (`0x0e 0x0d`) | `<<keydrop_txid>><<AES message>>` — a drop entry |
| cert (`0xcc`)   | `<<DomCert>><<CertificateAuthority>>` — a field |

The host type's reader is responsible for resolving the second-segment
name to actual data.

---

## URL form

The default URL form is **`quipu:<txid>`** — a custom URI scheme.

This is the on-chain canonical URL. Viewers can rewrite it to their
own endpoint (e.g., `https://viewer.example/<txid>` or a streamlit
route). The inscription itself doesn't bake in any viewer's address —
a single regex picks up every quipu reference and the viewer maps it
to its own URL space.

For sub-objects: `quipu:<txid>#<SubObj>`. The fragment after `#` is the
sub-object identifier; viewers interpret it.

---

## Escaping

Within prose where `<<...>>` should appear *literally* and not be
parsed as a citation, escape the opening sequence:

```
\<\<txid>>      — literal "<<txid>>" in output
```

This is markdown-style backslash escaping, which the markdown renderer
handles. Inside a `binding` fenced block, escaping isn't needed —
content is line-parsed and only valid binding-rule lines are processed
(everything else is treated as comment).

---

## Related specs

- [`bindings.md`](../quipu-types/bindings.md) — the 0xab binding type, source of the citation/alias/substitution vocabulary
- [`essay.md`](../quipu-types/essay.md) — the 0x01 essay type, primary consumer of citation resolution
- [`text.md`](../quipu-types/text.md) — the 0x00 text type, where citations remain literal
