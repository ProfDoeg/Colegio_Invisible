# Writing an Essay

A practical guide for inscribing a `0x01 essay` quipu. Aimed at:

- Future authors of essays for the project.
- Any future Claude session helping format prose for inscription.

If you only read one section, read **The shape of an essay** below. The
rest is reference detail.

---

## TL;DR

A quipu essay is **CommonMark markdown** plus two things:

1. `<<txid>>` to reference other inscriptions (renders as a link).
2. `` ```binding ``` `` fenced code blocks where the substitution engine
   reads import / alias / substitution rules.

Everything else is just markdown.

---

## The shape of an essay

```
header                          c1dd 0001 01 <tone> |Title|author=…|date=…|lang=…|

body                            CommonMark markdown:
                                  - prose
                                  - headings, lists, emphasis, tables, blockquotes
                                  - <<txid>> citations (resolve to links)
                                  - inline images: ![alt](<<txid>>)
                                  - ```binding fenced blocks (engine machinery)
```

After the substitution engine processes the body, the result is plain
markdown. Pass that to any CommonMark renderer for HTML.

---

## How to write one

### Step 1 — choose the header

```
|Title|author=...|date=...|lang=...|encoding=...|
```

| field | required | example | format |
|---|---|---|---|
| `Title` | no | `La Verna` | first pipe-field, no `=` |
| `author` | no | `Christophia Hayagriva` | free UTF-8 string |
| `date` | no | `2026-05-21` | ISO 8601: `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SSZ` |
| `lang` | no | `en`, `es`, `la` | BCP 47 |
| `encoding` | no | `utf-8` (default) | IANA codec name |

Skip any field you don't have. Put unreserved metadata in any other key:

```
|Title|series=Bordado Cycle|book=I|chapter=2|
```

Unrecognized keys are pass-through. Conventions accumulate over time.

### Step 2 — declare your bindings

If your essay refers to other inscriptions by short name, put the
binding rules in a fenced `binding` code block. Convention: one block
at the top of the essay covering most names; additional blocks where
local-only aliases make sense.

````markdown
```binding
<<commonNames>>                                    # import the project glossary

<<DomCert>>=<<6da7a9a9d8d651c4...>>                # local alias
<<MaierDecl>>=<<1ec0ee9b27d6ab91...>>

"Domremy"="Domrémy"                                 # spelling correction
"Sirichinova"="Sinchova"                            # name normalization
```
````

Or skip the block entirely if you only use raw txids in your prose
(no aliases, no substitutions).

### Step 3 — write your prose

```markdown
# La Verna

The certificate at <<DomCert>> was issued under the authority of
<<MaierDecl>>...

![the bordado](<<2b01e2094c52bf99fb1e0d855af18eabafa0b8a3b331276a87dbefe98a932d6a>>)
```

Use citation forms freely:

| what you want | how to write it |
|---|---|
| Link to a quipu with its title as the anchor | `<<txid>>` or `<<Alias>>` |
| Custom anchor text | `[my anchor](<<txid>>)` or `<<txid title="my anchor">>` |
| Inline an image quipu | `![alt text](<<image_txid>>)` |
| Link to a sub-object | `<<celestial_txid>><<Sirius>>` |
| Sub-object with custom anchor | `<<celestial_txid>><<Sirius title="The Dog Star">>` |

### Step 4 — use the rest of markdown for everything else

Standard CommonMark works:

```markdown
# Heading 1
## Heading 2

**bold**, *italic*, `code`, ~~strike~~

> blockquote, which can contain citations to <<DomCert>> too.

- bullet list
- item
- item

1. numbered list
2. item

| column | column |
|--------|--------|
| cell   | cell   |

```code block```

[regular link](https://example.com)

---

a horizontal rule above
```

Multi-language passage? Use a raw HTML span (markdown's escape hatch):

```markdown
The author wrote about <span lang="la">*Atalanta Fugiens*</span> at length.
```

### Step 5 — inscribe

Once the markdown body is ready:

```python
from canonical.essay import build_essay_quipu, TONE_ORDINARY

header, body = build_essay_quipu(
    title="La Verna",
    body_markdown=open("la_verna.md").read(),
    tone=TONE_ORDINARY,
    fields={
        "author":   "Christophia Hayagriva",
        "date":     "2026-05-21",
        "lang":     "en",
        "encoding": "utf-8",
    },
)
# Then inscribe header+body via the orchestrator / Cadena pipeline.
```

The builder validates field formats (ISO 8601 date, BCP 47 lang, IANA
encoding). Failures raise loudly so you catch them before broadcast.

### Step 6 — verify before broadcast

Test the substitution pipeline locally before paying to inscribe:

```python
from canonical.essay import substitute_body
import pandas as pd

df = pd.read_csv('data/quipu_data.csv')
title_map = dict(zip(df['root_txid'], df['title'].fillna('')))

rendered_md = substitute_body(
    body_markdown,
    title_lookup=lambda t: title_map.get(t, ''),
)
print(rendered_md)
```

Read the output. Make sure:
- All citations resolved (no `quipu:unresolved:` URLs in the output)
- All `binding` blocks were consumed
- Substitutions applied correctly

Then run it through your preferred CommonMark renderer to preview the
HTML.

---

## Common patterns

### Citing the same inscription many times

Define a short alias once in a binding block, then use the alias
throughout:

````markdown
```binding
<<Dom>>=<<6da7a9a9d8d651c4...>>
```

The cert <<Dom>> was issued in 2023. <<Dom>> rests on Maier's authority.
The artwork referenced in <<Dom>> is the Domremy bordado.
````

### Importing a project-wide glossary

Maintain a 0xab binding inscribed once, then import it from every
essay:

````markdown
```binding
<<glossary_v1_txid>>
```
````

Every name in the glossary becomes available. If you need to override
one for THIS essay, just reassign after the import:

````markdown
```binding
<<glossary_v1_txid>>
<<DomCert>>=<<some_other_txid>>   # local override
```
````

### Footnotes

Some markdown flavors support `[^1]` footnotes. Citations inside
footnotes work normally:

```markdown
The Joffrey Bourlémont story[^1] is referenced in <<DomCert>>.

[^1]: See <<wikipedia_link>> for the historical record.
```

### Quote a quipu's body inline

For now (v1), the simplest path is to paste the quoted text into a
markdown blockquote with attribution:

```markdown
> Joffrey Bourlémont, French nobleman turned Crusader...
> — from <<DomCert>>
```

A future `mode="embed"` attribute may automate this. Not yet in v1.

---

## What NOT to do

- **Don't put citations in a `0x00 text` body** if you want them
  resolved. Type 0x00 is literal — `<<txid>>` will appear unchanged
  in the output. Inscribe as `0x01 essay` for processed citations.

- **Don't use `binding` blocks for prose markup.** A `binding` block
  is for engine rules only. If you want a quoted source attribution,
  use a markdown blockquote.

- **Don't put `|` inside a header field value.** It's the field
  separator. Use a Unicode lookalike (`｜`) if you absolutely need a
  pipe in a title or value.

- **Don't put `>>` inside a citation attribute value.** It would close
  the citation prematurely. Use a Unicode lookalike if needed.

- **Don't expect the substitution engine to walk arbitrary chains.**
  Alias chains depth-limited at 8 hops. Import nesting capped at 64.
  Cycles are detected and terminate the walk silently.

---

## Reading an inscribed essay

If you encounter an inscribed essay and want to render it:

```python
from canonical.essay import read_essay_quipu, substitute_body
from colegio_tools import fetch_quipu_bytes
import pandas as pd

blob = fetch_quipu_bytes(essay_txid)            # raw bytes from chain
# header is 6 + (header tail) bytes; the tail terminates at the last
# closing pipe before non-pipe data
# (for essays, just call read_essay_quipu with whatever header/body
#  split your walker produces — it handles the multi-field tail)

# (For simplicity, treat the whole blob as header for parsing the
#  multi-field shape, and let read_essay_quipu split internally —
#  TBD: provide a small split helper in canonical/essay.py)

parsed = read_essay_quipu(header_bytes, body_bytes)
df = pd.read_csv('data/quipu_data.csv')
title_map = dict(zip(df['root_txid'], df['title'].fillna('')))

rendered_md = substitute_body(
    parsed['body'],
    fetcher=fetch_quipu_bytes,
    title_lookup=lambda t: title_map.get(t, ''),
)

import markdown
html = markdown.markdown(rendered_md, extensions=['extra', 'tables'])
print(html)
```

---

## Glossary of forms (quick reference)

```markdown
<<txid>>                               link, anchor = target's title
<<Alias>>                              alias → resolved → as above
<<txid title="My Anchor">>             link with custom anchor text
[My Anchor](<<txid>>)                  standard markdown form, same result
<<txid>><<SubObj>>                     sub-object link
![alt](<<image_txid>>)                 inline image (any image quipu)
[regular link](https://example.com)    normal markdown link, unchanged

```binding                              fenced binding-rule block
<<txid>>                                  - import another binding
<<A>>=<<B>>=<<txid>>                      - alias chain
"old"="new"                               - string substitution
```                                     end binding block
```

That's the full surface. Master these and you can publish anything
the protocol allows.

---

## Cross-references

- [`docs/quipu-types/essay.md`](../quipu-types/essay.md) — the formal essay spec
- [`docs/quipu-types/text.md`](../quipu-types/text.md) — the literal-text type 0x00
- [`docs/quipu-types/bindings.md`](../quipu-types/bindings.md) — the 0xab binding type
- [`docs/quipu-syntax/citations.md`](../quipu-syntax/citations.md) — the full citation grammar across types
- [`canonical/essay.py`](../../canonical/essay.py) — reference reader + transform implementation
