# Quipu type `0x09` — Book

> **STATUS: CANONICAL v1, implemented in `canonical/book.py`, not yet
> inscribed.** All self-tests pass (roundtrip, accessors, validation,
> cycle/depth-safe recursive walker, worked-example). The Dos ensayos
> book is the planned first inscription. Designed to support
> publication-unit structure (volumes, sub-books, libraries) and to
> serve as the recursive collector for multi-quipu corpora.

A **book quipu** is an ordered list of typed-and-named references to
other quipus. References can point to any type — essays, images,
bindings, sub-books, certs, identity quipus, future types. The book
itself doesn't dictate what its entries contain; it tells a reader
where to look and what role each entry plays.

A book is the quipu analogue of a published volume in the physical
world. It groups its constituent essays, artwork, prólogo, credits,
and bindings into a single addressable unit. Because entries can
point to other books, the same type also serves as a **library** — a
book of books.

---

## Why this type exists

The Colegio Invisible publishes its essays in real-world physical
volumes (Bordado, Mochuelo Libros). Each volume has a prólogo,
~12 numbered essays, cover and internal artwork, credits, and
sometimes a publisher's note. Above the volumes, the series itself
forms a library — 9 volumes (108 essays) plus forward, structure
description, concept-map analysis.

`0x09 book` exists to make this publication structure a first-class
on-chain object. A reader walking the chain hits a book's
`root_txid`, parses its structured body, and gets back the canonical
machine-readable manifest of that publication unit — its title,
ordered contents, and the role each entry plays. No markdown parsing
required, no convention-by-convention reconstruction.

---

## Byte layout

### Header — 6 + (header tail) bytes

```
offset  bytes        meaning
0..3    c1 dd 00 01  magic + protocol version 0.1
4       09           type byte = book
5       <tone>       tone byte — see tone.md for the canonical vocabulary
6..     | header tail |    pipe-delimited title + optional key=value fields
```

The header tail is identical to `0x00 text` — same multi-field
pipe-delimited grammar, same reserved field formats (`encoding`,
`date`, `lang`, `author`). See [`text.md`](./text.md) for the
authoritative header spec. Books inherit it verbatim and add the
following conventional fields (none enforced — all optional):

| field        | example                  | meaning |
|--------------|--------------------------|---------|
| `series`     | `Bordado`                | series name this book belongs to |
| `book`       | `I`                      | book identifier within the series (Roman, Arabic, named) |
| `year`       | `2025`                   | year of publication |
| `publisher`  | `Mochuelo Libros`        | publishing entity |
| `edition`    | `Primera`                | edition designator |
| `isbn`       | `978-987-…-…-…`          | ISBN if assigned |

Example header:

```
c1dd 0001 09 00 |Bordado, Volume I|author=El Ermitaño|date=2025-11-15|lang=es|series=Bordado|book=I|year=2025|publisher=Mochuelo Libros|
```

### Body

```
byte 0          version (uint8)             currently 0x01

bytes 1..2      entry_count (uint16 BE)     0..65535 entries

entries × entry_count:
  bytes 0..31   ref_txid                    32 raw bytes
  byte 32       tag_len (uint8)             0..255
  bytes …       tag (utf-8)                 free-form tag string
  byte          name_len (uint8)            0..255
  bytes …       name (utf-8)                free-form display name
```

Per-entry overhead: 35 bytes + len(tag) + len(name). For a typical
volume with ~16 entries and short tags/names, body ≈ 1-2 KB.

### Validation rules

A canonical-v1 book quipu satisfies:

1. Version byte equals `0x01`.
2. `entry_count` matches the actual number of entries decoded.
3. Each entry's `ref_txid` is exactly 32 raw bytes (no further
   structural validation — the target's type is encoded in its own
   header).
4. Each `tag` and `name` is valid UTF-8 of length ≤ 255 bytes.
5. Tags and names may be empty strings (`len == 0` is legal).

The protocol does **not**:

- Enforce uniqueness of `ref_txid` across entries — a book may list
  the same target multiple times under different tags.
- Enforce uniqueness of `tag` across entries — multiple entries may
  share a tag (e.g., `tag=binding` appearing twice for two imported
  bindings).
- Validate that referenced txids exist on chain or refer to canonical
  quipu types.
- Detect or prevent cycles when a book references itself or a sub-book
  that recursively references back. Cycle handling is a reader concern.

---

## Tags — free-form, with shared conventions

Tags are **free-form UTF-8 strings**. Readers display unknown tags
verbatim and treat them as opaque labels. No tag namespace is
enforced by the protocol.

However, the project maintains a **shared convention table** so
authors and readers speak the same language. Adding new conventions
requires no protocol change — just documentation.

### Conventional tags

| tag                    | cardinality | role |
|------------------------|:-----------:|------|
| `prologo`              | single      | editor's preface |
| `forward`              | single      | opening voice (typical for library-level books) |
| `introduction`         | single      | author's introduction |
| `publisher_note`       | single      | publisher's separate note |
| `author_note`          | single      | author's note |
| `essay/NN`             | ordered     | numbered essay, NN as zero-padded index (`01`..`12`) |
| `chapter/NN`           | ordered     | same as `essay/NN`, different vocabulary |
| `cover`                | single      | front cover image |
| `cover_back`           | single      | back cover image |
| `art/NN`               | ordered     | internal artwork |
| `figure/NN`            | ordered     | figures within the book |
| `binding`              | multiple    | 0xab bindings to import for citation resolution |
| `credits`              | single      | credits / acknowledgments page |
| `afterword`            | single      | closing essay |
| `concept_map`          | single      | concept-map analysis essay |
| `concept_map/img`      | single      | rendered citation-graph image |
| `volume/NN`            | ordered     | sub-volume (book) within a library |
| `subbook`              | multiple    | generic sub-book reference |
| `identity`             | multiple    | identity quipu references (author, editor, illustrator) |
| `cert`                 | multiple    | signature certs attached to the book |
| `errata`               | multiple    | post-publication corrections inscribed later |

**Ordering by tag suffix.** Tags of the form `prefix/NN` are sorted
numerically by `NN` when iterated as a group. Readers iterating
`essay/*` get essays in canonical order without consulting any
external manifest.

**Cardinality is convention, not constraint.** A book may technically
have two `prologo` entries; readers in conventional mode pick the
first or surface a warning, but the bytes are valid.

---

## Recursion — the library is a book

A book entry tagged `volume/NN` (or `subbook`) points to another
`0x09` book. The reader can recursively `read_book_quipu` on that
ref_txid to descend. There is no protocol-level distinction between
"a book" and "a library" — the latter is simply a book whose entries
happen to be books.

Example structure (Bordado as a library of 9 volumes):

```
Bordado Library (0x09 book)
├ tag=binding              → master 0xab binding (cross-volume citations)
├ tag=forward              → forward essay
├ tag=structure            → structure-of-the-corpus essay
├ tag=concept_map          → concept-map analysis essay
├ tag=concept_map/img      → rendered citation-graph image
├ tag=volume/01            → Volume I (another 0x09 book)
│                            ├ tag=binding         → Vol I bindings
│                            ├ tag=prologo         → Vol I prólogo
│                            ├ tag=cover           → Vol I cover art
│                            ├ tag=essay/01        → essay "Arthur Ben"
│                            ├ tag=essay/02        → essay "Anubis"
│                            │   …
│                            ├ tag=essay/12        → essay "Escritura nocturna"
│                            └ tag=credits         → Vol I credits
├ tag=volume/02            → Volume II (0x09 book)
│   …
├ tag=volume/09            → Volume IX (0x09 book)
└ tag=afterword            → optional afterword essay
```

Recursive walking is depth-bounded by the reader. A reasonable
default is **8 levels** (matching the binding alias-chain depth limit).
Cycles are detected by maintaining a visited-set during the walk.

---

## Reader API

```python
from book import read_book_quipu, build_book_quipu

parsed = read_book_quipu(header_bytes, body_bytes)
# parsed = {
#   'title':   str,
#   'tone':    int,
#   'fields':  dict,
#   'version': int,
#   'entries': [
#     {'ref_txid': '94f7…', 'tag': 'cover',    'name': 'Bordado Hayagriva'},
#     {'ref_txid': '84fb…', 'tag': 'prologo',  'name': 'Prólogo by Los editores'},
#     {'ref_txid': 'a4bb…', 'tag': 'essay/01', 'name': 'Arthur Ben'},
#     …
#   ]
# }
```

### Convenience accessors

```python
def book_entries_by_tag(parsed, tag):
    """Entries whose tag equals `tag` exactly."""

def book_entries_by_prefix(parsed, prefix):
    """Entries whose tag starts with `prefix`, sorted by tag suffix when numeric."""

def book_single(parsed, tag):
    """Return the single entry with this tag, or None. Warns if multiple match."""

def book_essays(parsed):
    """Shortcut for entries_by_prefix(parsed, 'essay/'), sorted numerically."""

def book_subbooks(parsed):
    """Shortcut for entries_by_prefix(parsed, 'volume/') + entries_by_tag('subbook')."""

def walk_book_tree(parsed, fetcher, max_depth=8, visited=None):
    """Recursively descend into sub-books, returning a nested structure.
    Cycle-safe via the visited set."""
```

---

## Builder

```python
def build_book_quipu(title, entries, tone=TONE_ORDINARY, fields=None):
    """Build a 0x09 book quipu's (header_bytes, body_bytes) pair.

    Args:
        title:    str, the book title.
        entries:  list of dicts with keys 'ref_txid' (32 raw bytes or
                  64-char hex), 'tag' (str), 'name' (str). Order is
                  preserved verbatim.
        tone:     TONE_ORDINARY (default), TONE_AFFECTION, or TONE_REVERENCE.
        fields:   optional dict[str, str] of header metadata.

    Returns:
        (header_bytes, body_bytes)
    """
```

Validates input and raises `ValueError` on:

- duplicate field keys in `fields`
- `|` or `=` inside the title or any field key/value
- entry count > 65535
- tag/name exceeding 255 UTF-8 bytes
- `ref_txid` not exactly 32 bytes (after hex decode if string given)

---

## Worked example — Bordado Volume I

A complete Volume I book inscription, source bytes annotated:

```
c1dd 0001 09 00 |Bordado, Volume I|author=El Ermitaño|date=2025-11-15|lang=es|series=Bordado|book=I|year=2025|publisher=Mochuelo Libros|
```

Body (decoded):

```
version = 0x01
entry_count = 16

[ 0] ref=<binding_vol1_txid>     tag="binding"        name="Volume I bindings"
[ 1] ref=<prologo_essay_txid>    tag="prologo"        name="Prólogo by Los editores"
[ 2] ref=<cover_image_txid>      tag="cover"          name="Bordado Hayagriva (Maier)"
[ 3] ref=<art_1_txid>            tag="art/01"         name="Teatrito Rioplatense de Entidades (Veroni)"
[ 4] ref=<essay_1_pair_txid>     tag="essay/01"       name="Arthur Ben"
[ 5] ref=<essay_2_pair_txid>     tag="essay/02"       name="Anubis"
[ 6] ref=<essay_3_pair_txid>     tag="essay/03"       name="Hayagriva"
[ 7] ref=<essay_4_pair_txid>     tag="essay/04"       name="El caballo y la rueda"
[ 8] ref=<essay_5_pair_txid>     tag="essay/05"       name="San Cristóbal"
[ 9] ref=<essay_6_pair_txid>     tag="essay/06"       name="Nudos hebraicos"
[10] ref=<essay_7_pair_txid>     tag="essay/07"       name="Sombrero judío"
[11] ref=<essay_8_pair_txid>     tag="essay/08"       name="Hornero"
[12] ref=<essay_9_pair_txid>     tag="essay/09"       name="Goethe en el volcán"
[13] ref=<essay_10_pair_txid>    tag="essay/10"       name="Ganas"
[14] ref=<essay_11_pair_txid>    tag="essay/11"       name="El anillo"
[15] ref=<essay_12_pair_txid>    tag="essay/12"       name="Escritura nocturna"
[16] ref=<credits_text_txid>     tag="credits"        name="Créditos"
```

A reader can now produce a TOC, render the cover, list the essays in
order, and follow each `ref_txid` to fetch the actual content — all
from this single structured manifest.

---

## Tone vocabulary

Inherited from `0x00 text`:

| `<tone>` | when to use |
|---|---|
| `0x00` ordinary  | the default — published volumes, libraries, technical compilations |
| `0x01` affection | personal compilations, gift volumes, dedicated curations |
| `0xff` reverence | memorial volumes, ancestor catalogs, commemorative editions |

The builder rejects other tone values; the reader accepts unknown
tones (passed through) for forward compatibility.

---

## Binding tunneling

A book may carry one or more `tag=binding` entries pointing at `0xab`
binding quipus. These bindings are evaluated once when the book is
opened, accumulated into a single `BindingDict`, and **tunneled into
every essay entry's render**. The essay-as-inscribed is immutable;
the book provides a contextual overlay.

This means the same essay rendered through two different books may
display differently: each book's binding entries define their own
overlay (title rewrites, citation rules, alias chains, footnote
injections). Readers see the essay-in-the-book's-voice.

Concretely, the viewer (or any conforming reader):

1. Parses the book.
2. Walks `tag=binding` entries, fetches each binding's bytes,
   evaluates them with `bindings.evaluate()` into one `BindingDict`.
3. For each `tag=essay/NN` entry, renders the essay by passing the
   merged `BindingDict` as `extra_bd` to `essay.substitute_body()`.
   The essay's own fenced ```binding``` blocks are merged first;
   the book-level bindings take precedence (last-write-wins).

This is the pattern by which a book editor / curator / annotator
inserts their voice into a corpus without ever modifying the
underlying inscriptions.

## Relationship to other types

| type | how a book points to it | role within the book |
|------|-------------------------|----------------------|
| `0x00 text` | entry with any role tag | credits, errata, raw quotations |
| `0x01 essay` | entry tagged `prologo`, `essay/NN`, `forward`, etc. | the main textual content |
| `0x03 image` | entry tagged `cover`, `art/NN`, `figure/NN`, `concept_map/img` | visual material |
| `0xab binding` | entry tagged `binding` | imported by the book's essays for citation resolution |
| `0xcc cert` | entry tagged `cert` | signatures attesting the book's authenticity |
| `0x1d identity` (TBD) | entry tagged `identity` | author / editor / illustrator metadata |
| `0x09 book` | entry tagged `volume/NN` or `subbook` | sub-books — recursion |

A book entry pointing to a non-existent or off-chain target is not
invalid at the protocol level; readers surface such entries as
"unresolved" and continue rendering.

---

## Open questions / future extensions

1. **Versioning** — should a new revision of a book (e.g., to add an
   errata entry) inscribe a fresh book quipu, or extend in place?
   The protocol is append-only on chain, so revisions are new
   inscriptions. Convention: include a `prev` field in the header
   pointing to the previous book revision's `root_txid`. Not yet
   spec'd.

2. **Ordering granularity** — `essay/NN` zero-padded indices give
   numeric sort within a prefix. Should the protocol promote this
   to a structural feature, or leave it as convention?

3. **Signed books** — a book can list a `cert` entry, but the binding
   between the book and its cert is by convention only. A future
   revision might add a header field `signed_by=<cert_txid>` for
   primary attestation.

4. **External pointers** — currently entries point only to on-chain
   txids. A future extension could allow off-chain pointers (DOIs,
   URLs, IPFS CIDs) under a different ref kind.

---

## Cross-references

- [`docs/quipu-types/text.md`](./text.md) — header grammar inherited by books
- [`docs/quipu-types/essay.md`](./essay.md) — the type books most commonly hold
- [`docs/quipu-types/bindings.md`](./bindings.md) — bindings imported by books
- [`docs/quipu-types/image.md`](./image.md) — image type for cover and internal art
- [`docs/design/book-108-cathedral.md`](../design/book-108-cathedral.md) — the inscription pattern using this type
