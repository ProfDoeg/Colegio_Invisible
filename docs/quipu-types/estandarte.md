# Quipu type `0xee` — Estandarte (protocol registry)

> **STATUS: CANONICAL v1, not yet inscribed.** Implemented in
> [`canonical/estandarte.py`](../../canonical/estandarte.py). The
> constitutional quipu — documents the Quipu Protocol's own type-byte
> vocabulary. Self-referential: type `0xee` documents `0xee` among the
> other types. Designed to be inscribed last, under La Verna's root,
> after every type it catalogs is stable.

An *Estandarte* ("banner / standard") is a single inscription that
catalogs every protocol type byte in use, along with each type's
named enum dimensions, single-bit flags, and a status (canonical /
proposed / draft / deprecated). It also catalogs cross-cutting
conventions. The founding set carries nine: the magic prefix, the tone
vocabulary, the diamond shape, the **assembly** rule (how strand
payloads concatenate back into one inscription), the **tag** primitive
(auxiliary root outputs whose spend carries no OP_RETURN), the
**ripcord** (the amendment cord: succession unique by double-spend),
citation by root txid, the consolidated-diamond forest, and the
pre-canonical errata clause covering inscriptions that predate the
registry.

Once inscribed, an Estandarte makes the protocol *referenceable on
chain*. Future quipus can cite it as the standard they conform to.
Amendments form a verifiable chain via a `parent_txid` field; a
reader walking from any leaf to its root accumulates the registry
with leaf-wins override semantics.

---

## Byte layout

### Header — 6 bytes flat

```
offset  bytes        meaning
0..3    c1 dd 00 01  magic + protocol version 0.1
4       ee           type byte = Estandarte
5       <tone>       tone byte — see tone.md for the canonical vocabulary
```

No title field — the Estandarte's identity is the registry itself,
not a label. Tone is restricted to `0x00` and `0xff` (no affection
tone — disclosure of the protocol is not an intimate act).

### Body

```
<parent_kind:1>                  00 = root, 01 = amendment
[if parent_kind == 01]:
    <parent_txid:32>             raw 32-byte root txid of parent Estandarte
<T:1>                            count of type entries
for each type entry:
    <type_byte:1>                the type byte being documented
    <name_len:1>  <name>         canonical name (UTF-8, ≤ 255 B)
    <desc_len:1>  <desc>         one-line description (UTF-8, ≤ 255 B)
    <status:1>                   0 canonical / 1 proposed / 2 draft / 3 deprecated
    <dim_count:1>                count of named enum dimensions
    for each dimension:
        <dim_name_len:1>  <dim_name>     e.g. "color", "bit_depth"
        <dim_desc_len:1>  <dim_desc>     what this byte means in the type's header
        <value_count:1>                  named values in this dimension
        for each value:
            <value:1>                    the byte value
            <val_name_len:1>  <val_name> e.g. "grayscale", "rgb"
            <val_desc_len:1>  <val_desc> one-liner
    <flag_count:1>                       count of independent single-bit flags
    for each flag:
        <bit:1>                          bit position 0–7
        <name_len:1>  <name>
        <desc_len:1>  <desc>
<C:1>                                    count of conventions
for each convention:
    <name_len:1>    <name>               e.g. "diamond", "citation"
    <syntax_len:1>  <syntax>             formal pattern / shape
    <desc_len:1>    <desc>               what it means / when it applies
```

All length-prefixed fields are 1-byte unsigned (max 255 bytes UTF-8).

---

## Dimensions vs. flags

A **dimension** is a single byte in the type's header whose value is
drawn from a mutually-exclusive named enumeration. A type may have
zero, one, or many dimensions:

| type | status | dimensions |
|---|---|---|
| `0x00` text | canonical | (none — only header fields are magic/type/tone/title) |
| `0x01` essay | canonical | (none) |
| `0x03` image | canonical | `color` (`grayscale`/`rgb`/`gray_alpha`/`rgba`), `bit_depth` |
| `0x07` sound | canonical | `codec` (`stft`/`lpc`/`codec2`/`opus`/`mp3`/`wav`/`flac`/`music`) |
| `0x09` book | canonical | (none) |
| `0x0c` cert-precursor | deprecated | (none — superseded by `0xcc`; one inscription, kept readable) |
| `0x0e` encrypted | canonical | `sub_family` (`aes`/`ecies`/`drop`/`centinela`/`cb-sale`/`shamir`), `variant` |
| `0x0f` file | canonical | (none — generic binary container; sha256 flag-gated) |
| `0x1d` identity | draft | (none — JSON body; one pre-canonical inscription) |
| `0x3d` scene | canonical | (none) |
| `0x5c` latex | canonical | (none) |
| `0xab` binding | canonical | (none) |
| `0xcc` cert | canonical | `subtype` (2 bytes big-endian: `hash`/`all-in-one`/`sale-offer`) |
| `0xce` celestial | canonical | `kind`, `grouped`, `meta` (`no`/`time`/`more`) |
| `0xda` dancer | canonical | `variant` (`performance`/`footage`/`graph`/`controller`) |
| `0xee` estandarte | canonical | (none) |

A **flag** is a single bit within a byte that's set independently of
other bits in the same byte. The Quipu Protocol uses dimensions
preferentially — flags exist for cases where multiple boolean
settings legitimately share a byte. No canonical type currently uses
the flag field; it's reserved for future use.

A type entry can declare both dimensions and flags. They are
documented separately so a reader can distinguish "this byte is an
enum value" from "this byte is a bitmask."

---

## Tone vocabulary

| `<tone>` | when to use |
|---|---|
| `0x00` ordinary | the standard registry; the working protocol declaration |
| `0xff` reverence | the canonical La Verna inscription; a posthumous or commemorative protocol freeze |

Affection (`0x01`) is not a valid Estandarte tone. The act of
declaring the protocol is constitutional, not intimate.

---

## Amendment chain

An Estandarte either is the *root* (no parent — `parent_kind = 00`)
or an *amendment* (`parent_kind = 01` followed by a 32-byte parent
txid). The parent txid is the **root transaction txid** of the
parent Estandarte (the inscription's canonical identifier).

`resolve_estandarte_chain(leaf_txid, fetcher)` walks the chain from
any leaf back to the root, accumulating entries. Override semantics:

- Types are keyed by `byte`. A type entry in a later amendment fully
  replaces the earlier entry for that byte.
- Conventions are keyed by `name`. Same override rule.
- Status `3 deprecated` retires an entry — the entry remains visible
  in the merged registry but its status flags it as no longer in use.

The resolver detects cycles and caps chain depth (default 64) to
protect against malformed input.

---

## Reading an Estandarte

```python
from estandarte import read_estandarte_quipu, format_estandarte
from colegio_tools import fetch_quipu_bytes

blob = fetch_quipu_bytes(estandarte_root_txid)
header, body = blob[:6], blob[6:]
parsed = read_estandarte_quipu(header, body)
print(format_estandarte(parsed))
```

For a chain of amendments:

```python
from estandarte import resolve_estandarte_chain

result = resolve_estandarte_chain(leaf_txid, fetch_quipu_bytes)
print(f"chain length: {result['chain_length']}")
print(f"root: {result['root_txid'][:12]}…  leaf: {result['leaf_txid'][:12]}…")
print(f"merged types: {len(result['types'])}")
```

---

## Inscription path

An Estandarte is inscribed as a single diamond — and since the
constitution/legislation split there are two of them: the constitution
`c1dd0000ee` (the `0xee` self-entry + the nine cross-cutting
conventions, ~2.7 KB, reverence tone, its ripcord armed) inscribed
first, then the v1
registry `c1dd0001ee` (15 type entries — thirteen canonical, one draft,
one deprecated; conventions inherited, ~4.0 KB with its parent prefix,
ordinary tone) inscribed as an amendment whose `parent_txid` is the
constitution's root. `registry_v1.preflight_inscription_form` refuses
the parentless form. Both fit comfortably in small diamonds
(≤25 knots × 80 bytes/knot per strand).

The Estandarte is the **last** thing inscribed in a protocol freeze.
Inscribing it before all its referenced types are stable would
either lock in known-broken bits or force an immediate amendment.
The Phase plan documented in the project notes:

1. Tighten the spec (drop bad subtypes, document the diamond, etc.)
2. Verify historical on-chain inscriptions match the tightened spec
3. Inscribe any new canonical examples
4. **Inscribe Estandarte v1** referencing the verified examples
5. Inscribe a `0xab` examples-binding citing the Estandarte

---

## Why this type exists

- **On-chain self-description.** A reader landing on any quipu can
  walk back to the Estandarte to learn the protocol's vocabulary.
  No external documentation server required.
- **Versioned via amendment chain.** Protocol changes don't break
  the lineage; they extend it. Old inscriptions remain valid under
  the older Estandarte; new ones cite the amendment chain leaf.
- **Self-referentiality is the proof.** The Estandarte that
  documents `0xee` is itself a `0xee` quipu. Anyone who can parse
  the Estandarte's body has, by virtue of doing so, demonstrated
  they implement the protocol the Estandarte declares.

---

## Open questions

1. **Multi-byte dimension encoding.** The current schema treats
   each dimension as a single byte. The `0xcc` cert subtype is
   2 bytes (subtype_hi:subtype_lo, big-endian). Documenting it as
   "one 16-bit dimension" works for the registry but a reader needs
   to know the byte layout from the type's own spec. An amendment
   might add an explicit `width` field per dimension.

2. **Conventions vs. types overlap.** The diamond and tone are
   cross-cutting and live in the conventions block. But tone is
   *also* a per-type header byte. Should tone be both a convention
   and a flag-list on every type? Currently it's only a convention,
   and per-type docs describe how each type uses it.

3. **Inscription target.** Currently planned for inscription under
   La Verna's root (`9xth7DcLGb1nACScMBeSfDCfghhLKF7yqs` 3-of-3
   bordado). Open: whether a posthumous Estandarte should carry
   `tone = 0xff`, and whether the bordado's full 3-of-3 should
   sign the inscription tx or just the cabeza.
