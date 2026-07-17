# Quipu type `0xee` — Estandarte (protocol registry)

> **STATUS: CANONICAL, not yet inscribed.** Implemented in
> [`canonical/estandarte.py`](../../canonical/estandarte.py), with the
> three standards authored and golden-frozen: the **constitution**
> `c1dd0000ee` ([`constitution.py`](../../canonical/constitution.py)),
> the **v1 registry** `c1dd0001ee`
> ([`registry_v1.py`](../../canonical/registry_v1.py)), and the **v2
> registry** `c1dd0002ee`
> ([`registry_v2.py`](../../canonical/registry_v2.py)). The
> constitutional quipu — documents the Quipu Protocol's own type-byte
> vocabulary. Self-referential: type `0xee` documents `0xee` among the
> other types. To be inscribed under the ACH root — the 3-of-3 multisig
> of Anthony, Christophia, and Hayagriva, the protocol's certificate
> authority.

An *Estandarte* ("banner / standard") catalogs protocol type bytes,
each type's named enum dimensions (with their wire width stated as
data — the `vkind` atom), single-bit flags, and a status (canonical /
proposed / draft / deprecated). It also catalogs cross-cutting
conventions.

Once inscribed, an Estandarte makes the protocol *referenceable on
chain*. Future quipus can cite it as the standard they conform to.
Amendments form a verifiable chain via a `parent_txid` field; a reader
walking from any leaf to its root accumulates the registry with
leaf-wins override semantics.

---

## The three standards

**Each version is a self-contained standard, declared as a delta**
([c1dd0002 §2](../design/c1dd0002.md)): an estandarte inherits its
parent chain and carries only what its version adds.

| inscription | version | tone | carries |
|---|---|---|---|
| constitution `c1dd0000ee` | `0x0000` | `0xee` sovereign | the `0xee` self-entry (the metacircle) + the thirteen founding conventions |
| v1 registry `c1dd0001ee` | `0x0001` | `0x00` ordinary | the 15 type entries (13 canonical, `0x1d` draft, `0x0c` deprecated); conventions inherited |
| v2 registry `c1dd0002ee` | `0x0002` | `0x00` ordinary | the celestial v2 entry (a keyed override of v1's) + the `atoms` / `date` / `strings` conventions |

The thirteen founding conventions: `magic`, `tone`, `diamond`,
`assembly`, `tag`, `ripcord`, **`genesis`** (the constitution's single
tag fans out into three ordinal ACH threads), **`despot`** (override
power while alive; first to burn), **`amend`** (constitutional
additions only; second to burn), **`commentary`** (voice without
power; outlives both burns), `citation`, `forest`, and
`pre-canonical`. The genesis fan-out and the burn ladder are law in
[c1dd0000.md](../design/c1dd0000.md), Articles V–VII.

A resolver at the v2 leaf composes the full registry: 16 type entries
(celestial speaking with v2's voice, everything else with v1's, `0xee`
with the constitution's) and 16 conventions.

---

## Byte layout

### Header — 6 bytes flat (the envelope)

```
offset  bytes        meaning
0..1    c1 dd        magic
2..3    <version>    protocol version, uint16 BE — 0000 constitution,
                     0001 v1, 0002 v2. The version selects the standard;
                     c1dd0001 is magic+version, not a 4-byte magic
4       ee           type byte = Estandarte
5       <tone>       tone byte — see tone.md
```

No title field — the Estandarte's identity is the registry itself,
not a label.

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
        <dim_name_len:1>  <dim_name>     e.g. "color", "subtype"
        <dim_desc_len:1>  <dim_desc>     what this field means in the type's header
        <vkind:1>                        the dimension's wire atom (atoms.py;
                                         u8/u16/u32 legal) — width stated as data
        <value_count:1>                  named values in this dimension
        for each value:
            <value:width(vkind)>         big-endian at the atom's width
            <val_name_len:1>  <val_name> e.g. "grayscale", "rgb"
            <val_desc_len:1>  <val_desc> one-liner
    <flag_count:1>                       count of independent single-bit flags
    for each flag:
        <bit:1>                          bit position 0–7
        <name_len:1>  <name>
        <desc_len:1>  <desc>
<C:1>                                    count of conventions
for each convention:
    <name_len:1>    <name>               e.g. "diamond", "atoms"
    <syntax_len:1>  <syntax>             formal pattern / shape
    <desc_len:1>    <desc>               what it means / when it applies
```

All length-prefixed fields are 1-byte unsigned (max 255 bytes UTF-8).
This body format is inherited unchanged across versions — a v2 reader
is a v1 reader; the reader refuses versions it does not implement
(`KNOWN_ESTANDARTE_VERSIONS`) rather than guessing.

---

## Dimensions vs. flags

A **dimension** is an unsigned field within the type's header whose
value is drawn from a mutually-exclusive named enumeration. Its wire
width is its `vkind` atom's width — `u8` unless declared otherwise;
cert's `subtype` declares `vkind = u16` and its values encode as
2 bytes. A grammar-fold reader computes the offset instead of
guessing it.

| type | status | dimensions |
|---|---|---|
| `0x00` text | canonical | (none — tone is a cross-type field) |
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
| `0xcc` cert | canonical | `subtype` — **vkind u16**: `hash`/`all-in-one`/`sale-offer` |
| `0xce` celestial | canonical | v1: `kind` (`earth`/`star`/`mixed`), `grouped`, `meta` (`no`/`time`/`more`) · **v2:** `kind` grown to the node-edge family (`genealogy`/`etymology`/`network`), `meta` = `no`/`more` only — see [celestial.md](celestial.md) |
| `0xda` dancer | canonical | `variant` (`performance`/`footage`/`graph`/`controller`) |
| `0xee` estandarte | canonical | (none) |

A **flag** is a single bit within a byte that's set independently of
other bits in the same byte. No canonical type currently uses the
flag field; it's reserved for future use.

---

## Tone vocabulary

| `<tone>` | when to use |
|---|---|
| `0x00` ordinary | the working protocol declarations — the v1 and v2 registries |
| `0xee` sovereign | the constitutional register: the constitution `c1dd0000ee` (tone and type share the byte) |
| `0xff` reverence | a posthumous or commemorative protocol freeze |

Affection (`0x01`) is not an Estandarte tone. The act of declaring
the protocol is constitutional, not intimate.

---

## Amendment chain

An Estandarte either is the *root* (no parent — `parent_kind = 00`)
or an *amendment* (`parent_kind = 01` followed by a 32-byte parent
txid). The parent txid is the **root transaction txid** of the
parent Estandarte (the inscription's canonical identifier).

`resolve_estandarte_chain(leaf_txid, fetcher)` walks the chain from
any leaf back to the root, accumulating entries. Override semantics:

- Types are keyed by `byte`. A type entry in a later amendment fully
  replaces the earlier entry for that byte (v2's celestial entry
  overrides v1's this way).
- Conventions are keyed by `name`. Same override rule.
- Status `3 deprecated` retires an entry — the entry remains visible
  in the merged registry but its status flags it as no longer in use.
- **One mechanism, two grains** — a same-version amendment grows
  *content*; a version-bump amendment increments the version and may
  extend the registry *format*. Within a chain the version may only
  grow toward the leaf; a regression is refused (a later law may not
  rewrite an earlier standard's past —
  [healing.md](../design/healing.md)).

The resolver detects cycles and caps chain depth (default 64).

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

Three diamonds, in constitutional order, each riding the last:

1. **The constitution** `c1dd0000ee` — root form (`parent_kind 00`),
   sovereign tone, its ripcord armed and its genesis tag carried
   (last output, N+2 anatomy).
2. **The v1 registry** `c1dd0001ee` — an amendment whose
   `parent_txid` is the constitution's root txid.
3. **The v2 registry** `c1dd0002ee` — an amendment whose
   `parent_txid` is the v1 registry's root txid.

The goldens (`tests/golden/*.hex`) freeze the **root forms** — content
review happens before any txid exists. At each ceremony the real
parent txid is passed and the bytes change only by the 33-byte parent
prefix; `preflight_inscription_form` refuses any legislation
(version ≥ 1) in parentless form.

---

## Why this type exists

- **On-chain self-description.** A reader landing on any quipu can
  walk back to the Estandarte to learn the protocol's vocabulary.
  No external documentation server required.
- **Versioned via amendment chain.** Protocol changes don't break
  the lineage; they extend it. Old inscriptions remain valid under
  the older standard — the version at bytes 2–3 selects the parser
  forever; new ones cite the amendment chain leaf.
- **Self-referentiality is the proof.** The Estandarte that
  documents `0xee` is itself a `0xee` quipu. Anyone who can parse
  the Estandarte's body has, by virtue of doing so, demonstrated
  they implement the protocol the Estandarte declares.

---

## Resolved and open questions

1. ~~**Multi-byte dimension encoding.**~~ **Resolved** by the `vkind`
   byte (the atom algebra, [c1dd0002 §7.1](../design/c1dd0002.md)):
   every dimension states its wire width as data. Cert's subtype is
   one 16-bit dimension, definitively.
2. **Conventions vs. types overlap.** Tone is both a convention and a
   per-type header byte. Currently it's only a convention, and
   per-type docs describe how each type uses it. Standing.
3. ~~**Inscription target.**~~ **Resolved**: under the ACH root — the
   3-of-3 of Anthony, Christophia, and Hayagriva. The constitution
   carries sovereign tone (`0xee`); the working registries carry
   ordinary (`0x00`).
