# Tone byte — canonical spec

The **tone byte** sits at offset 5 of every v1 Colegio Invisible quipu's
header, immediately after the type byte. It carries semantic information
about the inscribed content's emotional / classificatory register.

Tone is **transverse across types**: the same four values apply to text,
essay, image, scene, book, cert, encrypted, celestial, binding, and
estandarte quipus. Per-type specs cross-reference this document for the
tone vocabulary rather than restating it.

The canonical implementation lives in [`canonical/tone.py`](../../canonical/tone.py).
The full forward map + validator + reverse lookup are imported by every
type module rather than redeclared.

---

## Wire format

```
   header offset 5  <tone>  uint8, one of:
                              00 ordinary, 01 affection, 0d demonic, ff reverence
```

---

## Recognized values (v1)

| `<tone>` | name | when to use |
|---|---|---|
| `0x00` | ordinary  | the default; descriptive, academic, neutral, or literary content about the living |
| `0x01` | affection | paired, intimate, addressed to a specific other |
| `0x0d` | demonic   | content that documents harm: dictators, founding instruments of state terror, surveillance documents |
| `0xff` | reverence | the dead, ancestors, formal commemoration |

### `0x00` ordinary

The default. Use this for descriptive, neutral, academic, or literary
content about the living. If you don't have a specific reason to pick
another value, pick this one.

### `0x01` affection

Paired or intimate work — content addressed to a specific other, or
that exists within a known affectionate relationship. First observed
on the pair_HA / pair_CA inscriptions *Mi Caballo* and *Mi Perrito* —
short Spanish poems addressed to a beloved.

### `0x0d` demonic

Flags the **artifact**, not the inscriber. Use when the inscribed
content is itself an instrument or record of harm: a portrait of a
dictator, the founding document of a state-terror program, a
surveillance file, a torture-techniques catalog. The flag attaches
to what is depicted, not to the person inscribing it. A demonic-toned
quipu may be inscribed precisely so the archive preserves the artifact
under its true tone.

First inscribed instances: the Pinochet presidential portrait
(`03a08c37…`) and the October 1975 DINA invitation letter that founded
Operation Condor (`b0263c0f…`), both at block 6,217,650 under the
apocrypha key.

### `0xff` reverence

The dead, ancestors, formal commemoration. **Strict**: only for content
that refers to the dead. Inscriptions about the future, generational
change, or imagined coming things use `0x00`, not `0xff`.

(Two Bowie "Oh! You Pretty Things" inscriptions on chain used `0xff`
and that's a documented mis-tagging that stands — they should have
been `0x00`.)

---

## Builder behavior

Every `build_*_quipu()` function in `canonical/` calls
`tone.validate_tone(tone)` once at the top of its body. Unknown tone
bytes raise `ValueError` with a message listing the four canonical
values. A type module never carries its own per-module tone validation.

```python
from tone import validate_tone, TONE_ORDINARY, TONE_DEMONIC
def build_text_quipu(title, body, tone=TONE_ORDINARY, ...):
    validate_tone(tone)
    ...
```

---

## Reader behavior

Readers (`read_*_quipu`, `parse_dims` in NB 60, etc.) use
`tone.name(tone)` which returns the canonical lowercase name or
`unknown_0xNN` for any byte outside the four canonical values.
Readers therefore parse forward-compatibly: a future tone byte added
to a later version of the protocol still parses cleanly under v1
readers as `unknown_0xNN`, without crashing.

---

## Adding a new tone

A new tone byte is a protocol-level change. To add one (say a future
`0x5a` "ceremonial"):

1. Edit `canonical/tone.py`: add the constant + dict entry. Confirm
   the byte doesn't collide with any other position-5 semantic
   elsewhere (e.g. encrypted's sub-family byte at position 6 is
   independent and may share values without conflict).
2. Re-run every canonical type module's `_selftest()` — none should
   regress.
3. Update this spec.
4. Add a row to the table above with the semantic guidance.

All other code that touches tone bytes (NB 60's `TONE_NAMES`, the
streamlit viewer's tone-rendering helper) imports from `tone.py` and
picks up the new value automatically.

---

## History

| date | change |
|---|---|
| 2026-05-21 | v1: text + image grew per-module `TONE_*` constants for ordinary, affection, reverence (0x00, 0x01, 0xff) |
| 2026-05-22 | 0x0d demonic added per-module across 11 canonical files (commit `ddc9167`) |
| 2026-05-22 | tone byte centralized into `canonical/tone.py`; type modules import from it instead of redeclaring (this commit) |
