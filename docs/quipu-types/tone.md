# Tone byte — canonical spec

The **tone byte** sits at offset 5 of every v1 Colegio Invisible quipu's
header, immediately after the type byte. It carries semantic information
about the inscribed content's emotional / classificatory register.

Tone is **transverse across types**: the same eleven values apply to text,
essay, image, scene, book, cert, encrypted, celestial, binding,
estandarte, and latex quipus. Per-type specs cross-reference this document
for the tone vocabulary rather than restating it.

The canonical implementation lives in [`canonical/tone.py`](../../canonical/tone.py).
The full forward map + validator + reverse lookup are imported by every
type module rather than redeclared.

---

## Wire format

```
   header offset 5  <tone>  uint8, one of:
                              00 ordinary
                              01 affection/care    02 seeking/wandering
                              03 play/interaction  04 lust/wanting
                              05 rage/anger        06 fear/dread
                              07 grief/panic
                              0d demonic   a1 ai   ff reverence
```

---

## Recognized values (v1)

Tones `0x01`–`0x07` are **the affective family**: Jaak Panksepp's seven
primal, subcortical emotional systems shared across all mammals — distinct
neurological drives, not cognitive states. They mark the felt register the
content carries. `0x0d`, `0xa1`, `0xff` are a separate, classificatory axis.

| `<tone>` | name | when to use |
|---|---|---|
| `0x00` | ordinary  | the default; descriptive, academic, neutral, or literary content about the living |
| `0x01` | affection/care | the nurturing, protective bond; paired, intimate, addressed to a specific other (Panksepp CARE) |
| `0x02` | seeking/wandering | enthusiastic foraging, curiosity, anticipation, engagement with the world (SEEKING) |
| `0x03` | play/interaction | rough-and-tumble social joy, games, teasing, the "laughter" register (PLAY) |
| `0x04` | lust/wanting | the reproductive drive, desire, courtship (LUST) |
| `0x05` | rage/anger | frustration when goals are blocked or movement is restrained; fury (RAGE) |
| `0x06` | fear/dread | anxiety, the freeze-or-flee alarm, danger (FEAR) |
| `0x07` | grief/panic | separation distress, the isolation call, loss and longing (PANIC/GRIEF) |
| `0x0d` | demonic   | content that documents harm: dictators, founding instruments of state terror, surveillance documents |
| `0xa1` | ai        | authored by, or fully attributable to, a non-human model; machine-composed content |
| `0xe5` | hope      | esperanza; content written toward the future reader — corrections, healings, editions, invitations |
| `0xff` | reverence | the dead, ancestors, formal commemoration |

### `0x00` ordinary

The default. Use this for descriptive, neutral, academic, or literary
content about the living. If you don't have a specific reason to pick
another value, pick this one.

### the affective family (`0x01`–`0x07`)

These seven are Panksepp's primal emotional systems. Pick the tone for the
**drive the content carries**, not for a cognitive judgment about it. A
single inscription gets one tone; if several apply, pick the dominant
register. Names are kept lowercase, in `primary/secondary` form.

### `0x01` affection/care

The nurturing, protective bond — Panksepp's CARE system, folded together
with the existing affection register. Use for paired or intimate work
addressed to a specific other, parental tenderness, devotion, social
bonding. First observed on the pair_HA / pair_CA inscriptions *Mi Caballo*
and *Mi Perrito* — short Spanish poems addressed to a beloved.

### `0x02` seeking/wandering

Panksepp's SEEKING — the enthusiastic, exploratory drive to forage,
investigate, and engage with the world. Use for content charged with
curiosity, anticipation, questing, restless searching, the pull forward.

### `0x03` play/interaction

Panksepp's PLAY — rough-and-tumble social joy, the high-frequency
"laughter" register. Use for playful, ludic, game-like, teasing content;
delight taken in interaction itself.

### `0x04` lust/wanting

Panksepp's LUST — the reproductive drive and the courtship behaviors
around it. Use for erotic, desiring, amorous content.

### `0x05` rage/anger

Panksepp's RAGE — the aggressive, frustration-based response triggered
when a goal is blocked or movement is restrained. Use for furious,
indignant, thwarted, confined content.

### `0x06` fear/dread

Panksepp's FEAR — the anxiety/avoidance alarm that prompts freeze-or-flee.
Use for content of danger, dread, threat, apprehension.

### `0x07` grief/panic

Panksepp's PANIC/GRIEF — the separation-distress system, the isolation
call. Use for content of loss, longing, mourning, the pain of being parted
from one's own. Distinct from `0xff` reverence: grief is the acute felt
distress of separation; reverence is the formal honoring of the dead.

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

### `0xa1` ai

Authored by, or fully attributable to, a non-human model. Marks
inscriptions whose prose, image, or other content emerged from machine
composition rather than from a human hand. Distinct from cases of
collaborative authorship where a human edits or assembles AI-produced
fragments — for those, prefer `0x00` ordinary and acknowledge the
collaboration in the body text or in a co-author field.

Use `0xa1` when:
- The inscription's entire content was machine-composed and the human
  role was limited to prompting and broadcasting (e.g. an AI-authored
  binding quipu, a TikZ piece generated for typesetting, an AI's
  commentary essay).
- The inscriber wants the byte-level header itself to declare the
  inscription's machine origin, so any downstream renderer / indexer /
  archive can categorize without parsing the body.

Do **not** use `0xa1` for:
- Cases where AI assistance was used to draft but the human authored the
  final form. That is `0x00`.
- Encrypted-then-decrypted content whose inner body happens to be AI-
  authored — the tone reflects the outer artifact's character, not the
  pipeline that produced the inner bytes.

The byte mnemonic `0xa1` reads "a-one" / "AI"; the choice is deliberate
and the value sits in the non-ASCII range so there is no chance of
collision with text-body content that a misconfigured reader might
mistake for a tone byte.

First inscribed instances will be the commentary binding and TikZ
artwork pieces in *El Libro del Gólem* (multiman address).

### `0xe5` hope

Esperanza — the byte reads "E5" ≈ "ES". Content written TOWARD the
future reader, trusting it will be found and followed: corrections and
healings (the act of mending a permanent corpus presumes someone will
read it mended), edition catalogs, standing invitations, the thread
left for whoever comes. Where `0xff` faces the dead, `0xe5` faces the
not-yet-arrived. Coined by Anthony 2026-06-10 for the first correction
catalog (the healing of the Dantean Cosmos); its first inscription is
that catalog itself.

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
bytes raise `ValueError` with a message listing all eleven canonical
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
`unknown_0xNN` for any byte outside the eleven canonical values.
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
| 2026-05-23 | `0xa1` ai added during a conversation that produced *El Libro del Gólem*; designates inscriptions whose content is fully machine-composed |
| 2026-06-01 | affective family `0x02`–`0x07` added — Panksepp's primal emotional systems (seeking, play, lust, rage, fear, grief); `0x01` affection renamed `affection/care` to fold in CARE. Tones `0x01`–`0x07` now form the seven-system family |
