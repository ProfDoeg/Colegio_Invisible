---
name: humanizar
description: Humanize Colegio Invisible writeups in English or Spanish - apply the humanizer patterns under this corpus's house style, which takes precedence. Use for campa, essays, atlas writeups, and their Spanish versions.
---

# Humanizar — the humanizer, adapted for this corpus

Apply the installed `humanizer` skill's patterns (AI-tell removal) to a writeup,
in English or Spanish, under the constraints below. Where humanizer and house
style disagree, HOUSE STYLE WINS.

## House style takes precedence

1. **Quotations are untouchable.** `quote`/`quote_source` fields, blockquotes,
   and any verbatim source text (KJV, Qur'an, letters, testimony) are never
   edited. Virgil's "Quos ego—!" keeps its dash; editing a quotation to fit
   style falsifies it.
2. **The register is not an AI-tell.** This corpus is written as
   `national mythology: the canon is true` — present tense, third person,
   mythic elevation, declarative confidence. Humanizer's "significance
   inflation" and "excessive formality" patterns must NOT flatten it. The
   Lord speaks; the emir withdraws; the saint carries the child. That is the
   voice, not slop.
3. **Em dashes:** already banned in authored text (stricter than humanizer).
   The surviving matched-pair dashes bracket asides with internal commas and
   are deliberate — do not remove them. See
   `working/journeys/atlas_tools/README.md`.
4. **Straight quotes only.** Zero curly quotes in the corpus; never introduce one.
5. **campa length band:** 450-650 characters. Edits must not push a campa
   outside it.
6. Fixes are restructures, not lazy substitutions: when a sentence needs to
   lose a construction, rebuild it as prose — sometimes as two sentences, each
   with subject and predicate — never a mechanical swap. (The author's model:
   "Do not make schools by building rooms; make them by manufacturing
   teachers, a task of industrial scale.")

## Spanish patterns (the humanizer skill is English-only; use these for ES)

Kill on sight in AUTHORED Spanish text:

- **Muletillas de IA:** "cabe destacar", "cabe mencionar", "es importante
  destacar/mencionar/senalar", "en el vasto mundo de", "juega un papel
  crucial/fundamental", "a lo largo de la historia" (as filler), "sumergirse
  en", "un abanico de", "en el ambito de", "sin lugar a dudas", "no es solo X,
  sino Y" (the not-X-but-Y tic), "desde X hasta Y, pasando por Z" (fake-range
  trio), "tanto X como Y" chained more than once per paragraph.
- **Inflacion de significado:** "revolucionario", "invaluable", "fascinante",
  "impresionante" as reflexive adjectives. The corpus states facts and lets
  juxtaposition do the interpretive work.
- **Cierres de chatbot:** "En conclusion", "En resumen", "En definitiva",
  final paragraphs that restate the essay. The corpus ends on a fact or an
  image, never a summary.
- **Rule-of-three reflex** (clausal trios): the author has explicitly banned
  recapitulation sentences and clausal trios. Two items or four; a trio only
  when the material genuinely comes in threes (las tres virgenes martires).
- **Raya (—):** same rule as English em dash - banned in authored text,
  preserved in citas textuales. Spanish printed dialogue in quotations keeps
  its rayas.
- **Comillas:** straight " and ' only; never « » or curly.
- **Anglicismos de traduccion:** "eventualmente" for "finally" (use
  "finalmente"), "actualmente" misused, "asumir" for "suponer", calqued
  passive voice where Spanish wants the impersonal se.

## Procedure

1. Read the target text. Determine language (or both, for paired EN/ES).
2. Run the humanizer patterns (EN) or the Spanish list above (ES), always
   filtered through House style rules 1-6.
3. For paired texts, fix each language ON ITS OWN TERMS - the Spanish is not
   required to mirror the English sentence-for-sentence; it must be good
   Spanish (see es/richard_lionheart: "las contrata sin mas: son las..." -
   solved with a colon where English needed a restructure).
4. Present changes as a reviewable diff; for corpus files, never write
   without showing the proposal first. LOCKED corpus essays (171-220,
   augury, pet_sematary) are NEVER edited - findings go to INDEX.md as errata.
