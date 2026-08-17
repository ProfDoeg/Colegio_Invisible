# Apparatus exceptions

Ruled by the author, 2026-08-17.

The standing rule is that a stop belongs to whoever was actually there, and that
a journey does not reference forward. If a subject's only connection to a place
or an object is that someone else later travelled there or wrote about it, that
is the other person's stop, on their own file.

This file names the exception. A subject listed here may have their **theoretical
framework applied backward** to events they never themselves discussed, as stops
on **their own file**. The framework travels; the person does not.

## The governing formulation

Ruled by the author, 2026-08-17, and it settles the question better than any
prose above or below it:

> The words can gaze on previous events and prophesize future events, but a 2026
> block hash cannot be written in a 2016 OP_RETURN. A 2016 block hash can however
> be embedded in a 2026 OP_RETURN.

A journey file is a block. It is stamped at its own moment and it can only
embed what already exists at that moment.

- **Searle's file may embed the 1429 coronation.** Old hash, new block. This is
  the whole of the exception, and it is why the apparatus stops are legal.
- **Joan's file may not embed Searle.** New hash, old block. Not a stylistic
  preference: it is not a thing that can be written.
- **But the words themselves may gaze forward.** A prophecy in 1429 speaks of a
  maiden not yet come, and that is not a forward reference, because an open
  utterance about the future contains no later artifact. Merlin's file and
  Joan's file carry their prophecies exactly as they stand. What they must never
  carry is the pointer: the slug, the file name, the twentieth-century
  philosopher. Prophecy is words gazing forward. A `suggested_ref` is a hash.

So the test is not "does this stop mention something later" but "does this file
contain an artifact that did not yet exist when the file's own clock stopped".

## What the exception licenses

- Stops on the listed subject's own file, at the listed subject's own pin, dated
  only to order the segment, applying their apparatus to material they never
  treated.
- The interpretive status stated plainly in `date_confidence`, together with the
  primary sources for the material itself. See `j_l_austin.journey.json`, the
  segment "The Formula That Does Not Describe: Magic and Prophecy", which is the
  template: three Briar Rose stops, all at Austin's Oxford pin, each saying in
  its own confidence field that Austin is not on record discussing the tale.

## What it does not license

- **Any forward reference.** Nothing goes into `joan_of_arc.journey.json` or
  `merlin.journey.json` pointing at Searle or Austin. A fifteenth-century file
  does not know about a twentieth-century philosopher, whatever the reading.
- **Moving anybody.** The apparatus stop stays at the theorist's own coordinates.
  Nobody is staged at a place they never went.
- **Framework applied forward.** The exception is for past events. Applying a
  dead theorist's apparatus to something that postdates them is a different move
  and is not covered here; it needs the author's separate say-so. Granted once,
  see below.

## Forward grants

Framework-applied-forward is not licensed in general and never by an agent's own
judgement. It is listed here, subject by subject, only where the author has said
so directly.

| subject | granted | what may reach forward |
|---|---|---|
| **William S. Burroughs** (1914-1997) | 2026-08-17, on the author's explicit instruction, given after the block-rule objection was put to him and overruled | the cut-up and the word-as-virus, carried forward to prompt injection and to the instability in LLM assemblies where adversarial agents feed each other text that co-opts and pollutes their directives |
| **Jacques Derrida** (1930-2004) | 2026-08-17, on the author's explicit instruction: "We should include it. It resonates deeply with LLMs specifically" | iterability and *il n'y a pas de hors-texte*, the mark or the text that functions and signifies with no reference to anything outside itself, carried forward to large language models: a system whose entire operation takes place inside text, with no access to any world, referent, or ground outside the text it was trained on and the text it generates |

The reasoning that makes it more than a licence: Burroughs's cut-up was an
attempt to destabilize consciousness by remixing, an injection into the human
psyche, and propaganda is that same mechanism at scale. Both are his own
project, in his own decades, and need no grant. The grant covers only the last
step, naming what the mechanism does to machines.

**Scope, ruled 2026-08-17: one or two sentences.** Prompt injection is a
contemporary *example*, not a subject. It closes a stop that is otherwise
entirely Burroughs's own and it never gets a stop of its own, a segment, or a
place in a stop name. If it runs longer than a sentence or two, it has stopped
being an example and the grant no longer covers it.

The stop still declares itself. It sits at Burroughs's own pin, is dated inside
his life as an ordering device, and its `date_confidence` states that the forward
reach is an author's grant recorded here, that Burroughs died in 1997, and that
he is not on record on any of it.

**Derrida, scope, ruled 2026-08-17: one or two sentences.** The language model is
a contemporary *example*, and it closes a stop that is otherwise entirely
Derrida's own, the 1967 stop for the three books, never a new stop, a segment, or
a name. The moment it grows past an example it has stopped being one, and the
grant no longer covers it.

Here too the stop declares itself: Derrida's own Paris pin, dated inside his life,
with `date_confidence` stating that the forward reach is an author's grant
recorded here, that Derrida died in 2004, and that he is not on record discussing
anything of the kind.

## The list

| subject | apparatus | applied backward to |
|---|---|---|
| **J. L. Austin** (1911-1960) | performatives, felicity conditions, the illocutionary act | the spell; Briar Rose, the curse and its amendment |
| **John Searle** (1932-2025) | the declaration, constitutive rules, X counts as Y in context C, status functions | the Merlin prophecy of the maiden from the hoary wood; its reading onto Joan of Arc in 1429 |
| **Jacques Derrida** (1930-2004) | iterability, the mark that functions in the absence of its author, iter and the Sanskrit itara | Hansel and Gretel: the trail that exists only because it can be returned to, and is deformed by each return. Also holds a forward grant, see above |
| **William S. Burroughs** (1914-1997) | language as virus, the cut-up, rogue writing, playback | propaganda as the same mechanism at scale. Also holds a forward grant, see above |
| **Nick Land** (1962- ) | hyperstition: the fiction that makes itself real | to be set when the stops are written |

Land is living, so material contemporary with him is not an exception at all.
He is listed because his apparatus is applied backward to Austin and Searle.

## The adversary's duty

The verify stage must not silently strip an apparatus relation. On finding a
reference not rooted in the subject's own life it stops and asks the human
operator whether to add the subject to this list, and it says **which direction
it caught** — backward, which is licensable, or forward, which is not. Silent
deletion is what cost `john_searle.journey.json` both its Merlin material and
its LLM material on the first pass.
