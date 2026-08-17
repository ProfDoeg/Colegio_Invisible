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
  and is not covered here; it needs the author's separate say-so.

## The list

| subject | apparatus | applied backward to |
|---|---|---|
| **J. L. Austin** (1911-1960) | performatives, felicity conditions, the illocutionary act | the spell; Briar Rose, the curse and its amendment |
| **John Searle** (1932-2025) | the declaration, constitutive rules, X counts as Y in context C, status functions | the Merlin prophecy of the maiden from the hoary wood; its reading onto Joan of Arc in 1429 |
| **Jacques Derrida** (1930-2004) | iterability, the mark that functions in the absence of its author, iter and the Sanskrit itara | Hansel and Gretel: the trail that exists only because it can be returned to, and is deformed by each return |
| **William S. Burroughs** (1914-1997) | language as virus, the cut-up, rogue writing | to be set when the journey is written |
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
