# Working plan: the speech-acts thread

Opened 2026-08-17. This is the standing to-do for the Austin / Searle / Derrida /
Burroughs / Land sequence. It survives a session reset; context does not.

Rules that govern all of it: `EXCEPTIONS.md` (the block rule, the apparatus
exception, the Burroughs forward grant). House style: `atlas_tools/style.py`.

## Standing instructions from the author

- **The tool travels, the man does not.** "He births a theoretical tool and we
  take it for a short walk." Never narrate a theorist as present at, or inside,
  the historical material. No conceits, no magical realism, no staged scenes.
  State what the event was and what the tool says about it.
- **Agents write the prose. The main loop delegates and commits.** Hand-writing
  campas was a mistake and is not to be repeated.
- **Hard facts stated flat.** Violence and addiction get the date, the place and
  the fact. No lyricism, no euphemism, no redemption arc.
- **One subject at a time.** Derrida, then Burroughs, then the Land deep dive.
- Replies to the author stay short. He reads on a phone.

## Status

| # | subject | state |
|---|---|---|
| 1 | **J. L. Austin** | DONE. 9 segments. Pass 2 gave him the magic and prophecy segment, incl. the Briar Rose stops that are the template for every apparatus stop since. |
| 2 | **John Searle** | DONE. 11 segments, 51 stops. Prophecy-as-declaration, the rites, and the LLM segment all added and then corrected per the ruling above. Report section 11 lists what is unverified. |
| 3 | **Nick Land** | PARTIAL. Has hyperstition (vs Austin and Searle) and Capitalism is Artificial Intelligence. The injection stop was removed on the author ruling; that material is Burroughs's. Deep dive still owed, see below. |
| 4 | **Jacques Derrida** | RUNNING, `wf_ac4b9393-f30`, launched 16:16. |
| 5 | **William S. Burroughs** | NOT STARTED. Launches when Derrida lands. Brief below. |
| 6 | **Land deep dive** | NOT STARTED. After Burroughs. Brief below. |

## Burroughs brief (next to run)

Spine, in the author's words: **language is a virus, in humans, institutions and
machines.** Three hosts, in that order.

- **The psyche.** The cut-up and fold-in are not a literary method, they are a
  delivery mechanism. Burroughs's goal was to destabilize consciousness by
  remixing, to inject language past the reader's defences and cut the word lines
  that run people. The Nova trilogy's control-and-infection cosmology. "The
  Invisible Generation" (1966), the tape recorder and playback experiments, the
  street operations.
- **The institution.** Propaganda named as the same mechanism working at scale.
- **The machine.** Prompt injection, and the instability in LLM assemblies where
  adversarial agents feed each other text that co-opts and pollutes their
  directives. **ONE OR TWO SENTENCES ONLY**, closing a stop that is otherwise
  entirely his. Never its own stop, never a segment, never in a stop name. This
  reaches past his death and is covered by the forward grant recorded in
  `EXCEPTIONS.md`; it must say so in `date_confidence`.
- **Stated flat, no poetry:** he shot and killed his wife Joan Vollmer in Mexico
  City in 1951; he was an addict for most of his life.
- Geography from QUEUE: Tangier, Mexico City, London, Paris. Joins the corpus's
  Tangier / exile-writer geography.
- Keep the phrase "prompt injection" out of his own prose. His file should sound
  like 1962: control, the word lines, the virus, playback.

## Land deep dive brief (after Burroughs)

Author's list, to be researched properly rather than hand-added: retrocausality;
the numogram and its Ccru apparatus; the Cthulhu Club; the Babylonian gods and
AI; Lovecraftian horror; the performativity of hyperstition; and the podcast
material, including what he says about Burroughs on **The Dangerous Maybe**.
Land is living and active, so this material is contemporary with him and needs
no exception. He also touches many subjects already in the atlas, so the
interlock pass matters here more than usual.

## Done today, for the record

`EXCEPTIONS.md` written and then extended with the author's OP_RETURN
formulation and the Burroughs forward grant. `research_pipeline.js` write stage
patched to read `EXCEPTIONS.md` and to never strip an apparatus relation
silently: it must keep it and flag it under "Apparatus relations for the
operator" with the direction caught.
