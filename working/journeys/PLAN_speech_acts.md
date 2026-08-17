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
| 3 | **Nick Land** | DONE (deep dive complete, see row 6). |
| 4 | **Jacques Derrida** | DONE. 45 stops. Iterability spine, the Searle quarrel (Baltimore/Evanston), the Hansel and Gretel apparatus segment per EXCEPTIONS.md. es/ edition written. Report flags several unresolved contradictions (Cambridge signatories, cancer diagnosis year, graveside sentence). Forward grant added 2026-08-17: the hors-texte quote on the 1967 stop, closed with the LLM resonance the author asked for. |
| 5 | **William S. Burroughs** | DONE. 9 segments, 45 stops. Three-hosts structure (psyche: cut-up/Nova/Invisible Generation; institution: Scientology/Electronic Revolution, backward apparatus, no separate stop needed; machine: 2-sentence forward-grant close on "Paris, The Ticket That Exploded," avoids the phrase "prompt injection" in his own prose). Joan Vollmer's death stated flat. es/ edition written. Gate found and fixed 16 violations. |
| 6 | **Land deep dive** | DONE, 2026-08-17. 2 new segments, 12 new stops: The Decimal Labyrinth (numogram, Pandemonium, Cthulhu Club correspondence, Beaconsfield/Syzygy, Burroughs conscripted into the Lemurian Time War, the Lovecraft backward-apparatus stop) and Hyperstition in Practice (Catacomic's four features, the Babylonian foil not ingredient, Bitcoin/Kant, two Dangerous Maybe stops). EXCEPTIONS.md updated: Land's "applied backward to" now names the Necronomicon. Targeted search for Land discussing Burroughs on podcasts came up empty and the report says so as a negative finding rather than papering over it. es/ edition extended. Gate found and fixed 5 violations.

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
- **The machine.** Frame it explicitly as an instance of language-as-virus, not
  a separate topic: his own remixing (cut-up, fold-in) IS an attempt to "prompt
  inject" the human psyche, propaganda IS the same mechanism at the level of
  institutions, and "prompt injection" in LLM assemblies (adversarial agents
  feeding each other text that co-opts and pollutes directives) is the same
  concept again at the level of machines. One virus, three hosts, the author's
  own structure, so say it that way, human / organization / machine, rather
  than treating the machine case as a bolt-on. **ONE OR TWO SENTENCES ONLY** for
  the machine case specifically, closing a stop that is otherwise entirely his.
  Never its own stop, never a segment, never in a stop name. This reaches past
  his death and is covered by the forward grant recorded in `EXCEPTIONS.md`; it
  must say so in `date_confidence`.
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
