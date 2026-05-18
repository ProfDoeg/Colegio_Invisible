# canonical/

This folder holds the files that constitute **the Quipu Protocol itself** —
the byte-format spec, the reference encoders/decoders, the renderer, the
citation resolver, the whitepaper, and the test vectors. Everything here is
meant to be **inscribed on the Dogecoin chain** so that the protocol becomes
self-describing: any future reader (human, AI, alien archivist) can fetch
these bytes from chain and fully reconstruct the protocol without external
documentation.

Files outside this folder (in the repo root) are *tools* that use the
canonical modules — wallets, key management, Streamlit UI, codec
implementations, broadcast workflows, etc. Those are implementation
choices, not protocol. Anyone can write their own.

---

## The rule for what belongs here

**A file belongs in `canonical/` if and only if it is byte-level protocol
machinery.** Concretely, that means:

| YES belongs here | NO does not belong here |
|---|---|
| Wire-format encoders/decoders | Wallet operations |
| The Estandarte (type registry) | Private-key generation/storage |
| Type spec for any 0xXX byte | Network RPC code |
| Citation/reference resolvers | Streamlit or other UI |
| Renderers that work from bytes alone | UTXO selection / fee estimation |
| The whitepaper and conventions doc | Codec implementations (the bytes are spec, the codec is impl) |
| Test vectors | Specific node configuration |
| Diamond-walker bytes-in/bytes-out helpers | Any "happens to be the way Anthony does it" code |

The boundary test: **could two independent implementations of the protocol
both rely on this file as their source of truth, without disagreement?**
If yes, it's canonical. If it bakes in one party's wallet or one party's
node or one party's UI, it's a tool.

---

## Current contents

### Present and ready

- **`estandarte.py`** — type `0xee`. The protocol's own registry: documents
  every type byte, subtype, flag, and convention. Self-referential
  (documents `0xee` itself). Supports amendment chain via `parent_txid` in
  body header so future versions cite predecessors.

- **`celestial.py`** — type `0xce`. Encoder/decoder for celestial figures
  (earth or star coordinates, ungrouped or grouped). The grouped subtype
  (high bit `0x80` set in kind byte) lets one inscription carry multiple
  named constellation groups, each with its own point and line sets.

- **`celestial_render.py`** — produces a matplotlib figure from a celestial
  quipu's bytes alone. No off-chain inputs needed; group colors, legend,
  labels all derive from on-chain content.

- **`quipu_refs.py`** — implements the `<<txid>><<name>>` citation
  convention: parse, resolve (via fetcher callback), and render a single
  group as a standalone sub-figure.

### Pending — to be added

- **`colegio_core.py`** — extracted from the working repo's
  `colegio_tools.py`. Should contain only the diamond walker
  (`fetch_quipu_payload(txid)`) and OP_RETURN bytes assembly helpers.
  Everything wallet/RPC/key-touching stays in the (non-canonical)
  `colegio_tools.py`. Estimated ~12 KB once extracted.

- **`quipu_protocol.tex`** — the whitepaper, currently living in
  `~/Desktop/tufte-latex-master/quipu_protocol.tex`. Move or symlink in.
  Documents: the diamond pattern, the magic prefix, every type's purpose
  with worked examples, the citation convention, the lineage chain, the
  field-type vocabulary for certificates.

- **`test_vectors.json`** — for each type and subtype, a small worked
  example: `{type_byte, subtype_byte, header_hex, body_hex, expected_parsed_dict}`.
  Lets any implementation self-verify by parsing the example and
  comparing the result to `expected_parsed_dict`.

### Definitely not here

- `voice_codec.py` — the codec is an implementation; the protocol just
  reserves type byte `0x07` and three subtypes. A reader who can't decode
  STFT/LPC/Codec2 can still see the type byte and know what was attempted.
- `quipu_console.py` — Streamlit UI
- `quipu_orchestrator.py` — broadcast workflow
- `colegio_tools.py` (the full file) — wallet, RPC, node interaction
- `quipu_crypto.py` — key-touching crypto helpers
- `smoke_test.py`, `essay_renderer.py` — tools

---

## Lifecycle: how to add to this folder

When you (Claude or human) build something new and consider whether it
belongs here, ask:

1. **Is this a byte format?** If you're defining what bytes mean on chain
   — type bytes, subtype bytes, body layouts, header conventions — then yes,
   that documentation/code belongs in `canonical/`.

2. **Is it a parser that works from bytes alone?** No keys, no wallet,
   no RPC dependency. Just: bytes-in, structured-data-out. Yes, canonical.

3. **Is it a renderer that works from parsed data alone?** No off-chain
   asset lookup, no implementation-specific styling. Yes, canonical.

4. **Is it the spec itself?** Whitepaper, conventions documentation, test
   vectors. Yes, canonical.

5. **Does it touch a key, sign a transaction, talk to a node, render a
   UI, or do anything user-specific?** No — it's a *tool*. Lives in the
   repo root or wherever, gets shipped to users, but is NOT in `canonical/`.

When in doubt, ask: **would inscribing this file on chain make sense?**
Inscribing a wallet helper is nonsense — every reader needs their own
wallet logic for their own keys. Inscribing a byte-format spec is exactly
the point.

---

## What happens to the contents of this folder

Files in `canonical/` will be inscribed on the Dogecoin chain as `0x00`
text quipus, anchored by a quipu-of-quipus binding (`0x70`) and pointed
to from La Verna's bordado address via a tiny root-pointer transaction.

The Estandarte (`estandarte.py`'s output, ie the actual encoded registry
bytes — not the encoder source) is the first thing inscribed. It documents
the type vocabulary. Then the other modules and the whitepaper get
inscribed as text quipus citing the Estandarte as their authority.

A future reader who knows only "look at bordado, find the root pointer"
fetches the pointer, follows it to the binding, walks the binding to find
every canonical file, and reconstructs the protocol from chain alone.

Inscription budget for the full canonical corpus: approximately **75
DOGE** at predicted Dogecoin tip-per-tx rates. Comes from the 5,400-DOGE
endowment at bordado.

---

## Note to future Claude

If you are reading this in a later session: **this folder is the protocol**.
Treat any change here as a constitutional change. Don't add or remove
files casually. When you build a new module, ask the human whether it
belongs in `canonical/` — most things don't. The Estandarte amendment
chain exists precisely so that the on-chain registry can evolve without
losing history; use it rather than mutating the canonical folder
silently.

Specific things that have been discussed but not yet acted on:

- Extract `colegio_core.py` from the working `colegio_tools.py`
- Remove the `mixed` (0xce.0x02) subtype from `celestial.py` and from the
  Estandarte content — it conflates earth and sky coordinates and was
  judged bad science
- Verify the 0xcc body grammar for subtypes 0x01 (hash) and 0x02
  (all-in-one) against the actual on-chain bytes of Maier `1ec0…` and
  Domrémy `6da7a9…` once the local full-node IBD completes
- Add the diamond-pattern convention to the Estandarte (currently the
  Estandarte documents OP_RETURN payloads but not how multi-tx
  inscriptions assemble — major omission)
- Write test vectors

The user has explicitly said: **wait to publish until everything is worked
out and tight.** No broadcasting from `canonical/` until the spec is
verified, the test vectors exist, and the diamond-pattern convention is
documented.
