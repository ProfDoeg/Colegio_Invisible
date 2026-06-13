# Cartography — a concept map of the corpus

A reading of the 53 essays (the numbered sequence 220 → 171, plus the
unnumbered *augury* and *pet_sematary*) as a graph of concepts and the
relationships between them.

- `concept_map.md` — the prose synthesis: the three gravitational centers
  (Joan of Arc as lens, thread as thesis, the blockchain as culmination),
  the hidden through-lines (the cynocephalus narrator, the ombú that
  "makes the Atlantic crossing without moving", the Phrygian cap), and
  the corpus' self-demonstrating claim — a text that encodes its own
  certificate authority.
- `concept_map.json` — the graph: 56 concepts, 91 weighted edges, 14
  clusters (`{concepts, edges, clusters}`; edges are `{a, b, label,
  weight}`). Ready for a force-directed render in the same shape the
  console's wallet view uses.
- `notes.md` — the field notes the reading was built from.

## Provenance

Generated 2026-06-12 by the resident Claude on `nodus` (the LAN Linux
node), reading the essays under `essays/` directly. Not a hand-authored
artifact — a machine reading, kept for what it surfaces. Re-runnable by
pointing a fresh reading at `essays/`.
