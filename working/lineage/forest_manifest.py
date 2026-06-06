#!/usr/bin/env python3
"""Staging manifest for the Goethe — Italian Journey forest.

Single source of truth for the consolidated diamond inscription: every piece,
its type/tone, its body file, and its reference edges — the FULL graph, cycles
included.

WHY CYCLES ARE FINE HERE
  A quipu's reference identity is its per-quipu ROOT txid. Body content rides in
  the OP_RETURN strands that descend FROM the root, so a root txid is a function
  of the body's KNOT COUNT (size), not its content. A txid reference is fixed
  length (32 bytes), so resolving a placeholder to a real txid never changes a
  body's size — hence never changes any knot count, hence never changes any root
  txid. So:

      build every piece with PLACEHOLDER refs (correct sizes)
        -> every body's knot count is fixed
        -> compute ALL per-quipu root txids at once (none depends on content)
        -> backfill the REAL root txids into the bodies (sizes unchanged)

  Every sibling can reference every other — mutually, circularly — with no build
  ordering, no cycle-breaking, and no binding piece. Confirmed by the cemetery
  build: "substitutes the real txids back ... same length, so knot counts are
  preserved." The roots are formed before the bodies are finalized.

Run to print the reference graph + a rough cost:
  python3 working/lineage/forest_manifest.py
"""
import os, math

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# id            type   tone        references (full graph — cycles OK)             body file
PIECES = [
 ("bode",          "0xce", "reverence", [],                                          "working/cosmos/bode.0xce.bin"),
 ("playmobil",     "0x03", "play",      [],                                          "working/lineage/goethe_portrait.0x03.bin"),
 ("campagna",      "0x03", "play",      [],                                          "working/lineage/goethe_campagna.0x03.bin"),
 ("tower",         "0x03", "seeking",   [],                                          "working/lineage/malcesine_tower.0x03.bin"),
 ("gana",          "0x01", "lust",      ["journey","jung_quote","jung_gen","goethe_gen","b_etym","b_journey","b_descent","b_shiva","b_eranos","b_lineage","b_antarctica"], "working/lineage/essay_journey.0x01.bin"),
 ("jung_quote",    "0x00", "grief",     [],                                          "working/lineage/jung_quote.0x00.bin"),
 ("journey",       "0xce", "seeking",   ["gana","campagna","goethe_gen","orrery","tower","jung_quote"], "working/lineage/italian_journey.0xce.bin"),
 ("goethe_gen",    "0xce", "ordinary",  ["playmobil","journey"],                     "working/lineage/goethe.0xce.bin"),
 ("orrery",        "0x3d", "ordinary",  ["journey","bode"],                          "working/cosmos/orrery.0x3d.bin"),
 ("jung_gen",      "0xce", "ordinary",  ["goethe_gen"],                              "working/lineage/jung.0xce.bin"),
 # margin-art plates — each published as a 0x5c LaTeX quipu (the .tex IS the body),
 # placed in the essay's outer margins (one per movement, render="marginplate").
 ("b_etym",        "0x5c", "lust",      [], "working/lineage/art/01_gana_etym.0x5c.bin"),
 ("b_lineage",     "0x5c", "ordinary",  [], "working/lineage/art/02_lineage.0x5c.bin"),
 ("b_journey",     "0x5c", "seeking",   [], "working/lineage/art/03_journey.0x5c.bin"),
 ("b_descent",     "0x5c", "seeking",   [], "working/lineage/art/04_subterranean.0x5c.bin"),
 ("b_shiva",       "0x5c", "reverence", [], "working/lineage/art/05_shiva.0x5c.bin"),
 ("b_eranos",      "0x5c", "seeking",   [], "working/lineage/art/06_eranos.0x5c.bin"),
 ("b_antarctica",  "0x5c", "grief",     [], "working/lineage/art/07_antarctica.0x5c.bin"),
 # (images complete: campagna = Tischbein painting, playmobil = map marker)
 # The Italian-Journey 3D is FUSED into the orrery (journey rides the globe surface),
 # so there is ONE scene; journey→orrery is the Florence "cosmos" link.
]

NAMES = {"bode":"Bode — the whole sky","playmobil":"Playmobil Goethe marker","campagna":"Campagna emblem (Tischbein)","tower":"Malcesine — the Scaliger tower",
 "gana":"Gana (essay)","jung_quote":"Jung to Serrano — the Hyperborean reply","journey":"Journey atlas — 57 waypoints",
 "goethe_gen":"Goethe genealogy","orrery":"Dantean cosmos (walkable scene)",
 "jung_gen":"Jung genealogy",
 "b_etym":"Banner — Gana, the roots","b_lineage":"Banner — The Lineage","b_journey":"Banner — The Italian Journey",
 "b_descent":"Banner — The Descent","b_shiva":"Banner — Shiva","b_eranos":"Banner — Eranos","b_antarctica":"Banner — Ego & Unconscious"}


def find_cycles(pieces):
    """Report cycles (informational — they are legal here)."""
    g = {p[0]: list(p[3]) for p in pieces}
    cycles, stack, onstack = [], [], set()
    def dfs(u, path):
        onstack.add(u); path.append(u)
        for v in g.get(u, []):
            if v in onstack:
                cycles.append(path[path.index(v):] + [v])
            elif v not in seen:
                dfs(v, path)
        onstack.discard(u); path.pop()
    seen = set()
    for n in g:
        if n not in seen:
            seen.add(n); dfs(n, [])
            seen |= onstack
    # de-dup cyclic paths by their frozenset
    uniq, keys = [], set()
    for c in cycles:
        k = frozenset(c)
        if k not in keys: keys.add(k); uniq.append(c)
    return uniq


if __name__ == "__main__":
    print("Goethe — Italian Journey forest · %d pieces · full reference graph:\n" % len(PIECES))
    tot_b = tot_k = 0
    for pid, typ, tone, refs, path in PIECES:
        b = os.path.getsize(os.path.join(REPO, path)); k = math.ceil(b / 80); tot_b += b; tot_k += k
        rtxt = (" → " + ", ".join(refs)) if refs else " (leaf)"
        print("  %-13s %-5s %-9s %6dB %4dk%s" % (pid, typ, tone, b, k, rtxt))

    ROOT, TIP, STRUCT = 0.05, 0.025, 0.10
    body, roots = tot_k * TIP, len(PIECES) * ROOT
    print("\n  bodies %d B · %d knots ≈ %.2f DOGE @0.025 · +%d roots×0.05 = %.2f · +splitter/join %.2f"
          % (tot_b, tot_k, body, len(PIECES), roots, STRUCT))
    print("  ≈ %.2f DOGE total" % (body + roots + STRUCT))

    cyc = find_cycles(PIECES)
    print("\n  circular references present (legal — root txids are size-derived, formed first):")
    for c in cyc:
        print("    " + " → ".join(c))
    print("\n  build: placeholder refs → compute all root txids → backfill real txids.")
