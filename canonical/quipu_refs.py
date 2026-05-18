"""
quipu_refs.py — citation/reference primitive for quipus.

Provides a parse + resolve pipeline for the citation convention

    <<txid>><<name>>

which references a named object inside a celestial quipu (type 0xce).
The txid is the join-transaction hex (64 chars). The name is resolved
against the cited quipu in two passes:

    1. groups block first — matches a constellation / phase / group name
    2. points block fallback — matches an individual star or location name

So both `<<txid>><<Orion>>` (group) and `<<txid>><<Betelgeuse>>` (single
star inside that group) resolve cleanly from the same inscription.

Use cases:
    1. Text quipus (0x00) that cite a constellation in their prose
    2. Binding/index quipus (0xab DRAFT) that catalog canonical figures
       across many inscriptions
    3. Off-chain commentary, essays, whitepapers

Resolver pipeline:
    parse_refs(text)                       → list of (txid, name) pairs
    resolve_ref(txid, name, fetcher)       → ({"points":..., "lines":...,
                                                "name":..., "parent_title":...})
    render_constellation(...)              → matplotlib figure of just that
                                              group, isolated

`fetcher` is any callable that takes a txid hex string and returns the
concatenated OP_RETURN payload bytes. The default uses dogecoin-cli via
subprocess and assumes a local node, but you can pass any callable
(public-RPC client, block-explorer wrapper, in-memory test stub).
"""

from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from celestial import read_celestial_quipu


# ---------------------------------------------------------------------------
# Citation parser
# ---------------------------------------------------------------------------

# Match <<txid>><<name>>:
#   - <<{hex 64 chars}>>  — the txid (no embedded > or <)
#   - <<{anything up to next >>}>>  — the group name (UTF-8, no embedded >>)
CITATION_RE = re.compile(
    r"<<\s*([0-9a-fA-F]{64})\s*>>\s*<<\s*([^>]+?)\s*>>"
)


def parse_refs(text):
    """Find all `<<txid>><<name>>` citations in a text blob.

    Returns:
        list of (txid_hex, group_name) tuples in document order.
    """
    return [(m.group(1).lower(), m.group(2)) for m in CITATION_RE.finditer(text)]


def format_ref(txid, name):
    """Canonical formatter for a citation."""
    return f"<<{txid.lower()}>><<{name}>>"


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

def resolve_ref(txid, name, fetcher):
    """Resolve a `<<txid>><<name>>` citation to its sub-figure or point.

    Looks up `name` against the cited quipu in two passes:
      1. groups block (a constellation / phase / group)
      2. points block (a single star / location)

    Args:
        txid:    join-transaction hex (64 chars)
        name:    UTF-8 name from either the groups block or the points block
        fetcher: callable(txid_hex) -> bytes (the concatenated OP_RETURN
                 payload from the quipu's diamond)

    Returns:
        dict with keys:
            'parent_title':  title of the parent celestial quipu
            'parent_txid':   the join txid as given
            'name':          the name as given
            'kind':          'group' (matched a group) or 'point' (matched a single point)
            'tone':          tone byte of the parent quipu
            'points':        list of point dicts (with kind/coord keys preserved)
                             — many points for a group, exactly one for a point match
            'lines':         list of (a, b) line index pairs LOCAL to `points`
                             (re-indexed to 0..len(points)-1)
                             — empty list for a point match

    Raises:
        ValueError if the inscription isn't a celestial quipu, or if the
        named object isn't found in either the groups or the points.
    """
    blob = fetcher(txid)
    if isinstance(blob, str):
        blob = bytes.fromhex(blob.strip())

    # Recover header length from the on-chain layout (v1, May 2026 redesign):
    #   c1dd0001 type tone kind grouped meta K_hi K_lo T <title>
    if blob[:4] != b"\xc1\xdd\x00\x01":
        raise ValueError(f"txid {txid[:12]}... payload not a quipu (bad magic)")
    if blob[4] != 0xCE:
        raise ValueError(f"txid {txid[:12]}... is type 0x{blob[4]:02x}, not celestial")
    if len(blob) < 12:
        raise ValueError(f"txid {txid[:12]}... payload too short for celestial header")
    T = blob[11]
    header_len = 12 + T
    header = blob[:header_len]
    body   = blob[header_len:]

    parsed = read_celestial_quipu(header, body)

    # Pass 1 — try matching a group name
    if parsed["groups"] is not None:
        for g in parsed["groups"]:
            if g["name"] == name:
                global_to_local = {gi: li for li, gi in enumerate(g["point_indices"])}
                local_points = [parsed["points"][gi] for gi in g["point_indices"]]
                local_lines  = []
                for a, b in g["lines"]:
                    if a not in global_to_local or b not in global_to_local:
                        outsider = a if a not in global_to_local else b
                        raise ValueError(
                            f"group {name!r} has a line to point index {outsider} "
                            f"which is not a member of the group"
                        )
                    local_lines.append((global_to_local[a], global_to_local[b]))
                return {
                    "parent_title": parsed["title"],
                    "parent_txid":  txid.lower(),
                    "name":         name,
                    "kind":         "group",
                    "tone":         parsed["tone"],
                    "points":       local_points,
                    "lines":        local_lines,
                }

    # Pass 2 — try matching a single point name
    for pt in parsed["points"]:
        if pt["name"] == name:
            return {
                "parent_title": parsed["title"],
                "parent_txid":  txid.lower(),
                "name":         name,
                "kind":         "point",
                "tone":         parsed["tone"],
                "points":       [pt],
                "lines":        [],
            }

    # Neither matched — build a useful error
    available_groups = ([g["name"] for g in parsed["groups"]]
                       if parsed["groups"] is not None else [])
    available_points = [pt["name"] for pt in parsed["points"]]
    raise ValueError(
        f"name {name!r} not found in inscription {txid[:12]}... "
        f"(groups: {available_groups or 'none'}; "
        f"{len(available_points)} points named)"
    )


# ---------------------------------------------------------------------------
# Default fetcher (dogecoin-cli)
# ---------------------------------------------------------------------------

def dogecoin_cli_fetcher(txid):
    """Walk a quipu's diamond starting from the join tx and return the
    concatenated OP_RETURN bytes. Uses dogecoin-cli via subprocess.

    Assumes a local full node with txindex=1 (or wallet-relevant txs only,
    in which case `gettransaction` is used as fallback).

    Out of scope here: actually walking the multi-strand diamond. For now,
    this stub raises NotImplementedError. The full walker logic already
    exists in colegio_tools.py / quipu_orchestrator.py and can be wired
    in once the inscription is broadcast.
    """
    raise NotImplementedError(
        "dogecoin_cli_fetcher is a placeholder; wire to "
        "colegio_tools.fetch_quipu_payload(txid) once the orchestrator's "
        "walker is exposed as a standalone callable."
    )


# ---------------------------------------------------------------------------
# Single-constellation renderer
# ---------------------------------------------------------------------------

def render_constellation(resolved, output_path=None, style=None):
    """Render a single constellation (resolved from a `<<txid>><<name>>` ref).

    Args:
        resolved: dict returned by resolve_ref()
        output_path: optional PNG path
        style: optional style dict overriding celestial_render defaults

    Returns:
        (fig, ax) matplotlib pair.
    """
    import matplotlib
    if output_path:
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    from celestial_render import DEFAULT_STYLE_STAR
    st = dict(DEFAULT_STYLE_STAR)
    if style:
        st.update(style)

    points = resolved["points"]
    lines  = resolved["lines"]

    fig, ax = plt.subplots(figsize=st["figsize"], facecolor=st["bg"])
    ax.set_facecolor(st["bg"])

    # Coord extractor — handles both star and earth points
    def xy(pt):
        return (pt["ra"], pt["dec"]) if pt["kind"] == "star" else (pt["lng"], pt["lat"])

    for a, b in lines:
        xa, ya = xy(points[a])
        xb, yb = xy(points[b])
        ax.plot([xa, xb], [ya, yb],
                color=st["line_color"], lw=st["line_width"],
                alpha=st["line_alpha"], zorder=1)

    for pt in points:
        x, y = xy(pt)
        ax.scatter(x, y, s=st["point_size"], color=st["point_color"],
                   edgecolor=st["point_edge"], lw=0.4, zorder=3)
        ax.annotate(pt["name"], (x, y),
                    xytext=(5, 5), textcoords="offset points",
                    color=st["label_color"], fontsize=st["label_fontsize"],
                    zorder=4)

    ax.set_xlabel("Right Ascension (°)" if points[0]["kind"] == "star" else "Longitude (°)",
                  color=st["axis_color"])
    ax.set_ylabel("Declination (°)" if points[0]["kind"] == "star" else "Latitude (°)",
                  color=st["axis_color"])
    if points[0]["kind"] == "star":
        ax.invert_xaxis()
    ax.tick_params(colors=st["axis_color"])
    for sp in ax.spines.values():
        sp.set_color(st["spine_color"])
    ax.grid(True, color=st["grid_color"], lw=0.4, alpha=0.6)

    # Citation in the title — show provenance
    ax.set_title(f"{resolved['name']}\n"
                 f"from «{resolved['parent_title']}»  "
                 f"at txid {resolved['parent_txid'][:12]}…\n"
                 f"{len(points)} stars · {len(lines)} lines",
                 color=st["title_color"], fontsize=st["title_fontsize"])

    fig.tight_layout()
    if output_path:
        fig.savefig(output_path, dpi=st["dpi"], facecolor=st["bg"])
        print(f"wrote {output_path}", file=sys.stderr)
    return fig, ax
