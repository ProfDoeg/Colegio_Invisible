"""
celestial_render.py — render any 0xce celestial-figure quipu from its bytes.

This is the read-side complement to celestial.py. Given the (header, body)
bytes of a celestial quipu (homogeneous-star, homogeneous-earth, or mixed),
parse via read_celestial_quipu and produce a matplotlib figure.

The renderer is intentionally generic: it knows nothing about a particular
inscription's mythology, color groups, or label-placement quirks. It draws:

    - All points as white circles with their stored names labeled
    - All lines as gray strokes between point pairs
    - Title from the inscription header
    - Sky-style dark navy background for star figures
    - Earth-style map background for earth figures
    - Mixed figures get sky background with earth points marked square

Callers who want richer rendering (group colors, halos, custom label
placements like the first-light Orion+kin chart) can pass overrides via the
`style` and `label_overrides` kwargs, or call the low-level draw helpers
directly.

Usage from Python:

    from celestial_render import render_celestial_quipu
    fig, ax = render_celestial_quipu(header_bytes, body_bytes,
                                     output_path="/tmp/out.png")

Usage as CLI (reads hex from stdin or filename):

    python celestial_render.py /path/to/inscription.hex
    python celestial_render.py --header c1dd0001ce... --body ...
    cat header_body.hex | python celestial_render.py -

Hex-file format: one hex blob per file, either
    HEADER_HEX BODY_HEX           (space-separated)
or
    HEADER_HEX\\nBODY_HEX          (newline-separated)
or
    HEADER_BODY_HEX                (concatenated — header length recovered
                                    from the type and title-length bytes)
"""

from __future__ import annotations

import argparse
import os
import sys

# Allow being run from anywhere by import-pathing the local celestial module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from celestial import read_celestial_quipu, KIND_STAR, KIND_EARTH


# ---------------------------------------------------------------------------
# Default style
# ---------------------------------------------------------------------------

DEFAULT_STYLE_STAR = {
    "bg":              "#0c1226",
    "axis_color":      "#9aa6c0",
    "spine_color":     "#27314d",
    "grid_color":      "#1c2545",
    "line_color":      "#7a8aa8",
    "line_width":      0.8,
    "line_alpha":      0.85,
    "point_color":     "#dbe4f4",
    "point_edge":      "white",
    "point_size":      40,
    "label_color":     "#dbe4f4",
    "label_fontsize":  7,
    "title_color":     "#dbe4f4",
    "title_fontsize":  10,
    "figsize":         (12, 9),
    "dpi":             150,
}

DEFAULT_STYLE_EARTH = {
    **DEFAULT_STYLE_STAR,
    "bg":              "#f4f1e8",
    "axis_color":      "#3a3525",
    "spine_color":     "#a89a72",
    "grid_color":      "#d4cdb0",
    "line_color":      "#6b5d3f",
    "point_color":     "#3a3525",
    "point_edge":      "#1a1810",
    "label_color":     "#1a1810",
    "title_color":     "#1a1810",
}


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

def render_celestial_quipu(
    header_bytes,
    body_bytes,
    output_path=None,
    style=None,
    label_overrides=None,
    point_colors=None,
    show_pleiades_halo=False,
):
    """Render a celestial quipu's bytes to a matplotlib figure.

    Args:
        header_bytes, body_bytes: the (header, body) pair from build_celestial_quipu
            or read off-chain from a quipu inscription's diamond.
        output_path: if given, the figure is saved here as PNG.
        style: dict overriding any keys in DEFAULT_STYLE_STAR / DEFAULT_STYLE_EARTH.
        label_overrides: dict mapping point name -> (dx, dy, ha, va) tuple
            for custom label placement. Coords are matplotlib annotate-style
            offsets in points (pixels at default DPI).
        point_colors: dict mapping point name -> matplotlib color string,
            for per-point coloring beyond the default monochrome.
        show_pleiades_halo: if True and any point named "Alcyone" is in the
            inscription, draw an ellipse around the cluster centroid of
            stars whose names match the canonical seven-sisters set.

    Returns:
        (fig, ax) matplotlib Figure/Axes pair.
    """
    import matplotlib
    if output_path is not None:
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    parsed = read_celestial_quipu(header_bytes, body_bytes)
    title  = parsed["title"]
    kind   = parsed["kind"]
    points = parsed["points"]
    lines  = parsed["lines"]
    groups = parsed.get("groups")

    # If the inscription is grouped (0xcf), build per-group color maps so
    # each constellation reads distinctly and gets a legend entry.
    group_line_color = {}     # line_key (sorted index pair) -> color
    group_point_color = {}    # point name -> color
    group_legend = []         # [(group name, color)]
    if groups:
        # Distinct palette — extend if you have > 12 groups
        palette = [
            '#ffd84a', '#7fb8ff', '#73d0a4', '#f5b5d8',
            '#d8b48a', '#c08ad1', '#e6c068', '#f0d090',
            '#e0594a', '#9adfe0', '#b3a5d6', '#f3a36c',
        ]
        for gi, g in enumerate(groups):
            col = palette[gi % len(palette)]
            group_legend.append((g["name"], col))
            for idx in g["point_indices"]:
                group_point_color[points[idx]["name"]] = col
            for a, b in g["lines"]:
                key = tuple(sorted([a, b]))
                group_line_color[key] = col

    if kind == "earth":
        st = dict(DEFAULT_STYLE_EARTH)
    else:
        st = dict(DEFAULT_STYLE_STAR)
    if style:
        st.update(style)

    label_overrides = label_overrides or {}
    point_colors    = point_colors or {}

    # Coordinate accessors for the three kinds
    def coords(pt):
        if pt["kind"] == "star":
            return pt["ra"], pt["dec"]
        else:
            return pt["lng"], pt["lat"]  # earth: longitude X, latitude Y

    fig, ax = plt.subplots(figsize=st["figsize"], facecolor=st["bg"])
    ax.set_facecolor(st["bg"])

    # Lines first (so points draw on top). Use per-group color if present.
    # For timed earth figures, draw lines as chronological arrows (earlier→later)
    # when both endpoints carry a 'time' field.
    from matplotlib.patches import FancyArrowPatch
    for a_idx, b_idx in lines:
        pa, pb = points[a_idx], points[b_idx]
        xa, ya = coords(pa)
        xb, yb = coords(pb)
        key = tuple(sorted([a_idx, b_idx]))
        col = group_line_color.get(key, st["line_color"])
        is_timed_journey = (
            kind == "earth"
            and "time" in pa and pa["time"] is not None
            and "time" in pb and pb["time"] is not None
        )
        if is_timed_journey:
            # Arrow from earlier to later (handles forward and backward indexing)
            if pa["time"] <= pb["time"]:
                src, dst = (xa, ya), (xb, yb)
            else:
                src, dst = (xb, yb), (xa, ya)
            ax.add_patch(FancyArrowPatch(
                src, dst,
                arrowstyle='-|>', mutation_scale=10,
                color=col, lw=st["line_width"],
                alpha=st["line_alpha"], zorder=1,
            ))
        else:
            ax.plot([xa, xb], [ya, yb],
                    color=col, lw=st["line_width"],
                    alpha=st["line_alpha"], zorder=1)

    # Optional Pleiades halo (only triggers if names match)
    if show_pleiades_halo and kind == "star":
        ple_names = {'Alcyone','Atlas','Pleione','Electra','Maia','Merope','Taygeta'}
        ple_pts = [pt for pt in points if pt["name"] in ple_names]
        if len(ple_pts) >= 5:
            from matplotlib.patches import Ellipse
            cx = sum(pt["ra"]  for pt in ple_pts) / len(ple_pts)
            cy = sum(pt["dec"] for pt in ple_pts) / len(ple_pts)
            ax.add_patch(Ellipse((cx, cy), width=3.5, height=2.5,
                                 facecolor='#f5b5d8', alpha=0.15,
                                 edgecolor='#f5b5d8', lw=1.2, zorder=1))
            ax.add_patch(Ellipse((cx, cy), width=3.5, height=2.5,
                                 facecolor='none', alpha=0.7,
                                 edgecolor='#f5b5d8', lw=1.0, ls=':', zorder=2))

    # Points + labels. Priority: user-supplied point_colors > group color > default.
    for pt in points:
        x, y = coords(pt)
        marker = "o"
        color  = (point_colors.get(pt["name"])
                  or group_point_color.get(pt["name"])
                  or st["point_color"])
        ax.scatter(x, y,
                   s=st["point_size"],
                   color=color,
                   edgecolor=st["point_edge"],
                   lw=0.4,
                   marker=marker,
                   zorder=3)
        dx, dy, ha, va = label_overrides.get(pt["name"], (5, 5, "left", "bottom"))
        ax.annotate(pt["name"], (x, y),
                    xytext=(dx, dy), textcoords="offset points",
                    color=st["label_color"], fontsize=st["label_fontsize"],
                    ha=ha, va=va, zorder=4)

    # Axes
    if kind == "earth":
        ax.set_xlabel("Longitude (°)", color=st["axis_color"])
        ax.set_ylabel("Latitude (°)",  color=st["axis_color"])
    else:
        ax.set_xlabel("Right Ascension (°)", color=st["axis_color"])
        ax.set_ylabel("Declination (°)",     color=st["axis_color"])
        ax.invert_xaxis()  # RA decreases left-to-right by chart convention

    ax.tick_params(colors=st["axis_color"])
    for spine in ax.spines.values():
        spine.set_color(st["spine_color"])
    ax.grid(True, color=st["grid_color"], lw=0.4, alpha=0.6)

    tone_label = {0x00: "ordinary", 0x0d: "demonic", 0xff: "reverence"}.get(
        parsed["tone"], f"0x{parsed['tone']:02x}")
    ax.set_title(f"{title}\n"
                 f"{len(points)} points · {len(lines)} lines · "
                 f"kind={kind} · tone={tone_label}",
                 color=st["title_color"], fontsize=st["title_fontsize"])

    # On-chain legend (from groups block, if present)
    if group_legend:
        from matplotlib.lines import Line2D
        handles = [Line2D([0],[0], marker='o', ls='', color=col, label=name)
                   for (name, col) in group_legend]
        ax.legend(handles=handles, loc='lower left',
                  facecolor=st["bg"], edgecolor=st["spine_color"],
                  labelcolor=st["label_color"], fontsize=st["label_fontsize"]+1)

    fig.tight_layout()

    if output_path is not None:
        fig.savefig(output_path, dpi=st["dpi"], facecolor=st["bg"])
        print(f"wrote {output_path}", file=sys.stderr)

    return fig, ax


# ---------------------------------------------------------------------------
# Header-length recovery (for concatenated-hex inputs)
# ---------------------------------------------------------------------------

def _split_concat(blob_bytes):
    """Split a concatenated (header || body) byte blob using the on-chain
    header layout (v1, May 2026 redesign):
        4-byte magic + type + tone + kind + grouped + meta +
        2-byte K (uint16 BE) + title-length byte T + T bytes title.
    """
    if blob_bytes[:4] != b"\xc1\xdd\x00\x01":
        raise ValueError("not a quipu (c1dd0001 magic missing)")
    if blob_bytes[4] != 0xCE:
        raise ValueError(
            f"not a celestial quipu (type byte = {blob_bytes[4]:#04x}, "
            f"expected 0xce)"
        )
    if len(blob_bytes) < 12:
        raise ValueError("blob too short to contain a celestial header")
    T = blob_bytes[11]
    header_len = 12 + T
    return blob_bytes[:header_len], blob_bytes[header_len:]


def _decode_hex(s):
    """Strip whitespace from a hex string and return bytes; raise on bad hex."""
    cleaned = "".join(c for c in s if c not in " \t\r\n")
    if len(cleaned) % 2 != 0:
        raise ValueError("odd-length hex string")
    return bytes.fromhex(cleaned)


def _load_input(arg):
    """Accept a filename, a literal '-' for stdin, or a hex string.

    File / stdin contents can be:
      - 'HEADER_HEX BODY_HEX'    (space- or newline-separated)
      - 'HEADER||BODY' concatenated single hex blob

    Returns (header_bytes, body_bytes).
    """
    if arg == "-":
        text = sys.stdin.read()
    elif os.path.isfile(arg):
        with open(arg) as f:
            text = f.read()
    else:
        text = arg  # treat as inline hex

    tokens = text.strip().split()
    if len(tokens) == 2:
        return _decode_hex(tokens[0]), _decode_hex(tokens[1])
    if len(tokens) == 1:
        return _split_concat(_decode_hex(tokens[0]))
    raise ValueError(
        f"expected 1 or 2 hex tokens, got {len(tokens)} "
        f"(separate header and body with whitespace, or concatenate)"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main():
    ap = argparse.ArgumentParser(
        description="Render a 0xce celestial-figure quipu from its bytes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("input", nargs="?",
                    help="hex file path, '-' for stdin, or inline hex. "
                         "Required unless --header AND --body are passed.")
    ap.add_argument("--header", help="header hex (use with --body)")
    ap.add_argument("--body",   help="body hex (use with --header)")
    ap.add_argument("--output", "-o", default="celestial_render.png",
                    help="output PNG path (default: celestial_render.png)")
    ap.add_argument("--pleiades-halo", action="store_true",
                    help="draw a halo around the seven-sisters cluster if "
                         "the inscription contains them by name")
    args = ap.parse_args()

    if args.header and args.body:
        header_bytes = _decode_hex(args.header)
        body_bytes   = _decode_hex(args.body)
    elif args.input:
        header_bytes, body_bytes = _load_input(args.input)
    else:
        ap.error("provide an input file/hex, '-' for stdin, or both --header and --body")

    fig, _ax = render_celestial_quipu(
        header_bytes, body_bytes,
        output_path=args.output,
        show_pleiades_halo=args.pleiades_halo,
    )

    # Print a one-line summary to stdout
    parsed = read_celestial_quipu(header_bytes, body_bytes)
    print(f"title:  {parsed['title']!r}")
    _tones = {0x00: 'ordinary', 0x0d: 'demonic', 0xff: 'reverence'}
    print(f"kind:   {parsed['kind']}   tone: "
          f"{_tones.get(parsed['tone'], f'0x{parsed[\"tone\"]:02x}')}")
    print(f"points: {len(parsed['points'])}   lines: {len(parsed['lines'])}")
    print(f"output: {args.output}")


if __name__ == "__main__":
    _main()
