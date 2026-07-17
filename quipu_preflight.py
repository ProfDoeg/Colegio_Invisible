#!/usr/bin/env python3
"""quipu_preflight — final checks between signing and broadcasting.

Born from the Dantean Cosmos phantom (2026-06-10): every existing check
verified BYTE fidelity — strands reassemble to the body — and the body
round-tripped perfectly, carrying an unresolved stand-in txid onto the
chain. sha256("0xce Bode Uranographia full sky") is now permanently the
orrery's fixed-stars ref. The round-trip was true; it was the wrong
question. The right questions, asked here:

  1. WHAT WILL THE CHAIN STORE — re-extract every OP_RETURN payload from
     the SIGNED TRANSACTION HEX (not from the build's memory), reassemble
     each body, and compare to the body files. Trust nothing upstream.
  2. DOES IT DECODE — every reassembled body must parse through its
     canonical reader (split + magic + type dispatch). A body that
     decodes today will decode from the chain.
  3. DO THE REFERENCES RESOLVE — every 64-hex token in every body must be
     (a) a root of this very diamond, (b) a known on-chain txid (dataset,
     bodies mirror, or live resolver), or (c) EXPLICITLY DECLARED by the
     caller (hash certs legitimately carry non-txid SHA256s; a 0xab
     alias's left-hand names are deliberately dangling). Default-deny:
     an undeclared unknown token fails the flight. This is the check
     that would have caught the phantom.

Wired into quipu_diamond.broadcast_consolidated_diamond — broadcasting
runs the flight first and refuses on failure. Run it standalone any
time:

    .venv/bin/python quipu_preflight.py working/<stage>/artifacts
"""
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "canonical"))

HEX64 = re.compile(rb"[0-9a-fA-F]{64}")


class PreflightError(Exception):
    """The diamond must not fly. Message lists every failure."""


# ---------------------------------------------------------------------------
#  what the chain will store — OP_RETURN extraction from signed hex
# ---------------------------------------------------------------------------
def op_return_payload(tx_hex):
    """The OP_RETURN payload bytes of a signed tx (None if it has none)."""
    from cryptos import deserialize
    for out in deserialize(tx_hex).get("outs", []):
        script = bytes.fromhex(out.get("script", ""))
        if not script or script[0] != 0x6A:
            continue
        if len(script) >= 2 and script[1] == 0x4C:          # OP_PUSHDATA1
            n = script[2]
            return script[3:3 + n]
        n = script[1]                                       # direct push
        return script[2:2 + n]
    return None


def reassemble_body(artifacts_dir, pid, n_strands):
    """Concatenate the OP_RETURN payloads of every signed strand tx, in
    strand order — byte-for-byte what a chain reader will reconstruct."""
    out = bytearray()
    for i in range(n_strands):
        path = os.path.join(artifacts_dir, "strand_%s_%d.txns" % (pid, i))
        for tx_hex in open(path).read().splitlines():
            p = op_return_payload(tx_hex)
            if p is None:
                raise PreflightError("%s strand %d: knot tx with no OP_RETURN" % (pid, i))
            out += p
    return bytes(out)


# ---------------------------------------------------------------------------
#  reference extraction — generic sweep + type-aware exemptions
# ---------------------------------------------------------------------------
def extract_refs(blob):
    """Every 64-hex token in a body (ASCII form — citations, quipu_refs,
    binding lines, header fields). Lowercased, deduplicated."""
    return {m.group(0).decode().lower() for m in HEX64.finditer(blob)}


def alias_lhs_tokens(blob):
    """For a 0xab binding body: the LEFT-hand tokens of alias chains —
    names being DEFINED, deliberately allowed to dangle (that is the whole
    point of a healing alias). Only the chain's final target must resolve."""
    if len(blob) < 5 or blob[4] != 0xAB:
        return set()
    out = set()
    for line in blob.split(b"\n"):
        parts = [p.strip() for p in line.strip().split(b"=")]
        if len(parts) < 2:
            continue
        toks = [HEX64.search(p) for p in parts]
        if all(toks):                       # an alias chain of <<hex>> terms
            for m in toks[:-1]:             # all but the final target
                out.add(m.group(0).decode().lower())
    return out


def default_known_txids():
    """Txids the corpus already knows: the dataset (roots + joins) and the
    local body mirror. A live-RPC resolver can supplement via `resolver`."""
    known = set()
    csv = os.path.join(_HERE, "data", "quipu_data.csv")
    if os.path.exists(csv):
        import pandas as pd
        df = pd.read_csv(csv)
        for col in ("root_txid", "join_txid"):
            if col in df:
                known |= {str(t).lower() for t in df[col].dropna()}
    bodies = os.path.join(_HERE, "data", "bodies")
    if os.path.isdir(bodies):
        known |= {f[:-4].lower() for f in os.listdir(bodies) if f.endswith(".bin")}
    return known


# ---------------------------------------------------------------------------
#  the flight
# ---------------------------------------------------------------------------
def check_refs_resolve(bodies_by_pid, diamond_roots, *, declared_ok=(),
                       known_txids=None, resolver=None):
    """The phantom check. Returns a list of failure strings (empty = pass)."""
    known = set(known_txids) if known_txids is not None else default_known_txids()
    known |= {r.lower() for r in diamond_roots}
    ok = {d.lower() for d in declared_ok}
    failures = []
    for pid, blob in bodies_by_pid.items():
        exempt = alias_lhs_tokens(blob)
        for ref in sorted(extract_refs(blob)):
            if ref in known or ref in ok or ref in exempt:
                continue
            if resolver is not None:
                try:
                    if resolver(ref):
                        known.add(ref)
                        continue
                except Exception:               # noqa: BLE001
                    pass
            failures.append(
                "%s: unresolved 64-hex token %s… — not a diamond root, not a "
                "known txid, not declared. An undeclared stand-in dies here, "
                "not on the chain." % (pid, ref[:16]))
    return failures


def check_ref_graph(bodies_by_pid, expected, roots_by_pid=None):
    """The ZERO-ERRATA gate (demanded for the Book of 108): the reference
    graph must EQUAL the declared one — not merely resolve. A swapped pair
    of refs is two real, resolvable, decodable txids in the wrong places;
    only graph equality catches it.

    expected: {pid: iterable of refs} — each ref a 64-hex string or
    another pid (translated via roots_by_pid). DEFAULT-DENY: every piece
    must be declared, even with an empty set. Returns failure strings."""
    roots_by_pid = {k: v.lower() for k, v in (roots_by_pid or {}).items()}
    failures = []
    for pid, blob in bodies_by_pid.items():
        if pid not in expected:
            failures.append("%s: no declared reference set — every piece "
                            "declares, even 'no refs'" % pid)
            continue
        exp = set()
        for r in expected[pid]:
            r = str(r)
            exp.add(roots_by_pid.get(r, r.lower()))
        found = extract_refs(blob)
        for ref in sorted(exp - found):
            failures.append("%s: DECLARED ref %s… is absent from the body"
                            % (pid, ref[:16]))
        for ref in sorted(found - exp):
            failures.append("%s: UNDECLARED ref %s… present in the body "
                            "(wrong/swapped refs die here)" % (pid, ref[:16]))
    return failures


def galley_hash(artifacts_dir):
    """SHA256 over the index-ordered bodies REASSEMBLED FROM THE SIGNED
    TXS — a fingerprint of exactly what the chain will store."""
    import hashlib
    idx = json.load(open(os.path.join(artifacts_dir, "index.json")))
    h = hashlib.sha256()
    for piece in idx["pieces"]:
        h.update(piece["pid"].encode())
        h.update(reassemble_body(artifacts_dir, piece["pid"], piece["n_strands"]))
    return h.hexdigest()


def approve_galley(artifacts_dir, approver, note=""):
    """Record the human sign-off, bound to the artifact bytes: the galley
    that was proofread IS the inscription, cryptographically. Broadcast
    with require_approval=True refuses without a matching seal."""
    seal = {"galley_sha256": galley_hash(artifacts_dir),
            "approver": approver, "note": note}
    with open(os.path.join(artifacts_dir, "approval.json"), "w") as f:
        json.dump(seal, f, indent=2)
    return seal


def check_approval(artifacts_dir):
    """Failure strings if the approval seal is missing or stale."""
    path = os.path.join(artifacts_dir, "approval.json")
    if not os.path.exists(path):
        return ["no approval.json — the galley was never signed off "
                "(quipu_preflight.approve_galley after proofreading)"]
    seal = json.load(open(path))
    now = galley_hash(artifacts_dir)
    if seal.get("galley_sha256") != now:
        return ["approval is STALE: artifacts changed after sign-off "
                "(sealed %s…, now %s…) — re-proof and re-approve"
                % (str(seal.get("galley_sha256"))[:12], now[:12])]
    return []


def check_decodes(bodies_by_pid):
    """Every body must split + parse through its canonical reader."""
    import colegio_pipeline as P
    import importlib
    READERS = {0x00: ("text", "read_text_quipu"), 0x01: ("essay", "read_essay_quipu"),
               0x03: ("image", "read_image_quipu"), 0x07: ("sound", "read_sound_quipu"),
               0x09: ("book", "read_book_quipu"), 0x0E: ("encrypted", "read_encrypted_quipu"),
               0x0F: ("file", "read_file_quipu"), 0x3D: ("scene", "read_scene_quipu"),
               0x5C: ("latex", "read_latex_quipu"), 0xAB: ("bindings", "read_binding_quipu"),
               0xCC: ("cert", "read_cert"), 0xCE: ("celestial", "read_celestial_quipu"),
               0xDA: ("dancer", "read_dancer"), 0xEE: ("estandarte", "read_estandarte_quipu")}
    failures = []
    for pid, blob in bodies_by_pid.items():
        try:
            # The estandarte rides the version-aware envelope (2-byte magic
            # c1dd; bytes 2-3 are the version, so the constitution is
            # c1dd0000 — the literal-0001 check below would reject it).
            # Flat 6-byte header, no split needed; the inscription-form
            # gate also runs: legislation must ride the constitution
            # (docs/design/healing.md).
            if len(blob) >= 6 and blob[:2] == b"\xc1\xdd" and blob[4] == 0xEE:
                import registry_v1
                registry_v1.preflight_inscription_form(blob[:6], blob[6:])
                continue
            if blob[:4] != b"\xc1\xdd\x00\x01":
                raise ValueError("magic missing")
            t = blob[4]
            if t not in READERS:
                raise ValueError("unknown type byte %#04x" % t)
            header, body = P.split_blob(blob)
            mod, fn = READERS[t]
            getattr(importlib.import_module(mod), fn)(header, body)
        except Exception as e:                  # noqa: BLE001
            failures.append("%s: body does not decode: %s" % (pid, e))
    return failures


def check_ripcord(parent_root_tx, parent_n_strands,
                  successor_root_tx, successor_n_strands,
                  successor_blob=None):
    """The two-pointer ripcord gate (docs/design/healing.md; the ripcord
    convention in the constitutional estandarte): a successor registry's
    root must consume its parent's amendment cord, and thread and text
    must agree. Engine convention: tags sit at vout = n_strands + k, so
    the ripcord — the FIRST non-strand output — is vout n_strands.

    parent_root_tx / successor_root_tx   raw hex or deserialized dict
    parent_n_strands / successor_n_strands   strand counts (index.json)
    successor_blob   optional header+body bytes: parses as an estandarte
                     (inscription form: legislation rides the constitution)
                     and its parent_txid must name the parent root.

    Returns failure strings; empty list = the cord may be pulled."""
    from cryptos import serialize as _ser, deserialize as _deser
    from colegio_tools import _txid_of_serial
    failures = []
    parent = _deser(parent_root_tx) if isinstance(parent_root_tx, str) else parent_root_tx
    succ = _deser(successor_root_tx) if isinstance(successor_root_tx, str) else successor_root_tx
    parent_txid = _txid_of_serial(_ser(parent))

    if len(parent["outs"]) <= parent_n_strands:
        failures.append("parent root has no cord: %d outputs, %d strands — "
                        "the ripcord must be output %d"
                        % (len(parent["outs"]), parent_n_strands, parent_n_strands))
    if any(o.get("script", "").startswith("6a") for o in succ.get("outs", [])):
        failures.append("successor root carries an OP_RETURN — a cord spend "
                        "is an act, not writing; roots never carry payload")
    if not succ.get("ins"):
        failures.append("successor root has no inputs")
    else:
        in0 = succ["ins"][0]
        spent = (in0.get("tx_hash"), in0.get("tx_pos"))
        if spent != (parent_txid, parent_n_strands):
            failures.append("successor input 0 spends %s:%s, not the parent's "
                            "cord %s:%d — the thread must be input 0"
                            % (str(spent[0])[:12], spent[1],
                               parent_txid[:12], parent_n_strands))
    if len(succ.get("outs", [])) <= successor_n_strands:
        failures.append("successor root emits no fresh cord: %d outputs, %d "
                        "strands — every registry root must re-arm the ripcord"
                        % (len(succ.get("outs", [])), successor_n_strands))

    if successor_blob is not None:
        import registry_v1
        try:
            parsed = registry_v1.preflight_inscription_form(
                successor_blob[:6], successor_blob[6:])
        except Exception as e:                      # noqa: BLE001
            failures.append("successor blob fails inscription form: %s" % e)
        else:
            if parsed["parent_txid"] != parent_txid:
                failures.append("thread/text disagree: cord spent from %s… but "
                                "body parent_txid = %s… — the two pointers "
                                "must name the same root"
                                % (parent_txid[:12],
                                   str(parsed["parent_txid"])[:12]))
    return failures


def preflight(artifacts_dir, *, declared_ok=(), known_txids=None,
              resolver=None, expected_refs=None, require_approval=False,
              log=print):
    """Run the full flight on a built diamond's artifacts. Raises
    PreflightError listing EVERY failure; returns a summary dict on pass.

    expected_refs     {pid: refs} — enables the zero-errata graph-equality
                      gate (refs as 64-hex or pids). For cathedral-scale
                      inscriptions this is mandatory discipline.
    require_approval  refuse without a galley seal (approve_galley) whose
                      hash matches the artifacts as they are NOW."""
    idx = json.load(open(os.path.join(artifacts_dir, "index.json")))
    failures, bodies = [], {}
    roots, roots_by_pid = [], {}
    for piece in idx["pieces"]:
        pid, n = piece["pid"], piece["n_strands"]
        roots.append(piece["root"])
        roots_by_pid[pid] = piece["root"]
        disk = open(os.path.join(artifacts_dir, "%s.bin" % pid), "rb").read()
        from_txs = reassemble_body(artifacts_dir, pid, n)
        if from_txs != disk:
            failures.append("%s: signed-tx payloads != body file "
                            "(%d vs %d bytes)" % (pid, len(from_txs), len(disk)))
        bodies[pid] = from_txs                  # judge what the CHAIN gets

    failures += check_decodes(bodies)
    failures += check_refs_resolve(bodies, roots, declared_ok=declared_ok,
                                   known_txids=known_txids, resolver=resolver)
    if expected_refs is not None:
        failures += check_ref_graph(bodies, expected_refs, roots_by_pid)
    if require_approval:
        failures += check_approval(artifacts_dir)
    if failures:
        raise PreflightError(
            "PREFLIGHT FAILED — %d problem(s):\n  " % len(failures)
            + "\n  ".join(failures))
    summary = {"pieces": len(bodies), "knots": idx.get("total_knots"),
               "refs_checked": sum(len(extract_refs(b)) for b in bodies.values())}
    log("preflight PASSED: %(pieces)d pieces, %(knots)s knots, "
        "%(refs_checked)d refs all resolve" % summary)
    return summary


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)
    try:
        preflight(sys.argv[1], declared_ok=sys.argv[2:])
    except PreflightError as e:
        print(str(e))
        sys.exit(1)
