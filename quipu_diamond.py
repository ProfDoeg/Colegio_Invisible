#!/usr/bin/env python3
"""Canonical CONSOLIDATED-DIAMOND inscription — build (sign) + broadcast.

A consolidated diamond inscribes MANY quipus on one funding tree:

    one funder UTXO
      -> splitter          (1 in  -> P outs, one per piece-root)
      -> P per-quipu roots (1 in  -> 1+N outs: header strand + body strands)
      -> all strands       (CadenaAtom chains; header = strand 0 / cabeza,
                            body = strands 1..N, each <= CAP knots)
      -> mega-join         (Sigma strand-termini in -> 1 out, residual to funder)

Read back by read_quipu (colegio_tools): root:0 = header, root:1..N = body. So a
piece's bytes are split with colegio_pipeline.split_blob into (header, body), the
header becomes strand 0, and the body is cut into contiguous <=CAP-knot strands.

CROSS-REFERENCES (even cycles): a root txid is a function of a body's KNOT COUNT
(size), not its content, and a txid reference is fixed length. So: build every
piece with PLACEHOLDER refs (right sizes) -> compute all P roots at once -> back-
fill the real root txids into the referencing bodies (no size changes anywhere)
-> precompute strands -> mega-join. No build order, no cycle-breaking.

FEES — the whole point of canonizing this: every transaction pays
`FeePolicy.rate_kb` DOGE per kilobyte of its ACTUAL serialized size (measured by
signing a same-shape dummy, not guessed), floored at `FeePolicy.floor_doge`.
This is the lesson from the first forest: a flat-priced 32 KB mega-join worked
out to 0.0084 DOGE/KB and sat unmined for many blocks while size-capping miners
took smaller, higher-rate txs. The join is NOT replace-by-fee, so it must be
priced correctly the FIRST time. Size-pricing it (~0.10 DOGE/KB -> ~3 DOGE for a
32 KB join) makes it confirm in the next block. Knots, splitter, and every root
are priced the same way, by their own size.

Usage — SIGN (touches the key; the caller runs it):
    from quipu_diamond import FeePolicy, build_consolidated_diamond
    art = build_consolidated_diamond(pieces, placeholder_of, utxo, priv, addr, FeePolicy())
    write_artifacts(art, "working/<stage>/artifacts")

Usage — BROADCAST (keyless, resumable):
    from quipu_diamond import broadcast_consolidated_diamond
    broadcast_consolidated_diamond("working/<stage>/artifacts")

See docs/guides/consolidated-diamond.md for the full recipe.
"""
import os, sys, math, json, time, binascii, threading
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import fast_signing  # noqa: F401 — applies coincurve monkeypatch; QUIPU_SLOW_SIGN=1 to bypass
import cryptos
from cryptos import serialize as cs_serialize
from colegio_tools import CadenaAtom, _txid_of_serial, MEMPOOL_ANCESTOR_LIMIT
import colegio_pipeline as _P
import quipu_broadcast as _qb

DUST_FLOOR_SAT = 1_000_000          # keep the residual comfortably above dust
STRAND_CAP     = 24                 # knots per strand (< mempool ancestor limit 25)


# ===========================================================================
#  FEE POLICY — always the appropriate amount, by actual size
# ===========================================================================
class FeePolicy:
    """One rate for everything, applied to each tx's real serialized size.

    rate_kb     DOGE per kilobyte (default 0.10 — comfortably above the observed
                ~0.01-0.02 DOGE/KB miner inclusion floor and ~100x node relayfee,
                so every tx, including a big mega-join, confirms in a normal block
                without overpaying).
    floor_doge  minimum fee per tx (covers tiny txs / relay).
    margin      safety multiplier over measured size (covers per-input signature
                length variance so the paid rate is never *below* rate_kb).
    knot_tx_bytes  representative size of one OP_RETURN knot tx (calibrate once;
                ~280 B for an 80-byte payload).
    """
    def __init__(self, rate_kb=0.10, floor_doge=0.01, margin=1.02, knot_tx_bytes=315):
        self.rate_kb = float(rate_kb)
        self.floor_sat = int(round(floor_doge * 1e8))
        self.margin = float(margin)
        self.knot_tx_bytes = int(knot_tx_bytes)

    def fee_for_bytes(self, nbytes):
        sat = math.ceil(self.rate_kb * nbytes * self.margin / 1000.0 * 1e8)
        return max(self.floor_sat, int(sat))

    def knot_tip_sat(self):
        return self.fee_for_bytes(self.knot_tx_bytes)

    def describe(self):
        return ("FeePolicy %.3f DOGE/KB (margin %.2f, floor %.4f DOGE); "
                "knot tip %.4f DOGE @ %dB"
                % (self.rate_kb, self.margin, self.floor_sat / 1e8,
                   self.knot_tip_sat() / 1e8, self.knot_tx_bytes))


def doge(sat):
    return f"{sat/1e8:.8f} DOGE"


# ===========================================================================
#  STRAND SPLITTING — header = strand 0, body = strands 1..N
# ===========================================================================
def knot_count(payload):
    return math.ceil(len(payload) / 80) if payload else 1


def split_body(body, n_strands, knot_size=80):
    """Body -> n_strands contiguous knot ranges (modulo-balanced). Reader-side
    naive concatenation in strand order reconstructs the body."""
    if n_strands <= 1:
        return [body]
    total = math.ceil(len(body) / knot_size)
    base, extra = divmod(total, n_strands)
    out, ki = [], 0
    for i in range(n_strands):
        k = base + (1 if i < extra else 0)
        start = ki * knot_size
        end = (ki + k) * knot_size if i < n_strands - 1 else len(body)
        out.append(body[start:end]); ki += k
    assert b"".join(out) == body, "split lost or duplicated bytes"
    return out


def split_quipu(blob, cap=STRAND_CAP):
    """Full quipu blob -> [header, body0, body1, ...] (header = strand 0)."""
    header, body = _P.split_blob(blob)
    assert header + body == blob, "split_blob round-trip failed"
    n_body = max(1, math.ceil(knot_count(body) / cap))
    return [header] + split_body(body, n_body)


# ===========================================================================
#  SIZE MEASUREMENT — sign a same-shape dummy to get the real serialized size
# ===========================================================================
def _measure_tx_size(n_in, n_out, priv, address, dogecs):
    """Serialized byte size of a signed P2PKH tx with this shape (values don't
    affect size; signature length does, hence we actually sign)."""
    ins = [{"output": "%064x:%d" % (1, k), "value": 10 ** 14} for k in range(n_in)]
    per = 10 ** 14 // (n_out + 1)
    outs = [{"value": per, "address": address} for _ in range(n_out)]
    signed = dogecs.signall(dogecs.mktx(ins, outs), priv)
    return len(cs_serialize(signed)) // 2


# ===========================================================================
#  BUILD (SIGN) — returns artifacts; spends nothing
# ===========================================================================
def build_consolidated_diamond(pieces, placeholder_of, utxo, priv, address,
                               fee_policy=None, cap=STRAND_CAP,
                               extra_placeholders=None, tags_of=None,
                               declared_ok=None, known_txids=None, log=print):
    """Build + sign a consolidated diamond. Deterministic; broadcasts nothing.

    pieces            ordered list of (pid, full_quipu_blob_bytes). Order fixes
                      the splitter output index of each piece's root.
    placeholder_of    pid -> 64-hex placeholder txid embedded in bodies for that
                      piece (must match what the bodies actually contain).
    utxo              {"output": "txid:vout", "value": sat} at `address`.
    priv              funder private key hex (no 0x); MUST derive `address`.
    fee_policy        FeePolicy (default FeePolicy()).
    extra_placeholders  optional {placeholder_hex: target_pid} for non-pid aliases
                      (e.g. a body's internal cross-reference to another piece).
    declared_ok       optional iterable of 64-hex strings that are LEGITIMATELY
                      not txids (payload hashes in certs, lock hashes...).
                      Every other unknown 64-hex token in a final body FAILS
                      the build — see step 5b (the phantom check).
    tags_of           optional pid -> [{"value": sat, "address": str}, ...].
                      Each tag becomes an EXTRA output of that piece's root,
                      placed AFTER the strand seeds (vout = n_strands + k), with
                      the given scriptPubKey (P2PKH or P2SH address) and value.
                      Tags seed no OP_RETURN chain and are NOT consumed by the
                      mega-join — they sit unspent after inscription, dangling
                      off the textile (see docs/design/tag-architecture.md).
                      Tag values are spent out of the funder UTXO like fees.

    Returns a dict of artifacts (see write_artifacts).
    """
    fp = fee_policy or FeePolicy()
    dogecs = cryptos.Doge()
    assert dogecs.privtoaddr(priv) == address, "key does not derive the funder address"
    total_in = utxo["value"]
    tags_of = tags_of or {}
    for pid, tags in tags_of.items():
        assert pid in dict(pieces), "tags_of names unknown piece %r" % pid
        for t in tags:
            assert t["value"] >= 100_000, "tag %r below dust (0.001 DOGE)" % t

    # 1. split every piece (header = strand 0)
    quip = {}
    for pid, blob in pieces:
        strands = split_quipu(blob, cap)
        quip[pid] = {"blob": blob, "strands": strands,
                     "knots": [knot_count(s) for s in strands]}
    total_strands = sum(len(q["strands"]) for q in quip.values())
    total_knots = sum(sum(q["knots"]) for q in quip.values())
    P = len(pieces)
    log("%d pieces, %d strands, %d knots" % (P, total_strands, total_knots))

    # 2. fees — every structural tx priced by its measured size
    knot_tip = fp.knot_tip_sat()
    split_size = _measure_tx_size(1, P, priv, address, dogecs)
    join_size = _measure_tx_size(total_strands, 1, priv, address, dogecs)
    split_fee = fp.fee_for_bytes(split_size)
    join_fee = fp.fee_for_bytes(join_size)
    root_fee, tag_sat = {}, {}
    for pid, q in quip.items():
        tags = tags_of.get(pid, [])
        tag_sat[pid] = sum(t["value"] for t in tags)
        root_fee[pid] = fp.fee_for_bytes(
            _measure_tx_size(1, len(q["strands"]) + len(tags), priv, address, dogecs))
    strand_fees = total_knots * knot_tip
    total_root_fees = sum(root_fee.values())
    total_tag_sat = sum(tag_sat.values())
    log(fp.describe())
    log("  splitter %s (%dB) · roots Σ%s · join %s (%dB) · knots %s (%d×%s)"
        % (doge(split_fee), split_size, doge(total_root_fees),
           doge(join_fee), join_size, doge(strand_fees), total_knots, doge(knot_tip)))
    if total_tag_sat:
        log("  tags %s across %d outputs (left unspent, excluded from the join)"
            % (doge(total_tag_sat), sum(len(v) for v in tags_of.values())))

    final_out = total_in - split_fee - total_root_fees - strand_fees - join_fee - total_tag_sat
    if final_out < DUST_FLOOR_SAT:
        need = total_in - final_out + DUST_FLOOR_SAT
        raise ValueError("insufficient funds: have %s, need >= %s" % (doge(total_in), doge(need)))

    # 3. distribute (join_fee + residual) across all strand terminals
    total_terminals = join_fee + final_out
    base_term, remainder = divmod(total_terminals, total_strands)
    g = 0
    for pid, q in quip.items():
        q["seeds"] = []
        for k in q["knots"]:
            term = base_term + (remainder if g == 0 else 0)
            q["seeds"].append(k * knot_tip + term); g += 1
        q["root_input"] = sum(q["seeds"]) + tag_sat[pid] + root_fee[pid]
    splitter_outputs = [quip[pid]["root_input"] for pid, _ in pieces]
    assert total_in - sum(splitter_outputs) == split_fee, "splitter fee accounting broke"

    # 4. splitter + per-quipu roots (signed) — tag outputs AFTER the strand seeds,
    #    so read_quipu's "root:0 = header, root:1..N = body" stays untouched
    splitter_hex = cs_serialize(dogecs.signall(
        dogecs.mktx([utxo], [{"value": v, "address": address} for v in splitter_outputs]), priv))
    splitter_txid = _txid_of_serial(splitter_hex)
    root_hex, root_txid = {}, {}
    for i, (pid, _) in enumerate(pieces):
        q = quip[pid]
        outs = [{"value": s, "address": address} for s in q["seeds"]]
        outs += [{"value": t["value"], "address": t["address"]}
                 for t in tags_of.get(pid, [])]
        rh = cs_serialize(dogecs.signall(dogecs.mktx(
            [{"output": "%s:%d" % (splitter_txid, i), "value": q["root_input"]}],
            outs), priv))
        root_hex[pid] = rh; root_txid[pid] = _txid_of_serial(rh)

    # 5. backfill real root txids into referencing bodies (ASCII + raw, size-preserving)
    repl = {placeholder_of(pid): root_txid[pid] for pid, _ in pieces}
    for ph, tgt in (extra_placeholders or {}).items():
        repl[ph] = root_txid[tgt]

    def backfill(blob):
        n = 0
        for ph, real in repl.items():
            assert len(ph) == len(real) == 64
            a, ra = ph.encode(), real.encode()
            if a in blob:
                n += blob.count(a); blob = blob.replace(a, ra)
            rb, rr = binascii.unhexlify(ph), binascii.unhexlify(real)
            if rb in blob:
                n += blob.count(rb); blob = blob.replace(rb, rr)
        return blob, n

    def has_ph(blob):
        return any(ph.encode() in blob or binascii.unhexlify(ph) in blob for ph in repl)

    total_backfilled = 0
    for pid, q in quip.items():
        blob2, n = backfill(q["blob"])
        assert len(blob2) == len(q["blob"]), "%s: backfill changed length" % pid
        assert not has_ph(blob2), "%s: placeholder remains after backfill" % pid
        q["blob2"] = blob2; q["strands"] = split_quipu(blob2, cap)
        assert b"".join(q["strands"]) == blob2, "%s: strands != backfilled blob" % pid
        total_backfilled += n
    log("backfilled %d cross-references" % total_backfilled)

    # 5b. THE PHANTOM CHECK — the assertion above only knows DECLARED
    # placeholders. The Dantean Cosmos shipped an undeclared stand-in
    # (sha256 of a phrase) that round-tripped perfectly onto the chain.
    # Default-deny: every 64-hex token in every final body must be a root
    # of this diamond, a known txid, or explicitly declared via
    # `declared_ok` (hash certs carry non-txid SHA256s; 0xab alias
    # left-hand names dangle by design). See quipu_preflight.py.
    from quipu_preflight import check_refs_resolve, default_known_txids
    known = default_known_txids()
    if known_txids:
        known |= {t.lower() for t in known_txids}
    ref_failures = check_refs_resolve(
        {pid: q["blob2"] for pid, q in quip.items()},
        list(root_txid.values()), declared_ok=declared_ok or (),
        known_txids=known)
    if ref_failures:
        raise ValueError("unresolved references in final bodies:\n  "
                         + "\n  ".join(ref_failures))

    # 6. precompute strands
    cadenas = []  # (pid, idx, CadenaAtom)
    for pid, q in quip.items():
        q["cadenas"] = []
        for i, payload in enumerate(q["strands"]):
            cad = CadenaAtom(priv, payload,
                             {"output": "%s:%d" % (root_txid[pid], i), "value": q["seeds"][i]},
                             knot_tip)
            cad.precompute(); q["cadenas"].append(cad); cadenas.append((pid, i, cad))
    assert sum(len(c.txns) for _, _, c in cadenas) == total_knots, "knot count mismatch"

    # 7. mega-join from real termini
    join_inputs = [{"output": "%s:0" % c.txn_ids[-1],
                    "value": quip[pid]["seeds"][i] - knot_tip * len(c.txns)}
                   for pid, i, c in cadenas]
    actual_join_fee = sum(inp["value"] for inp in join_inputs) - final_out
    assert actual_join_fee == join_fee, "join fee accounting broke"
    join_hex = cs_serialize(dogecs.signall(
        dogecs.mktx(join_inputs, [{"value": final_out, "address": address}]), priv))
    join_txid = _txid_of_serial(join_hex)

    # verify the inscribed bytes round-trip (what the reader will reconstruct)
    for pid, q in quip.items():
        assert b"".join(c.data for c in q["cadenas"]) == q["blob2"], "%s: round-trip" % pid

    total_fee = split_fee + total_root_fees + strand_fees + actual_join_fee
    assert total_fee + total_tag_sat == total_in - final_out, "total fee accounting broke"
    log("TOTAL fees %s · tags %s · residual %s -> funder"
        % (doge(total_fee), doge(total_tag_sat), doge(final_out)))

    tags_out = {pid: [{"vout": len(quip[pid]["strands"]) + k,
                       "value": t["value"], "address": t["address"]}
                      for k, t in enumerate(tags_of.get(pid, []))]
                for pid, _ in pieces if tags_of.get(pid)}

    return {
        "address": address, "splitter": (splitter_hex, splitter_txid),
        "roots": {pid: (root_hex[pid], root_txid[pid]) for pid, _ in pieces},
        "strands": {pid: [(c.txns, c.txn_ids) for c in quip[pid]["cadenas"]] for pid, _ in pieces},
        "join": (join_hex, join_txid),
        "bodies": {pid: quip[pid]["blob2"] for pid, _ in pieces},
        "order": [pid for pid, _ in pieces],
        "tags": tags_out,
        "fees": {"total_sat": total_fee, "residual_sat": final_out, "knot_tip_sat": knot_tip,
                 "split_sat": split_fee, "join_sat": actual_join_fee,
                 "root_sat": {pid: root_fee[pid] for pid, _ in pieces},
                 "tag_sat": total_tag_sat,
                 "rate_kb": fp.rate_kb, "join_bytes": join_size},
        "totals": {"strands": total_strands, "knots": total_knots, "pieces": P},
    }


def write_artifacts(art, artifacts_dir):
    """Persist build_consolidated_diamond output to disk for the broadcaster."""
    d = artifacts_dir
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "splitter.hex"), "w").write(art["splitter"][0])
    open(os.path.join(d, "splitter.txid"), "w").write(art["splitter"][1])
    open(os.path.join(d, "megajoin.hex"), "w").write(art["join"][0])
    open(os.path.join(d, "megajoin.txid"), "w").write(art["join"][1])
    index = {"splitter": art["splitter"][1], "megajoin": art["join"][1],
             "total_knots": art["totals"]["knots"], "total_strands": art["totals"]["strands"],
             "fees": art["fees"], "tags": art.get("tags", {}), "pieces": []}
    for pid in art["order"]:
        rh, rt = art["roots"][pid]
        open(os.path.join(d, "root_%s.hex" % pid), "w").write(rh)
        open(os.path.join(d, "root_%s.txid" % pid), "w").write(rt)
        for i, (txns, txids) in enumerate(art["strands"][pid]):
            open(os.path.join(d, "strand_%s_%d.txns" % (pid, i)), "w").write("\n".join(txns))
            open(os.path.join(d, "strand_%s_%d.txids" % (pid, i)), "w").write("\n".join(txids))
        open(os.path.join(d, "%s.bin" % pid), "wb").write(art["bodies"][pid])
        index["pieces"].append({"pid": pid, "root": rt, "n_strands": len(art["strands"][pid]),
                                "knots": sum(len(t) for t, _ in art["strands"][pid]),
                                "tags": art.get("tags", {}).get(pid, [])})
    json.dump(index, open(os.path.join(d, "index.json"), "w"), indent=2)
    return index


# ===========================================================================
#  BROADCAST (KEYLESS) — idempotent, resumable; reuses quipu_broadcast primitives
# ===========================================================================
def _wait_confirmed(txid, label, log, poll=15, max_wait=2400):
    t = 0
    while t < max_wait:
        c = _qb.on_chain_with_confs(txid)
        if c is not None and c > 0:
            log("  ✓ %s confirmed (%ds)" % (label, t)); return
        time.sleep(poll); t += poll
    raise TimeoutError("%s not confirmed in %ds" % (label, max_wait))


def _launch_loom(artifacts_dir, port=8765, open_browser=True, log=print):
    """Best-effort: start the standard loom_monitor (loom_monitor.py) for these
    artifacts in a background subprocess and open the browser. Watch-only; never
    fails the broadcast — headless / no-browser just logs and continues."""
    try:
        import subprocess, webbrowser, urllib.request
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "loom_monitor.py")
        if not os.path.exists(script):
            return
        env = dict(os.environ, LOOM_ARTIFACTS=str(artifacts_dir), PORT=str(port))
        subprocess.Popen([sys.executable, script], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        url = "http://localhost:%d/" % port
        for _ in range(20):                       # wait up to ~10 s for it to bind
            try:
                urllib.request.urlopen(url, timeout=1); break
            except Exception:
                time.sleep(0.5)
        log("  loom: %s" % url)
        if open_browser:
            webbrowser.open(url)
    except Exception as e:                          # noqa: BLE001
        log("  loom launch skipped: %s" % e)


def broadcast_consolidated_diamond(artifacts_dir, log=print, strand_workers=16,
                                   declared_ok=(), known_txids=None,
                                   expected_refs=None, require_approval=False,
                                   skip_preflight=False, loom=True, loom_port=8765,
                                   loom_open=True):
    """Weave a built diamond onto chain from artifacts_dir. Keyless, idempotent,
    resumable — re-running only (re)sends what the node has forgotten.

    PREFLIGHT RUNS FIRST and broadcasting refuses on failure: the signed
    txs' OP_RETURN payloads are reassembled and must equal the body files,
    every body must decode through its canonical reader, and every 64-hex
    token must resolve (diamond root / known txid / declared_ok). Pass
    skip_preflight=True only with a reason you would be willing to read
    back from the chain forever.

    loom=True (default) auto-launches the live loom watcher (loom_monitor.py) on
    loom_port and opens the browser — fold-in so you don't set it up each time;
    loom=False to skip (headless / no display)."""
    d = artifacts_dir
    if skip_preflight:
        log("!! PREFLIGHT SKIPPED — the chain will hold whatever this is")
    else:
        from quipu_preflight import preflight
        preflight(d, declared_ok=declared_ok, known_txids=known_txids,
                  expected_refs=expected_refs, require_approval=require_approval,
                  log=log)
    if loom:                                        # auto-open the live loom watcher
        _launch_loom(d, loom_port, loom_open, log)
    idx = json.load(open(os.path.join(d, "index.json")))
    order = [p["pid"] for p in idx["pieces"]]
    rd = lambda f: open(os.path.join(d, f)).read().strip()

    # discover strands
    strands = {}
    for pid in order:
        i = 0
        while os.path.exists(os.path.join(d, "strand_%s_%d.txns" % (pid, i))):
            strands[(pid, i)] = (open(os.path.join(d, "strand_%s_%d.txns" % (pid, i))).read().splitlines(),
                                 open(os.path.join(d, "strand_%s_%d.txids" % (pid, i))).read().splitlines())
            i += 1
    log("diamond: %d pieces, %d strands, %d knots"
        % (len(order), len(strands), sum(len(t) for t, _ in strands.values())))

    # [1] splitter
    log("[1/5] splitter")
    sp = rd("splitter.txid"); _qb.send_if_needed(rd("splitter.hex"), sp, "splitter")
    _wait_confirmed(sp, "splitter", log)

    # [2] roots
    log("[2/5] %d roots" % len(order))
    roots = {pid: rd("root_%s.txid" % pid) for pid in order}
    for pid in order:
        _qb.send_if_needed(rd("root_%s.hex" % pid), roots[pid], "root[%s]" % pid)
    for pid in order:
        _wait_confirmed(roots[pid], "root[%s]" % pid, log)

    # [3] strands (each <= CAP knots = one ancestor wave)
    log("[3/5] %d strands (%d at a time)" % (len(strands), strand_workers))
    def weave(item):
        (pid, i), (txns, txids) = item
        start = _qb.find_resume_index(txids)
        j = start
        while j < len(txns):
            end = min(j + MEMPOOL_ANCESTOR_LIMIT, len(txns))
            for k in range(j, end):
                if not _qb.send_with_retry(txns[k], "strand[%s_%d] knot %d" % (pid, i, k)):
                    return False
            if end < len(txns):
                _wait_confirmed(txids[end - 1], "strand[%s_%d] anchor" % (pid, i), log)
            j = end
        return True
    with ThreadPoolExecutor(max_workers=strand_workers) as ex:
        if not all(ex.map(weave, list(strands.items()))):
            raise SystemExit("a strand failed — relaunch to resume")

    # [4] all termini mined (so the join's ancestors are all confirmed)
    log("[4/5] waiting for all termini to be mined")
    termini = [txids[-1] for _, txids in strands.values()]
    t, poll, max_wait = 0, 30, 5400
    while t < max_wait:
        done = sum(1 for x in termini if (_qb.on_chain_with_confs(x) or 0) > 0)
        log("  termini %d/%d (%ds)" % (done, len(termini), t))
        if done == len(termini):
            break
        time.sleep(poll); t += poll
    else:
        raise TimeoutError("not all termini confirmed — relaunch to resume")

    # [5] mega-join
    log("[5/5] mega-join")
    mj = rd("megajoin.txid"); _qb.send_if_needed(rd("megajoin.hex"), mj, "mega-join")
    _wait_confirmed(mj, "mega-join", log)
    log("ALL DONE. diamond closed: splitter %s · join %s" % (sp, mj))
    return {"splitter": sp, "roots": roots, "megajoin": mj}


if __name__ == "__main__":
    print("quipu_diamond ok —", FeePolicy().describe())
