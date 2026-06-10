#!/usr/bin/env python3
"""Tags — auxiliary unspent outputs on a quipu's root (the textile's future tense).

A tag is an output of a quipu's root transaction that seeds no OP_RETURN chain
and is not consumed by the join: a UTXO that belongs to the textile and sits
unspent after inscription. Its scriptPubKey is the grammar of a future event
(who may make it happen, under what conditions); its spend IS the event, and
the event is discoverable by walking forward from the textile itself.

Identified by ABSENCE: a reader reassembling the body collects each strand's
OP_RETURN payloads — a tag strand contributes nothing, so body reconstruction
is unchanged and tag-less readers are unaffected. Design:
docs/design/tag-architecture.md + docs/design/buyer-signs-first.md.

This module provides the three moving parts past inscription
(inscription-side support is `tags_of` in quipu_diamond.build_consolidated_diamond):

  · classify_root_outputs — the reader: which root outputs are strands, which
    are tags, and each tag's state (intact / spent and by what)
  · build_specialization_tx — spend a generic P2PKH tag into a buyer-specific
    bond P2SH, optionally emitting a continuation tag (the renewable thread)
  · build_claim_with_continuation — the seller's claim consuming the bond,
    paying profit + skimming a fresh tag so the textile stays sellable

Signing against custom redeem scripts reuses the centinela's proven machinery
(cryptos.transaction.multisign, mainnet-validated block 6,237,951).

  python quipu_tags.py        # offline self-test (no node, no funds)
"""
import os, sys, math

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import cryptos
from cryptos import serialize as cs_serialize, deserialize as cs_deserialize
from cryptos.transaction import serialize_script, deserialize_script, multisign
from colegio_tools import _txid_of_serial
from quipu_centinela import p2sh_address, SIGHASH_ALL, OP_1
from quipu_diamond import FeePolicy

DUST_SAT          = 100_000        # 0.001 DOGE — refuse to emit outputs below this
DEFAULT_TAG_SAT   = 5_000_000      # 0.05 DOGE — conventional seed / skim amount


# ---------------------------------------------------------------------------
#  the reader — classify a root's outputs into strands and tags
# ---------------------------------------------------------------------------
def _has_op_return(tx):
    return any(o.get("script", "").startswith("6a") for o in tx.get("outs", []))


def classify_root_outputs(root_tx, spend_of, get_tx):
    """Classify every output of a quipu's root as strand / tag / change.

    root_tx   deserialized root transaction (dict with "outs"), or raw hex
    spend_of  callable(txid, vout) -> spending txid or None (None = unspent)
    get_tx    callable(txid) -> deserialized tx dict (or raw hex)

    A STRAND output's spending tx carries an OP_RETURN (it is the strand's
    first knot). A TAG output is unspent, or spent by a transaction with no
    OP_RETURN (the tag's event — specialization, claim, trip, release...).

    Returns a list, one entry per output:
      {"vout", "value", "script", "kind": "strand"|"tag",
       "spent_by": txid|None, "state": "strand"|"intact"|"SPENT"}

    Both callables are injected so this runs against any index: RPC, the
    local dataset, or a mock in tests. No wallet, no keys.
    """
    if isinstance(root_tx, str):
        root_tx = cs_deserialize(root_tx)
    root_txid = _txid_of_serial(cs_serialize(root_tx))
    out = []
    for i, o in enumerate(root_tx["outs"]):
        spender = spend_of(root_txid, i)
        if spender is None:
            out.append({"vout": i, "value": o["value"], "script": o["script"],
                        "kind": "tag", "spent_by": None, "state": "intact"})
            continue
        stx = get_tx(spender)
        if isinstance(stx, str):
            stx = cs_deserialize(stx)
        if _has_op_return(stx):
            out.append({"vout": i, "value": o["value"], "script": o["script"],
                        "kind": "strand", "spent_by": spender, "state": "strand"})
        else:
            out.append({"vout": i, "value": o["value"], "script": o["script"],
                        "kind": "tag", "spent_by": spender, "state": "SPENT"})
    return out


def find_tags(root_tx, spend_of, get_tx):
    """Just the tags from classify_root_outputs."""
    return [c for c in classify_root_outputs(root_tx, spend_of, get_tx)
            if c["kind"] == "tag"]


def follow_thread(root_tx, spend_of, get_tx, max_hops=256):
    """Follow a renewable tag thread forward: root tag -> spend -> continuation
    tag -> spend -> ... Returns the hop list ending at the current intact tag
    (or at a terminal spend that emitted no continuation).

    CONTINUATION CONVENTION: a thread spend's vout 0 is always the event's
    principal output (the bond, the profit, the release) — never the thread.
    The continuation is the first output at vout >= 1 whose scriptPubKey
    matches the thread's. Matching by script alone would be ambiguous: a
    claim's profit and its skim tag can both pay the seller, and the profit
    sits at vout 0. Both builders in this module honor the convention
    (continuation/skim at vout 1).

    Each hop: {"outpoint": "txid:vout", "value", "spent_by": txid|None}.
    """
    tags = find_tags(root_tx, spend_of, get_tx)
    if not tags:
        return []
    t = tags[0]                                     # convention: first tag is the thread
    if isinstance(root_tx, str):
        root_tx = cs_deserialize(root_tx)
    txid = _txid_of_serial(cs_serialize(root_tx))
    spk = t["script"]
    hops = [{"outpoint": "%s:%d" % (txid, t["vout"]), "value": t["value"],
             "spent_by": t["spent_by"]}]
    while hops[-1]["spent_by"] and len(hops) < max_hops:
        stx = get_tx(hops[-1]["spent_by"])
        if isinstance(stx, str):
            stx = cs_deserialize(stx)
        stxid = _txid_of_serial(cs_serialize(stx))
        cont = next((j for j, o in enumerate(stx["outs"])
                     if j >= 1 and o["script"] == spk), None)
        if cont is None:
            break                                   # thread ended (no continuation)
        hops.append({"outpoint": "%s:%d" % (stxid, cont),
                     "value": stx["outs"][cont]["value"],
                     "spent_by": spend_of(stxid, cont)})
    return hops


def tag_status(txid, vout):
    """('intact', confs) | ('SPENT', None) | ('unknown', None) via local RPC.
    Same contract as quipu_centinela.check_centinela."""
    from colegio_tools import rpc_request
    try:
        o = rpc_request("gettxout", [txid, vout])
    except Exception:
        return ("unknown", None)
    if o is None:
        return ("SPENT", None)
    return ("intact", o.get("confirmations", 0))


# ---------------------------------------------------------------------------
#  specialization — generic P2PKH tag -> buyer-specific bond P2SH (+ thread)
# ---------------------------------------------------------------------------
def build_specialization_tx(tag_outpoint, tag_value, seller_priv, bond_address,
                            bond_value=None, continuation=True,
                            continuation_sat=DEFAULT_TAG_SAT, fee_policy=None):
    """Spend a generic P2PKH tag into a buyer-specific bond P2SH.

    tag_outpoint   "txid:vout" of the current tag UTXO
    tag_value      its value in sat
    seller_priv    key that controls the tag's P2PKH scriptPubKey
    bond_address   the bond's P2SH address (redeem script already buyer-specific;
                   build it with working/sale build_sale_redeem_script or
                   quipu_centinela.htlc_redeem + p2sh_address)
    bond_value     sat to place in the bond (default: everything left after the
                   continuation tag and the fee)
    continuation   emit output 1 = a fresh tag at the seller's own P2PKH, the
                   renewable thread (same scriptPubKey as a seller-funded tag)

    Returns (signed_hex, txid, detail_dict). Fee priced by measured size
    (FeePolicy default 0.10 DOGE/KB — one such tx is ~0.02-0.03 DOGE, so seed
    tags accordingly; see the economics note in tag-architecture.md).

    NOTE: any vout >= 1 output at the seller's P2PKH reads as a thread
    continuation under follow_thread's convention — including change. With
    continuation=False, leave bond_value=None (all-in) so no change output
    accidentally extends the thread.
    """
    fp = fee_policy or FeePolicy()
    d = cryptos.Doge()
    seller_addr = d.privtoaddr(seller_priv)

    # measure by signing a same-shape dummy (values don't affect size)
    dummy = d.signall(d.mktx(
        [{"output": "%064x:0" % 1, "value": 10 ** 12}],
        [{"value": 10 ** 10, "address": bond_address}] +
        ([{"value": 10 ** 10, "address": seller_addr}] if continuation else [])),
        seller_priv)
    fee = fp.fee_for_bytes(len(cs_serialize(dummy)) // 2)

    cont_sat = continuation_sat if continuation else 0
    if bond_value is None:
        bond_value = tag_value - cont_sat - fee
    change = tag_value - bond_value - cont_sat - fee
    if bond_value < DUST_SAT:
        raise ValueError("bond output %d sat below dust — tag too small for this fee/skim "
                         "(tag %d, fee %d, continuation %d)" % (bond_value, tag_value, fee, cont_sat))
    if change < 0:
        raise ValueError("tag value %d cannot cover bond %d + continuation %d + fee %d"
                         % (tag_value, bond_value, cont_sat, fee))
    if 0 < change < DUST_SAT:
        bond_value += change; change = 0            # fold sub-dust change into the bond

    outs = [{"value": bond_value, "address": bond_address}]
    if continuation:
        outs.append({"value": cont_sat, "address": seller_addr})
    if change:
        outs.append({"value": change, "address": seller_addr})
    signed = d.signall(d.mktx([{"output": tag_outpoint, "value": tag_value}], outs), seller_priv)
    hexs = cs_serialize(signed)
    return hexs, _txid_of_serial(hexs), {
        "bond_vout": 0, "bond_value": bond_value,
        "continuation_vout": 1 if continuation else None,
        "continuation_value": cont_sat if continuation else 0,
        "fee": fee, "change": change,
    }


# ---------------------------------------------------------------------------
#  claim with continuation — consume the bond, pay profit, re-seed the thread
# ---------------------------------------------------------------------------
def build_claim_with_continuation(bond_inputs, redeem_hex, claim_priv, dest_addr,
                                  tag_addr=None, skim_sat=DEFAULT_TAG_SAT,
                                  fee_policy=None, extra_scriptsig_items=None):
    """The seller's claim: consume the bond's UTXO(s) via the redeem script's
    IF branch, pay profit to dest_addr, and (if tag_addr) skim a fresh tag.

    bond_inputs    [{"output": "txid:vout", "value": sat}, ...] — the tag seed
                   and/or the buyer's funding at the bond P2SH
    redeem_hex     the bond's redeemScript
    claim_priv     key satisfying the IF branch's CHECKSIG
    tag_addr       continuation tag's address (None = no continuation)
    extra_scriptsig_items  pushed between the signature and the OP_1 selector
                   (e.g. an HTLC preimage); default none — matches the sale
                   bond's plain  OP_IF <pub> OP_CHECKSIG  claim leg.

    scriptSig per input:  <sig> [extra...] OP_1 <redeem>
    Returns (signed_hex, txid, detail). SIGHASH_ALL binds the outputs, so the
    adaptor completion published in the scriptSig is front-run-proof.
    """
    fp = fee_policy or FeePolicy()
    d = cryptos.Doge()
    total_in = sum(i["value"] for i in bond_inputs)
    extra = extra_scriptsig_items or []

    # size: measure unsigned shape + per-input p2sh scriptSig allowance
    n_out = 2 if tag_addr else 1
    redeem_len = len(redeem_hex) // 2
    per_in_ss = 1 + 73 + sum(1 + len(x) // 2 for x in extra) + 1 + 3 + redeem_len
    base = d.mktx([dict(i) for i in bond_inputs],
                  [{"value": total_in // (n_out + 1), "address": dest_addr}] * n_out)
    fee = fp.fee_for_bytes(len(cs_serialize(base)) // 2 + per_in_ss * len(bond_inputs))

    skim = skim_sat if tag_addr else 0
    profit = total_in - skim - fee
    if profit < DUST_SAT:
        raise ValueError("profit %d below dust (in %d, skim %d, fee %d)"
                         % (profit, total_in, skim, fee))

    outs = [{"value": profit, "address": dest_addr}]
    if tag_addr:
        outs.append({"value": skim, "address": tag_addr})
    tx = d.mktx([dict(i) for i in bond_inputs], outs)
    for k in range(len(bond_inputs)):
        sig = multisign(tx, k, redeem_hex, claim_priv, SIGHASH_ALL)
        items = [bytes.fromhex(sig)] + [bytes.fromhex(x) for x in extra] \
                + [OP_1, bytes.fromhex(redeem_hex)]
        tx["ins"][k]["script"] = serialize_script(items).hex()
    hexs = cs_serialize(tx)
    return hexs, _txid_of_serial(hexs), {
        "profit": profit, "skim": skim, "fee": fee,
        "continuation_vout": 1 if tag_addr else None,
    }


# ---------------------------------------------------------------------------
#  header convention helper — |tag=<vout>| field value for type headers
# ---------------------------------------------------------------------------
def tag_field(vout):
    """Value for the soft `tag=` header field naming the tag's output index.
    Structural detection (classify_root_outputs) never needs it; it makes the
    tag explicit for tooling. Multiple tags: comma-joined indices."""
    if isinstance(vout, (list, tuple)):
        return ",".join(str(int(v)) for v in vout)
    return str(int(vout))


# ---------------------------------------------------------------------------
#  offline self-test — full simulated lifecycle, no node, no funds
# ---------------------------------------------------------------------------
def _selftest():
    from quipu_centinela import htlc_redeem, _compressed_pub
    import hashlib
    d = cryptos.Doge()
    fp = FeePolicy()
    seller_priv = cryptos.random_key(); seller_addr = d.privtoaddr(seller_priv)
    buyer_priv  = cryptos.random_key()

    print("=== 1. diamond with a tag (engine integration) ===")
    from quipu_diamond import build_consolidated_diamond
    from canonical.text import build_text_quipu
    h1, b1 = build_text_quipu("pieza", "x" * 400)
    h2, b2 = build_text_quipu("tagged", "y" * 400)
    pieces = [("plain", h1 + b1), ("tagged", h2 + b2)]
    TAG_SAT = 10_000_000                            # 0.10 DOGE seed
    art = build_consolidated_diamond(
        pieces, lambda pid: "f" * 64,
        {"output": "%064x:0" % 0xAA, "value": 60 * 10 ** 8},
        seller_priv, seller_addr, fp,
        tags_of={"tagged": [{"value": TAG_SAT, "address": seller_addr}]},
        log=lambda *a: None)

    root_tx = cs_deserialize(art["roots"]["tagged"][0])
    n_strands = len(art["strands"]["tagged"])
    assert len(root_tx["outs"]) == n_strands + 1, "tag output missing from root"
    tag_out = root_tx["outs"][n_strands]
    assert tag_out["value"] == TAG_SAT, "tag value wrong"
    assert tag_out["script"] == d.addrtoscript(seller_addr), "tag scriptPubKey wrong"
    plain_root = cs_deserialize(art["roots"]["plain"][0])
    assert len(plain_root["outs"]) == len(art["strands"]["plain"]), "untagged root grew an output"
    join_tx = cs_deserialize(art["join"][0])
    assert len(join_tx["ins"]) == art["totals"]["strands"], "join consumed a tag!"
    assert art["tags"]["tagged"][0]["vout"] == n_strands
    assert art["fees"]["tag_sat"] == TAG_SAT
    print("  ✓ root has %d strand seeds + 1 tag @ vout %d; join consumes only the %d strands"
          % (n_strands, n_strands, art["totals"]["strands"]))
    print("  ✓ accounting: fees %.4f + tags %.4f + residual %.4f = funding 60 DOGE"
          % (art["fees"]["total_sat"] / 1e8, art["fees"]["tag_sat"] / 1e8,
             art["fees"]["residual_sat"] / 1e8))

    print("=== 2. reader — tags identified by absence ===")
    root_txid = art["roots"]["tagged"][1]
    first_knots = {}                                # (txid, vout) -> spending tx hex
    for i, (txns, txids) in enumerate(art["strands"]["tagged"]):
        first_knots[(root_txid, i)] = txns[0]
    spend_of = lambda txid, vout: (_txid_of_serial(first_knots[(txid, vout)])
                                   if (txid, vout) in first_knots else None)
    get_tx = lambda txid: next(t for t in first_knots.values()
                               if _txid_of_serial(t) == txid)
    cls = classify_root_outputs(art["roots"]["tagged"][0], spend_of, get_tx)
    kinds = [c["kind"] for c in cls]
    assert kinds == ["strand"] * n_strands + ["tag"], "classification wrong: %s" % kinds
    assert cls[-1]["state"] == "intact"
    print("  ✓ %d strands recognized by their OP_RETURN first knots; vout %d = intact tag"
          % (n_strands, n_strands))

    print("=== 3. specialization — tag -> bond + continuation ===")
    refund_h = 6_400_000
    preimage = hashlib.sha256(b"tag-selftest").digest()
    redeem = htlc_redeem(hashlib.sha256(preimage).hexdigest(),
                         _compressed_pub(seller_priv), refund_h,
                         _compressed_pub(buyer_priv))
    bond_addr, _ = p2sh_address(redeem)
    tag_outpoint = "%s:%d" % (root_txid, n_strands)
    sp_hex, sp_txid, sp = build_specialization_tx(
        tag_outpoint, TAG_SAT, seller_priv, bond_addr, fee_policy=fp)
    sp_tx = cs_deserialize(sp_hex)
    assert (sp_tx["ins"][0]["tx_hash"], sp_tx["ins"][0]["tx_pos"]) == (root_txid, n_strands), \
        "spends wrong outpoint"
    assert sp_tx["outs"][0]["script"].startswith("a914"), "bond output not P2SH"
    assert sp_tx["outs"][1]["script"] == d.addrtoscript(seller_addr), "continuation missing"
    assert sp_tx["outs"][1]["value"] == DEFAULT_TAG_SAT
    assert sp["bond_value"] + sp["continuation_value"] + sp["fee"] == TAG_SAT, "specialization accounting"
    print("  ✓ tag(%.2f) -> bond %.4f + continuation %.2f + fee %.4f DOGE"
          % (TAG_SAT / 1e8, sp["bond_value"] / 1e8,
             sp["continuation_value"] / 1e8, sp["fee"] / 1e8))

    print("=== 4. claim — bond -> profit + fresh tag (renewable thread) ===")
    FUNDING = 5 * 10 ** 8                           # buyer funds 5 DOGE
    bond_inputs = [{"output": "%s:0" % sp_txid, "value": sp["bond_value"]},
                   {"output": "%064x:0" % 0xBB, "value": FUNDING}]
    cl_hex, cl_txid, cl = build_claim_with_continuation(
        bond_inputs, redeem, seller_priv, seller_addr,
        tag_addr=seller_addr, fee_policy=fp,
        extra_scriptsig_items=[preimage.hex()])
    cl_tx = cs_deserialize(cl_hex)
    ss = deserialize_script(cl_tx["ins"][0]["script"])
    assert ss[1] == preimage.hex() and ss[2] == OP_1 and ss[3] == redeem, \
        "claim scriptSig is not <sig> <P> OP_1 <redeem>"
    assert cl_tx["outs"][1]["value"] == DEFAULT_TAG_SAT, "skim output wrong"
    assert cl["profit"] + cl["skim"] + cl["fee"] == sp["bond_value"] + FUNDING, "claim accounting"
    print("  ✓ claim consumes %d bond inputs; profit %.4f + tag %.2f + fee %.4f DOGE"
          % (len(bond_inputs), cl["profit"] / 1e8, cl["skim"] / 1e8, cl["fee"] / 1e8))

    print("=== 5. follow the thread root-tag -> specialization -> continuation ===")
    # reality: the claim spends the BOND (sp:0); the continuation tag (sp:1)
    # stays intact until the NEXT specialization consumes it
    spends = {(root_txid, n_strands): sp_hex, (sp_txid, 0): cl_hex}
    spends.update({k: v for k, v in first_knots.items()})
    thread_spend_of = lambda txid, vout: (_txid_of_serial(spends[(txid, vout)])
                                          if (txid, vout) in spends else None)
    all_tx = {_txid_of_serial(v): v for v in spends.values()}
    thread_get_tx = lambda txid: all_tx[txid]
    hops = follow_thread(art["roots"]["tagged"][0], thread_spend_of, thread_get_tx)
    assert len(hops) == 2, "thread should be root-tag + continuation: %r" % hops
    assert hops[0]["outpoint"] == tag_outpoint and hops[0]["spent_by"] == sp_txid
    assert hops[1]["outpoint"] == "%s:1" % sp_txid and hops[1]["spent_by"] is None, \
        "continuation should be intact (the claim consumed the bond, not the thread)"
    print("  ✓ thread: %s… -> specialization %s… -> continuation intact at %s…:1"
          % (tag_outpoint[:12], sp_txid[:12], sp_txid[:12]))

    print("=== 5b. profit output must NOT be mistaken for the thread ===")
    # extend the mock: next specialization spends the continuation (sp:1) into a
    # second bond WITHOUT a continuation -> thread must terminate, and must not
    # jump onto the claim's vout-0 profit (same scriptPubKey as the thread)
    sp2_hex, sp2_txid, _ = build_specialization_tx(
        "%s:1" % sp_txid, DEFAULT_TAG_SAT, seller_priv, bond_addr,
        continuation=False, fee_policy=fp)        # all-in: no change, no vout>=1
    spends[(sp_txid, 1)] = sp2_hex
    all_tx[sp2_txid] = sp2_hex
    hops = follow_thread(art["roots"]["tagged"][0], thread_spend_of, thread_get_tx)
    assert len(hops) == 2 and hops[1]["spent_by"] == sp2_txid, "thread did not follow into sp2"
    # sp2 has no vout>=1 output at the thread spk -> terminates; profit ignored
    print("  ✓ thread terminates at the no-continuation specialization; claim profit "
          "(vout 0, same spk) correctly ignored")

    print("=== 6. economics sanity (corrected numbers) ===")
    cycle = sp["fee"] + cl["fee"]
    print("  one specialize+claim cycle at %.2f DOGE/KB costs %.4f DOGE in fees"
          % (fp.rate_kb, cycle / 1e8))
    print("  a %.2f DOGE seed survives ~%d failed cycles before dust"
          % (TAG_SAT / 1e8, TAG_SAT // max(cycle, 1)))

    print("\nALL OFFLINE CHECKS PASSED. Next gate: on-chain end-to-end (real funds).")


if __name__ == "__main__":
    _selftest()
