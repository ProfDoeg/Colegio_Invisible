"""The ripcord: the constitutional amendment cord, walked and gated.

Offline (no node, no funds), mirroring quipu_tags' own self-test pattern:
a real engine-built root carries the cord (tags_of), a hand-built
successor root spends it as input 0, and mock spend_of/get_tx maps play
the index. Three things are pinned:

  1. follow_ripcord walks root-to-root and is SCRIPT-FREE — the successor
     re-encumbers its cord to different keys (succession) and the walk
     still resolves, where follow_thread's script-equality convention
     provably stops;
  2. check_ripcord (the two-pointer ceremony gate) passes the lawful
     shape and refuses: wrong input 0, a successor with no fresh cord,
     and a body whose parent_txid disagrees with the thread;
  3. the cord sits exactly where the engine convention puts it
     (vout = n_strands) and the join never consumes it.
"""
import pytest

import cryptos
from cryptos import serialize as cs_serialize, deserialize as cs_deserialize

from colegio_tools import _txid_of_serial
from quipu_diamond import FeePolicy, build_consolidated_diamond
from quipu_tags import classify_root_outputs, follow_ripcord, follow_thread
from quipu_preflight import check_ripcord
from registry_v1 import build_registry_v1
from text import build_text_quipu


@pytest.fixture(scope="module")
def thread():
    """One engine-built tagged root (the 'constitution') + one hand-built
    successor root (the 'legislation') spending its cord as input 0, with
    the cord re-encumbered to a DIFFERENT key (succession), plus the mock
    index maps."""
    d = cryptos.Doge()
    fp = FeePolicy()
    authority_a = cryptos.random_key()
    addr_a = d.privtoaddr(authority_a)
    authority_b = cryptos.random_key()          # the successor set
    addr_b = d.privtoaddr(authority_b)
    funder = cryptos.random_key()               # ceremony wallet — seeds pay
    addr_f = d.privtoaddr(funder)               # THIS key, never the authority

    # --- root A: engine-built, cord via tags_of (the v0 shape) ---
    h, b = build_text_quipu("constitution-stand-in", "x" * 400)
    CORD_SAT = 100_000_000                      # 1 DOGE, RIPCORD seed
    art = build_consolidated_diamond(
        [("v0", h + b)], lambda pid: "f" * 64,
        {"output": "%064x:0" % 0xA1, "value": 60 * 10 ** 8},
        authority_a, addr_a, fp,
        tags_of={"v0": [{"value": CORD_SAT, "address": addr_a}]},
        log=lambda *a: None)
    root_a_hex, root_a_txid = art["roots"]["v0"]
    n_strands_a = len(art["strands"]["v0"])
    cord_a = "%s:%d" % (root_a_txid, n_strands_a)

    # --- root B: successor, input 0 = cord A; own seeds; cord at addr_b ---
    SEED = 5_000_000
    root_b = d.signall(d.mktx(
        [{"output": cord_a, "value": CORD_SAT},                  # input 0: the pull
         {"output": "%064x:0" % 0xB2, "value": 10 * 10 ** 8}],   # ceremony funding
        [{"value": SEED, "address": addr_f},                     # strand seed 0 (funder)
         {"value": SEED, "address": addr_f},                     # strand seed 1 (funder)
         {"value": CORD_SAT, "address": addr_b}]),               # fresh cord, NEW keys
        authority_a)
    root_b_hex = cs_serialize(root_b)
    root_b_txid = _txid_of_serial(root_b_hex)
    n_strands_b = 2

    # --- the mock index ---
    knots = {}                                  # root A's strand first-knots
    for i, (txns, _txids) in enumerate(art["strands"]["v0"]):
        knots[(root_a_txid, i)] = txns[0]
    fake_knot = {"outs": [{"value": 0, "script": "6a00"}], "ins": []}
    spends = dict(knots)
    spends[(root_a_txid, n_strands_a)] = root_b_hex              # the pull
    by_id = {_txid_of_serial(v): v for v in knots.values()}
    by_id[root_b_txid] = root_b_hex
    # root B's seeds are spent by OP_RETURN knots; its cord stays intact
    for j, kid in enumerate(("k1" * 32, "k2" * 32)):
        spends[(root_b_txid, j)] = kid
        by_id[kid] = fake_knot

    def spend_of(txid, vout):
        v = spends.get((txid, vout))
        return (_txid_of_serial(v) if isinstance(v, str) and len(v) > 64 else v)

    def get_tx(txid):
        return by_id[txid]

    return {"art": art, "d": d,
            "root_a_hex": root_a_hex, "root_a_txid": root_a_txid,
            "n_strands_a": n_strands_a, "cord_a": cord_a, "cord_sat": CORD_SAT,
            "root_b": root_b, "root_b_hex": root_b_hex,
            "root_b_txid": root_b_txid, "n_strands_b": n_strands_b,
            "addr_a": addr_a, "addr_b": addr_b, "authority_a": authority_a,
            "spend_of": spend_of, "get_tx": get_tx}


# ---------------------------------------------------------------------------
# 1. The engine convention and the walk
# ---------------------------------------------------------------------------

def test_cord_sits_at_first_non_strand_vout_and_join_ignores_it(thread):
    art = thread["art"]
    root = cs_deserialize(thread["root_a_hex"])
    assert len(root["outs"]) == thread["n_strands_a"] + 1
    assert root["outs"][thread["n_strands_a"]]["value"] == thread["cord_sat"]
    join = cs_deserialize(art["join"][0])
    assert len(join["ins"]) == art["totals"]["strands"]   # cord never consumed
    cls = classify_root_outputs(thread["root_a_hex"],
                                thread["spend_of"], thread["get_tx"])
    assert [c["kind"] for c in cls] == ["strand"] * thread["n_strands_a"] + ["tag"]


def test_follow_ripcord_walks_root_to_root(thread):
    hops = follow_ripcord(thread["root_a_hex"],
                          thread["spend_of"], thread["get_tx"])
    assert len(hops) == 2
    assert hops[0]["root_txid"] == thread["root_a_txid"]
    assert hops[0]["cord_outpoint"] == thread["cord_a"]
    assert hops[0]["spent_by"] == thread["root_b_txid"]   # the spend IS the next root
    assert hops[1]["root_txid"] == thread["root_b_txid"]
    assert hops[1]["cord_outpoint"] == "%s:%d" % (thread["root_b_txid"],
                                                  thread["n_strands_b"])
    assert hops[1]["spent_by"] is None                    # intact: current leaf


def test_succession_breaks_follow_thread_but_not_the_ripcord(thread):
    # The successor's cord pays DIFFERENT keys (succession). follow_thread's
    # script-equality convention must stop at hop 1; the ripcord walk must not.
    d = thread["d"]
    a_spk = d.addrtoscript(thread["addr_a"])
    b_spk = d.addrtoscript(thread["addr_b"])
    assert a_spk != b_spk                                 # a real re-encumbrance
    old = follow_thread(thread["root_a_hex"], thread["spend_of"], thread["get_tx"])
    assert len(old) == 1, "script-equality walk should end at the succession"
    new = follow_ripcord(thread["root_a_hex"], thread["spend_of"], thread["get_tx"])
    assert len(new) == 2, "the ripcord walk must survive succession"


def test_cordless_root_terminates_the_walk(thread):
    # A root whose outputs are all strands ends the thread honestly.
    art = thread["art"]
    d = thread["d"]
    bare = d.signall(d.mktx(
        [{"output": "%064x:0" % 0xC3, "value": 10 ** 8}],
        [{"value": 5_000_000, "address": thread["addr_a"]}]), thread["authority_a"])
    bare_hex = cs_serialize(bare)
    bare_txid = _txid_of_serial(bare_hex)
    knot = {"outs": [{"value": 0, "script": "6a00"}], "ins": []}
    spend_of = lambda t, v: "k9" * 32 if (t, v) == (bare_txid, 0) else None
    get_tx = lambda t: knot
    hops = follow_ripcord(bare_hex, spend_of, get_tx)
    assert hops == [{"root_txid": bare_txid, "cord_outpoint": None,
                     "cord_value": None, "spent_by": None}]


# ---------------------------------------------------------------------------
# 2. The ceremony gate
# ---------------------------------------------------------------------------

def test_check_ripcord_passes_the_lawful_shape(thread):
    fails = check_ripcord(thread["root_a_hex"], thread["n_strands_a"],
                          thread["root_b_hex"], thread["n_strands_b"])
    assert fails == []


def test_check_ripcord_thread_and_text_must_agree(thread):
    # Body whose parent_txid names the cord's root: agrees.
    h, b = build_registry_v1(parent_txid=thread["root_a_txid"])
    assert check_ripcord(thread["root_a_hex"], thread["n_strands_a"],
                         thread["root_b_hex"], thread["n_strands_b"],
                         successor_blob=h + b) == []
    # Body pointing elsewhere: refused.
    h2, b2 = build_registry_v1(parent_txid="ff" * 32)
    fails = check_ripcord(thread["root_a_hex"], thread["n_strands_a"],
                          thread["root_b_hex"], thread["n_strands_b"],
                          successor_blob=h2 + b2)
    assert len(fails) == 1 and "disagree" in fails[0]
    # A rootless body fails the inscription form inside the gate.
    h3, b3 = build_registry_v1()
    fails = check_ripcord(thread["root_a_hex"], thread["n_strands_a"],
                          thread["root_b_hex"], thread["n_strands_b"],
                          successor_blob=h3 + b3)
    assert len(fails) == 1 and "inscription form" in fails[0]


def test_check_ripcord_refuses_wrong_input_zero(thread):
    d = thread["d"]
    wrong = d.signall(d.mktx(
        [{"output": "%064x:0" % 0xB2, "value": 10 * 10 ** 8},   # funding first
         {"output": thread["cord_a"], "value": thread["cord_sat"]}],
        [{"value": 5_000_000, "address": thread["addr_a"]},
         {"value": 5_000_000, "address": thread["addr_a"]},
         {"value": thread["cord_sat"], "address": thread["addr_b"]}]),
        thread["authority_a"])
    fails = check_ripcord(thread["root_a_hex"], thread["n_strands_a"],
                          cs_serialize(wrong), 2)
    assert len(fails) == 1 and "input 0" in fails[0]


def test_check_ripcord_refuses_a_successor_with_no_fresh_cord(thread):
    d = thread["d"]
    cordless = d.signall(d.mktx(
        [{"output": thread["cord_a"], "value": thread["cord_sat"]}],
        [{"value": 5_000_000, "address": thread["addr_a"]},
         {"value": 5_000_000, "address": thread["addr_a"]}]),
        thread["authority_a"])
    fails = check_ripcord(thread["root_a_hex"], thread["n_strands_a"],
                          cs_serialize(cordless), 2)
    assert len(fails) == 1 and "re-arm" in fails[0]


def test_check_ripcord_refuses_a_parent_with_no_cord(thread):
    # A parent whose outputs are all strands cannot be amended by thread.
    d = thread["d"]
    bare = d.signall(d.mktx(
        [{"output": "%064x:0" % 0xC4, "value": 10 ** 8}],
        [{"value": 5_000_000, "address": thread["addr_a"]}]), thread["authority_a"])
    fails = check_ripcord(cs_serialize(bare), 1,
                          thread["root_b_hex"], thread["n_strands_b"])
    assert any("no cord" in f for f in fails)
