"""The genesis fan-out and the tag quarantine, gated offline.

Mirrors test_ripcord's mock-index pattern: an engine-built constitution
stand-in root carries its single genesis tag; a hand-built fan-out spends it
into three outputs (despot · amend · commentary); the quarantine derives
intact tags and refuses an undeclared sweep. Nothing on chain, no funds.
"""
import pytest

import cryptos
from cryptos import serialize as cs_serialize

from colegio_tools import _txid_of_serial
from quipu_diamond import FeePolicy, build_consolidated_diamond
from quipu_preflight import (
    check_genesis_fanout, intact_tag_outpoints, check_spends_no_intact_tags,
)
from text import build_text_quipu


@pytest.fixture(scope="module")
def genesis():
    d = cryptos.Doge()
    fp = FeePolicy()
    authority = cryptos.random_key()
    addr = d.privtoaddr(authority)

    h, b = build_text_quipu("constitution-stand-in", "x" * 400)
    TAG_SAT = 100_000_000
    art = build_consolidated_diamond(
        [("v0", h + b)], lambda pid: "f" * 64,
        {"output": "%064x:0" % 0xA1, "value": 60 * 10 ** 8},
        authority, addr, fp,
        tags_of={"v0": [{"value": TAG_SAT, "address": addr}]},
        log=lambda *a: None)
    root_hex, root_txid = art["roots"]["v0"]
    n_strands = len(art["strands"]["v0"])
    genesis_op = (root_txid, n_strands)

    # the fan-out: spends the genesis tag; exactly 3 outputs; no OP_RETURN
    SEED = TAG_SAT // 4
    fan = d.signall(d.mktx(
        [{"output": "%s:%d" % genesis_op, "value": TAG_SAT}],
        [{"value": SEED, "address": addr},      # despot
         {"value": SEED, "address": addr},      # amend
         {"value": SEED, "address": addr}]),    # commentary
        authority)
    fan_hex = cs_serialize(fan)

    # mock index: strands spent by OP_RETURN knots; genesis tag intact
    knots = {}
    for i, (txns, _txids) in enumerate(art["strands"]["v0"]):
        knots[(root_txid, i)] = txns[0]
    spends = dict(knots)

    def spend_of(txid, vout):
        v = spends.get((txid, vout))
        return (_txid_of_serial(v) if isinstance(v, str) and len(v) > 64 else v)

    def get_tx(txid):
        for v in knots.values():
            if _txid_of_serial(v) == txid:
                return v
        raise KeyError(txid)

    return {"d": d, "authority": authority, "addr": addr,
            "root_hex": root_hex, "root_txid": root_txid,
            "n_strands": n_strands, "genesis_op": genesis_op,
            "fan_hex": fan_hex, "tag_sat": TAG_SAT,
            "spend_of": spend_of, "get_tx": get_tx}


def test_lawful_fanout_passes(genesis):
    assert check_genesis_fanout(genesis["root_hex"], genesis["n_strands"],
                                genesis["fan_hex"]) == []


def test_fanout_with_wrong_output_count_refused(genesis):
    d, addr = genesis["d"], genesis["addr"]
    two = d.signall(d.mktx(
        [{"output": "%s:%d" % genesis["genesis_op"], "value": genesis["tag_sat"]}],
        [{"value": 1_000_000, "address": addr},
         {"value": 1_000_000, "address": addr}]), genesis["authority"])
    fails = check_genesis_fanout(genesis["root_hex"], genesis["n_strands"],
                                 cs_serialize(two))
    assert len(fails) == 1 and "three outputs" in fails[0]


def test_fanout_not_spending_genesis_refused(genesis):
    d, addr = genesis["d"], genesis["addr"]
    wrong = d.signall(d.mktx(
        [{"output": "%064x:0" % 0xB7, "value": genesis["tag_sat"]}],
        [{"value": 1_000_000, "address": addr},
         {"value": 1_000_000, "address": addr},
         {"value": 1_000_000, "address": addr}]), genesis["authority"])
    fails = check_genesis_fanout(genesis["root_hex"], genesis["n_strands"],
                                 cs_serialize(wrong))
    assert len(fails) == 1 and "genesis tag" in fails[0]


def test_root_with_change_output_refused(genesis):
    # N+2 discipline: a spent-without-OP_RETURN output masquerades as a tag,
    # so the constitution root may carry EXACTLY one non-strand output.
    fails = check_genesis_fanout(genesis["root_hex"], genesis["n_strands"] - 1,
                                 genesis["fan_hex"])
    assert any("N+2" in f for f in fails)


def test_quarantine_derives_and_refuses_undeclared_sweep(genesis):
    quarantine = intact_tag_outpoints([genesis["root_hex"]],
                                      genesis["spend_of"], genesis["get_tx"])
    assert genesis["genesis_op"] in quarantine
    # an undeclared tx sweeping the tag: refused
    fails = check_spends_no_intact_tags(genesis["fan_hex"], quarantine)
    assert len(fails) == 1 and "INTACT TAG" in fails[0]
    # the same tx as a DECLARED act: passes the quarantine (its own gate —
    # check_genesis_fanout — then judges the act's shape)
    assert check_spends_no_intact_tags(genesis["fan_hex"], quarantine,
                                       declared={genesis["genesis_op"]}) == []
    # an ordinary funding tx never touching a tag: passes
    d, addr = genesis["d"], genesis["addr"]
    plain = d.signall(d.mktx(
        [{"output": "%064x:0" % 0xC9, "value": 10 ** 8}],
        [{"value": 5_000_000, "address": addr}]), genesis["authority"])
    assert check_spends_no_intact_tags(cs_serialize(plain), quarantine) == []
