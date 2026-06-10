"""The locus rule — corrections retrieved from local context, not global.

A quipu's dangling references heal through 0xab bindings later inscribed
at the quipu's OWN root address. These tests build a miniature corpus
and prove: the healing applies, it applies transitively, it does NOT
apply from another address (locality), and it does NOT apply from before
the work (corrections come after).
"""
import csv
import os

import pytest

import colegio_pipeline as P
from bindings import build_binding_quipu
from text import build_text_quipu

SOURCE  = "1a" * 32          # the flawed quipu (e.g. the orrery)
PHANTOM = "7e" * 32          # the dangling ref inside it
TARGET  = "6e" * 32          # what the phantom should resolve to
HEAL    = "ab" * 32          # the healing binding's root
ADDR    = "DApocryphaLikeAddress111111111111"


def _mini_corpus(tmp_path, rows, bodies):
    csv_path = tmp_path / "quipu_data.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["root_txid", "address", "type_byte",
                                          "blockheight"])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    store = {}
    for txid, blob in bodies.items():
        store[txid.lower()] = blob

    def base_fetch(txid):
        if str(txid).lower() in store:
            return store[str(txid).lower()]
        raise FileNotFoundError(txid)
    return str(csv_path), base_fetch


def _healing_blob(lhs=PHANTOM, rhs=TARGET):
    h, b = build_binding_quipu("<<%s>>=<<%s>>\n" % (lhs, rhs), tone=0x00)
    return h + b


def _target_blob():
    h, b = build_text_quipu("the real Uranographia", "stars " * 30)
    return h + b


def test_phantom_heals_through_own_address(tmp_path):
    csv_path, base = _mini_corpus(tmp_path, rows=[
        {"root_txid": SOURCE, "address": ADDR, "type_byte": "0x3d", "blockheight": 100},
        {"root_txid": HEAL,   "address": ADDR, "type_byte": "0xab", "blockheight": 200},
    ], bodies={HEAL: _healing_blob(), TARGET: _target_blob()})
    fetch = P.corrected_fetcher(base, SOURCE, csv_path=csv_path)
    with pytest.raises(FileNotFoundError):
        base(PHANTOM)                                  # dangling without the rule
    assert fetch(PHANTOM) == _target_blob()            # healed through it
    assert fetch(TARGET) == _target_blob()             # direct refs untouched


def test_binding_at_other_address_does_not_apply(tmp_path):
    csv_path, base = _mini_corpus(tmp_path, rows=[
        {"root_txid": SOURCE, "address": ADDR,    "type_byte": "0x3d", "blockheight": 100},
        {"root_txid": HEAL,   "address": "DOther", "type_byte": "0xab", "blockheight": 200},
    ], bodies={HEAL: _healing_blob(), TARGET: _target_blob()})
    fetch = P.corrected_fetcher(base, SOURCE, csv_path=csv_path)
    with pytest.raises(FileNotFoundError):
        fetch(PHANTOM)          # a stranger's binding is commentary, not correction


def test_earlier_binding_does_not_apply(tmp_path):
    csv_path, base = _mini_corpus(tmp_path, rows=[
        {"root_txid": SOURCE, "address": ADDR, "type_byte": "0x3d", "blockheight": 100},
        {"root_txid": HEAL,   "address": ADDR, "type_byte": "0xab", "blockheight": 50},
    ], bodies={HEAL: _healing_blob(), TARGET: _target_blob()})
    fetch = P.corrected_fetcher(base, SOURCE, csv_path=csv_path)
    with pytest.raises(FileNotFoundError):
        fetch(PHANTOM)          # corrections come AFTER the work they correct


def test_last_write_wins_and_chains(tmp_path):
    mid = "cc" * 32
    heal2 = "ad" * 32
    csv_path, base = _mini_corpus(tmp_path, rows=[
        {"root_txid": SOURCE, "address": ADDR, "type_byte": "0x3d", "blockheight": 100},
        {"root_txid": HEAL,   "address": ADDR, "type_byte": "0xab", "blockheight": 200},
        {"root_txid": heal2,  "address": ADDR, "type_byte": "0xab", "blockheight": 300},
    ], bodies={HEAL: _healing_blob(PHANTOM, mid),       # first: phantom -> mid
               heal2: _healing_blob(mid, TARGET),       # later: mid -> target
               TARGET: _target_blob()})
    fetch = P.corrected_fetcher(base, SOURCE, csv_path=csv_path)
    assert fetch(PHANTOM) == _target_blob()             # follows the chain