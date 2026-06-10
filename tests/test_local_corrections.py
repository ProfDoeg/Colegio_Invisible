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


def _lens_blob(subject, lhs=PHANTOM, rhs=TARGET):
    h, b = build_binding_quipu("<<%s>>\n<<%s>>=<<%s>>\n" % (subject, lhs, rhs),
                               tone=0x00)
    return h + b


def test_lens_binding_is_a_calling_point(tmp_path):
    """A 0xab with ONE import + aliases: citing it calls the subject, with
    the corrections riding along — the new calling mechanism."""
    LENS = "1e" * 32
    sh, sb = build_text_quipu("the subject work", "refs <<%s>> inside, %s"
                              % (PHANTOM, "z" * 60))
    subject_blob = sh + sb
    _, base = _mini_corpus(tmp_path, rows=[], bodies={
        LENS: _lens_blob(SOURCE), SOURCE: subject_blob, TARGET: _target_blob()})
    subj, fetch = P.resolve_call(LENS, base)
    assert subj == SOURCE, "lens did not resolve to its subject"
    assert fetch(SOURCE) == subject_blob
    assert fetch(PHANTOM) == _target_blob(), "lens aliases did not ride along"


def test_vocabulary_binding_is_not_a_lens(tmp_path):
    _, base = _mini_corpus(tmp_path, rows=[], bodies={HEAL: _healing_blob()})
    subj, _ = P.resolve_call(HEAL, base)        # aliases only, no import
    assert subj == HEAL, "a vocabulary binding must resolve to itself"


def test_lenses_stack_with_depth_cap(tmp_path):
    L1, L2 = "2e" * 32, "3e" * 32
    sh, sb = build_text_quipu("subject", "plain " * 20)
    _, base = _mini_corpus(tmp_path, rows=[], bodies={
        L2: _lens_blob(L1, lhs="9a" * 32, rhs="9b" * 32),   # edition of an edition
        L1: _lens_blob(SOURCE), SOURCE: sh + sb, TARGET: _target_blob()})
    subj, fetch = P.resolve_call(L2, base)
    assert subj == SOURCE
    assert fetch(PHANTOM) == _target_blob()     # L1's healing still rides


def test_catalog_binding_names_multiple_healed_subjects(tmp_path):
    """One 0xab healing SEVERAL works, each callable by name — the
    catalog form: <<binding>><<orrery>> etc., corrections riding on all."""
    CAT = "4e" * 32
    WORK2, PH2, TGT2 = "5a" * 32, "5e" * 32, "5f" * 32
    sh1, sb1 = build_text_quipu("work one", "alpha " * 20)
    sh2, sb2 = build_text_quipu("work two", "beta " * 20)
    th, tb = build_text_quipu("second target", "gamma " * 20)
    catalog = ("<<orrery>>=<<%s>>\n" % SOURCE +
               "<<journey>>=<<%s>>\n" % WORK2 +
               "<<viaje>>=<<journey>>\n" +              # name -> name chain
               "<<%s>>=<<%s>>\n" % (PHANTOM, TARGET) +  # healing for work one
               "<<%s>>=<<%s>>\n" % (PH2, TGT2))         # healing for work two
    ch, cb = build_binding_quipu(catalog, tone=0x00)
    _, base = _mini_corpus(tmp_path, rows=[], bodies={
        CAT: ch + cb, SOURCE: sh1 + sb1, WORK2: sh2 + sb2,
        TARGET: _target_blob(), TGT2: th + tb})

    subj, fetch = P.resolve_call(CAT, base, name="orrery")
    assert subj == SOURCE and fetch(PHANTOM) == _target_blob()
    subj, fetch = P.resolve_call(CAT, base, name="journey")
    assert subj == WORK2 and fetch(PH2) == th + tb      # both healings ride
    subj, _ = P.resolve_call(CAT, base, name="viaje")
    assert subj == WORK2, "name->name chain did not follow"
    with pytest.raises(KeyError):
        P.resolve_call(CAT, base, name="nonexistent")
    subj, _ = P.resolve_call(CAT, base)                 # bare call, no import
    assert subj == CAT, "catalog without import must not pick a default"


def test_correction_thread_follows_tag_spends(tmp_path):
    """Anthony's correction thread: catalog1 carries a tag_out; catalog2
    is funded by spending it. With spend callables, readers merge
    catalog2 over catalog1 (UTXO order = write order); an unspent tag
    means the catalog in hand is the current edition."""
    import cryptos
    from colegio_tools import _txid_of_serial
    from quipu_diamond import FeePolicy, build_consolidated_diamond
    priv = cryptos.random_key()
    addr = cryptos.Doge().privtoaddr(priv)
    T2 = "f2" * 32
    sh, sb = build_text_quipu("subject", "cites <<%s>> deep, %s" % (PHANTOM, "w" * 60))
    t2h, t2b = build_text_quipu("target two", "dos " * 20)
    h1, b1 = build_binding_quipu("<<%s>>\n<<%s>>=<<%s>>\n" % (SOURCE, PHANTOM, TARGET))
    h2, b2 = build_binding_quipu("<<%s>>=<<%s>>\n" % (PHANTOM, T2))
    cat1, cat2 = h1 + b1, h2 + b2
    TAG = 100_000_000

    art1 = build_consolidated_diamond(
        [("cat1", cat1)], lambda p: "9" * 64,
        {"output": "%064x:0" % 0xE1, "value": 30 * 10**8}, priv, addr,
        FeePolicy(), tags_of={"cat1": [{"value": TAG, "address": addr}]},
        known_txids={SOURCE, TARGET, PHANTOM}, log=lambda *a: None)
    root1_hex, root1 = art1["roots"]["cat1"]
    tag_vout = art1["tags"]["cat1"][0]["vout"]
    art2 = build_consolidated_diamond(                 # funded BY THE TAG
        [("cat2", cat2)], lambda p: "8" * 64,
        {"output": "%s:%d" % (root1, tag_vout), "value": TAG}, priv, addr,
        FeePolicy(), known_txids={T2, PHANTOM}, log=lambda *a: None)
    splitter2_hex, splitter2 = art2["splitter"]
    root2_hex, root2 = art2["roots"]["cat2"]

    spends = {(root1, i): txns[0]
              for i, (txns, _) in enumerate(art1["strands"]["cat1"])}
    spends[(root1, tag_vout)] = splitter2_hex          # the thread stitch
    spends[(splitter2, 0)] = root2_hex
    all_tx = {root1: root1_hex, splitter2: splitter2_hex, root2: root2_hex}
    all_tx.update({_txid_of_serial(v): v for v in spends.values()})
    spend_of = lambda txid, vout: (_txid_of_serial(spends[(txid, vout)])
                                   if (txid, vout) in spends else None)
    get_tx = lambda txid: all_tx[txid]

    store = {root1.lower(): cat1, root2.lower(): cat2,
             SOURCE: sh + sb, TARGET: _target_blob(), T2: t2h + t2b}

    def base(txid):
        if str(txid).lower() in store:
            return store[str(txid).lower()]
        raise FileNotFoundError(txid)

    subj, fetch = P.resolve_call(root1, base)          # thread NOT followed
    assert subj == SOURCE and fetch(PHANTOM) == _target_blob()
    subj, fetch = P.resolve_call(root1, base,          # thread followed
                                 spend_of=spend_of, get_tx=get_tx)
    assert subj == SOURCE and fetch(PHANTOM) == t2h + t2b, \
        "catalog2 did not merge over catalog1"
    del spends[(root1, tag_vout)]                      # tag unspent again
    subj, fetch = P.resolve_call(root1, base,
                                 spend_of=spend_of, get_tx=get_tx)
    assert fetch(PHANTOM) == _target_blob(), \
        "unspent tag must mean: this catalog is current"


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