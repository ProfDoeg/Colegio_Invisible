#!/usr/bin/env python3
"""Close the heal_earth diamond that couldn't close in one join.

The 575-strand combined inscription's single mega-join serialized to 103,242
bytes — over Dogecoin's 100,000-byte standard-tx ceiling, so every node
rejects it (`error -26: tx-size`). The data is all on chain and readable;
only the structural N->1 closure failed.

This closes it as a TWO-LEVEL join tree instead:
  level 1 — two sub-joins, each consolidating ~288 strand termini into one
            output (~52 KB apiece, comfortably under the limit)
  level 2 — one final join merging the two sub-join outputs into a single
            consolidated UTXO at the funder

It spends only the already-confirmed strand termini (vout 0 of each strand's
last knot tx). It inscribes nothing and re-signs no inscription bytes.

  sign:      build + sign the 3 closing txs (touches the key — you run it)
  broadcast: send the two sub-joins, then the final join (keyless)
"""
import argparse
import getpass
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "canonical"))

import cryptos
from cryptos import serialize as cs_serialize
from colegio_tools import _txid_of_serial
from quipu_diamond import FeePolicy, _measure_tx_size

ART = os.path.join(HERE, "artifacts", "diamond_combined")
CLOSE = os.path.join(HERE, "artifacts", "close")
CLI = os.path.expanduser("~/Documents/taller/dogecoin/src/dogecoin-cli")
ADDRESS = "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX"   # apocrypha / old_inscribe
STD_LIMIT = 100_000                              # MAX_STANDARD_TX_SIZE


def rpc(*a):
    out = subprocess.run([CLI] + list(a), capture_output=True, text=True)
    if out.returncode:
        raise RuntimeError(out.stderr.strip() or out.stdout.strip())
    s = out.stdout.strip()
    try:
        return json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return s


def termini():
    """(txid, vout, value_sat) for each strand's last tx vout 0, from the node.
    Fails fast if any terminus is already spent (diamond already closed)."""
    out, i = [], 0
    while True:
        p = os.path.join(ART, "strand_earth_combined_%d.txids" % i)
        if not os.path.exists(p):
            break
        last = open(p).read().split()[-1]
        u = rpc("gettxout", last, "0")
        if not u:
            raise SystemExit("terminus %s:0 not unspent — already closed?" % last)
        out.append((last, 0, int(round(u["value"] * 1e8))))
        i += 1
    return out


def load_key(keyfile):
    from colegio_tools import import_privKey
    priv = import_privKey(os.path.expanduser(keyfile),
                          getpass.getpass("keyfile password: "))
    if hasattr(priv, "to_bytes"):
        priv = priv.to_bytes().hex()
    elif isinstance(priv, (bytes, bytearray)):
        priv = priv.hex() if len(priv) == 32 else priv.decode()
    priv = priv[2:] if priv.startswith("0x") else priv
    assert cryptos.Doge().privtoaddr(priv) == ADDRESS, "key does not derive apocrypha"
    return priv


def build_join(inputs, priv, dogecs, fee):
    """Sign a P2PKH N->1 consolidation. Returns (hex, txid, out_value_sat)."""
    out_val = sum(v for _, _, v in inputs) - fee
    ins = [{"output": "%s:%d" % (t, vo), "value": v} for t, vo, v in inputs]
    hexd = cs_serialize(dogecs.signall(
        dogecs.mktx(ins, [{"value": out_val, "address": ADDRESS}]), priv))
    return hexd, _txid_of_serial(hexd), out_val


def sign(args):
    dogecs = cryptos.Doge()
    priv = load_key(args.keyfile)
    fp = FeePolicy(rate_kb=args.rate)
    term = termini()
    n = len(term)
    total = sum(v for _, _, v in term)
    try:
        est = rpc("estimatefee", "6")
        print("network estimatefee(6) = %s DOGE/kB · using %.3f" % (est, args.rate))
    except Exception:
        pass
    print("%d open termini, %.4f DOGE parked" % (n, total / 1e8))

    half = (n + 1) // 2
    batches = [term[:half], term[half:]]
    os.makedirs(CLOSE, exist_ok=True)
    sub_outs = []
    for bi, batch in enumerate(batches):
        size = _measure_tx_size(len(batch), 1, priv, ADDRESS, dogecs)
        fee = fp.fee_for_bytes(size)
        hexd, txid, outv = build_join(batch, priv, dogecs, fee)
        actual = len(hexd) // 2
        if actual >= STD_LIMIT:
            raise SystemExit("sub-join %d is %d bytes — still over the limit; "
                             "use more batches" % (bi, actual))
        open(os.path.join(CLOSE, "subjoin_%d.hex" % bi), "w").write(hexd)
        open(os.path.join(CLOSE, "subjoin_%d.txid" % bi), "w").write(txid)
        sub_outs.append((txid, 0, outv))
        print("  sub-join %d: %3d inputs · %5d bytes · fee %.4f DOGE · out %.4f -> %s"
              % (bi, len(batch), actual, fee / 1e8, outv / 1e8, txid[:16]))

    fsize = _measure_tx_size(len(sub_outs), 1, priv, ADDRESS, dogecs)
    ffee = fp.fee_for_bytes(fsize)
    fhex, ftxid, fout = build_join(sub_outs, priv, dogecs, ffee)
    open(os.path.join(CLOSE, "finaljoin.hex"), "w").write(fhex)
    open(os.path.join(CLOSE, "finaljoin.txid"), "w").write(ftxid)
    print("  final join:  %d inputs · %5d bytes · fee %.4f DOGE -> %s"
          % (len(sub_outs), len(fhex) // 2, ffee / 1e8, ftxid[:16]))

    spent = total - fout
    print("\nSIGNED. all 3 txs under the %d-byte limit." % STD_LIMIT)
    print("  consolidated output: %.4f DOGE -> apocrypha" % (fout / 1e8))
    print("  total close fee: %.4f DOGE" % (spent / 1e8))
    print("  final UTXO (the diamond's closing point): %s" % ftxid)
    print("\nBroadcast with:  close_diamond.py broadcast")


def broadcast(_args):
    import time
    sub = []
    for bi in (0, 1):
        h = open(os.path.join(CLOSE, "subjoin_%d.hex" % bi)).read().strip()
        txid = rpc("sendrawtransaction", h)
        sub.append(txid)
        print("sub-join %d sent: %s" % (bi, txid))
    # The two sub-joins together exceed the 101 KB unconfirmed-ancestor-size
    # limit, so the final join can't sit on BOTH at once. Wait for one to
    # confirm — then the remaining unconfirmed ancestor is a single ~52 KB
    # sub-join, under the limit, and the final join is accepted.
    fh = open(os.path.join(CLOSE, "finaljoin.hex")).read().strip()
    while True:
        try:
            ftxid = rpc("sendrawtransaction", fh)
            break
        except RuntimeError as e:
            if "too-long-mempool-chain" not in str(e):
                raise
            confs = [rpc("getrawtransaction", t, "1").get("confirmations", 0)
                     if isinstance(rpc("getrawtransaction", t, "1"), dict) else 0
                     for t in sub]
            print("  waiting for a sub-join to confirm (ancestor size) ... %s" % confs)
            time.sleep(60)
    print("final join sent: %s" % ftxid)
    print("\nDIAMOND CLOSING — 575 strands fold to one point.")
    print("  closing UTXO: %s" % ftxid)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sign")
    s.add_argument("--keyfile", required=True)
    s.add_argument("--rate", type=float, default=0.10,
                   help="DOGE/kB (default 0.10; bump if estimatefee is higher)")
    sub.add_parser("broadcast")
    a = ap.parse_args()
    {"sign": sign, "broadcast": broadcast}[a.cmd](a)
