#!/usr/bin/env python3
"""Heal the Dantean Cosmos — inscribe the 0xab alias that resolves the phantom.

The on-chain orrery (root 1fa3a4b9…) carries an unresolved stand-in as its
fixed-stars ref: 7e0eab43… = sha256("0xce Bode Uranographia full sky"),
missed by the forest backfill. This stage inscribes ONE tiny binding:

    <<7e0eab43…>> = <<6e10058f…>>          (phantom -> Bode's real root)

Binding-aware readers then resolve the orrery's sky to the Uranographia.
Last-write-wins semantics; nothing on chain is altered, the corpus heals
by addition — its own primitive, used for exactly what it was built for.

This build goes through the full new control path: the phantom appears
ONLY as an alias left-hand (type-aware exempt); Bode's root is supplied
via known_txids from the verified forest artifacts index; preflight runs
at build, again standalone, and again at broadcast.

SIGN (touches the key — you run it):
    .venv/bin/python build_and_sign.py sign \
        --utxo <txid>:<vout>:<value_sats> --address <funder_addr> \
        --keyfile ~/Desktop/cinv/llaves/<key>.enc        # password via prompt

BROADCAST (keyless, resumable):
    .venv/bin/python build_and_sign.py broadcast
"""
import argparse
import getpass
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "canonical"))

PHANTOM = "7e0eab43f4856b3329c1c5c446bb5fe7e0ae2cc413290d0638659b5a36442fcf"
BODE    = "6e10058f59cb709bdcaaf994b1dab448053ae482970155f4c34a60c20b89f366"
ORRERY  = "1fa3a4b90af9b7ac61cb7713b3fe26d20d2e9d65da86ac00343e4115438bddb8"
ART_DIR = os.path.join(HERE, "artifacts")


def build_blob():
    from bindings import build_binding_quipu
    body = "<<%s>>=<<%s>>\n" % (PHANTOM, BODE)
    h, b = build_binding_quipu(body, tone=0x00)
    return h + b


def known_txids():
    """Verified roots from the forest artifacts index (the dataset is
    stale; these roots were confirmed at inscription, block 6,237,154)."""
    idx = json.load(open(os.path.join(REPO, "working/lineage/artifacts/index.json")))
    return {p["root"] for p in idx["pieces"]}


def sign(args):
    import cryptos
    from colegio_tools import import_privKey
    from quipu_diamond import FeePolicy, build_consolidated_diamond, write_artifacts
    from quipu_preflight import preflight

    txid, vout, value = args.utxo.split(":")
    utxo = {"output": "%s:%s" % (txid, vout), "value": int(value)}
    priv = import_privKey(os.path.expanduser(args.keyfile),
                          getpass.getpass("keyfile password: "))
    if isinstance(priv, (bytes, bytearray)):
        priv = priv.decode()
    assert cryptos.Doge().privtoaddr(priv) == args.address, \
        "key does not derive the funder address"

    blob = build_blob()
    print("healing binding: %d bytes (%d knots)" % (len(blob), (len(blob)+79)//80))
    art = build_consolidated_diamond(
        [("heal_orrery", blob)], lambda pid: "e" * 64,
        utxo, priv, args.address, FeePolicy(),
        known_txids=known_txids())
    write_artifacts(art, ART_DIR)
    preflight(ART_DIR, known_txids=known_txids())
    print("\nSIGNED + PREFLIGHT PASSED.")
    print("  root (the binding's identity): %s" % art["roots"]["heal_orrery"][1])
    print("  total cost: %.4f DOGE · residual %.4f DOGE -> %s"
          % (art["fees"]["total_sat"]/1e8, art["fees"]["residual_sat"]/1e8,
             args.address))
    print("\nBroadcast with:  .venv/bin/python build_and_sign.py broadcast")


def broadcast(_args):
    from quipu_diamond import broadcast_consolidated_diamond
    out = broadcast_consolidated_diamond(ART_DIR, known_txids=known_txids())
    print("\nHEALED. The alias is on chain.")
    print("  binding root: %s" % out["roots"]["heal_orrery"])
    print("  orrery %s…'s phantom sky now resolves to Bode for "
          "binding-aware readers." % ORRERY[:12])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sign")
    s.add_argument("--utxo", required=True, help="txid:vout:value_sats at the funder")
    s.add_argument("--address", required=True)
    s.add_argument("--keyfile", required=True)
    sub.add_parser("broadcast")
    a = ap.parse_args()
    {"sign": sign, "broadcast": broadcast}[a.cmd](a)
