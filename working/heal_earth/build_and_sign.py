#!/usr/bin/env python3
"""Heal the orrery's Earth — give the globe its coasts, on chain.

The Dantean Cosmos' earth sphere refs the Italian Journey (762043aa…).
The 3D viewer has always drawn a world coastline on that globe from a
local asset; the chain never carried it. Two inscriptions close the gap:

  1. the COMBINED earth quipu (built by build_combined.py): the Italian
     Journey byte-faithful + 50m world coasts + the journey's five lakes
  2. CATALOG EDITION 2 — the v4 ToC form of the heal_orrery catalog,
     carried forward whole: same default subject (the orrery), the Bode
     correction AND the new <<journey>>=<<combined>> correction, the full
     subjects table, plus the atlas named <<coasts>>. Funded by SPENDING
     edition 1's tag output — the correction thread: readers follow the
     spend to find this edition; its own 0.5-DOGE tag awaits edition 3.

Binding-aware readers of the orrery then resolve Earth's surface to
journey + coasts + lakes (filling the journey's own named lacuna,
"Lacuna of Lago di Lugano"). The original journey stays on chain,
untouched — the corpus heals by addition, its own primitive, third use.

STAGE 1 — the combined quipu (touches the key — you run it):
    .venv/bin/python build_and_sign.py sign-combined \
        --utxo <txid>:<vout>:<value_sats> --address <funder_addr> \
        --keyfile ~/Desktop/cinv/llaves/<key>.enc
    .venv/bin/python build_and_sign.py broadcast-combined

STAGE 2 — catalog edition 2 (needs stage 1's root; spends the tag):
    .venv/bin/python build_and_sign.py sign-catalog \
        --subject <combined_root_txid> --address <funder_addr> \
        --keyfile ~/Desktop/cinv/llaves/<key>.enc
    .venv/bin/python build_and_sign.py broadcast-catalog
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

JOURNEY = "762043aaaed3fd92d3e129aa94ffb53753ad0e98a58f3fd7ab816379c13de9c4"
ORRERY = "1fa3a4b90af9b7ac61cb7713b3fe26d20d2e9d65da86ac00343e4115438bddb8"
PHANTOM = "7e0eab43f4856b3329c1c5c446bb5fe7e0ae2cc413290d0638659b5a36442fcf"
BODE = "6e10058f59cb709bdcaaf994b1dab448053ae482970155f4c34a60c20b89f366"
# <<coasts>> — the combined earth quipu, inscribed 2026-06-12 (13,774 knots)
COASTS = "97356eb571b58822fe473eb67179a4da09908466013512eef4f761b35d0f8025"
COMBINED_BIN = os.path.join(HERE, "artifacts", "earth_combined.0xce.bin")
ART_COMBINED = os.path.join(HERE, "artifacts", "diamond_combined")
ART_CATALOG = os.path.join(HERE, "artifacts", "diamond_catalog")

# Edition 1 of the catalog (heal_orrery, the Bode heal) and its correction
# thread: the tag output whose SPEND announces the next edition. UNSPENT =
# current. This edition (2) is funded by spending that tag.
CATALOG_V1 = "34316f64559d5825e3ecb6a617af7f3650e8563ca23a6d4e47089e7feb1d30d1"
TAG_OUTPOINT = CATALOG_V1 + ":2:100000000"      # 1 DOGE at the funder

# The Gana forest, verbatim from edition 1's subjects (on-chain facts).
FOREST = [
    ("bode", "6e10058f59cb709bdcaaf994b1dab448053ae482970155f4c34a60c20b89f366"),
    ("playmobil", "5dc8ed119de6e5470f6239d712a9dda9af106249c1023eec60aebb22aca102fe"),
    ("campagna", "ebaefd3e99b46ce1c6282209134f07990524ffe4a5bf1f2a6905905be0c0eda6"),
    ("tower", "ac915b7bdf9f37b2eafaf9f9b6c6c974220d5336b39237c3127661d0dc399ce8"),
    ("gana", "e00a1ace3afd59c005143a6354a6ff42e2b0dda246d3213a7a40836d3375600a"),
    ("jung_quote", "62c2b42750c8ae44309cee68e7c40ae7639144124f97d6db0fc0d13df13751f0"),
    ("journey", "762043aaaed3fd92d3e129aa94ffb53753ad0e98a58f3fd7ab816379c13de9c4"),
    ("goethe_gen", "77cd55bded8ea5ea5757e7526512cbfe276d89c88d1b01206f968ea8ad147061"),
    ("orrery", "1fa3a4b90af9b7ac61cb7713b3fe26d20d2e9d65da86ac00343e4115438bddb8"),
    ("jung_gen", "f2da803b67290489b001aefb517449ca784b532dda0b398a5490b5f9ce4e393e"),
    ("b_etym", "8d1e3b6c89f8bfc1f4e706e2cbe6774919126e9754b849e4bd673e82a0271ddb"),
    ("b_lineage", "b4d023875aa649440c34c05095437b4cd43c5c1eddfd53d6829c40ea1f2a1023"),
    ("b_journey", "9b845cdeb1e8a7ab8d364fa18c5c8f7bcf699471bbd0d2a302ac16efb748626f"),
    ("b_descent", "1aeb468d341b33efc75f1b70bbec1740dc9f08bb0b8ace621c2f6ca0dd8129f5"),
    ("b_shiva", "a8949b8248c476c4e93cb1c419d4da176f133b7862f5bdc26fede843194a68d6"),
    ("b_eranos", "83baf5826ffe4971e6e01fa4cf8d42f2334f69adcf627b34b365648dec80457d"),
    ("b_antarctica", "6f46b42033dea9dc5a3fb2a8b6b141c2eac6316872ea9792c6f50b45deab9907"),
]


def known_txids(extra=()):
    base = {JOURNEY, ORRERY, BODE, CATALOG_V1, COASTS} | {r for _, r in FOREST} | set(extra)
    idx_path = os.path.join(REPO, "working/lineage/artifacts/index.json")
    if os.path.exists(idx_path):                # forest index (old-Mac artifacts)
        idx = json.load(open(idx_path))
        base |= {p["root"] for p in idx["pieces"]}
    return base


def catalog_blob(combined_root):
    """Catalog edition 2 — the v4 ToC form of edition 1, carried forward:
    same default subject, ALL corrections (Bode heal + the new Earth heal),
    the full subjects table, plus the combined earth named <<coasts>>."""
    from bindings import build_binding_quipu
    from tone import TONE_HOPE                  # esperanza, as both heals
    body = "<<%s>>\n" % ORRERY                  # default subject (bare call)
    body += "______ corrections ______\n"
    body += "<<%s>>=<<%s>>\n" % (PHANTOM, BODE)           # edition 1's heal
    body += "<<%s>>=<<%s>>\n" % (JOURNEY, combined_root)  # the Earth heal
    body += "______ subjects ______\n"
    for pid, root in FOREST:
        body += "<<%s>>=<<%s>>\n" % (pid, root)
    body += "<<coasts>>=<<%s>>\n" % combined_root         # the atlas, by name
    h, b = build_binding_quipu(body, tone=TONE_HOPE)
    return h + b


def _load_key(args):
    import cryptos
    from colegio_tools import import_privKey
    priv = import_privKey(os.path.expanduser(args.keyfile),
                          getpass.getpass("keyfile password: "))
    if hasattr(priv, "to_bytes"):               # eth_keys.PrivateKey
        priv = priv.to_bytes().hex()
    elif isinstance(priv, (bytes, bytearray)):
        priv = priv.hex() if len(priv) == 32 else priv.decode()
    priv = priv[2:] if priv.startswith("0x") else priv
    assert cryptos.Doge().privtoaddr(priv) == args.address, \
        "key does not derive the funder address"
    return priv


def _sign_one(args, pid, blob, art_dir, extra_known=()):
    from quipu_diamond import FeePolicy, build_consolidated_diamond, write_artifacts
    from quipu_preflight import preflight
    txid, vout, value = args.utxo.split(":")
    utxo = {"output": "%s:%s" % (txid, vout), "value": int(value)}
    priv = _load_key(args)
    print("%s: %d bytes (%d knots) at %.3f DOGE/kB"
          % (pid, len(blob), (len(blob) + 79) // 80, args.rate))
    art = build_consolidated_diamond(
        [(pid, blob)], lambda _pid: "e" * 64,
        utxo, priv, args.address, FeePolicy(rate_kb=args.rate),
        tags_of={pid: [{"value": 100_000_000, "address": args.address}]},
        known_txids=known_txids(extra_known))
    write_artifacts(art, art_dir)
    preflight(art_dir, known_txids=known_txids(extra_known))
    print("\nSIGNED + PREFLIGHT PASSED.")
    print("  root: %s" % art["roots"][pid][1])
    print("  total cost: %.4f DOGE · residual %.4f DOGE -> %s"
          % (art["fees"]["total_sat"] / 1e8, art["fees"]["residual_sat"] / 1e8,
             args.address))


def sign_combined(args):
    blob = open(COMBINED_BIN, "rb").read()
    _sign_one(args, "earth_combined", blob, ART_COMBINED)
    print("\nBroadcast with:  .venv/bin/python build_and_sign.py broadcast-combined")


def broadcast_combined(_args):
    from quipu_diamond import broadcast_consolidated_diamond
    out = broadcast_consolidated_diamond(ART_COMBINED, known_txids=known_txids())
    print("\nCOMBINED EARTH ON CHAIN.")
    print("  root: %s" % out["roots"]["earth_combined"])
    print("\nNow stage 2:  sign-binding --subject %s ..." % out["roots"]["earth_combined"])


def sign_catalog(args):
    """Edition 2, funded by SPENDING edition 1's tag (the correction thread:
    readers follow the spend; the old catalog stops being current the moment
    this confirms). The 1-DOGE tag must cover fees + the next edition's tag,
    so this stage runs at the measured rate (0.02 DOGE/kB — the slow lane;
    ~35 knots, build_cpfp.py can accelerate if ever needed) and seeds the
    next tag at 0.5 DOGE.

    Tag rule (docs/design/tag-architecture.md — "identified by absence"):
    a tag is a root output with no OP_RETURN chain on it, and its spend
    toward the successor "may pass through a funding splitter"
    (docs/quipu-types/bindings.md, the correction thread). Satisfied here:
    the diamond spends the tag via its splitter, value outputs only."""
    from quipu_diamond import FeePolicy, build_consolidated_diamond, write_artifacts
    from quipu_preflight import preflight
    if args.utxo != TAG_OUTPOINT:
        print("WARNING: not spending edition 1's tag (%s) — the correction "
              "thread will NOT mark this as the successor." % TAG_OUTPOINT)
    txid, vout, value = args.utxo.split(":")
    utxo = {"output": "%s:%s" % (txid, vout), "value": int(value)}
    priv = _load_key(args)
    blob = catalog_blob(args.subject)
    print("catalog edition 2: %d bytes (%d knots)" % (len(blob), (len(blob) + 79) // 80))
    art = build_consolidated_diamond(
        [("heal_earth", blob)], lambda _pid: "e" * 64,
        utxo, priv, args.address, FeePolicy(rate_kb=0.02),
        tags_of={"heal_earth": [{"value": 50_000_000,        # next edition's tag
                                 "address": args.address}]},
        known_txids=known_txids((args.subject,)))
    write_artifacts(art, ART_CATALOG)
    preflight(ART_CATALOG, known_txids=known_txids((args.subject,)))
    print("\nSIGNED + PREFLIGHT PASSED.")
    print("  root: %s" % art["roots"]["heal_earth"][1])
    print("  total cost: %.4f DOGE · residual %.4f DOGE -> %s"
          % (art["fees"]["total_sat"] / 1e8, art["fees"]["residual_sat"] / 1e8,
             args.address))
    print("\nBroadcast with:  .venv/bin/python build_and_sign.py broadcast-catalog")


def broadcast_catalog(_args):
    from quipu_diamond import broadcast_consolidated_diamond
    out = broadcast_consolidated_diamond(ART_CATALOG, known_txids=known_txids())
    print("\nHEALED. The Earth has its coasts and lakes; the lacuna of "
          "Lago di Lugano is filled.")
    print("  catalog edition 2 root: %s" % out["roots"]["heal_earth"])
    print("  carried forward: phantom->Bode; new: journey->combined; "
          "the atlas is callable as <<coasts>>.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("sign-combined", "sign-catalog"):
        s = sub.add_parser(name)
        s.add_argument("--utxo", required=(name == "sign-combined"),
                       default=(None if name == "sign-combined" else TAG_OUTPOINT),
                       help="txid:vout:value_sats (sign-catalog defaults to "
                            "edition 1's tag — the correction thread)")
        s.add_argument("--address", required=True)
        s.add_argument("--keyfile", required=True)
        s.add_argument("--rate", type=float, default=0.05,
                       help="DOGE/kB fee rate (default 0.05 — above the "
                            "sub-0.02 mempool queue as measured 2026-06-12)")
        if name == "sign-catalog":
            s.add_argument("--subject", required=True,
                           help="root txid of the inscribed combined quipu")
    sub.add_parser("broadcast-combined")
    sub.add_parser("broadcast-catalog")
    a = ap.parse_args()
    {"sign-combined": sign_combined, "broadcast-combined": broadcast_combined,
     "sign-catalog": sign_catalog, "broadcast-catalog": broadcast_catalog}[a.cmd](a)
