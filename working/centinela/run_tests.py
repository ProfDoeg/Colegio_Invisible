"""Parallel on-chain test of all three centinela lock modes:
  A = pure hashlock (P2SH, bearer claim)
  B = pre-signed sweep (P2PKH)
  C = HTLC hybrid (P2SH, preimage + D-sig, CLTV refund)

  python   working/centinela/run_tests.py build     # create 3 locks, print fund targets
  python   working/centinela/run_tests.py claim      # after funding: build claims (dry)
  BROADCAST=1 python .../run_tests.py claim           # build + broadcast all, watch confirms

All claims sweep back to DEST (apocrypha), so net cost is just the claim fees.
The funding tx spends YOUR coins — you run that; this script never does.
"""
import os, sys, json, time
from pathlib import Path

THIS = Path(__file__).parent; REPO = THIS.parent.parent
sys.path.insert(0, str(REPO))
import warnings; warnings.filterwarnings("ignore")

import quipu_centinela as C
from quipu_diamond import FeePolicy
from colegio_tools import rpc_request

DEST = os.environ.get("DEST", "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX")   # apocrypha
BASE = THIS / "test3"
MODES = ["A", "B", "C"]


def build():
    BASE.mkdir(parents=True, exist_ok=True)
    h = rpc_request("getblockcount", [])
    a = C.build_hashlock(out_dir=str(BASE / "A"), note="test A hashlock")
    b = C.build_presigned_lock(out_dir=str(BASE / "B"), note="test B presigned")
    c = C.build_centinela(refund_height=h + 100000, out_dir=str(BASE / "C"), note="test C htlc")
    targets = {"A": a["p2sh_addr"], "B": b["fund_addr"], "C": c["p2sh_addr"]}
    json.dump(targets, open(BASE / "targets.json", "w"), indent=2)
    print("=== 3 centinela locks built (height %d) — fund these ===" % h)
    print("  A  hashlock (P2SH)    :", targets["A"])
    print("  B  pre-signed (P2PKH) :", targets["B"])
    print("  C  HTLC (P2SH)        :", targets["C"])
    print("\nfund all three in one tx (≈3.3 DOGE each — they sweep back to apocrypha):")
    sm = json.dumps({targets["A"]: 3.3, targets["B"]: 3.3, targets["C"]: 3.3})
    print('  dogecoin-cli sendmany "" \'%s\'' % sm)
    print("\nNOTE: Mode A is bearer/front-runnable — its claim reveals P with no signature, so in")
    print("principle a mempool watcher could redirect it. Modest amount + a healthy fee (this")
    print("script size-prices) keeps the window small; it's the known Mode-A property, on display.")


def _outpoints_from_funding(txids, targets):
    """Locate each target's funding outpoint from the funding tx(s). This node has
    no scantxoutset / address index, so we read the funding tx's vouts directly."""
    found = {}
    for txid in txids:
        rt = rpc_request("getrawtransaction", [txid, 1])
        for v in rt["vout"]:
            for m, addr in targets.items():
                if addr in v.get("scriptPubKey", {}).get("addresses", []):
                    found[m] = ("%s:%d" % (txid, v["n"]), int(round(v["value"] * 1e8)))
    return found


def _sized(make):
    """Size-price: build provisional, measure, reprice, rebuild. make(fee)->(hex,txid)."""
    prov = make(2_000_000); size = len(prov[0]) // 2
    fee = FeePolicy().fee_for_bytes(size)
    hexs, txid = make(fee)
    return hexs, txid, size, fee


def _conf(txid):
    try:
        r = rpc_request("getrawtransaction", [txid, 1])
        return 1 if r.get("blockhash") else 0
    except Exception:
        return None


def claim():
    targets = json.load(open(BASE / "targets.json"))
    bundles = {m: json.load(open(BASE / m / "bundle.json")) for m in MODES}
    txids = [t for t in os.environ.get("FUND_TXIDS", "").replace(",", " ").split() if t]
    if not txids:
        raise SystemExit("set FUND_TXIDS=<funding txid(s)> — no scantxoutset/address index on this "
                         "node, so I read the outpoints from the funding tx itself")
    found = _outpoints_from_funding(txids, targets)
    sent = {}
    for m in MODES:
        if m not in found:
            print("%s: no output to %s in funding tx(s)" % (m, targets[m])); continue
        outpoint, value = found[m]
        if m == "A":
            make = lambda fee, o=outpoint, v=value: C.build_claim_hashlock(o, v, DEST, bundles["A"], fee)
        elif m == "B":
            make = lambda fee, o=outpoint, v=value: C.sweep_p2pkh(o, v, bundles["B"]["x_priv"], DEST, fee)
        else:
            make = lambda fee, o=outpoint, v=value: C.build_claim_tx(o, v, DEST, bundles["C"], fee)
        hexs, txid, size, fee = _sized(make)
        print("%s: claim %dB, fee %.4f DOGE (%.4f/KB), %s -> apocrypha, txid %s"
              % (m, size, fee / 1e8, fee / size * 1000 / 1e8, outpoint[:18] + "…", txid[:16]))
        if os.environ.get("BROADCAST") == "1":
            try:
                print("   sent:", rpc_request("sendrawtransaction", [hexs]))
                sent[m] = txid
            except Exception as e:
                print("   *** RELAY REJECTED:", e)
        else:
            print("   (dry — set BROADCAST=1 to send)")
    if sent:
        print("\nwatching %d claim(s) confirm..." % len(sent))
        for _ in range(40):
            st = {m: _conf(t) for m, t in sent.items()}
            print("  ", {m: ("blk" if st[m] else "mempool" if st[m] == 0 else "?") for m in st})
            if all(st.get(m) for m in sent):
                print("ALL CLAIMS CONFIRMED — modes", ",".join(sent), "validated on chain"); break
            time.sleep(20)


if __name__ == "__main__":
    {"build": build, "claim": claim}.get(sys.argv[1] if len(sys.argv) > 1 else "build", build)()
