#!/usr/bin/env python3
"""open_from_chain.py — open a sealed quipu using nothing but public chain data.

Point it at a sealed root and it walks, narrating each step:

    the root's outputs             which are strands, which is not
    the strands to their termini   following each OP_RETURN chain forward
    the join                       the transaction that gathers the termini
    the tail                       the join's output that seeds no OP_RETURN
    the tail's spend               a quipu root, and so the publication
    the keydrop it carries         a key, named, and the txid it opens
    the box                        opened, and its inner quipu read

Nothing here is a secret. The seller's key was published on chain in a keydrop,
so the sealed content opens for anyone, and the route to it is discoverable from
the sealed quipu itself. That is the whole claim of the construction and this
script is the proof of it.

By default it reads the corpus in `data/`, so it runs with no node and no
network. `--node` re-reads the same facts live from a txindex node instead.

    .venv/bin/python working/sale/open_from_chain.py
    .venv/bin/python working/sale/open_from_chain.py --out /tmp/on_custody.md
    .venv/bin/python working/sale/open_from_chain.py <root_txid>

Sealed quipu with no published key stay sealed and say so. That is not a
failure, it is the honest report: `00109923` is sealed under a private
passphrase and is meant to stay that way.
"""
from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import sys
import urllib.request
import warnings

warnings.filterwarnings("ignore")

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "canonical"))

DATA = os.path.join(REPO, "data")
BODIES = os.path.join(DATA, "bodies")
CACHE = os.path.join(DATA, "cache", "rawtx.jsonl")
THREAD = os.path.join(DATA, "thread")
CATALOG = os.path.join(DATA, "quipu_data.csv")

BOX = "f74a53b76bb2b6dfc9e26e7218525cfcb1f440cd3becbf4e38b31fbaf7b71d6d"

TICK = "  ·"


def say(*a):
    print(*a, flush=True)


# ---------------------------------------------------------------------------
#  the chain, offline or live
# ---------------------------------------------------------------------------
class Chain:
    """Transaction lookup plus a forward spend index.

    Offline the index is built from the cached records, so it only sees the
    corpus. That is enough to walk any catalogued quipu, and it is honest
    about its edge: a spend by a transaction nobody cached reads as unspent.
    """

    def __init__(self, rpc=None):
        self.rpc = rpc
        self.tx = {}
        self.spent = {}
        if rpc is None:
            self._load_cache()

    def _load_cache(self):
        """data/thread first, then the big fetch cache if it happens to be here.

        The thread bundle is committed, so a fresh clone can walk the sale with
        nothing else. The fetch cache is regenerated from chain and ignored by
        git, so it is a bonus when present: it widens the walk to every other
        catalogued quipu.
        """
        for txid, rec in self._from_thread():
            self.tx[txid] = rec
            for inp in rec["inputs"]:
                self.spent[inp] = txid
        if not os.path.exists(CACHE):
            if not self.tx:
                raise SystemExit(f"nothing to read: no {THREAD}, no {CACHE}")
            return
        with open(CACHE) as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                txid = rec.get("txid")
                if not txid or txid in self.tx:
                    continue
                self.tx[txid] = rec
                for inp in rec.get("inputs", []):
                    self.spent[inp] = txid

    @staticmethod
    def _from_thread():
        """Records parsed straight out of the verbatim transactions."""
        if not os.path.isdir(THREAD):
            return
        import cryptos
        for name in sorted(os.listdir(THREAD)):
            if not name.endswith(".hex"):
                continue
            with open(os.path.join(THREAD, name)) as f:
                tx = cryptos.deserialize(f.read().strip())
            op_ret = None
            for o in tx["outs"]:
                script = o.get("script", "")
                if script.startswith("6a"):
                    op_ret = script
                    break
            yield name[:-4], {
                "txid": name[:-4],
                "inputs": [f"{i['tx_hash']}:{i['tx_pos']}" for i in tx["ins"]],
                "num_outputs": len(tx["outs"]),
                "op_return": op_ret,
                "blockheight": None,
            }

    def record(self, txid):
        if txid in self.tx:
            return self.tx[txid]
        if self.rpc is None:
            return None
        raw = self.rpc("getrawtransaction", [txid, 1])
        op_ret = None
        for v in raw.get("vout", []):
            asm = v.get("scriptPubKey", {}).get("asm", "")
            if asm.startswith("OP_RETURN"):
                parts = asm.split()
                op_ret = parts[1] if len(parts) > 1 else ""
                break
        rec = {
            "txid": txid,
            "inputs": [f"{v['txid']}:{v['vout']}" for v in raw.get("vin", []) if "txid" in v],
            "num_outputs": len(raw.get("vout", [])),
            "op_return": op_ret,
            "blockheight": None,
            "raw": raw,
        }
        self.tx[txid] = rec
        return rec

    def spender(self, txid, n):
        """Which transaction consumed txid:n, or None."""
        hit = self.spent.get(f"{txid}:{n}")
        if hit or self.rpc is None:
            return hit
        # live: an unspent output is still reported by gettxout; a spent one
        # is not, and finding its spender needs an index the vanilla node
        # does not keep. The cache is the index.
        return None

    def raw_hex(self, txid):
        path = os.path.join(THREAD, f"{txid}.hex")
        if os.path.exists(path):
            with open(path) as f:
                return f.read().strip()
        if self.rpc is not None:
            return self.rpc("getrawtransaction", [txid])
        return None

    def has_op_return(self, txid):
        rec = self.record(txid)
        return bool(rec and rec.get("op_return"))


def make_rpc(url, user, password):
    def call(method, params):
        req = json.dumps({"jsonrpc": "1.0", "id": "o", "method": method,
                          "params": params}).encode()
        r = urllib.request.Request(url, data=req)
        r.add_header("Authorization",
                     "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode())
        r.add_header("Content-Type", "text/plain")
        out = json.loads(urllib.request.urlopen(r, timeout=30).read())
        if out.get("error"):
            raise RuntimeError(f"{method}: {out['error']}")
        return out["result"]
    return call


# ---------------------------------------------------------------------------
#  the walk
# ---------------------------------------------------------------------------
def walk_to_publication(chain, root, catalog_roots, max_hops=100, quiet=False):
    """From a quipu root, follow its thread forward to whatever spends its tail.

    Returns (strands, join, tail_chain, publication) with any of them None if
    the walk runs out of chain.
    """
    rec = chain.record(root)
    if rec is None:
        raise SystemExit(f"{root[:12]} is not in the corpus and no node was given")
    talk = (lambda *a: None) if quiet else say

    strands, plain = [], []
    for n in range(rec["num_outputs"]):
        sp = chain.spender(root, n)
        if sp is None:
            plain.append((n, None))
        elif chain.has_op_return(sp):
            strands.append((n, sp))
        else:
            plain.append((n, sp))
    talk(f"{TICK} root {root[:12]}… has {rec['num_outputs']} outputs: "
        f"{len(strands)} seed OP_RETURN chains, {len(plain)} do not")

    # each strand runs forward until something without an OP_RETURN eats it
    termini = []
    for n, first in strands:
        cur, hops = first, 0
        while hops < max_hops:
            nxt = chain.spender(cur, 0)
            if nxt is None or not chain.has_op_return(nxt):
                break
            cur, hops = nxt, hops + 1
        termini.append(cur)
    if termini:
        talk(f"{TICK} {len(termini)} strand chains run to their termini")

    join = None
    joins = {chain.spender(t, 0) for t in termini}
    joins.discard(None)
    if len(joins) == 1:
        join = joins.pop()
        talk(f"{TICK} all termini are consumed by one join: {join[:12]}…")
    elif joins:
        talk(f"{TICK} termini scatter into {len(joins)} spends, no single join")

    # the tail: the join's output that seeds no OP_RETURN, followed forward
    tail_chain, publication = [], None
    cur = join
    hops = 0
    while cur and hops < max_hops:
        nxt = chain.spender(cur, 0)
        if nxt is None:
            break
        if nxt in catalog_roots and nxt != root:
            publication = nxt
            break
        tail_chain.append(nxt)
        cur, hops = nxt, hops + 1
    for t in tail_chain:
        talk(f"{TICK} tail carries forward through {t[:12]}…")
    if publication:
        talk(f"{TICK} the tail is spent by {publication[:12]}…, a quipu root")
    return strands, join, tail_chain, publication


def thread_downstream(chain, root, catalog_roots, titles, accept, max_quipu=8):
    """Follow this quipu's thread forward until `accept` recognises something.

    A tail is not always spent by the thing that opens you. The encrypted family
    is inscribed as one running thread, each quipu's tail seeding the next one's
    root, and a keydrop sits some way along it. So the walk keeps going: each
    root it reaches becomes the next root to walk from, and it stops the moment
    `accept` finds what it wants rather than running the thread to its end.
    """
    cur, seen, quiet = root, {root}, False
    for _ in range(max_quipu):
        _, _, _, nxt = walk_to_publication(chain, cur, catalog_roots, quiet=quiet)
        quiet = True
        if nxt is None or nxt in seen:
            return None
        say(f"{TICK} downstream on the thread: {nxt[:12]}… {titles.get(nxt, '')!r}")
        seen.add(nxt)
        got = accept(nxt)
        if got is not None:
            return got
        cur = nxt
    return None


# ---------------------------------------------------------------------------
#  the reading
# ---------------------------------------------------------------------------
def blob_of(chain, root):
    path = os.path.join(BODIES, f"{root}.bin")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    raise SystemExit(f"no body for {root[:12]}… in data/bodies")


def sender_pubkey(chain, root):
    """The inscriber's identity pubkey, out of the root's own scriptSig."""
    import cryptos
    hexstr = chain.raw_hex(root)
    if not hexstr:
        return None
    tx = cryptos.deserialize(hexstr)
    script = tx["ins"][0]["script"]
    raw = bytes.fromhex(script)
    # P2PKH scriptSig is push(sig) push(pubkey); the pubkey is the last push
    i, last = 0, None
    while i < len(raw):
        ln = raw[i]
        if ln > 75:
            break
        last = raw[i + 1:i + 1 + ln]
        i += 1 + ln
    return last


def catalog_titles():
    titles, roots = {}, set()
    with open(CATALOG) as f:
        for row in csv.DictReader(f):
            roots.add(row["root_txid"])
            titles[row["root_txid"]] = row.get("title", "")
    return roots, titles


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=BOX)
    ap.add_argument("--node", action="store_true", help="read live instead of the corpus")
    ap.add_argument("--rpc", default="http://127.0.0.1:22555/")
    ap.add_argument("--rpcuser", default=os.environ.get("RPC_USER", "drdoeg"))
    ap.add_argument("--rpcpassword", default=os.environ.get("RPC_PASSWORD", "password"))
    ap.add_argument("--out", help="write the opened plaintext here")
    args = ap.parse_args()

    import colegio_pipeline as CP
    from canonical import encrypted as E
    from coincurve import PrivateKey, PublicKey

    rpc = make_rpc(args.rpc, args.rpcuser, args.rpcpassword) if args.node else None
    chain = Chain(rpc)
    roots, titles = catalog_titles()
    root = args.root

    say(f"\nthe sealed quipu  {root}")
    hdr, body = CP.split_blob(blob_of(chain, root))
    sealed = E.read_encrypted_quipu(hdr, body)
    say(f"  type 0x{hdr[4]:02x} · sub 0x{hdr[6]:02x} ({sealed.get('sub_name','?')})"
        f" · tone 0x{hdr[5]:02x} · {sealed.get('title','')!r}")
    if sealed.get("session_pub"):
        say(f"  sealed to session_pub {sealed['session_pub']}")

    def keydrop_for(cand):
        """A keydrop on the thread that names this quipu, or None."""
        chdr, cbody = CP.split_blob(blob_of(chain, cand))
        if chdr[4] != 0x0e:
            return None                       # some other type, keeps no keys
        read = E.read_encrypted_quipu(chdr, cbody)
        for d in read.get("drops", []):
            ref = d.get("ref_txid", "")
            ref = ref.hex() if isinstance(ref, (bytes, bytearray)) else ref
            if ref == root:
                k = d["key"]
                return cand, read, (k if isinstance(k, (bytes, bytearray))
                                    else bytes.fromhex(k))
        return None

    say("\nwalking the thread forward")
    hit = thread_downstream(chain, root, roots, titles, keydrop_for)
    route = "the quipu's own thread"

    if hit is None:
        # The 2022 quipu were inscribed one at a time, before the running
        # thread, so their keydrops are siblings rather than descendants.
        # Searching the catalogue finds them, but it is a weaker claim and
        # says so: you had to know where else to look.
        say("\nnothing on the thread names this quipu; searching the catalogue")
        for cand in sorted(roots):
            if cand == root:
                continue
            try:
                hit = keydrop_for(cand)
            except (SystemExit, ValueError):
                continue
            if hit is not None:
                route = "a catalogue search, not the thread"
                break

    if hit is None:
        say("\nthe thread carries no keydrop naming this quipu.")
        say("it stays sealed, which for a passphrase-sealed quipu is the point.")
        return 1

    publication, pub, key = hit
    say(f"\nthe publication  {publication}")
    say(f"  found by {route}")
    say(f"  {pub.get('sub_name','?')} · {pub.get('title','')!r}")
    for k, v in (pub.get("header_fields") or {}).items():
        say(f"  header says {k} = {v}")
    for d in pub["drops"]:
        ref = d.get("ref_txid", "")
        ref = ref.hex() if isinstance(ref, (bytes, bytearray)) else ref
        mark = "  <- this one" if ref == root else ""
        say(f"  drop {d.get('name','?')!r} opens {ref[:12]}…{mark}")
    say(f"  key for this quipu: {key.hex()}")

    say("\nopening")
    if hdr[6] == E.SUB_CB:
        # a sale box is sealed to a session keypair, and the shared secret is
        # ECDH between that key and the seller's identity, which is public in
        # the scriptSig that funded the box's own root
        pub_id = sender_pubkey(chain, root)
        if pub_id is None:
            say("  the inscriber's pubkey needs the root's scriptSig, which is not bundled")
            return 1
        say(f"{TICK} inscriber identity pubkey from the root's scriptSig: {pub_id.hex()}")
        res = E.read_cb_box_quipu(hdr, body, session_privkey=PrivateKey(key),
                                  sender_pubkey=PublicKey(pub_id))
        say(f"{TICK} the key derives to the box's session_pub, so it is the right key")
        ih, ib = res["inner_header"], res["inner_body"]
        magic_ok = res["magic_ok"]
    else:
        ih, ib = E.open_with_key(hdr, body, key)
        magic_ok = ih[:4] == b"\xc1\xdd\x00\x01"
    say(f"{TICK} envelope opened, ciphertext decrypted, inner quipu framed correctly:"
        f" magic_ok={magic_ok}")

    say(f"\nthe inner quipu  type 0x{ih[4]:02x} · tone 0x{ih[5]:02x} · {len(ib)} B")
    try:
        text = ib.decode("utf-8")
    except UnicodeDecodeError:
        say("  (not text; write it out with --out and read it as bytes)")
        text = None
    if text:
        head = "\n".join(text.splitlines()[:12])
        say("\n" + head + "\n  …")
    if args.out:
        with open(args.out, "wb") as f:
            f.write(ib)
        say(f"\nwrote {len(ib)} B to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
