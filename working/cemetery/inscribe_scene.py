"""Inscribe the cemetery 0x3d scene quipu from apocrypha.

The first canonical 0x3d scene quipu on Dogecoin: a small walkable
pet cemetery in Cazón, Provincia de Buenos Aires, with the Sky of
al-Jawza wheeling overhead. Three graves (Sparkle, Peter Bea, Paco),
six referenced quipus (5 photos + 1 celestial), one default camera.

Authored as El Ermitaño, signed by the apocrypha key.
"""
import os, sys, json, time
from pathlib import Path

THIS_DIR = Path(__file__).parent
PROJECT  = THIS_DIR.parent.parent
sys.path.insert(0, str(PROJECT))

from colegio_tools import rpc_request, unspent, import_privKey, _txid_of_serial
from cryptos import serialize as cs_serialize
import cryptos
from quipu_orchestrator import Quipu, STATE_ROOT_BUILT
from canonical.scene import build_scene_quipu


class MultiInputQuipu(Quipu):
    """Quipu variant whose root tx consumes multiple funding UTXOs.

    Used here to consolidate apocrypha's two outstanding UTXOs
    (Goethe-join terminus + a 1-DOGE leftover) into a single root tx
    so the funding topology shows a 2-input consolidation feeding
    the cemetery diamond — more interesting shape on the funding map
    than a single-UTXO root."""

    def __init__(self, privkey_hex, utxos, strand_payloads, **kw):
        primary = max(utxos, key=lambda u: u['value'])
        super().__init__(privkey_hex=privkey_hex, utxo=primary,
                         strand_payloads=strand_payloads, **kw)
        self.all_utxos = list(utxos)

    def build_root(self):
        n = len(self.strand_payloads)
        total_in = sum(u['value'] for u in self.all_utxos)
        funds = total_in - self.root_fee
        per = funds // n
        remainder = funds - per * n
        seeds = [per] * n
        seeds[0] += remainder
        self.strand_seeds = seeds

        tx = self.doge.mktx(
            self.all_utxos,
            [{"value": s, "address": self.addr} for s in seeds],
        )
        signed = self.doge.signall(tx, self.priv)
        self.root_hex = cs_serialize(signed)
        self.root_txid = _txid_of_serial(self.root_hex)
        self.state = STATE_ROOT_BUILT
        return self.root_txid

APOC_ADDR = "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX"
KEY_PATH  = "/Users/anthonyschultz/Desktop/cinv/llaves/mi_prv.enc"
TIP_SAT   = 5_000_000   # 0.05 DOGE per strand tx — project convention

TITLE  = "Cementerio de los Animales"
FIELDS = {
    "author": "El Ermitaño",
    "date":   "2026-05-22",
    "lang":   "es",
    "place":  "Cazón, Provincia de Buenos Aires, Argentina",
}

LOG_PATH = THIS_DIR / "inscribe.log"


def log(msg):
    """Direct-file logging with explicit fsync — survives crashes.
    (Threaded broadcast loggers via stdout lose lines on process death.)"""
    line = f"[{time.strftime('%H:%M:%S')}] {msg}\n"
    print(line, end="", flush=True)
    with open(LOG_PATH, "a") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())


def main():
    log("=" * 60)
    log("cemetery 0x3d scene inscription — start")
    log("=" * 60)

    # 1. load scene body, build the (header, body) bytes
    body_dict = json.loads((THIS_DIR / "scene_body.json").read_text())
    header, body = build_scene_quipu(
        title=TITLE,
        gltf_body=body_dict,
        fields=FIELDS,
    )
    log(f"built quipu: header={len(header)} B, body={len(body)} B")

    # 2. import key, consume ALL apocrypha UTXOs as root inputs
    #    (consolidates the Goethe-join terminus + the stray 1-DOGE leftover)
    priv = import_privKey(KEY_PATH, "")
    priv_hex = priv.to_hex()[2:] if priv.to_hex().startswith("0x") else priv.to_hex()
    utxos = sorted(unspent(APOC_ADDR), key=lambda u: -u['value'])
    log(f"apocrypha has {len(utxos)} UTXOs")
    for u in utxos:
        log(f"  in:  {u['output']}  = {u['value']/1e8} DOGE")
    total_in = sum(u['value'] for u in utxos)
    log(f"total input value: {total_in/1e8} DOGE")
    if total_in < 200_000_000:
        raise RuntimeError("apocrypha total < 2 DOGE — top up before inscribing")

    # 3. configure MultiInputQuipu — N inputs → 2-strand diamond
    q = MultiInputQuipu(
        privkey_hex=priv_hex,
        utxos=utxos,
        strand_payloads=[header, body],
        tip=TIP_SAT,
        root_fee=TIP_SAT,
        join_fee=TIP_SAT,
    )

    # 4. build + broadcast root
    root_txid = q.build_root()
    log(f"root_txid (= scene quipu id): {root_txid}")
    q.broadcast_root()
    log("root broadcast — waiting for confirmation…")
    q.wait_root_confirmed(on_poll=lambda e, c: log(f"  root confs={c} ({e}s)"))
    log("root confirmed")

    # 5. precompute + broadcast strands
    seeds_info = q.precompute_strands()
    log(f"strands precomputed: {[(i, n) for i, (_, n) in enumerate(seeds_info)]}")
    q.broadcast_strands(on_tx=lambda si, ti, txid:
                        log(f"  strand {si} tx {ti}: {txid}"))
    log("all strand txs broadcast — waiting for terminus confirmations…")
    q.wait_strands_confirmed(on_poll=lambda e, n, t:
                             log(f"  strands {n}/{t} confirmed ({e}s)"))
    log("all strand termini confirmed")

    # 6. build + broadcast join
    join_txid = q.build_join()
    log(f"join_txid: {join_txid}")
    q.broadcast_join()
    log("join broadcast")

    # 7. dump the result
    result = {
        "root_txid":   root_txid,
        "join_txid":   join_txid,
        "header_hex":  header.hex(),
        "header_len":  len(header),
        "body_len":    len(body),
        "title":       TITLE,
        "fields":      FIELDS,
        "broadcast":   time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "address":     APOC_ADDR,
        "type_byte":   "0x3d",
        "type_name":   "scene",
    }
    out_path = THIS_DIR / "inscription_result.json"
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    log(f"wrote {out_path}")
    log("DONE")


if __name__ == "__main__":
    main()
