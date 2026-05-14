"""
quipu_orchestrator.py — Two-phase quipu builder.

Phase 1 (instantiate): build and broadcast the root tx (1 input → N outputs).
                       Wait for confirmation.

Phase 2 (fill):        precompute and broadcast all N strands in parallel.
                       Each strand is its own CadenaAtom — independent ancestor
                       chains rooted at the now-confirmed root tx. Each strand
                       can have up to ~25 txs in mempool simultaneously (the
                       per-tx ancestor limit). With N strands of length M, total
                       in-flight mempool descendants = N × M, all parallel.

Phase 3 (close, opt):  joining tx (N inputs from strand termini → 1 output to
                       self). Consolidates the strand-end UTXOs back into one
                       so the next quipu can open from a single input.

The state machine progresses INIT → ROOT_BUILT → ROOT_BROADCAST → ROOT_CONFIRMED
→ STRANDS_PRECOMPUTED → STRANDS_BROADCAST → STRANDS_CONFIRMED → JOINED.
"""

import time
import cryptos
from cryptos import serialize as cs_serialize

from colegio_tools import (
    rpc_request,
    CadenaAtom,
    _txid_of_serial,
)


# State constants
STATE_INIT = "INIT"
STATE_ROOT_BUILT = "ROOT_BUILT"
STATE_ROOT_BROADCAST = "ROOT_BROADCAST"
STATE_ROOT_CONFIRMED = "ROOT_CONFIRMED"
STATE_STRANDS_PRECOMPUTED = "STRANDS_PRECOMPUTED"
STATE_STRANDS_BROADCAST = "STRANDS_BROADCAST"
STATE_STRANDS_CONFIRMED = "STRANDS_CONFIRMED"
STATE_JOIN_BUILT = "JOIN_BUILT"
STATE_JOIN_BROADCAST = "JOIN_BROADCAST"
STATE_DONE = "DONE"


class Quipu:
    """Two-phase quipu builder.

    Args:
        privkey_hex: signing key as hex string (no 0x prefix)
        utxo:        {"output": "txid:vout", "value": int_satoshis}
        strand_payloads: list of bytes
                         [0] = header (cabeza) bytes including protocol header
                         [1:] = body strand payloads
        tip:         per-strand-tx fee in satoshis (default 0.05 DOGE)
        root_fee:    fee for the root tx (default 0.05 DOGE)
        join_fee:    fee for the joining tx (default 0.05 DOGE)
    """

    def __init__(
        self,
        privkey_hex,
        utxo,
        strand_payloads,
        tip=5_000_000,
        root_fee=5_000_000,
        join_fee=5_000_000,
    ):
        if len(strand_payloads) < 1:
            raise ValueError("need at least one strand (the cabeza)")
        if len(strand_payloads) > 255:
            raise ValueError("max 255 strands per quipu")

        self.priv = privkey_hex
        self.utxo = utxo
        self.strand_payloads = strand_payloads
        self.tip = tip
        self.root_fee = root_fee
        self.join_fee = join_fee

        self.doge = cryptos.Doge()
        self.addr = self.doge.privtoaddr(privkey_hex)

        self.state = STATE_INIT
        self.root_txid = None
        self.root_hex = None
        self.strand_seeds = None
        self.strands = []  # list of CadenaAtom
        self.join_txid = None
        self.join_hex = None

    # -----------------------------------------------------------------
    # Phase 1 — instantiate (root tx)
    # -----------------------------------------------------------------

    def build_root(self):
        """Build and sign the root tx. Does not broadcast.
        Allocates utxo value across N strand outputs, with any remainder
        added to the first (header) strand."""
        n = len(self.strand_payloads)
        funds = self.utxo["value"] - self.root_fee
        per = funds // n
        remainder = funds - per * n
        seeds = [per] * n
        seeds[0] += remainder
        self.strand_seeds = seeds

        tx = self.doge.mktx(
            [self.utxo],
            [{"value": s, "address": self.addr} for s in seeds],
        )
        signed = self.doge.signall(tx, self.priv)
        self.root_hex = cs_serialize(signed)
        self.root_txid = _txid_of_serial(self.root_hex)
        self.state = STATE_ROOT_BUILT
        return self.root_txid

    def broadcast_root(self):
        """Send the root tx to the node. Must call build_root first."""
        if self.state != STATE_ROOT_BUILT:
            raise RuntimeError(f"can't broadcast_root from {self.state}")
        returned = rpc_request("sendrawtransaction", [self.root_hex])
        if returned != self.root_txid:
            raise RuntimeError(
                f"node returned txid {returned}, expected {self.root_txid}"
            )
        self.state = STATE_ROOT_BROADCAST
        return returned

    def wait_root_confirmed(self, max_wait=600, poll=15, on_poll=None):
        """Block until the root tx has at least 1 confirmation.
        on_poll(elapsed_s, confs) is called each cycle, for UI updates."""
        if self.state not in (STATE_ROOT_BROADCAST, STATE_ROOT_CONFIRMED):
            raise RuntimeError(f"can't wait from {self.state}")
        if self.state == STATE_ROOT_CONFIRMED:
            return True
        start = time.time()
        while time.time() - start < max_wait:
            try:
                t = rpc_request("gettransaction", [self.root_txid, True])
                confs = t.get("confirmations", 0)
                if on_poll:
                    on_poll(int(time.time() - start), confs)
                if confs >= 1:
                    self.state = STATE_ROOT_CONFIRMED
                    return True
            except Exception:
                if on_poll:
                    on_poll(int(time.time() - start), -1)
            time.sleep(poll)
        return False

    # -----------------------------------------------------------------
    # Phase 2 — fill (precompute + broadcast all strands)
    # -----------------------------------------------------------------

    def precompute_strands(self):
        """Build and sign every strand tx. No network calls.
        Requires root_txid to be known (build_root has run)."""
        if self.state not in (STATE_ROOT_BUILT, STATE_ROOT_BROADCAST, STATE_ROOT_CONFIRMED):
            raise RuntimeError(f"can't precompute from {self.state}")
        self.strands = []
        for i, payload in enumerate(self.strand_payloads):
            cad = CadenaAtom(
                self.priv,
                payload,
                {"output": f"{self.root_txid}:{i}", "value": self.strand_seeds[i]},
                self.tip,
            )
            cad.precompute()
            self.strands.append(cad)
        self.state = STATE_STRANDS_PRECOMPUTED
        return [(c.txn_ids, len(c.txns)) for c in self.strands]

    def broadcast_strands(self, on_tx=None):
        """Send every strand tx into mempool.
        Within each strand: txs must go in dependency order.
        Across strands: independent — they can interleave in any order.

        on_tx(strand_index, tx_index, txid) is called for each successful send.

        Returns list of (strand_index, terminus_txid, total_txs_in_strand)."""
        if self.state != STATE_STRANDS_PRECOMPUTED:
            raise RuntimeError(f"can't broadcast strands from {self.state}")
        results = []
        for si, cad in enumerate(self.strands):
            for ti, (hex_str, txid) in enumerate(zip(cad.txns, cad.txn_ids)):
                returned = rpc_request("sendrawtransaction", [hex_str])
                if returned != txid:
                    raise RuntimeError(
                        f"strand {si} tx {ti}: node returned {returned}, "
                        f"expected {txid}"
                    )
                if on_tx:
                    on_tx(si, ti, txid)
            results.append((si, cad.txn_ids[-1], len(cad.txns)))
        self.state = STATE_STRANDS_BROADCAST
        return results

    def wait_strands_confirmed(self, max_wait=600, poll=15, on_poll=None):
        """Wait until every strand terminus tx has ≥1 confirmation."""
        if self.state not in (STATE_STRANDS_BROADCAST, STATE_STRANDS_CONFIRMED):
            raise RuntimeError(f"can't wait from {self.state}")
        if self.state == STATE_STRANDS_CONFIRMED:
            return True
        terminus_txids = [c.txn_ids[-1] for c in self.strands]
        start = time.time()
        while time.time() - start < max_wait:
            confs_per = []
            for txid in terminus_txids:
                try:
                    t = rpc_request("gettransaction", [txid, True])
                    confs_per.append(t.get("confirmations", 0))
                except Exception:
                    confs_per.append(-1)
            elapsed = int(time.time() - start)
            n_confirmed = sum(1 for c in confs_per if c >= 1)
            if on_poll:
                on_poll(elapsed, n_confirmed, len(terminus_txids))
            if n_confirmed == len(terminus_txids):
                self.state = STATE_STRANDS_CONFIRMED
                return True
            time.sleep(poll)
        return False

    # -----------------------------------------------------------------
    # Phase 3 — close (joining tx, optional)
    # -----------------------------------------------------------------

    def build_join(self):
        """Build the joining tx: N inputs from strand termini → 1 output back
        to self. Consolidates the strand termini into a single UTXO."""
        if self.state != STATE_STRANDS_CONFIRMED:
            raise RuntimeError(f"can't build join from {self.state}")
        inputs = []
        for i, cad in enumerate(self.strands):
            terminus_value = self.strand_seeds[i] - self.tip * len(cad.txns)
            inputs.append(
                {"output": f"{cad.txn_ids[-1]}:0", "value": terminus_value}
            )
        total = sum(i["value"] for i in inputs)
        output_value = total - self.join_fee
        if output_value <= 0:
            raise RuntimeError("joining tx would have non-positive output")
        tx = self.doge.mktx(inputs, [{"value": output_value, "address": self.addr}])
        signed = self.doge.signall(tx, self.priv)
        self.join_hex = cs_serialize(signed)
        self.join_txid = _txid_of_serial(self.join_hex)
        self.state = STATE_JOIN_BUILT
        return self.join_txid

    def broadcast_join(self):
        """Send the joining tx."""
        if self.state != STATE_JOIN_BUILT:
            raise RuntimeError(f"can't broadcast_join from {self.state}")
        returned = rpc_request("sendrawtransaction", [self.join_hex])
        if returned != self.join_txid:
            raise RuntimeError(
                f"node returned {returned}, expected {self.join_txid}"
            )
        self.state = STATE_JOIN_BROADCAST
        return returned

    def wait_join_confirmed(self, max_wait=600, poll=15, on_poll=None):
        """Wait for joining tx confirmation."""
        if self.state not in (STATE_JOIN_BROADCAST, STATE_DONE):
            raise RuntimeError(f"can't wait from {self.state}")
        if self.state == STATE_DONE:
            return True
        start = time.time()
        while time.time() - start < max_wait:
            try:
                t = rpc_request("gettransaction", [self.join_txid, True])
                confs = t.get("confirmations", 0)
                if on_poll:
                    on_poll(int(time.time() - start), confs)
                if confs >= 1:
                    self.state = STATE_DONE
                    return True
            except Exception:
                if on_poll:
                    on_poll(int(time.time() - start), -1)
            time.sleep(poll)
        return False

    # -----------------------------------------------------------------
    # Reporting
    # -----------------------------------------------------------------

    def total_fees_sat(self):
        n_strand_txs = sum(len(c.txns) for c in self.strands) if self.strands else 0
        return self.root_fee + self.tip * n_strand_txs + self.join_fee

    def summary(self):
        return {
            "state": self.state,
            "root_txid": self.root_txid,
            "join_txid": self.join_txid,
            "n_strands": len(self.strand_payloads),
            "strand_payload_sizes": [len(p) for p in self.strand_payloads],
            "strand_tx_counts": [len(c.txns) for c in self.strands] if self.strands else None,
            "total_fees_DOGE": self.total_fees_sat() / 10**8,
            "addr": self.addr,
        }
