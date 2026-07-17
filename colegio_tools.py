"""
colegio_tools.py — Dogecoin "quipu" inscription toolkit.

Reorganized: node-backed Cadena/CadenaMulti, pre-scan reader, .env-based
RPC config, SoChain code removed.

The reader works by scanning all transactions of the addresses you watch
(via importaddress + listtransactions on your node) into dataframes, then
walking strand-by-strand through those dataframes. This works for quipus
on addresses you control — which is the current use case.

A future direct-walker that reads any quipu by txid alone (without
pre-scanning addresses) would need either a global forward-spend index or
a block-scan strategy. Not built yet.

Sections:
    1. Imports
    2. Config & RPC
    3. State constants
    4. OP_RETURN primitive (mk_opreturn)
    5. Cadena (single-key)
    6. CadenaMulti (multisig)
    7. Quipu reader (pre-scan)
    8. Image bit-codec
    9. ECIES helpers
    10. Key / wallet utilities
    11. QR helper
"""

# ---------------------------------------------------------------------------
# 1. Imports
# ---------------------------------------------------------------------------
import os
import json
import time
import struct
import getpass
import hashlib

import requests
import numpy as np
import pandas as pd
import qrcode
from PIL import Image
from dotenv import load_dotenv

import ecies
import eth_keys
import coincurve
import cryptos
from cryptos import serialize, deserialize
from cryptos.py3specials import (
    safe_hexlify,
    from_int_to_byte,
    from_string_to_bytes,
)
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256


# ---------------------------------------------------------------------------
# 2. Config & RPC
# ---------------------------------------------------------------------------
# Loads a .env file from the working directory if present. The defaults below
# preserve current behavior so notebooks don't break before a .env exists,
# but you should create one and remove the defaults to take secrets out of
# the code entirely. See .env.example.
load_dotenv()

RPC_USER     = os.getenv("RPC_USER", "drdoeg")
RPC_PASSWORD = os.getenv("RPC_PASSWORD", "password")
RPC_HOST     = os.getenv("RPC_HOST", "192.168.1.235")
RPC_PORT     = int(os.getenv("RPC_PORT", "22555"))

RPC_URL = f"http://{RPC_USER}:{RPC_PASSWORD}@{RPC_HOST}:{RPC_PORT}"

AES_KEY_BYTES_LEN = 32


# Module-level session reuses the underlying TCP connection (HTTP keep-alive).
# Without this, scan_accounts (~15k+ RPC calls) exhausts macOS ephemeral
# ports and throws "[Errno 49] Can't assign requested address".
_RPC_SESSION = requests.Session()
_RPC_SESSION.headers.update({"content-type": "application/json"})

def rpc_request(method, params=None):
    """Call a Dogecoin Core RPC method. Returns the 'result' field."""
    if params is None:
        params = []
    payload = json.dumps({
        "method": method,
        "params": params,
        "jsonrpc": "2.0",
        "id": 0,
    })
    response = _RPC_SESSION.post(
        RPC_URL,
        data=payload,
    )
    if response.status_code != 200:
        raise RuntimeError(
            f"RPC request failed ({response.status_code}): {response.text}"
        )
    body = response.json()
    if body.get("error"):
        raise RuntimeError(f"RPC error: {body['error']}")
    return body["result"]


def current_block_height():
    return rpc_request("getblockcount")


def unspent(address):
    """List unspent outputs for an address in cryptos-compatible format."""
    raw = rpc_request("listunspent", [0, 9999999, [address]])
    return [
        {
            "value": int(out["amount"] * 100_000_000),  # DOGE -> satoshis
            "output": f"{out['txid']}:{out['vout']}",
        }
        for out in raw
    ]


def only_conf(utxos):
    """Filter utxos to only those whose funding tx has at least one confirmation."""
    out = []
    for u in utxos:
        txid = u["output"].split(":")[0]
        info = rpc_request("gettransaction", [txid])
        if info.get("confirmations", 0) > 0:
            out.append(u)
    return out


# ---------------------------------------------------------------------------
# 3. State constants
# ---------------------------------------------------------------------------
# Step-by-step lifecycle (Cadena, CadenaMulti):
STATE_CONF  = "CONF"   # last broadcast tx is confirmed (or no broadcast yet)
STATE_READY = "READY"  # next tx is built & signed, awaiting broadcast
STATE_SENT  = "SENT"   # broadcast, awaiting confirmation
STATE_DONE  = "DONE"   # full chain complete

# Atomic lifecycle (CadenaAtom, CadenaMultiAtom):
STATE_INIT        = "INIT"         # constructed, nothing computed yet
STATE_PRECOMPUTED = "PRECOMPUTED"  # all txs built and signed, none broadcast
STATE_BROADCAST   = "BROADCAST"    # all txs in mempool, none yet confirmed
STATE_CONFIRMED   = "CONFIRMED"    # final tx in chain has at least 1 confirmation

# Mempool policy: Dogecoin Core's default is 25 unconfirmed ancestors per chain.
MEMPOOL_ANCESTOR_LIMIT = 25


# ---------------------------------------------------------------------------
# 4. OP_RETURN primitive
# ---------------------------------------------------------------------------
def mk_opreturn(msg, rawtx=None, json_out=False):
    """Build an OP_RETURN script hex (or attach it to an existing rawtx).

    msg: bytes or str — the data to embed.
    rawtx: optional hex tx; if given, returns a new rawtx with the OP_RETURN
           output appended.
    json_out: if True and rawtx is None, returns {'script': ..., 'value': 0}.
    """
    def op_push(data):
        bytedata = data if isinstance(data, bytes) else data.encode()
        n = len(bytedata)
        if n < 0x4c:
            return from_int_to_byte(n) + bytedata
        elif n < 0xff:
            return from_int_to_byte(76) + struct.pack("<B", n) + bytedata
        elif n < 0xffff:
            return from_int_to_byte(77) + struct.pack("<H", n) + bytedata
        elif n < 0xffffffff:
            return from_int_to_byte(78) + struct.pack("<I", n) + bytedata
        else:
            raise ValueError("OP_RETURN payload too large")

    orhex = safe_hexlify(b"\x6a" + op_push(msg))
    orjson = {"script": orhex, "value": 0}
    if rawtx is not None:
        txo = deserialize(rawtx)
        if "outs" not in txo:
            raise ValueError("OP_RETURN cannot be the sole output")
        txo["outs"].append(orjson)
        return serialize(txo)
    return orjson if json_out else orhex


# ---------------------------------------------------------------------------
# 5. Cadena (single-key, node-backed)
# ---------------------------------------------------------------------------
class Cadena:
    """A single-strand inscription chain.

    Splits `data` into 80-byte chunks and posts them in a chain of
    self-spending OP_RETURN transactions.
    """

    def __init__(self, prvkey, data, utxo_dct, tip):
        self.data = data
        self.doge = cryptos.Doge()
        self.clip = [data[i:i + 80] for i in range(0, len(data), 80)]
        self.og_len = len(self.clip)
        self.state = STATE_CONF
        self.utxo = utxo_dct
        self.head_utxo = utxo_dct
        self.txn_ids = [utxo_dct["output"].split(":")[0]]
        self.prv = prvkey
        self.addr = self.doge.privtoaddr(prvkey)
        self.tip = tip
        self.index = 0
        self.signed_inscribed_tx = None

    def make_tx(self):
        tx = self.doge.mktx(
            [self.head_utxo],
            [{"value": self.head_utxo["value"] - self.tip, "address": self.addr}],
        )
        serial = mk_opreturn(self.clip[self.index], cryptos.serialize(tx))
        inscribed = cryptos.deserialize(serial)
        self.signed_inscribed_tx = self.doge.signall(inscribed, self.prv)
        self.state = STATE_READY

    def broadcast(self):
        raw_hex = serialize(self.signed_inscribed_tx)
        cast_txid = rpc_request("sendrawtransaction", [raw_hex])
        self.txn_ids.append(cast_txid)
        self.head_utxo = {
            "output": f"{cast_txid}:0",
            "value": self.head_utxo["value"] - self.tip,
        }
        self.index += 1
        self.state = STATE_SENT

    def update(self):
        txid = self.head_utxo["output"].split(":")[0]
        info = rpc_request("gettransaction", [txid])
        if info.get("confirmations", 0) > 0:
            self.state = STATE_CONF
            if self.index == self.og_len:
                self.state = STATE_DONE


# ---------------------------------------------------------------------------
# 6. CadenaMulti (multisig, node-backed)
# ---------------------------------------------------------------------------
class CadenaMulti:
    """Multisig variant of Cadena. All listed private keys must sign each tx."""

    DOGE_P2SH_MAGIC = 22  # Dogecoin mainnet P2SH version byte

    def __init__(self, prvkeys, data, utxo_dct, tip):
        self.data = data
        self.doge = cryptos.Doge()
        self.doge.script_magicbyte = self.DOGE_P2SH_MAGIC
        self.clip = [data[i:i + 80] for i in range(0, len(data), 80)]
        self.og_len = len(self.clip)
        self.state = STATE_CONF
        self.utxo = utxo_dct
        self.head_utxo = utxo_dct
        self.txn_ids = [utxo_dct["output"].split(":")[0]]
        self.prvs = prvkeys
        self.pubs = [self.doge.privtopub(p) for p in prvkeys]
        self.script, self.addr = self.doge.mk_multisig_address(
            *self.pubs, num_required=len(self.pubs)
        )
        self.tip = tip
        self.index = 0
        self.signed_inscribed_tx = None

    def make_tx(self):
        tx = self.doge.mktx(
            [self.head_utxo],
            [{"value": self.head_utxo["value"] - self.tip, "address": self.addr}],
        )
        serial = mk_opreturn(self.clip[self.index], cryptos.serialize(tx))
        inscribed = cryptos.deserialize(serial)
        sigs = [
            self.doge.multisign(tx=inscribed, i=0, script=self.script, pk=prv)
            for prv in self.prvs
        ]
        self.signed_inscribed_tx = cryptos.apply_multisignatures(
            inscribed, 0, self.script, *sigs
        )
        self.state = STATE_READY

    def broadcast(self):
        raw_hex = serialize(self.signed_inscribed_tx)
        cast_txid = rpc_request("sendrawtransaction", [raw_hex])
        self.txn_ids.append(cast_txid)
        self.head_utxo = {
            "output": f"{cast_txid}:0",
            "value": self.head_utxo["value"] - self.tip,
        }
        self.index += 1
        self.state = STATE_SENT

    def update(self):
        # NOTE: indentation bug in the previous version made this method
        # unreachable. It is now a real method on the class.
        txid = self.head_utxo["output"].split(":")[0]
        info = rpc_request("gettransaction", [txid])
        if info.get("confirmations", 0) > 0:
            self.state = STATE_CONF
            if self.index == self.og_len:
                self.state = STATE_DONE


# ---------------------------------------------------------------------------
# 6b. CadenaAtom (single-key, precomputed)
# ---------------------------------------------------------------------------
# Atomic lifecycle:
#   INIT -> precompute() -> PRECOMPUTED -> broadcast() -> BROADCAST -> confirm() -> CONFIRMED
#
# precompute() builds and signs all N transactions in memory. After it
# runs, every txid in the strand is knowable — including the final tail
# txid — without anything yet on chain. broadcast() pushes them all in
# dependency order in one operation; for chains over 25 ops it auto-waves
# (broadcast, wait, confirm, repeat).
#
# Use this when you want the strand to either fully exist or fully not
# exist on chain — the bordado mode of inscription.

class CadenaAtom:
    """Atomic single-key strand. Build all transactions in memory first,
    then broadcast in one operation."""

    def __init__(self, prvkey, data, utxo_dct, tip):
        self.data = data
        self.doge = cryptos.Doge()
        self.clip = [data[i:i + 80] for i in range(0, len(data), 80)]
        self.og_len = len(self.clip)
        self.utxo = utxo_dct
        self.prv = prvkey
        self.addr = self.doge.privtoaddr(prvkey)
        self.tip = tip
        self.state = STATE_INIT
        self.txns = []
        self.txn_ids = []

    def precompute(self):
        """Build and sign every transaction in the strand. No network calls."""
        head_utxo = dict(self.utxo)
        for op_data in self.clip:
            tx = self.doge.mktx(
                [head_utxo],
                [{"value": head_utxo["value"] - self.tip, "address": self.addr}],
            )
            serial = mk_opreturn(op_data, cryptos.serialize(tx))
            inscribed = cryptos.deserialize(serial)
            signed = self.doge.signall(inscribed, self.prv)
            signed_hex = serialize(signed)
            txid = _txid_of_serial(signed_hex)
            self.txns.append(signed_hex)
            self.txn_ids.append(txid)
            head_utxo = {
                "output": f"{txid}:0",
                "value": head_utxo["value"] - self.tip,
            }
        self.state = STATE_PRECOMPUTED

    def broadcast(self, wave_size=MEMPOOL_ANCESTOR_LIMIT,
                  poll_interval_s=30, max_wait_s=600):
        """Push all precomputed txs to the node in dependency order.

        For strands of <= wave_size, pushes everything at once.
        For longer strands, broadcasts in waves of wave_size with waits
        for confirmation between waves.
        """
        if self.state != STATE_PRECOMPUTED:
            raise RuntimeError(
                f"broadcast() requires PRECOMPUTED state; got {self.state}"
            )
        n = len(self.txns)
        i = 0
        while i < n:
            wave_end = min(i + wave_size, n)
            for j in range(i, wave_end):
                rpc_request("sendrawtransaction", [self.txns[j]])
            if wave_end < n:
                self._wait_confirmed(self.txn_ids[wave_end - 1],
                                     poll_interval_s, max_wait_s)
            i = wave_end
        self.state = STATE_BROADCAST

    def confirm(self):
        """Check if the final tx in the strand has at least one confirmation."""
        if not self.txn_ids:
            raise RuntimeError("nothing precomputed")
        info = rpc_request("gettransaction", [self.txn_ids[-1]])
        if info.get("confirmations", 0) > 0:
            self.state = STATE_CONFIRMED
            return True
        return False

    @staticmethod
    def _wait_confirmed(txid, poll_interval_s, max_wait_s):
        """Block until txid has >= 1 confirmation, or raise on timeout."""
        elapsed = 0
        while elapsed < max_wait_s:
            try:
                info = rpc_request("gettransaction", [txid])
                if info.get("confirmations", 0) > 0:
                    return
            except RuntimeError:
                pass
            time.sleep(poll_interval_s)
            elapsed += poll_interval_s
        raise TimeoutError(
            f"tx {txid[:16]}... did not confirm within {max_wait_s}s"
        )


# ---------------------------------------------------------------------------
# 6c. CadenaMultiAtom (multisig, precomputed)
# ---------------------------------------------------------------------------
class CadenaMultiAtom:
    """Atomic multisig strand. All listed private keys must sign each tx."""

    DOGE_P2SH_MAGIC = 22

    def __init__(self, prvkeys, data, utxo_dct, tip):
        self.data = data
        self.doge = cryptos.Doge()
        self.doge.script_magicbyte = self.DOGE_P2SH_MAGIC
        self.clip = [data[i:i + 80] for i in range(0, len(data), 80)]
        self.og_len = len(self.clip)
        self.utxo = utxo_dct
        self.prvs = prvkeys
        self.pubs = [self.doge.privtopub(p) for p in prvkeys]
        self.script, self.addr = self.doge.mk_multisig_address(
            *self.pubs, num_required=len(self.pubs)
        )
        self.tip = tip
        self.state = STATE_INIT
        self.txns = []
        self.txn_ids = []

    def precompute(self):
        """Build, multisign, and serialize every tx in the strand."""
        head_utxo = dict(self.utxo)
        for op_data in self.clip:
            tx = self.doge.mktx(
                [head_utxo],
                [{"value": head_utxo["value"] - self.tip, "address": self.addr}],
            )
            serial = mk_opreturn(op_data, cryptos.serialize(tx))
            inscribed = cryptos.deserialize(serial)
            sigs = [
                self.doge.multisign(tx=inscribed, i=0, script=self.script, pk=prv)
                for prv in self.prvs
            ]
            signed = cryptos.apply_multisignatures(
                inscribed, 0, self.script, *sigs
            )
            signed_hex = serialize(signed)
            txid = _txid_of_serial(signed_hex)
            self.txns.append(signed_hex)
            self.txn_ids.append(txid)
            head_utxo = {
                "output": f"{txid}:0",
                "value": head_utxo["value"] - self.tip,
            }
        self.state = STATE_PRECOMPUTED

    def broadcast(self, wave_size=MEMPOOL_ANCESTOR_LIMIT,
                  poll_interval_s=30, max_wait_s=600):
        return CadenaAtom.broadcast(self, wave_size, poll_interval_s, max_wait_s)

    def confirm(self):
        return CadenaAtom.confirm(self)


# ---------------------------------------------------------------------------
# 6d. Helper: compute txid from a signed serial tx hex
# ---------------------------------------------------------------------------
def _txid_of_serial(serial_hex):
    """Compute the txid of a serialized transaction.

    Bitcoin/Dogecoin txid convention: double-SHA256 of the raw tx bytes,
    displayed in byte-reversed (little-endian) hex.
    """
    raw = bytes.fromhex(serial_hex)
    h1 = hashlib.sha256(raw).digest()
    h2 = hashlib.sha256(h1).digest()
    return h2[::-1].hex()


# ---------------------------------------------------------------------------
# 7. Quipu reader (pre-scan via tracked accounts)
# ---------------------------------------------------------------------------
# Workflow:
#   1. scan_accounts({addr: label, ...})   -> (df_tx, df_out)   slow, do once
#   2. find_quipu_roots(addr, df_tx, df_out) -> [txid, ...]      list quipus
#   3. read_quipu(txid, df_out)            -> (header, body)    decode one
#
# The dataframes can be cached / saved to disk and reloaded later.

def get_all_transactions(account_name, batch_size=10000):
    """Page through listtransactions for a wallet account label."""
    transactions = []
    offset = 0
    while True:
        batch = rpc_request(
            "listtransactions", [account_name, batch_size, offset, True]
        )
        if not batch:
            break
        transactions.extend(batch)
        offset += batch_size
    return transactions


def extract_op_return(vout):
    """Return the OP_RETURN payload hex from a vout dict, or None."""
    if vout.get("scriptPubKey", {}).get("type") != "nulldata":
        return None
    hex_data = vout["scriptPubKey"]["hex"]
    if not hex_data.startswith("6a"):
        return None
    length_byte = int(hex_data[2:4], 16)
    if length_byte <= 75:
        return hex_data[4:4 + length_byte * 2]
    if length_byte == 0x4c:  # OP_PUSHDATA1
        n = int(hex_data[4:6], 16)
        return hex_data[6:6 + n * 2]
    if length_byte == 0x4d:  # OP_PUSHDATA2
        n = int(hex_data[4:8], 16)
        return hex_data[8:8 + n * 2]
    if length_byte == 0x4e:  # OP_PUSHDATA4
        n = int(hex_data[4:12], 16)
        return hex_data[12:12 + n * 2]
    return None


def _process_transaction_row(row):
    """Expand one tx row into one row per output."""
    txid = row["txid"]
    return [
        {
            "txout": f"{txid}:{n}",
            "spent_in": None,
            "value": row["values"][n],
            "op_return": row["op_return"],
            "blockheight": row["blockheight"],
            "blocktime": row["blocktime"],
            "txid": txid,
            "n": n,
        }
        for n in range(row["num_outputs"])
    ]


def scan_accounts(accounts):
    """Build (df_transactions, df_outputs) for a dict of {address: account_label}.

    df_outputs has one row per (txid, vout_n) with 'spent_in' filled in for
    outputs we observed being spent within the same account set.
    """
    all_tx = []
    for _addr, label in accounts.items():
        for tx in get_all_transactions(label):
            tx["account_label"] = label
            all_tx.append(tx)

    detailed = []
    seen = set()
    for tx in all_tx:
        txid = tx["txid"]
        if txid in seen:
            continue
        seen.add(txid)
        # gettransaction (wallet RPC) works in pruned mode for wallet-relevant
        # txs. We decode the hex field to get the same shape getrawtransaction
        # would have returned, then merge in the block metadata from the wallet
        # view. (getrawtransaction would require -txindex, which is incompatible
        # with prune.)
        wallet_tx = rpc_request("gettransaction", [txid, True])
        raw = rpc_request("decoderawtransaction", [wallet_tx["hex"]])
        raw["blockhash"] = wallet_tx.get("blockhash")
        raw["blocktime"] = wallet_tx.get("blocktime")
        block = rpc_request("getblockheader", [raw["blockhash"]])
        last_vout = raw["vout"][-1]
        op = (
            extract_op_return(last_vout)
            if last_vout["scriptPubKey"]["type"] == "nulldata"
            else None
        )
        detailed.append({
            "txid": txid,
            "blockhash": raw["blockhash"],
            "blocktime": raw["blocktime"],
            "blockheight": block["height"],
            "inputs": [f"{vin['txid']}:{vin['vout']}" for vin in raw["vin"]],
            "values": [vo["value"] for vo in raw["vout"]],
            "num_inputs": len(raw["vin"]),
            "num_outputs": len(raw["vout"]),
            "op_return": op,
            "addresses_in_outputs": [
                vo["scriptPubKey"].get("addresses", [])
                for vo in raw["vout"]
            ],
        })

    df_tx = pd.DataFrame(detailed).sort_values(by=["blockheight", "blocktime"])

    output_rows = []
    for _, row in df_tx.iterrows():
        output_rows.extend(_process_transaction_row(row))
    df_out = pd.DataFrame(output_rows).sort_values(by=["blockheight", "blocktime"])

    # Fill spent_in by matching each tx's inputs to existing outputs
    for _, tx in df_tx.iterrows():
        for input_ref in tx["inputs"]:
            mask = df_out["txout"] == input_ref
            if mask.any():
                df_out.loc[mask, "spent_in"] = tx["txid"]

    return df_tx, df_out


def _build_spender_index_rpc(address):
    """For an address loaded in the wallet, build a {txout -> spender_txid} dict
    by scanning the wallet's tx history at that address. Used by read_strand
    when no df_outputs is provided (RPC mode)."""
    spent_map = {}
    # Pull a generous slice of wallet txs (multiple labels possible — listtransactions
    # is filterable by label/account, but we just grab all and filter by address).
    txs = rpc_request("listtransactions", ["*", 10000, 0, True])
    seen_txids = set()
    for entry in txs:
        if entry.get("address") != address:
            continue
        txid = entry["txid"]
        if txid in seen_txids:
            continue
        seen_txids.add(txid)
        raw = rpc_request("getrawtransaction", [txid, 1])
        for vin in raw.get("vin", []):
            prev = vin.get("txid")
            if prev is None:
                continue
            spent_map[f"{prev}:{vin['vout']}"] = txid
    return spent_map


def outputs_walk_index(df_outputs):
    """O(1) lookup maps for the dataframe walkers, memoized on df.attrs.

    Returns {"txout": {txout -> (spent_in, op_return_of_that_row)},
             "txid_op": {txid -> op_return}}.

    Built once per dataframe (O(n)) and cached in df.attrs; every walker
    lookup is then a dict hit instead of a full-frame boolean scan — the
    difference between minutes and hours once the frame holds ~10^5 rows.
    The cache is keyed on len(df); if you mutate spent_in/op_return in
    place WITHOUT changing the row count, delete
    df.attrs["_quipu_walk_index"] to force a rebuild."""
    cached = df_outputs.attrs.get("_quipu_walk_index")
    if cached is not None and cached["n"] == len(df_outputs):
        return cached
    txout_map, txid_op = {}, {}
    for txout, spent_in, op, txid in zip(df_outputs["txout"].to_numpy(),
                                         df_outputs["spent_in"].to_numpy(),
                                         df_outputs["op_return"].to_numpy(),
                                         df_outputs["txid"].to_numpy()):
        txout_map[txout] = (spent_in, op)
        if txid not in txid_op:
            txid_op[txid] = op
    cached = {"n": len(df_outputs), "txout": txout_map, "txid_op": txid_op}
    df_outputs.attrs["_quipu_walk_index"] = cached
    return cached


def read_strand(txout, df_outputs=None, spender_map=None):
    """Walk a strand iteratively, collecting OP_RETURN payload bytes along the way.

    Two backends:
      - If df_outputs is given, walk using the pre-scanned dataframe (fast, bulk).
      - Otherwise walk via RPC. spender_map ({txout -> spender_txid}) must be
        provided; build it once per address with _build_spender_index_rpc.

    Returns hex-string of concatenated OP_RETURN payloads (empty if no strand)."""
    idx = outputs_walk_index(df_outputs) if df_outputs is not None else None
    out = ""
    cur = txout
    while True:
        if idx is not None:
            hit = idx["txout"].get(cur)
            if hit is None: return out
            spend_tx = hit[0]
            if not spend_tx: return out
            spend_hit = idx["txout"].get(f"{spend_tx}:0")
            if spend_hit is None: return out
            op_data = spend_hit[1]
            if not op_data: return out
        else:
            spend_tx = (spender_map or {}).get(cur)
            if spend_tx is None: return out
            raw = rpc_request("getrawtransaction", [spend_tx, 1])
            op_data = None
            for v in raw.get("vout", []):
                d = extract_op_return(v)
                if d:
                    op_data = d
                    break
            if not op_data: return out
        out += op_data
        cur = f"{spend_tx}:0"


def read_quipu(tx, df_outputs=None):
    """Read a multi-strand quipu from its root txid. Strand 0 is the header
    (cabeza); strands 1..N are body chunks (cuerpos), concatenated in order.

    Two backends, auto-selected:
      - If df_outputs is given → dataframe walker (fast for bulk reads).
      - Otherwise → RPC walker. Derives the address from the root tx's first
        output, builds a spender index once, then walks each strand."""
    if df_outputs is None:
        # RPC mode — derive address from root tx, build spender map once
        root = rpc_request("getrawtransaction", [tx, 1])
        first_out = root["vout"][0]
        addrs = first_out.get("scriptPubKey", {}).get("addresses", [])
        if not addrs:
            raise ValueError(f"can't derive address from {tx} output 0")
        address = addrs[0]
        spender_map = _build_spender_index_rpc(address)
        kwargs = {"spender_map": spender_map}
    else:
        kwargs = {"df_outputs": df_outputs}

    header = read_strand(f"{tx}:0", **kwargs)
    body_parts = []
    idx = 1
    while True:
        strand = read_strand(f"{tx}:{idx}", **kwargs)
        if strand == "":
            break
        body_parts.append(strand)
        idx += 1
    return header, "".join(body_parts)


def fetch_quipu_bytes(txid, max_walk=64):
    """Fetch the concatenated header+body bytes of any quipu given its root
    OR its join txid.

    A diamond's root has N≥2 outputs (one per strand) and NO OP_RETURN
    outputs (its outputs fund strand starters). Strand txs carry the
    OP_RETURN-bearing knots; the join has 1 regular output collecting
    every strand terminus. Given a join, walks back via first input
    until a tx with ≥2 outputs and no OP_RETURNs is found — that's the
    root. Then defers to read_quipu to walk forward through all strands.

    Args:
        txid: hex string — either a quipu's root or its join txid
        max_walk: safety bound on the back-walk depth

    Returns:
        bytes — concatenated header + body, suitable for resolve_ref's
        fetcher contract and for the canonical readers.
    """
    def _looks_like_root(tx):
        vout = tx.get("vout", [])
        if len(vout) < 2:
            return False
        for o in vout:
            spk = o.get("scriptPubKey", {})
            asm = spk.get("asm", "")
            if asm.startswith("OP_RETURN"):
                return False
        return True

    tx = rpc_request("getrawtransaction", [txid, 1])
    if _looks_like_root(tx):
        root = txid
    else:
        cur = txid
        root = None
        for _ in range(max_walk):
            t = rpc_request("getrawtransaction", [cur, 1])
            if _looks_like_root(t):
                root = cur
                break
            vin = t.get("vin", [])
            if not vin or "txid" not in vin[0]:
                raise ValueError(f"hit a coinbase or malformed tx walking back from {txid}")
            cur = vin[0]["txid"]
        if root is None:
            raise ValueError(
                f"could not find diamond root within {max_walk} hops from {txid} "
                f"(is this really a quipu join/root?)"
            )

    header_hex, body_hex = read_quipu(root)
    return bytes.fromhex(header_hex + body_hex)


def identify_quipus(df_transactions, df_outputs):
    """Return quipu-root txids. The criterion (per the author):

        a root transaction carries no OP_RETURN of its own, and the
        spend of its 0th output carries the c1dd magic.

    Output :0 starts the cabeza strand, so its spender's OP_RETURN is the
    first header knot — the magic bytes themselves. Nothing else in a
    wallet's graph has this shape: knots carry their own OP_RETURN,
    splitters/joins feed txs without one, and mid-strand knots never
    spend a :0 that begins a header.

    Two earlier criteria proved wrong in turn:
      - "every output spent by a tx with an OP_RETURN" — rejects 2022-era
        roots (e.g. the 1ec0… certificate node), whose change outputs are
        spent by ordinary txs;
      - "every output spent by an in-frame tx" — rejects any root with a
        tag output (quipu_tags vout≥1 convention), where UNSPENT is the
        steady state meaning 'current edition' (the 34316f64… healing
        catalog was invisible under this rule)."""
    idx = outputs_walk_index(df_outputs)
    if "op_return" in df_transactions.columns:
        own_op = df_transactions["op_return"].fillna("").to_numpy()
    else:
        own_op = [""] * len(df_transactions)
    results = []
    for txid, op in zip(df_transactions["txid"].to_numpy(), own_op):
        if op:
            continue
        hit = idx["txout"].get(f"{txid}:0")
        if hit is None or not hit[0]:
            continue
        spender_op = idx["txid_op"].get(hit[0]) or ""
        if spender_op.startswith("c1dd"):
            results.append(txid)
    return results


def find_quipu_roots(address, df_transactions, df_outputs):
    """Return quipu-root txids whose first output pays `address`.

    A "quipu root" is a transaction with N outputs, each of which is then
    spent in a tx that carries an OP_RETURN. This is the test in
    identify_quipus(); find_quipu_roots adds an address filter so you can
    ask "which quipus did this wallet originate or hold?"
    """
    all_roots = identify_quipus(df_transactions, df_outputs)
    out = []
    for txid in all_roots:
        rows = df_transactions[df_transactions["txid"] == txid]
        if rows.empty:
            continue
        addrs_per_out = rows.iloc[0]["addresses_in_outputs"]
        # Match if the address appears in any output
        if any(address in addrs for addrs in addrs_per_out):
            out.append(txid)
    return out


def find_pre_funded_quipu_roots(address, df_transactions, df_outputs):
    """Find candidate quipu-root txs that haven't been inscribed yet —
    "broomhead" roots ready to write to. Heuristic:
      - ≥2 outputs to `address`
      - all those outputs currently unspent (spent_in is null in df_outputs)
      - tx itself isn't a quipu-strand step (no OP_RETURN of its own)

    These show up as quipu nodes with N unspent tendrils in the topology
    view, distinct from fully-inscribed quipus (find_quipu_roots).
    """
    out = []
    for _, tx in df_transactions.iterrows():
        txid = tx["txid"]
        # Skip if the tx itself carries an OP_RETURN (it's a strand step,
        # not a root)
        if tx.get("op_return"):
            continue
        addrs_per_out = tx["addresses_in_outputs"]
        out_indices = [
            i for i, addrs in enumerate(addrs_per_out) if address in addrs
        ]
        if len(out_indices) < 2:
            continue
        all_unspent = True
        for i in out_indices:
            rows = df_outputs[df_outputs["txout"] == f"{txid}:{i}"]
            if rows.empty:
                all_unspent = False
                break
            sp = rows.iloc[0]["spent_in"]
            if sp and not (isinstance(sp, float) and sp != sp):
                all_unspent = False
                break
        if all_unspent:
            out.append(txid)
    return out


# ---------------------------------------------------------------------------
# 8. Image bit-codec
# ---------------------------------------------------------------------------
def grey_imgarr(imgarr):
    return imgarr[:, :, :3].mean(axis=2).astype("uint8")


def message_2_bit_array(message, mode=None):
    """Convert str / bytes / hex-str to a uint8 bit-array (MSB first)."""
    if isinstance(message, bytes):
        hex_str = message.hex()
    elif isinstance(message, str):
        hex_str = message if mode in ("hex", "hexstring") else message.encode().hex()
    else:
        raise TypeError("message must be bytes or str")

    num = int("0x" + hex_str, base=16)
    bit_len = ((len(hex_str) + 1) // 2) * 8
    bin_str = bin(num)[2:]
    bits = [0] * (bit_len - len(bin_str)) + [int(b) for b in bin_str]
    return np.array(bits, dtype="uint8")


def bit_array_2_byte_str(bit_array):
    bin_str = "0b" + "".join(str(b) for b in bit_array)
    return int(bin_str, base=2).to_bytes(len(bit_array) // 8, "big")


def bit_array_2_hex_str(bit_array):
    return bit_array_2_byte_str(bit_array).hex()


def bit_array_2_str(bit_array, encoding="utf-8"):
    return bit_array_2_byte_str(bit_array).decode(encoding)


def int2bitarray(x, bit=8):
    return message_2_bit_array(hex(x)[2:], mode="hex")[:bit]


def bitarray2int(b_arr):
    ln = b_arr.shape[0]
    scales = (2 ** np.arange(7, -1, -1))[:ln]
    return (b_arr * scales).sum()


def imgarr2bitarray(imgarr, bit=8):
    return np.array(
        [int2bitarray(it, bit) for it in imgarr.reshape(-1)]
    ).reshape(-1)


def bitarray2imgarr(barrs, imgshape=(16, 16), bit=2, color=1):
    flat = barrs.reshape(-1)
    ints = [bitarray2int(flat[i:i + bit]) for i in range(0, len(flat), bit)]
    return np.array(ints).reshape(*imgshape, color).astype("uint8")


class bitimage:
    """Resize an image to (dims), encode to a bit array at given bit-depth and color."""

    def __init__(self, imgpath, dims=(16, 16), bit=2, color=1):
        self.color = color
        self.bit = bit
        self.dims = list(dims)
        self.img_og = Image.open(imgpath)
        self.img_resize = self.img_og.resize(dims)
        self.grey = grey_imgarr(np.array(self.img_resize))
        self.img_grey = Image.fromarray(self.grey)
        self.bitarray = imgarr2bitarray(self.grey, bit)
        self.bitarray_color = imgarr2bitarray(
            np.array(self.img_resize)[:, :, :color], bit
        )
        self.newimg = Image.fromarray(
            bitarray2imgarr(self.bitarray, imgshape=dims[::-1], bit=bit, color=1).squeeze()
        )
        self.newimg_color = Image.fromarray(
            bitarray2imgarr(
                self.bitarray_color, imgshape=dims[::-1], bit=bit, color=3
            ).squeeze()
        )
        self.bytestring = bit_array_2_byte_str(self.bitarray)
        self.bytestring_color = bit_array_2_byte_str(self.bitarray_color)


def read_image_data(hex_header, image_bytes):
    """Decode an image-quipu given the header hex and the body bytes."""
    C = {0: 1, 1: 3}[int(hex_header[12:14], 16)]
    L = int(hex_header[14:18], 16)
    W = int(hex_header[18:22], 16)
    B = int(hex_header[22:24], 16)
    bits = message_2_bit_array(image_bytes, mode=None)
    arr = bitarray2imgarr(bits, imgshape=(W, L), bit=B, color=C).squeeze()
    return arr


# ---------------------------------------------------------------------------
# 9. ECIES helpers
# ---------------------------------------------------------------------------
def shared_key(prvKey, pubKey):
    cc_prv = coincurve.PrivateKey(prvKey.to_bytes())
    cc_pub = coincurve.PublicKey(pubKey.to_compressed_bytes())
    return HKDF(cc_pub.multiply(cc_prv.secret).format(), AES_KEY_BYTES_LEN, b"", SHA256)


def get_txn_pub_from_node(txn_ident):
    """Recover the pubkey used to sign the first input of a tx via the node.

    Uses gettransaction + decoderawtransaction so it works in pruned mode for
    wallet-relevant txs (getrawtransaction would need -txindex).
    """
    wallet_tx = rpc_request("gettransaction", [txn_ident, True])
    raw = rpc_request("decoderawtransaction", [wallet_tx["hex"]])
    asm = raw["vin"][0]["scriptSig"]["asm"]
    # asm format: "<sig> <pubkey>" — pubkey is the last token, uncompressed = 130 hex chars
    return asm.split()[-1]


def _strip_pub_prefix(pub_hex):
    """Accept 128-hex (eth_keys form) or 130-hex with leading '04' (Bitcoin
    uncompressed form). Returns the 128-hex eth_keys form."""
    pub_hex = pub_hex.strip().lower()
    if len(pub_hex) == 130 and pub_hex.startswith("04"):
        return pub_hex[2:]
    if len(pub_hex) == 128:
        return pub_hex
    raise ValueError(f"unexpected pubkey hex length: {len(pub_hex)} (need 128 or 130)")


def get_address_pubkeys(address, max_scan=2000):
    """Resolve a Dogecoin address to its underlying secp256k1 pubkey(s).

    P2PKH (single-key) addresses → returns a list of length 1.
    P2SH multisig addresses → returns the list of component pubkeys parsed
    from the redeem script.

    Strategy: scan the wallet's `listtransactions ['*' ...]` history (which
    includes any watched address with importaddress) for an input whose
    decoded scriptSig comes from this address, then either:
      - extract the trailing pubkey from a P2PKH scriptSig ('<sig> <pubkey>')
      - extract the redeem script from a P2SH scriptSig (last asm token)
        and parse its '<m> <pk1> <pk2> ... <n> OP_CHECKMULTISIG' form

    Returns a list of pubkey hex strings (128 chars, eth_keys form).

    Raises RuntimeError if no spending tx is found within max_scan recent
    wallet txs — typical when the recipient address has never spent on
    chain, or isn't watched.
    """
    txs = rpc_request("listtransactions", ["*", max_scan, 0, True])
    seen_txids = set()
    for t in reversed(txs):
        txid = t.get("txid")
        if not txid or txid in seen_txids:
            continue
        seen_txids.add(txid)
        try:
            wtx = rpc_request("gettransaction", [txid, True])
            raw = rpc_request("decoderawtransaction", [wtx["hex"]])
        except Exception:
            continue
        for vin in raw.get("vin", []):
            prev_txid = vin.get("txid")
            prev_vout = vin.get("vout")
            if prev_txid is None or prev_vout is None:
                continue
            # Identify the address that signed this input
            try:
                prev_wtx = rpc_request("gettransaction", [prev_txid, True])
                prev_raw = rpc_request("decoderawtransaction", [prev_wtx["hex"]])
            except Exception:
                continue
            try:
                spk = prev_raw["vout"][prev_vout]["scriptPubKey"]
            except (IndexError, KeyError):
                continue
            addrs = spk.get("addresses") or []
            if address not in addrs:
                continue

            asm = vin.get("scriptSig", {}).get("asm", "")
            tokens = asm.split()
            if not tokens:
                continue

            spk_type = spk.get("type")
            if spk_type == "pubkeyhash":
                # P2PKH: scriptSig is '<sig> <pubkey>'
                pub_hex = tokens[-1]
                try:
                    return [_strip_pub_prefix(pub_hex)]
                except ValueError:
                    continue
            if spk_type == "scripthash":
                # P2SH: scriptSig is 'OP_0 <sig1> ... <redeem_script>'
                # The redeem script is the last asm token; parse it as a
                # standard multisig 'm <pk1>..<pkN> n OP_CHECKMULTISIG'.
                # The 'asm' for the redeem script in OP_PUSHDATA form is
                # the last hex blob — need to decode it as script tokens.
                redeem_hex = tokens[-1]
                # Manual parse: redeem script is the same hex; iterate ops.
                try:
                    redeem = bytes.fromhex(redeem_hex)
                except ValueError:
                    continue
                pubs = _parse_multisig_redeem(redeem)
                if pubs:
                    return [_strip_pub_prefix(p) for p in pubs]
                continue
            # Other script types (witness, etc.) not handled
    raise RuntimeError(
        f"could not resolve pubkey(s) for address {address}: no spending "
        f"tx found in the last {max_scan} wallet transactions. The address "
        f"must have spent at least once on chain, and either be in the "
        f"wallet or have been involved in a tx the wallet has seen."
    )


def _parse_multisig_redeem(script_bytes):
    """Parse a standard multisig redeem script and return the list of pubkey
    hex strings. Returns [] if the script isn't a valid m-of-n multisig."""
    if len(script_bytes) < 4:
        return []
    # Opcodes: OP_1..OP_16 are 0x51..0x60; OP_CHECKMULTISIG is 0xae.
    OP_CHECKMULTISIG = 0xae
    if script_bytes[-1] != OP_CHECKMULTISIG:
        return []
    m_byte = script_bytes[0]
    n_byte = script_bytes[-2]
    if not (0x51 <= m_byte <= 0x60 and 0x51 <= n_byte <= 0x60):
        return []
    n = n_byte - 0x50
    # Walk pushes between [1] and [-2]
    pos = 1
    end = len(script_bytes) - 2
    pubs = []
    while pos < end:
        push_len = script_bytes[pos]
        # Standard secp256k1 pubkeys: 0x21 (compressed 33B) or 0x41 (uncompressed 65B)
        if push_len in (0x21, 0x41):
            pos += 1
            if pos + push_len > end:
                return []
            pubs.append(script_bytes[pos:pos + push_len].hex())
            pos += push_len
        else:
            return []
    if len(pubs) != n:
        return []
    # Normalize: if any pubkey is compressed, uncompress it via coincurve so
    # we always return uncompressed-eth_keys form. (eth_keys' PublicKey
    # constructor wants 64 bytes, no prefix.)
    out = []
    for p in pubs:
        if len(p) == 66:  # compressed
            cc = coincurve.PublicKey(bytes.fromhex(p))
            uncompressed = cc.format(compressed=False).hex()
            out.append(uncompressed)
        else:
            out.append(p)
    return out


def array_dec_from_txn(txn_ident, prvKey_input, index_key, df_outputs):
    """Decrypt an image-quipu addressed to one of N recipients."""
    hex_header, body_hex = read_quipu(txn_ident, df_outputs)
    enc_bytes = bytes.fromhex(body_hex)
    N_keys = int(hex_header[24:26])
    zip_keys = [enc_bytes[i * 64:(i + 1) * 64] for i in range(N_keys)]
    zip_data = enc_bytes[N_keys * 64:]
    pub_hex = get_txn_pub_from_node(txn_ident)
    txn_pub = eth_keys.keys.PublicKey(bytes.fromhex(pub_hex))
    sk = shared_key(prvKey_input, txn_pub)
    session = ecies.sym_decrypt(sk, zip_keys[index_key])
    data = ecies.sym_decrypt(session, zip_data)
    return hex_header, read_image_data(hex_header, data)


# ---------------------------------------------------------------------------
# 9b. Encrypted-quipu wrappers — DELEGATES to canonical/encrypted.py
# ---------------------------------------------------------------------------
# canonical/encrypted.py is the single implementation of the 0x0e wire
# format (reconciled July 2026 — see tests/test_encrypted_wire.py). The
# functions here keep their historical signatures for the console and the
# notebooks, but:
#
#   build_*  emit the CANONICAL v1 layout (0e <tone> ae/ec/0d …). The
#            pre-canonical nb17/nb18 layouts are never written again.
#   read_*   accept BOTH eras — the four pre-canonical inscriptions
#            (d0209a, d68175 broadcasts; 89b51b, f278e4 keydrops) stay
#            legible forever via the canonical module's legacy readers.

def _enc():
    """The canonical encrypted module (lazy import; canonical/ on path)."""
    import sys as _sys
    canon = os.path.join(os.path.dirname(os.path.abspath(__file__)), "canonical")
    if canon not in _sys.path:
        _sys.path.insert(0, canon)
    import encrypted as E
    return E


def _cc_priv(priv):
    """eth_keys PrivateKey / coincurve.PrivateKey / 32 bytes → coincurve."""
    if isinstance(priv, coincurve.PrivateKey):
        return priv
    if hasattr(priv, "to_bytes"):
        return coincurve.PrivateKey(priv.to_bytes())
    return coincurve.PrivateKey(bytes(priv))


def _cc_pub(pub):
    """eth_keys PublicKey / coincurve.PublicKey / serialized bytes → coincurve."""
    if isinstance(pub, coincurve.PublicKey):
        return pub
    if hasattr(pub, "to_compressed_bytes"):
        return coincurve.PublicKey(pub.to_compressed_bytes())
    return coincurve.PublicKey(bytes(pub))


def _coerce_aes_key(password_or_key):
    """32-byte AES key passthrough, else SHA-256(passphrase) — same KDF
    convention as scripts/aes_encrypt.py and nb02's aes_encrypt_file."""
    if isinstance(password_or_key, (bytes, bytearray)) and len(password_or_key) == 32:
        return bytes(password_or_key)
    if isinstance(password_or_key, str):
        return hashlib.sha256(password_or_key.encode()).digest()
    raise TypeError("password_or_key must be a 32-byte key or a passphrase string")


def aes_encrypt_bytes(plain_bytes, password_or_key):
    """Byte-level analog of scripts/aes_encrypt.py:aes_encrypt_file."""
    return ecies.sym_encrypt(key=_coerce_aes_key(password_or_key), plain_text=plain_bytes)


def aes_decrypt_bytes(cipher_bytes, password_or_key):
    return ecies.sym_decrypt(key=_coerce_aes_key(password_or_key), cipher_text=cipher_bytes)


def build_aes_sealed_quipu(inner_header_bytes, inner_body_bytes, password_or_key,
                           *, title="", tone=0x00):
    """AES-seal a plaintext quipu. Emits the CANONICAL layout
    (0e <tone> ae <variant>, body = AES(key, length-framed inner header+body));
    the whole inner quipu, header included, is sealed — unlike the old
    splice, which left the inner header in cleartext.

    `password_or_key`: 32-byte raw key, or passphrase string (SHA-256 KDF).
    Returns (outer_header_bytes, outer_body_bytes).
    """
    E = _enc()
    key = password_or_key if isinstance(password_or_key, str) else bytes(password_or_key)
    return E.build_aes_quipu(inner_header_bytes, inner_body_bytes, key,
                             title=title, tone=tone)


def read_aes_sealed_quipu(outer_header_bytes, outer_body_bytes, password_or_key):
    """Unwrap an AES-sealed quipu of EITHER era (canonical 0e <tone> ae, or
    the pre-canonical 0e ae splice). Returns (inner_header, inner_body) in
    plaintext-quipu shape so existing per-type readers handle the result."""
    E = _enc()
    if E.classify_encrypted(outer_header_bytes) == "legacy_aes":
        return E.read_legacy_aes_sealed(outer_header_bytes, outer_body_bytes,
                                        password_or_key)
    parsed = E.read_encrypted_quipu(outer_header_bytes, outer_body_bytes,
                                    key=password_or_key)
    if "inner_header" not in parsed:
        raise ValueError(f"not an AES-openable quipu (sub {parsed.get('sub_name')})")
    return parsed["inner_header"], parsed["inner_body"]


def build_broadcast_quipu(inner_header_struct, title_field, inner_body_bytes,
                          author_privkey, recipient_pubkeys):
    """Broadcast-seal a quipu to N recipients. Emits the CANONICAL ECIES
    layout (0e <tone> ec 00, body = <N:1> + N×64B envelopes + AES(session,
    framed inner)) — the pre-canonical nb17 layout is never written again.

    Historical signature, kept for the console:
      inner_header_struct : bytes 4+ of the plaintext inner header, up to
                            (not including) the |title| field
      title_field         : e.g. b'|My Image|', with bordering pipes; also
                            reused as the outer public title
      inner_body_bytes    : raw inner content
      author_privkey      : eth_keys or coincurve PrivateKey
      recipient_pubkeys   : list of eth_keys or coincurve PublicKey
    """
    E = _enc()
    inner_header = (b"\xc1\xdd\x00\x01" + bytes(inner_header_struct)
                    + bytes(title_field))
    outer_title = bytes(title_field).strip(b"|").decode("utf-8", "replace")
    return E.build_ecies_quipu(inner_header, inner_body_bytes,
                               _cc_priv(author_privkey),
                               [_cc_pub(p) for p in recipient_pubkeys],
                               title=outer_title)


def read_broadcast_quipu(outer_header_bytes, outer_body_bytes, my_privkey, author_pubkey):
    """Decrypt a broadcast quipu of EITHER era (canonical 0e <tone> ec, or
    pre-canonical 0e 03) by trying each envelope against `my_privkey`.
    Returns (inner_header_bytes, inner_body_bytes); for the legacy layout
    the inner header is synthesized plaintext-image-shaped (placeholder
    tone 0x00 — the old writer dropped the tone byte)."""
    E = _enc()
    parsed = E.read_encrypted_quipu(outer_header_bytes, outer_body_bytes,
                                    my_privkey=_cc_priv(my_privkey),
                                    author_pubkey=_cc_pub(author_pubkey))
    if "inner_header" not in parsed:
        raise ValueError(f"could not decrypt (sub {parsed.get('sub_name')})")
    return parsed["inner_header"], parsed["inner_body"]


def build_keydrop_quipu(target_txid_hex, aes_key, title_field=b""):
    """Release `aes_key` for the encrypted quipu at `target_txid_hex`.
    Emits the CANONICAL keydrop (0e <tone> 0d 00, u16-count body) with a
    single anonymous drop — the pre-canonical 0e 0e 0d layout is never
    written again. The txid is display-endian, as before."""
    E = _enc()
    title = bytes(title_field).strip(b"|").decode("utf-8", "replace")
    return E.build_keydrop_quipu([("", target_txid_hex, bytes(aes_key))],
                                 title=title)


def parse_keydrop_quipu(header_bytes, body_bytes):
    """First released (target_txid_hex, aes_key) of a keydrop of EITHER era.
    (Canonical keydrops may carry several drops — use
    canonical/encrypted.read_encrypted_quipu for the full list.)"""
    E = _enc()
    parsed = E.read_encrypted_quipu(header_bytes, body_bytes)
    drops = parsed.get("drops")
    if not drops:
        raise ValueError(f"not a key-drop quipu (sub {parsed.get('sub_name')})")
    return drops[0]["ref_txid"], drops[0]["key"]


def find_keydrop_for(encrypted_txid_hex, quipus, df_outputs):
    """Scan a list of quipu rows for a keydrop (either era) releasing a key
    for the given encrypted-quipu txid.

    `quipus` is an iterable of dict-likes with a 'root_txid' field.
    Returns (keydrop_row, aes_key_bytes) or None.
    """
    E = _enc()
    for q in quipus:
        try:
            head_hex, body_hex = read_quipu(q["root_txid"], df_outputs)
            head = bytes.fromhex(head_hex)
            if len(head) < 7 or head[4:5] != b"\x0e":
                continue
            parsed = E.read_encrypted_quipu(head, bytes.fromhex(body_hex))
        except Exception:
            continue
        for d in parsed.get("drops") or []:
            if d["ref_txid"] == encrypted_txid_hex:
                return q, d["key"]
    return None


def apply_keydrop(target_header_bytes, target_body_bytes, aes_key):
    """Apply a released 32-byte key to a sealed quipu of EITHER era
    (canonical ae/ec, legacy broadcast, legacy AES splice). Returns
    plaintext (inner_header, inner_body)."""
    return _enc().open_with_key(target_header_bytes, target_body_bytes, aes_key)


# ---------------------------------------------------------------------------
# 10. Key / wallet utilities
# ---------------------------------------------------------------------------
# TODO: the password-based KDF here is plain SHA-256, which is not a real
# KDF. Replace with scrypt or argon2id in a future pass and migrate any
# existing _prv.enc files. Leaving it untouched here to not break existing
# encrypted keyfiles.

def save_privkey(privkey, privkey_filepath, password=None):
    if password is None:
        while True:
            password = getpass.getpass("Input password for encrypting keyfile: ")
            password_2 = getpass.getpass("Repeat password for encrypting keyfile: ")
            if password == password_2:
                print("\nPasswords match...")
                break
            print("\nPasswords do not match...")
    encrypted = ecies.sym_encrypt(
        key=hashlib.sha256(password.encode()).digest(),
        plain_text=privkey.to_bytes(),
    )
    with open(privkey_filepath, "wb") as f:
        f.write(encrypted)
    print(f"Password protected file written to {privkey_filepath}")


def import_privKey(privkey_filepath, password=None):
    if password is None:
        password = getpass.getpass("Input password for decrypting keyfile: ")
    with open(privkey_filepath, "rb") as f:
        encrypted = f.read()
    return import_privKey_from_bytes(encrypted, password)


def import_privKey_from_bytes(encrypted_bytes, password):
    """Decrypt the `_prv.enc`-formatted bytes (AES-encrypted with
    SHA-256(password) as the key) into an eth_keys PrivateKey. Used by
    UI surfaces that load keys via file upload / drag-drop rather than
    from a path."""
    decrypted = ecies.sym_decrypt(
        key=hashlib.sha256((password or "").encode()).digest(),
        cipher_text=encrypted_bytes,
    )
    return eth_keys.keys.PrivateKey(decrypted)


def save_pubkey(pubkey, pubkey_filepath):
    with open(pubkey_filepath, "wb") as f:
        f.write(pubkey.to_bytes())
    print(f"File written to {pubkey_filepath}")


def import_pubKey(pubkey_filepath):
    with open(pubkey_filepath, "rb") as f:
        return eth_keys.keys.PublicKey(f.read())


def save_addr(addr, addr_filepath):
    with open(addr_filepath, "wb") as f:
        f.write(addr.encode())
    print(f"Address written to {addr_filepath}: {addr}")


def import_addr(addr_filepath):
    with open(addr_filepath, "rb") as f:
        return f.read().decode()


def gen_save_keys_addr(basename_filepath, password=None, coin="Doge"):
    if os.path.isfile(basename_filepath + "_prv.enc"):
        privkey2save = import_privKey(basename_filepath + "_prv.enc", password)
    else:
        privkey2save = ecies.utils.generate_eth_key()
    pubkey2save = privkey2save.public_key
    save_privkey(privkey2save, basename_filepath + "_prv.enc", password=password)
    save_pubkey(pubkey2save, basename_filepath + "_pub.bin")
    chain = cryptos.Doge() if coin[0].lower() == "d" else cryptos.Bitcoin()
    addr2save = chain.pubtoaddr("04" + pubkey2save.to_bytes().hex())
    save_addr(addr2save, basename_filepath + "_addr.bin")
    return make_qr(addr2save, basename_filepath + "_addr.png")


def add_address_to_watch(address, label="watch"):
    """Register an address for the wallet to watch. NEVER rescans.

    Use for addresses we just created and funded ourselves — the wallet
    sees their txs automatically as new blocks arrive. Idempotent: safe
    to call repeatedly for the same address.

    For deep historical scans across the full chain, see scantxoutset (CLI
    only — there is intentionally no Python wrapper because it's a footgun
    in interactive UIs).
    """
    return rpc_request("importaddress", [address, label, False])


def get_address_utxos(address):
    """Return current spendable UTXOs at a watched address. Fast (~ms),
    no scan, does not block other RPC. Call repeatedly to refresh balances
    in a UI."""
    return rpc_request("listunspent", [0, 9999999, [address]])


def add_address_to_node(address, label, rescan=False):
    """DEPRECATED. Use add_address_to_watch() instead.

    Kept for backward compatibility with older scripts. The rescan
    argument is forcibly ignored — this function now NEVER triggers a
    chain rescan. If you really need a historical scan, use scantxoutset
    from the CLI as a deliberate act, not via library call.
    """
    if rescan:
        import warnings
        warnings.warn(
            "add_address_to_node(rescan=True) is now a no-op. "
            "The rescan footgun was removed. Use scantxoutset from CLI "
            "if you genuinely need a historical scan.",
            DeprecationWarning, stacklevel=2,
        )
    return rpc_request("importaddress", [address, label, False])


# ---------------------------------------------------------------------------
# 11. QR helper
# ---------------------------------------------------------------------------
def make_qr(data, image_path=None):
    qr = qrcode.QRCode(version=1, box_size=5, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")
    if image_path is not None:
        img.save(image_path)
    return img
