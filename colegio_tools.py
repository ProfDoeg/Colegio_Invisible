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
        self.script, self.addr = self.doge.mk_multsig_address(
            self.pubs, len(self.pubs)
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
        self.script, self.addr = self.doge.mk_multsig_address(
            self.pubs, len(self.pubs)
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


def read_strand(txout, df_outputs):
    """Walk a strand using a pre-built df_outputs (iterative — no recursion)."""
    out = ""
    cur = txout
    while True:
        rows = df_outputs[df_outputs["txout"] == cur]
        if rows.empty:
            return out
        row = rows.iloc[0]
        spend_tx = row["spent_in"]
        if not spend_tx:
            return out
        spend_head = f"{spend_tx}:0"
        spend_rows = df_outputs[df_outputs["txout"] == spend_head]
        if spend_rows.empty:
            return out
        spend_row = spend_rows.iloc[0]
        if not spend_row["op_return"]:
            return out
        out += spend_row["op_return"]
        cur = spend_head


def read_quipu(tx, df_outputs):
    """Multi-strand pre-scan read. Strand 0 is header, strands 1..N are body."""
    header = read_strand(f"{tx}:0", df_outputs)
    body_parts = []
    idx = 1
    while True:
        strand = read_strand(f"{tx}:{idx}", df_outputs)
        if strand == "":
            break
        body_parts.append(strand)
        idx += 1
    return header, "".join(body_parts)


def identify_quipus(df_transactions, df_outputs):
    """Return txids that look like quipu heads:
    transactions where every output is subsequently spent in a tx that has
    an OP_RETURN."""
    results = []
    for _, tx in df_transactions.iterrows():
        txid = tx["txid"]
        ok = True
        for n in range(tx["num_outputs"]):
            txout = f"{txid}:{n}"
            spent_in = df_outputs.loc[df_outputs["txout"] == txout, "spent_in"]
            if spent_in.empty or spent_in.values[0] is None:
                ok = False
                break
            spend_id = spent_in.values[0]
            op = df_outputs.loc[df_outputs["txid"] == spend_id, "op_return"]
            if op.empty or op.values[0] is None:
                ok = False
                break
        if ok:
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
    decrypted = ecies.sym_decrypt(
        key=hashlib.sha256(password.encode()).digest(),
        cipher_text=encrypted,
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


def add_address_to_node(address, label, rescan=False):
    """Register a watch-only address with the connected Dogecoin node."""
    return rpc_request("importaddress", [address, label, rescan])


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
