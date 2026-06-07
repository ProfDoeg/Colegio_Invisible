#!/usr/bin/env python3
"""El Centinela — a cryptographic canary / tripwire keyed to an HTLC.

The premise: you cannot tell whether an encrypted blob has been *decrypted* —
that's silent and offline. This converts "was the seal opened?" into a public,
timestamped, on-chain event: the secret needed to claim a bait UTXO lives inside
an AES-sealed (`0e ae`) quipu, so a greedy opener moves the coins, and the spend
*is* the tamper-evidence. Watch the outpoint: unspent = intact, spent = opened.

LOCK = HTLC (Mode C, "best of both worlds"). The bait sits in a P2SH output:

    OP_IF
        OP_SHA256 <H(P)> OP_EQUALVERIFY <D_pub> OP_CHECKSIG     # claim: preimage P + D's sig
    OP_ELSE
        <T> OP_CHECKLOCKTIMEVERIFY OP_DROP <F_pub> OP_CHECKSIG  # refund: funder, after height T
    OP_ENDIF

Why this and not a bare hashlock or a pre-signed tx:
  · self-locked on chain (robust — can't be passively invalidated),
  · the claim CHECKSIG binds the destination under SIGHASH_ALL, so revealing P in
    the mempool is useless to a front-runner (they'd need D's key to re-sign for
    their own outputs — front-running is dead),
  · the opener signs at CLAIM time, so no frozen fee,
  · the funder's key is never exposed (funds in from X, claim signed by D),
  · CLTV refund leg recovers the bait if the seal is never opened (re-armable).

The `0e ae` seal carries the bundle {P, D_wif, redeem, p2sh_addr, refund_height}.
Whoever decrypts it can claim; the funder keeps only F (the refund key) and the
AES key (the "open" credential they hand out or withhold).

VERIFIED on the local Dogecoin source before writing: the spend relays
(AreInputsStandard checks only P2SH redeem sigops, no template requirement;
scriptSig is push-only; pushes << 520 B), CLTV/CSV are active, P2SH magic = 22.

SAFETY: this module never touches the funder's spending key. build_centinela
generates a fresh throwaway D and (in test mode) a throwaway F; you fund the P2SH
yourself and, in production, supply only your F *public* key. The claim tool signs
with the throwaway D from the seal. The refund tool signs with your F key — YOU
run that.

  python quipu_centinela.py            # offline self-test (no node, no funds)
"""
import os, sys, json, hashlib
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE); sys.path.insert(0, os.path.join(_HERE, "canonical"))

import cryptos
from cryptos import serialize as cs_serialize, deserialize as cs_deserialize
from cryptos.transaction import serialize_script, deserialize_script, multisign
from colegio_tools import _txid_of_serial

try:
    from quipu_diamond import FeePolicy
except Exception:
    FeePolicy = None

DOGE_P2SH_MAGIC = 22            # verified: Doge().script_magicbyte default
SIGHASH_ALL     = 1

# opcodes (ints; serialize_script emits >=16 as the raw opcode byte)
OP_IF, OP_ELSE, OP_ENDIF = 0x63, 0x67, 0x68
OP_DROP, OP_EQUALVERIFY  = 0x75, 0x88
OP_EQUAL                 = 0x87
OP_SHA256, OP_CHECKSIG   = 0xa8, 0xac
OP_CHECKLOCKTIMEVERIFY   = 0xb1
OP_1 = 1                        # serialize_script: int 1 -> OP_1 (0x51, "true")


# ---------------------------------------------------------------------------
#  script construction
# ---------------------------------------------------------------------------
def cscriptnum(n):
    """Minimal little-endian CScriptNum encoding (positive; for CLTV heights)."""
    if n == 0:
        return b""
    out = bytearray()
    while n:
        out.append(n & 0xff); n >>= 8
    if out[-1] & 0x80:
        out.append(0x00)        # keep it positive
    return bytes(out)


def htlc_redeem(h_hex, d_pub_hex, refund_height, f_pub_hex):
    """The HTLC redeemScript (hex). h_hex = SHA256(preimage); pubs are compressed."""
    return serialize_script([
        OP_IF,
        OP_SHA256, bytes.fromhex(h_hex), OP_EQUALVERIFY, bytes.fromhex(d_pub_hex), OP_CHECKSIG,
        OP_ELSE,
        cscriptnum(refund_height), OP_CHECKLOCKTIMEVERIFY, OP_DROP, bytes.fromhex(f_pub_hex), OP_CHECKSIG,
        OP_ENDIF,
    ]).hex()


def p2sh_address(redeem_hex):
    """P2SH address (Dogecoin, version 22) + funding scriptPubKey for a redeemScript."""
    h160 = cryptos.bin_hash160(bytes.fromhex(redeem_hex))
    addr = cryptos.bin_to_b58check(h160, DOGE_P2SH_MAGIC)
    funding_spk = (b"\xa9\x14" + h160 + b"\x87").hex()        # OP_HASH160 <h160> OP_EQUAL
    # cross-check against the library helper
    d = cryptos.Doge()
    assert d.p2sh_scriptaddr(redeem_hex) == addr, "p2sh address mismatch vs cryptos helper"
    return addr, funding_spk


def _compressed_pub(priv_hex):
    return cryptos.compress(cryptos.privtopub(priv_hex))


# ---------------------------------------------------------------------------
#  build (no funder key — generates throwaway D; F is pub-only in production)
# ---------------------------------------------------------------------------
def build_centinela(refund_height, funder_pub_hex=None, note="", out_dir=None):
    """Create a centinela lock. Returns a dict with the P2SH address to fund, the
    redeemScript, the secret bundle, and (if out_dir) writes artifacts + the 0xae
    seal. funder_pub_hex = your COMPRESSED refund pubkey (only you can refund);
    if None, a throwaway F is generated (TEST ONLY — refund would be claimable by
    whoever holds the generated F key)."""
    preimage = hashlib.sha256(os.urandom(32)).digest()        # 32-byte high-entropy secret P
    h_hex = hashlib.sha256(preimage).hexdigest()              # OP_SHA256 lock value
    d_priv = cryptos.random_key(); d_pub = _compressed_pub(d_priv)

    test_mode = funder_pub_hex is None
    f_priv = None
    if test_mode:
        f_priv = cryptos.random_key(); funder_pub_hex = _compressed_pub(f_priv)

    redeem = htlc_redeem(h_hex, d_pub, refund_height, funder_pub_hex)
    addr, funding_spk = p2sh_address(redeem)

    bundle = {"P": preimage.hex(), "D_priv": d_priv, "redeem": redeem,
              "p2sh_addr": addr, "refund_height": refund_height, "note": note}
    out = {"p2sh_addr": addr, "funding_spk": funding_spk, "redeem": redeem,
           "h": h_hex, "d_pub": d_pub, "funder_pub": funder_pub_hex,
           "test_mode": test_mode, "f_priv": f_priv, "bundle": bundle}

    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        json.dump({k: v for k, v in out.items() if k != "bundle"},
                  open(os.path.join(out_dir, "centinela.json"), "w"), indent=2)
        json.dump(bundle, open(os.path.join(out_dir, "bundle.json"), "w"), indent=2)  # the secret
        _try_write_seal(bundle, out_dir)
    return out


def _try_write_seal(bundle, out_dir, aes_key=None):
    """Wrap the secret bundle in a 0e ae AES quipu (the actual canary seal).
    Best-effort: if the encrypted/text modules aren't importable, skip (the
    plaintext bundle.json already lets the claim tool run for the test)."""
    try:
        from canonical.encrypted import build_aes_quipu
        from canonical.text import build_text_quipu
        key = aes_key or os.urandom(32)
        ih, ib = build_text_quipu("centinela", json.dumps(bundle))
        h, b = build_aes_quipu(ih, ib, key, title="centinela")
        open(os.path.join(out_dir, "seal.0e_ae.bin"), "wb").write(h + b)
        open(os.path.join(out_dir, "seal_aes_key.hex"), "w").write(key.hex())
    except Exception as e:
        print("  (seal skipped: %s — plaintext bundle.json written instead)" % e)


# ---------------------------------------------------------------------------
#  claim (opener: preimage P + D's key) — front-run resistant via SIGHASH_ALL
# ---------------------------------------------------------------------------
def build_claim_tx(outpoint, value_sat, dest_addr, bundle, fee_sat):
    """Signed claim tx spending the HTLC outpoint to dest_addr. Uses the IF branch
    (preimage + D's signature). Keyless w.r.t. the funder — D is the throwaway in
    the seal. Returns (signed_hex, txid)."""
    d = cryptos.Doge()
    redeem = bundle["redeem"]; P = bytes.fromhex(bundle["P"]); d_priv = bundle["D_priv"]
    tx = d.mktx([{"output": outpoint, "value": value_sat}],
                [{"address": dest_addr, "value": value_sat - fee_sat}])
    sig = multisign(tx, 0, redeem, d_priv, SIGHASH_ALL)        # sign against the redeemScript
    tx["ins"][0]["script"] = serialize_script(
        [bytes.fromhex(sig), P, OP_1, bytes.fromhex(redeem)]).hex()   # <sig> <P> OP_1 <redeem>
    hexs = cs_serialize(tx)
    return hexs, _txid_of_serial(hexs)


# ---------------------------------------------------------------------------
#  refund (funder, after height T) — YOU run this with your F key
# ---------------------------------------------------------------------------
def build_refund_tx(outpoint, value_sat, dest_addr, redeem, refund_height, f_priv, fee_sat):
    """Signed refund tx via the ELSE branch (CLTV >= T, funder sig). Sets
    nLockTime = T and a non-final sequence so CLTV is enforced."""
    d = cryptos.Doge()
    tx = d.mktx([{"output": outpoint, "value": value_sat}],
                [{"address": dest_addr, "value": value_sat - fee_sat}])
    tx["locktime"] = refund_height
    tx["ins"][0]["sequence"] = 0xfffffffe                      # non-final -> CLTV active
    sig = multisign(tx, 0, redeem, f_priv, SIGHASH_ALL)
    tx["ins"][0]["script"] = serialize_script(
        [bytes.fromhex(sig), None, bytes.fromhex(redeem)]).hex()      # <sig> OP_0 <redeem>
    hexs = cs_serialize(tx)
    return hexs, _txid_of_serial(hexs)


# ---------------------------------------------------------------------------
#  seal — turn a built + funded Mode-C lock into the canonical 0e ca quipu
# ---------------------------------------------------------------------------
def seal_centinela(out_dir, outpoint, key=None, title="El Centinela"):
    """Wrap a built (and funded) Mode-C lock as ONE inscribable canary object:
    a 0e ca centinela quipu with a PUBLIC descriptor {mode,outpoint,p2sh,redeem,
    refund} in the header and the AES-SEALED secret {P, D_priv} in the body.

    Reads bundle.json (P/D_priv/redeem/p2sh_addr/refund_height) from out_dir.
    `outpoint` is the funded bait UTXO "txid:vout" (known only after funding).
    `key` = 32-byte raw key (default random, saved to seal_key.hex) or a passphrase
    string (KEY_PASSWORD). Writes centinela.0e_ca.bin and returns a summary."""
    from canonical.encrypted import build_centinela_quipu
    from canonical.text import build_text_quipu
    b = json.load(open(os.path.join(out_dir, "bundle.json")))
    secret = json.dumps({"P": b["P"], "D_priv": b["D_priv"],
                         "note": "claim: reveal P + sign with D_priv (SIGHASH_ALL); the coins are yours."})
    ih, ib = build_text_quipu("centinela-secret", secret)
    desc = {"mode": "C", "outpoint": outpoint, "p2sh": b["p2sh_addr"],
            "redeem": b["redeem"], "refund": str(b["refund_height"])}
    if key is None:
        key = os.urandom(32)
    h, body = build_centinela_quipu(ih, ib, key, descriptor=desc, title=title)
    blob = h + body
    open(os.path.join(out_dir, "centinela.0e_ca.bin"), "wb").write(blob)
    if isinstance(key, (bytes, bytearray)):
        open(os.path.join(out_dir, "seal_key.hex"), "w").write(key.hex())
    b["outpoint"] = outpoint
    json.dump(b, open(os.path.join(out_dir, "bundle.json"), "w"), indent=2)
    return {"blob_len": len(blob), "header_len": len(h), "body_len": len(body),
            "key": key.hex() if isinstance(key, (bytes, bytearray)) else "<passphrase>",
            "descriptor": desc}


# ---------------------------------------------------------------------------
#  watch — has the seal been opened?
# ---------------------------------------------------------------------------
def check_centinela(txid, vout):
    """('intact', confs) if the bait UTXO is unspent; ('TRIPPED', None) if spent
    (seal opened); ('unknown', None) if the node doesn't know the funding tx."""
    from colegio_tools import rpc_request
    try:
        o = rpc_request("gettxout", [txid, vout])
    except Exception:
        return ("unknown", None)
    if o is None:
        return ("TRIPPED", None)                               # spent -> opened
    return ("intact", o.get("confirmations", 0))


def _persist(out, bundle, out_dir):
    if not out_dir:
        return
    os.makedirs(out_dir, exist_ok=True)
    json.dump({k: v for k, v in out.items() if k != "bundle"},
              open(os.path.join(out_dir, "centinela.json"), "w"), indent=2)
    json.dump(bundle, open(os.path.join(out_dir, "bundle.json"), "w"), indent=2)
    _try_write_seal(bundle, out_dir)


# ---------------------------------------------------------------------------
#  Mode A — pure hashlock (bearer; front-runnable; simplest, self-locked)
# ---------------------------------------------------------------------------
def hashlock_redeem(h_hex):
    """OP_SHA256 <H(P)> OP_EQUAL — spend by revealing P, no signature."""
    return serialize_script([OP_SHA256, bytes.fromhex(h_hex), OP_EQUAL]).hex()


def build_hashlock(out_dir=None, note=""):
    P = os.urandom(32); h = hashlib.sha256(P).hexdigest()
    redeem = hashlock_redeem(h); addr, spk = p2sh_address(redeem)
    bundle = {"mode": "hashlock", "P": P.hex(), "redeem": redeem, "p2sh_addr": addr, "note": note}
    out = {"mode": "hashlock", "p2sh_addr": addr, "funding_spk": spk,
           "redeem": redeem, "h": h, "bundle": bundle}
    _persist(out, bundle, out_dir)
    return out


def build_claim_hashlock(outpoint, value_sat, dest_addr, bundle, fee_sat):
    """Bearer claim: scriptSig = <P> <redeem>, NO signature (front-runnable)."""
    d = cryptos.Doge()
    tx = d.mktx([{"output": outpoint, "value": value_sat}],
                [{"address": dest_addr, "value": value_sat - fee_sat}])
    tx["ins"][0]["script"] = serialize_script(
        [bytes.fromhex(bundle["P"]), bytes.fromhex(bundle["redeem"])]).hex()
    hexs = cs_serialize(tx)
    return hexs, _txid_of_serial(hexs)


# ---------------------------------------------------------------------------
#  Mode B — pre-signed sweep (plain P2PKH; robust relay; fee frozen at sign-time)
# ---------------------------------------------------------------------------
def build_presigned_lock(out_dir=None, note=""):
    """Throwaway funder X (fund this address) + burner D. After funding, the
    pre-signed X->D sweep is made with sweep_p2pkh and sealed; the opener also
    gets D's key. (For the on-chain test we sweep X->dest directly — same relay.)"""
    d = cryptos.Doge()
    x_priv = cryptos.random_key(); d_priv = cryptos.random_key()
    bundle = {"mode": "presigned", "x_priv": x_priv, "x_addr": d.privtoaddr(x_priv),
              "d_priv": d_priv, "d_addr": d.privtoaddr(d_priv), "note": note}
    out = {"mode": "presigned", "fund_addr": bundle["x_addr"],
           "burner_addr": bundle["d_addr"], "bundle": bundle}
    _persist(out, bundle, out_dir)
    return out


def sweep_p2pkh(outpoint, value_sat, priv, dest_addr, fee_sat):
    """Plain P2PKH sweep of outpoint -> dest_addr, signed with priv. (Mode B's
    pre-signed tx is exactly this, signed ahead of time and sealed.)"""
    d = cryptos.Doge()
    signed = d.signall(d.mktx([{"output": outpoint, "value": value_sat}],
                              [{"address": dest_addr, "value": value_sat - fee_sat}]), priv)
    hexs = cs_serialize(signed)
    return hexs, _txid_of_serial(hexs)


# ---------------------------------------------------------------------------
#  offline self-test — construction integrity, no node, no funds
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=== centinela offline self-test ===")
    c = build_centinela(refund_height=6_300_000, note="self-test")
    print("P2SH addr :", c["p2sh_addr"], "(starts 9/A =>", c["p2sh_addr"][0], ")")
    print("redeem    :", c["redeem"])
    # 1. redeemScript disassembles to the expected HTLC shape
    dis = deserialize_script(c["redeem"])
    assert dis[0] == OP_IF and dis[-1] == OP_ENDIF, "redeem not IF..ENDIF"
    assert OP_CHECKLOCKTIMEVERIFY in dis and dis.count(OP_CHECKSIG) == 2, "missing CLTV / 2x CHECKSIG"
    print("redeem disassembly OK:", len(dis), "items, 2x CHECKSIG + CLTV present")
    # 2. P2SH address derivation matches the library helper (asserted inside p2sh_address)
    # 3. claim tx builds, signs against the redeem, and its scriptSig disassembles to <sig> <P> OP_1 <redeem>
    fake_outpoint = "%s:0" % ("ab" * 32)
    dest = cryptos.Doge().privtoaddr(cryptos.random_key())
    hexs, txid = build_claim_tx(fake_outpoint, 100_000_000, dest, c["bundle"], fee_sat=1_000_000)
    ss = deserialize_script(cs_deserialize(hexs)["ins"][0]["script"])
    assert ss[2] == OP_1, "claim selector is not OP_1 (IF branch)"
    assert ss[1] == c["bundle"]["P"], "preimage not in scriptSig"
    assert ss[3] == c["redeem"], "redeem not the last scriptSig push"
    print("claim scriptSig OK: <sig %dB> <P 32B> OP_1 <redeem %dB>, txid %s" %
          (len(ss[0]) // 2, len(ss[3]) // 2, txid[:16]))
    # 4. refund tx builds with locktime + non-final sequence + ELSE branch
    rhex, rtxid = build_refund_tx(fake_outpoint, 100_000_000, dest, c["redeem"],
                                  6_300_000, c["f_priv"], fee_sat=1_000_000)
    rtx = cs_deserialize(rhex); rss = deserialize_script(rtx["ins"][0]["script"])
    assert rtx["locktime"] == 6_300_000 and rtx["ins"][0]["sequence"] == 0xfffffffe, "CLTV ctx not set"
    assert rss[1] is None, "refund selector is not OP_0 (ELSE branch)"
    print("refund scriptSig OK: <sig> OP_0 <redeem>, locktime/seq set for CLTV, txid %s" % rtxid[:16])

    # 5. Mode A — pure hashlock: P2SH addr + bearer claim scriptSig = <P> <redeem>
    a = build_hashlock(note="self-test")
    ah = deserialize_script(a["redeem"])
    assert ah[0] == OP_SHA256 and ah[-1] == OP_EQUAL, "hashlock redeem shape"
    ahex, atxid = build_claim_hashlock("%s:0" % ("cd" * 32), 100_000_000, dest, a["bundle"], 1_000_000)
    ass = deserialize_script(cs_deserialize(ahex)["ins"][0]["script"])
    assert len(ass) == 2 and ass[0] == a["bundle"]["P"] and ass[1] == a["redeem"], "hashlock claim scriptSig"
    print("Mode A OK: P2SH", a["p2sh_addr"], "claim scriptSig <P> <redeem> (no sig), txid", atxid[:16])

    # 6. Mode B — pre-signed P2PKH sweep
    b = build_presigned_lock(note="self-test")
    bhex, btxid = sweep_p2pkh("%s:0" % ("ef" * 32), 100_000_000, b["bundle"]["x_priv"], dest, 1_000_000)
    bss = deserialize_script(cs_deserialize(bhex)["ins"][0]["script"])
    assert len(bss) == 2, "P2PKH scriptSig should be <sig> <pubkey>"
    print("Mode B OK: fund X", b["fund_addr"], "-> presigned P2PKH sweep, txid", btxid[:16])

    print("\nALL OFFLINE CHECKS PASSED (modes A/B/C). Next gate: on-chain end-to-end.")
