"""fast_signing.py — coincurve (libsecp256k1) drop-in for cryptos ECDSA signing.

Replaces cryptos.main.ecdsa_raw_sign (and the same symbol re-exported into
cryptos.transaction) with a coincurve-backed implementation.  Both code paths
implement RFC 6979 deterministic nonces and low-S canonicalization; the
signatures are byte-identical (verified empirically across thousands of cases).

Set  QUIPU_SLOW_SIGN=1  to bypass the monkeypatch and use the pure-Python path.

Usage — import once before any cryptos signing call:
    import fast_signing        # applies the patch automatically

Or from quipu_diamond (already wired in at module import time).
"""

import os

import coincurve
import cryptos.main as _cm
import cryptos.transaction as _ct

# secp256k1 group order (same constant used by cryptos.main.N)
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

_slow_ecdsa_raw_sign = _cm.ecdsa_raw_sign  # stash original for the slow path


def _fast_ecdsa_raw_sign(msghash: bytes, priv) -> tuple:
    """coincurve-backed RFC 6979 ECDSA sign.

    Drop-in replacement for cryptos.main.ecdsa_raw_sign.  Returns the same
    (v, r, s) triple with the same v-encoding convention:
        v = 27 + recovery_id  [+ 4 if the key is in a compressed format]
    libsecp256k1 produces low-S signatures natively so no flip is needed.
    """
    priv_int = _cm.decode_privkey(priv)
    priv_bytes = priv_int.to_bytes(32, "big")
    sk = coincurve.PrivateKey(priv_bytes)
    # hasher=None: msghash is already the 32-byte double-SHA256 of the tx
    sig65 = sk.sign_recoverable(msghash, hasher=None)
    r = int.from_bytes(sig65[0:32], "big")
    s = int.from_bytes(sig65[32:64], "big")
    rec_id = sig65[64]  # 0 or 1
    fmt = _cm.get_privkey_format(priv)
    v = 27 + rec_id + (4 if "compressed" in fmt else 0)
    return v, r, s


def apply_patch() -> None:
    """Monkeypatch cryptos so all P2PKH signing uses libsecp256k1."""
    _cm.ecdsa_raw_sign = _fast_ecdsa_raw_sign
    _ct.ecdsa_raw_sign = _fast_ecdsa_raw_sign


def remove_patch() -> None:
    """Restore the original pure-Python signer."""
    _cm.ecdsa_raw_sign = _slow_ecdsa_raw_sign
    _ct.ecdsa_raw_sign = _slow_ecdsa_raw_sign


# Apply the patch at import time unless the caller explicitly opts out.
if not os.environ.get("QUIPU_SLOW_SIGN"):
    apply_patch()
