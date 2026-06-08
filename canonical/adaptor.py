"""
adaptor.py — ECDSA adaptor signatures (canonical).

A pre-signature scheme that lets a signer commit, in advance, to producing
a standard ECDSA signature whose subsequent completion reveals the discrete
log of an adaptor point T = t·G. Used by the verified-key sale construction
(docs/quipu-syntax/verified-key-sale.md) to bind the claim transaction's
signature to revealing the session private key.

Why this exists
---------------
A buyer paying for sealed content needs the cryptographic guarantee that
when the seller takes the money, the decryption key is revealed. Standard
hashlocks bind `SHA256(P) = H` but do not bind H to "the actual key for
the box." A ZK proof of the binding works but is heavyweight.

ECDSA adaptor signatures sidestep both problems: the binding lives in the
pre-signature itself, which the buyer verifies before paying. The seller's
act of broadcasting their (completed) claim signature is algebraically
equivalent to publishing the adaptor secret. No script changes, no SNARK,
no trusted setup.

Construction (Blockstream-style ECDSA adaptor)
-----------------------------------------------
Pre-sign(d, m, T):              Verify(P, m, T, presig):
    k ← random                       check DLEQ(R, R_a)
    R = k·G                          r = R_a.x mod n
    R_a = k·T                        check s_a·R == H(m)·G + r·P
    r = R_a.x mod n
    s_a = k⁻¹(H(m) + r·d)
    π = DLEQ(R, R_a, k)
    presig = (R, R_a, s_a, π)

Complete(presig, t):            Extract(presig, sig):
    s = s_a · t⁻¹                    t = s_a · s⁻¹
    normalize s to low-s              (handle ±t ambiguity from low-s)
    return (r, s)

After completion, (r, s) is a standard ECDSA signature under the signer's
pubkey P for message m, with nonce k·t. It verifies against any standard
ECDSA verifier (OP_CHECKSIG, etc.).

The DLEQ proof is Chaum-Pedersen: prover knows k where A = k·G and B = k·H;
verifier checks they share the same scalar. Without DLEQ, the pre-signature
could be malformed (using different k for R and R_a) and completion would
fail to reveal t. DLEQ closes that gap.

References
----------
- Blockstream secp256k1-zkp ecdsa_adaptor module
- Aumayr, Maffei, Moreno-Sanchez et al., "Generalized Bitcoin-Compatible
  Channels", IACR 2020/476
- Madsen/Kakvi/Tibouchi, "Adaptor Signature Scheme from ECDSA"
"""

from __future__ import annotations

import hashlib
import os
from coincurve import PrivateKey, PublicKey


# ---------------------------------------------------------------------------
# Curve constants
# ---------------------------------------------------------------------------

# secp256k1 curve order (Z_n)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# secp256k1 field prime (Z_p)
P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


def _G():
    """The secp256k1 generator G as a PublicKey object."""
    return PrivateKey.from_int(1).public_key


# ---------------------------------------------------------------------------
# Scalar / point helpers
# ---------------------------------------------------------------------------

def _scalar_to_bytes(s: int) -> bytes:
    """Encode a scalar in [0, n) as 32-byte big-endian."""
    return (s % N).to_bytes(32, "big")


def _scalar_from_bytes(b: bytes) -> int:
    """Decode 32-byte big-endian to integer."""
    return int.from_bytes(b, "big")


def _inv_mod_n(x: int) -> int:
    """Modular inverse of x mod n. Raises if x % n == 0."""
    if x % N == 0:
        raise ValueError("cannot invert zero mod n")
    return pow(x, -1, N)


def _point_mul(P: PublicKey, s: int) -> PublicKey:
    """Multiply a point P by scalar s (mod n). Raises if s % n == 0."""
    if s % N == 0:
        raise ValueError("scalar is zero mod n")
    return P.multiply(_scalar_to_bytes(s))


def _point_add(*points: PublicKey) -> PublicKey:
    """Add 2+ points."""
    return PublicKey.combine_keys(list(points))


def _point_neg(P: PublicKey) -> PublicKey:
    """Negate a point: -P = (x, -y mod p)."""
    x, y = P.point()
    return PublicKey.from_point(x, (-y) % P_FIELD)


def _random_scalar() -> int:
    """Cryptographically random scalar in [1, n-1]."""
    while True:
        k = _scalar_from_bytes(os.urandom(32)) % N
        if 0 < k < N:
            return k


# ---------------------------------------------------------------------------
# DLEQ (Chaum-Pedersen NIZK)
# ---------------------------------------------------------------------------

def _dleq_challenge(G_pt: PublicKey, H_pt: PublicKey,
                    A: PublicKey, B: PublicKey,
                    U1: PublicKey, U2: PublicKey) -> int:
    """Fiat-Shamir challenge for the DLEQ proof. Domain-separated."""
    h = hashlib.sha256()
    h.update(b"COLEGIO-DLEQ-secp256k1-v1\x00")
    for pt in (G_pt, H_pt, A, B, U1, U2):
        h.update(pt.format(compressed=True))
    return _scalar_from_bytes(h.digest()) % N


def dleq_prove(k: int, G_pt: PublicKey, H_pt: PublicKey,
               A: PublicKey, B: PublicKey) -> tuple:
    """Prove that A = k·G_pt and B = k·H_pt (i.e., they share discrete log k).

    Args:
        k:    the shared discrete log
        G_pt: first base point (typically the curve generator G)
        H_pt: second base point (typically the adaptor's T)
        A:    A = k·G_pt
        B:    B = k·H_pt

    Returns:
        (c, z) tuple of integers in [0, n).
    """
    u = _random_scalar()
    U1 = _point_mul(G_pt, u)
    U2 = _point_mul(H_pt, u)
    c = _dleq_challenge(G_pt, H_pt, A, B, U1, U2)
    z = (u + c * k) % N
    return (c, z)


def dleq_verify(proof: tuple, G_pt: PublicKey, H_pt: PublicKey,
                A: PublicKey, B: PublicKey) -> bool:
    """Verify a DLEQ proof that A and B share a discrete log against G_pt, H_pt."""
    try:
        c, z = proof
        if not (0 < c < N) or not (0 < z < N):
            return False
        # Recover U1 = z·G_pt - c·A and U2 = z·H_pt - c·B
        U1 = _point_add(_point_mul(G_pt, z), _point_neg(_point_mul(A, c)))
        U2 = _point_add(_point_mul(H_pt, z), _point_neg(_point_mul(B, c)))
        c_check = _dleq_challenge(G_pt, H_pt, A, B, U1, U2)
        return c_check == c
    except (ValueError, Exception):
        return False


# ---------------------------------------------------------------------------
# Pre-signature: build, verify, complete, extract
# ---------------------------------------------------------------------------

def pre_sign(signer_priv: bytes, message_hash: bytes,
             adaptor_pub: bytes) -> dict:
    """Produce an ECDSA adaptor pre-signature.

    Args:
        signer_priv:  32-byte signer's private key d
        message_hash: 32-byte message digest (tx sighash)
        adaptor_pub:  33-byte compressed adaptor public key T = t·G

    Returns:
        dict with:
          'R'      — 33B compressed hex of R = k·G
          'R_a'    — 33B compressed hex of R_a = k·T
          's_a'    — hex of s_a = k⁻¹(H(m) + r·d) where r = R_a.x mod n
          'dleq_c' — hex of DLEQ challenge
          'dleq_z' — hex of DLEQ response
    """
    if len(signer_priv) != 32:
        raise ValueError("signer_priv must be 32 bytes")
    if len(message_hash) != 32:
        raise ValueError("message_hash must be 32 bytes")
    if len(adaptor_pub) != 33:
        raise ValueError("adaptor_pub must be 33-byte compressed")

    d = _scalar_from_bytes(signer_priv)
    if not (0 < d < N):
        raise ValueError("signer_priv is not a valid scalar")

    T = PublicKey(adaptor_pub)
    G = _G()

    # Loop until we get a valid (k, r, s_a) — overwhelmingly succeeds first try
    for _ in range(16):
        k = _random_scalar()
        R = _point_mul(G, k)
        R_a = _point_mul(T, k)

        r = R_a.point()[0] % N
        if r == 0:
            continue

        e = _scalar_from_bytes(message_hash)
        s_a = (_inv_mod_n(k) * (e + r * d)) % N
        if s_a == 0:
            continue

        dleq = dleq_prove(k, G, T, R, R_a)

        return {
            "R":       R.format(compressed=True).hex(),
            "R_a":     R_a.format(compressed=True).hex(),
            "s_a":     hex(s_a),
            "dleq_c":  hex(dleq[0]),
            "dleq_z":  hex(dleq[1]),
        }

    raise RuntimeError("pre_sign exhausted retries (vanishingly improbable)")


def pre_verify(signer_pub: bytes, message_hash: bytes,
               adaptor_pub: bytes, presig: dict) -> bool:
    """Verify an ECDSA adaptor pre-signature.

    Returns True iff the pre-signature is well-formed and binds completion
    to the discrete log of adaptor_pub.
    """
    try:
        if len(signer_pub) != 33 or len(message_hash) != 32 or len(adaptor_pub) != 33:
            return False
        P = PublicKey(signer_pub)
        T = PublicKey(adaptor_pub)
        R = PublicKey(bytes.fromhex(presig["R"]))
        R_a = PublicKey(bytes.fromhex(presig["R_a"]))
        s_a = int(presig["s_a"], 16)
        dleq = (int(presig["dleq_c"], 16), int(presig["dleq_z"], 16))

        if not (0 < s_a < N):
            return False

        G = _G()

        # 1. DLEQ — proves R and R_a share the same scalar k
        if not dleq_verify(dleq, G, T, R, R_a):
            return False

        # 2. r = R_a.x mod n
        r = R_a.point()[0] % N
        if r == 0:
            return False

        # 3. Check s_a · R == H(m)·G + r·P
        lhs = _point_mul(R, s_a)
        e = _scalar_from_bytes(message_hash)
        if e % N == 0:
            return False  # degenerate message hash
        rhs = _point_add(_point_mul(G, e), _point_mul(P, r))

        return lhs.format() == rhs.format()
    except (ValueError, KeyError, Exception):
        return False


def complete(presig: dict, adaptor_secret: bytes) -> tuple:
    """Complete an adaptor pre-signature using the adaptor secret t.

    Args:
        presig:         dict from pre_sign
        adaptor_secret: 32-byte t (such that T = t·G)

    Returns:
        (r, s) tuple of ints — the completed standard ECDSA signature.
        s is normalized to low-s form per BIP-66.
    """
    if len(adaptor_secret) != 32:
        raise ValueError("adaptor_secret must be 32 bytes")
    t = _scalar_from_bytes(adaptor_secret)
    if not (0 < t < N):
        raise ValueError("adaptor_secret is not a valid scalar")

    R_a = PublicKey(bytes.fromhex(presig["R_a"]))
    r = R_a.point()[0] % N
    s_a = int(presig["s_a"], 16)

    s = (s_a * _inv_mod_n(t)) % N

    # Low-s normalization (BIP-66)
    if s > N // 2:
        s = N - s

    return (r, s)


def extract_with_T(presig: dict, sig: tuple, adaptor_pub: bytes) -> bytes:
    """Extract the adaptor secret t from a pre-signature and a completed sig.

    Args:
        presig:      dict from pre_sign
        sig:         (r, s) tuple from the completed (broadcast) signature
        adaptor_pub: 33-byte compressed T, used to disambiguate ±t

    Returns:
        32-byte adaptor secret t such that t·G == T (the published adaptor point).

    Raises:
        ValueError if neither ±t derives to T (pre-sig or sig was tampered).
    """
    r_pre = PublicKey(bytes.fromhex(presig["R_a"])).point()[0] % N
    r_sig, s = sig
    if r_pre != r_sig:
        raise ValueError("sig.r does not match presig.R_a.x — wrong pre-signature")
    s_a = int(presig["s_a"], 16)

    # Candidate t = s_a · s⁻¹ mod n
    t_candidate = (s_a * _inv_mod_n(s)) % N

    G = _G()
    T_expected = PublicKey(adaptor_pub)

    # Try +t
    if t_candidate != 0:
        T_check = _point_mul(G, t_candidate)
        if T_check.format() == T_expected.format():
            return _scalar_to_bytes(t_candidate)

    # Try -t (handles low-s normalization sign flip)
    t_neg = (N - t_candidate) % N
    if t_neg != 0:
        T_check = _point_mul(G, t_neg)
        if T_check.format() == T_expected.format():
            return _scalar_to_bytes(t_neg)

    raise ValueError("extracted secret does not match adaptor pubkey T")


# ---------------------------------------------------------------------------
# Standard ECDSA verify (used in self-tests)
# ---------------------------------------------------------------------------

def _ecdsa_verify(r: int, s: int, message_hash: bytes, pubkey: bytes) -> bool:
    """Verify (r, s) as a standard ECDSA signature on message_hash under pubkey."""
    if not (0 < r < N) or not (0 < s < N):
        return False
    e = _scalar_from_bytes(message_hash)
    s_inv = _inv_mod_n(s)
    u1 = (e * s_inv) % N
    u2 = (r * s_inv) % N
    P = PublicKey(pubkey)
    G = _G()
    try:
        R_check = _point_add(_point_mul(G, u1), _point_mul(P, u2))
    except ValueError:
        return False
    return (R_check.point()[0] % N) == r


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _selftest_dleq():
    print("=== DLEQ ===")
    G = _G()
    H_priv = PrivateKey()
    H = H_priv.public_key

    k = _random_scalar()
    A = _point_mul(G, k)
    B = _point_mul(H, k)

    proof = dleq_prove(k, G, H, A, B)
    assert dleq_verify(proof, G, H, A, B), "honest DLEQ failed to verify"
    print("  ✓ honest DLEQ verifies")

    # Tampered response
    bad = (proof[0], (proof[1] + 1) % N)
    assert not dleq_verify(bad, G, H, A, B), "tampered response accepted"
    print("  ✓ tampered response rejected")

    # Wrong scalar — A uses k, B uses k2
    k2 = _random_scalar()
    B2 = _point_mul(H, k2)
    proof_wrong = dleq_prove(k, G, H, A, B)  # proof for B (correct), used against B2
    assert not dleq_verify(proof_wrong, G, H, A, B2), "DLEQ accepted mismatched scalars"
    print("  ✓ mismatched-scalar DLEQ rejected")
    print()


def _selftest_roundtrip():
    print("=== Adaptor roundtrip ===")
    signer = PrivateKey()
    d_bytes = signer.secret
    P_bytes = signer.public_key.format(compressed=True)

    t_priv = PrivateKey()
    t_bytes = t_priv.secret
    T_bytes = t_priv.public_key.format(compressed=True)

    m_hash = hashlib.sha256(b"sale claim tx sighash example").digest()

    # 1. Pre-sign
    presig = pre_sign(d_bytes, m_hash, T_bytes)
    print(f"  pre-sig: R={presig['R'][:16]}.., R_a={presig['R_a'][:16]}.., "
          f"s_a={presig['s_a'][:18]}..")

    # 2. Pre-verify
    assert pre_verify(P_bytes, m_hash, T_bytes, presig), "pre-verify failed"
    print("  ✓ pre-verify accepts honest pre-sig")

    # 3. Complete
    r, s = complete(presig, t_bytes)
    print(f"  completed sig: r={hex(r)[:18]}.., s={hex(s)[:18]}..")
    assert 0 < s <= N // 2, "completed s is not in low-s form"

    # 4. Completed sig verifies as standard ECDSA
    assert _ecdsa_verify(r, s, m_hash, P_bytes), \
        "completed sig fails standard ECDSA verify"
    print("  ✓ completed sig verifies as standard ECDSA under signer's pubkey")

    # 5. Extract
    t_recovered = extract_with_T(presig, (r, s), T_bytes)
    assert t_recovered == t_bytes, \
        f"extracted t mismatch:\n  expected {t_bytes.hex()}\n  got      {t_recovered.hex()}"
    print("  ✓ extracted adaptor secret matches original t")
    print()


def _selftest_tamper_rejection():
    print("=== Tamper rejection ===")
    signer = PrivateKey()
    d_bytes = signer.secret
    P_bytes = signer.public_key.format(compressed=True)

    t_priv = PrivateKey()
    T_bytes = t_priv.public_key.format(compressed=True)

    m_hash = hashlib.sha256(b"original message").digest()
    presig = pre_sign(d_bytes, m_hash, T_bytes)

    # Wrong message
    m_bad = hashlib.sha256(b"different message").digest()
    assert not pre_verify(P_bytes, m_bad, T_bytes, presig), "wrong message accepted"
    print("  ✓ wrong message rejected")

    # Wrong signer
    other = PrivateKey()
    assert not pre_verify(other.public_key.format(compressed=True),
                          m_hash, T_bytes, presig), "wrong signer accepted"
    print("  ✓ wrong signer pubkey rejected")

    # Wrong adaptor
    other_T = PrivateKey().public_key.format(compressed=True)
    assert not pre_verify(P_bytes, m_hash, other_T, presig), "wrong adaptor accepted"
    print("  ✓ wrong adaptor pubkey rejected")

    # Tampered s_a
    tampered = dict(presig)
    tampered["s_a"] = hex((int(presig["s_a"], 16) + 1) % N)
    assert not pre_verify(P_bytes, m_hash, T_bytes, tampered), "tampered s_a accepted"
    print("  ✓ tampered s_a rejected")
    print()


def _selftest_wrong_secret_extraction():
    print("=== Wrong-secret detection ===")
    signer = PrivateKey()
    t_priv = PrivateKey()
    other_t = PrivateKey()

    m_hash = hashlib.sha256(b"x").digest()
    presig = pre_sign(signer.secret, m_hash,
                      t_priv.public_key.format(compressed=True))

    # Complete with the WRONG t — produces a sig that doesn't verify under signer's pubkey
    r_wrong, s_wrong = complete(presig, other_t.secret)
    assert not _ecdsa_verify(r_wrong, s_wrong, m_hash,
                             signer.public_key.format(compressed=True)), \
        "sig completed with wrong t should not verify"
    print("  ✓ completing with wrong t yields a sig that fails ECDSA verification")

    # Extract should detect mismatch when given T
    try:
        extract_with_T(presig, (r_wrong, s_wrong),
                       t_priv.public_key.format(compressed=True))
        assert False, "extract_with_T should have raised on wrong-secret sig"
    except ValueError as e:
        print(f"  ✓ extract_with_T raises on tampered sig: {e}")
    print()


if __name__ == "__main__":
    print("# canonical/adaptor.py self-tests\n")
    _selftest_dleq()
    _selftest_roundtrip()
    _selftest_tamper_rejection()
    _selftest_wrong_secret_extraction()
    print("All adaptor.py self-tests passed.")
