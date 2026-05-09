#!/usr/bin/env python3
"""
test_quipu_crypto.py — Verify the five seal mechanisms work end-to-end.

This tests the cryptographic foundation BEFORE any inscription happens.
If anything fails here, fix it now — we cannot fix it after the encrypted
quipus are on chain.

Specifically tests the five-quipu structure for the La Verna certificate:
    Quipu 1: password-sealed
    Quipu 2: key-drop sealed
    Quipu 3: ECIES, locked by C + A (any pair: works as 2-key combo)
    Quipu 4: ECIES, locked by H + A
    Quipu 5: ECIES, locked by H + C + A

Plus negative tests: each seal MUST fail to open with wrong inputs.

Run: python test_quipu_crypto.py
Exit 0 if all pass, 1 otherwise.
"""

import sys
import secrets
import traceback

from eth_keys.datatypes import PrivateKey

# Import the module under test
sys.path.insert(0, ".")
import quipu_crypto as qc


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

passed = []
failed = []


def test(name):
    def deco(fn):
        try:
            fn()
            passed.append(name)
            print(f"  ✓ {name}")
        except Exception as e:
            failed.append((name, e, traceback.format_exc()))
            print(f"  ✗ {name}")
            print(f"      {type(e).__name__}: {e}")
        return fn
    return deco


def must_fail(name, fn):
    """Run fn and assert it raises. Used for negative tests."""
    try:
        fn()
    except Exception:
        passed.append(name)
        print(f"  ✓ {name}")
        return
    failed.append((name, AssertionError("expected failure but it succeeded"), ""))
    print(f"  ✗ {name} — unexpectedly succeeded (should have failed)")


# ---------------------------------------------------------------------------
# Set up test keypairs (NOT real keys — generated fresh per run)
# ---------------------------------------------------------------------------

print("=" * 60)
print("quipu_crypto — primitive tests")
print("=" * 60)

# Three keyholders, names matching the project's three witnesses
prv_H = PrivateKey(secrets.token_bytes(32))
prv_C = PrivateKey(secrets.token_bytes(32))
prv_A = PrivateKey(secrets.token_bytes(32))

pub_H = prv_H.public_key
pub_C = prv_C.public_key
pub_A = prv_A.public_key

# Test plaintext — small enough to inspect, big enough to actually exercise AES
PLAINTEXT = b"La Verna :: Reserva Natural de la Orden Franciscana :: " \
            b"five sealed pilgrimage points await their revelation."

print(f"\nGenerated 3 fresh test keypairs (Hayagriva, Christophia, Anthony)")
print(f"Plaintext: {len(PLAINTEXT)} bytes")
print()

# ---------------------------------------------------------------------------
# Math sanity checks — combining keys must be self-consistent
# ---------------------------------------------------------------------------

print("== Key-combination math ==")


@test("combine_pubkeys: single key returns equivalent pubkey")
def _():
    combined = qc.combine_pubkeys([pub_A])
    assert combined.to_bytes() == pub_A.to_bytes(), \
        "single-pubkey combination should equal the input pubkey"


@test("combine_privkeys: single key returns equivalent privkey")
def _():
    combined = qc.combine_privkeys([prv_A])
    assert combined.to_bytes() == prv_A.to_bytes(), \
        "single-privkey combination should equal the input privkey"


@test("Quipu 3 lock: combine(C, A) is consistent (priv side derives matching pub)")
def _():
    qc.assert_combination_consistent([prv_C, prv_A])


@test("Quipu 4 lock: combine(H, A) is consistent")
def _():
    qc.assert_combination_consistent([prv_H, prv_A])


@test("Quipu 5 lock: combine(H, C, A) is consistent")
def _():
    qc.assert_combination_consistent([prv_H, prv_C, prv_A])


@test("Combination is order-independent (priv side)")
def _():
    a = qc.combine_privkeys([prv_H, prv_C, prv_A]).to_bytes()
    b = qc.combine_privkeys([prv_A, prv_C, prv_H]).to_bytes()
    c = qc.combine_privkeys([prv_C, prv_A, prv_H]).to_bytes()
    assert a == b == c, "addition mod n must be commutative"


@test("Combination is order-independent (pub side)")
def _():
    a = qc.combine_pubkeys([pub_H, pub_C, pub_A]).to_bytes()
    b = qc.combine_pubkeys([pub_A, pub_C, pub_H]).to_bytes()
    c = qc.combine_pubkeys([pub_C, pub_A, pub_H]).to_bytes()
    assert a == b == c, "point addition must be commutative"


# ---------------------------------------------------------------------------
# Quipu 1: password-sealed
# ---------------------------------------------------------------------------

print("\n== Quipu 1 (password) ==")

PASSWORD = "campo de bourlemont"   # the kind of phrase that might lock such a thing


@test("Quipu 1: password round-trip")
def _():
    ct = qc.encrypt_password(PASSWORD, PLAINTEXT)
    pt = qc.decrypt_password(PASSWORD, ct)
    assert pt == PLAINTEXT


must_fail(
    "Quipu 1: wrong password fails",
    lambda: qc.decrypt_password("wrong phrase", qc.encrypt_password(PASSWORD, PLAINTEXT))
)


# ---------------------------------------------------------------------------
# Quipu 2: key-drop sealed
# ---------------------------------------------------------------------------

print("\n== Quipu 2 (key drop) ==")


@test("Quipu 2: keydrop round-trip")
def _():
    ct, key = qc.encrypt_keydrop(PLAINTEXT)
    assert len(key) == 32, "keydrop key should be 32 bytes"
    pt = qc.decrypt_keydrop(key, ct)
    assert pt == PLAINTEXT


@test("Quipu 2: each keydrop generates a fresh key (no reuse)")
def _():
    _, k1 = qc.encrypt_keydrop(PLAINTEXT)
    _, k2 = qc.encrypt_keydrop(PLAINTEXT)
    assert k1 != k2, "fresh random keys per call"


must_fail(
    "Quipu 2: wrong AES key fails",
    lambda: qc.decrypt_keydrop(b"\x00" * 32, qc.encrypt_keydrop(PLAINTEXT)[0])
)


# ---------------------------------------------------------------------------
# Quipu 3: ECIES, C + A
# ---------------------------------------------------------------------------

print("\n== Quipu 3 (ECIES: C + A) ==")


@test("Quipu 3: encrypt to combined(C+A), decrypt with both privkeys")
def _():
    combined_pub = qc.combine_pubkeys([pub_C, pub_A])
    ct = qc.encrypt_ecies(combined_pub, PLAINTEXT)
    pt = qc.decrypt_ecies([prv_C, prv_A], ct)
    assert pt == PLAINTEXT


must_fail(
    "Quipu 3: only Anthony cannot decrypt",
    lambda: qc.decrypt_ecies(
        [prv_A],
        qc.encrypt_ecies(qc.combine_pubkeys([pub_C, pub_A]), PLAINTEXT)
    )
)


must_fail(
    "Quipu 3: only Christophia cannot decrypt",
    lambda: qc.decrypt_ecies(
        [prv_C],
        qc.encrypt_ecies(qc.combine_pubkeys([pub_C, pub_A]), PLAINTEXT)
    )
)


must_fail(
    "Quipu 3: H+A cannot decrypt (wrong combination)",
    lambda: qc.decrypt_ecies(
        [prv_H, prv_A],
        qc.encrypt_ecies(qc.combine_pubkeys([pub_C, pub_A]), PLAINTEXT)
    )
)


# ---------------------------------------------------------------------------
# Quipu 4: ECIES, H + A
# ---------------------------------------------------------------------------

print("\n== Quipu 4 (ECIES: H + A) ==")


@test("Quipu 4: encrypt to combined(H+A), decrypt with both privkeys")
def _():
    combined_pub = qc.combine_pubkeys([pub_H, pub_A])
    ct = qc.encrypt_ecies(combined_pub, PLAINTEXT)
    pt = qc.decrypt_ecies([prv_H, prv_A], ct)
    assert pt == PLAINTEXT


must_fail(
    "Quipu 4: only Hayagriva cannot decrypt",
    lambda: qc.decrypt_ecies(
        [prv_H],
        qc.encrypt_ecies(qc.combine_pubkeys([pub_H, pub_A]), PLAINTEXT)
    )
)


# ---------------------------------------------------------------------------
# Quipu 5: ECIES, H + C + A
# ---------------------------------------------------------------------------

print("\n== Quipu 5 (ECIES: H + C + A) ==")


@test("Quipu 5: encrypt to combined(H+C+A), decrypt with all three privkeys")
def _():
    combined_pub = qc.combine_pubkeys([pub_H, pub_C, pub_A])
    ct = qc.encrypt_ecies(combined_pub, PLAINTEXT)
    pt = qc.decrypt_ecies([prv_H, prv_C, prv_A], ct)
    assert pt == PLAINTEXT


must_fail(
    "Quipu 5: any two cannot decrypt (H+A only)",
    lambda: qc.decrypt_ecies(
        [prv_H, prv_A],
        qc.encrypt_ecies(qc.combine_pubkeys([pub_H, pub_C, pub_A]), PLAINTEXT)
    )
)


must_fail(
    "Quipu 5: any two cannot decrypt (C+A only)",
    lambda: qc.decrypt_ecies(
        [prv_C, prv_A],
        qc.encrypt_ecies(qc.combine_pubkeys([pub_H, pub_C, pub_A]), PLAINTEXT)
    )
)


# ---------------------------------------------------------------------------
# Cross-mechanism sanity: ciphertexts from different mechanisms differ
# ---------------------------------------------------------------------------

print("\n== Cross-mechanism sanity ==")


@test("Same plaintext, different mechanisms → different ciphertexts")
def _():
    ct_pwd = qc.encrypt_password("any password", PLAINTEXT)
    ct_drop, _ = qc.encrypt_keydrop(PLAINTEXT)
    ct_ecies = qc.encrypt_ecies(pub_A, PLAINTEXT)
    assert ct_pwd != ct_drop != ct_ecies != ct_pwd


@test("Same plaintext, same mechanism, different keys → different ciphertexts")
def _():
    ct1 = qc.encrypt_password("password one", PLAINTEXT)
    ct2 = qc.encrypt_password("password two", PLAINTEXT)
    assert ct1 != ct2


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print("\n" + "=" * 60)
n_pass = len(passed)
n_fail = len(failed)
total = n_pass + n_fail

if n_fail == 0:
    print(f"  {n_pass}/{total} passed ✓")
    print("  Cryptographic foundation is solid. Safe to proceed to inscription.")
    sys.exit(0)
else:
    print(f"  {n_pass}/{total} passed, {n_fail} failed ✗")
    print("\n  Failed tests:")
    for name, err, tb in failed:
        print(f"    - {name}: {err}")
    print("\n  DO NOT proceed to inscription until all tests pass.")
    sys.exit(1)
