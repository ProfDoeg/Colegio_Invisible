"""
quipu_crypto.py — Encryption primitives for sealed quipus.

Three independent mechanisms:

    ECIES (combined keys)
        Encrypt to one or more pubkeys combined by curve point addition.
        Decrypt by combining the corresponding privkeys and running ECIES
        decryption normally. Cardinality 1 (single keyholder) and N>1
        (multi-keyholder) work with the same code path.

    Password (hashed to AES key)
        AES-encrypt with key = SHA256(password). Anyone who knows the
        password can decrypt.

    Key drop (random AES key, released later)
        Generate a random 32-byte AES key. Encrypt with it. Hold the key
        privately; later inscribe a "key drop" quipu to release it.

The primitives don't build headers or chunk OP_RETURNs — they operate on
plaintext bytes and return ciphertext bytes. Header construction and
inscription happen in a separate layer.
"""

import hashlib
import os

import coincurve
import ecies
import eth_keys
from eth_keys.datatypes import PrivateKey, PublicKey


# secp256k1 group order — the modulus for private-key arithmetic.
# Reference: SEC 2 v2.0, page 9.
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

AES_KEY_BYTES_LEN = 32  # 256 bits — matches existing colegio_tools usage


# ---------------------------------------------------------------------------
# Key combination
# ---------------------------------------------------------------------------

def combine_pubkeys(pubkeys):
    """Combine N pubkeys into a single pubkey by curve point addition.

    Args:
        pubkeys: list of eth_keys.keys.PublicKey objects (length >= 1)

    Returns:
        eth_keys.keys.PublicKey representing the curve point sum.
        For a single-element list, returns an equivalent pubkey directly.

    Raises:
        ValueError if the result is the point at infinity (effectively
        impossible with random keys but worth catching).
    """
    if not pubkeys:
        raise ValueError("need at least one pubkey")
    if len(pubkeys) == 1:
        # Single key: nothing to combine, return as-is.
        return PublicKey(pubkeys[0].to_bytes())
    # coincurve.PublicKey.combine_keys is a classmethod that does
    # curve point addition over a list of PublicKey objects.
    cc_keys = [coincurve.PublicKey(b"\x04" + p.to_bytes()) for p in pubkeys]
    combined_cc = coincurve.PublicKey.combine_keys(cc_keys)
    # eth_keys PublicKey wants 64 bytes (no 0x04 prefix)
    uncompressed = combined_cc.format(compressed=False)
    if len(uncompressed) != 65 or uncompressed[0] != 0x04:
        raise ValueError("combined point isn't a valid pubkey (point at infinity?)")
    return PublicKey(uncompressed[1:])


def combine_privkeys(privkeys):
    """Combine N privkeys by integer addition mod the secp256k1 order.

    Args:
        privkeys: list of eth_keys.keys.PrivateKey objects (length >= 1)

    Returns:
        eth_keys.keys.PrivateKey representing the sum.

    Raises:
        ValueError if the sum is zero mod n (vanishingly unlikely with
        random keys).
    """
    if not privkeys:
        raise ValueError("need at least one privkey")
    total = 0
    for p in privkeys:
        total = (total + int.from_bytes(p.to_bytes(), "big")) % SECP256K1_ORDER
    if total == 0:
        raise ValueError("combined privkey is zero — invalid")
    return PrivateKey(total.to_bytes(32, "big"))


def assert_combination_consistent(privkeys, pubkeys=None):
    """Self-test: verify that combining N privkeys gives the privkey
    corresponding to combining the matching N pubkeys.

    If pubkeys is None, derives them from privkeys.
    Raises AssertionError on mismatch.
    """
    if pubkeys is None:
        pubkeys = [p.public_key for p in privkeys]
    if len(privkeys) != len(pubkeys):
        raise ValueError("privkeys and pubkeys must be same length")
    combined_priv = combine_privkeys(privkeys)
    combined_pub_via_priv = combined_priv.public_key
    combined_pub_via_pub = combine_pubkeys(pubkeys)
    if combined_pub_via_priv.to_bytes() != combined_pub_via_pub.to_bytes():
        raise AssertionError(
            "combined privkey's pubkey doesn't match combined pubkeys — math is wrong"
        )


# ---------------------------------------------------------------------------
# Mechanism 1: ECIES with combined keys
# ---------------------------------------------------------------------------

def encrypt_ecies(combined_pubkey, plaintext):
    """Encrypt plaintext to a (combined or single) pubkey via ECIES.

    Args:
        combined_pubkey: eth_keys.keys.PublicKey (single or combined)
        plaintext: bytes

    Returns:
        ciphertext bytes (ECIES-formatted; includes ephemeral pubkey)
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    # ecies.encrypt expects a hex pubkey string with 04 prefix
    pub_hex = "04" + combined_pubkey.to_bytes().hex()
    return ecies.encrypt(pub_hex, plaintext)


def decrypt_ecies(privkeys, ciphertext):
    """Decrypt ECIES ciphertext using one or more privkeys.

    If multiple privkeys are given, they're combined first; the combined
    privkey must correspond to the combined pubkey used for encryption.

    Args:
        privkeys: list of eth_keys.keys.PrivateKey, or a single PrivateKey
        ciphertext: bytes

    Returns:
        plaintext bytes
    """
    if isinstance(privkeys, PrivateKey):
        privkeys = [privkeys]
    combined = combine_privkeys(privkeys)
    return ecies.decrypt(combined.to_hex(), ciphertext)


# ---------------------------------------------------------------------------
# Mechanism 2: Password-derived AES
# ---------------------------------------------------------------------------

def encrypt_password(password, plaintext):
    """AES-encrypt with key = SHA256(password)."""
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    if isinstance(password, str):
        password = password.encode()
    key = hashlib.sha256(password).digest()
    return ecies.aes_encrypt(key=key, plain_text=plaintext)


def decrypt_password(password, ciphertext):
    """Decrypt AES ciphertext using SHA256(password) as the key."""
    if isinstance(password, str):
        password = password.encode()
    key = hashlib.sha256(password).digest()
    return ecies.aes_decrypt(key=key, cipher_text=ciphertext)


# ---------------------------------------------------------------------------
# Mechanism 3: Key drop (random AES key, released later)
# ---------------------------------------------------------------------------

def encrypt_keydrop(plaintext):
    """Generate a fresh random AES key and encrypt with it.

    Returns:
        (ciphertext, aes_key) — keep aes_key secret until the key drop.
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    aes_key = os.urandom(AES_KEY_BYTES_LEN)
    ciphertext = ecies.aes_encrypt(key=aes_key, plain_text=plaintext)
    return ciphertext, aes_key


def decrypt_keydrop(aes_key, ciphertext):
    """Decrypt AES ciphertext using a previously-generated AES key."""
    if len(aes_key) != AES_KEY_BYTES_LEN:
        raise ValueError(f"aes_key must be {AES_KEY_BYTES_LEN} bytes, got {len(aes_key)}")
    return ecies.aes_decrypt(key=aes_key, cipher_text=ciphertext)
