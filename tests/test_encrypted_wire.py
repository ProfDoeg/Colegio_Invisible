"""Encrypted-quipu (0x0e) wire-format reconciliation gates.

Two wire eras are inscribed on mainnet and both must stay legible forever:

  pre-canonical (2022, nb17/nb18 era, written by the old colegio_tools):
    d68175…  0e 03 broadcast (grayscale image, 2 recipients)
    d0209a…  0e 03 broadcast (RGB image, 3 recipients)
    89b51b…  0e 0e 0d keydrop  → releases the session key for d0209a
    f278e4…  0e 0e 0d keydrop  → releases the session key for d68175

  canonical v1 (2026, canonical/encrypted.py):
    00109923…  0e 00 ae 01  AES (password variant)
    f7a8ee4f…  0e 00 ae 00  AES (raw-key variant)
    1bbc2dff…  0e 00 ec 00  ECIES broadcast, 3 recipients
    c277cd57…  0e ff 0d 00  keydrop → releases keys for f7a8ee4f + 1bbc2dff

canonical/encrypted.py is the single parsing implementation (July 2026
reconciliation); colegio_tools.py only delegates. Writers emit canonical
only. These tests are the proof: every sealed on-chain quipu with a public
keydrop must decrypt end-to-end, in both eras, through the unified path.
"""
import os

import pytest

MAGIC = b"\xc1\xdd\x00\x01"

LEGACY_BC_GRAY = "d68175766b70f7163aec93e5a4e81480a6c6dd51d0577319d6f3392e8725f53b"
LEGACY_BC_RGB  = "d0209a0f85872d6826c58bc23fab37c8b21feb22c15a5a6469f45358fb78ba41"
LEGACY_DROP_A  = "89b51b4852b0e80f49cdb229d85ef4757d943c9fe4ba62e39e886f31c70142c4"
LEGACY_DROP_B  = "f278e466012fb78422834742c6440c935f4cc2ef64e7228b7291891a27368367"
CANON_AE_PW    = "00109923db8b1004ac48470516af86d41e6cf26d8667c32be6c0b3edc0cdb664"
CANON_AE_RAW   = "f7a8ee4f997f33682038192d1d378eec7260770588411bcd7fe8bebb6be3fa02"
CANON_EC       = "1bbc2dffbb40e1a93467a123a9af9890d8bb37253e420b7af0392d9f239ba818"
CANON_DROP     = "c277cd570bf36cdca153b95ee90d2d35d2b3d69619394d1f2c3d0d17b855f66c"

EXPECT_CLASS = {
    LEGACY_BC_GRAY: "legacy_broadcast",
    LEGACY_BC_RGB:  "legacy_broadcast",
    LEGACY_DROP_A:  "legacy_drop",
    LEGACY_DROP_B:  "legacy_drop",
    CANON_AE_PW:    "canonical",
    CANON_AE_RAW:   "canonical",
    CANON_EC:       "canonical",
    CANON_DROP:     "canonical",
}


def _blob(txid):
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "data", "bodies", f"{txid}.bin")
    if not os.path.exists(path):
        pytest.skip(f"corpus body {txid[:12]}… not present")
    with open(path, "rb") as f:
        return f.read()


def _split(txid):
    import colegio_pipeline as P
    return P.split_blob(_blob(txid))


# ---------------------------------------------------------------------------
# Classification — the cross-misparse regression
# ---------------------------------------------------------------------------

def test_every_onchain_encrypted_blob_classifies():
    """Each of the 8 inscribed 0x0e quipus classifies to its true era —
    the old failure mode was each implementation misparsing the other's
    layout as garbage."""
    from encrypted import classify_encrypted
    for txid, expect in EXPECT_CLASS.items():
        header, _ = _split(txid)
        got = classify_encrypted(header)
        assert got == expect, f"{txid[:12]}…: classified {got}, expected {expect}"


def test_unified_reader_parses_all_onchain_blobs():
    """Parse-only read (no keys) succeeds on every inscribed 0x0e quipu."""
    from encrypted import read_encrypted_quipu
    for txid in EXPECT_CLASS:
        parsed = read_encrypted_quipu(*_split(txid))
        assert isinstance(parsed, dict), txid


def test_legacy_keydrop_not_misparsed_as_canonical_drop():
    """The historic bug: the canonical reader treated the legacy 0e 0e 0d
    header's title bytes as a u16 drop count. The unified reader must
    return exactly one drop with the true 32-byte target txid."""
    from encrypted import read_encrypted_quipu
    parsed = read_encrypted_quipu(*_split(LEGACY_DROP_A))
    assert parsed.get("legacy") is True
    assert len(parsed["drops"]) == 1
    assert parsed["drops"][0]["ref_txid"] == LEGACY_BC_RGB
    assert parsed["title"] == "Release something glorious to the world"


# ---------------------------------------------------------------------------
# End-to-end decryption — the corpus is the fixture, the keydrops the keys
# ---------------------------------------------------------------------------

def test_legacy_keydrops_open_legacy_broadcasts():
    """89b51b opens d0209a (RGB 64×128×5bpp → 15360 B); f278e4 opens
    d68175 (gray 64×64×5bpp → 2560 B). Byte-exact plaintext sizes."""
    from encrypted import read_encrypted_quipu, open_with_key
    cases = [
        (LEGACY_DROP_A, LEGACY_BC_RGB, 64 * 128 * 3 * 5 // 8),
        (LEGACY_DROP_B, LEGACY_BC_GRAY, 64 * 64 * 1 * 5 // 8),
    ]
    for drop_txid, target_txid, expect_len in cases:
        drop = read_encrypted_quipu(*_split(drop_txid))["drops"][0]
        assert drop["ref_txid"] == target_txid
        th, tb = _split(target_txid)
        inner_h, inner_b = open_with_key(th, tb, drop["key"])
        assert inner_h[:4] == MAGIC
        assert inner_h[4] == 0x03, "inner is an image quipu"
        assert len(inner_b) == expect_len, (
            f"{target_txid[:12]}…: decrypted {len(inner_b)} B, "
            f"expected {expect_len}")


def test_canonical_keydrop_opens_ae_and_ec():
    """c277cd57's two named drops open the AES quipu and the ECIES
    broadcast; both inners carry the c1dd0001 magic and decode as text."""
    from encrypted import read_encrypted_quipu, open_with_key
    from text import read_text_quipu
    drops = {d["name"]: d for d in read_encrypted_quipu(*_split(CANON_DROP))["drops"]}
    assert set(drops) == {"AES message", "ECIES letter"}
    assert drops["AES message"]["ref_txid"] == CANON_AE_RAW
    assert drops["ECIES letter"]["ref_txid"] == CANON_EC
    for d in drops.values():
        th, tb = _split(d["ref_txid"])
        inner_h, inner_b = open_with_key(th, tb, d["key"])
        assert inner_h[:4] == MAGIC
        inner = read_text_quipu(inner_h, inner_b)
        assert inner.get("title"), f"{d['ref_txid'][:12]}…: inner text has a title"


def test_password_variant_opens_with_dropped_raw_key():
    """A password-variant (0e·ae·01) quipu must open with the DERIVED
    32-byte key too — that is what a keydrop would release. Round-trip
    built, not on-chain (the on-chain password quipu's passphrase is
    private, as it should be)."""
    import hashlib
    from encrypted import build_aes_quipu, read_encrypted_quipu
    from text import build_text_quipu
    ih, ib = build_text_quipu("t", "sealed words")
    oh, ob = build_aes_quipu(ih, ib, "una frase")
    assert oh[7] == 0x01  # password variant
    derived = hashlib.sha256("una frase".encode()).digest()
    parsed = read_encrypted_quipu(oh, ob, key=derived)
    assert parsed["magic_ok"] and parsed["inner_header"] == ih


# ---------------------------------------------------------------------------
# colegio_tools delegation surface
# ---------------------------------------------------------------------------

def test_colegio_tools_builders_emit_canonical_wire():
    """The legacy layouts are never written again: every build_* in
    colegio_tools must emit canonical headers (registered tone at byte 5,
    registered sub-family at byte 6)."""
    import colegio_tools as ct
    from encrypted import classify_encrypted
    ih = MAGIC + b"\x00\x00|t|"
    ib = b"cuerpo"

    oh, _ = ct.build_aes_sealed_quipu(ih, ib, "clave")
    assert classify_encrypted(oh) == "canonical" and oh[6] == 0xAE

    import coincurve
    priv = coincurve.PrivateKey(b"\x11" * 32)
    rec = coincurve.PrivateKey(b"\x22" * 32)
    oh, _ = ct.build_broadcast_quipu(ih[4:ih.index(b"|")], ih[ih.index(b"|"):],
                                     ib, priv, [rec.public_key])
    assert classify_encrypted(oh) == "canonical" and oh[6] == 0xEC

    oh, _ = ct.build_keydrop_quipu("ab" * 32, b"\x07" * 32, b"|drop|")
    assert classify_encrypted(oh) == "canonical" and oh[6] == 0x0D


def test_colegio_tools_readers_handle_both_eras():
    """read_aes_sealed / read_broadcast / parse_keydrop / apply_keydrop keep
    their historical signatures but read BOTH eras via the canonical module."""
    import colegio_tools as ct

    # canonical round-trip through the wrappers
    ih = MAGIC + b"\x00\x00|t|"
    ib = b"cuerpo secreto"
    oh, ob = ct.build_aes_sealed_quipu(ih, ib, "clave")
    assert ct.read_aes_sealed_quipu(oh, ob, "clave") == (ih, ib)

    # legacy on-chain keydrop through the same wrapper surface
    import colegio_pipeline as P
    h, b = _split(LEGACY_DROP_B)
    target_txid, key = ct.parse_keydrop_quipu(h, b)
    assert target_txid == LEGACY_BC_GRAY
    th, tb = _split(LEGACY_BC_GRAY)
    inner_h, inner_b = ct.apply_keydrop(th, tb, key)
    assert inner_h[:4] == MAGIC and len(inner_b) == 2560


def test_legacy_aes_splice_still_readable():
    """No 0e ae splice is inscribed, but old local files exist: the
    cleartext-header splice layout must stay decryptable."""
    import ecies as _e
    import hashlib
    from encrypted import classify_encrypted, read_legacy_aes_sealed, read_encrypted_quipu
    ih = MAGIC + b"\x00\xff|vieja|"
    ib = b"cuerpo antiguo"
    # Build the splice the way the old colegio_tools did
    oh = MAGIC + b"\x0e\xae" + ih[4:]
    ob = _e.sym_encrypt(hashlib.sha256(b"pw").digest(), ib)
    assert classify_encrypted(oh) == "legacy_aes"
    assert read_legacy_aes_sealed(oh, ob, "pw") == (ih, ib)
    parsed = read_encrypted_quipu(oh, ob, key="pw")
    assert parsed["legacy"] and parsed["inner_body"] == ib


# ---------------------------------------------------------------------------
# split_blob era-awareness
# ---------------------------------------------------------------------------

def test_split_blob_offsets_both_eras():
    """Legacy keydrop headers are 7 structural bytes + |title| (not 8);
    legacy broadcast headers are 13 + |title|; canonical are 8 + |title|.
    A wrong split silently corrupts every downstream parse."""
    import colegio_pipeline as P
    h, b = _split(LEGACY_DROP_A)
    assert h[4:7] == b"\x0e\x0e\x0d" and len(b) == 64

    h, b = _split(LEGACY_BC_GRAY)
    assert len(h) == 13 + 2 + len("Here is an encrypted image going out to a very special lady...Wow")
    assert len(b) % 1 == 0 and len(b) > 2 * 64  # envelopes + ciphertext

    h, b = _split(CANON_DROP)
    assert len(h) == 8  # canonical keydrop: title lives at end of body
