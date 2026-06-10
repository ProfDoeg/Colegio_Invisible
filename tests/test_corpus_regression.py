"""The gold regression: every quipu actually on chain must keep decoding.

Inscriptions are permanent; the readers are the living half of the
protocol. This test walks data/quipu_data.csv + data/bodies/*.bin (the
local mirror of the corpus, refreshed by update_quipu_data.py) and:

  canonical_v1 rows      must split + decode with the canonical reader,
                         and the decoded title must match the dataset.
  pre_canonical rows     are allowed to deviate from the specs (that is
                         what pre-canonical means) — we require only that
                         the body bytes exist and, when the structural
                         magic is present, that the type byte matches.
  not_yet_canonicalized  same lenient contract as pre_canonical.

If a canonical reader change ever breaks one of these, the failure names
the txid — the exact inscription that just became unreadable.
"""
import os

import pytest

READERS = {
    0x00: ("text", "read_text_quipu"),
    0x01: ("essay", "read_essay_quipu"),
    0x03: ("image", "read_image_quipu"),
    0x09: ("book", "read_book_quipu"),
    0x0E: ("encrypted", "read_encrypted_quipu"),
    0x3D: ("scene", "read_scene_quipu"),
    0x5C: ("latex", "read_latex_quipu"),
    0xAB: ("bindings", "read_binding_quipu"),
    0xCC: ("cert", "read_cert"),
    0xCE: ("celestial", "read_celestial_quipu"),
    0xDA: ("dancer", "read_dancer"),
    0xEE: ("estandarte", "read_estandarte_quipu"),
}

MAGIC = b"\xc1\xdd\x00\x01"


def _reader(type_byte):
    import importlib
    modname, fnname = READERS[type_byte]
    return getattr(importlib.import_module(modname), fnname)


def _rows(corpus):
    out = []
    for _, r in corpus.iterrows():
        if r.body_path and os.path.exists(r.body_path):
            out.append(r)
    return out


def test_every_body_file_present(corpus):
    """The dataset and the body mirror must agree."""
    missing = [r.root_txid for _, r in corpus.iterrows()
               if r.body_path and not os.path.exists(r.body_path)]
    assert not missing, f"{len(missing)} body files missing: {missing[:3]}..."


def test_corpus_decodes(corpus):
    """Strict for canonical_v1, lenient for the pre-canonical era."""
    import colegio_pipeline as P

    strict_checked = lenient_checked = 0
    failures = []
    for r in _rows(corpus):
        blob = open(r.body_path, "rb").read()
        txid = str(r.root_txid)[:12]
        type_byte = int(str(r.type_byte), 16)

        if r.canonical_status == "canonical_v1":
            try:
                header, body = P.split_blob(blob)
                assert header[:4] == MAGIC, "magic missing"
                assert header[4] == type_byte, \
                    f"type byte {header[4]:#04x} != dataset {type_byte:#04x}"
                parsed = _reader(type_byte)(header, body)
                csv_title = r.title if isinstance(r.title, str) else None
                if csv_title:
                    got = parsed.get("title")
                    assert got == csv_title, f"title {got!r} != {csv_title!r}"
            except Exception as e:                          # noqa: BLE001
                failures.append(f"{txid} ({r.type_name}, canonical_v1): {e}")
            strict_checked += 1
        else:
            # pre-canonical: bytes exist; if structurally headed, type agrees
            if blob[:4] == MAGIC and blob[4] != type_byte:
                failures.append(
                    f"{txid} ({r.canonical_status}): structural type byte "
                    f"{blob[4]:#04x} != dataset {type_byte:#04x}")
            lenient_checked += 1

    assert not failures, "\n".join(failures)
    assert strict_checked > 0, "no canonical_v1 rows checked — dataset empty?"
    print(f"\ncorpus regression: {strict_checked} canonical_v1 decoded strictly, "
          f"{lenient_checked} pre-canonical checked leniently")


def test_canonical_titles_roundtrip(corpus):
    """Decoded tone must be a registered tone byte for every canonical row."""
    import colegio_pipeline as P
    from tone import VALID_TONES

    for r in _rows(corpus):
        if r.canonical_status != "canonical_v1":
            continue
        blob = open(r.body_path, "rb").read()
        header, _ = P.split_blob(blob)
        assert header[5] in VALID_TONES, \
            f"{str(r.root_txid)[:12]}: tone {header[5]:#04x} not in the registry"
