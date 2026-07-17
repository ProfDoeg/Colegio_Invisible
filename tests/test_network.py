"""Network (0xce kind 0x05) v2 codec — the delta the v2 registry legislates.

Network entered the law at v2 (nothing kind-0x05 was ever legislated under
v1 or inscribed), so network.py is a v2 codec with no legacy path. These
tests pin the codec to the law and the law to the codec:

  1. the v2 wire — c1dd0002 envelope, 9-byte precision dates in the
     more-block, the builder's old vkind-lock gone;
  2. the closed ntype enum — place/agent/relay/resource; the struck
     NTYPE_UNCERTAIN (0x04) raises at build and read;
  3. honest refusal — a v1-stamped or unknown-version blob is refused,
     never guessed; partial trailing edges are malformed, never dropped;
  4. registry agreement — the codec's enum and the v2 registry's network
     entry cannot drift apart.
"""
import struct

import pytest

import network
from network import (
    build_network, read_network, read_network_quipu,
    NTYPE_NAME_TO_BYTE, NTYPE_PLACE, NTYPE_AGENT, ETYPE_ROAD, ETYPE_RELAY,
)
from registry_v2 import v2_type_entry, TYPE_CELESTIAL


def _tiny():
    nodes = [
        {"name": "Cusco", "ntype": "place", "lat": -13.532, "lng": -71.9675,
         "born": 1438, "note": "the navel",
         "dates": [("seized", {"jd": 2280940.0, "precision": "month"})]},
        {"name": "Chasqui corps", "ntype": "agent", "lat": None, "lng": None},
    ]
    edges = [(0, 1, ETYPE_RELAY, 0, None)]
    return build_network("tiny", nodes, edges, tone=0x00)


# ---------------------------------------------------------------------------
# 1. The v2 wire
# ---------------------------------------------------------------------------

def test_emits_v2_envelope_and_reserved_zeros():
    hdr, _body = _tiny()
    assert hdr[:4] == b"\xc1\xdd\x00\x02"    # magic + version v2
    assert hdr[4] == 0xCE and hdr[6] == 0x05
    assert hdr[7] == 0x00 and hdr[8] == 0x00  # grouped/meta reserved


def test_v2_date_var_roundtrips_with_precision():
    hdr, body = _tiny()
    d = read_network_quipu(hdr, body)
    n0 = d["nodes"][0]
    assert n0["dates"] == [("seized", {"jd": 2280940.0, "precision": "month"})]
    assert n0["note"] == "the navel"
    # a bare float date = precision unspecified (still the 9-byte v2 wire)
    h2, b2 = build_network("t", [{"name": "n", "dates": [("d", 2451545.0)]}], [])
    got = read_network_quipu(h2, b2)["nodes"][0]["dates"]
    assert got == [("d", {"jd": 2451545.0, "precision": "unspecified"})]


def test_abstract_node_and_typed_edges_roundtrip():
    hdr, body = _tiny()
    d = read_network_quipu(hdr, body)
    n1 = d["nodes"][1]
    assert n1["abstract"] is True and n1["lat"] is None and n1["lng"] is None
    assert n1["ntype"] == NTYPE_AGENT
    assert d["edges"] == [(0, 1, ETYPE_RELAY, 0, None)]
    assert d["lines"] == [(0, 1)]


# ---------------------------------------------------------------------------
# 2. The closed ntype enum
# ---------------------------------------------------------------------------

def test_ntype_uncertain_refused_at_build():
    for bad in ("uncertain", 0x04, 0xFF):
        with pytest.raises(ValueError, match="closed"):
            build_network("x", [{"name": "n", "ntype": bad}], [])
    assert not hasattr(network, "NTYPE_UNCERTAIN")


def test_ntype_uncertain_refused_at_read():
    hdr, body = build_network("x", [{"name": "n"}], [])
    # body = K:u16 + T:u8 + "x" -> the first node's ntype sits at offset 4
    assert body[4] == NTYPE_PLACE
    patched = bytearray(body); patched[4] = 0x04
    with pytest.raises(ValueError, match="closed v2 enum"):
        read_network_quipu(hdr, bytes(patched))


# ---------------------------------------------------------------------------
# 3. Honest refusal
# ---------------------------------------------------------------------------

def test_v1_stamp_refused_never_guessed():
    hdr, body = _tiny()
    with pytest.raises(ValueError, match="entered the law at v2"):
        read_network(b"\xc1\xdd\x00\x01" + (hdr + body)[4:])
    with pytest.raises(ValueError, match="unknown version"):
        read_network(b"\xc1\xdd\x00\x03" + (hdr + body)[4:])


def test_trailing_edge_bytes_are_malformed():
    hdr, body = _tiny()
    with pytest.raises(ValueError, match="trailing"):
        read_network(hdr + body + b"\x00\x01")


def test_reserved_header_bytes_enforced():
    hdr, body = _tiny()
    bent = bytearray(hdr); bent[8] = 0x01
    with pytest.raises(ValueError, match="reserved"):
        read_network_quipu(bytes(bent), body)


# ---------------------------------------------------------------------------
# 4. Registry agreement — codec and law cannot drift
# ---------------------------------------------------------------------------

def test_codec_enum_matches_the_v2_registry():
    assert set(NTYPE_NAME_TO_BYTE) == {"place", "agent", "relay", "resource"}
    kind = next(d for d in v2_type_entry(TYPE_CELESTIAL)["dimensions"]
                if d["name"] == "kind")
    net = next(v for v in kind["values"] if v["name"] == "network")
    for name in NTYPE_NAME_TO_BYTE:
        assert name in net["desc"], \
            f"codec ntype {name!r} not named in the registry's network entry"
    assert "uncertain" not in net["desc"]
