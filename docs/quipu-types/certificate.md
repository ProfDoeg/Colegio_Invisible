# Quipu type `0xcc` — Certificate

> **STATUS: CANONICAL v1.** Implemented in
> [`canonical/cert.py`](../../canonical/cert.py). Two subtypes are
> in active use on chain: hash certs (`0x0001`) and all-in-one certs
> (`0x0002`).

A *certificate quipu* carries either a cryptographic attestation
(hash cert) or a self-contained attestation document (all-in-one cert).
Both share an 8-byte structural header; the 2-byte subtype field at
offsets 6..7 picks the body shape.

---

## Byte layout

### Header — 8 structural bytes

```
offset  bytes              meaning
0..3    c1 dd 00 01        magic + protocol version 0.1
4       cc                 type byte = certificate
5       <tone>             tone byte — see tone.md for the canonical vocabulary
6..7    <subtype_hi lo>    uint16 BE; 0x0001 = hash, 0x0002 = all-in-one
```

### Body — depends on subtype

**Subtype `0x0001` — hash cert**:

```
| HASH_ALGO | <hash_hex>
Field:value\n …
```

The pipe preamble is `|HASH_ALGO|` followed by the hex digest. **The
hash hex has no closing pipe** — it runs until the first non-hex
character (typically the start of a `Field:value` line). After the
hash, the body carries identifying metadata about the parties or
content being attested, one `Field:value` per line.

**Subtype `0x0002` — all-in-one cert**:

```
| TITLE |
Field: value\n …
```

The pipe preamble is just `|TITLE|`. After it, the body carries the
attestation content as `Field: value` lines.

---

## Tone vocabulary

Same as text and image quipus:

| `<tone>` | name | when to use |
|---|---|---|
| `0x00` | ordinary | descriptive / neutral / academic certificate |
| `0x01` | affection | personal / paired / intimate certificate |
| `0xff` | reverence | the dead, ancestors, formal commemorative attestation |

The two existing on-chain certs (Maier, Domremy) both use `0xff`.

---

## `Field:value` separator convention

Both `Field:value` (no space) and `Field: value` (with space) appear on
chain. The canonical reader accepts either:

| Inscription | Convention |
|---|---|
| Maier (0x0001 hash) | `Hayagriva_Public:0x...` (no space) |
| Domremy (0x0002 all-in-one) | `Title: Domrémy` (with space) |

The canonical builders default to:
- `field_separator=":"` for `build_hash_cert` (matches Maier)
- `field_separator=": "` for `build_allinone_cert` (matches Domremy)

Either can be overridden via the `field_separator` argument.

---

## Recommended field vocabulary

**Hash cert (0x0001)** — typically declares parties:

| Field | Meaning |
|---|---|
| `<Name>_Public` | Compressed secp256k1 public key for the named party |
| `Artist` | The party being certified |

**All-in-one cert (0x0002)** — typically declares content:

| Field | Meaning |
|---|---|
| `Title` | Short title of the attested work |
| `Artist` | Creator / signer / responsible party |
| `Image` | Citation to attested image quipu, `<<txid>>` |
| `CertificateAuthority` | Citation to a hash cert that authorizes this attestation, `<<txid>>` |
| `Text` | Descriptive prose, may span paragraphs |

The all-in-one's `CertificateAuthority` field is the key
self-referential primitive: an all-in-one cert names which hash cert
witnessed it. Walking from an all-in-one to its authority lets a
verifier check that the parties named in the hash cert (via their
public keys) had the right to attest the all-in-one's content.

---

## Worked example — Maier hash cert (`0x0001`)

On chain at root [`1ec0ee9b27d6ab91…`](https://blockchair.com/dogecoin/transaction/1ec0ee9b27d6ab91169b28f3acdada51cab8eb03af8c2a7e128d122a2dba7d0c)
(bordado 3-of-3 multisig).

```
Header (8 bytes):
  c1 dd 00 01                          magic + version
  cc                                   type = certificate
  ff                                   tone = reverence
  00 01                                subtype = hash

Body (one cabeza OP_RETURN + cuerpos):
  |SHA256|337095adb739572e5566416637a4e8905f0fda28a804999a3e472b024c5a1ba0
  Hayagriva_Public:0x505d743671977487913280812271df3e8b27126788d03b5dd84430280b710b20584a8c442082960a67214fba8f45e97c7aeca15a6a59ba98f830dfe9e487d8cd
  Christophia_Public:0x6bb329760057768325b73b3420650c0d077790ce78a54a5f40630a5342d11310b24308716b30b3e86539964f701e4e570ce497b6073c652ab153dbe676b57970
  Anthony_Public:0xcd477d18b1ed8549fd6d9d576c8378deed4df4a926f0fe8ea9dbde07a72bb5911bf9a1f380ea24adabff0b91eb5525e4526f22d9ed1e3bcbebe97093d4871f53
  Artist:Laura_Renee_Maier
```

The SHA256 digest is over the canonical serialization of the four
identity fields; verifying the hash proves the listed parties signed
exactly this combination.

---

## Worked example — Domremy all-in-one cert (`0x0002`)

On chain at root [`6da7a9a9d8d651c4…`](https://blockchair.com/dogecoin/transaction/6da7a9a9d8d651c48e0a979ea6d1f00ce03cd1388ea390c5fa2050f9b2fb4910)
(bordado 3-of-3 multisig).

```
Header (8 bytes):
  c1 dd 00 01                          magic + version
  cc                                   type = certificate
  ff                                   tone = reverence
  00 02                                subtype = all-in-one

Body (one cabeza OP_RETURN + cuerpos):
  |Domrémy Bordado Certificate|<cabeza padding spaces>
  Title: Domrémy
  Artist: Ekaterina Sirichinova
  Image: <<b92bbbf974ad7d1ba035d03b34ee455dadf4e85c365d841beb4443e55da0b66c>>
  CertificateAuthority: <<1ec0ee9b27d6ab91169b28f3acdada51cab8eb03af8c2a7e128d122a2dba7d0c>>
  Text: Joffrey Bourlémont, French nobleman turned Crusader, set for Jerusalem
        to find peace, war and the Well of Souls. He returned to Vosges weary
        and heartbroken. Solace came through a clearing in Domrémy. Here he
        built a well and tower for children to gather and hear to tales of
        dragons, ciphers and Celtic magic. Two centuries later Joan of Arc
        would draw power from this enchanted place, and thread a national
        identity.
```

Note the `CertificateAuthority` field cites Maier (the `0x0001` hash
cert above): the parties named in Maier's hash cert are the parties
authorized to attest this Domremy bordado.

The cabeza padding (trailing spaces after the closing `|` of the
title) is a diamond/strand artifact — the cabeza OP_RETURN is filled
to 80 bytes with spaces — and the canonical reader strips it
gracefully.

---

## Reference parser

See [`canonical/cert.py`](../../canonical/cert.py) for the authoritative
builder + reader. Round-trip self-tests cover:

- Build Maier-shaped hash cert + read-back
- Build Domremy-shaped all-in-one cert + read-back
- Parse the actual Maier on-chain bytes
- Parse the actual Domremy on-chain bytes (with cabeza padding tolerated)
- 6 validation cases (bad tone, hash_algo with pipe, non-hex hash_hex,
  title with pipe, unknown subtype, wrong type byte)

---

## Future subtypes

Reserved but not yet defined:

- `0x0000` — wrapper cert (essay_renderer references `0xcc 0x0000` as a
  "wrapper" subtype that wraps another quipu type with certificate
  semantics; spec pending)
- `0x0003+` — additional subtype values are unallocated

A new subtype is added by inscribing an Estandarte amendment that
documents the new subtype byte and its body convention.

---

## Why `0xcc`

`cc` for *certificate*, but also a satisfying byte pattern (`11001100`)
that's easy to spot in hexdumps. No collision with the other
established type bytes (`00` text, `03` image, `07` audio, `0e`
encrypted, `1d` identity, `ab` binding, `ce` celestial, `ee` Estandarte).
