# Encrypted-wire reconciliation (0x0e) — July 2026

Deliberately split out of the v0.2 build (`c1dd0002.md` §"Deliberately out
of scope"). This session closed it.

## The fork that was

Two live implementations of the 0x0e family cross-misparsed each other:

| | `colegio_tools.py` (nb17/nb18, 2022) | `canonical/encrypted.py` (May 2026) |
|---|---|---|
| AES | `0e ae` spliced after magic, **inner header cleartext**, body-only sealed | `0e <tone> ae <variant>`, whole inner (header+body) length-framed and sealed |
| broadcast | `0e <inner_type> <color LLWWB> <N> \|title\|`, N in header | `0e <tone> ec 00`, N as first body byte |
| keydrop | `0e 0e 0d \|title\|`, body = `[txid:32][key:32]` | `0e <tone> 0d <variant>`, body = u16 count + named drops |

The canonical reader parsed a legacy keydrop's title bytes as a u16 drop
count; the legacy reader saw canonical tones as inner types. Each side's
callers were blind to the other side's inscriptions.

## On-chain ground truth (the decider)

Both eras are inscribed; neither implementation could simply win.

* pre-canonical (blocks 4.25–4.27M, 2022): `d68175`/`d0209a` broadcasts,
  `89b51b`/`f278e4` keydrops (each releasing one broadcast's session key).
* canonical v1 (blocks ~6.21M, 2026): `00109923` (ae·password),
  `f7a8ee4f` (ae·raw), `1bbc2dff` (ec), `c277cd57` (keydrop releasing the
  previous two).

## The reconciliation

1. **One parser.** `canonical/encrypted.py` owns the wire format. It gained
   `classify_encrypted()` (era detection from header bytes — unambiguous:
   canonical always has a registered tone at byte 5 and a registered
   sub-family at byte 6; the legacy layouts never do at both positions),
   legacy readers (`parse_legacy_keydrop`, `read_legacy_broadcast_quipu`,
   `read_legacy_aes_sealed`), and `open_with_key()` (apply a released key to
   a sealed quipu of either era). `read_encrypted_quipu` dispatches on the
   classification and returns canonical-shaped dicts with `legacy: True`
   for the old era.
2. **Writers emit canonical only.** `colegio_tools.build_*` keep their
   historical signatures but now delegate to the canonical builders. The
   pre-canonical layouts are never written again. (Side benefit: the old
   AES splice leaked the entire inner header in cleartext; the canonical
   wrap seals it.)
3. **Readers accept both.** `colegio_tools.read_* / parse_* / apply_keydrop
   / find_keydrop_for` delegate to the unified reader; the console, viewer,
   refs resolver, and dataset builder all read through it.
   `colegio_pipeline.split_blob` learned the legacy header spans (7+title
   for `0e 0e 0d`, 13+title for the nb17 broadcast).
4. **Proof.** `tests/test_encrypted_wire.py`: every sealed on-chain 0x0e
   quipu with a public keydrop decrypts end-to-end (legacy plaintexts
   byte-exact: 15360 B / 2560 B image streams; canonical inners
   magic-checked and text-decoded), plus cross-misparse regressions and
   wrapper-surface checks. Corpus regression (448-test suite) green.

This is consistent with the healing model: the originals stay exactly as
inscribed; the READERS grew until everything on chain is legible again.

## Unauthenticated AES — proposal only (no wire change)

All 0x0e sealing is AES-256-CBC via `ecies.sym_encrypt` with **no MAC**.
The only integrity signal after decryption is `magic_ok` (the inner
`c1dd0001`), which any bit-flipped ciphertext tail passes — CBC malleability
lets an attacker flip chosen plaintext bits in block N by garbling block
N−1. Threat is modest (inscriptions are immutable once mined; the realistic
window is pre-broadcast relay), but a keyed integrity check is cheap.

**Proposal for the v0.2 registry triage (do not implement before the
registry conversation — v1 is frozen and the constitution's amendment
ladder applies):**

* New AES variants `0x02` (raw key + MAC) and `0x03` (password + MAC):
  body = `HMAC-SHA256(mac_key, ciphertext)[:16]` ‖ ciphertext, with
  `enc_key = HKDF(key, "colegio-enc")`, `mac_key = HKDF(key, "colegio-mac")`
  — encrypt-then-MAC, verify before decrypt.
* Same for `ec` envelopes' payload ciphertext (envelopes themselves are
  already all-or-nothing: a garbled envelope yields a wrong session key and
  total decryption failure).
* Existing variants stay valid and readable forever; readers treat the MAC
  variants as strictly-preferred for new writes once registered.

Until then, `magic_ok` remains the honest, documented integrity level.
