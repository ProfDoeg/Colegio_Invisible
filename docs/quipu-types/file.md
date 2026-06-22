# Quipu type `0x0F` — File

> **STATUS: CANONICAL v1.** Implemented in
> [`canonical/file.py`](../../canonical/file.py). A generic binary
> container: any blob of bytes inscribed as a named, typed file with
> optional integrity protection.

A *file quipu* wraps an opaque body of raw file bytes in a small,
self-describing header. The header carries an **optional** sha256
digest of the body (flag-gated), a **mimetype**, a **filename**, and an
**optional title**. The container never interprets the body — that is
the whole point. PDFs, archives, fonts, firmware, anything: if it is a
sequence of bytes with a name, it can be a `0x0F` file.

The reader is **keyless** and the container parse is **pure stdlib**
(`struct` + `hashlib` only — no numpy, no third-party imports).

---

## Byte layout

### Header — variable length

```
offset  bytes            meaning
0..3    c1 dd 00 01      magic + protocol version 0.1
4       0f               type byte = file
5       <tone>           tone byte — see tone.md for the canonical vocabulary
6       <flags>          bit0 (0x01) = sha256 present;
                         bits 1-7 reserved (MUST be 0)
[7..38] <sha256:32>      present IFF flags bit0 set —
                         raw sha256 digest of the body
N       <mimelen>        length of mimetype, 0..255
N+1..   <mimetype>       UTF-8 (e.g. 'application/pdf'); may be length 0
M       <namelen>        length of filename, 0..255
M+1..   <filename>       UTF-8 (e.g. 'report.pdf')
K       <titlelen>       length of title, 0..255
K+1..   <title>          UTF-8 human title; may be length 0
```

The structural prefix up to and including the flags byte is **7 bytes**
(offsets 0..6). When the sha256 flag is set, the 32-byte digest occupies
offsets 7..38; otherwise the length-prefixed fields begin at offset 7.

Each of the three text fields is **length-prefixed and self-delimiting**,
so the header length is recoverable from the header bytes alone — a
reader never needs the total blob length to find where the header ends
and the body begins:

```
header_len = 7
           + (32 if flags & 0x01 else 0)
           + 1 + mimelen
           + 1 + namelen
           + 1 + titlelen
```

All multi-byte values are **big-endian** (here only the digest is
multi-byte, and it is a raw opaque hash, not an integer).

### Body — raw file bytes

The body is opaque. The container neither parses nor transforms it.
The reader reports `size = len(body)` and returns the bytes verbatim.

---

## The `sha256` flag and the tri-state contract

Integrity is **optional**. Whether a digest is present is decided
solely by **bit0 of the flags byte** — never inferred from the header
length. This makes the absent-digest case unambiguous: a file with no
hash is *not making an integrity claim*, and must therefore **never**
read as "tampered".

The reader exposes integrity as a three-valued `sha256_ok`:

| `flags & 0x01` | `has_sha256` | `sha256` | `sha256_ok` | meaning |
|---|---|---|---|---|
| clear | `False` | `None` | `None` | no integrity claim made |
| set, digest matches | `True` | 64-hex | `True` | verified |
| set, digest differs | `True` | 64-hex | `False` | genuine tamper / corruption |

- `has_sha256 = bool(flags & 0x01)`.
- When clear: `sha256 = None`, `sha256_ok = None`.
- When set: `sha256` is the 64-char lowercase hex of the stored digest;
  `sha256_ok = (hashlib.sha256(body).digest() == stored)`.
- `sha256_ok is False` happens **only** on a genuine present-digest
  mismatch — flipping a single body byte is enough to trip it.

A header whose `flags` has any **reserved bit (1..7)** set is
**rejected** (the reader raises `ValueError`) rather than silently
reinterpreting the following bytes. The builder never sets a reserved
bit.

### Renderer rule

A renderer should show:

- a **verified** badge only when `sha256_ok is True`,
- a **tampered** warning only when `sha256_ok is False`,
- and **nothing** about integrity when `sha256_ok is None` (an unhashed
  file is not "tampered" — it simply never claimed a hash).

---

## API

```python
build_file_quipu(filename, body, *, mimetype='', sha256=None,
                 title='', tone=TONE_ORDINARY) -> (header_bytes, body_bytes)
```

`sha256` parameter:

| value | effect |
|---|---|
| `None` or `False` | omit digest; flags bit0 clear |
| `True` | digest = `hashlib.sha256(body).digest()`; flags bit0 set |
| `bytes` of length 32 | used verbatim; flags bit0 set |
| anything else (incl. wrong-length bytes) | raises `ValueError` |

Validation: `validate_tone(tone)`; each of `mimetype` / `filename` /
`title` must encode to ≤ 255 UTF-8 bytes; reserved flag bits stay 0.
The body is returned unchanged.

```python
read_file_quipu(header_bytes, body_bytes) -> dict
```

Returns:

```python
{
  'type':       'file',
  'tone':       int,
  'flags':      int,
  'has_sha256': bool,
  'sha256':     str | None,     # 64-char lowercase hex, or None
  'sha256_ok':  None | True | False,
  'mimetype':   str,
  'filename':   str,
  'title':      str,
  'body':       bytes,
  'size':       int,            # len(body)
}
```

Validates magic == `c1dd0001`, `header_bytes[4] == 0x0F`, and that no
reserved flag bits are set. **Keyless** — no key material is consulted.

**Reader calling convention.** `decode.py` invokes every reader as
`reader(hdr, body)` — the header strand and body strand arrive as two
separate `bytes` arguments, so the signature is
`read_file_quipu(header_bytes, body_bytes)`.

---

## Why `0x0F`

`0x0F` was the lowest free type byte: `0x0C` (cert-precursor) and `0x0E`
(encrypted) were already allocated, and `0x0F` was unused across every
registry. It sits just past the encrypted type — a fitting neighbour,
since both are "envelope" types that carry an opaque payload (one
encrypted, one merely named).

The mnemonic is loose but apt: `0F` ≈ "file" — the generic catch-all
for bytes that do not (yet) have a dedicated, structured quipu type.

---

## Reference parser

See [`canonical/file.py`](../../canonical/file.py) for the authoritative
builder + reader. Round-trip self-tests cover:

- a file **with** sha256 — asserts `sha256_ok is True`, and that
  flipping one body byte makes a fresh read's `sha256_ok` `False`;
- a file **without** sha256 — asserts `has_sha256 is False` and
  `sha256_ok is None`, even against a wholly different body (never a
  false tamper);
- mimetype / filename / title / tone round-trip, including non-ASCII
  UTF-8 fields, a verbatim 32-byte digest, and empty mimetype/title;
- validation cases (over-long fields, bad tone, wrong-length digest,
  bad `sha256` type, reserved flag bit set);
- container purity (`numpy` not imported after `import file`).
