# Next session — handoff: keydrop display

The current console can read text quipus, image quipus, identity, cert,
and shows encrypted (`0x0e`) quipus as opaque "🔒 encrypted, N bytes
ciphertext." The next build is to **decrypt and display encrypted
quipus when a corresponding key-drop quipu has been published on
chain.**

## Background — what a key drop is

A key drop is a quipu of type `0x0e 0x0e 0x0d`. Its body contains:

```
[encrypted_txid: 32 bytes][aes_key: 32 bytes]
```

The pattern (from the protocol's original design, per
`quipu_header_bytes.md`):

1. Author broadcasts an encrypted quipu (e.g., `0x0e 0x03` for an
   encrypted image). Body layout:
   `[N_recip × 64-byte session-key copies][AES-encrypted body]`
2. Sometime later, the author broadcasts a key drop revealing the AES
   session key.
3. Anyone reading the chain can now **bypass the per-recipient
   session-key copies entirely** and decrypt the body directly with
   the released key.

## The on-chain test pairs

There are exactly two encrypted-image + key-drop pairs already on
apocrypha. End-to-end test data for free:

| Encrypted image quipu | Key drop quipu |
|---|---|
| `d68175766b70f716...` ("Here is an encrypted image going out to a very special lady...Wow") | `89b51b4852b0e80f...` ("Release something glorious to the world") |
| `d0209a0f85872d68...` ("This is an encrypted image for two special ladies...Hola") | `f278e466012fb784...` ("Release something glorious to the world") |

If the implementation works, opening either encrypted image's popup in
the topology view should reveal the actual decrypted image (instead of
the current ciphertext blob).

## Where to add the support

In `quipu_console.py`:

1. **`build_quipu_content_html`** (the topology popup) — currently
   handles `type_byte == 0x0e` by showing the lock icon and ciphertext
   byte count. Needs to:
   - Detect if this encrypted quipu has a corresponding key drop on
     chain
   - If yes: pull the AES key from the key-drop body, skip past the
     session-key copies in the encrypted body, AES-decrypt the
     remainder, render the inner content as the appropriate type
     (image / text / etc.) using the existing per-type rendering
     code
   - If no key drop yet: keep the current "🔒 encrypted" display

2. **Same logic** in the dropdown inspector and the Read tab decoder
   (three sites total).

3. **Key-drop quipus themselves** — currently fall through to the
   generic "no specialized decoder" branch. Should:
   - Parse body as `[encrypted_txid (32 bytes)][aes_key (32 bytes)]`
   - Display: "🗝 releases the key for `<encrypted_txid>`" with a
     mini-link to that quipu's display, plus the AES key (perhaps
     truncated for display)

## Implementation sketch

A helper to find the key drop that releases a given encrypted quipu:

```python
def find_keydrop_for(encrypted_txid, quipus, df_out):
    """Scan a list of quipus for a key drop whose body's first 32 bytes
    match encrypted_txid (as raw bytes, big-endian). Returns
    (keydrop_quipu, aes_key_bytes) or None."""
    target = bytes.fromhex(encrypted_txid)[::-1]  # txid is little-endian on-wire
    for q in quipus:
        if q['type_byte'] != 0x0e:
            continue
        # Confirm it's specifically a key drop (0x0e 0x0e 0x0d) not just
        # any encrypted-family type — check header bytes 5 and 6
        # (header_bytes[5] == 0x0e, header_bytes[6] == 0x0d)
        ...
        h, b = read_quipu_bytes(q['root_txid'], df_out)
        if len(b) >= 64 and b[:32] == target:
            return q, b[32:64]
    return None


def decrypt_with_keydrop(encrypted_body_bytes, aes_key, n_recip):
    """Skip past the N_recip × 64-byte session-key copies and AES-decrypt
    the remainder using the released key (from the key drop)."""
    skip = n_recip * 64
    ciphertext = encrypted_body_bytes[skip:]
    return ecies.sym_decrypt(aes_key, ciphertext)
```

Note on **endianness of the txid in the key-drop body**: needs
verification against the actual on-chain pairs. The convention is
likely little-endian internal representation (Bitcoin-style) vs the
big-endian display form. Test by computing both directions.

## Caveats and open questions

1. **The `n_recip` field needs to be parsed** from the encrypted
   quipu's header (per `quipu_header_bytes.md`, byte 12 for
   `0x0e 0x03`). Don't assume `n_recip = 1`.

2. **Endianness of encrypted_txid in keydrop body** — verify by
   comparing the body's first 32 bytes (both directions) against the
   txids of the known encrypted quipus.

3. **What if more than one key drop exists for the same encrypted
   quipu?** Probably take the first; in practice the user wouldn't
   re-drop. Handle gracefully.

4. **Auto-link in the topology graph** — once the encrypted ↔ key-drop
   mapping is detected, we could draw an explicit edge between the
   two nodes in the pyvis network. Useful but optional for v1.

## Files to touch

- `quipu_console.py` — content rendering, three sites (popup,
  dropdown inspector, Read tab)
- Possibly `colegio_tools.py` — add the `find_keydrop_for` helper
  there for reusability, or keep it inline in `quipu_console.py`

## Test plan

1. Compute history on apocrypha (already cached if the console was
   recently used, otherwise ~30-60s rescan)
2. Click the encrypted image quipu `d68175...` in the topology
3. Should see the actual decrypted image (was previously a ciphertext
   blob)
4. Repeat for `d0209a...`
5. Click each key drop (`89b51b...`, `f278e4...`) — should see "this
   releases the key for ..." with the referenced txid

## Beyond this build

Subsequent natural extensions, in roughly increasing complexity:

- **Visual link in topology**: dashed edge from key-drop node to the
  encrypted-quipu node it unlocks
- **Compose new encrypted broadcasts**: extend the Plan/Inscribe tabs
  to handle the encryption pipeline (probably with the `0x0e 0x00`
  text variant first since image header layout is more complex)
- **Combined-key ECIES**: the multi-keyholder threshold seals from
  `quipu_crypto.py` (`combine_pubkeys`/`combine_privkeys`) — used by
  the five-seal La Verna scheme. Wire into the console for ceremonial
  unsealing workflows (need all N participants present)
- **Multisig orchestrator** (`QuipuMulti`): the bigger build that lets
  you actually inscribe La Verna's bordado certificate. PSBT-style
  round-robin signing among Hayagriva, Christophia, Anthony.

## Where state currently is (2026-05-14)

- 25 quipus on chain (23 historical + Atom + Sabina)
- Apocrypha: 1 UTXO of 16.85 DOGE (consolidated from Sabina join)
- Bordado: 2 pre-funded cert roots awaiting strands (`a90fb985...` La
  Verna, `891126...` third certificate) + ~6,800 DOGE in reserves
- Streamlit console runs at http://localhost:8501; launch with:
  ```
  cd ~/Desktop/Colegio_Invisible
  .venv/bin/streamlit run quipu_console.py
  ```
- Latest commit on `main`: `9f4cd2b` (README setup expansion)
