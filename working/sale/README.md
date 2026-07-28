# The sale, and opening it

The *On Custody* verified-key sale, inscribed 2026-06-08, is the protocol's
one deployed atomic content sale. This directory holds what built it and what
now opens it.

## Opening it, offline

Needs nothing but the repo. No node, no network, no keys.

```bash
.venv/bin/python working/sale/open_from_chain.py
```

That walks the sealed box to the key that opens it and prints the essay. Give
it any other sealed root to walk that one instead:

```bash
.venv/bin/python working/sale/open_from_chain.py <root_txid> --out /tmp/plain.md
```

All six openable sealed quipu open this way. `00109923` does not, and should
not: it is sealed under a private passphrase and no key was ever published.

## What the walk proves

Nothing secret is used. The seller published `session_priv` on chain in a
keydrop, and the keydrop is reachable from the sealed quipu itself:

```
f74a53b7  box root, 0x0e 0xcb, four strand outputs
   └─ four OP_RETURN chains ──> 53f90464  the join
        └─ tail ──> ac2f8fb3 ──> 333960698b05  the keydrop
                                   drop "session" opens f74a53b7
                                   header claim=dd57dbc9
```

The tail is the diamond's own continuation, so a reader who has the box can
find the publication without being told where to look. The bond and the claim
are not on that lineage, they descend from the buyer's funds; you reach them
through the keydrop's `claim=` header field.

Two honest limits, both reported by the script when they apply. The 2022 pair
predates the running thread, so their keydrops are siblings rather than
descendants and are found by a catalogue search instead; the script says which
route it used. And `session_priv` cannot be recovered from the claim alone:
extracting it from the adaptor-completed signature needs the pre-signature from
the offer, which travelled as a Nostr DM. That is exactly why the keydrop was
inscribed.

## The artifacts

| artifact | txid | block |
|---|---|---|
| box, `0x0e 0xcb` | `f74a53b76bb2…` | 6240572 |
| bond, P2SH | `51839f00701d…` | 6240592 |
| claim | `dd57dbc9bcb1…` | 6242356 |
| keydrop, `0x0e 0x0d` v1 | `333960698b05…` | 6240693 |

Seller: `DA4zu5QTQXvwLg58KTZEgiShyBN9gxc5ka`. That address is not one of the
nine `update_quipu_data.py` walks, which is why none of this was catalogued
until now.

## Rebuilding the bundle

Only needed if the set changes. Wants a fork node for `quipuscan` and any
txindex node for the transactions.

```bash
.venv/bin/python working/sale/bundle_sale.py --dry-run
```

It writes `data/bodies/<root>.bin`, `data/thread/<txid>.hex` (tracked, this is
what makes the offline walk work on a fresh clone), a record per transaction
into the ignored fetch cache, and a catalog row per quipu. Re-running is safe.

## Reaching the fork node from the road

No WireGuard client needed on the travel Mac, the VPS jump is enough:

```bash
ssh -J root@167.233.121.56 drdoeg@10.99.0.2 'dogecoin-cli -rpcport=22600 getblockcount'
```

For spectra or `--node` work, forward the fork RPC to a local port:

```bash
ssh -N -J root@167.233.121.56 -L 26000:127.0.0.1:22600 drdoeg@10.99.0.2
```

## The rest of the directory

`build_sale.py`, `build_box_inscription.py`, `build_real_claim.py`,
`build_bond_funding.py`, `build_keydrop_inscription.py` are what produced the
sale in June. They carry hardcoded `~/Desktop/cinv` paths and an old
`dogecoin-cli` path, so they run as written only on the machine that inscribed
it. `verify_sale.py`, `extract_and_decrypt.py` and `verify_nostr_roundtrip.py`
are the checks from that day, and they expect a `working/sale/artifacts/`
directory that was never committed.
