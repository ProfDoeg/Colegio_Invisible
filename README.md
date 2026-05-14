# Colegio Invisible

Research and development on the **quipu** — a multi-strand inscription
protocol that records arbitrary data (text, images, encrypted payloads)
across the Dogecoin blockchain.

The name comes from Andean *quipus*: knotted-string records where meaning
lives in the structure of the knots and the relationships between strands.
Here, each "strand" is a chain of OP_RETURN-bearing transactions, and a
quipu is a transaction with multiple outputs that each become the head of
a strand. Reading a quipu walks each strand and concatenates the recorded
bytes.

---

## Status

**Active R&D on the production code.** The course notebooks (see Archive
below) are frozen — they were written when the SoChain v2 API was the
reading mechanism, which has since been deprecated. Reanimating the course
would require infrastructure work that is currently out of scope.

The protocol itself, the toolkit, and the production code paths are all
under active development against a local Dogecoin Core node.

---

## Repo layout

The repo contains three logically separate things. They share a folder
because they share a history; treat them as separate projects.

### Production code (active)

- `colegio_tools.py` — the canonical library. Node-backed `Cadena` /
  `CadenaMulti` writers, pre-scan reader (`scan_accounts`,
  `read_quipu`, `find_quipu_roots`), image bit-codec, ECIES helpers,
  key/wallet utilities. Loads RPC credentials from `.env`.
- `.env.example` — template for RPC credentials. Copy to `.env` and fill in.
- `smoke_test.py` — single-script health check. Run after setup to confirm
  imports, codec round-trips, key save/load, and node connectivity.
- `tests/sample.png` — small fixture image used by the smoke test.
- `quipu_orchestrator.py` — `Quipu` class implementing the **two-phase
  diamond pattern**: consolidation → root tx (1→N) → parallel strand
  fill → joining tx (N→1) → consolidated UTXO. Each quipu opens from
  one input and closes to one output.
- `quipu_console.py` — **Streamlit interface** for the toolkit. Four
  tabs: Plan (text/image authoring with live encoding preview),
  Inscribe (the three-phase build, with per-phase buttons and
  confirmation waits), Read (decode any quipu by txid), Wallet
  (UTXO browser + force-directed history topology with click-to-popup
  showing decoded content for every quipu rooted at the address).
- `STATUS.md` — current corpus state, what works end-to-end, what's
  open. Read this first to orient.

#### Launching the Streamlit console

```bash
# Make sure the Dogecoin Core daemon is running (see "Setup" below)
~/Desktop/dogecoin/src/dogecoind -daemon

# Start the console
cd ~/Desktop/Colegio_Invisible
.venv/bin/streamlit run quipu_console.py
# Opens at http://localhost:8501
```

In the sidebar: load a key (the apocrypha test key lives at
`~/Desktop/cinv/llaves/mi_prv.enc` with empty-string password). Pick
an address in the Wallet tab to see its full quipu history as a
force-directed network of broom-heads.

### CLI toolkit (stable, useful)

A bilingual (Spanish / English) set of standalone command-line utilities
exposing the cryptographic primitives used by the project. These work
independently of the rest of the codebase and have no Dogecoin dependency.

- `ecc_generate.py` — generate an ECC private key
- `ecc_keyboard.py` — import an ECC key from hex input
- `ecc_pubkey_extract.py` — derive public key from private key
- `ecc_keydump.py` — print decrypted contents of a keyfile
- `ecc_sign.py` / `ecc_verify.py` — ECDSA sign and verify
- `ecc_encrypt.py` / `ecc_decrypt.py` — ECIES message encryption
- `aes_encrypt.py` / `aes_decrypt.py` — symmetric AES with password-derived key
- `sha_256.py` — file hashing

Each script prints usage when run with the wrong argument count. Most prompt
securely (via `getpass`) when passwords are not given on the command line.

### Archive (frozen)

Material kept for reference. Not maintained, not guaranteed to run.

- `01_cuaderno.ipynb` … `20_cuaderno.ipynb` — the course curriculum.
  Twenty bilingual notebooks structured as a spiral covering Python and
  terminal basics → symmetric and asymmetric cryptography → Dogecoin
  keys/addresses/transactions → multisig → OP_RETURN inscription →
  multi-strand quipus → encrypted broadcast → BIP44 / HD wallets.
- `quipu2.ipynb`, `quipu3-saved.ipynb` — R&D scratch notebooks from the
  transition off SoChain. Most of `colegio_tools.py` was distilled from
  these.
- `notas/`, `scripts/`, `secrets/`, `sound/`, `img/` — supporting assets
  from earlier development.

---

## Setup

Requires Python 3.9+ and a synced Dogecoin Core node reachable over RPC.

The setup has two big pieces: getting the **node** running, and getting
the **Python toolkit** ready against it. Once both are in place, the
**daily launch sequence** is two commands.

### 1. Dogecoin Core node

The toolkit is designed to work against a **pruned watch-only** node
(~20 GB on disk instead of the full ~110 GB chain). Detailed build
instructions for macOS are in `doc/build-macos.md` of the
[ProfDoeg/dogecoin](https://github.com/ProfDoeg/dogecoin) fork; the
quick version:

```bash
# Install build deps via Homebrew (Intel Mac, macOS 13+)
brew install autoconf automake libtool miniupnpc openssl pkg-config \
             protobuf@21 zeromq qrencode boost@1.85 berkeley-db@5 libevent

# Clone, configure (daemon-only — no GUI requires full Xcode), build
git clone https://github.com/ProfDoeg/dogecoin ~/Desktop/dogecoin
cd ~/Desktop/dogecoin
git checkout 1.14-maint
./autogen.sh
PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig:$(brew --prefix libevent)/lib/pkgconfig:$(brew --prefix protobuf@21)/lib/pkgconfig" \
BDB_LIBS="-L$(brew --prefix berkeley-db@5)/lib -ldb_cxx-5.3" \
BDB_CFLAGS="-I$(brew --prefix berkeley-db@5)/include" \
./configure --without-gui --without-miniupnpc \
            --with-boost="$(brew --prefix boost@1.85)"
make -j$(sysctl -n hw.ncpu)
```

Then create the node's config file at
`~/Library/Application Support/Dogecoin/dogecoin.conf`:

```ini
server=1
rpcuser=drdoeg
rpcpassword=password
rpcport=22555
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
prune=20000          # ~20 GB rolling window
listen=1
dbcache=2048
```

Start the daemon and import the four watched addresses **before** the
sync gets far (rescan=false so they accumulate matches as new blocks
arrive):

```bash
~/Desktop/dogecoin/src/dogecoind -daemon
CLI=~/Desktop/dogecoin/src/dogecoin-cli
$CLI importaddress 9xth7DcLGb1nACScMBeSfDCfghhLKF7yqs "hca" false
$CLI importaddress A7pfCe2Cw9JD2C4vEZbpDmUZJy7B2TaefV "ha" false
$CLI importaddress AD28bxzxyrd3a4Qgad2VNQ2eN5Leg8ozuw "ca" false
$CLI importaddress D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX "old_inscribe" false
```

Initial sync takes several hours to a day depending on bandwidth. Check
progress with `$CLI getblockchaininfo` — `initialblockdownload: false`
and `verificationprogress` near 1.0 means done.

### 2. Python toolkit (this repo)

```bash
# Clone
git clone https://github.com/ProfDoeg/Colegio_Invisible
cd Colegio_Invisible

# Create a venv and install dependencies (pinned in requirements.txt)
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Configure node access
cp .env.example .env
$EDITOR .env       # fill in RPC_USER, RPC_PASSWORD, RPC_HOST, RPC_PORT
                   # — same credentials you set in dogecoin.conf

# Verify everything works
.venv/bin/python smoke_test.py
.venv/bin/python test_quipu_crypto.py    # 23 crypto seal tests
```

### 3. Local-only files not in this repo

A few things the toolkit expects are deliberately **not** committed.
They're either secrets, locally-generated state, or chain data:

| Path | What it is | Source |
|---|---|---|
| `~/Library/Application Support/Dogecoin/dogecoin.conf` | Node RPC config | You write it (see above) |
| `~/Library/Application Support/Dogecoin/blocks/`, `chainstate/` | Pruned chain data | The daemon writes it during sync |
| `<repo>/.env` | RPC credentials for `colegio_tools` | `cp .env.example .env`, then edit |
| `<repo>/.venv/` | Python virtual environment | `python3 -m venv .venv` |
| `~/Desktop/cinv/` | Your key files (encrypted `.enc`, public `.bin`, address QRs) | **Yours.** Restore from your own backup, or generate fresh keys with the CLI toolkit and lose continuity with the existing on-chain corpus. |
| `~/Desktop/cinv/labels.json` | UTXO labels you've added in the console | Auto-created by `quipu_console.py` |

The `~/Desktop/cinv/` directory is the most important non-repo dependency.
It holds the keys used to sign new inscriptions — particularly:

- `llaves/mi_prv.enc` — the apocrypha test key (empty password,
  effectively unprotected — this is the convention for test inscriptions)
- `hayagriva_pvt.enc`, `christophia_pvt.enc`, `anthony_pvt.enc` — the
  three bordado witness keys (real passwords, required together as a
  3-of-3 multisig)
- Plus various `.bin` public-key and address files

If you don't have these (e.g., setting up on a new laptop), you'll need
to restore from your own backup. They are not in this repository and
never should be.

### 4. Daily launch sequence

Once both the node and toolkit are set up:

```bash
# Start the Dogecoin Core daemon (if not already running)
~/Desktop/dogecoin/src/dogecoind -daemon

# Confirm it's responsive
~/Desktop/dogecoin/src/dogecoin-cli getblockchaininfo | grep blocks

# Start the Streamlit console
cd ~/Desktop/Colegio_Invisible
.venv/bin/streamlit run quipu_console.py
# Opens at http://localhost:8501
```

Or, if you only want to use the toolkit programmatically:

```python
from colegio_tools import scan_accounts, find_quipu_roots, read_quipu

df_tx, df_out = scan_accounts({"D6zKNn...": "old_inscribe"})
roots = find_quipu_roots("D6zKNn...", df_tx, df_out)
header, body = read_quipu(roots[0], df_out)
```

### Dependencies

Pinned in `requirements.txt` (frozen against Python 3.9.6 on macOS).
Direct deps: `numpy`, `pandas`, `requests`, `python-dotenv`, `qrcode`,
`Pillow`, `eth-keys`, `coincurve`, `eciespy`, `pycryptodome`,
`cryptos` (a fork of Vitalik Buterin's pybitcointools — fragile, the
pin is load-bearing), `streamlit`, `plotly`, `pyvis`.

---

## Glossary

- **Quipu** — a transaction whose outputs become the heads of multiple
  data-bearing strands. The structure is named after Andean knotted-string
  records.
- **Strand** (sometimes *cadena*) — a linear chain of self-spending
  transactions, each carrying an 80-byte OP_RETURN payload. Reading a
  strand walks forward through the chain and concatenates the payloads.
- **Header** — bytes at the start of a quipu describing its type, version,
  and content. Begins with the protocol magic `0xC1DD` and a 2-byte
  version. Type/tone byte allocations are an active design question; see
  `notebooks/18_cuaderno.ipynb` for current thinking.
- **OP_RETURN** — a Bitcoin/Dogecoin script opcode that creates a
  provably-unspendable output. Up to 80 bytes of arbitrary data can be
  attached. The mechanism that makes inscription possible.
- **Cadena / CadenaMulti** — the writer classes that build, sign, and
  broadcast a strand of inscription transactions. `CadenaMulti` uses a
  multisig address as the strand's funding holder.

---

## Roadmap

Rough direction, in no particular order:

- Split `colegio_tools.py` into a real package (`src/colegio/...` with
  `node`, `inscriptions`, `crypto`, `imaging` submodules)
- Multisig orchestrator — the two-phase `Quipu` class is single-key
  (apocrypha-style); a `QuipuMulti` extension would handle the bordado
  3-of-3 (and 2-of-2 paired) inscriptions with PSBT-style round-robin
  signing across the witnesses
- Formalize the header protocol — type bytes, tone bytes, type-specific
  layouts beyond the image case (DRAFT specs already in
  `docs/quipu-types/` and `docs/quipu-syntax/`)
- Eventually: fold quipu read/write into a fork of Dogecoin Core's wallet
  software, exposing it as native RPC and wallet UI features

---

## Security notes

- `secrets/` and `.env` are listed in `.gitignore` for a reason. Anything
  in those locations should be treated as local-only.
- Encrypted keyfiles use a single SHA-256 of the password as the AES
  key. This is a deliberate minimal-cryptography choice — the protocol's
  register is hand-picked primitives, not modern password-hardening
  KDFs. Passworded keyfiles offer obfuscation against casual inspection;
  they are not strong protection against a motivated attacker with the
  keyfile bytes. Use a long, high-entropy password and keep the keyfile
  itself local.
- The RPC credentials in old commit history may have been exposed. If
  this matters, rotate them.
