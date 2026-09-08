#!/usr/bin/env python3
"""verify_golem_book.py -- read El Libro del Gólem back off the Dogecoin chain
through the project's own node and compare every strand, byte for byte, with
the artifacts committed in working/golem/artifacts/ on 2026-05-23.

    python3 atlas_tools/verify_golem_book.py [--datadir ~/.dogecoin]

For each of the 13 quipus listed in quipu_order.txt: strand 0 is the header,
strands 1..N are body chunks. Each strand's txids come from
strand_<name>_<k>.txids; every tx is fetched with `dogecoin-cli
getrawtransaction <txid> 1` and its OP_RETURN payloads are concatenated in
order. The result is compared with <name>_header.bin and <name>_body.bin.
Prints a table and exits 0 only if everything matches. Read-only: never
touches wallets, never calls stop.
"""
import glob, hashlib, json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
ART = os.path.join(REPO, "working", "golem", "artifacts")
CLI = "/usr/local/bin/dogecoin-cli"
DATADIR = os.path.expanduser("~/.dogecoin")
if "--datadir" in sys.argv:
    DATADIR = os.path.expanduser(sys.argv[sys.argv.index("--datadir") + 1])


def rawtx(txid):
    out = subprocess.run([CLI, f"-datadir={DATADIR}", "getrawtransaction", txid, "1"],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def op_return_bytes(tx):
    chunks = []
    for o in tx["vout"]:
        asm = o["scriptPubKey"].get("asm", "")
        if asm.startswith("OP_RETURN"):
            parts = asm.split()
            if len(parts) > 1:
                chunks.append(bytes.fromhex(parts[1]))
    return b"".join(chunks)


def read_strand(path):
    data = b""
    n = 0
    for line in open(path):
        txid = line.strip()
        if not txid:
            continue
        data += op_return_bytes(rawtx(txid)); n += 1
    return data, n


def main():
    order = [l.strip() for l in open(os.path.join(ART, "quipu_order.txt")) if l.strip()]
    all_ok = True; total_tx = 0; total_bytes = 0
    print(f"{'quipu':8s} {'strands':>7s} {'txs':>5s} {'hdr':>4s} {'body':>5s} {'bytes':>7s}  root")
    for name in order:
        files = sorted(glob.glob(os.path.join(ART, f"strand_{name}_*.txids")),
                       key=lambda p: int(re.search(r"_(\d+)\.txids$", p).group(1)))
        header_chain, n0 = read_strand(files[0])
        body_chain = b""; ntx = n0
        for f in files[1:]:
            d, n = read_strand(f); body_chain += d; ntx += n
        header_disk = open(os.path.join(ART, f"{name}_header.bin"), "rb").read()
        body_disk = open(os.path.join(ART, f"{name}_body.bin"), "rb").read()
        h_ok = header_chain == header_disk
        b_ok = body_chain == body_disk
        root = open(os.path.join(ART, f"root_{name}.txid")).read().strip()
        all_ok &= (h_ok and b_ok); total_tx += ntx; total_bytes += len(header_chain) + len(body_chain)
        print(f"{name:8s} {len(files):7d} {ntx:5d} {'ok' if h_ok else 'DIFF':>4s} {'ok' if b_ok else 'DIFF':>5s} {len(body_chain):7d}  {root[:16]}…")
        if name == "forward" and b_ok:
            text = body_chain.decode("utf-8", "replace")
            print("   forward body begins:", repr(text[:110]))
            print("   forward body sha256:", hashlib.sha256(body_chain).hexdigest())
    print(f"\n{total_tx} transactions read, {total_bytes} bytes of OP_RETURN payload; "
          + ("ALL 13 QUIPUS MATCH THE COMMITTED ARTIFACTS" if all_ok else "MISMATCH FOUND"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
