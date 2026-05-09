#!/usr/bin/env python3
"""
smoke_test.py — Run from repo root to verify the project setup is healthy.

Walks through dependency-ordered checks. Each check only runs if its
prerequisites passed. Prints ✓ / ✗ / ⊘ and a final tally.

Usage:
    python smoke_test.py

Exit code 0 if all required checks pass, 1 otherwise.
"""

import os
import sys
import traceback
from pathlib import Path


# Track results
results = []  # list of (name, status, detail)


def check(name, required=True):
    """Decorator for individual checks. The decorated function returns
    a detail string on success or raises on failure."""
    def deco(fn):
        def runner():
            try:
                detail = fn()
                results.append((name, "PASS", detail or ""))
                detail_str = f" — {detail}" if detail else ""
                print(f"  ✓ {name}{detail_str}")
                return True
            except SkipTest as e:
                results.append((name, "SKIP", str(e)))
                print(f"  ⊘ {name} — skipped: {e}")
                return None
            except Exception as e:
                results.append((name, "FAIL", str(e)))
                print(f"  ✗ {name}")
                print(f"      {type(e).__name__}: {e}")
                if os.getenv("SMOKE_VERBOSE"):
                    print(traceback.format_exc())
                return False
        runner.required = required
        return runner
    return deco


class SkipTest(Exception):
    pass


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

@check(".env loads and required vars are set")
def check_env():
    try:
        from dotenv import load_dotenv
    except ImportError:
        raise RuntimeError("python-dotenv not installed — `pip install python-dotenv`")
    load_dotenv()
    required = ["RPC_USER", "RPC_PASSWORD", "RPC_HOST", "RPC_PORT"]
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        raise RuntimeError(f"missing env vars: {missing}. Copy .env.example to .env and fill it in.")
    return f"host={os.getenv('RPC_HOST')}:{os.getenv('RPC_PORT')}"


@check("colegio_tools imports cleanly")
def check_import():
    # Make repo root importable regardless of where script is run from
    sys.path.insert(0, str(Path(__file__).parent.resolve()))
    import colegio_tools
    n_callables = sum(
        1 for x in dir(colegio_tools)
        if callable(getattr(colegio_tools, x)) and not x.startswith("_")
    )
    return f"{n_callables} public names"


@check("OP_RETURN primitive produces expected hex")
def check_opreturn():
    import colegio_tools as ct
    # Short payload — direct push (no OP_PUSHDATA prefix)
    payload = b"hello"
    hex_out = ct.mk_opreturn(payload)
    # Expected: OP_RETURN (6a) + length (05) + ascii "hello" (68656c6c6f)
    expected = "6a0568656c6c6f"
    if hex_out != expected:
        raise AssertionError(f"got {hex_out!r}, expected {expected!r}")
    return "short push correct"


@check("Image bit-codec round-trip (tests/sample.png)")
def check_image_codec():
    sample = Path(__file__).parent / "tests" / "sample.png"
    if not sample.exists():
        raise SkipTest(f"no sample image at {sample}")

    import colegio_tools as ct
    import numpy as np

    bi = ct.bitimage(str(sample), dims=(16, 16), bit=8, color=3)

    # Round-trip: original resized array -> bits -> bytes -> bits -> array
    orig = np.array(bi.img_resize)[:, :, :3]
    bits = ct.imgarr2bitarray(orig, bit=8)
    recovered = ct.bitarray2imgarr(bits, imgshape=(16, 16), bit=8, color=3)

    if not np.array_equal(orig, recovered):
        max_diff = int(np.abs(orig.astype(int) - recovered.astype(int)).max())
        raise AssertionError(f"round-trip mismatch, max pixel diff = {max_diff}")
    return f"16x16 RGB round-trip exact"


@check("Key save/load round-trip (encrypted)")
def check_key_roundtrip():
    import colegio_tools as ct
    import ecies
    import tempfile

    # Generate a throwaway key, save it password-protected, load it back
    privkey = ecies.utils.generate_eth_key()
    with tempfile.NamedTemporaryFile(suffix="_prv.enc", delete=False) as f:
        path = f.name
    try:
        ct.save_privkey(privkey, path, password="smoketest")
        loaded = ct.import_privKey(path, password="smoketest")
        if loaded.to_bytes() != privkey.to_bytes():
            raise AssertionError("loaded key doesn't match saved key")
    finally:
        os.unlink(path)
    return "encrypt → decrypt match"


@check("Node responds (current_block_height)")
def check_node():
    import colegio_tools as ct
    try:
        height = ct.current_block_height()
    except Exception as e:
        raise RuntimeError(
            f"node unreachable at {os.getenv('RPC_HOST')}:{os.getenv('RPC_PORT')} — {e}"
        )
    if not isinstance(height, int):
        raise AssertionError(f"expected int block height, got {type(height).__name__}: {height!r}")
    return f"block height = {height:,}"


@check("Node chain tip looks plausible")
def check_chain_tip():
    import colegio_tools as ct
    height = ct.current_block_height()
    # Dogecoin block 1 was Dec 2013. ~1 block per minute → ~5M blocks/year.
    # As of 2024, height is around 5M+. Be generous on the lower bound.
    if height < 1_000_000:
        raise AssertionError(f"height {height} suspiciously low — is the node fully synced?")
    return f"height {height:,} ≥ 1,000,000 (looks synced)"


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

CHECKS = [
    check_env,
    check_import,
    check_opreturn,
    check_image_codec,
    check_key_roundtrip,
    check_node,
    check_chain_tip,
]

print("=" * 60)
print("Colegio Invisible — smoke test")
print("=" * 60)

for c in CHECKS:
    ok = c()
    # If a required check fails, skip everything that depends on it.
    if ok is False and c.required:
        # Mark remaining checks as skipped due to upstream failure.
        for remaining in CHECKS[CHECKS.index(c) + 1:]:
            results.append((remaining.__name__, "SKIP", "upstream check failed"))
            print(f"  ⊘ {remaining.__name__.replace('check_', '')} — skipped (upstream failure)")
        break

# Summary
print("=" * 60)
n_pass = sum(1 for _, s, _ in results if s == "PASS")
n_fail = sum(1 for _, s, _ in results if s == "FAIL")
n_skip = sum(1 for _, s, _ in results if s == "SKIP")
total = len(results)

if n_fail == 0:
    print(f"  {n_pass}/{total} passed" + (f", {n_skip} skipped" if n_skip else ""))
    print("  All required checks ✓")
    sys.exit(0)
else:
    print(f"  {n_pass}/{total} passed, {n_fail} failed, {n_skip} skipped")
    print("  Re-run with SMOKE_VERBOSE=1 for full tracebacks.")
    sys.exit(1)
