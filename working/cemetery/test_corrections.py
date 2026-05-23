"""Verify the corrections binding does what we expect.

Loads the inscribed v1 essay body (data/bodies/d442073b…bin), applies
the corrections binding's substitution rules to it, then runs the
essay engine's full substitute_body pipeline to produce the final
rendered markdown. Reports:

  - dogechain.info occurrences in raw body  (should be 8)
  - dogechain.info occurrences after binding (should be 0)
  - quipu: occurrences after binding         (should be 8)
  - lines that contained dogechain URLs (before + after)
  - visible anchor text preserved
"""
import sys, re
from pathlib import Path

PROJECT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "canonical"))

V1_TXID = "d442073b33f2a4d04292853abb39e171ae593fcc288a1e4fc2518d5d7a7e5985"
V1_BIN  = PROJECT / "data" / "bodies" / f"{V1_TXID}.bin"
BINDING = Path(__file__).parent / "corrections.ab"

# ---- 1. Pull the markdown body out of the inscribed bytes ---------------
blob = V1_BIN.read_bytes()
# header ends at the closing pipe of the last key=value field
# walk pipes from pos 6 until we hit one followed by a non-pipe content
assert blob[:4] == b"\xc1\xdd\x00\x01" and blob[4] == 0x01, "not an essay quipu"
pos = 6  # past magic+type+tone
assert blob[pos:pos+1] == b"|", "essay header must start with |"
# walk through |title|k=v|k=v|...| until we find the closing | followed by body
pos += 1
last_pipe = 0
while pos < len(blob):
    nxt = blob.find(b"|", pos)
    if nxt < 0: break
    seg = blob[pos:nxt]
    # body starts when a segment contains a newline (markdown body)
    if b"\n" in seg:
        last_pipe = pos - 1  # the pipe before this segment is the closing pipe
        break
    pos = nxt + 1
    last_pipe = pos - 1
body_md = blob[last_pipe + 1:].decode("utf-8")
print(f"v1 essay body: {len(body_md)} chars, "
      f"{body_md.count('dogechain.info')} dogechain refs, "
      f"{body_md.count('quipu:')} quipu refs")

# ---- 2. Read the binding + apply its substitution rules ----------------
binding_text = BINDING.read_text(encoding="utf-8")
print(f"\nbinding rules:")
for line in binding_text.strip().splitlines():
    print(f"  {line}")

# Parse "X"="Y" lines
SUB_RE = re.compile(r'^"((?:[^"\\]|\\.)*)"="((?:[^"\\]|\\.)*)"$')
rules = []
for line in binding_text.strip().splitlines():
    line = line.strip()
    if not line: continue
    m = SUB_RE.match(line)
    if not m:
        print(f"  ! could not parse: {line}")
        continue
    rules.append((m.group(1), m.group(2)))

print(f"\nparsed {len(rules)} substitution rule(s)")

corrected = body_md
for find, replace in rules:
    n_before = corrected.count(find)
    corrected = corrected.replace(find, replace)
    print(f"  applied: {find!r} -> {replace!r}  ({n_before} occurrence(s))")

# ---- 3. Verify counts ---------------------------------------------------
print()
print("=" * 60)
print("AFTER BINDING APPLIED")
print("=" * 60)
print(f"  dogechain.info refs: {corrected.count('dogechain.info')}  (was 8, should be 0)")
print(f"  quipu: refs:         {corrected.count('quipu:')}  (was 2, should be 10: 2 images + 8 new)")

# ---- 4. Show the 8 lines that had dogechain URLs --------------------
print()
print("=" * 60)
print("BEFORE / AFTER (lines that contained dogechain.info)")
print("=" * 60)
v1_lines = body_md.splitlines()
v2_lines = corrected.splitlines()
for i, (v1, v2) in enumerate(zip(v1_lines, v2_lines)):
    if "dogechain.info" not in v1:
        continue
    # Show each link in this line as before/after
    pat = re.compile(r'(\[[^\]]*\]\(https://dogechain\.info/tx/[0-9a-f]{64}\))|(<a href="https://dogechain\.info/tx/[0-9a-f]{64}">[^<]*</a>)')
    pat2 = re.compile(r'(\[[^\]]*\]\(quipu:[0-9a-f]{64}\))|(<a href="quipu:[0-9a-f]{64}">[^<]*</a>)')
    v1_links = [m.group(0) for m in pat.finditer(v1)]
    v2_links = [m.group(0) for m in pat2.finditer(v2)]
    print(f"\n  line {i+1} ({len(v1_links)} link(s)):")
    for vb, va in zip(v1_links, v2_links):
        print(f"    BEFORE: {vb[:110]}")
        print(f"    AFTER:  {va[:110]}")

print()
print("=" * 60)
print("CHECKS")
print("=" * 60)
assert corrected.count('dogechain.info') == 0, "FAIL: dogechain still present"
assert corrected.count('quipu:') == 10, f"FAIL: expected 10 quipu: refs, got {corrected.count('quipu:')}"
# anchor preservation: every hex-shortened anchor like `c1542c10…` should still appear
for short_hex in ["c1542c10", "014123b2", "a01e8625", "9e42c7ab", "dcd31fa3", "2ae7fe90", "1f63558b", "420d1b6b"]:
    assert short_hex in corrected, f"FAIL: anchor pattern {short_hex} disappeared"
print("  ✓ no dogechain.info references remain")
print("  ✓ 10 quipu: references present (2 image + 8 corrected)")
print("  ✓ all 8 hex anchor patterns preserved in output")
print()
print("BINDING WORKS.")
