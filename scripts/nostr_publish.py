##################################################################################
# este guión publica un evento Nostr desde un borrador JSON aprobado
# es la única herramienta del proyecto que carga una clave de firma Nostr
#
# usar en el terminal con el siguiente comando:
# > python nostr_publish.py <KEY_PATH> <DRAFT_PATH> [PASSWORD] [--relays ...] [--dry-run]
# <KEY_PATH>:   el camino al archivo de clave privada cifrado por AES (ej. key1_prv.enc)
# <DRAFT_PATH>: el camino al archivo borrador JSON. Debe contener al menos:
#                 {"kind": 1, "content": "...", "tags": [["t","quipu"], ...]}
# [PASSWORD]:   opcional. Si se omite, se pedirá de manera segura
#
# Opciones:
#   --relays a,b,c  lista separada por comas de URLs de relés
#   --dry-run       firmar pero no publicar; imprimir el evento firmado
#
# EJEMPLO:
# >python nostr_publish.py /Users/anthony/cinv/llaves/key1_prv.enc draft.json
#
# SI <PASSWORD> NO ESTá INCLUIDO EL USUARIO ESTARá APUNTADO A INGRESARLO DE UNA MANERA SEGURA
##################################################################################
##################################################################################
# this script publishes a Nostr event from an approved JSON draft
# this is the ONLY tool in the project that loads a Nostr signing key
#
# the privkey lives in-process for milliseconds and is never written anywhere.
# this CLI is the boundary between "draft authored by Claude / by hand" and
# "signed event leaving the machine". any Nostr READING happens elsewhere,
# in a separate session that has no keyfile access — see
# docs/guides/nostr-integration.md for the full architecture.
#
# run at the terminal:
# > python nostr_publish.py <KEY_PATH> <DRAFT_PATH> [PASSWORD] [--relays ...] [--dry-run]
# <KEY_PATH>:   path to AES-encrypted privkey file (e.g. key1_prv.enc)
# <DRAFT_PATH>: path to JSON draft. Must contain at least:
#                 {"kind": 1, "content": "...", "tags": [["t","quipu"], ...]}
# [PASSWORD]:   optional. If omitted, prompted securely via getpass
#
# Flags:
#   --relays a,b,c  comma-separated relay URLs (default from canonical/nostr.py)
#   --dry-run       sign but don't publish; print the signed event
#
# EXAMPLE:
# >python nostr_publish.py /Users/anthony/cinv/llaves/key1_prv.enc draft.json
#
# IF <PASSWORD> IS NOT INCLUDED USER WILL BE PROMPTED TO ENTER IT SECURELY
##################################################################################

from sys import argv, exit, stderr
from pathlib import Path
import getpass
import json
import re
import sys

THIS_DIR = Path(__file__).resolve().parent
PROJECT  = THIS_DIR.parent
sys.path.insert(0, str(PROJECT))

from colegio_tools import import_privKey
from canonical.nostr import (build_event, publish_event, verify_event,
                              privkey_to_xonly_pubkey, to_bech32_npub,
                              to_bech32_note, DEFAULT_RELAYS)


# ---------------------------------------------------------------------------
# argv parsing — keep simple, mirror the existing ecc_*.py style
# ---------------------------------------------------------------------------

def parse_args(argv):
    pos = []
    relays = DEFAULT_RELAYS
    dry_run = False
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == '--relays':
            relays = tuple(r.strip() for r in argv[i+1].split(','))
            i += 2
        elif a == '--dry-run':
            dry_run = True
            i += 1
        elif a.startswith('--'):
            usage_and_exit(f'unknown flag: {a}')
        else:
            pos.append(a)
            i += 1
    return pos, relays, dry_run


def usage_and_exit(msg=None):
    if msg:
        print(f'error: {msg}\n', file=stderr)
    print('Usage:', file=stderr)
    print('  python nostr_publish.py <KEY_PATH> <DRAFT_PATH> [PASSWORD] '
          '[--relays a,b,c] [--dry-run]', file=stderr)
    print('  > python nostr_publish.py <KEY_PATH> <DRAFT_PATH> [PASSWORD] '
          '[--relays a,b,c] [--dry-run]', file=stderr)
    exit(2)


# ---------------------------------------------------------------------------
# Sanity checks on the draft — hard fail rather than publish leaks
# ---------------------------------------------------------------------------

MAX_CONTENT_BYTES = 65535
MAX_TAGS          = 100
HEX64_RE          = re.compile(r'\b[0-9a-fA-F]{64}\b')


def sanity_check_draft(draft, privkey_hex, expected_pubkey_hex):
    """Refuse to publish anything that looks like it leaks the privkey or
    is structurally unreasonable. Hard fails raise ValueError; warnings
    print to stderr but don't stop the run.
    """
    if not isinstance(draft, dict):
        raise ValueError('draft must be a JSON object')

    # Required fields
    if 'kind' not in draft:
        raise ValueError('draft missing required field: kind')
    if 'content' not in draft:
        raise ValueError('draft missing required field: content')
    kind    = draft['kind']
    content = draft['content']
    tags    = draft.get('tags', [])

    if not isinstance(kind, int):
        raise ValueError(f'kind must be int, got {type(kind).__name__}')
    if not isinstance(content, str):
        raise ValueError(f'content must be str, got {type(content).__name__}')
    if not isinstance(tags, list):
        raise ValueError(f'tags must be list, got {type(tags).__name__}')

    # Size caps
    n_bytes = len(content.encode('utf-8'))
    if n_bytes > MAX_CONTENT_BYTES:
        raise ValueError(f'content too large: {n_bytes} bytes '
                         f'(max {MAX_CONTENT_BYTES})')
    if len(tags) > MAX_TAGS:
        raise ValueError(f'too many tags: {len(tags)} (max {MAX_TAGS})')

    # HARD FAIL: privkey hex in any string field of the draft.
    leak_targets = [content]
    for tag in tags:
        if isinstance(tag, list):
            for v in tag:
                if isinstance(v, str):
                    leak_targets.append(v)
    for s in leak_targets:
        if privkey_hex in s.lower() or privkey_hex.lower() in s.lower():
            raise ValueError('REFUSING: privkey hex appears in draft fields')

    # WARN: stray 64-hex strings (might be txids — fine — or might be
    # accidental secrets). Print a count, let the operator notice.
    matches = HEX64_RE.findall(content)
    if matches:
        # Skip the pubkey itself (legitimate)
        suspicious = [m for m in matches if m.lower() != expected_pubkey_hex.lower()]
        if suspicious:
            print(f'  WARN: content contains {len(suspicious)} 64-hex-char '
                  f'string(s) — verify none are secrets', file=stderr)

    # WARN: unknown event kind
    KNOWN_KINDS = {0, 1, 3, 4, 5, 6, 7, 1063, 30023, 10002}
    if kind not in KNOWN_KINDS:
        print(f'  WARN: kind {kind} not in standard set (continuing)',
              file=stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    pos, relays, dry_run = parse_args(argv)
    if len(pos) == 3:
        key_path, draft_path, password = pos
    elif len(pos) == 2:
        key_path, draft_path = pos
        password = getpass.getpass(
            'Input password for privkey file:\n'
            'Ingresar password para el archivo de la clave privada: ')
    else:
        usage_and_exit('expected 2 or 3 positional arguments')

    # 1. Read the draft
    try:
        draft = json.loads(Path(draft_path).read_text(encoding='utf-8'))
    except Exception as e:
        usage_and_exit(f'failed to read/parse draft: {e}')

    # 2. Decrypt the privkey — in-process only, never written
    try:
        priv = import_privKey(key_path, password)
        privkey_hex = priv.to_hex()[2:]   # strip leading '0x'
    except Exception as e:
        print(f'Key import failed (decryption error?): {e}', file=stderr)
        print(f'Importación de la clave ha fallado: {e}', file=stderr)
        exit(3)

    # 3. Derive identity (the same npub the keyholder always has)
    xonly = privkey_to_xonly_pubkey(privkey_hex)
    npub  = to_bech32_npub(xonly)
    print(f'publishing as:')
    print(f'  npub:   {npub}')
    print(f'  pubkey: {xonly}')

    # 4. Sanity-check the draft against the privkey (refuse leaks)
    try:
        sanity_check_draft(draft, privkey_hex, xonly)
    except ValueError as e:
        print(f'\nDRAFT REJECTED: {e}', file=stderr)
        print(f'BORRADOR RECHAZADO: {e}', file=stderr)
        # Scrub the privkey reference before exit (cooperative; Python
        # doesn't guarantee wipe but at least drop the binding).
        privkey_hex = None
        del priv
        exit(4)

    # 5. Build + sign the event
    event = build_event(
        privkey_hex,
        kind       = draft['kind'],
        content    = draft['content'],
        tags       = draft.get('tags', []),
        created_at = draft.get('created_at'),
    )

    # Cooperative scrub — privkey no longer needed
    privkey_hex = None
    del priv

    if not verify_event(event):
        print('INTERNAL ERROR: self-signed event failed verification', file=stderr)
        exit(5)

    print(f'\nsigned event:')
    print(f'  id:     {event["id"]}')
    print(f'  note:   {to_bech32_note(event["id"])}')
    print(f'  kind:   {event["kind"]}')
    print(f'  tags:   {len(event["tags"])} tag(s)')
    print(f'  bytes:  {len(event["content"].encode("utf-8"))} (content)')

    if dry_run:
        print('\n--dry-run: not publishing. Signed event JSON:')
        print(json.dumps(event, indent=2, ensure_ascii=False))
        return

    # 6. Publish to relays
    print(f'\npublishing to {len(relays)} relay(s)...')
    results = publish_event(event, relays=relays, timeout=10)
    accepted = 0
    for url, reply in results:
        ok = isinstance(reply, list) and len(reply) >= 3 and reply[0] == 'OK' and reply[2] is True
        marker = 'OK ' if ok else 'FAIL'
        print(f'  [{marker}] {url}: {reply}')
        if ok:
            accepted += 1

    print(f'\naccepted by {accepted}/{len(results)} relay(s)')
    if accepted == 0:
        exit(6)


if __name__ == '__main__':
    main()
