#!/usr/bin/env bash
# deploy_atlas.sh — publish the globes to nodus and to colegioinvisible.com.
#
# The atlas is NOT part of the spectra build, so publish.sh does not touch it
# (it now rsyncs to /quipu/). This is the atlas's own path.
#
# Why the precompression step matters: the globe is a single ~5.9 MB html with
# everything inlined. Served raw over a long-haul mobile link it is punishing.
# Brotli at level 11 takes it to ~1.5 MB, but nginx's on-the-fly brotli only
# reaches level 5 (~1.9 MB), so we compress ONCE here at deploy time and let
# brotli_static serve it straight from disk.
#
# The .br/.gz siblings MUST be regenerated on every deploy: nginx serves them
# in preference to the .html, so a stale .br would silently serve the OLD atlas
# while the .html on disk looks correct. That is the trap this script exists to
# close.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/quipu_out"
NODUS=${NODUS:-drdoeg@192.168.1.231}
PUBLIC=${PUBLIC:-root@178.105.218.163}
# Absolute, not $HOME or ~: this string is interpolated locally and then run on
# nodus, so anything needing shell expansion on the far side arrives literal.
KEY=${KEY:-/home/drdoeg/.ssh/id_ed25519_deploy}
DOMAIN=${DOMAIN:-colegioinvisible.com}

echo "==> rsync globes to nodus"
rsync -az "$OUT"/atlas_globe.html "$OUT"/atlas_globe_es.html "$NODUS":www/atlas/

echo "==> nodus -> public, then precompress on the far side"
ssh "$NODUS" "rsync -az -e 'ssh -i $KEY' \
    ~/www/atlas/atlas_globe.html ~/www/atlas/atlas_globe_es.html \
    $PUBLIC:/var/www/$DOMAIN/atlas/ && \
  ssh -i $KEY $PUBLIC 'set -e
    cd /var/www/$DOMAIN/atlas
    for f in atlas_globe.html atlas_globe_es.html; do
      brotli -f -q 11 -o \$f.br \$f
      gzip -9 -k -f \$f
    done
    # /atlas/ resolves to index.html, and brotli_static looks for
    # index.html.br beside it, not the symlink target. Without these two the
    # index path silently falls back to level-5 dynamic brotli.
    ln -sf atlas_globe_es.html.br index.html.br
    ln -sf atlas_globe_es.html.gz index.html.gz
    chown -h www-data:www-data index.html.br index.html.gz
    chown www-data:www-data *.html *.br *.gz'"

echo "==> verifying"
for path in "/atlas/" "/atlas/atlas_globe.html"; do
    out=$(curl -sS -H 'Accept-Encoding: br' -o /dev/null \
        -w '%{http_code} %{size_download} %{http_version}' "https://$DOMAIN$path")
    set -- $out
    printf '  %-26s http=%s  %s  %s bytes on the wire\n' "$path" "$3" "$1" "$2"
done
echo "  (raw html is ~5.9 MB; anything near 1.5 MB means brotli_static is working,"
echo "   ~1.9 MB means it fell back to dynamic and the .br files are missing)"
