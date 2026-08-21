#!/usr/bin/env bash
# deploy_atlas.sh — publish the globes to nodus and to colegioinvisible.com.
#
# The atlas is NOT part of the spectra build, so publish.sh does not touch it
# (it now rsyncs to /quipu/). This is the atlas's own path.
#
# Runs from EITHER machine: on the Mac it stages through nodus; on nodus
# itself it copies locally and pushes straight to the public VPS with the
# deploy key. Same script, same result.
#
# Why the precompression step matters: the globe is a single html with
# everything inlined (~23 MB at 597 travelers). Served raw over a long-haul
# mobile link it is punishing. Brotli at level 11 cuts it hard, but nginx's
# on-the-fly brotli only reaches level 5, so we compress ONCE here at deploy
# time and let brotli_static serve it straight from disk.
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
# Absolute, not $HOME or ~: this string may be interpolated on one machine and
# run on another, so anything needing far-side shell expansion arrives literal.
KEY=${KEY:-/home/drdoeg/.ssh/id_ed25519_deploy}
DOMAIN=${DOMAIN:-colegioinvisible.com}

# The far-side compression pass, run on the public box after the html lands.
COMPRESS='set -e
    cd /var/www/'"$DOMAIN"'/atlas
    for f in atlas_globe.html atlas_globe_es.html; do
      brotli -f -q 11 -o $f.br $f
      gzip -9 -k -f $f
    done
    # /atlas/ resolves to index.html, and brotli_static looks for
    # index.html.br beside it, not the symlink target. Without these two the
    # index path silently falls back to level-5 dynamic brotli.
    ln -sf atlas_globe_es.html.br index.html.br
    ln -sf atlas_globe_es.html.gz index.html.gz
    chown -h www-data:www-data index.html.br index.html.gz
    chown www-data:www-data *.html *.br *.gz'

if [ "$(hostname)" = "nodus" ]; then
    echo "==> local copy to ~/www/atlas"
    rsync -a "$OUT"/atlas_globe.html "$OUT"/atlas_globe_es.html ~/www/atlas/

    echo "==> nodus -> public, then precompress on the far side"
    rsync -az -e "ssh -i $KEY" \
        ~/www/atlas/atlas_globe.html ~/www/atlas/atlas_globe_es.html \
        "$PUBLIC:/var/www/$DOMAIN/atlas/"
    ssh -i "$KEY" "$PUBLIC" "$COMPRESS"
else
    echo "==> rsync globes to nodus"
    rsync -az "$OUT"/atlas_globe.html "$OUT"/atlas_globe_es.html "$NODUS":www/atlas/

    echo "==> nodus -> public, then precompress on the far side"
    ssh "$NODUS" "rsync -az -e 'ssh -i $KEY' \
        ~/www/atlas/atlas_globe.html ~/www/atlas/atlas_globe_es.html \
        $PUBLIC:/var/www/$DOMAIN/atlas/ && \
      ssh -i $KEY $PUBLIC '${COMPRESS//\'/\'\\\'\'}'"
fi

echo "==> verifying"
for path in "/atlas/" "/atlas/atlas_globe.html"; do
    out=$(curl -sS -H 'Accept-Encoding: br' -o /dev/null \
        -w '%{http_code} %{size_download} %{http_version}' "https://$DOMAIN$path")
    set -- $out
    printf '  %-26s http=%s  %s  %s bytes on the wire\n' "$path" "$3" "$1" "$2"
done
echo "  (raw html is ~23 MB; a few MB on the wire means brotli_static is working,"
echo "   near-raw size means it fell back and the .br files are missing)"
