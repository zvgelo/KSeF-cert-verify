#!/usr/bin/env bash
# Skrypt uruchomieniowy (Linux): używa pakietu w ./dist albo zainstalowanego przez pip.
DIR="$(cd "$(dirname "$0")/.." && pwd)"
if [ -x "$DIR/dist/ksef-cert-verify/ksef-cert-verify" ]; then exec "$DIR/dist/ksef-cert-verify/ksef-cert-verify" "$@"; fi
exec python3 -m ksef_cert_verify "$@"
