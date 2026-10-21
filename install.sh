#!/bin/sh
# Install Hashling from this folder (a downloaded or cloned copy of the repo).
#   ./install.sh
# Same steps as the online installer, using the code right here instead of downloading it.
set -eu
ROOT="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
tar -czf "$TMP/hashling.tgz" --exclude node_modules --exclude .git --exclude helpers/build --exclude .vercel \
  -C "$(dirname "$ROOT")" "$(basename "$ROOT")"
HASHLING_SOURCE="$TMP/hashling.tgz" sh "$ROOT/scripts/install.sh"
