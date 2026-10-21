#!/bin/sh
# Builds the native helpers and assembles Hashling.app.
#   HASHLING_SIGN="Developer ID Application: ..."  sign with that identity (default: ad-hoc)
#   HASHLING_APP_DIR=~/Applications                where to put Hashling.app
#   HASHLING_BUILD_DIR=helpers/build               where the compiled helpers go
#   HASHLING_PORTABLE=1                            leave this Mac's paths out of Info.plist (release build)
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${HASHLING_BUILD_DIR:-$ROOT/helpers/build}"
APP_DIR="${HASHLING_APP_DIR:-$HOME/Applications}"
APP="$APP_DIR/Hashling.app"
SIGN="${HASHLING_SIGN:--}"
NODE="$(command -v node)"
mkdir -p "$OUT" "$APP_DIR"

echo "Building helpers..."
swiftc -O -o "$OUT/hashling-ble" "$ROOT/helpers/ble.swift" \
  -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker "$ROOT/helpers/ble-Info.plist"
swiftc -O -o "$OUT/hashling-auth" "$ROOT/helpers/auth.swift"
swiftc -O -o "$OUT/Hashling" "$ROOT/helpers/launcher.swift"
swiftc -O -o "$OUT/hashling-trash" "$ROOT/helpers/trash.swift"
swiftc -O -o "$OUT/hashling-ocr" "$ROOT/helpers/ocr.swift"

echo "Assembling $APP ..."
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$OUT/Hashling" "$OUT/hashling-ble" "$OUT/hashling-auth" "$OUT/hashling-trash" "$OUT/hashling-ocr" "$APP/Contents/MacOS/"
cp "$ROOT/helpers/AppIcon.icns" "$APP/Contents/Resources/" 2>/dev/null || true
if [ -n "${HASHLING_PORTABLE:-}" ]; then PLIST_ROOT="" PLIST_NODE=""; else PLIST_ROOT="$ROOT" PLIST_NODE="$NODE"; fi
VERSION="$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$ROOT/package.json" | head -1)"
sed -e "s|@ROOT@|$PLIST_ROOT|g" -e "s|@NODE@|$PLIST_NODE|g" -e "s|@VERSION@|$VERSION|g" "$ROOT/helpers/Info.plist" > "$APP/Contents/Info.plist"

opts="--force --timestamp=none"
[ "$SIGN" != "-" ] && opts="--force --options runtime --timestamp"
for b in hashling-ble hashling-auth hashling-trash hashling-ocr Hashling; do
  codesign $opts --sign "$SIGN" --identifier "dev.hashling.$b" "$APP/Contents/MacOS/$b"
done
codesign $opts --sign "$SIGN" "$APP"
codesign --verify "$APP" && echo "Signed: $(codesign -dvv "$APP" 2>&1 | grep -m1 Authority= || echo ad-hoc)"
echo "Done."
