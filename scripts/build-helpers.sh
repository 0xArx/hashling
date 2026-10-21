#!/bin/sh
# Builds the native helpers and assembles Hashling.app.
#   HASHLING_SIGN="Developer ID Application: ..."  sign with that identity (default: ad-hoc)
#   HASHLING_APP_DIR=~/Applications                where to put Hashling.app
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/helpers/build"
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
sed -e "s|@ROOT@|$ROOT|g" -e "s|@NODE@|$NODE|g" "$ROOT/helpers/Info.plist" > "$APP/Contents/Info.plist"

opts="--force --timestamp=none"
[ "$SIGN" != "-" ] && opts="--force --options runtime --timestamp"
for b in hashling-ble hashling-auth hashling-trash hashling-ocr Hashling; do
  codesign $opts --sign "$SIGN" --identifier "dev.hashling.$b" "$APP/Contents/MacOS/$b"
done
codesign $opts --sign "$SIGN" "$APP"
codesign --verify "$APP" && echo "Signed: $(codesign -dv "$APP" 2>&1 | grep Authority= | head -1 || echo ad-hoc)"
echo "Done."
