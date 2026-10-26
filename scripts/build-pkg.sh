#!/bin/sh
# Builds Hashling-<version>.pkg, the double-click installer for people who don't use Terminal.
# It brings everything with it (Hashling.app, Hashling's code, Node 24, YARA-X and osquery), installs into
# your home folder without an admin password, and starts Hashling, like the one-line installer does.
#   sh scripts/build-pkg.sh                       signed with "Developer ID Installer", notarized and stapled
#   HASHLING_PKG_UNSIGNED=1 sh scripts/build-pkg.sh   an unsigned package, for tests only (Gatekeeper blocks it)
# Uses dist/Hashling.app when release.sh has just built and notarized it; otherwise builds the app here.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
VERSION="$(node -p 'require("./package.json").version')"
DIST="$ROOT/dist"
WORK="$DIST/pkg-work"
STAGE="$WORK/root"
APP_SIGN="${HASHLING_SIGN:-Developer ID Application: ABDUL RAHMAN SHAHZAD (VP9VT747BA)}"
PKG_SIGN="${HASHLING_PKG_SIGN:-Developer ID Installer: ABDUL RAHMAN SHAHZAD (VP9VT747BA)}"
PROFILE="${HASHLING_NOTARY_PROFILE:-hashling}"
UNSIGNED="${HASHLING_PKG_UNSIGNED:-}"
NODE_VERSION=24.22.1
NODE_SHA256=89c682593d76cd44233fa53b1563264e7de9cbb189cad169135c5b4fadfbc0a7
YARA_VERSION=1.22.0
OSQ_VERSION="${HASHLING_OSQUERY_VERSION:-5.23.1}"
OUT="$DIST/Hashling-$VERSION.pkg"

if [ -z "$UNSIGNED" ] && ! security find-identity -v -p basic | grep -q "$PKG_SIGN"; then
  echo "The \"$PKG_SIGN\" certificate is not in the keychain, so the package can't be signed."
  echo "Create it at developer.apple.com (Certificates, +, Developer ID, Developer ID Installer), or run with HASHLING_PKG_UNSIGNED=1 for a test build."
  exit 1
fi
# osquery ships read-only folders, so make the last build writable before removing it.
[ -d "$WORK" ] && chmod -R u+w "$WORK"
rm -rf "$WORK" && mkdir -p "$STAGE/Applications" "$STAGE/.hashling/runtime" "$STAGE/.hashling/engines/yara-x" "$WORK/dl"

echo "1/6 Hashling.app"
if [ -d "$DIST/Hashling.app" ]; then
  ditto "$DIST/Hashling.app" "$STAGE/Applications/Hashling.app"
else
  SIGN_FOR_APP="$APP_SIGN"; [ -n "$UNSIGNED" ] && SIGN_FOR_APP="-"
  HASHLING_SIGN="$SIGN_FOR_APP" HASHLING_APP_DIR="$WORK/app" HASHLING_BUILD_DIR="$WORK/build" HASHLING_PORTABLE=1 sh "$ROOT/scripts/build-helpers.sh" >/dev/null
  ditto "$WORK/app/Hashling.app" "$STAGE/Applications/Hashling.app"
fi

echo "2/6 Hashling's code (this commit, with its packages)"
mkdir -p "$STAGE/.hashling/app"
git archive --format=tar HEAD | tar -x -C "$STAGE/.hashling/app"
( cd "$STAGE/.hashling/app" && npm ci --omit=dev --no-audit --no-fund --silent )
rm -rf "$STAGE/.hashling/app/site" "$STAGE/.hashling/app/docs" "$STAGE/.hashling/app/.github"

echo "3/6 Node $NODE_VERSION (from nodejs.org, checked against its published SHA-256)"
curl -fsSL -o "$WORK/dl/node.tgz" "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-darwin-arm64.tar.gz"
[ "$(shasum -a 256 "$WORK/dl/node.tgz" | cut -d' ' -f1)" = "$NODE_SHA256" ] || { echo "The Node download did not match its checksum."; exit 1; }
tar -xzf "$WORK/dl/node.tgz" -C "$WORK/dl" "node-v$NODE_VERSION-darwin-arm64/bin/node"
cp "$WORK/dl/node-v$NODE_VERSION-darwin-arm64/bin/node" "$STAGE/.hashling/runtime/node"
codesign --verify --strict "$STAGE/.hashling/runtime/node"

echo "4/6 YARA-X $YARA_VERSION (from GitHub, checked against the SHA-256 GitHub publishes)"
YARA_ASSET="yara-x-v$YARA_VERSION-aarch64-apple-darwin.tar.gz"
YARA_SHA="$(curl -fsSL "https://api.github.com/repos/VirusTotal/yara-x/releases/tags/v$YARA_VERSION" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const a=JSON.parse(s).assets.find(x=>x.name==='$YARA_ASSET');process.stdout.write((a&&a.digest||'').replace('sha256:',''))})")"
curl -fsSL -o "$WORK/dl/yara.tgz" "https://github.com/VirusTotal/yara-x/releases/download/v$YARA_VERSION/$YARA_ASSET"
[ -n "$YARA_SHA" ] && [ "$(shasum -a 256 "$WORK/dl/yara.tgz" | cut -d' ' -f1)" = "$YARA_SHA" ] || { echo "The YARA-X download did not match its checksum."; exit 1; }
tar -xzf "$WORK/dl/yara.tgz" -C "$WORK/dl"
cp "$(find "$WORK/dl" -type f -name yr | head -1)" "$STAGE/.hashling/engines/yara-x/yr"
if [ -n "$UNSIGNED" ]; then codesign --force --sign - "$STAGE/.hashling/engines/yara-x/yr"
else codesign --force --options runtime --timestamp --sign "$APP_SIGN" "$STAGE/.hashling/engines/yara-x/yr"; fi

echo "5/6 osquery $OSQ_VERSION (official release, signature checked)"
curl -fsSL -o "$WORK/dl/osq.tgz" "https://github.com/osquery/osquery/releases/download/$OSQ_VERSION/osquery-${OSQ_VERSION}_1.macos_arm64.tar.gz"
mkdir -p "$STAGE/.hashling/engines/osquery"
tar -xzf "$WORK/dl/osq.tgz" -C "$STAGE/.hashling/engines/osquery"
codesign --verify "$STAGE/.hashling/engines/osquery/opt/osquery/lib/osquery.app"
# Its files arrive read-only, which pkgbuild trips over; you own them after install either way.
chmod -R u+w "$STAGE/.hashling/engines/osquery"

echo "6/6 Packing"
mkdir -p "$WORK/scripts"
cp "$ROOT/scripts/pkg/postinstall" "$WORK/scripts/postinstall" && chmod 755 "$WORK/scripts/postinstall"
# Never let Installer "relocate" the app to some other copy it finds on the Mac.
pkgbuild --analyze --root "$STAGE" "$WORK/components.plist" >/dev/null
i=0; while /usr/libexec/PlistBuddy -c "Print :$i" "$WORK/components.plist" >/dev/null 2>&1; do
  /usr/libexec/PlistBuddy -c "Set :$i:BundleIsRelocatable false" "$WORK/components.plist" 2>/dev/null ||
    /usr/libexec/PlistBuddy -c "Add :$i:BundleIsRelocatable bool false" "$WORK/components.plist"
  i=$((i + 1)); done
# macOS won't let pkgbuild strip its own com.apple.provenance tags; the "write: Permission denied" lines it prints are harmless.
pkgbuild --root "$STAGE" --component-plist "$WORK/components.plist" --install-location / --scripts "$WORK/scripts" \
  --identifier dev.hashling.pkg --version "$VERSION" "$WORK/hashling-component.pkg" >/dev/null
sed "s|@VERSION@|$VERSION|g" "$ROOT/scripts/pkg/distribution.xml" > "$WORK/distribution.xml"
if [ -n "$UNSIGNED" ]; then
  productbuild --distribution "$WORK/distribution.xml" --resources "$ROOT/scripts/pkg/resources" --package-path "$WORK" "$OUT" >/dev/null
  echo "Built an UNSIGNED test package: $OUT ($(du -h "$OUT" | cut -f1))"
  exit 0
fi
productbuild --distribution "$WORK/distribution.xml" --resources "$ROOT/scripts/pkg/resources" --package-path "$WORK" --sign "$PKG_SIGN" "$OUT" >/dev/null
echo "Sending the package to Apple to notarize (a few minutes) ..."
xcrun notarytool submit "$OUT" --keychain-profile "$PROFILE" --wait --timeout 30m | tee "$WORK/notarize.log"
grep -q "status: Accepted" "$WORK/notarize.log" || { echo "Apple did not accept the package."; exit 1; }
xcrun stapler staple "$OUT"
spctl --assess --type install --verbose=2 "$OUT" 2>&1 | tee /dev/stderr | grep -q "Notarized Developer ID"
echo "Built $OUT ($(du -h "$OUT" | cut -f1)), signed, notarized and stapled."
