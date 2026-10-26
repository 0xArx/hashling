#!/bin/sh
# Installs a built Hashling .pkg into a throwaway home folder (never yours), runs its setup step in test
# mode, then starts Hashling from the installed files with only what the package brought: its own Node,
# YARA-X and osquery. Usage: sh scripts/test-pkg.sh [dist/Hashling-x.y.z.pkg]
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG="${1:-$(ls "$ROOT"/dist/Hashling-*.pkg | tail -1)}"
T="$(mktemp -d -t hashling-pkg)"
H="$T/home"
cleanup() { [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null; chmod -R u+w "$T" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
fail() { echo "FAIL $*"; exit 1; }
ok() { echo "ok   $*"; }

pkgutil --check-signature "$PKG" >/dev/null 2>&1 && ok "package is signed" || echo "note package is not signed (test build)"
pkgutil --expand-full "$PKG" "$T/x"
COMP="$T/x/hashling-component.pkg"
mkdir -p "$H"
ditto "$COMP/Payload" "$H"
[ -x "$H/Applications/Hashling.app/Contents/MacOS/Hashling" ] && ok "Hashling.app lands in ~/Applications" || fail "Hashling.app missing"
for f in hashling-auth hashling-ocr hashling-trash hashling-ble; do [ -x "$H/Applications/Hashling.app/Contents/MacOS/$f" ] || fail "helper $f missing"; done
ok "Touch ID, text reading, Trash and Bluetooth helpers are inside the app"
codesign --verify --deep --strict "$H/Applications/Hashling.app" && ok "the app's signature is intact"

HOME="$H" HASHLING_PKG_TEST=1 sh "$COMP/Scripts/postinstall" || fail "the setup step failed"
ok "the setup step runs"
NODE="$H/.hashling/runtime/node"
[ "$("$NODE" --version)" = "v24.22.1" ] && ok "its own Node runs ($("$NODE" --version))" || fail "bundled Node does not run"
"$H/.hashling/engines/yara-x/yr" --version >/dev/null && ok "its own YARA-X runs ($("$H/.hashling/engines/yara-x/yr" --version))" || fail "bundled YARA-X does not run"
"$H/.hashling/engines/osquery/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd" --version >/dev/null 2>&1 && ok "osquery runs" || fail "bundled osquery does not run"

# Start Hashling from the installed files with a PATH that has no Homebrew, so nothing outside the package helps.
PORT=5866
env -i HOME="$H" PATH=/usr/bin:/bin:/usr/sbin:/sbin HASHLING_HOME="$H/.hashling" HASHLING_PORT=$PORT HASHLING_ENRICH=0 HASHLING_NO_UPDATE_CHECK=1 \
  HASHLING_APP="$H/Applications/Hashling.app" "$NODE" --no-warnings "$H/.hashling/app/src/daemon.ts" >"$T/daemon.log" 2>&1 &
PID=$!
i=0; until curl -s "http://127.0.0.1:$PORT/api/health" | grep -q '"ok":true'; do i=$((i + 1)); [ $i -gt 60 ] && { cat "$T/daemon.log" | tail -20; fail "Hashling did not start from the package"; }; sleep 0.5; done
ok "Hashling starts from the installed files with no Homebrew on PATH"
TOKEN="$(cat "$H/.hashling/token")"
ENG="$(curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/api/overview" | "$NODE" -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const e=JSON.parse(s).engines||{};process.stdout.write(JSON.stringify(e))})")"
echo "$ENG" | grep -q '"yara":true' && ok "it finds the bundled YARA-X scanner" || fail "YARA-X not found by Hashling: $ENG"
HOME="$H" "$H/.hashling/app/bin/hashling" version >/dev/null && ok "the hashling command works with the bundled Node"
echo "Package test passed: $(basename "$PKG") installs and runs on its own."
