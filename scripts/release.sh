#!/bin/sh
# Builds a Hashling.app signed with the maintainer's Developer ID, has Apple notarize it,
# and (with --publish) puts it on a GitHub Release with the source and SHA-256 checksums.
#   sh scripts/release.sh             build, sign, notarize and check, into dist/
#   sh scripts/release.sh --publish   also create the GitHub Release vX.Y.Z (version from package.json)
# Needs: the "Developer ID Application" certificate in the keychain, a notarytool keychain profile
# (HASHLING_NOTARY_PROFILE, default "hashling"), and for --publish the GitHub CLI signed in
# (or GH_TOKEN) as someone who can write to the repo.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
VERSION="$(node -p 'require("./package.json").version')"
TAG="v$VERSION"
DIST="$ROOT/dist"
SIGN="${HASHLING_SIGN:-Developer ID Application: ABDUL RAHMAN SHAHZAD (VP9VT747BA)}"
PROFILE="${HASHLING_NOTARY_PROFILE:-hashling}"
REPO="${HASHLING_REPO:-0xArx/hashling}"
PUBLISH=""; [ "${1:-}" = "--publish" ] && PUBLISH=1

if [ -n "$PUBLISH" ]; then
  [ -z "$(git status --porcelain)" ] || { echo "Commit or stash your changes first: a release must match a commit."; exit 1; }
  git fetch -q origin main
  [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || { echo "Push main first: the release is made from origin/main."; exit 1; }
fi

rm -rf "$DIST" && mkdir -p "$DIST/build"
echo "1/5 Building and signing Hashling.app $VERSION ..."
HASHLING_SIGN="$SIGN" HASHLING_APP_DIR="$DIST" HASHLING_BUILD_DIR="$DIST/build" HASHLING_PORTABLE=1 \
  sh "$ROOT/scripts/build-helpers.sh"
rm -rf "$DIST/build"

echo "2/5 Sending it to Apple to notarize (a few minutes) ..."
ditto -c -k --keepParent "$DIST/Hashling.app" "$DIST/notarize.zip"
xcrun notarytool submit "$DIST/notarize.zip" --keychain-profile "$PROFILE" --wait --timeout 30m | tee "$DIST/notarize.log"
grep -q "status: Accepted" "$DIST/notarize.log" || { echo "Apple did not accept it. See: xcrun notarytool log <id> --keychain-profile $PROFILE"; exit 1; }
rm "$DIST/notarize.zip" "$DIST/notarize.log"

echo "3/5 Stapling Apple's ticket and checking with Gatekeeper ..."
xcrun stapler staple "$DIST/Hashling.app"
spctl --assess --type execute --verbose=2 "$DIST/Hashling.app" 2>&1 | tee /dev/stderr | grep -q "source=Notarized Developer ID"

echo "4/5 Packing the app and the source, with checksums ..."
APPZIP="Hashling-$VERSION-mac.zip"
SRC="hashling-$VERSION-source.tar.gz"
ditto -c -k --keepParent "$DIST/Hashling.app" "$DIST/$APPZIP"
git archive --format=tar.gz --prefix="hashling-$VERSION/" -o "$DIST/$SRC" HEAD
# The double-click installer, when the "Developer ID Installer" certificate is in the keychain.
PKG="Hashling-$VERSION.pkg"
if security find-identity -v -p basic | grep -q "Developer ID Installer"; then
  sh "$ROOT/scripts/build-pkg.sh" && sh "$ROOT/scripts/test-pkg.sh" "$DIST/$PKG"
else
  PKG=""; echo "   (No Developer ID Installer certificate, so no .pkg this time.)"
fi
( cd "$DIST" && shasum -a 256 "$APPZIP" "$SRC" $PKG > SHA256SUMS.txt && cat SHA256SUMS.txt )

if [ -z "$PUBLISH" ]; then echo "5/5 Done (not published). Files are in $DIST"; exit 0; fi

echo "5/5 Publishing GitHub Release $TAG ..."
cat > "$DIST/notes.md" <<NOTES
**To install Hashling, use https://hashling.vercel.app/start.**${PKG:+ The easiest way is \`$PKG\` below: double-click it and follow the steps.}

What is in this release:

${PKG:+- \`$PKG\`: the double-click installer. It brings everything Hashling needs, installs into your home folder without your Mac password, and is signed and notarized by Apple.
}- \`$APPZIP\`: Hashling.app, signed with the maintainer's Apple Developer ID (team VP9VT747BA) and notarized by Apple.
- \`$SRC\`: the exact source code this release was built from.
- \`SHA256SUMS.txt\`: checksums, so you can confirm nothing was changed on the way.

Check a download:

\`\`\`sh
shasum -a 256 -c SHA256SUMS.txt --ignore-missing
spctl --assess --type execute --verbose=2 Hashling.app   # should say: source=Notarized Developer ID
\`\`\`

To use the notarized app instead of the one the installer built: install Hashling first, then unzip \`$APPZIP\`, replace \`~/Applications/Hashling.app\` with it and run \`hashling restart\`. macOS sees it as a new app, so turn Full Disk Access on for it again (System Settings, Privacy & Security). Running the installer again puts back a locally built app.

Found a security problem? Please report it privately: see [SECURITY.md](https://github.com/$REPO/blob/main/SECURITY.md).
NOTES
gh release create "$TAG" --repo "$REPO" --target "$(git rev-parse HEAD)" --title "Hashling $VERSION" \
  --notes-file "$DIST/notes.md" "$DIST/$APPZIP" "$DIST/$SRC" "$DIST/SHA256SUMS.txt" ${PKG:+"$DIST/$PKG"}
git fetch -q --tags origin
echo "Published: https://github.com/$REPO/releases/tag/$TAG"
