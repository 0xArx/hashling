#!/bin/sh
# Hashling installer for macOS (Apple silicon).
#   curl -fsSL https://hashling.vercel.app/install.sh | sh
# Installs: Node 24, ClamAV and YARA-X (Homebrew), osquery (official release),
# Hashling itself in ~/.hashling/app, Hashling.app in ~/Applications, and a login service.
# Uninstall any time with: hashling uninstall --all
#
# Testing the installer without touching a live install:
#   HASHLING_SOURCE=/path/hashling.tar.gz  use a local source archive instead of GitHub
#   HASHLING_SKIP_SIGNATURES=1           skip the 110 MB ClamAV signature download
#   HASHLING_NO_START=1                  build everything but do not link, start or open Hashling
#   HASHLING_ANSWER=y|n                  answer the installer's yes/no question without a keyboard
#   HASHLING_BREW_PATH=/nonexistent      pretend Homebrew is not installed (tests the prompt)
set -eu
USER_PATH="$PATH"
PATH_ADDED=""

REPO="${HASHLING_REPO:-0xArx/hashling}"
REF="${HASHLING_REF:-main}"
OSQ_VERSION="${HASHLING_OSQUERY_VERSION:-5.23.1}"
HASHLING_HOME="$HOME/.hashling"
APP_SRC="$HASHLING_HOME/app"

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
# step <number> <total> <title> [detail]
step() { printf '\n\033[1;34mStep %s of %s:\033[0m \033[1m%s\033[0m\n' "$1" "$2" "$3"; [ -n "${4:-}" ] && printf '   %s\n' "$4"; return 0; }
die() { printf '\n\033[1;31mSomething went wrong:\033[0m %s\n' "$*" >&2; exit 1; }
# Questions are read from the keyboard even though this script arrives through a pipe.
# With no keyboard (an automated run) the answer is "no": never install anything unasked.
if ( : < /dev/tty ) 2>/dev/null; then TTY=/dev/tty; else TTY=""; fi
ask() {
  printf '%s ' "$1"
  if [ -n "${HASHLING_ANSWER:-}" ]; then reply="$HASHLING_ANSWER"; printf '%s\n' "$reply"
  elif [ -z "$TTY" ] || ! read -r reply < "$TTY"; then reply="n"; printf '(no keyboard, so no)\n'; fi
  case "$reply" in y|Y|yes|Yes|"") return 0;; *) return 1;; esac
}

printf '\n\033[1mHi, I’m Hashling\033[0m, your personal AI cybersecurity agent. Let me set myself up.\n'
printf 'This takes about 5 minutes (up to 20 on a brand-new Mac). Keep using your Mac; I’ll ask if I need you.\n'
# Tool output goes to a log so the screen stays readable; it is shown only if something fails.
LOG="$(mktemp -t hashling-install)"

[ "$(uname -s)" = "Darwin" ] || die "I only run on macOS."
[ "$(uname -m)" = "arm64" ] || die "I need a Mac with Apple silicon (M1 or newer). Check in Apple menu > About This Mac."
MACOS="$(sw_vers -productVersion 2>/dev/null || echo 0)"
[ "${MACOS%%.*}" -ge 14 ] 2>/dev/null || die "I need macOS 14 (Sonoma) or newer. This Mac has macOS $MACOS. Update it in System Settings, General, Software Update."
FREE_GB="$(df -g "$HOME" | awk 'NR==2 {print $4}')"
[ "${FREE_GB:-0}" -ge 3 ] || die "I need about 3 GB of free space and this Mac has ${FREE_GB:-0} GB. Empty the Trash or remove a few large files, then run the installer again."

step 1 6 "Checking the tools I need" "I use Homebrew, a free and widely used tool for installing software on Macs."
BREW="${HASHLING_BREW_PATH:-/opt/homebrew/bin/brew}"
if [ -n "${HASHLING_BREW_PATH:-}" ]; then HAVE_BREW=""; [ -x "$BREW" ] && HAVE_BREW=1
else command -v brew >/dev/null 2>&1 && HAVE_BREW=1 || { [ -x "$BREW" ] && eval "$("$BREW" shellenv)" && HAVE_BREW=1; } || HAVE_BREW=""; fi
if [ -z "$HAVE_BREW" ]; then
  printf '   Homebrew is not installed yet.\n'
  if ask "   Install Homebrew now? It will ask for your Mac password once. [Y/n]"; then
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" < "${TTY:-/dev/null}" || die "Homebrew did not finish installing. Run this installer again to retry."
    eval "$(/opt/homebrew/bin/brew shellenv)"
  else
    die "I need Homebrew. Install it from https://brew.sh, then run the Hashling line again."
  fi
fi
if ! xcode-select -p >/dev/null 2>&1; then
  say "I also need Apple's Command Line Tools. A window will appear: click Install, then Agree."
  xcode-select --install >/dev/null 2>&1 || true
  printf '   Waiting for it to finish (usually 5 to 15 minutes)'
  # Apple's installer runs in its own window; carry on by ourselves once it is done (give up after an hour).
  i=0; while ! xcode-select -p >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -gt 360 ] && { printf '\n'; die "The Command Line Tools did not finish. When that window says it is done, run the installer again."; }
    sleep 10; [ $((i % 6)) -eq 0 ] && printf '.'
  done
  printf ' done.\n'
fi
say "Tools are ready."

step 2 6 "Installing the scanning engines" "ClamAV and YARA-X help me find malware; Node is what I run on. A few minutes on a fresh Mac."
brew install node@24 clamav yara-x >>"$LOG" 2>&1 || die "Homebrew could not install the engines. Details: $LOG"
NODE="$(brew --prefix node@24)/bin/node"
NPM="$(brew --prefix node@24)/bin/npm"

mkdir -p "$HASHLING_HOME/engines" "$HASHLING_HOME/clamav-db"
chmod 700 "$HASHLING_HOME"

if [ -x "$HASHLING_HOME/engines/osquery/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd" ]; then
  step 3 6 "Adding osquery" "Already installed."
else
  step 3 6 "Adding osquery" "An open-source tool from the Linux Foundation that lets me see what is running on this Mac."
  TMP="$(mktemp -d)"
  curl -fsSL -o "$TMP/osq.tgz" "https://github.com/osquery/osquery/releases/download/$OSQ_VERSION/osquery-${OSQ_VERSION}_1.macos_arm64.tar.gz"
  mkdir -p "$HASHLING_HOME/engines/osquery"
  tar -xzf "$TMP/osq.tgz" -C "$HASHLING_HOME/engines/osquery"
  rm -rf "$TMP"
  codesign --verify "$HASHLING_HOME/engines/osquery/opt/osquery/lib/osquery.app" || die "osquery signature check failed."
fi

step 4 6 "Downloading my latest version"
TMP="$(mktemp -d)"
if [ -n "${HASHLING_SOURCE:-}" ]; then cp "$HASHLING_SOURCE" "$TMP/hashling.tgz"
else
  CODE="$(curl -sSL -w '%{http_code}' -o "$TMP/hashling.tgz" "https://github.com/$REPO/archive/refs/heads/$REF.tar.gz" 2>>"$LOG" || true)"
  case "$CODE" in
    200) ;;
    000|"") die "I couldn’t reach GitHub to download myself. Check your internet connection and try again." ;;
    404) die "I’m not available to download yet. Its code has not been published, so there is nothing to install. Check https://hashling.vercel.app for news." ;;
    *) die "GitHub had a problem sending me (error $CODE). Try again in a few minutes." ;;
  esac
fi
rm -rf "$APP_SRC.new" && mkdir -p "$APP_SRC.new"
tar -xzf "$TMP/hashling.tgz" -C "$APP_SRC.new" --strip-components 1
rm -rf "$TMP"
# npm starts whichever "node" comes first on PATH; pin it to the node@24 installed above, so an
# older or broken Node elsewhere on the Mac cannot break the install.
( cd "$APP_SRC.new" && PATH="$(dirname "$NODE"):$PATH" "$NPM" ci --omit=dev --no-audit --no-fund --silent >>"$LOG" 2>&1 ) || die "I couldn’t set up the parts I need. This is usually a brief network problem, so run the installer again. Details: $LOG"
rm -rf "$APP_SRC" && mv "$APP_SRC.new" "$APP_SRC"

cat > "$HASHLING_HOME/freshclam.conf" <<EOF
DatabaseDirectory $HASHLING_HOME/clamav-db
DatabaseMirror database.clamav.net
EOF
step 5 6 "Downloading the latest malware fingerprints" "About 110 MB, from the ClamAV project. Updated automatically from now on."
if [ -n "${HASHLING_SKIP_SIGNATURES:-}" ]; then say "Skipped (test mode)."
else "$(brew --prefix)/bin/freshclam" --config-file="$HASHLING_HOME/freshclam.conf" --cvdcertsdir="$(brew --prefix)/etc/clamav/certs" --quiet >>"$LOG" 2>&1 || say "Signature download will be retried in the background."; fi

say "Building my app..."
PATH="$(dirname "$NODE"):$PATH" sh "$APP_SRC/scripts/build-helpers.sh" >>"$LOG" 2>&1 || die "I couldn’t build my app. Details: $LOG"

# Teach AI agents how to use Hashling (Claude Code reads skills from ~/.claude/skills),
# and offer to connect Claude Code to Hashling. <hashling command> is what the agent runs.
CONNECTED=""
connect_agents() {
  if [ -d "$HOME/.claude" ] && [ -f "$APP_SRC/SKILL.md" ]; then
    mkdir -p "$HOME/.claude/skills/hashling" && cp "$APP_SRC/SKILL.md" "$HOME/.claude/skills/hashling/SKILL.md"
  fi
  command -v claude >/dev/null 2>&1 || return 0
  if claude mcp get hashling >/dev/null 2>&1; then CONNECTED=1
  elif ask "Connect me to Claude Code, so you can ask it about your Mac and it checks with me? [Y/n]"; then
    claude mcp add --scope user hashling -- "$1" mcp >>"$LOG" 2>&1 && CONNECTED=1 && say "Connected. Try asking Claude Code: is my Mac safe?"
  fi
  return 0
}

BIN_DIR="$(brew --prefix)/bin"
if [ -n "${HASHLING_NO_START:-}" ]; then
  chmod +x "$APP_SRC/bin/hashling"
  connect_agents "$APP_SRC/bin/hashling"
  printf '\nTest mode: Hashling was built in %s but not linked, started or opened.\n' "$HASHLING_HOME"
  exit 0
fi
ln -sf "$APP_SRC/bin/hashling" "$BIN_DIR/hashling"
chmod +x "$APP_SRC/bin/hashling"
# A fresh Homebrew is not on Terminal's search path yet, so `hashling` would say "command not found".
case ":$USER_PATH:" in *":$BIN_DIR:"*) ;; *)
  if ! grep -qs "brew shellenv" "$HOME/.zprofile"; then
    PATH_ADDED=1
    printf '\n# Added by the Hashling installer so Homebrew tools (and `hashling`) work in Terminal.\neval "$(%s/brew shellenv)"\n' "$BIN_DIR" >> "$HOME/.zprofile"
  fi ;;
esac

step 6 6 "Starting up" "I start now and every time you log in. Look for the # in your menu bar: that’s me."
HASHLING_NODE="$NODE" "$BIN_DIR/hashling" install >>"$LOG" 2>&1 || die "I didn’t start. Details: $LOG"

connect_agents "$BIN_DIR/hashling"

cat <<EOF

$(printf '\033[1;32m')All set. I’m installed and keeping watch over this Mac.$(printf '\033[0m')

My dashboard is opening in your browser. I’ll walk you through a
2-minute setup where you choose how much detail you want to see.

  Open my dashboard any time:   click the # in the menu bar, or run  hashling open
  Remove me:                     hashling uninstall --all
$( [ -n "$PATH_ADDED" ] && printf '\n  The hashling command works in new Terminal windows (not this one).\n' || true )

EOF
if [ -n "$CONNECTED" ]; then printf '  Claude Code is connected: ask it "is my Mac safe?"\n'
else cat <<EOF
  Using an AI agent? Connect it to me:
    Claude Code:   claude mcp add --scope user hashling -- hashling mcp
    Others:        command "hashling", args ["mcp"]
EOF
fi
HASHLING_NODE="$NODE" "$BIN_DIR/hashling" open || true
