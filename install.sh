#!/bin/sh
# Usage:
#   curl -fsSL https://github.com/boormat/boom-sshh/releases/latest/download/install.sh | sh
set -eu

REPO="boormat/boom-sshh"
BASE_URL="https://github.com/${REPO}/releases/latest/download"

# --- Detect OS ---
OS=$(uname -s)
case "$OS" in
  Linux)  OS_NAME=linux ;;
  Darwin) OS_NAME=darwin ;;
  *)      echo "error: unsupported OS: $OS"; exit 1 ;;
esac

# --- Detect arch ---
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)  ARCH_NAME=x86_64 ;;
  aarch64|arm64) ARCH_NAME=aarch64 ;;
  *)             echo "error: unsupported architecture: $ARCH"; exit 1 ;;
esac

BIN="boom-sshh-${OS_NAME}-${ARCH_NAME}"
echo "asset: ${BASE_URL}/${BIN}"

# --- Download binary + checksums ---
# tempdir is local so no exec squash of /tmp
TMP=$(mktemp -d -p .)
trap 'rm -r "$TMP"' EXIT
TMPBIN="${TMP}/${BIN}"

curl -fsSL "${BASE_URL}/${BIN}"              -o "${TMPBIN}"
curl -fsSL "${BASE_URL}/checksums.txt"       -o "${TMP}/checksums.txt"

# --- Verify SHA256 ---
(cd "$TMP" && grep " ${BIN}$" checksums.txt | sha256sum -c --strict) || {
  echo "error: checksum verification failed"
  exit 1
}

# --- Install ---
chmod u+x "${TMPBIN}"
echo ""
echo "installing $(${TMPBIN} version)"
"${TMPBIN}" init-agent

echo "  boom-sshh init user@remote-host"
