#!/bin/sh
set -eu

REPO="boormat/boom-sshh"

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

# --- Get latest release tag ---
TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | head -1 | cut -d '"' -f 4)

if [ -z "$TAG" ]; then
  echo "error: could not determine latest release"
  exit 1
fi

echo "latest release: ${TAG}"
echo "asset: ${BIN}"

# --- Download binary + checksums ---
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
curl -fsSL "${BASE_URL}/${BIN}"              -o "${TMP}/${BIN}"
curl -fsSL "${BASE_URL}/checksums.txt"       -o "${TMP}/checksums.txt"

# --- Verify SHA256 ---
(cd "$TMP" && grep " ${BIN}$" checksums.txt | sha256sum -c --strict) || {
  echo "error: checksum verification failed"
  exit 1
}

# --- Install ---
INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ] 2>/dev/null; then
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

install -m 0755 "${TMP}/${BIN}" "${INSTALL_DIR}/boom-sshh"

echo ""
echo "installed ${INSTALL_DIR}/boom-sshh"

# --- Install boom-sshend client (extracted from the agent) ---
CLIENT_ARCH="${ARCH_NAME}-${OS_NAME}"
if "${INSTALL_DIR}/boom-sshh" extract-client "${CLIENT_ARCH}" "${INSTALL_DIR}/boom-sshend" 2>/dev/null; then
  echo "installed ${INSTALL_DIR}/boom-sshend"
else
  echo "warning: could not extract boom-sshend client (not embedded in this build)"
fi
echo ""
echo "next steps:"
echo "  eval \$(boom-sshh agent)"
echo "  boom-sshh init user@remote-host"
