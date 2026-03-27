#!/bin/sh
set -e

REPO="apisentry-dev/apisentry"
BINARY="apisentry"
INSTALL_DIR="/usr/local/bin"

# Detect OS and arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

case "$OS" in
  linux|darwin) ;;
  *)
    echo "Unsupported OS: $OS. Download manually from:"
    echo "  https://github.com/$REPO/releases/latest"
    exit 1
    ;;
esac

ASSET="${BINARY}-${OS}-${ARCH}"
URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"

echo "Downloading APISentry for ${OS}/${ARCH}..."
curl -fsSL "$URL" -o "/tmp/${BINARY}"
chmod +x "/tmp/${BINARY}"

echo "Installing to ${INSTALL_DIR}/${BINARY} ..."
mv "/tmp/${BINARY}" "${INSTALL_DIR}/${BINARY}"

echo ""
echo "APISentry installed successfully!"
echo "Run: apisentry scan --spec openapi.yaml --target https://api.yourapp.com"
