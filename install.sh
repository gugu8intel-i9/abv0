#!/bin/sh
set -e

echo "⚡ Installing abv0 - The Faster, Secure, High-Performance Package Manager..."

OS="$(uname -s)"
ARCH="$(uname -m)"

TARGET=""
case "${OS}" in
    Linux*)
        case "${ARCH}" in
            x86_64*) TARGET="abv0-linux-x86_64" ;;
            *) echo "Error: Unsupported Linux architecture '${ARCH}'"; exit 1 ;;
        esac
        ;;
    Darwin*)
        case "${ARCH}" in
            x86_64*) TARGET="abv0-darwin-x86_64" ;;
            arm64*|aarch64*) TARGET="abv0-darwin-arm64" ;;
            *) echo "Error: Unsupported macOS architecture '${ARCH}'"; exit 1 ;;
        esac
        ;;
    *)
        echo "Error: Unsupported operating system '${OS}'"
        exit 1
        ;;
esac

BIN_DIR="$HOME/.abv0/bin"
mkdir -p "${BIN_DIR}"

URL="https://raw.githubusercontent.com/gugu8intel-i9/abv0/main/release/${TARGET}"

echo "⬇️  Downloading ${TARGET}..."
curl -s -L -o "${BIN_DIR}/abv0" "${URL}"
chmod 0700 "${BIN_DIR}/abv0"

echo ""
echo "✅ abv0 installed successfully to ${BIN_DIR}/abv0"
echo "💡 Make sure to add it to your PATH in your profile (~/.zshrc or ~/.bashrc):"
echo "    export PATH=\"${BIN_DIR}:\$PATH\""
echo ""
echo "🚀 Try running your first brew command:"
echo "    abv0 list"
