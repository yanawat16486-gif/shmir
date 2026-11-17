#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Build and bundle a standalone shmir CLI for this Mac's architecture.
set -eu
cd "$(dirname "$0")/.."
if [ "$(uname -s)" != Darwin ]; then
  echo 'This script must run on macOS (Mach-O bundling requires otool/install_name_tool).' >&2
  exit 1
fi
if ! command -v brew >/dev/null 2>&1; then
  echo 'Homebrew is needed for the initial build. Install it from https://brew.sh and rerun.' >&2
  exit 1
fi
# Homebrew only serves the BUILD machine. End users do not need it.
# Avoid an unrelated tap update breaking an otherwise valid source build.
HOMEBREW_NO_AUTO_UPDATE=1 brew install cmake pkgconf openssl@3 argon2 json-c
PREFIX=$(brew --prefix)
OPENSSL_PREFIX=$(brew --prefix openssl@3)
ARGON2_PREFIX=$(brew --prefix argon2)
JSONC_PREFIX=$(brew --prefix json-c)
# Homebrew may contain other OpenSSL versions under $PREFIX/lib. Pin 3.
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$OPENSSL_PREFIX;$ARGON2_PREFIX;$JSONC_PREFIX;$PREFIX" \
  -DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX" \
  -DOPENSSL_INCLUDE_DIR="$OPENSSL_PREFIX/include" \
  -DOPENSSL_CRYPTO_LIBRARY="$OPENSSL_PREFIX/lib/libcrypto.dylib" \
  -DSHMIR_PYTHON_COMPAT=OFF
cmake --build build-release --parallel
ctest --test-dir build-release --output-on-failure
# Check that a dylib's own @rpath install name is not mistaken for a dependency.
python3 tests/test_bundle_macos.py
ARCH=$(uname -m)
DIST="$(pwd)/dist/shmir-macos-$ARCH"
rm -rf "$DIST"
python3 scripts/bundle_macos.py "$(pwd)/build-release/shmir" "$DIST" \
  --search "$(brew --prefix openssl@3)/lib" \
  --search "$(brew --prefix argon2)/lib" \
  --search "$(brew --prefix json-c)/lib" \
  --search "$(brew --prefix)/lib"
cp README.md "$DIST/README-source.md"
cp scripts/install.sh scripts/uninstall.sh "$DIST/"
chmod +x "$DIST/install.sh" "$DIST/uninstall.sh"
printf '%s\n' '#!/bin/sh' 'cd "$(dirname "$0")"' 'exec ./bin/shmir "$@"' > "$DIST/run.sh"
chmod +x "$DIST/run.sh"
(cd dist && /usr/bin/zip -qr "shmir-macos-$ARCH-portable.zip" "shmir-macos-$ARCH")
echo "Portable package: dist/shmir-macos-$ARCH-portable.zip"
echo 'To run without installation: ./run.sh'
echo 'To install as a shell command: ./install.sh (then open a new terminal)'
echo 'To remove installed command: ./uninstall.sh'
