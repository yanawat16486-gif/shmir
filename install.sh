#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# One command from the source root: build, test, bundle, then install.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
if [ "$(uname -s)" != Darwin ]; then
  echo 'Error: this one-command installer is for macOS. On Linux, use CMake.' >&2
  exit 1
fi
if [ ! -f "$ROOT/CMakeLists.txt" ] || [ ! -f "$ROOT/scripts/package-macos.sh" ]; then
  echo 'Error: incomplete shmir source directory.' >&2
  exit 1
fi
printf '\n== shmir: build + bundle + install ==\n'
printf 'This will use Homebrew for BUILD dependencies only. No sudo needed for installation.\n\n'
"$ROOT/scripts/package-macos.sh"
ARCH=$(uname -m)
DIST="$ROOT/dist/shmir-macos-$ARCH"
if [ ! -x "$DIST/bin/shmir" ] || [ ! -d "$DIST/lib" ] || [ ! -x "$DIST/install.sh" ]; then
  echo 'Error: packaging did not produce the expected installable directory.' >&2
  exit 1
fi
"$DIST/install.sh"
printf '\nSuccess. Open a NEW terminal or run: export PATH="$HOME/.local/bin:$PATH"\n'
printf 'Then: shmir --help\n'
