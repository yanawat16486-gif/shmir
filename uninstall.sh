#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Uninstall from any working directory, including the source tree.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec "$ROOT/scripts/uninstall.sh" "$@"
