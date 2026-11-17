#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Per-user install for the packaged, self-contained macOS shmir distribution.
set -eu
umask 077
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
# When run from the source checkout (scripts/install.sh), delegate to the
# one-command source installer. A release archive has no CMakeLists.txt.
if [ -f "$SELF_DIR/../CMakeLists.txt" ] && [ -x "$SELF_DIR/../install.sh" ]; then
  exec "$SELF_DIR/../install.sh" "$@"
fi
if [ ! -x "$SELF_DIR/bin/shmir" ] || [ ! -d "$SELF_DIR/lib" ]; then
  echo 'Error: run install.sh from an extracted shmir-macos-*-portable directory (bin/shmir and lib/ required).' >&2
  exit 1
fi
if [ "$(uname -s)" != Darwin ]; then
  echo 'Error: portable macOS installer requires macOS.' >&2
  exit 1
fi
case "$(uname -m)" in
 arm64|x86_64) ;;
 *) echo 'Unsupported architecture.' >&2; exit 1;;
esac
BIN_DIR="$HOME/.local/bin"
APP_ROOT="$HOME/.local/share/shmir"
APP_DIR="$APP_ROOT/app"
CMD="$BIN_DIR/shmir"
PROFILE="$HOME/.zprofile"
START='# >>> shmir PATH >>>'
END='# <<< shmir PATH <<<'
if [ -L "$APP_ROOT" ] || [ -L "$APP_DIR" ] || [ -L "$BIN_DIR" ] || [ -L "$CMD" ] || [ -L "$APP_ROOT/.env" ]; then
  echo 'Error: existing symlink at an installation path; refusing to modify it.' >&2
  exit 1
fi
if [ -e "$CMD" ]; then
  if ! grep -q '^# shmir-installed-command-v1$' "$CMD" 2>/dev/null; then
    echo "Error: $CMD already exists and is not managed by shmir." >&2
    exit 1
  fi
fi
# Recognize an intact v4 package, v5/v6 metadata, or an empty directory left
# by an interrupted/uninstalled previous version. Do not adopt unrelated files.
if [ -d "$APP_ROOT" ]; then
  for entry in "$APP_ROOT"/* "$APP_ROOT"/.[!.]*; do
    [ -e "$entry" ] || [ -L "$entry" ] || continue
    case "$entry" in
      "$APP_DIR"|"$APP_ROOT/.shmir-install-v1"|"$APP_ROOT/.env") ;;
      *) echo "Error: unrelated file in $APP_ROOT: $entry" >&2; exit 1 ;;
    esac
  done
  if [ -d "$APP_DIR" ]; then
    if [ ! -x "$APP_DIR/bin/shmir" ] || [ ! -d "$APP_DIR/lib" ]; then
      echo "Error: unrecognized app directory: $APP_DIR" >&2; exit 1
    fi
    for entry in "$APP_DIR"/* "$APP_DIR"/.[!.]*; do
      [ -e "$entry" ] || [ -L "$entry" ] || continue
      case "$entry" in
        "$APP_DIR/bin"|"$APP_DIR/lib"|"$APP_DIR/README-source.md") ;;
        *) echo "Error: unrelated file in $APP_DIR: $entry" >&2; exit 1 ;;
      esac
    done
  fi
  if [ -f "$APP_ROOT/.env" ] && ! grep -Fq 'SHMIR_LAYOUT=portable-v1' "$APP_ROOT/.env"; then
    echo 'Error: existing .env is not a shmir-managed file; refusing overwrite.' >&2
    exit 1
  fi
fi
if [ -L "$APP_DIR" ]; then echo 'Error: app directory is a symlink.' >&2; exit 1; fi
if [ -e "$PROFILE" ] && [ -L "$PROFILE" ]; then
  echo 'Error: .zprofile is a symlink; refusing to edit.' >&2
  exit 1
fi
# Initialize the secret first. Failure/cancellation leaves the old installation
# in place; state is only replaced when the user supplies a new password.
# The C binary knows the same XDG state location as the original Python code.
if [ -L "${XDG_STATE_HOME:-$HOME/.local/state}/shamir-secret-sharing" ] || \
   [ -L "${XDG_STATE_HOME:-$HOME/.local/state}/shamir-secret-sharing/shares.enc" ] || \
   [ -L "${XDG_STATE_HOME:-$HOME/.local/state}/shamir-secret-sharing/shares.json" ]; then
  echo 'Error: refusing symlinked state paths.' >&2; exit 1
fi
printf '\n== Clean initialization: create a NEW secret and password ==\n'
"$SELF_DIR/bin/shmir" --setup
mkdir -p "$BIN_DIR" "$APP_ROOT"
TMP="$APP_ROOT/.app-new-$$"
if [ -e "$TMP" ]; then echo 'Error: temporary directory already exists.' >&2; exit 1; fi
mkdir "$TMP"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
cp -R "$SELF_DIR/bin" "$TMP/bin"
cp -R "$SELF_DIR/lib" "$TMP/lib"
if [ -f "$SELF_DIR/README-source.md" ]; then cp "$SELF_DIR/README-source.md" "$TMP/README-source.md"; fi
if [ -d "$APP_DIR" ]; then
  BACKUP="$APP_ROOT/.app-old-$$"
  if [ -e "$BACKUP" ]; then echo 'Error: backup path exists.' >&2; exit 1; fi
  mv "$APP_DIR" "$BACKUP"
  mv "$TMP" "$APP_DIR"
  rm -rf "$BACKUP"
else
  mv "$TMP" "$APP_DIR"
fi
# Recreate shmir-owned install metadata on every successful install.
# Note: C17 CLI does not read this metadata; it is not a secrets file.
ENV_TMP="$APP_ROOT/.env-new-$$"
( umask 077
  printf '%s\n' '# Managed by shmir install.sh; recreated on each install.' \
    'SHMIR_LAYOUT=portable-v1' \
    'SHMIR_STATE_NAME=shamir-secret-sharing' \
    'SHMIR_STATE_FILE=shares.enc' > "$ENV_TMP"
)
mv -f "$ENV_TMP" "$APP_ROOT/.env"
printf 'shmir portable per-user install\n' > "$APP_ROOT/.shmir-install-v1"
# Use a wrapper instead of a symlink: Mach-O run.sh uses a relative directory.
CMD_TMP="$BIN_DIR/.shmir-new-$$"
cat > "$CMD_TMP" <<'WRAPPER'
#!/bin/sh
# shmir-installed-command-v1
exec "$HOME/.local/share/shmir/app/bin/shmir" "$@"
WRAPPER
chmod 755 "$CMD_TMP"
mv -f "$CMD_TMP" "$CMD"
# Make the command discoverable from a NEW zsh login session, without sudo.
if [ "${SHMIR_SKIP_PATH_UPDATE:-0}" != 1 ]; then
  if [ -e "$PROFILE" ] && grep -Fq "$START" "$PROFILE"; then
    echo 'PATH marker already exists; leaving .zprofile unchanged.'
  else
    {
      printf '\n%s\n' "$START"
      printf 'export PATH="$HOME/.local/bin:$PATH"\n'
      printf '%s\n' "$END"
    } >> "$PROFILE"
  fi
fi
printf '\nInstalled: %s\n' "$CMD"
printf 'Open a NEW terminal window, then run: shmir\n'
printf 'To uninstall: %s/uninstall.sh (from this package)\n' "$SELF_DIR"
