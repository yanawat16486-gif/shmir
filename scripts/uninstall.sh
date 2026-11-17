#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Complete user-level removal for shmir v4 and newer.
# Run from source root, source scripts/, or a portable bundle.
set -eu
umask 077
BIN_DIR="$HOME/.local/bin"
APP_ROOT="$HOME/.local/share/shmir"
APP_DIR="$APP_ROOT/app"
CMD="$BIN_DIR/shmir"
PROFILE="$HOME/.zprofile"
STATE_BASE="${XDG_STATE_HOME:-$HOME/.local/state}"
STATE_DIR="$STATE_BASE/shamir-secret-sharing"
START='# >>> shmir PATH >>>'
END='# <<< shmir PATH <<<'
MARKER="$APP_ROOT/.shmir-install-v1"

# Check before removing anything. Never follow a link to an unrelated location.
for p in "$BIN_DIR" "$APP_ROOT" "$APP_DIR" "$CMD" "$PROFILE" "$STATE_DIR" "$MARKER" "$APP_ROOT/.env"; do
  if [ -L "$p" ]; then
    echo "Error: refusing symlinked path: $p" >&2
    exit 1
  fi
done
if [ -e "$CMD" ] && ! grep -q '^# shmir-installed-command-v1$' "$CMD" 2>/dev/null; then
  echo "Error: $CMD is not a managed shmir command; refusing to remove." >&2
  exit 1
fi
# Accept v4-v6 packages with missing markers and partial cleanups, but
# refuse to delete arbitrary application directories or unrelated files.
managed=0
if [ -f "$MARKER" ] || [ -e "$CMD" ]; then managed=1; fi
if [ -d "$APP_ROOT" ]; then
  for entry in "$APP_ROOT"/* "$APP_ROOT"/.[!.]*; do
    [ -e "$entry" ] || [ -L "$entry" ] || continue
    case "$entry" in
      "$APP_DIR"|"$MARKER"|"$APP_ROOT/.env") ;;
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
    managed=1
  fi
  if [ -f "$APP_ROOT/.env" ]; then
    if ! grep -Fq 'SHMIR_LAYOUT=portable-v1' "$APP_ROOT/.env"; then
      echo 'Error: unrecognized .env; refusing to delete.' >&2; exit 1
    fi
    managed=1
  fi
fi
if [ -f "$PROFILE" ]; then
  count_start=$(grep -Fxc "$START" "$PROFILE" || :)
  count_end=$(grep -Fxc "$END" "$PROFILE" || :)
  if [ "$count_start" -ne "$count_end" ] || [ "$count_start" -gt 1 ]; then
    echo 'Error: malformed shmir PATH block in .zprofile; refusing to edit.' >&2
    exit 1
  fi
fi
# The C CLI can persist its state using XDG_STATE_HOME. Ensure state path is local.
case "$STATE_DIR" in
  /*) ;;
  *) echo 'Error: XDG_STATE_HOME must be absolute.' >&2; exit 1 ;;
esac
# Avoid recursively deleting any user-created files from the state directory.
for file in "$STATE_DIR/shares.enc" "$STATE_DIR/shares.json"; do
  if [ -L "$file" ]; then echo "Error: refusing symlinked state: $file" >&2; exit 1; fi
done
if [ "$managed" -eq 0 ] && [ ! -f "$STATE_DIR/shares.enc" ] && [ ! -f "$STATE_DIR/shares.json" ]; then
  echo 'No shmir installation or known state files found; nothing removed.'
  exit 0
fi
printf '%s\n' 'This will remove the shmir CLI, its bundled libraries, .env, managed PATH block,'
printf '%s\n' 'and encrypted state files (shares.enc and legacy shares.json) from:'
printf '  %s\n' "$STATE_DIR"
printf '%s\n' 'WARNING: Python original and C rewrite use the SAME shares.enc!'
printf '%s\n' 'Deleting it may permanently destroy secrets used by BOTH programs.'
printf '%s\n' 'Exported shares elsewhere, source files, and Homebrew packages are not removed.'
printf 'Type DELETE SHMIR to continue: '
IFS= read -r confirm || exit 1
[ "$confirm" = 'DELETE SHMIR' ] || { echo 'Cancelled; nothing removed.'; exit 0; }

if [ -e "$CMD" ]; then rm -f -- "$CMD"; fi
if [ -d "$APP_DIR" ]; then rm -rf -- "$APP_DIR"; fi
if [ -f "$APP_ROOT/.env" ]; then rm -f -- "$APP_ROOT/.env"; fi
if [ -f "$MARKER" ]; then rm -f -- "$MARKER"; fi
rmdir "$APP_ROOT" 2>/dev/null || :
if [ -d "$STATE_DIR" ]; then
  for file in "$STATE_DIR/shares.enc" "$STATE_DIR/shares.json"; do
    if [ -f "$file" ]; then rm -f -- "$file"; fi
  done
  rmdir "$STATE_DIR" 2>/dev/null || :
fi
if [ -f "$PROFILE" ] && [ "$count_start" -eq 1 ]; then
  TMP=$(mktemp "$HOME/.zprofile.shmir.XXXXXX")
  trap 'rm -f "$TMP"' EXIT HUP INT TERM
  awk -v start="$START" -v end="$END" '
    $0==start {skip=1; next}
    $0==end && skip {skip=0; next}
    !skip {print}
  ' "$PROFILE" > "$TMP"
  chmod 600 "$TMP"
  mv -f "$TMP" "$PROFILE"
  trap - EXIT HUP INT TERM
fi
printf '%s\n' 'shmir uninstalled. Open a new Terminal window.'
