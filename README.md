# shmir — C17 Rewrite (Phase 2 compatibility)

C implementation of the **3-of-5 Shamir Secret Sharing math project**, ported from
`Shamir_Phase2_Secure_Fixed.py`. It provides a reusable `libshmir`, a terminal CLI,
encrypted persistent state, and tests. The Python CLI lives in `reference/`
and uses the same encrypted state format.

## Requirements

* C17 compiler, CMake >=3.20
* OpenSSL >=3 (`libcrypto`), `json-c`, `libargon2`
* POSIX OS: **macOS, Linux, FreeBSD** (macOS/FreeBSD not yet runtime-tested).
* Python 3 with `cryptography` and `argon2-cffi` for the Python CLI's encrypted
  storage and for the optional cross-language test.

On macOS with Homebrew:

```sh
brew install cmake openssl@3 json-c argon2 pkg-config
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$(brew --prefix)"
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/shmir --demo
./build/shmir
```

On Debian/Ubuntu for development:

```sh
sudo apt install build-essential cmake pkg-config libssl-dev libjson-c-dev libargon2-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DSHMIR_SANITIZE=ON
cmake --build build -j
ASAN_OPTIONS=detect_leaks=1 ctest --test-dir build --output-on-failure
```

When the optional Python packages are missing, the `python_compat` test will fail; install
`python3 -m pip install cryptography argon2-cffi` in an isolated virtualenv or disable the
cross-language test using `-DSHMIR_PYTHON_COMPAT=OFF` (see CMake option below).

## Commands

```
./build/shmir                 # Interactive terminal menu
./build/shmir --no-alt-screen # Keep terminal output visible
./build/shmir --demo          # Deterministic example and math checks
 ./build/shmir --test         # Launch built test executable
 ./build/shmir --help
```

Menu 1 creates 5 shares and saves encrypted state; 2 recovers manually; 3 recovers from
stored shares; 4 runs the demo; 5 deletes encrypted state; 6 exports a single holder's
plaintext share without overwriting an existing file.

The Python CLI exposes the same six menu actions and supports `--demo`,
`--test`, `--help`, `--no-alt-screen`, and `--setup`:

```sh
python3 reference/Shamir_Phase2_Secure_Fixed.py --help
python3 reference/Shamir_Phase2_Secure_Fixed.py --test
```

Use `--setup` only to reset the shared state. It requires an interactive
terminal and exact confirmation with `RESET SHMIR`. Successful setup replaces
`shares.enc` and removes legacy `shares.json` after verifying the new file.

The file path is `$XDG_STATE_HOME/shamir-secret-sharing/shares.enc` or, by default,
`$HOME/.local/state/shamir-secret-sharing/shares.enc`. Legacy `shares.json` migration
requires explicit approval and **does not delete the old plaintext file**.

## Format compatibility and cryptography

* Prime **50021**, degree 2, threshold **3** and total **5**.
* Random coefficients via OpenSSL `RAND_bytes`; degree is exactly 2 (nonzero `a2`).
* Argon2id time cost 3, memory 65536 KiB, parallelism 2, output 32 bytes.
* AES-256-GCM with per-write random 16-byte salt and 12-byte nonce.
* JSON envelope version 2, exact canonical AAD compatible with Python `json.dumps(...,sort_keys=True,separators=(',',':'))`.
* Atomic temporary-file replace, 0600 file mode and 0700 state-directory mode.
* Rejects symlinks at state file and in directory components, uses bounded file reads, and
  rejects invalid share sets and malformed parameters.
* Manual or exported shares are *not encrypted*. Keep holders' copies separate.

**Security note:** This is a math-school-project reference, not independently audited
cryptographic software. No password recovery exists. Do not use it for high-value secrets.
Memory zeroization is best-effort for passwords, keys and temporary decrypted buffers;
third-party JSON library allocations may retain sensitive data until deallocation.

## Validation status

Tested in a Linux x86-64 build with ASan+UBSan and LeakSanitizer-enabled runs:
- C assertions covering the deterministic example, all 26 qualified 3/4/5 combinations,
  many randomly split secrets, invalid inputs, tamper detection, wrong passwords, permissions,
  no-overwrite export and deletion.
- Round-trip **Python → C** and **C → Python** using the actual Phase 2 source.
- Python baseline self-test (14/14) passed in this environment.

**Not yet verified:** actual macOS Apple Silicon or FreeBSD builds; C UI parity for Thai
prompts and all UX nuances; cryptographic independent audit. Terminal UI modernization
is deferred by design.

## One-command portable macOS distribution (no runtime Homebrew dependencies)

From this source tree **on a Mac**, run:

```sh
./scripts/package-macos.sh
```

The script installs the **build-time** dependencies with Homebrew if needed, builds and
runs the native C tests, copies non-system `.dylib` dependencies into `lib/`, patches
Mach-O loader paths and ad-hoc signs the modified binaries. The resulting archive is
`dist/shmir-macos-arm64-portable.zip` on Apple Silicon or
`dist/shmir-macos-x86_64-portable.zip` on Intel.

Extract the archive and run `./run.sh` inside its folder. The **receiving Mac** does
not need Homebrew, Python, CMake, OpenSSL, json-c or Argon2 installed separately.
The package is architecture-specific. This packaging step has not been executed on
macOS in this environment: run and validate on a real Mac before sharing. Ad-hoc
signing is not Apple notarization, and macOS Gatekeeper may still require an explicit
user trust decision for software downloaded from the internet.

All bundled third-party libraries remain subject to their respective license notices;
review and include required notices before redistributing publicly.

## Install with ONE command from the source root (macOS)

From the extracted `shmir-c` source directory on your Mac, run:

```sh
./install.sh
```

If you are already inside `scripts/`, `./install.sh` also redirects to the same
one-command source installer. **Do not run** `python3 -m pip install ...` for
the normal C17 installation; the Python dependencies are only for optional
compatibility tests.

That command runs the existing `scripts/package-macos.sh` automatically: checks
Homebrew, installs **build-only** dependencies if required, builds the C17 code,
runs CTest, bundles required non-system Mach-O `.dylib` files, and installs the
result for your account. You do **not** need to run the packaging script or enter
`dist/` yourself. An internet connection and Homebrew are needed on the **build
Mac** the first time; the installed CLI does not require Python or Homebrew at
runtime. The scripts use no `sudo` for the user-level install.

Open a new zsh login terminal and run from any directory:

```sh
shmir
shmir --help
shmir --demo
```

Or use `export PATH="$HOME/.local/bin:$PATH"` in the current terminal session.
The program is stored at `~/.local/share/shmir/app/`, with a command launcher at
`~/.local/bin/shmir`. A marked PATH stanza is added to `~/.zprofile` unless you
set `SHMIR_SKIP_PATH_UPDATE=1`.

**Uninstall from the source root** (no build or Homebrew required):

```sh
./uninstall.sh
```

The uninstaller removes only identifiable shmir-managed program files and its
own PATH block. It preserves encrypted State in
`~/.local/state/shamir-secret-sharing/shares.enc`, exported shares, and other
user data. It refuses to remove files that appear to belong to another program.

For **redistribution**, `./scripts/package-macos.sh` still builds the portable ZIP
separately, which includes its own `install.sh` and `uninstall.sh`. When installed
from that ZIP, those scripts work directly without Homebrew or building anything.

**Validation caveat:** The macOS build, bundling and signing process has not been
run in this Linux environment. Verify on a real Apple Silicon Mac before handing
out binaries. Ad-hoc signing is not Apple notarization; review bundled library
licenses before public redistribution.

## Installer reliability fixes (2026-11-17)

* Fixed AppleClang's `mkdtemp` declaration error in `tests/test_shmir.c` by enabling Darwin declarations before includes (Linux keeps POSIX declarations).
* The source installer suppresses unrelated Homebrew auto-updates during dependency installation (`HOMEBREW_NO_AUTO_UPDATE=1` for that command only).
* The macOS package build explicitly selects Homebrew `openssl@3` rather than another `libcrypto` accidentally exposed by `/opt/homebrew/lib`.

These changes have passed local Linux Release tests, including cross-language compatibility. The Mach-O bundle and native macOS installer still require final verification on a Mac.

### Mach-O bundle validation (November 2026)

The bundled dylib's first `otool -L` entry is its own install name
(e.g. `@rpath/libargon2.1.dylib`), **not** a dependency. The bundler
now skips that entry when resolving dependencies, verifies the install
name separately, rewrites the remaining third-party dependencies to
`@executable_path/../lib/`, and ad-hoc signs the modified binaries.

The one-command macOS packaging sequence also runs
`python3 tests/test_bundle_macos.py` as a mocked Mach-O regression test.
This regression test passes on Linux but is not a substitute for a real
macOS binary loading test.

## macOS one-command installation and full removal

From the unpacked **source root**, run `./install.sh` (build, test, package, install).
From the same directory run `./uninstall.sh` to remove the installed program.
Both commands also work from the extracted portable package. Do not run the
`script/install.sh` source variant in isolation unless the source root is intact.

Each successful install rewrites the installation metadata file
`~/.local/share/shmir/.env` (not read by the C17 executable). Uninstall works
with v4's existing `.shmir-install-v1` marker even if `.env` is absent. It
requires the exact confirmation `DELETE SHMIR` and removes the managed command,
bundled libraries, env metadata, PATH block, and default encrypted state
(`shares.enc` / legacy `shares.json`). For a custom `XDG_STATE_HOME`, run
uninstall with the same value; exported shares in other folders are not removed.
Source files and Homebrew build dependencies are retained.

## v6 legacy install migration

`./install.sh` recognizes an intact v4 installation at `~/.local/share/shmir/app`
even if `.shmir-install-v1` is missing. It then replaces the managed app,
rewrites its `.env`, and restores its install metadata. Unknown content in the
legacy app directory blocks migration. `./uninstall.sh` recognizes the same
legacy layout and requires typing `DELETE SHMIR` before removing managed app
files and default encrypted state. User files outside managed paths and
Homebrew build dependencies are not removed.


## Python → C17 shared state path (v7)

The C CLI uses **exactly the same state path** as `shmir_secret_code.py`:
`$XDG_STATE_HOME/shamir-secret-sharing/shares.enc` when `XDG_STATE_HOME` is set,
otherwise `~/.local/state/shamir-secret-sharing/shares.enc`. The old unencrypted
`shares.json` lives next to it. `.env` under `~/.local/share/shmir/` is install
metadata **only**; it does not override the state path.

**Warning:** A full uninstall deletes both default state files used by the
Python and C versions, after typing `DELETE SHMIR`. To remove only the old
installed C app, preserving shares, use the explicit forced cleanup described
in the chat. The installer can adopt a recognized old installation or an
empty previously created app directory.

## Clean reset and full uninstall (v8)

`./install.sh` builds/tests/bundles, then launches interactive `shmir --setup`
before installing the new binary. You must enter `RESET SHMIR`, choose a secret
number (0-50020), and set a new password (at least 12 characters). Old encrypted
state is atomically replaced only after the new password is provided. The new
state is verified, then legacy `shares.json` is deleted. Cancelling setup does
not replace the state or change the installed binary. Neither script stores
passwords in `.env`. The state path is identical to the original Python version:
`${XDG_STATE_HOME:-$HOME/.local/state}/shamir-secret-sharing/shares.enc`.

`./uninstall.sh` removes the managed CLI, bundled libraries, `.env`, PATH block,
and **both** `shares.enc` and `shares.json` after `DELETE SHMIR` confirmation.
It also removes known state if the executable was already uninstalled. It does
not erase copies of exported plaintext shares, source files, or build tooling.
Deleting state also affects the original Python script.

## License

The shmir C17 project source is made available under the **Mozilla Public
License 2.0 (MPL-2.0)**. See [`LICENSE`](LICENSE). Source files contain
the standard MPL notice. The historical Python reference is included as
reference material from the original project; confirm you hold the rights
to all included material before publishing.

MPL-2.0 is file-level copyleft: when distributing modified MPL-covered files,
follow the license's source availability obligations. Independently authored
files in a larger work may use other licenses. As copyright holder, you can
separately license your own code, but third-party contributions require
appropriate additional rights for proprietary relicensing.

**Security notice:** This is a teaching / experimental secret-sharing
implementation. It has not undergone independent security review. Do not
rely on it for high-value secrets without auditing and appropriate testing.

**Bundled dependencies:** The project uses OpenSSL, Argon2 and json-c.
The MPL license on this repository does not relicense these libraries. Before
publishing compiled portable macOS releases, include the exact corresponding
third-party licenses and notices for the versions shipped; see
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md).

**Clean-install warning:** `./install.sh` can replace existing encrypted
state after explicit confirmation. `./uninstall.sh` can permanently delete
shared encrypted state used by the historical Python program. Back up any
needed shares before proceeding.
