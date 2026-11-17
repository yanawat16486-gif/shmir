# C Rewrite status — 2026-11-17

## Implemented
- Split into `src/core`, `src/crypto`, `src/storage`, `src/platform`, `src/cli` with `include/shmir` public API.
- Shamir split/recovery and 3-of-5 validation, including all 3/4/5 subsets.
- Encrypted state format byte-level behavior compatible with original Python Phase 2 (JSON envelope/AAD, KDF, AES-GCM).
- Legacy JSON import with explicit confirmation, preserve legacy file.
- Per-holder plaintext export, no overwrite, file permissions.
- CLI interactive menu, alt-screen option, fixed demo, help, `--test`.
- ASan/UBSan build; C and cross-language Python tests.

## Remaining work / differences
- UI texts are currently mostly English; the old Thai TUI presentation is deferred to the dedicated UI rewrite.
- C error prompts/edge-case UX do not yet match Python word for word.
- Full Phase 2 scenario parity needs additional interactive script tests (password retry, migration cancellation, terminal Ctrl-C).
- POSIX/macOS/FreeBSD source build expected but only Linux tested here.
- No independent security audit; do not use for production secret storage.
