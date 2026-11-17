# Third-party license checklist (before distributing binaries)

This repository's MPL-2.0 license covers the shmir project code and does
**not** replace third-party licenses. The macOS bundling scripts may copy
libraries into a release archive. Inspect the **actual bundled artifacts**
and include the corresponding licenses, copyright notices and any required
attribution when releasing binaries.

- **OpenSSL / libcrypto** — confirm the bundled version and its license
  terms (modern OpenSSL releases use Apache License 2.0).
- **Argon2 / libargon2** — inspect the license shipped with the precise
  Homebrew Argon2 formula/source used in the bundle.
- **json-c / libjson-c** — inspect the copyright and license notice shipped
  with the precise version bundled.
- **Other transitive libraries** — enumerate `otool -L` dependencies of
  each bundled dylib and executable; inspect licenses as applicable.

Do not treat this checklist as the license texts themselves. Package and
verify the exact third-party license files before making a downloadable
binary release publicly available.
