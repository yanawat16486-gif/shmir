# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#!/usr/bin/env python3
"""Bundle non-system Mach-O dependencies alongside shmir executable.
Run on macOS after CMake has built the CLI. Python is a build-time dependency only.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def macho_links(binary):
    """Return (install_name, dependencies) from otool -L.

    For Mach-O dylibs, the first listed entry is the dylib's own install
    name, not an external dependency. Executables have no such entry.
    """
    lines = run('otool', '-L', str(binary)).splitlines()[1:]
    entries = [s.strip().split(' (compatibility version ', 1)[0]
               for s in lines if s.strip()]
    if binary.suffix == '.dylib':
        if not entries:
            raise RuntimeError(f'Missing Mach-O install name: {binary}')
        return entries[0], entries[1:]
    return None, entries


def deps(binary):
    return macho_links(binary)[1]


def resolve(dep, loader, roots):
    if dep.startswith('/usr/lib/') or dep.startswith('/System/Library/'):
        return None
    if dep.startswith('/'):
        p = Path(dep)
        if p.exists():
            return p.resolve()
    if dep.startswith('@loader_path/'):
        p = loader.parent / dep[len('@loader_path/'):]
        if p.exists():
            return p.resolve()
    if dep.startswith('@executable_path/'):
        p = roots[0] / dep[len('@executable_path/'):]
        if p.exists():
            return p.resolve()
    if dep.startswith('@rpath/'):
        name = dep[len('@rpath/'):]
        for root in roots[1:]:
            p = root / name
            if p.exists():
                return p.resolve()
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--search', action='append', default=[])
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    dest = args.destination.resolve()
    bindir = dest / 'bin'
    libdir = dest / 'lib'
    bindir.mkdir(parents=True, exist_ok=True)
    libdir.mkdir(parents=True, exist_ok=True)
    executable = bindir / 'shmir'
    shutil.copy2(binary, executable)
    roots = [bindir, *[Path(p).resolve() for p in args.search]]
    pending = [executable]
    done = set()
    originals = {}
    while pending:
        item = pending.pop(0)
        if item in done:
            continue
        done.add(item)
        for dep in deps(item):
            resolved = resolve(dep, item, roots)
            if resolved is None:
                if dep.startswith('/usr/lib/') or dep.startswith('/System/Library/'):
                    continue
                raise RuntimeError(f'Unresolved dependency: {item}: {dep}')
            # Two different libraries with the same filename are not safe to bundle.
            target = libdir / resolved.name
            if target in originals and originals[target] != resolved:
                raise RuntimeError(f'Library basename conflict: {target.name}')
            originals[target] = resolved
            if not target.exists():
                shutil.copy2(resolved, target)
            if target not in done:
                pending.append(target)
            new_ref = '@executable_path/../lib/' + target.name
            run('install_name_tool', '-change', dep, new_ref, str(item))
    for lib in originals:
        run('install_name_tool', '-id', '@rpath/' + lib.name, str(lib))
    # Changes to Mach-O binaries invalidate their original signatures.
    for item in sorted(done):
        run('codesign', '--force', '--sign', '-', str(item))
    for item in sorted(done):
        print(f'Bundled: {item.relative_to(dest)}')
        own_id, dependencies = macho_links(item)
        if item.suffix == '.dylib' and own_id != '@rpath/' + item.name:
            raise RuntimeError(f'Incorrect bundled dylib install name: {item}: {own_id}')
        for dep in dependencies:
            if not (dep.startswith('/usr/lib/') or dep.startswith('/System/Library/')
                    or dep.startswith('@executable_path/../lib/')):
                raise RuntimeError(f'Unbundled dependency after rewrite: {item}: {dep}')
    print('Ready:', dest)


if __name__ == '__main__':
    try:
        main()
    except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        sys.exit(f'bundle failed: {exc}')
