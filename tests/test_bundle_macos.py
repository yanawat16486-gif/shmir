# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#!/usr/bin/env python3
"""Portable regression tests for Mach-O install names and dependency rewriting.

Mocks Apple's Mach-O tools; the real signing/loading check must run on macOS.
"""
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

module_path = Path(__file__).resolve().parents[1] / 'scripts' / 'bundle_macos.py'
spec = importlib.util.spec_from_file_location('bundle_macos', module_path)
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


def verify_bundle(via_symlink=False):
    with TemporaryDirectory() as tmp:
        physical = Path(tmp) / 'physical'
        physical.mkdir()
        if via_symlink:
            alias = Path(tmp) / 'alias'
            alias.symlink_to(physical, target_is_directory=True)
            root = alias
        else:
            root = physical
        source_bin = root / 'build' / 'shmir'
        source_lib = root / 'brew' / 'libargon2.1.dylib'
        source_bin.parent.mkdir()
        source_lib.parent.mkdir()
        source_bin.write_bytes(b'mock executable')
        source_lib.write_bytes(b'mock dylib')
        # macOS /var and /tmp can be symlinks to /private/var and /private/tmp.
        # The bundler canonicalizes its destination via Path.resolve().
        dist = (root / 'dist').resolve()
        links = {}

        def fake_run(*argv):
            command = argv[0]
            if command == 'otool':
                target = Path(argv[2])
                if target not in links:
                    if target.name == 'shmir':
                        links[target] = ['/opt/homebrew/lib/libargon2.1.dylib']
                    else:
                        links[target] = ['@rpath/libargon2.1.dylib', '/usr/lib/libSystem.B.dylib']
                return str(target) + ':\n' + ''.join(
                    '\t' + name + ' (compatibility version 1.0.0, current version 1.0.0)\n'
                    for name in links[target]
                )
            if command == 'install_name_tool':
                if argv[1] == '-change':
                    path = Path(argv[4])
                    links[path] = [argv[3] if x == argv[2] else x for x in links[path]]
                elif argv[1] == '-id':
                    path = Path(argv[3])
                    links[path] = [argv[2], *links[path][1:]]
                else:
                    raise AssertionError(argv)
                return ''
            if command == 'codesign':
                return ''
            raise AssertionError(argv)

        import sys
        argv = ['bundle_macos.py', str(source_bin), str(dist), '--search', str(source_lib.parent)]
        # The sample dylib's absolute install-name path is typically from brew.
        # Bundle resolver takes @rpath paths or absolute existing paths.
        # Use @rpath here to exercise the lookup by search root.
        def run_with_rpath(*args):
            if args[0] == 'otool' and Path(args[2]).name == 'shmir' and Path(args[2]) not in links:
                links[Path(args[2])] = ['@rpath/libargon2.1.dylib']
            return fake_run(*args)
        with patch.object(bundle, 'run', side_effect=run_with_rpath), patch.object(sys, 'argv', argv):
            bundle.main()
        assert links[dist / 'bin' / 'shmir'] == ['@executable_path/../lib/libargon2.1.dylib']
        assert links[dist / 'lib' / 'libargon2.1.dylib'] == ['@rpath/libargon2.1.dylib', '/usr/lib/libSystem.B.dylib']
        assert (dist / 'lib' / 'libargon2.1.dylib').exists()


if __name__ == '__main__':
    verify_bundle()
    verify_bundle(via_symlink=True)
    print('Mach-O bundle regression passed (direct and symlinked paths)')
