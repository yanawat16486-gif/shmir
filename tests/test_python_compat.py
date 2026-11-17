# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Cross-language state envelope compatibility using actual Python Phase 2 source."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import sys

source = Path(__file__).resolve().parents[1] / 'reference/Shamir_Phase2_Secure_Fixed.py'
spec = importlib.util.spec_from_file_location('shmir_reference', source)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
exe = Path(sys.argv[1]).resolve()
password = 'correct horse battery staple'
shares = mod.create_shares(41216,37,82)
with tempfile.TemporaryDirectory() as d:
    env = os.environ.copy()
    env['XDG_STATE_HOME'] = d
    old = os.environ.get('XDG_STATE_HOME')
    os.environ['XDG_STATE_HOME'] = d
    try:
        # Python -> C
        mod.save_shares(shares, password)
        p = subprocess.run([str(exe),'--no-alt-screen'],input=f'{password}\n3\n1 3 5\n0\n',text=True,capture_output=True,env=env,timeout=20)
        assert p.returncode==0, p.stderr
        assert 'Recovered secret: 41216' in p.stdout, p.stdout
        # C -> Python: create a new encrypted set, then read with Python source
        mod.delete_saved_shares()
        p = subprocess.run([str(exe),'--no-alt-screen'],input=f'1\n41216\n{password}\n{password}\n0\n',text=True,capture_output=True,env=env,timeout=20)
        assert p.returncode==0, p.stderr
        recovered=mod.load_shares(password)
        assert mod.recover_secret(recovered[:3])==41216, recovered
        assert len(recovered)==5
        assert mod.state_path().stat().st_mode & 0o777 == 0o600
        print('PASS: Python->C and C->Python encrypted state compatibility')
    finally:
        if old is None:os.environ.pop('XDG_STATE_HOME',None)
        else:os.environ['XDG_STATE_HOME']=old
