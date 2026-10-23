#!/usr/bin/env python3
"""Run production C transport with mocked OpenSC functions. No card I/O."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='tokensigner-espk-test-') as directory:
    binary = str(Path(directory) / 'transport')
    subprocess.run(['xcrun', 'clang', '-DENABLE_SM', '-Wno-deprecated-declarations',
                    '-I', str(root / 'Sources/CFastCA/include'),
                    '-I', str(root / 'Sources/CFastCA/vendor'),
                    str(root / 'Tests/NativeESPK/transport.c'), '-o', binary], check=True)
    subprocess.run([binary], check=True)
