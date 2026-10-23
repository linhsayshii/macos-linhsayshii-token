#!/usr/bin/env python3
"""Embed the measured ARM64 ESPK runtime and dependency in a local test bundle."""
import ctypes
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parent.parent
app = Path(sys.argv[1]).resolve()
if not app.name.endswith('.app') or not (app / 'Contents/MacOS/TokenHelper').is_file():
    raise SystemExit('Expected a prepared app bundle containing TokenHelper')
destination = app / 'Contents/Frameworks/ESPK'
source = Path('/opt/homebrew/Cellar/opensc/0.27.1/lib/libopensc.13.dylib').resolve()
expected = '4d817582d5e5351b2dc0b5dd2f4dd32f0ab3debc81708687d63235028bde6dfa'
if hashlib.sha256(source.read_bytes()).hexdigest() != expected:
    raise SystemExit('OpenSC source runtime differs from the measured EFY runtime; nothing embedded')

def run(*args):
    return subprocess.check_output(args, text=True).strip()

def dependencies(path):
    return [line.strip().split(' (', 1)[0] for line in run('otool', '-L', str(path)).splitlines()[2:]]

libraries = {source.name: source}
for dependency in dependencies(source):
    if dependency.startswith(('/usr/lib/', '/System/Library/')):
        continue
    path = Path(dependency).resolve()
    if path.name != 'libcrypto.4.dylib':
        raise SystemExit(f'Unexpected OpenSC dependency: {path.name}')
    libraries[path.name] = path
for path in libraries.values():
    if run('lipo', '-archs', str(path)) != 'arm64':
        raise SystemExit(f'Expected native ARM64 runtime: {path.name}')
    if path != source and any(not dep.startswith(('/usr/lib/', '/System/Library/')) for dep in dependencies(path)):
        raise SystemExit(f'Unresolved transitive dependency in {path.name}')

destination.mkdir(parents=True, exist_ok=True)
manifest = []
for name, path in libraries.items():
    target = destination / name
    target.unlink(missing_ok=True)
    shutil.copy2(path, target)
    target.chmod(0o644)
    run('install_name_tool', '-id', '@loader_path/' + name, str(target))
    for dep in dependencies(path):
        if Path(dep).name in libraries:
            run('install_name_tool', '-change', dep, '@loader_path/' + Path(dep).name, str(target))
    run('codesign', '--force', '--sign', '-', str(target))
    run('codesign', '--verify', '--strict', str(target))
    if any(not dep.startswith(('/usr/lib/', '/System/Library/', '@loader_path/')) for dep in dependencies(target)):
        raise SystemExit('Packaged runtime still depends on external libraries')
    manifest.append({'name': name, 'architecture': 'arm64',
        'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'packaged_sha256': hashlib.sha256(target.read_bytes()).hexdigest(), 'dependencies': dependencies(target)})

notices = app / 'Contents/Resources/ESPK-Notices'
notices.mkdir(parents=True, exist_ok=True)
shutil.copy2(root / 'Sources/CFastCA/vendor/COPYING', notices / 'OpenSC-COPYING')
crypto = libraries['libcrypto.4.dylib']
shutil.copy2(crypto.parent.parent / 'LICENSE.txt', notices / 'OpenSSL-LICENSE.txt')
(notices / 'README.txt').write_text(
    'OpenSC 0.27.1 (LGPL 2.1 or later), dynamically loaded from Contents/Frameworks/ESPK.\n'
    'Source: https://github.com/OpenSC/OpenSC/tree/0.27.1\n'
    'OpenSSL libcrypto from the local ARM64 runtime; Apache License 2.0.\n'
    'Source: https://github.com/openssl/openssl\n'
    'This is a local test bundle; public release/distribution is a separate step.\n')
runtime = ctypes.CDLL(str(destination / source.name))
runtime.sc_get_version.restype = ctypes.c_char_p
if runtime.sc_get_version() != b'0.27.1':
    raise SystemExit('Packaged OpenSC ABI check failed')
# Non-code resources must live outside Contents/Frameworks for strict signing.
(destination / 'manifest.json').unlink(missing_ok=True)
(notices / 'runtime-manifest.json').write_text(json.dumps({'version': '0.27.1', 'libraries': manifest}, indent=2) + '\n')
print('PASS bundled ARM64 ESPK runtime, dependency closure, licenses, ABI and code signatures')
