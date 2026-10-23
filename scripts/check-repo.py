#!/usr/bin/env python3
"""Read-only check that local feature branches are consolidated into the current checkout."""
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent.parent

def git(*args):
    return subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=True)

current = git('branch', '--show-current').stdout.strip()
branches = git('for-each-ref', '--format=%(refname:short)', 'refs/heads').stdout.splitlines()
status = {}
for branch in branches:
    if branch != current:
        status[branch] = git('merge-base', '--is-ancestor', branch, 'HEAD').returncode == 0
required = [
    'Sources/Bridges/BridgeCatalog.swift', 'Sources/Bridges/VNPTBridge.swift',
    'Sources/Bridges/LocalCA.swift', 'Sources/Bridges/ESignerBridge.swift',
    'Sources/Bridges/CTSignBridge.swift', 'Sources/Bridges/MinvoiceInvoices.swift',
    'Sources/TokenHelper/ESPK.swift', 'Sources/App/CertificatePicker.swift',
    'Sources/Core/AuditLog.swift', 'Package.resolved'
]
missing = [name for name in required if not (root / name).is_file()]
print(json.dumps({'branch': current, 'merged_local_branches': status, 'missing_required_files': missing}, indent=2))
if missing or not all(status.values()):
    raise SystemExit(1)
