#!/usr/bin/env python3
"""Check the actual bundled shim with synthetic APDUs; no token/PIN/PCSC calls."""
import ctypes
from pathlib import Path
import sys

root = Path(__file__).resolve().parent.parent
path = Path(sys.argv[1]) if len(sys.argv) > 1 else root / '.local/test-env/TokenSigner.app/Contents/MacOS/libTSShim.dylib'
shim = ctypes.CDLL(str(path))
rewrite = shim.ts_reencode
rewrite.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
                    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t]
rewrite.restype = ctypes.c_size_t


def check(name, source, expected):
    incoming = (ctypes.c_ubyte * len(source)).from_buffer_copy(source)
    outgoing = (ctypes.c_ubyte * (len(source) + 8))()
    count = rewrite(incoming, len(source), outgoing, len(outgoing))
    if bytes(outgoing[:count]) != expected:
        raise SystemExit(f'FAIL bundled shim: {name}; rebuild TSShim before packaging.')


payload = bytes(range(14))
check('short-Lc / extended-Le repair', bytes.fromhex('0cb000000e') + payload + bytes.fromhex('00ef'),
      bytes.fromhex('0cb0000000000e') + payload + bytes.fromhex('00ef'))
payload = bytes(i % 256 for i in range(274))
header = bytes.fromhex('0c2a9080000112')
check('NC-CA extended-Lc / short-Le repair', header + payload + b'\x20', header + payload + b'\x00\x20')
check('valid extended APDU remains unchanged', header + payload + b'\x00\x20', b'')
print('PASS bundled shim: both length repairs present; valid APDU untouched; no token or PIN used.')
