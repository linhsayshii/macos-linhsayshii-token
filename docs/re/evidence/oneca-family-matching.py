"""Offline research fixture checker; never loads middleware or contacts a token."""
from functools import reduce
from operator import xor
from pathlib import Path
import json


def parse_atr(value):
    b = bytes.fromhex(value)
    if len(b) < 2 or len(b) > 33 or b[0] not in (0x3b, 0x3f):
        raise ValueError('ATR bounds/TS')
    pos, y, historical_count = 2, b[1] >> 4, b[1] & 15
    protocols = []
    while True:
        td = None
        for bit in range(4):
            if y & (1 << bit):
                if pos >= len(b):
                    raise ValueError('truncated interface bytes')
                if bit == 3:
                    td = b[pos]
                pos += 1
        if td is None:
            break
        protocols.append(td & 15)
        y = td >> 4
    historical_start = pos
    pos += historical_count
    tck_required = any(t != 0 for t in protocols)
    if len(b) != pos + int(tck_required):
        raise ValueError('ATR historical length/TCK/trailing data')
    if tck_required and reduce(xor, b[1:], 0) != 0:
        raise ValueError('ATR TCK')
    return {'protocols': protocols or [0], 'historical_start': historical_start,
            'historical_count': historical_count,
            'historical_hex': b[historical_start:pos].hex(), 'tck_required': tck_required}


def mask_match(value, pattern, mask):
    a, p, m = map(bytes.fromhex, (value, pattern, mask))
    return len(a) == len(p) == len(m) and all((x & z) == (y & z) for x,y,z in zip(a,p,m))


def classify(value, profiles):
    try:
        decoded = parse_atr(value)
    except ValueError:
        return 'invalid-atr', []
    hits = [p['id'] for p in profiles if mask_match(value, p['atr_pattern'], p['atr_mask'])]
    if hits:
        return 'registered-candidate', hits
    h = bytes.fromhex(decoded['historical_hex'])
    if h.startswith(b'\x00jmToken-'):
        return 'longmai-family-hint-only', []
    return 'unknown-family', []


if __name__ == '__main__':
    fixture_path = Path(__file__).with_name('oneca-family-discovery-fixtures.json')
    f = json.loads(fixture_path.read_text())
    for case in f['cases']:
        status, hits = classify(case['atr'], f['profiles'])
        assert status == case['expected']['status'], (case['id'], status)
        assert hits == case['expected']['profiles'], (case['id'], hits)
    for p in f['profiles']:
        assert len(bytes.fromhex(p['atr_pattern'])) == len(bytes.fromhex(p['atr_mask'])) == 23
    print(json.dumps({'scope':'offline research ATR/registry fixtures only',
        'cases_passed':len(f['cases']), 'hardware_calls':0, 'authentication_calls':0,
        'signatures':0, 'runtime_source_changed':False}, indent=2))
