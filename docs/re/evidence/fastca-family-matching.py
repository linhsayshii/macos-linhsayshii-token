#!/usr/bin/env python3
"""Offline research fixture generator; no device I/O or authentication.

This is an independent reference for reviewing the proposed family matcher,
not a test of the product's production parser or signing implementation.
"""
import json
from functools import reduce
from operator import xor
from pathlib import Path

PATTERN = bytes.fromhex('3b9f958131fe9f006646530500000071df000000000000')
MASK = bytes.fromhex('ffffffffffffffffffffffff000000ffffffff00000000')


def valid_atr(atr):
    if len(atr) < 2 or atr[0] not in (0x3b, 0x3f):
        return False
    pos, present, protocols = 2, atr[1] >> 4, []
    while True:
        next_present = None
        for bit in range(4):
            if present & (1 << bit):
                if pos >= len(atr):
                    return False
                value = atr[pos]
                pos += 1
                if bit == 3:
                    protocols.append(value & 15)
                    next_present = value >> 4
        if next_present is None:
            break
        present = next_present
    tck = any(protocol != 0 for protocol in protocols)
    return (len(atr) == pos + (atr[1] & 15) + int(tck)
            and (not tck or reduce(xor, atr[1:], 0) == 0))


def mask_match(atr):
    return len(atr) == len(MASK) and all(
        (value & mask) == (pattern & mask)
        for value, pattern, mask in zip(atr, PATTERN, MASK))


def changed(base, edits):
    atr = bytearray.fromhex(base)
    for index, value in edits.items():
        atr[index] = value
    atr[-1] = reduce(xor, atr[1:-1], 0)
    return atr.hex()


def build():
    old = '3b9f958131fe9f006646530510523971df000069000011'
    new = '3b9f958131fe9f006646530510063171df00006900004d'
    cases = [
        ('observed-fastca-original', old, True, True, 'hardware observation'),
        ('observed-fastca-0631', new, True, True, 'hardware observation'),
        ('upstream-2012', '3b9f958131fe9f006646530501001171df000003900080', True, True, 'OpenSC source comment'),
        ('upstream-2022-opensc', '3b9f958131fe9f006646530523002571df000003900096', True, True, 'OpenSC source comment'),
        ('upstream-2022-feitian', '3b9f958131fe9f006646530523002571df000000000005', True, True, 'OpenSC source comment'),
        ('observed-efy-same-oem', '3b9f958131fe9f006646530510113971df00005100006a', True, True, 'hardware observation; other CA'),
        ('observed-oneca-other-oem', '3b9f118131fe9f006a6d546f6b656e2d5b000581900061', True, False, 'hardware observation; Longmai'),
        ('synthetic-version-status', changed(new, {12:0x32,13:0x42,14:0x59,20:0x90,21:0x01}), True, True, 'synthetic; not device coverage'),
        ('synthetic-unknown-customer', changed(new, {19:0x77}), True, True, 'synthetic; not FastCA issuer or auth proof'),
        ('bad-tck-still-raw-mask-match', new[:-2]+'4c', False, True, 'negative synthetic'),
        ('wrong-history-length', '3b9e'+new[4:], False, False, 'negative synthetic'),
        ('truncated', new[:-2], False, False, 'negative synthetic'),
        ('extra-byte', new+'00', False, False, 'negative synthetic'),
        ('different-fixed-oem-signature', changed(new, {10:0x54}), True, False, 'negative synthetic with recomputed TCK'),
    ]
    fixtures = []
    for name, encoded, well_formed, matches, origin in cases:
        atr = bytes.fromhex(encoded)
        assert valid_atr(atr) == well_formed, name
        assert mask_match(atr) == matches, name
        fixtures.append(dict(name=name, atr=encoded, origin=origin,
                             atrWellFormed=well_formed, rawFamilyMaskMatch=matches,
                             sharedFamilyDiscovery=well_formed and matches,
                             fastcaCustomerHint=(well_formed and matches and atr[19]==0x69),
                             signingAuthorizationEstablishedByATR=False))
    preflight = [
        ('valid-family-unknown-pin-profile', 'public ESPK metadata and cert/key match', 'readable; PIN protocol needs independent evidence'),
        ('missing-catalog', 'catalog absent', 'incompatible catalog; no signing target'),
        ('malformed-catalog', 'invalid lengths or duplicate/conflicting object identity', 'reject malformed metadata'),
        ('key-id-mismatch', 'certificate and key CKA_ID differ', 'reject target binding'),
        ('public-key-mismatch', 'same CKA_ID but public modulus differs', 'reject target binding'),
        ('unsupported-sign-capability', 'RSA4096 or EC requires unavailable native signing path', 'readable; signing backend unavailable'),
        ('other-ca-issuer', 'family matches but certificate issuer is EFY', 'route by confirmed provider; do not label FastCA'),
        ('duplicate-physical-identity', 'two readers with same certificate', 'preserve physical reader identity; do not guess target'),
    ]
    return dict(scope='Offline reference fixtures, not production tests or hardware coverage',
                source='fastca-family-source.json', pattern=PATTERN.hex(), mask=MASK.hex(),
                variableByteIndices=[12,13,14,19,20,21,22],
                familyATRLayout=dict(length=23, historyStart=7, historyLength=15,
                                     tckIndex=22, tckXORRange='1..22 inclusive'),
                fixtures=fixtures,
                preflightCases=[dict(name=n,input=i,expectedState=e,pinAttempts=0)
                                for n,i,e in preflight])


if __name__ == '__main__':
    output = json.dumps(build(), ensure_ascii=False, indent=2) + '\n'
    target = Path(__file__).with_name('fastca-family-fixtures.json')
    target.write_text(output)
    print('14 ATR fixtures checked; 8 preflight scenarios recorded; no device I/O')
