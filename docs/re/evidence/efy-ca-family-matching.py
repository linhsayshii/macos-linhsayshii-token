#!/usr/bin/env python3
"""Offline EFY candidate-selection evidence. No hardware, PIN, or production edits.

The oracle is the captured Calais ATR/ATRMask, not a list of fabricated devices.
Synthetic variants below exercise the contract; they are not observed EFY models.
This deliberately grants no authentication/signing capability from an ATR match.
"""
import hashlib
import json
from functools import reduce
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REGISTRY = ROOT / "docs/re/evidence/efy-ca-installed-windows.json"
OBSERVED = bytes.fromhex("3b9f958131fe9f006646530510113971df00005100006a")


def parse_atr(atr):
    if len(atr) < 2 or len(atr) > 33 or atr[0] not in (0x3b, 0x3f):
        raise ValueError("ATR length/convention")
    cursor, group, y = 2, 1, atr[1] >> 4
    interfaces, protocols = [], []
    while True:
        next_y = None
        for bit, kind in ((1, "TA"), (2, "TB"), (4, "TC"), (8, "TD")):
            if y & bit:
                if cursor >= len(atr):
                    raise ValueError("truncated interface bytes")
                value = atr[cursor]
                interfaces.append({"name": kind + str(group), "offset": cursor, "value": f"{value:02x}"})
                cursor += 1
                if kind == "TD":
                    protocols.append(value & 15)
                    next_y = value >> 4
        if next_y is None or next_y == 0:
            break
        y, group = next_y, group + 1
    hist_length = atr[1] & 15
    needs_tck = any(p != 0 for p in protocols)
    hist_end = cursor + hist_length
    if hist_end + int(needs_tck) != len(atr):
        raise ValueError("ATR historical/TCK length")
    if needs_tck and reduce(int.__xor__, atr[1:], 0) != 0:
        raise ValueError("invalid TCK")
    return {"convention": f"{atr[0]:02x}", "interfaces": interfaces,
            "protocols": protocols or [0], "historical_offset": cursor,
            "historical_length": hist_length, "tck_offset": hist_end if needs_tck else None,
            "tck_valid": needs_tck}


def registry_pair():
    rows = [r for r in json.loads(REGISTRY.read_text())["registry"]
            if r["Key"].endswith("\\SmartCards\\EFY-CA Token Manager v1.0")]
    assert {r["View"] for r in rows} == {"Registry32", "Registry64"}
    pairs = {(bytes(r["Values"]["ATR"]), bytes(r["Values"]["ATRMask"])) for r in rows}
    assert len(pairs) == 1
    return pairs.pop()


TEMPLATE, MASK = registry_pair()


def masked_match(atr):
    return len(atr) == len(TEMPLATE) and all((a & m) == (b & m) for a, b, m in zip(atr, TEMPLATE, MASK))


def candidate(atr):
    try:
        parse_atr(atr)
    except ValueError:
        return False
    return masked_match(atr)


def repair_tck(atr):
    value = bytearray(atr)
    value[-1] = reduce(int.__xor__, value[1:-1], 0)
    return bytes(value)


def vector(name, atr, expect, origin="synthetic offline vector, not observed hardware"):
    actual = candidate(atr)
    assert actual == expect, name
    return {"name": name, "atr": atr.hex(), "origin": origin,
            "calais_mask_matches": masked_match(atr), "expected_candidate": expect,
            "actual_candidate": actual, "equals_original_exact_allowlist": atr == OBSERVED,
            "auth_or_sign_permission_from_vector": False}


def main():
    assert len(TEMPLATE) == len(MASK) == 23
    assert [i for i, m in enumerate(MASK) if m == 0] == [12, 13, 14, 22]
    cases = [vector("observed_101139", OBSERVED, True, "observed EFY from A01/B02")]
    for label, version in (("synthetic_100631", "100631"), ("synthetic_105239", "105239"),
                           ("synthetic_010011", "010011"), ("synthetic_230025", "230025"),
                           ("synthetic_ffffff", "ffffff"), ("synthetic_000000", "000000")):
        atr = bytearray(OBSERVED); atr[12:15] = bytes.fromhex(version)
        cases.append(vector(label, repair_tck(atr), True))
    # Reject neighbouring issuers even when the transport family is shared.
    for name, index, value in (("fastca_customer",19,0x69), ("ncca_customer",19,0x59),
                               ("vnpt_customer",19,0x32), ("wrong_family_FS",10,0x54),
                               ("different_personalization",11,0x07), ("fixed_byte18",18,1),
                               ("fixed_byte20",20,1), ("fixed_byte21",21,1)):
        atr = bytearray(OBSERVED); atr[index] = value
        cases.append(vector(name, repair_tck(atr), False))
    bad = bytearray(OBSERVED); bad[-1] ^= 1
    cases.append(vector("bad_TCK_even_though_mask_matches", bytes(bad), False))
    cases.append(vector("truncated", OBSERVED[:-1], False))
    cases.append(vector("trailing_byte", OBSERVED+b"\0", False))
    cases.append(vector("customer_byte_only_wrong_layout", bytes(19)+b"\x51"+bytes(3), False))
    swept = 0
    for offset in (12, 13, 14):
        for value in range(256):
            atr = bytearray(OBSERVED); atr[offset] = value; atr = repair_tck(atr)
            assert candidate(atr)
            swept += 1
    fixed_mutations = 0
    for offset, mask in enumerate(MASK):
        if mask and offset != 0:
            for bit in range(8):
                atr = bytearray(OBSERVED); atr[offset] ^= 1 << bit; atr = repair_tck(atr)
                assert not candidate(atr)
                fixed_mutations += 1
    result = {"evidence_id":"EFY-CA-C02", "kind":"offline ATR candidate-selection fixture only",
              "registry_evidence_path":str(REGISTRY.relative_to(ROOT)),
              "registry_evidence_sha256":hashlib.sha256(REGISTRY.read_bytes()).hexdigest(),
              "template":TEMPLATE.hex(), "mask":MASK.hex(),
              "wildcard_zero_based_offsets":[12,13,14,22],
              "observed_atr_structure":parse_atr(OBSERVED),
              "vectors":cases, "wildcard_single_byte_values_swept":swept,
              "fixed_position_bit_mutations_rejected":fixed_mutations,
              "result":"PASS", "physical_card_IO":False,
              "PIN_authentication_or_signatures":0,
              "limits":["Not production implementation or an auth eligibility oracle.",
                        "Synthetic EFY suffixes do not assert those EFY models exist.",
                        "Calais registration establishes candidate mask, not proof of every card's PIN/sign protocol."]}
    path = ROOT / "docs/re/evidence/efy-ca-family-fixtures.json"
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps({"result":"PASS","explicit_vectors":len(cases),"wildcard_sweeps":swept,
                      "fixed_bit_mutations":fixed_mutations,"physical_card_IO":False}))


if __name__ == "__main__":
    main()
