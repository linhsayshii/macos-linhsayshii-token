"""Offline reconstruction of selected Minvoice 1.0.3 CIL; no vendor/network execution."""
import hashlib
import json
from pathlib import Path

EVIDENCE = Path(__file__).resolve().parents[2] / 'docs/re/evidence/minvoice-bulk-control-flow.json'

def groups(count, size):
    # ChunkBy: indexed Select -> GroupBy(Index / chunkSize) -> group Value.ToList.
    # Positive inputs: CIL integer division equals Python floor division.
    if count < 0 or size <= 0:
        raise ValueError('Model accepts only nonnegative counts and positive sizes')
    grouped = {}
    for index in range(count):
        grouped.setdefault(index // size, []).append(index)
    return list(grouped.values())

def scenario(count, size, *, stop_group=None, stage=None):
    actions = []
    confirmed = []
    for number, group in enumerate(groups(count, size), 1):
        if number == stop_group and stage == 'cancel-before-group':
            return {'actions': actions, 'upload_acknowledged_groups': confirmed,
                'terminal': 'cancelled-before-next-group', 'vendor_callback_success_possible': True}
        actions.append({'group': number, 'step': 'download', 'requested_count': len(group)})
        if number == stop_group and stage == 'download-error':
            return {'actions': actions, 'upload_acknowledged_groups': confirmed, 'terminal': 'exception-stops-loop'}
        actions.append({'group': number, 'step': 'sign-returned-documents'})
        if number == stop_group and stage == 'sign-error-cleanup-succeeds':
            actions.append({'group': number, 'step': 'delete-cache; installed-build-swallow-catch'})
        actions.append({'group': number, 'step': 'upload-returned-documents'})
        if number == stop_group and stage == 'upload-error':
            return {'actions': actions, 'upload_acknowledged_groups': confirmed,
                'terminal': 'exception-stops-loop; failing-upload-business-state-unknown'}
        confirmed.append(number)
    return {'actions': actions, 'upload_acknowledged_groups': confirmed, 'terminal': 'loop-completed'}

if __name__ == '__main__':
    source = json.loads(EVIDENCE.read_text())
    methods = {m['token']: m for m in source['methods']}
    for method in methods.values():
        assert hashlib.sha256(bytes.fromhex(method['raw_il_hex'])).hexdigest() == method['body']['il_sha256']
    # Lock the inferred group key to the exact observed 14-byte CIL lambda.
    assert methods['0x0600044b']['raw_il_hex'] == '036f0504000a027b0604000a5b2a'
    # This is model validation, not native vendor execution or backend capacity testing.
    checked = 0
    for size in [1, 2, 3, 7, 99, 100, 128]:
        for count in range(1025):
            actual = groups(count, size)
            assert [v for group in actual for v in group] == list(range(count))
            assert all(0 < len(g) <= size for g in actual)
            assert len(actual) == (count + size - 1) // size
            checked += 1
    boundaries = []
    for count in [0, 1, 2, 3, 99, 100, 101, 199, 200, 201, 299, 300, 301, 999, 1000, 1001, 10000]:
        grouped = groups(count, 100)
        boundaries.append({'invoice_count': count, 'cash_groups': len(grouped),
            'full_groups_of_100': count // 100, 'tail_group_count': count % 100})
    normal = scenario(300, 100)
    assert [a['requested_count'] for a in normal['actions'] if a['step'] == 'download'] == [100, 100, 100]
    failed = scenario(300, 100, stop_group=2, stage='upload-error')
    assert failed['upload_acknowledged_groups'] == [1]
    assert not any(a['group'] == 3 for a in failed['actions'])
    cancelled = scenario(300, 100, stop_group=2, stage='cancel-before-group')
    assert cancelled['upload_acknowledged_groups'] == [1]
    swallowed = scenario(300, 100, stop_group=2, stage='sign-error-cleanup-succeeds')
    assert any(a['group'] == 2 and a['step'] == 'upload-returned-documents' for a in swallowed['actions'])
    result = {'kind': 'analyst-control-flow-model', 'executed_vendor_code': False,
        'external_network': False, 'real_signatures_or_invoices_created': False,
        'basis': str(EVIDENCE.relative_to(EVIDENCE.parents[3])),
        'model_invariant_cases': checked, 'cash_boundaries': boundaries,
        'cash_300_success_path': normal,
        'ordinary_300_default_size_2': {'groups': len(groups(300, 2)), 'group_size': 2},
        'cash_300_upload_error_group_2': failed,
        'cash_300_download_error_group_2': scenario(300, 100, stop_group=2, stage='download-error'),
        'cash_300_cancel_before_group_2': cancelled,
        'cash_300_sign_error_group_2_cleanup_succeeds': swallowed,
        'limitations': ['Model follows selected exact-build CIL; it is not a live 300-invoice transaction.',
            'Upload acknowledged means transport completion only, not an independent per-invoice issued-state check.',
            'Returned XML/signature count is backend-dependent; not forced equal to requested invoice count.',
            'Server/UI limits, mixed-series behavior, failure atomicity and idempotency are not established.']}
    print(json.dumps(result, indent=2))
