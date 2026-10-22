#!/usr/bin/env python3
"""Start/stop only our packaged app; smoke-test loopback routes, never signing."""
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode

root = Path(__file__).resolve().parent.parent
state = root / '.local/test-env'
state.mkdir(parents=True, exist_ok=True)
for port in (32001, 16080):
    with socket.socket() as connection:
        connection.settimeout(0.3)
        if connection.connect_ex(('127.0.0.1', port)) == 0:
            raise SystemExit(f'Port {port} occupied: close the existing signer before this check.')
fd = os.open(state / 'integration-smoke.log', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
app = subprocess.Popen([str(state / 'TokenSigner.app/Contents/MacOS/App')],
                       stdin=subprocess.DEVNULL, stdout=fd, stderr=fd)
os.close(fd)


def request(path, port=16080, body=None, origin='https://hddt.minvoice.com.vn'):
    headers = {'Origin': origin}
    if body is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    req = urllib.request.Request(f'http://127.0.0.1:{port}{path}', data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=3) as response:
        return response.status, json.loads(response.read())


try:
    for _ in range(60):
        if app.poll() is not None:
            raise SystemExit('App stopped before bridge startup; see local smoke log.')
        try:
            status, _ = request('/api/SignHash/Version', 32001)
            _, negotiate = request('/signalr/negotiate?clientProtocol=2.1')
            break
        except (OSError, ValueError):
            time.sleep(0.25)
    else:
        raise SystemExit('Bridge startup timed out.')
    query = urlencode({'transport': 'longPolling', 'connectionToken': negotiate['ConnectionToken']})
    invocation = json.dumps({'H': 'handlerHub', 'M': 'getVersion', 'A': [], 'I': 'smoke'})
    _, reply = request('/signalr/send?' + query, body=urlencode({'data': invocation}).encode())
    if reply.get('R') != '2.0.0' or negotiate['ProtocolVersion'] != '2.1':
        raise SystemExit('Unexpected Minvoice handshake/version.')
    request('/signalr/abort?' + query)
    try:
        request('/signalr/negotiate', origin='https://untrusted.invalid')
    except urllib.error.HTTPError as error:
        if error.code != 403:
            raise
    else:
        raise SystemExit('Unknown origin was accepted.')
    result = {'ctsign_http_status': status, 'minvoice_protocol': negotiate['ProtocolVersion'],
              'minvoice_getVersion': reply['R'], 'unknown_origin_status': 403,
              'no_signing_or_external_rest': True}
    (state / 'integration-smoke.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
finally:
    app.terminate()
    try:
        app.wait(timeout=5)
    except subprocess.TimeoutExpired:
        app.kill()
        app.wait()
