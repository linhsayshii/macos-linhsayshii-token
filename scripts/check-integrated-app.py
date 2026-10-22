#!/usr/bin/env python3
"""Start/stop only our packaged app; smoke-test loopback routes, never signing."""
import base64
import hashlib
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
for port in (32001, 16080, 8768, 8769):
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


def esigner(port, origin='https://thuedientu.gdt.gov.vn'):
    """Real WebSocket upgrade and CHECK_VERSION; stdlib only, no signing."""
    with socket.create_connection(('127.0.0.1', port), timeout=3) as connection:
        key = base64.b64encode(os.urandom(16)).decode()
        head = (f'GET /plugin/sign HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n'
                f'Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n'
                f'Sec-WebSocket-Key: {key}\r\nOrigin: {origin}\r\n\r\n')
        connection.sendall(head.encode())
        headers = b''
        while not headers.endswith(b'\r\n\r\n'):
            byte = connection.recv(1)
            if not byte or len(headers) > 8192:
                raise ValueError('Invalid WebSocket upgrade')
            headers += byte
        if origin == 'https://untrusted.invalid':
            assert b' 403 ' in headers
            return 403
        expected = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
        assert b' 101 ' in headers and expected.lower() in headers.lower()
        data = b'{"CODE":"CHECK_VERSION"}'
        mask = os.urandom(4)
        connection.sendall(bytes([0x81, 0x80 | len(data)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))
        def receive(count):
            result = b''
            while len(result) < count:
                chunk = connection.recv(count - len(result))
                if not chunk:
                    raise ValueError('WebSocket closed before reply')
                result += chunk
            return result
        frame = receive(2)
        assert frame[0] == 0x81 and not frame[1] & 0x80
        length = frame[1] & 127
        if length == 126:
            length = int.from_bytes(receive(2), 'big')
        assert length < 4096
        reply = json.loads(receive(length))
        assert reply.get('SUCCESS') == 'TRUE' and reply.get('CODE') == 'CHECK_VERSION'
        return reply['VERSION']


try:
    for _ in range(60):
        if app.poll() is not None:
            raise SystemExit('App stopped before bridge startup; see local smoke log.')
        try:
            status, _ = request('/api/SignHash/Version', 32001)
            _, negotiate = request('/signalr/negotiate?clientProtocol=2.1')
            esigner_versions = {str(port): esigner(port) for port in (8768, 8769)}
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
    for port in (8768, 8769):
        assert esigner(port, 'https://untrusted.invalid') == 403
    _, ct_post = request('/API/HUBCLIENT/GETCERT', 32001, body=b'{}')
    assert 'status' in ct_post
    _, xml_reply = request('/api/hubclient/signxml', 32001, body=b'{"filePath":"/not-a-picker-grant"}')
    assert xml_reply['status'] == 500 and 'dataFile' in xml_reply['message']
    try:
        request('/api/SignHash/Version', 32001, origin='https://untrusted.invalid')
    except urllib.error.HTTPError as error:
        assert error.code == 403
    else:
        raise SystemExit('CTSign accepted an unknown origin.')
    result = {'ctsign_http_status': status, 'minvoice_protocol': negotiate['ProtocolVersion'],
              'minvoice_getVersion': reply['R'], 'unknown_origin_status': 403,
              'esigner_versions': esigner_versions, 'esigner_unknown_origin_status': 403,
              'ctsign_post_case_insensitive': True, 'ctsign_signxml_route': True, 'ctsign_unknown_origin_status': 403,
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
