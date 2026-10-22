#!/usr/bin/env python3
"""Start/stop only our packaged app; smoke-test loopback routes, never signing."""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode

root = Path(__file__).resolve().parent.parent
state = root / '.local/test-env'
state.mkdir(parents=True, exist_ok=True)
for port in (32001, 16080, 8768, 8769, 4433, 4434):
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


def websocket_reply(port, path, message, tls=False, origin='https://thuedientu.gdt.gov.vn'):
    """Real WebSocket upgrade and CHECK_VERSION; stdlib only, no signing."""
    raw = socket.create_connection(('127.0.0.1', port), timeout=3)
    if tls:
        cert = Path.home() / 'Library/Application Support/TokenSigner/tls/ca.pem'
        context = ssl.create_default_context(cafile=cert)
        # This generated, explicitly pinned CA may predate SKI/AKI extensions.
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        connection = context.wrap_socket(raw, server_hostname='localhost')
    else:
        connection = raw
    with connection:
        key = base64.b64encode(os.urandom(16)).decode()
        head = (f'GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n'
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
        data = message.encode()
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
        return receive(length).decode()


def esigner(port, origin='https://thuedientu.gdt.gov.vn'):
    reply = websocket_reply(port, '/plugin/sign', '{"CODE":"CHECK_VERSION"}', origin=origin)
    if reply == 403:
        return 403
    result = json.loads(reply)
    assert result.get('SUCCESS') == 'TRUE' and result.get('CODE') == 'CHECK_VERSION'
    return result['VERSION']


def vnpt(port, origin='https://dichvucong.gov.vn'):
    reply = websocket_reply(port, '/plugin', '{"functionID":7,"funcCallback":"smoke","args":[]}', tls=True, origin=origin)
    if reply == 403:
        return 403
    assert reply == '1*smoke'
    return reply


try:
    for _ in range(60):
        if app.poll() is not None:
            raise SystemExit('App stopped before bridge startup; see local smoke log.')
        try:
            status, _ = request('/api/SignHash/Version', 32001)
            _, negotiate = request('/signalr/negotiate?clientProtocol=2.1')
            esigner_versions = {str(port): esigner(port) for port in (8768, 8769)}
            vnpt_versions = {str(port): vnpt(port) for port in (4433, 4434)}
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
    for port in (4433, 4434):
        assert vnpt(port, 'https://untrusted.invalid') == 403
    for port in (8768, 8769):
        assert esigner(port, 'https://untrusted.invalid') == 403
    _, ct_post = request('/API/HUBCLIENT/GETCERT', 32001, body=b'{}')
    assert 'status' in ct_post
    _, xml_reply = request('/api/hubclient/signxml', 32001, body=b'{"filePath":"/not-a-picker-grant"}')
    assert xml_reply['status'] == 500 and 'dataFile' in xml_reply['message']
    # Rejected during input validation: never reach certificate selection or PIN.
    xml_diagnostics = []
    for document, code in (
        (b'not XML', 'XML_PARSE'),
        (b'<!DOCTYPE a [<!ENTITY x SYSTEM "file:///not-readable">]><a>&x;</a>', 'XML_DTD_ENTITY'),
        (b'<a><b Id="private-test-value"/><c id="private-test-value"/></a>', 'XML_DUPLICATE_ID'),
        (b'<a><Signature/></a>', 'XML_EXISTING_SIGNATURE'),
    ):
        body = json.dumps({'dataFile': base64.b64encode(document).decode()}).encode()
        _, diagnostic = request('/api/hubclient/signxml', 32001, body=body,
                                origin='https://thuedientu.gdt.gov.vn')
        assert diagnostic['status'] == 500 and f'[{code}]' in diagnostic['message']
        assert 'private-test-value' not in diagnostic['message'] and 'data' not in diagnostic
        xml_diagnostics.append(code)
    try:
        request('/api/SignHash/Version', 32001, origin='https://untrusted.invalid')
    except urllib.error.HTTPError as error:
        assert error.code == 403
    else:
        raise SystemExit('CTSign accepted an unknown origin.')
    result = {'ctsign_http_status': status, 'minvoice_protocol': negotiate['ProtocolVersion'],
              'minvoice_getVersion': reply['R'], 'unknown_origin_status': 403,
              'esigner_versions': esigner_versions, 'esigner_unknown_origin_status': 403,
              'vnpt_wss': vnpt_versions, 'vnpt_unknown_origin_status': 403, 'TLS_verified_with_pinned_local_CA': True,
              'ctsign_post_case_insensitive': True, 'ctsign_signxml_route': True, 'ctsign_unknown_origin_status': 403,
              'ctsign_xml_diagnostics': xml_diagnostics,
              'no_signing_or_external_rest': True}
    (state / 'integration-smoke.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
finally:
    # A startup scan can still own a read-only helper when the smoke finishes.
    # Remember only this app's children; never terminate another signer's helper.
    child_result = subprocess.run(['pgrep', '-P', str(app.pid)], capture_output=True, text=True)
    children = [int(pid) for pid in child_result.stdout.split() if pid.isdigit()]
    app.terminate()
    try:
        app.wait(timeout=5)
    except subprocess.TimeoutExpired:
        app.kill()
        app.wait()

    for pid in children:
        command = subprocess.run(['ps', '-p', str(pid), '-o', 'command='], capture_output=True, text=True).stdout.strip()
        if command.startswith(str(state / 'TokenSigner.app/Contents/MacOS/TokenHelper') + ' '):
            try:
                os.kill(pid, 15)
            except ProcessLookupError:
                pass
