#!/usr/bin/env python3
"""Drive the VNPT-CA Plugin bridge (WSS) of a running TokenSigner and verify the results.
Run:  python3 -I scripts/vnpt-ws-test.py <port> <cert-serial-hex>     (port = 4433 + TOKENSIGNER_PORT_OFFSET)
Each sign opens the approval sheet (first time) and the PIN sheet in the menu bar popover.
Trusts only the generated local CA file, so no keychain change is needed. No PIN is handled here."""
import base64, hashlib, json, os, socket, ssl, struct, subprocess, sys

port, serial = int(sys.argv[1]), sys.argv[2]
CA = os.path.expanduser("~/Library/Application Support/TokenSigner/tls/ca.pem")
OUT = "/tmp/vnpt-test"; os.makedirs(OUT, exist_ok=True)

def connect():
    ctx = ssl.create_default_context(cafile=CA)
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT   # Python 3.13+ strict mode wants SKI/AKI; browsers do not
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=300), server_hostname="127.0.0.1")
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET /plugin/sign HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: https://dichvucong.gov.vn\r\n"
               f"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf: buf += s.recv(1024)
    assert b" 101 " in buf.split(b"\r\n")[0], buf[:200]
    return s

def send(s, text):
    p = text.encode(); mask = os.urandom(4); n = len(p)
    hdr = bytes([0x81]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n) if n < 65536 else bytes([0x80 | 127]) + struct.pack(">Q", n))
    s.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(p)))

def recvn(s, n):
    d = b""
    while len(d) < n:
        c = s.recv(n - len(d)); assert c, "closed"; d += c
    return d

def recv(s):
    msg = b""
    while True:
        b0, b1 = recvn(s, 2); n = b1 & 0x7F
        if n == 126: n = struct.unpack(">H", recvn(s, 2))[0]
        elif n == 127: n = struct.unpack(">Q", recvn(s, 8))[0]
        msg += recvn(s, n)
        if b0 & 0x80: return json.loads(msg)

def call(s, fid, args):
    send(s, json.dumps({"functionID": fid, "funcCallback": "cb", "args": args}))
    r = recv(s); print(f"  functionID {fid}: code={r['code']} error={r['error']!r}"); return r

def run(cmd): return subprocess.run(cmd, capture_output=True, text=True)

s = connect()
print("getVersion:"); print("  ->", call(s, 11, [])["data"])
print("GetCertInfo:"); info = call(s, 0, [])
cert = json.loads(info["data"]); print("  ->", cert["serial"], cert["notAfter"])
cert_der = base64.b64decode(cert["certificate"])
open(f"{OUT}/cert.der", "wb").write(cert_der)
run(["openssl", "x509", "-inform", "DER", "-in", f"{OUT}/cert.der", "-out", f"{OUT}/cert.pem"])
run(["sh", "-c", f"openssl x509 -inform DER -in {OUT}/cert.der -noout -pubkey > {OUT}/pub.pem"])
opts = lambda extra={}: json.dumps({"certificateSerial": serial, **extra})
ok = {}

print("\nSignCMS (SHA-256, detached): approve + enter PIN in the popover")
content = b"TokenSigner CMS test " * 40
open(f"{OUT}/content.bin", "wb").write(content)
r = call(s, 4, [base64.b64encode(content).decode(), opts()])
if r["code"] == 0:
    open(f"{OUT}/cms.der", "wb").write(base64.b64decode(r["data"]))
    v = run(["openssl", "cms", "-verify", "-noverify", "-binary", "-inform", "DER", "-in", f"{OUT}/cms.der", "-content", f"{OUT}/content.bin", "-out", "/dev/null"])
    ok["CMS sha256"] = v.returncode == 0; print("  openssl cms -verify:", "OK" if v.returncode == 0 else v.stderr.strip())
    # signHash is checked against the key of the certificate that actually signed (certificateSerial), not GetCertInfo's pick.
    run(["sh", "-c", f"openssl cms -cmsout -inform DER -in {OUT}/cms.der -certsout {OUT}/signer.pem && openssl x509 -in {OUT}/signer.pem -noout -pubkey > {OUT}/pub.pem"])

print("\nSignXML with SHA-1 (rsa-sha1)")
xml = b"<HDon><DLHDon><TTChung><SHDon>2</SHDon></TTChung></DLHDon><DSCKS><NBan/></DSCKS></HDon>"
r = call(s, 1, [base64.b64encode(xml).decode(), opts({"digestMethod": "http://www.w3.org/2000/09/xmldsig#sha1"})])
if r["code"] == 0:
    open(f"{OUT}/signed.xml", "wb").write(base64.b64decode(r["data"]))
    v = run(["xmlsec1", "--verify", "--insecure", "--id-attr:Id", "http://www.w3.org/2000/09/xmldsig#:Object", "--enabled-key-data", "x509", f"{OUT}/signed.xml"])
    ok["XML sha1"] = v.returncode == 0; print("  xmlsec1 --verify:", "OK" if v.returncode == 0 else (v.stdout + v.stderr).strip()[:300])

print("\nsignHash (precomputed SHA-256 digest)")
msg = b"TokenSigner signHash test"; digest = hashlib.sha256(msg).digest()
open(f"{OUT}/digest.bin", "wb").write(digest)
r = call(s, 9, [base64.b64encode(digest).decode(), opts()])
if r["code"] == 0:
    open(f"{OUT}/hash.sig", "wb").write(base64.b64decode(r["data"]))
    v = run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", f"{OUT}/pub.pem", "-in", f"{OUT}/digest.bin", "-sigfile", f"{OUT}/hash.sig", "-pkeyopt", "digest:sha256"])
    ok["signHash"] = v.returncode == 0; print("  openssl pkeyutl -verify:", (v.stdout + v.stderr).strip())

print("\nSUMMARY:", ok)
