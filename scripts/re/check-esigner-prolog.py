#!/usr/bin/env python3
"""Compile selected production XML signing sources in a temporary directory.
No SwiftPM/.build access, app launch, hardware access or network requests.
Only a digest shim is supplied to avoid compiling unrelated CMS dependencies.
"""
import hashlib
import json
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[2]

def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True)

sources = [root / p for p in [
    'Sources/Core/XMLDSigSigner.swift', 'Sources/Core/MessageSigner.swift',
    'Sources/Core/DigestInfo.swift', 'scripts/re/esigner-prolog-signing.swift']]
with tempfile.TemporaryDirectory(prefix='tokensigner-prolog-') as path:
    tmp = pathlib.Path(path)
    run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
         '-subj', '/CN=TokenSigner Synthetic Fixture', '-keyout', str(tmp/'key.pem'), '-out', str(tmp/'cert.pem')])
    run(['/usr/bin/openssl', 'rsa', '-in', str(tmp/'key.pem'), '-outform', 'DER', '-out', str(tmp/'key.der')])
    run(['/usr/bin/openssl', 'x509', '-in', str(tmp/'cert.pem'), '-outform', 'DER', '-out', str(tmp/'cert.der')])
    shim = tmp / 'DigestShim.swift'
    shim.write_text('''import Foundation
import CryptoKit
enum CMSSigner {
    static func digest(_ d: Data, _ h: HashAlg) -> Data {
        h == .sha256 ? Data(SHA256.hash(data: d)) : Data(Insecure.SHA1.hash(data: d))
    }
}
''')
    run(['/usr/bin/swiftc', '-module-cache-path', str(tmp/'module-cache'),
         *map(str, sources), str(shim), '-o', str(tmp/'fixtures')])
    fixtures = json.loads(run([str(tmp/'fixtures'), str(tmp)]).stdout)
    xmlsec = next((p for p in ['/opt/homebrew/bin/xmlsec1', '/usr/local/bin/xmlsec1'] if pathlib.Path(p).is_file()), None)
    for row in fixtures:
        if row['accepted']:
            if xmlsec:
                args = [xmlsec, '--verify', '--insecure', '--enabled-key-data', 'x509',
                        '--id-attr:id', 'HSoKhaiThue', '--id-attr:Id', 'http://www.w3.org/2000/09/xmldsig#:Object']
                signed = tmp / (row['fixture']+'.xml')
                run([*args, str(signed)])
                row['xmlsecVerified'] = True
                tampered = tmp / 'tampered.xml'
                tampered.write_bytes(signed.read_bytes().replace('Thử tổng hợp'.encode(), b'TAMPERED'))
                result = subprocess.run([*args, str(tampered)], capture_output=True)
                assert result.returncode != 0, 'Tampered document unexpectedly verified'
                row['tamperRejected'] = True
            else:
                row['xmlsecVerified'] = 'unavailable'
    print(json.dumps({'scope':'selected production signing files, software key, synthetic inputs only',
        'swiftpm_build_used':False, 'digest_only_shim':True,
        'sourceSHA256':{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        'fixtures':fixtures}, ensure_ascii=False, indent=2))
