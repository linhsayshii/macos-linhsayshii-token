"""Inspect captured ZIP/multipart offline; raw XML/certificates stay private."""
import argparse
import base64
import copy
import email.parser
import email.policy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET
import zipfile

DS = 'http://www.w3.org/2000/09/xmldsig#'
NS = {'ds': DS}
def local(tag):
    return tag.rsplit('}', 1)[-1]
def tree(node):
    return (node.tag, dict(node.attrib), node.text, node.tail, [tree(c) for c in node])
def paths(root):
    result = {}
    def walk(node, parent):
        path = parent + '/' + local(node.tag)
        result[id(node)] = path
        for child in node:
            walk(child, path)
    walk(root, '')
    return result

def inspect(root, expected):
    def write(name, data):
        path = root / name
        path.write_bytes(data)
        path.chmod(0o600)
        return path
    archives = sorted(root.glob('*-download.zip'))
    uploads = sorted(root.glob('*-signed.multipart'))
    assert archives and uploads
    unsigned = {}
    archive_counts = []
    for archive in archives:
        with zipfile.ZipFile(archive) as z:
            assert len(z.infolist()) <= 100 and sum(i.file_size for i in z.infolist()) < 32*1024*1024
            archive_counts.append(len(z.infolist()))
            for info in z.infolist():
                name = info.filename.lower()
                assert re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.xml', name)
                assert name not in unsigned and info.file_size < 4*1024*1024
                unsigned[name] = z.read(info)
    signed = {}
    upload_counts = []
    for upload in uploads:
        raw = upload.read_bytes()
        boundary = raw.split(b'\r\n', 1)[0][2:]
        assert re.fullmatch(b'[A-Za-z0-9-]{1,100}', boundary)
        msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(
            b'MIME-Version: 1.0\r\nContent-Type: multipart/form-data; boundary="' + boundary + b'"\r\n\r\n' + raw)
        parts = list(msg.iter_parts())
        upload_counts.append(len(parts))
        for part in parts:
            name = part.get_filename().lower()
            assert name in unsigned and name not in signed
            assert part.get_param('name', header='content-disposition') == 'files'
            assert part.get_content_type() == 'text/xml'
            signed[name] = part.get_payload(decode=True)
    assert set(unsigned) == set(signed)
    assert sum(len(ET.fromstring(data).findall("./DLieu/HDon")) for data in unsigned.values()) == expected
    profiles = []
    for index, name in enumerate(unsigned, 1):
        before, after = unsigned[name], signed[name]
        assert b'<!DOCTYPE' not in before.upper() + after.upper()
        u, s = ET.fromstring(before), ET.fromstring(after)
        node_paths = paths(s)
        sigs = s.findall('.//ds:Signature', NS)
        assert len(sigs) == 1
        sig = sigs[0]
        si = sig.find('ds:SignedInfo', NS)
        refs = si.findall('ds:Reference', NS)
        reference_profiles = []
        for ref in refs:
            uri = ref.attrib['URI']
            assert uri.startswith('#')
            targets = [n for n in s.iter() if n.attrib.get('Id') == uri[1:]]
            assert len(targets) == 1
            role = 'signing-time' if uri == '#signtime' else 'archive-entry-guid'
            assert role == 'signing-time' or uri[1:].lower() == name[:-4]
            reference_profiles.append({'role': role, 'target_path': node_paths[id(targets[0])],
                'digest_method': ref.find('ds:DigestMethod', NS).attrib['Algorithm'],
                'transforms': [t.attrib['Algorithm'] for t in ref.findall('ds:Transforms/ds:Transform', NS)]})
        certs = sig.findall('ds:KeyInfo/ds:X509Data/ds:X509Certificate', NS)
        assert len(certs) == 1
        cert = base64.b64decode(certs[0].text)
        certpath = write(f'{index:02d}-embedded-cert.pem', b'-----BEGIN CERTIFICATE-----\n' + base64.encodebytes(cert) + b'-----END CERTIFICATE-----\n')
        signedpath = write(f'{index:02d}-signed.xml', after)
        write(f'{index:02d}-unsigned.xml', before)
        command = ['xmlsec1', '--verify', '--lax-key-search', '--pubkey-cert-pem', str(certpath),
            '--enabled-reference-uris', 'same-doc', '--id-attr:Id', 'DLieu', '--id-attr:Id', 'Object']
        def verify(path, label):
            result = subprocess.run(command + [str(path)], capture_output=True)
            write(f'{index:02d}-{label}.log', result.stdout + result.stderr)
            return result.returncode
        verified = verify(signedpath, 'verify') == 0
        assert verified
        cleaned = copy.deepcopy(s)
        for parent in cleaned.iter():
            for child in list(parent):
                if child.tag == '{' + DS + '}Signature':
                    parent.remove(child)
        assert tree(cleaned) == tree(u)
        obj = sig.find('ds:Object', NS)
        signing_time = next(n for n in obj.iter() if local(n.tag) == 'SigningTime')
        negative_controls = {}
        invoice_nodes = s.findall('./DLieu/HDon')
        assert len(refs) == 2 and any(p['target_path'] == '/TDiep/DLieu' for p in reference_profiles)
        for kind in [f'invoice-data-{i}' for i in range(1, len(invoice_nodes)+1)] + ['signing-time', 'signature-value']:
            # Change only raw text bytes; reserializing with ElementTree can itself
            # alter namespace prefixes and invalidate an otherwise untouched signature.
            if kind.startswith('invoice-data-'):
                chunks = list(re.finditer(rb'<HDon(?:\s[^>]*)?>[\s\S]*?</HDon>', after))
                assert len(chunks) == len(invoice_nodes)
                chunk = chunks[int(kind.rsplit('-', 1)[-1])-1]
                leaf = re.search(rb'<(?P<tag>[A-Za-z_][A-Za-z0-9_.:-]*)(?:\s[^<>]*)?>(?P<text>[^<]+)</(?P=tag)>', chunk.group())
                assert leaf is not None
                start = end = chunk.start() + leaf.end('text')
                replacement = b'X'
            elif kind == 'signing-time':
                leaf = re.search(rb'<(?P<tag>(?:[A-Za-z_][A-Za-z0-9_.-]*:)?SigningTime)(?:\s[^<>]*)?>(?P<text>[^<]+)</(?P=tag)>', after)
                assert leaf is not None
                start, end = leaf.span('text')
                replacement = b'2000-01-01T00:00:00'
            else:
                leaf = re.search(rb'<(?P<tag>(?:[A-Za-z_][A-Za-z0-9_.-]*:)?SignatureValue)(?:\s[^<>]*)?>(?P<text>[^<]+)</(?P=tag)>', after)
                assert leaf is not None
                char = re.search(rb'[A-Za-z0-9+/]', leaf.group('text'))
                assert char is not None
                start = leaf.start('text') + char.start()
                end = start + 1
                replacement = b'A' if after[start:end] != b'A' else b'B'
            changed = after[:start] + replacement + after[end:]
            ET.fromstring(changed)
            path = write(f'{index:02d}-tampered-{kind}.xml', changed)
            negative_controls[kind] = verify(path, f'tampered-{kind}') != 0
            assert negative_controls[kind]
        profiles.append({'index': index, 'unsigned_bytes': len(before), 'signed_bytes': len(after),
            'unsigned_sha256': hashlib.sha256(before).hexdigest(), 'signed_sha256': hashlib.sha256(after).hexdigest(),
            'contained_invoice_count': len(invoice_nodes),
            'declared_quantity_matches_contained_count': s.findtext('./TTChung/SLuong') == str(len(invoice_nodes)),
            'root': local(s.tag), 'signature_path': node_paths[id(sig)], 'signature_count': len(sigs),
            'canonicalization': si.find('ds:CanonicalizationMethod', NS).attrib['Algorithm'],
            'signature_method': si.find('ds:SignatureMethod', NS).attrib['Algorithm'],
            'references': reference_profiles, 'keyinfo_children': [local(n.tag) for n in sig.find('ds:KeyInfo', NS)],
            'x509data_children': [local(n.tag) for n in sig.find('ds:KeyInfo/ds:X509Data', NS)],
            'time_object_id': obj.attrib.get('Id'),
            'signature_property_target': next(n.attrib.get('Target') for n in obj.iter() if local(n.tag) == 'SignatureProperty'),
            'time_format_seconds_no_zone': bool(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', signing_time.text or '')),
            'original_tree_unchanged_after_removing_signature': True, 'xmlsec_valid': verified,
            'negative_control_mutation': 'only selected raw text bytes changed; XML not reserialized',
            'negative_controls_rejected': negative_controls})
    report = {'expected_invoices': expected, 'zip_counts': archive_counts, 'multipart_counts': upload_counts,
        'xml_document_count': len(unsigned), 'contained_invoice_count': sum(p['contained_invoice_count'] for p in profiles),
        'filenames_match_exactly': True, 'multipart_field': 'files', 'part_content_type': 'text/xml',
        'xmlsec_version': subprocess.run(['xmlsec1', '--version'], capture_output=True, text=True).stdout.strip(),
        'verification_scope': 'Cryptographic signature and same-document references with each embedded public certificate; no CA-chain/revocation/legal-validity/business-state query.',
        'profiles': profiles}
    write('xml-profile.json', (json.dumps(report, indent=2) + '\n').encode())
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    parser.add_argument('--expected', type=int, required=True)
    args = parser.parse_args()
    print(json.dumps(inspect(args.directory, args.expected)))
