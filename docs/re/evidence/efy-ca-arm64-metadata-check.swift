import Foundation
import CryptoKit
let root = URL(fileURLWithPath: CommandLine.arguments[1])
let catalog = try ESPKCatalog.parse(Data(contentsOf: root.appendingPathComponent("catalog.bin")))
var certs: [ESPKAttributes] = [], keys: [ESPKAttributes] = []
for entry in catalog where entry.directory == "pkcs11" {
    let file = String(format: "%04x.bin", entry.id)
    if entry.name.hasPrefix("cert") {
        certs.append(try ESPKAttributes(data: Data(contentsOf: root.appendingPathComponent(file))))
    } else if entry.name.hasPrefix("prvk") {
        keys.append(try ESPKAttributes(data: Data(contentsOf: root.appendingPathComponent(file))))
    }
}
let identities = try ESPKSigningIdentity.resolve(certificates: certs, keys: keys)
let rows = identities.map { identity -> [String: Any] in
    [
        "id_sha256": SHA256.hash(data: identity.id).map { String(format: "%02x", $0) }.joined(),
        "certificate_der_bytes": identity.certificateDER.count,
        "certificate_der_sha256": SHA256.hash(data: identity.certificateDER).map { String(format: "%02x", $0) }.joined(),
        "modulus_bits": identity.modulus.count * 8,
        "exponent_hex": identity.exponent.map { String(format: "%02x", $0) }.joined(),
        "key_reference": String(format: "%04x", identity.keyReference),
        "certificate_public_key_matches": RSAPKCS1v15.certificateMatches(identity)
    ]
}
let result: [String: Any] = [
    "catalog_entries": catalog.count,
    "certificate_objects": certs.count,
    "private_key_metadata_objects": keys.count,
    "resolved_signing_identities": rows.count,
    "identities": rows,
    "source_scope": "Unmodified ESPKCatalog, ESPKSigningIdentity.resolve and certificateMatches from current Core source; no card or signing API"
]
FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys]))
