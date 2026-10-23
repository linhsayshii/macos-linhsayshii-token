// Standalone fixture harness; compile with the production XMLDSigSigner,
// MessageSigner and DigestInfo files. The runner supplies CMSSigner.digest only.
import Foundation
import Security
import CryptoKit

@main struct PrologSigningFixtures {
    static func main() async throws {
        let dir = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        let keyData = try Data(contentsOf: dir.appendingPathComponent("key.der"))
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                  kSecAttrKeyClass as String: kSecAttrKeyClassPrivate]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(keyData as CFData, attrs as CFDictionary, &error) else {
            throw error!.takeRetainedValue()
        }
        let signer = SoftwareSigner(key: key, certificateDER: try Data(contentsOf: dir.appendingPathComponent("cert.der")))
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<HSoThueDTu xmlns=\"http://kekhaithue.gdt.gov.vn/TKhaiThue\"><HSoKhaiThue id=\"ID_1\"><tenDVu>Thử tổng hợp</tenDVu></HSoKhaiThue><CKyDTu/></HSoThueDTu>"
        let bytes = Data(xml.utf8)
        let cases: [(String, Data, Bool)] = [
            ("utf8", bytes, true), ("utf8-bom", Data([0xef, 0xbb, 0xbf]) + bytes, true),
            ("no-declaration", Data(xml.components(separatedBy: "\r\n")[1].utf8), true),
            ("double-bom", Data([0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf]) + bytes, false),
            ("base64-text", Data(bytes.base64EncodedString().utf8), false),
            ("json-envelope", try JSONSerialization.data(withJSONObject: ["data": bytes.base64EncodedString()]), false),
            ("html-login", Data("<!DOCTYPE html><html><body>Test login</body></html>".utf8), false),
            ("junk-prolog", Data("TEST_ONLY".utf8) + bytes, false),
            ("utf16", xml.replacingOccurrences(of: "UTF-8", with: "UTF-16").data(using: .utf16)!, false)
        ]
        var options = XMLSignOptions()
        options.kind = .custom(parentXPath: "HSoThueDTu/CKyDTu")
        options.signElements = ["HSoKhaiThue"]
        options.signingTime = Date(timeIntervalSince1970: 1_792_761_600)
        var results: [[String: Any]] = []
        for (label, input, expectedAccepted) in cases {
            var row: [String: Any] = ["fixture": label, "inputBytes": input.count,
                "inputSHA256": SHA256.hash(data: input).map { String(format: "%02x", $0) }.joined()]
            do {
                let output = try await XMLDSigSigner.signEnveloped(xml: input, signer: signer, options: options)
                precondition(expectedAccepted, "Unexpected accepted fixture")
                precondition(String(data: output, encoding: .utf8) != nil && !output.starts(with: [0xef, 0xbb, 0xbf]))
                precondition(output.starts(with: Data("<?xml".utf8)))
                _ = try XMLDocument(data: output, options: [.nodePreserveAll])
                // Persist only synthetic XML in the runner's temporary directory
                // so independent xmlsec1 checks the exact serialized bytes.
                try output.write(to: dir.appendingPathComponent("\(label).xml"))
                row["accepted"] = true; row["outputBytes"] = output.count
                row["outputSHA256"] = SHA256.hash(data: output).map { String(format: "%02x", $0) }.joined()
                row["outputUTF8WithoutBOM"] = true; row["outputParseable"] = true
                let alternatives = [Data(output.base64EncodedString().utf8),
                    try JSONSerialization.data(withJSONObject: ["status": 200, "data": output.base64EncodedString()])]
                for alternative in alternatives {
                    precondition((try? XMLDocument(data: alternative, options: [])) == nil,
                                 "Wire envelope is not a raw XML document")
                }
                row["base64AndJSONAreNotRawXML"] = true
            } catch let e as XMLDSigError {
                precondition(!expectedAccepted, "Unexpected rejected fixture")
                row["accepted"] = false; row["diagnostic"] = e.description
            }
            results.append(row)
        }
        print(String(decoding: try JSONSerialization.data(withJSONObject: results, options: [.sortedKeys, .prettyPrinted]), as: UTF8.self))
    }
}
