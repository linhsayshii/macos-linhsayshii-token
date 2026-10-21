# TokenSigner P2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add XMLDSig and CMS signing to Core, the eSigner and VNPT-CA Plugin bridges, CTSigningHub `signxml`, web defenses, session approval and an audit log.

**Architecture:** Format signers (`XMLDSigSigner`, `CMSSigner`) are pure Core code that take a `MessageSigner` and know nothing about tokens. `MessageSigner` signs a *raw message* (the token hashes on-card, because these tokens only do `CKM_*_RSA_PKCS`, never a precomputed DigestInfo). Real tokens use `BrokerSigner` (TokenBroker); tests use `SoftwareSigner` (`SecKey`). Bridges only translate wire protocol to a `SigningService` protocol, which `AppModel` implements (approval → PIN → sign → audit). All bridges share one `WebGuard` (Host/Origin/CORS) backed by an `OriginStore`.

**Tech Stack:** Swift 6.4, Swift Testing, swift-nio (+ NIOWebSocket, NIOSSL), swift-asn1, swift-certificates, Foundation `XMLDocument` (C14N), openssl 4 and xmlsec1 for golden tests.

**Spec:** `docs/superpowers/specs/2026-10-21-tokensigner-design.md` (P2 rows of §5, §6). Protocol notes: `docs/re/esigner.md`, `docs/re/vnpt-plugin.md`, `docs/re/ctsigninghub.md`, `docs/re/macsigner-repo.md`.

## Global Constraints

- Everything from the P1 plan's Global Constraints still holds (arm64 app, Apple-only deps, Vietnamese UI copy, colors only from `Theme.swift`, light mode).
- Bind `127.0.0.1` only. Never `0.0.0.0`.
- PINs go only app → helper over stdin. Never on disk, in logs, in argv, in audit.jsonl.
- Accept only base64 `dataFile`-style inputs. Never implement `getFileLocal` or any `filePath` parameter.
- Never reuse the vendor's TLS key (`localhost.jks`). Generate our own local CA + leaf (SAN `localhost`, `127.0.0.1`).
- Never run vendor installers. Vendor files are untrusted data.
- Signing always goes through `TokenBroker` for real tokens (on-card RSA). A software `SecKey` appears in tests only.
- Items marked **(verify)** in the spec: implement the spec's best guess behind a small adapter and leave a `// shortcut: …` comment naming what to confirm against captured vendor traffic (no Parallels VM available in this phase).
- Audit log fields: time, origin, bridge, cert serial, operation, SHA-256 of input, result. Never PIN or content.
- Commit footer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`
- Build: `swift build`; tests: `swift test`. Toolchain is CommandLineTools: no SwiftUI `@State` macro, use `@Published` on the model.

## File Structure

| File | Responsibility |
|---|---|
| `Sources/Core/MessageSigner.swift` | `MessageSigner` protocol, `SoftwareSigner`, `BrokerSigner` |
| `Sources/Core/CMSSigner.swift` | CMS/PKCS#7 detached SignedData builder (swift-asn1) |
| `Sources/Core/XMLDSigSigner.swift` | XMLDSig enveloped signer (inclusive C14N, TT78 SigningTime, placement XPath) |
| `Sources/Core/AuditLog.swift` | append-only `audit.jsonl` |
| `Sources/Core/OriginStore.swift` | `origins.json` persistence + pending-unknown set |
| `Sources/Bridges/WebGuard.swift` | Host + Origin + CORS decisions shared by HTTP/WS bridges |
| `Sources/Bridges/SigningService.swift` | protocol bridges call; request/response value types |
| `Sources/Bridges/CTSignBridge.swift` | + `signxml` |
| `Sources/Bridges/ESignerBridge.swift` | pure `{CODE,INPUT}` message handler + `ESignerRequestAdapter` |
| `Sources/Bridges/VNPTBridge.swift` | pure `Connector` handler + `VNPTArgsAdapter` |
| `Sources/Bridges/WSServer.swift` | NIO WebSocket/WSS server hosting a message handler |
| `Sources/Bridges/LocalCA.swift` | generate CA + leaf, PEM files, keychain-trust command |
| `Sources/App/AppModel.swift` | implements `SigningService`; unknown-origin prompt; wiring |

## Phase gating

Tasks 1–3 = signing formats. 4–6 = defense/approval/audit. 7–10 = bridges. 11 = app wiring + verify. Tasks 4–6 land before any bridge so every bridge is born guarded.

---

### Task 1: MessageSigner + SHA-1 mechanism

**Files:**
- Create: `Sources/Core/MessageSigner.swift`
- Modify: `Sources/Core/HelperProtocol.swift` (add `sha1RSA`), `Sources/TokenHelper/PKCS11.swift:69-73` (map to `CKM_SHA1_RSA_PKCS`)
- Test: `Tests/CoreTests/MessageSignerTests.swift`

**Interfaces:**
- Produces:
  ```swift
  public protocol MessageSigner: Sendable {
      var certificateDER: Data { get }
      func sign(message: Data, hash: HashAlg) async throws -> Data   // PKCS#1 v1.5 signature over `message`
  }
  public struct SoftwareSigner: MessageSigner { public init(key: SecKey, certificateDER: Data) }
  public struct BrokerSigner: MessageSigner {
      public init(broker: TokenBroker, module: ModuleInfo, serial: String, cert: CertInfo, pin: @escaping @Sendable () async throws -> String)
  }
  ```
  `BrokerSigner.sign` maps `.sha256 → SignMech.sha256RSA`, `.sha1 → SignMech.sha1RSA`, calls `broker.sign(...)`, base64-decodes. The `pin` closure is called per sign (the AppModel shows the PIN sheet there).

- [ ] **Step 1: Write the failing test**

```swift
import Testing, Foundation, Security
@testable import Core

func makeTestKey() throws -> SecKey {
    var e: Unmanaged<CFError>?
    let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String: 2048]
    return try #require(SecKeyCreateRandomKey(attrs as CFDictionary, &e))
}

@Test func softwareSignerSignsSHA256AndSHA1() async throws {
    let key = try makeTestKey()
    let s = SoftwareSigner(key: key, certificateDER: Data([1]))
    let msg = Data("hello".utf8)
    for (h, alg) in [(HashAlg.sha256, SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256),
                     (.sha1, .rsaSignatureMessagePKCS1v15SHA1)] {
        let sig = try await s.sign(message: msg, hash: h)
        let pub = try #require(SecKeyCopyPublicKey(key))
        #expect(SecKeyVerifySignature(pub, alg, msg as CFData, sig as CFData, nil))
    }
}

@Test func sha1MechRawValue() { #expect(SignMech.sha1RSA.rawValue == "SHA1_RSA_PKCS") }
```

- [ ] **Step 2:** Run `swift test --filter MessageSignerTests` → FAIL (types missing).
- [ ] **Step 3: Implement**

```swift
// MessageSigner.swift
import Foundation
import Security

public protocol MessageSigner: Sendable {
    var certificateDER: Data { get }
    func sign(message: Data, hash: HashAlg) async throws -> Data
}

public struct SoftwareSigner: MessageSigner, @unchecked Sendable {
    let key: SecKey
    public let certificateDER: Data
    public init(key: SecKey, certificateDER: Data) { self.key = key; self.certificateDER = certificateDER }
    public func sign(message: Data, hash: HashAlg) async throws -> Data {
        let alg: SecKeyAlgorithm = hash == .sha256 ? .rsaSignatureMessagePKCS1v15SHA256 : .rsaSignatureMessagePKCS1v15SHA1
        var e: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(key, alg, message as CFData, &e) else { throw e!.takeRetainedValue() }
        return sig as Data
    }
}

public struct BrokerSigner: MessageSigner {
    let broker: TokenBroker, module: ModuleInfo, serial: String, cert: CertInfo
    let pin: @Sendable () async throws -> String
    public var certificateDER: Data { Data(base64Encoded: cert.derB64) ?? Data() }
    public init(broker: TokenBroker, module: ModuleInfo, serial: String, cert: CertInfo,
                pin: @escaping @Sendable () async throws -> String) {
        self.broker = broker; self.module = module; self.serial = serial; self.cert = cert; self.pin = pin
    }
    public func sign(message: Data, hash: HashAlg) async throws -> Data {
        let b64 = try await broker.sign(module: module, serial: serial, certId: cert.id,
                                        mech: hash == .sha256 ? .sha256RSA : .sha1RSA,
                                        dataB64: message.base64EncodedString(), pin: try await pin())
        return Data(base64Encoded: b64) ?? Data()
    }
}
```
Add `case sha1RSA = "SHA1_RSA_PKCS"` to `SignMech`; add `case .sha1RSA: mechType = CK_MECHANISM_TYPE(CKM_SHA1_RSA_PKCS)` to the helper switch. Make `HashAlg: Sendable, Equatable`.

- [ ] **Step 4:** `swift test --filter MessageSignerTests && swift build` → PASS.
- [ ] **Step 5:** Commit `feat(core): MessageSigner + SHA1_RSA_PKCS mech`.
- Note: SHA-1 on the real Feitian token is **not hardware-verified**; Task 11 checks it.

---

### Task 2: CMS detached SignedData

**Files:**
- Create: `Sources/Core/CMSSigner.swift`
- Test: `Tests/CoreTests/CMSSignerTests.swift`, helper `Tests/CoreTests/TestPKI.swift` (self-signed cert + key via `swift-certificates`, writes PEM to a temp dir)

**Interfaces:**
- Consumes: `MessageSigner`.
- Produces: `public enum CMSSigner { public static func signDetached(content: Data, signer: MessageSigner, hash: HashAlg = .sha256, signingTime: Date = Date()) async throws -> Data }` returning DER ContentInfo(SignedData).

Structure to build (DER, via `SwiftASN1.DER.Serializer`): ContentInfo{1.2.840.113549.1.7.2, [0] SignedData{version 1, digestAlgorithms SET{AlgId(hash)}, encapContentInfo{id-data} (no eContent), certificates [0] IMPLICIT {cert DER}, signerInfos SET{SignerInfo{version 1, sid IssuerAndSerialNumber, digestAlg, signedAttrs [0] IMPLICIT, sigAlg rsaEncryption 1.2.840.113549.1.1.1 NULL, signature OCTET STRING}}}}. Signed attrs (this order, as DER SET OF sorted by encoding): contentType(1.2.840.113549.1.9.3 = id-data), signingTime(1.2.840.113549.1.9.5, UTCTime), messageDigest(1.2.840.113549.1.9.4 = SHA-X(content)), signingCertificateV2(1.2.840.113549.1.9.16.2.47 = SEQ{SEQ{ESSCertIDv2{[hashAlg omitted if SHA-256 default], certHash SHA-256(cert)}}}). The signature is over the DER of the attribute SET with the universal SET tag (0x31), **not** the `[0]` tag; the signed-attrs field in SignerInfo is the same bytes with tag 0xA0.

- [ ] **Step 1: Failing test** — sign "hello" with a software cert, write content/sig/cert to temp files, run `openssl cms -verify -binary -inform DER -in sig.der -content content.bin -noverify`‑free variant: `-CAfile cert.pem -purpose any`. Expect exit 0. (Also run with SHA-1.) Helper `runTool("/opt/homebrew/bin/openssl", args)`; `try #require`/skip via `.enabled(if: FileManager.default.isExecutableFile(atPath: …))` trait.

```swift
@Test(.enabled(if: Tool.exists("openssl")))
func cmsDetachedVerifiesWithOpenSSL() async throws {
    let pki = try TestPKI.make()                       // key, certDER, certPEM path
    let content = Data("<a>hello</a>".utf8)
    let der = try await CMSSigner.signDetached(content: content, signer: pki.signer)
    let d = try TempDir(); try content.write(to: d["c.bin"]); try der.write(to: d["s.der"])
    let r = try Tool.run("openssl", ["cms","-verify","-binary","-inform","DER","-in",d["s.der"].path,
                                     "-content",d["c.bin"].path,"-CAfile",pki.certPEMPath,"-purpose","any","-out","/dev/null"])
    #expect(r.status == 0, "\(r.stderr)")
}
```
- [ ] **Step 2:** run → FAIL. **Step 3:** implement `CMSSigner`. **Step 4:** run → PASS; add test that tampering `content` makes openssl exit ≠ 0. **Step 5:** commit `feat(core): CMS detached signer`.
- Risk: DER set ordering of signed attrs. Sort attribute encodings lexicographically (what DER requires); the openssl test catches mistakes.

---

### Task 3: XMLDSig enveloped

**Files:**
- Create: `Sources/Core/XMLDSigSigner.swift`
- Test: `Tests/CoreTests/XMLDSigTests.swift`

**Interfaces:**
- Consumes: `MessageSigner`.
- Produces:
  ```swift
  public enum XMLDocKind: Sendable { case hoaDon, toKhai, custom(parentXPath: String) }
  public struct XMLSignOptions: Sendable {
      public var hash: HashAlg = .sha256              // .sha1 → rsa-sha1/sha1 variant
      public var kind: XMLDocKind = .hoaDon
      public var signingTime: Date = Date()
      public var signatureId = "SigningData"          // Id of ds:Signature (hoaDon: "seller")
      public var signingTimeId = "SigningTime"
  }
  public enum XMLDSigSigner {
      public static func signEnveloped(xml: Data, signer: MessageSigner, options: XMLSignOptions) async throws -> Data
      public static func placementPath(_ k: XMLDocKind) -> [String]   // hoaDon → ["HDon","DSCKS","NBan"], toKhai → ["TKhai","DSCKS","NNT"]
  }
  ```
  Placement: walk the path from the root, creating missing intermediate elements, append `ds:Signature` as last child of the final element. Algorithm URIs: C14N `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`; sig `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` (or `…#rsa-sha1`); digest `http://www.w3.org/2001/04/xmlenc#sha256` (or `…xmldsig#sha1`). References: (1) `URI=""` with transforms enveloped-signature + c14n, digest of the doc *without* the Signature; (2) `URI="#SigningTime"` for the `ds:Object/SignatureProperties/SignatureProperty Target="#SigningData"/SigningTime` (ISO 8601 `yyyy-MM-dd'T'HH:mm:ss`, +07:00 fixed). KeyInfo = `X509Data/X509Certificate` + `KeyValue/RSAKeyValue(Modulus, Exponent)` (modulus/exponent parsed from the cert's SPKI via swift-certificates).
  Canonicalization: `XMLDocument(data:options:[.nodePreserveAll])`, then `node.canonicalXMLStringPreservingComments(false)`. For SignedInfo, canonicalize the node *inside the final document* (so in-scope namespaces are right), after the digests are inserted with an empty `SignatureValue`.

- [ ] **Step 1: Failing tests**
  1. `placement`: sign `<HDon><DLHDon/><DSCKS><NBan/></DSCKS></HDon>`, assert `//HDon/DSCKS/NBan/ds:Signature` exists, a second parse has `SignatureProperty/SigningTime` with Target `#SigningData`.
  2. `selfVerify` (no external tool): re-derive digest of the enveloped-removed doc → equals `DigestValue`; canonicalize SignedInfo from the output, `SecKeyVerifySignature` with the test key's public key → true. Tamper a byte of the body → digest mismatch detected.
  3. `xmlsec1` golden (skip when missing): `xmlsec1 --verify --id-attr:Id Signature --pubkey-cert-pem cert.pem --enabled-key-data x509 out.xml` → exit 0, for sha256 and sha1.
- [ ] **Step 2:** run → FAIL. **Step 3:** implement. **Step 4:** PASS (xmlsec1 test skipped if absent; see Task 11 for installing it). **Step 5:** commit `feat(core): XMLDSig enveloped signer`.
- `shortcut:` comments: (a) fixed `+07:00` signing time zone; (b) golden structure compare vs vendor tool deferred (needs Parallels capture); (c) `NameIDTimeSignature`/XAdES-style node targeting from VNPT `XmlSignatureOption` not implemented, only placement XPath.

---

### Task 4: WebGuard + OriginStore

**Files:**
- Create: `Sources/Core/OriginStore.swift`, `Sources/Bridges/WebGuard.swift`
- Modify: `Sources/Bridges/HTTPServer.swift` (use WebGuard; take `OriginStore` instead of static allowlist)
- Test: `Tests/CoreTests/OriginStoreTests.swift`, `Tests/BridgesTests/WebGuardTests.swift`; keep `OriginAllowlistTests`.

**Interfaces:**
- Produces:
  ```swift
  public actor OriginStore {
      public init(fileURL: URL)                          // default dir: ~/Library/Application Support/TokenSigner/origins.json
      public func allowlist() -> OriginAllowlist         // defaults + stored patterns
      public func add(_ pattern: String) throws          // persists
      public func remove(_ pattern: String) throws
      public func notePending(_ origin: String)          // unknown origin seen; deduped
      public func takePending() -> [String]
  }
  public struct WebGuard: Sendable {
      public enum Verdict: Equatable, Sendable { case ok(origin: String?), badHost, unknownOrigin(String) }
      public init(port: Int)
      public func check(host: String?, origin: String?, allowlist: OriginAllowlist) -> Verdict
      public func corsHeaders(origin: String?, allowlist: OriginAllowlist) -> [String: String]   // ACAO echo + Allow-Private-Network + Vary
  }
  ```
  Rules: Host must be `127.0.0.1:<port>` or `localhost:<port>`. `origin == nil` → `.ok(nil)` (curl / native, no browser). An Origin present but not allowlisted → `.unknownOrigin(o)` (caller rejects 403 and calls `notePending`). The guard owns *all* origin decisions; the HTTPServer no longer inlines them.

- [ ] **Step 1: Failing tests** — rebinding host `evil.com:32001` → `.badHost`; `localhost:32001` ok; allowlisted origin ok + CORS headers contain `Access-Control-Allow-Origin == origin`, `Access-Control-Allow-Private-Network == "true"`; unknown origin → `.unknownOrigin`; no `Access-Control-Allow-Origin` for unknown. OriginStore: fresh file → defaults; `add("foo.example")` persists across a new instance reading the same file; `remove` works; defaults are not removable (throw) ; `notePending` dedupes.
- [ ] **Step 2–4:** implement; refactor `HTTPServer` so a 403 + pending-note happens for unknown origins on non-preflight requests, preflight for unknown origins gets no CORS headers (browser blocks). Run all tests + existing `CTSignTests`.
- [ ] **Step 5:** commit `feat(bridges): WebGuard + persisted origin store`.

---

### Task 5: AuditLog

**Files:** Create `Sources/Core/AuditLog.swift`; test `Tests/CoreTests/AuditLogTests.swift`.

**Interfaces:**
- Produces:
  ```swift
  public struct AuditEntry: Codable, Equatable, Sendable {
      public let time: String            // ISO8601
      public let origin, bridge, certSerial, operation, inputSHA256, result: String
  }
  public actor AuditLog {
      public init(fileURL: URL)
      public func append(origin: String, bridge: String, certSerial: String, operation: String,
                         input: Data, result: String)         // hashes `input` itself; never stores it
      public func recent(_ n: Int) -> [AuditEntry]
  }
  ```
  One JSON object per line, file mode 0600, newest appended last.
- [ ] **Step 1:** test: append two entries, `recent(1)` returns the second, raw file content contains `inputSHA256` of the data (64 hex) and does **not** contain the input bytes (use a recognizable marker string); file permissions 0600.
- [ ] **Step 2–4:** implement with `FileHandle.seekToEnd/write`. **Step 5:** commit `feat(core): audit.jsonl`.

---

### Task 6: SigningService contract

**Files:** Create `Sources/Bridges/SigningService.swift`; test `Tests/BridgesTests/FakeSigningService.swift` (shared test double).

**Interfaces:**
- Produces:
  ```swift
  public struct BridgeContext: Sendable { public let bridge: String; public let origin: String }
  public enum SigningFailure: Error, Equatable, Sendable {
      case unknownSerial(String), userDenied, userCancelled, certExpired, bad(String), card(String)
  }
  public struct SignedResult: Sendable { public let data: Data; public let certSerial: String }
  public protocol SigningService: Sendable {
      func certificates() async -> [CertInfo]
      func signXML(_ ctx: BridgeContext, serial: String?, xml: Data, options: XMLSignOptions) async throws -> SignedResult
      func signCMS(_ ctx: BridgeContext, serial: String?, content: Data, hash: HashAlg) async throws -> SignedResult
      func signRaw(_ ctx: BridgeContext, serial: String, digest: Data, hash: HashAlg) async throws -> SignedResult  // precomputed hash path → 501 stub today
  }
  ```
  `serial == nil` means "the only/first cert" (eSigner/VNPT flows without a chooser). `CTSignBridge` keeps its existing `SigningBackend` for P1 methods; it gains an optional `service` for `signxml`.
- [ ] Steps: write `FakeSigningService`, a trivial compile test; commit `feat(bridges): SigningService contract`.

---

### Task 7: CTSigningHub `signxml`

**Files:** Modify `Sources/Bridges/CTSignBridge.swift`, `Sources/Bridges/CTSignModel.swift`; test in `Tests/BridgesTests/CTSignTests.swift`.

Wire shape (**verify**): `POST /api/HubClient/signxml` body `SignXmlRequest {dataFile (base64 xml), base64Cert?, cks?, dataBV?, serinumber, requestId, filePath}` → `{status:200, message:"SUCCESS", data:"<base64 signed xml>"}`. Errors reuse the P1 table: 404 unknown serial, 403 denied, 500 other. `filePath` is **ignored and never read**; if `dataFile` is missing → `{status:500, message:"thiếu dataFile (không đọc filePath)"}`.
Adapter: `struct SignXmlRequestAdapter { static func parse(_ body: Data) -> (serial: String, xml: Data, options: XMLSignOptions)? }`. Maps `cks`/`dataBV` to nothing yet.
`// shortcut: cks/dataBV semantics (placement/signing-type) unknown — confirm against a captured eInvoice signxml call; default placement is hoaDon.`

- [ ] **Step 1:** failing tests: happy path returns base64 whose decode contains `<ds:Signature` (via `FakeSigningService` returning a canned doc); `filePath`-only body → 500 and the fake service was never called; unknown serial → 404.
- [ ] **Step 2–4:** implement + pass. **Step 5:** commit `feat(bridges): CTSigningHub signxml`.

---

### Task 8: eSigner bridge (WebSocket :8768/8769)

**Files:**
- Create: `Sources/Bridges/ESignerBridge.swift`, `Sources/Bridges/WSServer.swift`
- Modify: `Package.swift` (add `NIOWebSocket`, `NIOSSL`, `NIOFoundationCompat` to Bridges; `NIOSSL` from swift-nio-ssl **is an Apple package** and satisfies "Apple-only"), `Sources/Bridges/HTTPServer.swift` untouched
- Test: `Tests/BridgesTests/ESignerTests.swift`, `Tests/BridgesTests/WSServerTests.swift`

**Interfaces:**
- Produces:
  ```swift
  public struct ESignerBridge: Sendable {
      public init(service: any SigningService)
      public func handle(text: String, origin: String) async -> String   // JSON in, JSON out; never throws
  }
  public enum ESignerRequestAdapter {            // isolates the nested-vs-flat (verify) question
      public static func fields(from root: [String: Any]) -> [String: Any]   // returns INPUT if it is a dict, else the root itself
  }
  public final class WSServer: @unchecked Sendable {
      public init(port: Int, fallbackPort: Int?, path: String, store: OriginStore,
                  tls: NIOSSLContext?, handler: @escaping @Sendable (String, String) async -> String)   // (text, origin) -> reply
      public func start() async throws -> Int          // returns bound port
      public func stop() async
  }
  ```
  Codes implemented: `CHECK_VERSION` → `{CODE, SUCCESS:"TRUE", IS_UPDATE:"N", VERSION:"1.1.0"}`; `CER_002` → cert fields `HEX_SERIAL, CERT_SUBJECT, CERT_ISSUER, NGAY_HLUC, NGAY_HHAN, CERT_CHAIN(b64 DER), MST` (MST parsed from subject `MST=` / `UID=MST:` if present); `CER_001` (`VALUE`/`BASE64_VALUE` base64 XML, `SERIAL_NUMBER`, `DATE_SIGNING`, `TIMEZONE_SIGNING`) → `SIGNED_CONTENT` base64 signed xml, via `signXML` with `kind: .toKhai`; `NTDT_CER_001`, `ONLINE_XML_CER_001`, `ONLINE_SUBMIT_SIGNING_001` map to the same path. `PIN_CODE` in a request is **ignored** (PIN is entered only in the native sheet) and never logged. Every other code → `{CODE, SUCCESS:"FALSE", ERROR:"NOT_SUPPORTED"}` (JFU_*, IMP_*, … are P3+/out of scope). Bad JSON → `{SUCCESS:"FALSE", ERROR:"BAD_JSON"}`.
  Path: accept `/plugin/sign` (confirmed path correction in esigner.md); fallback port 8769 when 8768 is in use.
  `// shortcut: nested INPUT vs flat fields — adapter accepts both; confirm which the portal sends. CER_001 in MacSigner is "prepared-byte" (portal sends canonicalized SignedInfo as BASE64_VALUE); we implement the full-document path from esigner.md. Confirm against captured eTax traffic, then add a prepared-byte branch if needed.`

- [ ] **Step 1: Failing tests (handler, no sockets)** — nested and flat `CER_002` both return cert fields; `CER_001` returns `SIGNED_CONTENT` (fake service); unknown code → `NOT_SUPPORTED`; `PIN_CODE` present is never passed to the service (assert the fake's captured args); `filePath`/`GDT_SIGN_PATH` ignored.
- [ ] **Step 2:** FAIL → implement `ESignerBridge` → PASS.
- [ ] **Step 3: Failing socket test** — start `WSServer` on port 0-style test port with a `URLSessionWebSocketTask` client: (a) allowlisted Origin → echo handler reply; (b) Origin `https://evil.example` → handshake rejected (403, task fails); (c) `Host: evil.com` → rejected; (d) occupied primary port → binds fallback.
- [ ] **Step 4:** implement `WSServer` (`NIOHTTPServerUpgrader` + `NIOWebSocketServerUpgrader` with `shouldUpgrade` running `WebGuard.check`; frame handler collects text frames, runs `Task { handler }`, writes reply back on the loop). Bind 127.0.0.1.
- [ ] **Step 5:** commit `feat(bridges): eSigner WebSocket bridge`.

---

### Task 9: Local CA + localhost leaf

**Files:** Create `Sources/Bridges/LocalCA.swift`; test `Tests/BridgesTests/LocalCATests.swift`.

**Interfaces:**
- Produces:
  ```swift
  public struct LocalCA {
      public init(directory: URL)      // ~/Library/Application Support/TokenSigner/tls/
      public func ensure() throws -> (caCertPEM: String, leafCertPEM: String, leafKeyPEM: String)   // generates once, reuses
      public func sslContext() throws -> NIOSSLContext
      public func isTrusted() -> Bool                    // `security verify-cert -c leaf.pem -p ssl -s localhost` exit 0
      public static func trustCommand(caPath: String) -> [String]   // ["security","add-trusted-cert","-r","trustRoot","-k","<login.keychain-db>", caPath]
  }
  ```
  CA: P-256, `CN=TokenSigner Local CA`, 10 y, basicConstraints CA, keyUsage certSign. Leaf: P-256, `CN=localhost`, 1 y (< 398 d for Safari/Chrome), SAN `DNS:localhost, IP:127.0.0.1`, EKU serverAuth. Keys at 0600. **Never** read `localhost.jks`. Trust is added by the user clicking a Settings button (runs `trustCommand`; macOS prompts for password) — the app never silently trusts.
- [ ] **Step 1:** failing tests: `ensure()` twice returns identical PEMs; leaf SAN contains both names; leaf verifies against CA (`openssl verify -CAfile ca.pem leaf.pem` exit 0); key files are 0600; `sslContext()` builds.
- [ ] **Step 2–4:** implement with `swift-certificates` (`Certificate`, `P256.Signing.PrivateKey`, `Certificate.Extensions`). **Step 5:** commit `feat(bridges): local CA + localhost leaf`.

---

### Task 10: VNPT-CA Plugin bridge (WSS :4433)

**Files:** Create `Sources/Bridges/VNPTBridge.swift`; test `Tests/BridgesTests/VNPTTests.swift`.

**Interfaces:**
- Consumes: `SigningService`, `WSServer` (TLS context from Task 9, path `/plugin/`, prefix match).
- Produces:
  ```swift
  public struct VNPTBridge: Sendable {
      public init(service: any SigningService, version: String = "1.0.0.9")
      public func handle(text: String, origin: String) async -> String   // Connector JSON → {code,data,error}
  }
  public enum VNPTArgsAdapter {      // (verify) per-function args layout lives only here
      public static func signXML(args: [String]) -> (xml: Data, options: XMLSignOptions)?
      public static func signCMS(args: [String]) -> (content: Data, hash: HashAlg)?
      public static func signHash(args: [String]) -> (digest: Data, hash: HashAlg)?
  }
  ```
  Dispatch on `functionID`: 0 `GetCertInfo` → `data` = JSON string of selected cert `{serial, subject, issuer, notBefore, notAfter, cert(b64 DER)}`; 1 `SignXML` → `data` = b64 signed xml; 4 `SignCMS` → b64 detached CMS; 9 `signHash` → `code:5` + `error:"Token chỉ ký trên dữ liệu gốc"` (precomputed hash unsupported, same as CTSigningHub); 11 `getVersion`, 7 `CheckPlugin` → version string; 6 `SetLicenseKey` → accept, store nothing, `code:0` (our access control is the origin allowlist); 2 `SignPDF` → `code:1 "NOT_SUPPORTED (P3)"`; everything else → same. Codes follow the `SIGNING_RESULT` table in vnpt-plugin.md (0 success, 1 bad input, 3 failed, 4 no key, 11 user cancel, 12 internal). Response always echoes `funcCallback` as an extra field. No `filePath`/`ChooseFile`/file-system functions.
  `// shortcut: args layouts and the XmlSignatureOption/ObjData JSON field names are reconstructed from static RE (vnpt-plugin.md §3); the plugin license forbids reverse engineering the vendor binary, so confirm only against captured portal traffic.`

- [ ] **Step 1: Failing tests** — `getVersion` → `{"code":0,"data":"1.0.0.9",…}`; GetCertInfo with fake service; SignXML args `[xmlB64, "{…options json…}"]` → signed b64; SignCMS; signHash → code 5; user denial → code 11; unknown functionID → code 1; malformed JSON → code 1; `funcCallback` echoed.
- [ ] **Step 2–4:** implement → PASS. Add a WSS test: `WSServer(tls: ca.sslContext())`, client `URLSession` with a delegate pinning the generated CA (no keychain), connects `wss://127.0.0.1:4433`-style test port to `/plugin/x`, round-trips `getVersion`.
- [ ] **Step 5:** commit `feat(bridges): VNPT-CA Plugin WSS bridge`.

---

### Task 11: AppModel wiring, unknown-origin prompt, audit, status

**Files:**
- Modify: `Sources/App/AppModel.swift`, `Sources/App/MenuBarView.swift`, `Sources/App/ApprovalSheet.swift` (+ new `Sources/App/OriginPromptSheet.swift`)
- Test: build + `scripts/p2-smoke.sh` (curl + websocat-free python `-I` / `swift` client? — use `curl` for HTTP and `scripts/ws-smoke.swift` run with `swift` for WS) — manual/hardware.

Work:
1. `AppModel: SigningService`. `signXML`/`signCMS`: resolve target by serial (nil → single cert), block expired certs (`certExpired`), run the existing approval flow keyed `(origin, cert serial)` (reuse `ApprovalCenter` + approval sheet; `operation` text "Ký XML"/"Ký CMS"), build a `BrokerSigner` whose `pin` closure drives the existing PIN sheet, call `XMLDSigSigner`/`CMSSigner`, append to `AuditLog` (result `ok`/`denied`/`error:<kind>`), set `signingStatus`/`lastSignResult`. Note: XMLDSig needs one on-card signature, CMS one — a single PIN prompt each.
2. Start order: `OriginStore` + `AuditLog` in `~/Library/Application Support/TokenSigner/`; `HTTPServer` (32001), eSigner `WSServer` (8768 + 8769 fallback), VNPT `WSServer` (4433, TLS from `LocalCA`; if leaf missing/untrusted still start, show "chưa tin cậy" status). `BridgeStatus` becomes per-bridge dictionary `bridges: [String: BridgeStatus]`.
3. Unknown origin: bridges call `store.notePending`; AppModel polls `takePending()` (1s) and presents `OriginPromptSheet` (origin text, **Cho phép** primary / **Từ chối** danger). Allow → `store.add(host)`; request that was rejected stays rejected (portal retries).
4. Menu bar: bridge list rows (CTSigningHub 32001, eSigner 8768, VNPT-CA 4433) with status; "Tin cậy chứng chỉ localhost" button when `!LocalCA.isTrusted()` (runs `trustCommand`); last 10 audit entries; "Đang ký N".
5. `scripts/p2-smoke.sh`: curl signxml to :32001 with Origin `https://thuedientu.gdt.gov.vn`, and with a bad Host / bad Origin expecting 403.

- [ ] **Step 1:** write wiring; `swift build` clean. **Step 2:** `swift test` all green. **Step 3:** run app (`swift run App` or the bundled build) and `scripts/p2-smoke.sh`. **Step 4:** commit `feat(app): wire P2 bridges, approval, audit`.

---

### Task 12: Verification + hand-over

- [ ] `brew install xmlsec1` is **not** assumed; if absent, XMLDSig golden test reports skipped. Ask the user before installing; if installed, rerun `swift test` and confirm no skip.
- [ ] Hardware (user types PIN; `TOKEN_TESTS=1`): sign an XML via CTSigningHub `signxml` and a CMS via the VNPT WSS bridge on a real CMC/VNPT token; verify the XML with `xmlsec1 --verify` and the CMS with `openssl cms -verify`. Record SHA-1 token result (`SHA1_RSA_PKCS`).
- [ ] Write `docs/VERIFY-P2.md`: what was verified on hardware, what was only unit/fake-tested, and the **(verify)** list needing Parallels captures: CTSigningHub `signxml` `cks`/`dataBV` meaning and Version string; eSigner nested vs flat and CER_001 prepared-byte; VNPT `args` layouts and `Connector` extra fields (`domain`, `payload*callback` framing from macsigner-repo.md).
- [ ] Leave a hand-over note in the shared notes folder. Commit `docs: P2 verification notes`.

## Self-Review

- **Spec coverage:** XMLDSig (T3) · CMS (T2) · eSigner (T8) · VNPT WSS + local CA (T9, T10) · CTSigningHub signxml (T7) · Host/Origin/CORS/PNA + allowlist file + unknown-origin prompt (T4, T11) · session approval (reuses `ApprovalCenter`, T11) · audit.jsonl (T5, T11). PAdES / M-Invoice are P3, not here.
- **Spec deviation (flagged):** spec §6 says `Signer.sign(digestInfo:)`. These tokens cannot sign a DigestInfo (P1 finding, SignHash is a 501 stub), so the P2 abstraction is `MessageSigner.sign(message:hash:)` (raw message, token hashes on-card). Same on-card mechanism P1 uses.
- **Known limits to disclose:** PIN is asked per on-card signature (no session PIN cache); SHA-1 mech unverified on hardware until T12; `xmlsec1` not installed on this Mac at plan time (`which xmlsec1` empty), so that golden test is skipped until installed.
- **Type consistency:** `MessageSigner`, `BrokerSigner`, `XMLSignOptions`, `SigningService`, `BridgeContext`, `WSServer.handler (text, origin)` are named identically across tasks.
