# Agent prompt — sửa cơ chế ký của app sang host-hash + RSA_PKCS

Copy nguyên khối dưới đây cho agent khác. Agent làm trong checkout `p1-token-core`
(hoặc nhánh của nó), build bằng `swift build`.

---

## Bối cảnh (đã xác nhận trên phần cứng, đừng nghi ngờ lại)

App TokenSigner ký tài liệu qua token Feitian ePass2003 trên macOS 27. Test thật
(`scripts/sign-size-test.sh`) đã chứng minh:

- Hash **trên thẻ** (`SHA256_RSA_PKCS`, stream dữ liệu gốc lên thẻ) **hỏng với dữ
  liệu ≥240 byte** (`C_Sign rv=48` = CKR_DEVICE_ERROR). Đây là đường app **đang**
  dùng và nó hỏng với mọi tài liệu thật.
- Hash **bằng phần mềm** rồi ký `RSA_PKCS` trên một **DigestInfo SHA-256** (51B →
  thẻ pad PKCS#1 v1.5 thành khối 256B, gửi một APDU extended-Lc) **chạy OK**.
- Ký tài liệu thật (XMLDSig, CMS, PAdES, CTSigningHub SignHash) luôn hash
  SignedInfo bằng phần mềm và ký RSA_PKCS trên DigestInfo — tức đúng đường OK.

Nên phải chuyển app từ `.sha256RSA` sang hash-phần-mềm + `.rsaPKCS`.

## Có sẵn để dùng (đừng tạo trùng)

- `Sources/Core/DigestInfo.swift`: `DigestInfo.wrap(_ digest: [UInt8], _ alg: HashAlg) throws -> [UInt8]`.
  `HashAlg.sha256` yêu cầu digest đúng 32 byte, trả về `sha256Prefix + digest`.
- `Sources/Core/HelperProtocol.swift:19` — `SignMech.rsaPKCS` = `"RSA_PKCS"`
  ("sign a caller-built DigestInfo, PKCS#1 v1.5 pad on-card"). Đây là mech cần dùng.
- `TokenBroker.sign(module:serial:certId:mech:dataB64:pin:) async throws -> String`
  trả về chữ ký base64. `dataB64` là **khối sẽ ký** đã base64 (với `.rsaPKCS` =
  DigestInfo đã base64).
- SHA-256 phần mềm: `import Crypto` (swift-crypto, đã kéo gián tiếp qua X509) hoặc
  `import CryptoKit`; dùng `SHA256.hash(data:)`. Chọn cái build được, kiểm bằng
  `swift build`.

## Việc 1 — `AppModel.sign` (Sources/App/AppModel.swift, dòng ~157–181)

Hiện tại dòng 179–180:
```swift
return try await broker.sign(module: target.module, serial: serial, certId: target.cert.id,
                             mech: .sha256RSA, dataB64: dataB64, pin: pin)
```
`dataB64` là **dữ liệu gốc** (raw message). Đổi thành: giải base64 `dataB64` ra
bytes, hash SHA-256 bằng phần mềm (32 byte), `DigestInfo.wrap(_, .sha256)`, base64
lại, rồi ký với `mech: .rsaPKCS`. Ví dụ:
```swift
guard let raw = Data(base64Encoded: dataB64) else { throw TokenBroker.SignError.card("dữ liệu ký không hợp lệ") }
let digest = Array(SHA256.hash(data: raw))                 // 32 byte
let block = try DigestInfo.wrap(digest, .sha256)           // prefix + digest
return try await broker.sign(module: target.module, serial: serial, certId: target.cert.id,
                             mech: .rsaPKCS, dataB64: Data(block).base64EncodedString(), pin: pin)
```
Sửa luôn comment dòng 156 ("the token hashes it on-card (SHA256withRSA)") cho đúng
thực tế mới (hash phần mềm, ký RSA_PKCS trên DigestInfo).

## Việc 2 — gỡ stub `Backend.sign` (Sources/App/AppModel.swift, dòng ~227–235)

Hiện tại ném `CTSignError.precomputedHashUnsupported`. `digestB64` là hash **dựng
sẵn** CTSigningHub gửi (trường `DLieuHash` của SignHash — SHA-256 của SignedInfo,
base64). Giải base64 ra 32 byte, `DigestInfo.wrap`, base64, ký `.rsaPKCS`:
```swift
func sign(serial: String, digestB64: String) async throws -> String {
    guard let digest = Data(base64Encoded: digestB64), digest.count == 32 else {
        throw CTSignError.precomputedHashUnsupported   // chỉ nhận SHA-256 32 byte
    }
    let block = try DigestInfo.wrap(Array(digest), .sha256)
    // dùng đúng đường approval/PIN như AppModel.sign — gọi model.sign(...) với block đã bọc,
    // KHÔNG hash lại. Nếu AppModel.sign luôn tự hash, tách một nhánh nhận sẵn DigestInfo
    // (ví dụ tham số preHashed/alreadyDigestInfo) để tránh hash hai lần.
}
```
Lưu ý: `digestB64` đã là hash, **không hash lại**. Nếu Việc 1 làm `AppModel.sign`
luôn tự hash dữ liệu gốc, thì SignHash cần đường riêng đi thẳng tới
`broker.sign(mech: .rsaPKCS, dataB64: <DigestInfo base64>)` qua cùng cơ chế
approval + PIN prompt (đừng nhân đôi logic — refactor phần spawn login/sign/logout
dùng chung). Cập nhật comment struct `Backend` (dòng ~224–226) cho khớp.
Nếu `DLieuHash` hóa ra là **hex** chứ không phải base64, parse hex thay vì base64 —
kiểm bằng độ dài chuỗi (64 hex vs ~44 base64) rồi quyết.

## Kiểm tra
- `swift build` sạch.
- Chạy test suite nếu có (`swift test`).
- Nếu cắm được token: ký thử từ menu (nút "Ký thử") phải OK; và nếu dựng được một
  tài liệu >240B để ký, xác nhận không còn `C_Sign rv=48`.
- Báo rõ cái gì đã verify trên phần cứng, cái gì chưa.

## Ràng buộc bảo mật (bắt buộc)
- PIN chỉ qua stdin tới TokenHelper, không ghi đĩa/log/argv; xoá `pinDraft` sau submit.
- Giữ nguyên cảnh báo trước khi ký (sai PIN đốt một lần thử; khoá sau N lần).
- Không chạy installer vendor; không chạy file vendor tải về.
- Chỉ bind 127.0.0.1.

## Commit / PR
- Commit message kết thúc bằng:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`
- PR description kết thúc bằng:
  `🤖 Generated with [Claude Code](https://claude.com/claude-code)`
