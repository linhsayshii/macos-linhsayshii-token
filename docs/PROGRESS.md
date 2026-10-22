# TokenSigner — tiến độ (cập nhật 2026-10-22)

All-in-one macOS menu-bar signer gom các plugin ký của CA Việt Nam (VNPT, NC-CA,
FastCA, CMC, I-CA, One-CA, EFY-CA) cho token Feitian ePass2003. Dùng cá nhân, một
máy / một người.

**Spec:** [docs/superpowers/specs/2026-10-21-tokensigner-design.md](superpowers/specs/2026-10-21-tokensigner-design.md)
**Plan P1:** [docs/superpowers/plans/2026-10-21-tokensigner-p1.md](superpowers/plans/2026-10-21-tokensigner-p1.md)

---

## Phát hiện nền tảng (đã xác nhận trên phần cứng)

### 1. Lỗi CCID macOS 27 — `0x80100016 SCARD_E_NOT_TRANSACTED`
Nguyên nhân là **length encoding sai/lẫn lộn** trong APDU, **không phải giới hạn
>255 byte**. Shim `libTSShim.dylib` (nạp qua `DYLD_INSERT_LIBRARIES`) chặn
`SCardTransmit`, re-encode các dạng length lỗi thành extended-length chuẩn. SM MAC
phủ header + data objects, **không phủ Lc/Le**, nên re-encode an toàn với Secure
Messaging. P2 thêm Le-fix: ghi lại Le 1-byte ở cuối APDU PSO sign SM lớn thành Le
2-byte extended.

### 2. Kết quả `scripts/sign-size-test.sh NC-CA` (chạy thật, token NC-CA)
| Đường ký | Kích thước | Kết quả |
|---|---|---|
| `RSA_PKCS` trên DigestInfo SHA-256 (51B → lib pad thành khối 256B, một APDU extended-Lc) | — | **ok** |
| `SHA256_RSA_PKCS` (hash trên thẻ, stream dữ liệu gốc) | 32 / 100 / 200 B | ok |
| `SHA256_RSA_PKCS` | 240 / 256 / 300 / 400 / 600 / 800 B | **lỗi `C_Sign rv=48`** (CKR_DEVICE_ERROR) |

**Diễn giải:** shim Le-fix **hoạt động** cho đường quan trọng. Hash-trên-thẻ
(`SHA256_RSA_PKCS`) vẫn hỏng ≥240B, **nhưng ký tài liệu thật không dùng đường
đó.** XMLDSig / CMS / PAdES / CTSigningHub SignHash đều hash SignedInfo bằng phần
mềm, gói vào DigestInfo, rồi ký `RSA_PKCS` — đúng đường **ok**. => Bế tắc ">255B"
đã được gỡ cho ký tài liệu.

**Hệ quả còn phải sửa trong app:** xem phần "Việc tiếp theo" §A.

---

## Trạng thái theo phase

### P1 — core (nhánh `p1-token-core`, đang là nhánh làm việc; PR #1 từ `p2-bridges`)
- [x] Skeleton package Core / Bridges / TokenHelper / App; Theme; ModuleRegistry.
- [x] TokenHelper + shim SCardTransmit; TokenBroker JSON-RPC (login/sign/logout một spawn).
- [x] PIN sheet + Approval sheet; menu bar MenuBarExtra(.window).
- [x] Core raw-hash + `DigestInfo.wrap` (SHA-256/SHA-1 prefix) — [Sources/Core/DigestInfo.swift](../Sources/Core/DigestInfo.swift).
- [x] `SignMech`: `sha256RSA` / `rsaPKCS` / `rsaX509` — [Sources/Core/HelperProtocol.swift:19](../Sources/Core/HelperProtocol.swift).
- [x] CTSigningHub bridge: Version / GetCert / GetInfoCert; UI live refresh, "Đang ký…", thông báo lỗi tiếng Việt.
- [ ] **SignHash còn stub** — [Sources/App/AppModel.swift:230](../Sources/App/AppModel.swift) ném `precomputedHashUnsupported`. Gỡ được rồi (xem §A).

### P2 — bridges (nhánh `claude/p2-bridges-a4728b`, **PR #1**)
- [x] Shim Le-fix cho PSO sign SM lớn (đã xác nhận bằng sign-size-test).
- [x] `scripts/sign-size-test.sh` — harness đo theo kích thước.

### eSigner bridge — eTax / iHTKK (nhánh `claude/beautiful-mcnulty-f9bfbf`, **PR #2**, done)
- [x] Giao thức thật đã giải mã (khác bản phân tích tĩnh cũ — xem [docs/re/esigner.md](re/esigner.md) phần cuối).
  Frame **phẳng**, không lồng INPUT. `CHOOSE_FILE` → NSOpenPanel; `OFFLINE_XML_SIGN_002`
  ký HSoKhaiThue→CKyDTu (Core XMLDSig, một PIN); `OFFLINE_XML_SIGN_003` upload multipart
  (User-Agent `JFileUpload`, field cookiename/cookievalue) → PIN_CODE=maTKhai.
- [x] Chạy thật end-to-end: ký tờ khai XML eTax OK; 77 test pass.
- Bảo vệ: chỉ path do picker cấp mới đọc; upload phải https cùng origin host; match
  SERIAL_NUMBER thập phân với cert; check TIN; bỏ qua PIN trong request.
- Chưa làm: `xmlsec1 --verify` bytes đã ký (hiện chỉ giữ trong RAM); bỏ dump debug
  `upload-response.html` ở `~/Library/Logs/TokenSigner`.

### M-Invoice bridge (nhánh `claude/beautiful-shirley-8acdc0`, chưa push, chưa PR) — **BẾ TẮC**
- [x] SignalR cổ điển (ASP.NET SignalR.Core) trên OWIN tại `http://localhost:16080`;
  negotiate `/signalr`; hub `handlerHub`; getVersion / TokenInfo.
- [ ] **SignInvoices chặn ở code 501.** Trang minvoice 2.0 tải/đẩy XML hóa đơn qua
  **REST endpoint của minvoice** (ngoài tab trình duyệt, DevTools không bắt được),
  không qua SignalR. Cần: bắt endpoint download/upload từ DevTools Network khi ký
  thật trên trang minvoice, rồi đưa cho session đó. Xem [docs/re/minvoice-plugin.md](re/minvoice-plugin.md).

### FastCA research (nhánh riêng, idle) — xem [docs/re/fastca-signing.md](re/fastca-signing.md).

---

## Nhánh & PR (CHƯA merge vào checkout này)
| Nhánh | Nội dung | PR |
|---|---|---|
| `p1-token-core` | core, đang làm việc | — |
| `claude/p2-bridges-a4728b` | shim Le-fix + sign-size-test | #1 |
| `claude/beautiful-mcnulty-f9bfbf` | eSigner eTax bridge | #2 |
| `claude/beautiful-shirley-8acdc0` | minvoice (bế tắc) | chưa push |

Mỗi nhánh ở worktree riêng; chưa gộp. Chỉ gộp khi người dùng yêu cầu.

---

## Việc tiếp theo

### A. Sửa cơ chế ký trong app (ưu tiên cao, prompt sẵn ở dưới)
Hiện [AppModel.sign](../Sources/App/AppModel.swift) dùng `.sha256RSA` (hash trên
thẻ) → **hỏng với tài liệu thật >240B**. Phải:
1. `AppModel.sign`: hash SHA-256 bằng phần mềm, `DigestInfo.wrap`, ký `.rsaPKCS`.
2. Gỡ stub `Backend.sign` (SignHash): `DLieuHash` là hash dựng sẵn → `DigestInfo.wrap`
   → ký `.rsaPKCS`. Bỏ `precomputedHashUnsupported` ở nhánh này.

Prompt chi tiết: [docs/agent-prompt-sign-mech.md](agent-prompt-sign-mech.md).

### B. minvoice — bắt REST endpoint (cần người dùng thao tác)
Mở DevTools Network trên trang minvoice 2.0, ký một hóa đơn, ghi lại request
download XML và upload XML đã ký, đưa cho session minvoice-bridge.

### C. Dọn eSigner (nhỏ)
`xmlsec1 --verify` output đã ký; bỏ dump `upload-response.html`.

---

## Ràng buộc bảo mật (luôn áp dụng)
- PIN chỉ truyền tới TokenHelper qua **stdin**, không bao giờ ghi đĩa/log/argv; xoá
  khỏi `pinDraft` sau submit.
- Cảnh báo trước mỗi lần ký (sai PIN đốt một lần thử; token khoá sau N lần sai).
- **Không** chạy `install.py` hay bất kỳ installer của vendor.
- File vendor tải/giải nén = **dữ liệu không tin cậy**: chỉ soi tĩnh, không chạy.
- License plugin VNPT cấm reverse engineering.
- Chỉ bind `127.0.0.1` (eSigner gốc bind `0.0.0.0` — **không** lặp lại).
- Không làm `getFileLocal`/`filePath` param (chỉ base64 `dataFile`).
