# TokenSigner — tiến độ (cập nhật 2026-10-23)

## Tích hợp hiện tại — 23/10/2026

Minvoice cash đơn và FastCA native đã nằm trong cùng app `p1-token-core`.
Bản chung build đạt, 57 tests đạt; gói app local/ad-hoc và smoke hai cổng đạt.
Minvoice đã nối download ZIP → profile XML riêng → backend token → verify →
upload → callback. Chưa live-test Minvoice macOS + FastCA; chứng thư FastCA hiện
hết hạn 30/07/2026 nên bridge từ chối nghiệp vụ. Xem
[MINVOICE.md](MINVOICE.md) và [báo cáo tích hợp](INTEGRATION-2026-10-23.md).
Các mục theo nhánh/ngày cũ bên dưới là lịch sử; trạng thái “SignInvoices 501”
trên worktree riêng không còn mô tả checkout tích hợp này.

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

**Đường ký trong app đã sửa ở `caa25ba`:** xem phần "Việc tiếp theo" §A.

---

## Trạng thái theo phase

### P1 — core (nhánh `p1-token-core`, đang là nhánh làm việc; PR #1 từ `p2-bridges`)
- [x] Skeleton package Core / Bridges / TokenHelper / App; Theme; ModuleRegistry.
- [x] TokenHelper + shim SCardTransmit; TokenBroker JSON-RPC (login/sign/logout một spawn).
- [x] PIN sheet + Approval sheet; menu bar MenuBarExtra(.window).
- [x] Core raw-hash + `DigestInfo.wrap` (SHA-256/SHA-1 prefix) — [Sources/Core/DigestInfo.swift](../Sources/Core/DigestInfo.swift).
- [x] `SignMech`: `sha256RSA` / `rsaPKCS` / `rsaX509` — [Sources/Core/HelperProtocol.swift:19](../Sources/Core/HelperProtocol.swift).
- [x] CTSigningHub bridge: Version / GetCert / GetInfoCert; UI live refresh, "Đang ký…", thông báo lỗi tiếng Việt.
- [x] SignHash đã nối: SHA-256 dựng sẵn (base64/hex) → DigestInfo → `.rsaPKCS` (`caa25ba`).
- [x] Reader polling 175 ms, chỉ refresh helper khi reader/ATR đổi và dừng quét khi đang ký (`7609b92`). Probe PC/SC trên máy trả `SCARD_STATE_UNKNOWN` cho reader giả PnP, nên dùng phương án polling dự phòng.
- [x] Approval/PIN hiện trong NSPanel riêng, tự active khi yêu cầu ký đến dù popover đóng; đóng cửa sổ sẽ từ chối/huỷ continuation; yêu cầu đồng thời bị từ chối để không ghi đè prompt (`65fcf9e`).

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
- [x] Dọn eSigner trên nhánh riêng (`f58a51c`): `xmlsec1 --verify` trước khi chấp nhận chữ ký; thiếu công cụ thì bỏ qua có log, verify lỗi thì không upload; file tạm xoá bằng `defer`. Bỏ dump debug `upload-response.html` và trích đoạn body trong log. Đã build và 80 test đạt, chưa kiểm thử lại với cổng thuế/token thật.

### M-Invoice bridge (nhánh `claude/beautiful-shirley-8acdc0`, chưa push, chưa PR) — **BẾ TẮC**
- [x] SignalR cổ điển (ASP.NET SignalR.Core) trên OWIN tại `http://localhost:16080`;
  negotiate `/signalr`; hub `handlerHub`; getVersion / TokenInfo.
- [ ] **SignInvoices vẫn chặn ở code 501.** Trang gửi BrowserInfo/PlugCommand;
  **process plugin** tải/đẩy XML qua REST. DevTools của trang không quan sát được
  REST do process đó gửi. Đợt 2026-10-22 đã khôi phục call chain download/upload
  bằng CIL; xem [minvoice-rest-static.md](re/minvoice-rest-static.md). Còn phải
  xác minh profile XML hóa đơn, login/response và capture có kiểm soát trước khi nối ký thật.

### FastCA — đã tích hợp và ký thật trong app
- [x] Profile ATR FastCA đã test chọn backend native `FastCA-ESPK`; UI ghi “Thử nghiệm”.
  Candidate `libcastle` chỉ còn trong bằng chứng lịch sử, không dùng để routing.
- [x] Module generic chỉ nhận token có reader khớp để không ghi đè target của CA khác.
- [x] Đợt setup môi trường: kiểm tra `codesign` trên host đạt cho source/destination;
  đã provision candidate đúng hash vào module directory của app. Lỗi restricted-shell
  trước đó không tái hiện ngoài sandbox. Xem [fastca-signing.md](re/fastca-signing.md).
- [x] Đã thử đọc thật candidate arm64/x86_64: nhận slot nhưng token-info lỗi rv=5;
  lỗi nội bộ `0x30` (`CKR_DEVICE_ERROR`) khi cô lập reader FastCA. Xem
  [fastca-live-test.md](re/fastca-live-test.md).
- [x] Đã xác định gate generic module: metadata `0x6900` không khớp accepted
  `0x8600`/`0x0600`; secure messaging không lỗi. Không patch vendor/ATR/phản hồi thẻ.
- [x] Backend OpenSC/ESPK thử nghiệm đọc catalog/chứng thư, xác thực PIN và ký thật
  trên macOS. AUTH/MSE/PSO đều `9000`; RSA 256 byte đạt Security.framework và OpenSSL.
- [x] Core có parser ESPK read-only và tests bounds/duplicate/truncation, key pairing,
  RSA verification và serial routing; tổng 38 tests đạt sau tích hợp.
- [x] Backend native đã nối vào App/TokenHelper/menu bar/SignHash; registry không còn
  chọn generic candidate. User ký từ menu đạt; SignHash HTTP local tạo RSA 256 byte,
  helper/AppModel và OpenSSL đều verify đạt. Toàn bộ 38 tests đạt.
- [ ] Chưa test portal với chứng thư còn hạn hoặc nhiều FastCA/hotplug thật.
- Chi tiết/source/bằng chứng: [fastca-native-signing.md](re/fastca-native-signing.md).

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

### A. Đường ký trong app — đã hoàn tất ở `caa25ba`
[AppModel.sign](../Sources/App/AppModel.swift) hash SHA-256 bằng phần mềm, bọc
DigestInfo rồi ký `.rsaPKCS`. `Backend.sign` nhận `DLieuHash` SHA-256 đã dựng sẵn,
decode base64/hex và bọc DigestInfo mà không hash lại. Dữ liệu không hợp lệ bị từ chối.

Prompt chi tiết: [docs/agent-prompt-sign-mech.md](agent-prompt-sign-mech.md).

### B. minvoice — xác minh phần còn thiếu sau phân tích CIL
Đọc [minvoice-rest-static.md](re/minvoice-rest-static.md) trước khi capture. Endpoint
download/upload đã có căn cứ tĩnh; cần quan sát process plugin trong môi trường thử
nghiệm được cho phép để xác minh login, response và mẫu chữ ký. DevTools của trang
chỉ giúp phần SignalR. Không tự gọi API nghiệp vụ hoặc phát hành hóa đơn để nghiên cứu.

### C. Dọn eSigner — đã hoàn tất ở nhánh riêng (`f58a51c`)
Đã verify output ký bằng xmlsec1 và bỏ dump response. Chưa gộp nhánh, chưa push.

### D. Xác minh thay đổi ngày 2026-10-22
- P1: `swift build` đạt; 30 test đạt với đường dẫn Testing macro plugin trong [BUILD.md](BUILD.md).
- Cửa sổ duyệt/PIN: harness [check-prompt-window.swift](../scripts/check-prompt-window.swift) chạy trong event loop AppKit đầy đủ, xác nhận visible/key/active, đóng cửa sổ gọi huỷ, mở prompt tiếp và dismiss không gọi huỷ. Xem [VERIFY-P1.md](VERIFY-P1.md) để kiểm thử từ SignHash thật.
- eSigner: build đạt, 80 test đạt; gồm kiểm chứng chữ ký XML thật và phát hiện sửa dữ liệu, namespace/ID, thiếu binary, process lỗi, dọn file tạm và chặn upload sau ký lại thất bại.
- Chưa đo lại độ trễ cắm/rút hay ký trên token thật trong đợt này. M-Invoice có
  kết quả CIL mới và bộ tạo request ngoại tuyến trên worktree riêng; chưa nối dispatch ký.

### E. Điều tra installer / FastCA / M-Invoice ngày 2026-10-22
- `Downloads/setup.exe` được định danh là bootstrapper ClickOnce MinvoicePlug,
  không phải driver FastCA. Có REA resource Evidence lưu trong repo và kiểm tra
  chữ ký PKCS#7/digest PE ngoại tuyến; xem [setup-clickonce.md](re/setup-clickonce.md).
- FastCA: phân biệt ATR wildcard candidate với khả năng ký thật; sửa kết luận cũ
  về chữ ký dylib/Windows ARM trong báo cáo. Không cài hoặc chạy vendor artifact.
- Không trộn nhánh M-Invoice/eSigner vào checkout gốc; file prompt untracked của
  người dùng được giữ nguyên.
- Đợt setup môi trường đã chạy `scripts/test-env.sh all` trên host có đủ quyền:
  FastCA/core build đạt, **31/31 test đạt**; M-Invoice build đạt, **81/81 test đạt**.
  Lỗi 19 issues trước đó của fixture socket/Security không còn ở host executor.
  Không sửa fixture hoặc bỏ test để né lỗi môi trường. Hướng dẫn chạy lại và mở
  từng app: [TEST-ENVIRONMENT.md](TEST-ENVIRONMENT.md).

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

## 2026-10-22 — ký thật qua Windows ARM/Parallels

- [x] Windows nhận đúng USB FastCA và NC-CA qua Microsoft CCID; cả hai vendor
  PKCS#11 x86 đọc được token-info (rv=0).
- [x] User tự bấm test và nhập PIN trong CSP dialog: FastCA và NC-CA đều tạo
  chữ ký SHA-256/RSA PKCS#1 v1.5 dài 256 byte.
- [x] Verify trong Windows và verify độc lập bằng OpenSSL trên macOS đều đạt.
- FastCA certificate hết hạn 30/07/2026; NC-CA còn hạn đến 17/03/2029.
  Không kiểm tra portal hoặc chain/revocation. Lỗi catalog middleware FastCA
  native macOS vẫn còn; kết quả Windows không thay thế phép đo đó.
- Bằng chứng/source test: [windows-signing-test.md](re/windows-signing-test.md),
  [windows-signing-validation.json](re/evidence/windows-signing-validation.json).

## 2026-10-22 — FastCA ký thật trực tiếp trên macOS

- [x] User tự nhập PIN trong cửa sổ native; đúng một authentication trong lượt ký,
  không tự retry. Ký fixed test message, không gọi nghiệp vụ/portal.
- [x] Chữ ký RSA 2048/SHA-256 PKCS#1 v1.5 được verify độc lập bằng OpenSSL `Verified OK`.
- [x] Source snapshot, public key, chữ ký và REA records lưu trong
  [native report](re/fastca-native-signing.md); không lưu PIN/derived key/private key.
- Backend native sau đó đã tích hợp và test thành công qua menu + SignHash trong
  App. Generic candidate đã được bỏ khỏi routing FastCA; xem [FASTCA.md](FASTCA.md).
