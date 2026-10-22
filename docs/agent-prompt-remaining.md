> Lưu lịch sử: các hướng dẫn chia nhánh và blocker Minvoice dưới đây đã được thay thế bởi [PROGRESS.md](PROGRESS.md) và [BRANCH-CONSOLIDATION.md](BRANCH-CONSOLIDATION.md). Không dùng tài liệu này để checkout bản app cũ.

# Agent prompt — việc còn lại của TokenSigner

Danh sách việc còn lại sau khi cơ chế ký đã sửa (commit `caa25ba` trên
`p1-token-core`: host-hash SHA-256 + RSA_PKCS trên DigestInfo, gỡ stub SignHash).
Mỗi việc độc lập và **nằm trên nhánh khác nhau** — đọc kỹ nhánh của từng việc. Giao
cho agent cả khối, hoặc cắt từng việc một.

Bối cảnh nền tảng (đừng nghi ngờ lại): [docs/PROGRESS.md](PROGRESS.md). Build bằng
`swift build`. Về `swift test`: toolchain CommandLineTools ở máy này thiếu plugin
macro swift-testing (`error: external macro implementation type
'TestingMacros.TestDeclarationMacro' could not be found`). Nếu gặp lỗi đó, đó là
vấn đề toolchain chứ không phải code — báo rõ test không chạy được, cần Xcode full,
đừng sửa test để né lỗi macro.

---

## Việc 1 — tối ưu tốc độ nhận token (nhánh `p1-token-core`)

**Hiện trạng:** vòng quét ở [Sources/App/AppModel.swift:75-78](../Sources/App/AppModel.swift)
chạy `scanTick()` rồi `Task.sleep(for: .milliseconds(500))`. `scanTick` liệt kê
reader (PC/SC rẻ) và chỉ full-refresh khi tập reader đổi. Nghĩa là cắm token mất
tới ~500ms mới hiện, và vẫn là polling tốn CPU nền.

**Mục tiêu:** phát hiện cắm/rút token gần như tức thì, ít polling hơn.

- Cách tốt nhất: dùng `SCardGetStatusChange` **chặn** (blocking) với reader giả
  `\\?PnP?\Notification` để chờ sự kiện plug/unplug thay cho poll 500ms. Khi
  `SCardGetStatusChange` trả về (có thay đổi hoặc hết timeout), gọi `scanTick()`.
  Đặt timeout vừa phải (ví dụ 10s) để vẫn thoát vòng sạch khi `scanTask` bị huỷ.
  Tìm wrapper PC/SC hiện có: `grep -rn "SCardGetStatusChange\|SCardEstablishContext\|SCardListReaders\|scanner.readers" Sources`.
- Nếu `SCardGetStatusChange` khó bọc an toàn trong Swift concurrency, phương án
  tối thiểu: giảm `sleep` xuống ~150-200ms. Giữ nguyên tối ưu "chỉ full-refresh khi
  reader-set đổi" ([AppModel.swift:88-96](../Sources/App/AppModel.swift)) — đừng
  full-refresh mỗi tick (full-refresh spawn helper, đắt và giữ vendor lock).
- Giữ guard `if signing { return }` — đang ký thì giữ vendor lock, không quét.

## Việc 2 — cửa sổ tự bật khi có yêu cầu ký (nhánh `p1-token-core`)

**Hiện trạng:** approval sheet và PIN sheet gắn bằng `.sheet` trên `MenuBarView`
([Sources/App/MenuBarView.swift:30-31](../Sources/App/MenuBarView.swift)). Sheet
chỉ hiện khi popover `MenuBarExtra(.window)` đang mở. Khi trình duyệt gửi yêu cầu
ký (`POST /api/HubClient/SignHash` tới cổng 32001, hoặc bridge eSigner) lúc popover
đóng, `approvalPrompt`/`pinPrompt` được set nhưng **không có cửa sổ nào host sheet**
→ người dùng không thấy gì, yêu cầu treo.

**Mục tiêu:** khi `approvalPrompt` hoặc `pinPrompt` chuyển sang non-nil do một yêu
cầu ký đến, app phải tự đưa một cửa sổ có chứa sheet đó ra trước và active, không
cần người dùng bấm icon menu bar.

- `MenuBarExtra(.window)` **không có API công khai** để mở popover bằng code. Vì
  vậy đừng cố mở popover; thay vào đó present approval/PIN trong một **cửa sổ
  riêng** mà app điều khiển được.
- Cách làm gợi ý: khi cần hỏi (trong `signPreparedBlock` trước `withCheckedContinuation`,
  [AppModel.swift:174-177](../Sources/App/AppModel.swift)), mở một window SwiftUI
  riêng (`Window`/`WindowGroup` có `id`, dùng `@Environment(\.openWindow)`), hoặc
  một `NSWindow`/`NSPanel` qua một AppDelegate nhỏ, rồi
  `NSApplication.shared.activate(ignoringOtherApps: true)` và
  `window.makeKeyAndOrderFront(nil)` / `orderFrontRegardless()` để đưa ra trước.
  Đóng cửa sổ đó khi `submitApproval` / `submitPIN` xong (prompt về nil).
- Giữ nguyên luồng continuation hiện có (`approvalCont`, và cơ chế PIN tương ứng) —
  chỉ thêm phần hiện cửa sổ + active, không đổi logic hỏi/đáp.
- Không auto-ký. Cửa sổ bật ra để người dùng **thấy và tự duyệt**; cảnh báo trước
  mỗi lần ký giữ nguyên (sai PIN đốt một lần thử; token khoá sau N lần sai).

## Việc 3 — dọn bridge eSigner (nhánh `claude/beautiful-mcnulty-f9bfbf`, PR #2)

Giao thức eSigner (eTax/iHTKK) đã chạy end-to-end. Chi tiết:
[docs/re/esigner.md](re/esigner.md) phần "## RESOLVED" cuối file. Hai việc dọn nhỏ,
đừng đổi hành vi giao thức:

1. **Bỏ dump debug `upload-response.html`.** Luồng upload `OFFLINE_XML_SIGN_003`
   ghi body phản hồi ra `~/Library/Logs/TokenSigner/upload-response.html`. Tìm:
   `grep -rn "upload-response.html\|Library/Logs/TokenSigner" Sources`. Xoá phần
   ghi file; nếu cần biết upload thành/bại thì kiểm tra status/nội dung **trong bộ
   nhớ**, không ghi đĩa. Nếu không còn ai dùng thư mục Logs đó, bỏ luôn code tạo nó.
2. **`xmlsec1 --verify` chữ ký XML trước khi coi là thành công.** Chỗ ký nằm ở
   `OFFLINE_XML_SIGN_002` (ký `HSoKhaiThue` → `CKyDTu`). Tìm:
   `grep -rn "OFFLINE_XML_SIGN_002\|CKyDTu\|SignedInfo" Sources`. Sau khi dựng XML
   đã ký, trước khi upload, verify bằng `xmlsec1`:
   - Ghi bytes ra file tạm trong `FileManager.default.temporaryDirectory` (KHÔNG
     ghi vào Logs), xoá ngay sau verify bằng `defer`.
   - Gọi `xmlsec1 --verify` qua `Process`, đường dẫn tuyệt đối.
   - `xmlsec1` có thể **không cài**: nếu không tìm thấy binary thì **bỏ qua verify
     lặng lẽ** (log một dòng, vẫn coi là thành công) — đừng làm luồng ký fail vì
     thiếu công cụ tuỳ chọn. Binary có mà verify fail → coi là lỗi ký, không upload,
     báo lỗi tiếng Việt rõ ràng.

## Việc 4 — minvoice: nối REST endpoint (nhánh `claude/beautiful-shirley-8acdc0`) — CẦN NGƯỜI DÙNG TRƯỚC

**Bế tắc hiện tại:** SignalR cổ điển (ASP.NET SignalR.Core trên OWIN,
`http://localhost:16080`, hub `handlerHub`) đã dựng; getVersion/TokenInfo chạy.
Nhưng `SignInvoices` chặn ở code 501 vì trang minvoice 2.0 tải/đẩy XML hóa đơn qua
**REST endpoint của minvoice** (ngoài tab trình duyệt, DevTools Network không bắt
được từ page). Chi tiết: [docs/re/minvoice-plugin.md](re/minvoice-plugin.md).

**Chặn cứng:** không làm tiếp được cho tới khi có người dùng mở DevTools Network
trên trang minvoice 2.0, ký một hóa đơn thật, và ghi lại:
- request **download** XML hóa đơn chưa ký (URL, method, header, body),
- request **upload** XML đã ký (URL, method, header, body, content-type).

Khi có hai request đó, agent nối chúng vào luồng ký của bridge minvoice: download →
hash SignedInfo bằng phần mềm → ký `.rsaPKCS` (cùng cơ chế đã sửa ở `caa25ba`) →
upload. **Đừng đoán endpoint** — chờ capture thật.

---

## Ràng buộc bảo mật (bắt buộc cho mọi việc)
- PIN chỉ truyền tới TokenHelper qua **stdin**, không bao giờ ghi đĩa/log/argv; xoá
  khỏi `pinDraft` sau submit. File tạm (ví dụ để `xmlsec1` verify) chỉ chứa dữ liệu
  đã ký công khai, **không** chứa PIN, xoá ngay sau dùng.
- Cảnh báo trước mỗi lần ký; không auto-ký ở bất kỳ việc nào.
- Chỉ bind `127.0.0.1`. Không chạy installer vendor; không chạy file vendor tải về
  (coi là dữ liệu không tin cậy, chỉ soi tĩnh).
- Không làm `getFileLocal`/`filePath` param (chỉ base64 `dataFile`).
- License plugin VNPT cấm reverse engineering.

## Commit / PR (cho mọi việc)
- Commit message kết thúc bằng:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`
- PR description kết thúc bằng:
  `🤖 Generated with [Claude Code](https://claude.com/claude-code)`
