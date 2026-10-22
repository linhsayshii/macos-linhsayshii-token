# Đối chiếu và hợp nhất các nhánh — 23/10/2026

Tất cả nhánh làm việc đã là tổ tiên của `p1-token-core`, gồm:

| Nhánh/tip | Cách tiếp nhận |
| --- | --- |
| `master` / `7f11ad1` | Nền tảng, đã nằm trong lịch sử |
| `claude/p2-bridges-a4728b` / `bbdb7d2` | Nằm trong nhánh eSigner; giữ bridge/core, shim, CORS, TLS, audit và tài liệu xác minh |
| `claude/beautiful-mcnulty-f9bfbf` / `f58a51c` | Merge `3a4dcd4`; cập nhật vào AppModel hiện tại |
| `claude/beautiful-shirley-8acdc0` / `b472572` | Merge `e63c9fd`; giữ Minvoice cash/transport mới hơn |

Không dùng chiến lược lấy toàn bộ AppModel cũ: việc đó sẽ mất Minvoice cash,
FastCA native, kiểm tra chữ ký, popup chooser, cancellation và NC-CA Le-fix.
Các file chung đã được đối chiếu chức năng và giữ implementation mới hơn.

## Những phần bị sót đã tiếp nhận

- VNPT WSS 4433 + 4434, callback `<payload>*<callback>`, GetCertInfo và CMS DVC.
  Chọn CKS qua popup chung; không tự dùng chứng thư đầu tiên.
- Local CA/leaf TLS, kiểm tra trust và nút user chủ động tin cậy trong menu;
  trust command được giới hạn SSL/localhost ở login keychain. Không fallback
  plaintext nếu tạo TLS thất bại, không nhập hay lưu mật khẩu Keychain.
- CMS attached: nhánh cũ trả detached cho cả `type=cms`. Bản chung tạo đúng
  eContent; OpenSSL kiểm tra độc lập cả detached và attached.
- Shared OriginStore trên HTTP/WS/Minvoice, UI cho phép/từ chối/gỡ origin,
  preflight echo header hợp lệ thay vì cố định Content-Type.
- Audit digest-only và menu lịch sử ký; port offset dev; service catalog sáu
  listener; dependency lock và launcher chung thay các launcher theo worktree.
- Giữ các test/verify scripts P2 còn hữu ích. `MinvoiceTests.swift` cũ được thay
  bởi MinvoiceTransportTests và cash integration fixtures; không khôi phục test
  khẳng định mọi SignInvoices trả 501. Không phục hồi debug dump/frame log.
- Không phục hồi command chaining thất bại hoặc hash dài trên thẻ. SHA-1 phục vụ
  protocol cũ vẫn host-hash rồi RSA_PKCS; không cần cơ chế SHA1_RSA_PKCS chẩn đoán.

## Dọn và giữ bằng chứng

Nguồn chạy và hướng dẫn hiện tại trỏ checkout gốc. PROGRESS/BUILD/TEST-ENVIRONMENT
đã cập nhật; bản tiến độ và hướng dẫn cũ được giữ trong `docs/archive/`.
Ghi chú nghiên cứu đang sửa được snapshot tại `.local/branch-consolidation/`
trước merge và khôi phục sau đó; không reset hoặc xóa raw capture.
Worktree cũ được giữ để bảo toàn bằng chứng/công việc nghiên cứu và cache riêng;
không còn được launcher chính dùng. Không xóa nhánh hoặc push remote trong đợt này.

## Phạm vi chưa làm xong, không phải nhánh bị sót

- Minvoice: HDon/BKe thường, batch/partial failure/idempotency và các command
  ngoài cash đơn chưa có profile/fixture thật để hỗ trợ an toàn.
- eSigner: các command ngoài luồng eTax đã xác minh; PDF, Office, native messaging
  và browser extension chưa triển khai.
- VNPT: `checkPluginAdvanced` cần signed challenge của hãng; PDF/Office/file APIs
  không hỗ trợ. Một số schema XML/CMS/hash ngoài DVC còn cần capture portal.
- FastCA chỉ profile ESPK đã xác minh; One-CA/EFY và các ATR khác chưa hỗ trợ đầy
  đủ. Middleware các CA khác vẫn phải có sẵn; không đóng gói installer vendor.
- Certificate chain/revocation, runtime distribution/notarization và live portal
  regression sau merge còn cần kiểm thử riêng. FastCA cert hiện có đã hết hạn.
- Git remote chưa được push/đổi default branch. Dùng `p1-token-core` local làm
  nguồn hiện tại; origin/HEAD lịch sử có thể còn trỏ P2.

Validation cuối đợt được ghi ở
[branch-consolidation-validation-2026-10-23.json](re/evidence/branch-consolidation-validation-2026-10-23.json).
