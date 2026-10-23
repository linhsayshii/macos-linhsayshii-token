# Tích hợp Minvoice và FastCA — 23/10/2026

Hai tuyến đã nằm trong cùng checkout/app `main`. FastCA được tiếp quản
thành commit `4a4da78`, giữ native ESPK/OpenSC 0.27.1 và chọn khóa theo catalog/
CKA_ID/public key. Minvoice đã nối từ SignalR đến REST, signer cash riêng, token
backend, verify-before-upload và callback, với phạm vi một hóa đơn cash mỗi lần.
Chi tiết: [MINVOICE.md](MINVOICE.md), [FASTCA.md](FASTCA.md).

Validation của **bản chung**:

- Build toàn app/helper thành công qua SwiftPM test build; 57 tests đạt
  (3 TSShim, 24 Core, 30 Bridges), không cần token/PIN/Windows.
- Chữ ký XML mới được xmlsec1 kiểm chứng độc lập; fixture bị sửa bị từ chối.
- Gói app ad-hoc tạo thành công, `codesign --verify --strict` đạt. Runtime
  OpenSC 0.27.1 được kiểm tra trên máy; không bundle hoặc cài runtime mới.
- Smoke chạy gói app: CTSigningHub HTTP 200; Minvoice negotiate protocol 2.1,
  getVersion 2.0.0, origin ngoài allowlist HTTP 403. Script đóng đúng process nó
  mở sau test, không tự ký, đăng nhập hay gọi REST nghiệp vụ.
- [Validation record](re/evidence/integration-validation-2026-10-23.json) chỉ giữ
  hash/count/status, không có credential hay XML hóa đơn thật.

Phân biệt kết quả đã có trước bàn giao với đợt này: FastCA từng ký thật trên
macOS qua menu và SignHash, OpenSSL Verified OK; Minvoice Windows từng ký cash
và XML verify đạt. Hai kết quả đó chưa chứng minh phép thử chung Minvoice macOS
với FastCA. FastCA certificate hiện hết hạn 30/07/2026; không bypass hiệu lực
chứng thư để thử hóa đơn. Chưa xác nhận live portal/chain/revocation, HDon/BKe,
batch/partial result/idempotency, mọi ATR FastCA, hay distribution/notarization.

Thay đổi nghiên cứu chưa thuộc phần source tích hợp vẫn được giữ trong working
tree; không reset/ghi đè, không stage toàn bộ evidence hoặc raw capture. Không
merge nhánh eSigner/P2 hoặc push lên remote trong đợt này.
