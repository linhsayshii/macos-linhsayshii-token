# Capture ký lô Minvoice — 23/10/2026

User yêu cầu quan sát ký nhiều hóa đơn và chọn thử **3 hóa đơn cùng mẫu/ký hiệu**.
Dùng plugin Windows gốc 1.0.3.0; SHA-256 kiểm tra trước phiên:
`4e891736c97f593f4306f56ce645f039ac91aa3e54ed01d81cb7b822093331e0`.

## Phạm vi và câu hỏi

Capture có kiểm soát bằng relay HTTP loopback trên Windows; upstream HTTPS cố định
`api-hddt.minvoice.com.vn`. Chỉ đổi LinkApi của một lệnh SignInvoices do user gửi.
User tự chọn hóa đơn, bấm ký và nhập PIN; agent không tự login/ký/upload/retry.
Không thay proxy/trust store/USB/plugin. Không dùng lại nonce của capture đơn.

Cần xác định trực tiếp: số hóa đơn trong mỗi download, số XML trong ZIP; số upload,
số multipart part; tương ứng download/upload theo từng hóa đơn; profile và verify
của cả ba chữ ký; callback và kết quả UI. Static chỉ gợi ý ordinary chunk theo
setting (mặc định 2), cash chunk 100; chưa coi là quan sát runtime của lô này.
Không cố tình tạo lỗi trên hóa đơn thật để thử partial success hay rollback.

## Công cụ riêng

- `scripts/re/MinvoiceBatchCaptureRelay.cs`: dựa trên relay v3 đã dùng thành công,
  giữ bản đơn nguyên vẹn. CLI nhận thư mục mới và số hóa đơn (2–100); phiên này 3.
  Chặn login thứ hai, giới hạn upload tối đa bằng số hóa đơn; không tự retry.
  Chỉ log count/type của GUID array download/delete-cache và số dòng header
  x_req_id; không giữ giá trị GUID/header/credential. Bảo toàn request upstream.
- `scripts/re/minvoice-batch-capture-hook.js`: cần điền API/tenant/số lượng từ
  descriptor private. Kiểm tra health có cùng expected_invoice_count, đúng tenant
  và upstream, đúng số GUID không trùng, chỉ reserve một command. Nếu sai thì
  không gửi. Node tests dùng cả WS/XHR, health lỗi/sai count, GUID lỗi/trùng,
  reservation cạnh tranh, abort/restore, callback redaction và traffic khác.
- Relay self-test dùng mock upstream, không gọi backend Minvoice thật; kiểm tra
  ba upload được forward và upload thứ tư bị chặn. Raw ZIP/signed multipart ở
  thư mục ACL riêng trong guest, bản sao Mac ở .local mode 0600.

## User thao tác sau khi relay được xác nhận sẵn sàng

Reload trang Minvoice để gỡ hook cũ; dán hook **phiên batch mới** vào Console.
Chờ `armed for batch: connection verified` kèm invoice_count: 3. Chọn đúng ba
hóa đơn chờ ký cùng mẫu/ký hiệu rồi tự bấm ký lô một lần. Sau dòng `one
user-initiated batch SignInvoices command routed through loopback`, tự xử lý PIN
trong cửa sổ plugin. Báo lại kết quả UI và dòng callback nếu xuất hiện; không gửi
PIN/cookie/password/raw payload. Không tự thử ký lại khi chưa đối chiếu trạng thái.

## Trạng thái

Relay đã compile/self-test .NET x86 đạt; Node hook tests đạt. Health Windows
ready=true với expected_invoice_count=3, hết hạn UTC 2026-10-23T06:50:33Z
(13:50 ngày 23/10 tại Việt Nam). [Preparation evidence](evidence/minvoice-batch-capture-preparation.json).
Chưa có giao dịch ký lô được capture trong phiên này.


## Kết quả lúc 09:59 ngày 23/10/2026

[Evidence đã che thông tin](evidence/minvoice-live-cash-batch-success.json).
Tám request nghiệp vụ hoàn tất: login/bootstrap/detail HTTP 200, POST
`download-xml-invoice-cash` với array **3 GUID** nhận ZIP 200 (2855 byte), POST
Guid.Empty `upload-xml` nhận **204/body rỗng**. Không có failure/delete-cache.
User xác nhận UI báo thành công và cả ba hóa đơn đã đổi trạng thái.

**Ba hóa đơn không tương ứng ba XML hay ba chữ ký.** ZIP có một entry GUID.xml
(15149 byte), cấu trúc `/TDiep/DLieu/HDon` xuất hiện ba lần; `TTChung/SLuong` bằng
3. Upload multipart có một part `files`, cùng filename, type `text/xml`, XML ký
18807 byte; toàn body multipart 19008 byte. Một chữ ký tại
`/TDiep/CKSNNT/Signature` tham chiếu toàn `/TDiep/DLieu` và Object `signtime`.
Profile inclusive C14N, RSA-SHA256, digest SHA256 như capture cash đơn trước.
Sau khi bỏ riêng Signature, cây XML giữ nguyên toàn bộ dữ liệu gốc.

xmlsec1 1.3.12 trên Mac verify chữ ký và reference đạt bằng certificate công khai
nhúng trong XML. Năm bản sao offline sửa riêng dữ liệu HDon thứ 1, 2, 3,
SigningTime và SignatureValue đều bị từ chối. Không kiểm tra chain/revocation.
Raw XML/certificate/log giữ private .local, không đưa vào Git. Dùng
`scripts/re/inspect-minvoice-batch-capture.py` để lặp lại phân tích offline.

Không có callback envelope thực trong dữ liệu thu được; kết quả UI là user xác
nhận. Không suy thành công cho mọi loại lô hoặc cách xử lý lỗi từng phần.
Đặc biệt integration phải kiểm tra theo document/profile trả về; không ép số
ZIP entries bằng số invoice IDs. GUID request không được giữ, nên chưa chứng
minh mapping từng request GUID sang HDon bằng dữ liệu gốc.

Relay đã dừng lúc 10:03:39 ngày 23/10 sau khi copy/hash và kiểm tra; plugin
Windows vẫn chạy. Hook/nonce phiên này không dùng lại.
