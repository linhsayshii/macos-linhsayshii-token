# Minvoice và tương thích nhiều dòng token của mỗi CA

Đối chiếu source ngày 23/10/2026 theo yêu cầu sản phẩm dùng chung được chuyển
qua phiên FastCA: hỗ trợ các dòng/model/firmware phù hợp của từng hãng CA,
không giới hạn vào ATR của một chiếc đã thử.

## Kết quả đối chiếu Minvoice

- `Sources/Bridges/MinvoiceInvoices.swift` và `MinvoiceBridge.swift` không có
  allowlist ATR, USB/OEM hoặc tên FastCA/OneCA/issuer riêng cho token mẫu.
- SerialNumber từ command được dùng để chọn chứng thư và đối chiếu serial do
  API Minvoice trả về với chứng thư đã duyệt. Đây là binding động của request,
  không phải whitelist serial của mẫu nghiên cứu; giữ kiểm tra này.
- `AppModel.withMinvoiceApproval` dùng certificate picker chung, giữ target gồm
  module/token serial/cert ID, duyệt trước ký; signer gọi broker.sign với đúng
  target và xác minh signature bằng public certificate đã chọn.
- Nút thắt routing còn ở lớp chung: đường scan trong AppModel hiện gọi
  `ModuleRegistry.lookup(atr:)`. Việc mở rộng nhận diện family/capability phải
  được main xử lý ở registry/broker/provider, không vá ATR trong Minvoice.
- Profile đã chứng minh hiện là cash TDiep, XMLDSig RSA-SHA256/SHA256 với
  CKM_RSA_PKCS và DigestInfo SHA256. Token/certificate chỉ có ECC hoặc không hỗ
  trợ cơ chế RSA phù hợp chưa nằm trong profile này. Không suy issuer cùng tên
  hoặc ATR tương tự là có thể dùng cùng protocol.

## Quy tắc tích hợp

Minvoice nhận SignTarget từ picker/broker/provider chung đã xác minh tương thích
model và key/certificate. Họ ATR/USB/reader chỉ chọn ứng viên đọc metadata;
không mở rộng guard bằng wildcard rồi gửi PIN đến protocol chưa xác minh.
Trước PIN cần đảm bảo provider/backend đúng, key/certificate/CKA_ID/public key
được gắn đúng target theo contract backend. Không tự đổi target/fallback, thử
PIN/derive hoặc retry ký. Các backend có hỗ trợ RSA phù hợp được dùng cùng
pipeline XML và batch; không thêm nhánh theo tên CA trong bridge.

## Mức bằng chứng và khoảng trống

Minvoice Windows: capture thật cash1 và batch3, verify XML độc lập đạt.
Minvoice macOS: user xác nhận batch2 thành công; audit ghi Minvoice RSA_PKCS ok
lúc17:19:36 ngày23/10. Evidence đã che thông tin không gắn giao dịch này với
provider/model/firmware cụ thể, nên không dùng nó để cấp coverage cho mọi dòng
FastCA hay hãng khác. Native FastCA đọc/ký và từng biến thể ATR do phiên FastCA
báo cáo là coverage riêng của provider; cần giữ riêng với portal Minvoice.

Main nên ghi ma trận theo model/backend với các cột nhận diện/đọc metadata,
đọc chứng thư, xác thực, ký+verify, portal Minvoice và batch. Mỗi cột giữ nguồn
bằng chứng và phần chưa thử; không coi nhiều ATR trong registry là đã support
mọi token. Không thay đổi phạm vi nghiệp vụ, tự capture hoặc phát hành hóa đơn
trong đợt đối chiếu này. Không sửa source routing/transport chung.
