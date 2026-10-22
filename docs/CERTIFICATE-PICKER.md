# Popup tự bật và chọn chữ ký số

App khởi động bridge và scanner từ `TokenSignerApp.init`, độc lập với việc mở
menu bar. Yêu cầu ký CTSign hoặc Minvoice mở `NSPanel` riêng: kích hoạt app,
đưa cửa sổ ra trước và nhận bàn phím. Không cần bấm biểu tượng menu bar trước.

Luồng ký: **Chọn CKS → Duyệt yêu cầu → Nhập PIN → Ký/xác minh**. Picker hiển thị
origin, thao tác, CA, chủ thể, serial token, serial CKS và hạn dùng. Người dùng
chọn hàng và bấm Tiếp tục, kể cả khi chỉ có một CKS. Trong menu có thêm
“Chọn CKS và ký thử…” để thử luồng lựa chọn với tất cả token.

Đây là cửa sổ native của TokenSigner; không dùng Windows Hello, passkey hoặc
Touch ID để thay PIN USB token. Quyền duyệt 10 phút hiện có chỉ bỏ qua bước duyệt
cho đúng origin/serial đã cấp; picker và PIN vẫn cần thao tác của người dùng.

## Quy tắc lựa chọn

- Serial CKS từ trang được đối chiếu không phân biệt hoa/thường. Các CKS khác vẫn
  hiển thị nhưng không chọn được. Nút Ký thử riêng từng token ràng buộc token đó.
- Hai token chứa cùng chứng thư có hàng riêng, định danh bằng physical serial,
  module/backend, CKA_ID và DER. Hai hàng không thể phân biệt an toàn bị khóa.
- Kiểm tra hiệu lực từ DER; CKS lỗi định dạng hoặc token khóa PIN không chọn được.
  Minvoice ký hóa đơn yêu cầu CKS còn hiệu lực. Đọc thông tin và ký thử/SignHash
  chẩn đoán vẫn hiển thị cảnh báo CKS hết hạn theo hành vi sẵn có.
- Khi chưa cắm token, popup chờ và tự cập nhật danh sách. Rút token xóa lựa chọn
  bị ảnh hưởng; xác nhận kiểm tra lại inventory hiện tại. Không tự chọn token khác.
- Chỉ quét khi đang chọn CKS, chưa đăng nhập token. Nút Tiếp tục bị khóa trong lúc
  helper đang đọc inventory để tránh chồng tác vụ PC/SC. Từ bước duyệt/PIN trở đi,
  scanner dừng đến khi request kết thúc.
- Một request giữ cửa sổ tại một thời điểm. Request mới nhận busy, không chiếm
  cửa sổ hoặc continuation cũ. Huỷ task/đóng cửa sổ/Escape giải phóng prompt và
  tiếp tục theo nhánh huỷ. PIN draft được xóa khi gửi/huỷ, chỉ truyền helper qua stdin.

TokenInfo Minvoice chỉ chọn/đọc thông tin, không hỏi PIN hoặc ký dummy. Lựa chọn
được nhớ riêng theo origin trong bộ nhớ; khi không còn phù hợp sẽ hỏi lại. Lệnh
SignInvoices có thể không gửi SerialNumber; nếu có, serial đó luôn được giữ.

## Kiểm tra

`Tests/AppTests/CertificatePickerTests.swift` kiểm tra tự present khi model nhận
request mà không start/mở menu, chuỗi picker/approval/PIN, hủy, busy, hotplug,
serial cố định, trùng serial trên hai USB, DER hết hạn/khóa PIN, Minvoice TokenInfo
và chặn nghiệp vụ trước approval. Không gửi PIN thật hoặc gọi helper ký thật.

```sh
swift test -Xswiftc -plugin-path -Xswiftc /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing
swiftc -parse-as-library Sources/App/SigningPromptWindow.swift scripts/check-prompt-window.swift -o /tmp/tokensigner-window-check
/tmp/tokensigner-window-check
# Tùy chọn: hiện cửa sổ picker với dữ liệu giả và lưu ảnh; không dùng token thật.
TOKENSIGNER_PICKER_SNAPSHOT=/tmp/tokensigner-picker.png swift test --skip-build --filter nativeCertificatePickerRendersWithMultipleTokens
```

Runtime harness chạy AppKit event loop thật, xác nhận visible/key/app active,
đóng cửa sổ trả nhánh huỷ và mở được bước tiếp theo. Kiểm tra UI và fixture không
thay thế việc người dùng thử ký trên portal với chứng thư còn hiệu lực.

Validation 23/10/2026: 66 tests đạt (3 shim, 24 Core, 30 Bridges, 9 App), kiểm tra
render native nhiều token đạt; harness visible/key/active và đóng/mở prompt đạt.
Gói app ad-hoc qua codesign strict và smoke CTSign/Minvoice/403. Yêu cầu HTTP
SignHash giả tới gói app mới tự bật picker trước khi mở menu bar; bấm Huỷ trả
“Đã huỷ yêu cầu ký”. Không gửi PIN hay gọi REST nghiệp vụ/upload. Chi tiết trong
[evidence](re/evidence/certificate-picker-validation-2026-10-23.json).
