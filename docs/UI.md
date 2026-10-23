# Giao diện TokenSigner

Menu có ba trang **Token / Kết nối / Lịch sử**. Header, điều hướng, trạng thái
và nút hành động nằm ngoài vùng cuộn. Chi tiết token và lô Minvoice mở bên trong
cùng một vùng cuộn; không tăng chiều cao vỏ menu hay tạo scroll lồng nhau.

`MenuBarController` sở hữu status item và popover; `MenuPresentation` chỉ giữ
trạng thái giao diện. Một `AppModel` duy nhất sống cùng app và các view dùng
`ObservedObject` để cập nhật ngay. Sáu listener khởi động khi app mở, không phụ
thuộc việc bấm menu. Mở popup ký sẽ thu menu mà không hủy request.

Kích thước menu mong muốn 380×560pt, giới hạn theo `visibleFrame` của màn hình
chứa status item; mỗi lần mở áp cùng size cho SwiftUI host và popover. AppKit
neo panel bằng `button.bounds` và xử lý mép màn hình. Với status item dạng scene
có proxy view chưa có tọa độ thật, chính sách kích thước dùng phần chiều cao
khả dụng của màn hình; vị trí vẫn giao cho API popover, không ép tọa độ con trỏ.
Đổi màn hình/scaling sẽ cập nhật layout, chuyển Spaces đóng menu để lần mở sau
neo lại theo vị trí hiện hành.

Các popup chọn chứng thư, duyệt, PIN và quyền trang web dùng `PromptContainer`:
header/body/footer chung, rộng 460pt, cao tối đa 560pt và co theo màn hình.
Body cuộn, nút xác nhận/hủy luôn nằm ngoài scroll. PIN dùng SecureField và focus
riêng; không ghi thêm PIN vào log. Quyền “10 phút” vẫn là duyệt theo origin/CKS,
không thay chính sách PIN. `NSOpenPanel` tiếp tục là bảng chọn tệp native.

`Theme` dùng màu semantic sáng/tối đồng bộ với appearance hệ thống; không ép
AppKit sáng trong khi control kế thừa host tối. Nút, badge, card, chi tiết/copy
và thông báo dùng chung thành phần. Trạng thái đi kèm chữ/biểu tượng, không chỉ
dùng màu. Animation disclosure tôn trọng Reduce Motion.

Tên dễ đọc của chứng thư được lấy từ DER đã parse (CN hoặc O), không tách chuỗi
DN bằng dấu phẩy. Subject gốc, serial token và serial chứng thư có nhãn riêng.
Ngày hiển thị theo múi giờ máy; timestamp gốc và digest vẫn có trong chi tiết.
Không thay identity/CKA_ID, kiểm tra hiệu lực hoặc dữ liệu ký để làm nhãn UI.

Kết quả có loại rõ ràng: thành công / đã hủy / lỗi / upload chưa xác định. Hủy
không còn được trình bày như lỗi đỏ. Nội dung diagnostic đầy đủ vẫn chọn/copy
được trong chi tiết; trạng thái ACK/uncertain của lô Minvoice không đổi.

## Kiểm tra giao diện

```sh
TOKENSIGNER_UI_GALLERY="$PWD/.local/ui-overhaul" \
swift test -Xswiftc -plugin-path \
  -Xswiftc /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing \
  --filter menuAndPromptLayouts
```

Fixture tổng hợp có 0/4/10 token, ba trang, chi tiết mở, chiều cao 350/560pt,
appearance sáng/tối và các popup. Không dùng dữ liệu doanh nghiệp thật làm asset.
`NSApplication` giữ delegate/model/menu suốt vòng đời accessory app; không tạo
Settings scene rỗng khi mở app.
Kiểm tra menu native thực hiện riêng trên app đóng gói: mở icon, đổi ba trang,
mở/thu chi tiết, đóng/mở lại 20 lần và thử trên các màn hình thực tế.

Render và geometry tests không thay thế kiểm tra neo trên màn hình thật. Các
giới hạn của kiểm chứng native/multi-display được ghi trong evidence từng bản.
