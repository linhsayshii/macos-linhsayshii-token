# Kế hoạch tích hợp Minvoice ký khoảng 300 hóa đơn/lần

Đã triển khai và qua 151 tests, đóng gói app thử: [evidence](../re/evidence/minvoice-bulk-integration-2026-10-23.json). Chưa ký live300.

Ngày 23/10/2026. User giao triển khai trong luồng chính. Mục tiêu: nhận một lệnh
SignInvoices với số lượng thay đổi, phục vụ nhu cầu khoảng 300 hóa đơn/lần trong
app hiện có, dùng backend ký/certificate/FastCA hiện có.

Căn cứ: [nghiên cứu tổng quát](../re/minvoice-bulk-signing.md),
[capture cash batch thật](../re/minvoice-batch-live-capture.md),
[CIL và mô hình](../re/evidence/minvoice-bulk-control-flow.json).
Hiện app vẫn guard count==1 và ZIP reader một entry. Runtime đã xác nhận cash
1/3 hóa đơn; chia nhóm 100 dựa trên đúng code Windows 1.0.3.0. Chưa có live300.

## Phạm vi bàn giao

Ưu tiên hoàn thành **cash TDiep cùng mẫu/ký hiệu**, với n thay đổi và ít nhất
300 được kiểm thử. 300 cash → ba nhóm 100; 301 → 100+100+100+1. Không hardcode
số lượng bằng 3 hay 300. Ordinary dùng chunk setting và profile riêng; không bật
nhánh đó bằng cash signer khi chưa đủ fixture/verification. Tách rõ giới hạn
command/ZIP/XML/tổng bộ nhớ của app khỏi giới hạn nhóm 100 của Windows plugin.

Không cần thử phát hành 300 hóa đơn thật để bắt đầu hoặc để hoàn thành kiểm thử
offline; bản app phải được triển khai, kiểm thử và bàn giao trước. Live300 khi
user có lô thực sự cần ký là bước xác nhận runtime bổ sung, không giả lập thành
đã thử thật.

## Thứ tự triển khai

### 1. Mô hình batch và hợp đồng đầu vào

- Giữ API/signing backend hiện có, thêm batch request/plan/result và group state.
  Validate danh sách không rỗng, không trùng, số lượng/body trong giới hạn tài
  nguyên đã ghi rõ, API origin/certificate/session theo allowlist hiện có.
- Mỗi group giữ index, requested invoice count, document count, trạng thái.
  Bộ đếm invoice và document tách biệt; metadata invoice IDs chỉ ở bộ nhớ hoặc
  nơi bảo vệ phù hợp, không đưa vào log thường.
- Chọn cash bằng metadata như contract; không giả định detail đầu tiên chứng
  minh cả lô cùng serial. Quyết định kiểm tra đồng nhất cần được ghi rõ và test;
  không tự gom lẫn cash/ordinary hoặc nhiều mẫu trong một group.

### 2. ZIP nhiều XML và kiểm tra profile

- Mở rộng `Sources/Bridges/MinvoiceZIP.swift` trả danh sách entries, không ghi
  đường dẫn từ ZIP xuống filesystem. Giữ kiểm tra CRC/framing và giới hạn tổng
  giải nén, từng file, số entries, kích thước archive; chặn path traversal,
  duplicate entry ID, encryption/format chưa hỗ trợ và archive rỗng.
- Một XML TDiep có thể chứa nhiều HDon; số entries không bằng invoice count.
  Không ép tập ZIP GUID trùng requested GUID; mapping semantic chưa được capture
  đủ. Kiểm tra identity/profile/count theo bằng chứng có thật, ghi rõ giới hạn.
- Ký từng document bằng profile MinvoiceCashXML hiện có rồi verify serialized
  XML với certificate đã duyệt. Chỉ upload sau khi **mọi document của group**
  ký/verify đạt. Không sao chép lỗi Windows nuốt sign error rồi upload.

### 3. Executor tuần tự và phiên ký

- Mở rộng `Sources/Bridges/MinvoiceInvoices.swift`: bỏ guard một invoice, lập
  lịch cash theo nhóm tối đa100, giữ thứ tự IDs. Với300 phải có ba download
  body mỗi body100 IDs; group trước kết thúc upload rồi mới download group sau.
- Một approval cho toàn batch/certificate/origin cụ thể, một signing lock cho
  phiên và auth/bootstrap một lần. Dùng backend/helper/FastCA đã tích hợp;
  không hỏi approval/PIN cho từng invoice một cách không cần thiết, không lưu
  PIN/credential trên đĩa hoặc log. Việc giữ phiên token theo lifetime khả dụng
  của backend; không tự đổi certificate hoặc fallback serial.
- Với mỗi group: cancellation check → download → parse ZIP → ký/verify mọi XML
  → cancellation check → upload multipart đúng contract → nhận ACK → cập nhật
  tiến độ → group tiếp. Giữ nhịp nghỉ800ms có thể hủy giữa group như contract
  nghiên cứu; không dùng sleep để suy backend capacity/thời gian hoàn thành.
- Không tự retry login/download/upload hay gọi delete-cache để “sửa” lỗi trong
  đường mới nếu chưa có hợp đồng retry riêng. Ưu tiên giữ một upload attempt
  mỗi group; không thêm rollback không được chứng minh.

### 4. Kết quả một phần, hủy và kết nối không rõ kết quả

State tối thiểu: pending → downloading → signing/verifying → uploading →
uploadAcknowledged; terminal bổ sung failed/cancelled/uploadUncertain.
`uploadAcknowledged` chỉ phản ánh response contract, không tự coi là cơ quan
thuế đã phát hành nếu không có xác nhận trạng thái nghiệp vụ độc lập.

- Nếu download/sign/verify group2 lỗi: dừng, không upload group2 hoặc chạy group3;
  giữ group1 đã ACK. Group đã fail không được trộn với group chưa chạy.
- Nếu upload group2 timeout/mất kết nối: group1 đã ACK, group2 uncertain,
  group3 pending/notStarted. Không tự gửi lại group2 hoặc cả lô.
- Nếu user hủy trước upload thì không upload thêm; nếu upload đã bắt đầu, báo
  đang chờ xác định kết quả, không bắt đầu group kế. Không báo thành công toàn
  lô từ callback Windows hay từ việc worker không có Exception.
- Callback SignalR giữ casing/schema hiện có; chỉ báo success toàn command khi
  mọi group đạt contract. Cancel/partial/uncertain phải hiện đúng trong app và
  trả lỗi tương thích portal, không bịa trạng thái success/code mới chưa hỗ trợ.
- UI hiển thị “Đã gửi 100/300, nhóm 1/3”, số document đang ký và số chưa chạy;
  không lấy signature count thay invoice count. Không có nút tự retry toàn lô
  sau kết quả chưa rõ. Giữ kết quả đủ để user đối chiếu danh sách trên Minvoice.

### 5. Kiểm thử có ý nghĩa trước khi mở tính năng

Dùng HTTP mock và software certificate/signing fixture; không token/PIN/network
nghiệp vụ thật trong test. Giữ test cash đơn hiện có để chống regression.

| Ca | Tiêu chí |
|---|---|
| n=1,3,99,100 | Một group, đúng IDs/order; aggregate HDon vẫn được ký đúng |
| n=101,200,201,300,301 | Chia nhóm đúng, không mất/trùng IDs;300 đúng3×100 |
|300 thành công|Login/bootstrap một lần, approval một phiên; group upload ACK trước download tiếp; callback success một lần|
|ZIP nhiều entries/aggregate|Một hoặc nhiều XML, mỗi XML có một hoặc nhiều HDon; số signature theo documents; multipart field files đúng|
|Input/ZIP lỗi|Rỗng/trùng IDs, malformed/duplicate/path ZIP, CRC sai, quá giới hạn, XML sai profile bị từ chối trước upload liên quan|
|Sign/verify lỗi tại group2|Không upload group2; group1 vẫn recorded; group3 không chạy|
|Upload timeout tại group2|Không retry; trạng thái100 ACK/100 uncertain/100 chưa chạy|
|Hủy trước group2|Không download/upload tiếp; kết quả cancelled/partial, không success300|
|Hủy trong ký/upload|Không bắt đầu thao tác tiếp theo; phân biệt chưa gửi với đã gửi/chưa rõ|
|Request trùng/đồng thời|Busy/signing lock ngăn hai phiên cùng dùng token; không gửi hai lần|
|Progress/privacy|Đếm invoice riêng document, terminal đúng; không log PIN/password/cookie/XML thật|
|Regression FastCA/bridges|Build và tests hiện có đạt; mock không làm thay đổi việc chọn cert hay cơ chế ký|

Nếu thêm fake-time cho nhịp nghỉ thì tests không chờ800ms thật mỗi nhóm. Đo bộ
nhớ/thời gian trong fixture đại diện300 với dữ liệu hàng hóa lớn; ghi số đo,
không suy hiệu năng thật từ model scheduler.

### 6. Đóng gói và báo cáo

- Build app chung, chạy bộ test phù hợp và ghi chính xác kết quả. Không chỉ
  cập nhật tài liệu hoặc xóa guard rồi kết luận xong.
- Bàn giao binary app thử hiện có theo workflow repo, liệt kê phạm vi cash,
  giới hạn tài nguyên, số test qua và những gì chưa thử live.
- Khi có lô thật user muốn ký: user tự chọn/bấm ký/PIN; agent quan sát request,
  verify artifact và đối chiếu kết quả từng nhóm. Không cố tình ngắt mạng hay
  tạo lỗi trên lô300 thật để thử rollback.

## Điều kiện hoàn thành triển khai

App nhận n thay đổi, test300 cash chạy trọn ba nhóm đúng thứ tự, hỗ trợ ZIP nhiều
XML/aggregate, mọi XML verify trước upload, kết quả lỗi/hủy/uncertain không làm
ký gửi lại hoặc báo toàn lô thành công, regression đạt, có bản app review được.
Tách kết luận “đã triển khai và qua mock300” khỏi “đã ký live300”.
