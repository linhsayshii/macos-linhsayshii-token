# Minvoice trong TokenSigner

Checkout tích hợp `p1-token-core` phục vụ CTSigningHub trên `127.0.0.1:32001`
và SignalR classic `handlerHub` trên `127.0.0.1:16080` trong cùng app. Minvoice
có WebSocket và long polling, `processMessage` nhận JSON string và trả callback
`reponseResult` riêng cho connection; `getVersion` trả version tương thích của
bridge TokenSigner, không phải version của binary hãng.

## Phạm vi đã triển khai

`SignInvoices` hỗ trợ **lô cash cùng mẫu/ký hiệu**, 1–1000 invoice IDs duy nhất,
chia tuần tự nhóm tối đa 100. Mục tiêu 300 đã qua mock với ba nhóm 100; 301
thành bốn nhóm. ZIP có thể chứa nhiều GUID.xml, mỗi XML `TDiep` có thể chứa nhiều
HDon. Số hóa đơn, XML và chữ ký không bị ép bằng nhau. Ordinary HDon/BKe,
lô trộn và các lệnh ký khác vẫn chưa được hỗ trợ.
TokenInfo/GetCertificate/GetInfoToken mở cửa sổ chọn CKS của TokenSigner khi
chưa có lựa chọn của origin đó. Người dùng chọn rõ CKS; thông tin lựa chọn được
nhớ trong bộ nhớ theo origin để các lần hỏi lặp không bật cửa sổ liên tục.
Yêu cầu ký vẫn mở lại picker. Chi tiết: [CERTIFICATE-PICKER.md](CERTIFICATE-PICKER.md).

1. Kiểm tra origin, API HTTPS cố định và command. Người dùng chọn CKS trong popup;
   serial do trang chỉ định luôn ràng buộc lựa chọn. Nếu thiếu/rỗng SerialNumber,
   picker cho chọn trong các CKS phù hợp. Hai token chứa cùng serial chứng thư
   được phân biệt bằng physical token/module/CKA_ID/DER; không dùng vị trí hàng
   hoặc mặc định lấy chứng thư đầu tiên.
2. Giữ signing lock chung, kiểm tra hiệu lực chứng thư từ DER và hiện approval
   cho toàn lô trước REST login theo chính sách phiên duyệt hiện có. BrowserInfo chỉ tồn tại trong bộ nhớ; không log/lưu credential.
3. POST `/api/account/login` với `UserNameOrEmailAddress`, `Password`,
   `RememberMe=false`; chỉ chuyển cookie `__tenant` ban đầu. GET bootstrap
   `/api/abp/application-configuration`; giữ cookie xác thực và XSRF trong phiên
   riêng, không dùng cookie/cache/keychain mặc định của URLSession.
4. GET tenant/time, token registration theo đúng serial, detail của **mọi invoice**.
   App yêu cầu tất cả invoiceSerial giống nhau trước upload đầu tiên; đây là
   guard đồng nhất riêng của app, không sao chép shortcut detail đầu của Windows. Nhánh
   cash được nhận diện theo thân method `IsInvoiceCash` của installed plugin:
   serial ASCII dài ít nhất 7, ký tự ở index 4 là M, không phân biệt hoa/thường.
5. POST GUID array đến `/api/app/release-invoice/download-xml-invoice-cash`.
   Mỗi nhóm có một download. ZIP được đọc trong bộ nhớ: archive 16 MiB, mỗi XML
   8 MiB, tổng bung 32 MiB, tối đa 100 entries; multipart tối đa 40 MiB. Chặn
   ZIP64, mã hoá, tên/ID entry trùng, path lạ, CRC sai và sai kích thước. Không
   extract ra đĩa. Dùng GUID của entry cho XML reference và filename upload;
   không giả định backend luôn đặt entry GUID bằng invoice ID đã yêu cầu.
6. Ký profile riêng: `TDiep/CKSNNT/Signature`, reference `DLieu Id=<entry GUID>`
   và `Object Id=signtime`. Inclusive C14N, RSA-SHA256, SHA256 digests; time subtree
   không namespace, text server time giữ dạng giây không zone. KeyInfo chỉ có
   X509SubjectName/X509Certificate. Chặn DTD/entity, duplicate ID, signature cũ
   hoặc cấu trúc khác profile trước khi yêu cầu PIN.
7. PIN trong cửa sổ app, chỉ qua stdin helper. Chỉ hỏi một lần trong lô; giữ
   tham chiếu PIN tạm trong RAM của phiên được duyệt, xóa tham chiếu khi xong,
   lỗi hoặc hủy; không dùng lại ở lô khác. Helper hiện vẫn login/sign/logout
   từng XML theo lifetime backend hiện có, không tuyên bố một card-login cho cả
   lô. Hash SignedInfo trên host, bọc
   DigestInfo rồi `.rsaPKCS`; FastCA dùng ESPK/OpenSC native, CA khác dùng PKCS11.
   Helper/app kiểm tra chữ ký; kiểm tra lại digest và RSA của XML đã tuần tự hoá
   với chính chứng thư được duyệt trước upload. Không phụ thuộc xmlsec1 ở runtime.
8. Sau khi **mọi XML của nhóm** đã ký và verify, một POST multipart `files`, `<entry GUID>.xml`, `text/xml` đến
   `/api/app/release-invoice/00000000-0000-0000-0000-000000000000/upload-xml`.
   Chỉ khi mọi nhóm nhận HTTP 204/body rỗng mới tạo callback
   `code:1, data:{status:true,command:SignInvoices,batch:...}`. Giữa các nhóm
   chờ 800 ms có thể hủy; không chờ nhóm sau song song với upload nhóm trước.
   Không tự retry. Mất kết nối/huỷ trong upload trả trạng thái chưa xác định và
   yêu cầu kiểm tra hóa đơn trước khi gửi lại; không giả định rollback.

URLSession từ chối redirect, giới hạn response, không chuyển credential sang host
khác. Server bind loopback, kiểm tra Host/Origin và ràng buộc connection token với
origin. SignalR abort huỷ operation đang chờ; app đóng prompt/tiếp tục continuation
bằng nhánh huỷ. Không có thao tác ký dummy để xác thực token như plugin Windows.

## Căn cứ và validation

Contract được đối chiếu với plugin Windows **1.0.3.0**, SHA-256
`4e891736c97f593f4306f56ce645f039ac91aa3e54ed01d81cb7b822093331e0`.
Cash live ngày 23/10/2026 có download 200/upload 204 và user xác nhận UI thành công;
XML Windows verify độc lập đạt. Đây là căn cứ profile, **không phải phép thử của
bản macOS tích hợp mới**. [Evidence đã che dữ liệu](re/evidence/minvoice-live-cash-success.json).
Callback casing lấy từ CIL/web bundle; giao dịch live chưa thu callback envelope.

Đợt tích hợp ban đầu đạt 57 tests: 3 shim, 24 Core, 30 Bridges. Fixture phần mềm kiểm tra
luồng đủ từ approval đến callback, đăng nhập/cookie, lỗi auth, chọn sai chứng thư,
hết hạn, huỷ, yêu cầu đồng thời, signature mismatch, ZIP lỗi và upload lỗi/timeout.
`xmlsec1` kiểm chứng độc lập XML do signer mới tạo và từ chối dữ liệu bị sửa.
WebSocket/long polling và chống dùng connection khác origin cũng được kiểm tra.
Không có request REST nghiệp vụ thật hay PIN/token thật trong đợt tích hợp này.

```sh
./scripts/test-env.sh test-core      # toàn bộ suite của app tích hợp
./scripts/test-env.sh test-minvoice  # nhóm Minvoice/transport
./scripts/package-test-app.sh        # đóng gói output đã build; kiểm tra OpenSC
python3 scripts/check-integrated-app.py
```

Smoke script chỉ mở rồi đóng app của nó, kiểm tra version/SignalR/403 qua loopback;
không đăng nhập Minvoice, ký hay upload. Gói local ở `.local/test-env/TokenSigner.app`,
ký ad-hoc cho máy phát triển; OpenSC 0.27.1 là dependency ngoài bundle.

## Chưa xác nhận

User đã xác nhận ký được lô 2 cash trên macOS sau bản chẩn đoán (xem mục cuối).
Các cỡ lô/mẫu/CA khác vẫn cần xác nhận riêng khi có nghiệp vụ thực tế. Chưa có kết quả Minvoice macOS + FastCA end-to-end. Chứng thư FastCA
hiện tại đã hết hạn 30/07/2026 nên bridge từ chối trước login; menu/SignHash kiểm
tra mật mã riêng vẫn có thể dùng cho chẩn đoán. Không coi HTTP upload thành công
là kiểm chứng độc lập trạng thái phát hành, chain hay revocation. Chưa phân phối/
notarize, chưa mở hỗ trợ mọi mẫu FastCA hoặc ordinary/mixed chưa có fixture thật.


## Tiến độ, hủy và giới hạn kiểm chứng

Menu “Lô Minvoice” tách ACK upload, chưa rõ, chưa chạy và số XML/chữ ký.
Nút “Hủy lô Minvoice” hủy tác vụ mạng/chờ PIN và ngăn nhóm tiếp theo. Nếu upload
đã bắt đầu mà không nhận đúng ACK (kể cả bị hủy), nhóm đó là uploadUncertain.
Ví dụ timeout nhóm 2 của 300: 100 ACK / 100 chưa rõ / 100 chưa chạy. Lỗi ký/
verify nhóm 2 không upload nhóm đó. Mọi lỗi đều dừng, không tự gửi lại hoặc
rollback nhóm trước. ACK upload không đồng nghĩa cơ quan thuế đã phát hành.

151 tests đạt trong bản tích hợp, có mock 1/3/99/100/101/200/201/300/301,
ZIP nhiều XML, aggregate HDon, CRC/path/ID/size lỗi, auth một phiên, thứ tự
nhóm, lỗi/huỷ nhóm 2 và menu hủy/PIN một phiên. Benchmark offline riêng 300
với khoảng 3 MB multipart: xem evidence; không suy ra năng lực backend/token.
Capture Windows thật mới có cash 1/3. Bản macOS mới **chưa ký live300**;
không cần người dùng phát hành 300 hóa đơn để thay cho kiểm thử offline.
Mapping invoice GUID → HDon trong XML vẫn do backend cung cấp; app chưa có
bằng chứng để kiểm tra mapping nội dung đó độc lập, không ép entry GUID bằng
requested GUID. [Kế hoạch](plans/minvoice-bulk-300-integration.md),
[evidence triển khai](re/evidence/minvoice-bulk-integration-2026-10-23.json).


## Chẩn đoán kết nối và lần ký Mac đã xác nhận

Bản chẩn đoán trả token như `[MI_HTTP login/fetch URL:-1009]` trong callback và
kết quả ở menu (chọn/copy được). Route là enum bước, không phải URL thực. Reason
phân biệt mở kết nối, đọc response, URL không khớp, quá kích thước, HTTP status,
JSON, cookie bootstrap và shape. Chỉ lưu domain hệ thống trong allowlist/mã số,
đọc tối đa ba NSError trong chuỗi nguyên nhân; domain lạ thành `other`. Không
lưu lỗi gốc, localizedDescription, URL, GUID, header, cookie hay body.

Ngày 23/10 user đã xác nhận **bản macOS ký thành công hai hóa đơn trong một
lần** sau khi mở bản chẩn đoán. Đây là xác nhận trực tiếp của user, chưa thu
wire capture mới và chưa ghi nhận CA dùng cho lần này. Lỗi kết nối cũ 0/2 trước
tải XML không tái hiện trong lần đó; **chưa xác định nguyên nhân gốc**, không
suy thành lỗi PIN/token hay khẳng định thay đổi chẩn đoán đã sửa lỗi mạng.
156 tests và smoke sáu cổng đạt; không tự replay credentials hoặc ký để tìm lỗi.
[Evidence](re/evidence/minvoice-http-diagnostics-2026-10-23.json).
