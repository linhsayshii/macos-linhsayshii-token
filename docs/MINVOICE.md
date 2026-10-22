# Minvoice trong TokenSigner

Checkout tích hợp `p1-token-core` phục vụ CTSigningHub trên `127.0.0.1:32001`
và SignalR classic `handlerHub` trên `127.0.0.1:16080` trong cùng app. Minvoice
có WebSocket và long polling, `processMessage` nhận JSON string và trả callback
`reponseResult` riêng cho connection; `getVersion` trả version tương thích của
bridge TokenSigner, không phải version của binary hãng.

## Phạm vi đã triển khai

`SignInvoices` hỗ trợ **một hóa đơn cash mỗi lần**, ZIP có đúng một GUID.xml,
XML root `TDiep`. `HDon`, `BKe`, batch và các lệnh ký khác trả lỗi chưa hỗ trợ.
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
   trước REST login. BrowserInfo chỉ tồn tại trong bộ nhớ; không log/lưu credential.
3. POST `/api/account/login` với `UserNameOrEmailAddress`, `Password`,
   `RememberMe=false`; chỉ chuyển cookie `__tenant` ban đầu. GET bootstrap
   `/api/abp/application-configuration`; giữ cookie xác thực và XSRF trong phiên
   riêng, không dùng cookie/cache/keychain mặc định của URLSession.
4. GET tenant/time, token registration theo đúng serial, invoice detail. Nhánh
   cash được nhận diện theo thân method `IsInvoiceCash` của installed plugin:
   serial ASCII dài ít nhất 7, ký tự ở index 4 là M, không phân biệt hoa/thường.
5. POST GUID array đến `/api/app/release-invoice/download-xml-invoice-cash`.
   Đọc ZIP trong bộ nhớ, giới hạn archive 2 MiB/XML 8 MiB; chặn archive nhiều file,
   ZIP64, mã hoá, path lạ, CRC sai và dữ liệu bung không khớp kích thước. Không
   extract ra đĩa. Dùng GUID của entry cho XML reference và filename upload;
   không giả định backend luôn đặt entry GUID bằng invoice ID đã yêu cầu.
6. Ký profile riêng: `TDiep/CKSNNT/Signature`, reference `DLieu Id=<entry GUID>`
   và `Object Id=signtime`. Inclusive C14N, RSA-SHA256, SHA256 digests; time subtree
   không namespace, text server time giữ dạng giây không zone. KeyInfo chỉ có
   X509SubjectName/X509Certificate. Chặn DTD/entity, duplicate ID, signature cũ
   hoặc cấu trúc khác profile trước khi yêu cầu PIN.
7. PIN trong cửa sổ app, chỉ qua stdin helper. Hash SignedInfo trên host, bọc
   DigestInfo rồi `.rsaPKCS`; FastCA dùng ESPK/OpenSC native, CA khác dùng PKCS11.
   Helper/app kiểm tra chữ ký; kiểm tra lại digest và RSA của XML đã tuần tự hoá
   với chính chứng thư được duyệt trước upload. Không phụ thuộc xmlsec1 ở runtime.
8. Một POST multipart `files`, `<entry GUID>.xml`, `text/xml` đến
   `/api/app/release-invoice/00000000-0000-0000-0000-000000000000/upload-xml`.
   Chỉ HTTP 204/body rỗng tạo callback `code:1, data:{status:true,command:SignInvoices}`.
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

Cần user tự thử Minvoice trên macOS với token/chứng thư còn hiệu lực sau khi mở
bản app mới. Chưa có kết quả Minvoice macOS + FastCA end-to-end. Chứng thư FastCA
hiện tại đã hết hạn 30/07/2026 nên bridge từ chối trước login; menu/SignHash kiểm
tra mật mã riêng vẫn có thể dùng cho chẩn đoán. Không coi HTTP upload thành công
là kiểm chứng độc lập trạng thái phát hành, chain hay revocation. Chưa phân phối/
notarize, chưa mở hỗ trợ mọi mẫu FastCA hoặc hóa đơn/batch chưa có fixture thật.
