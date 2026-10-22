# Các bridge trong app chung

App menu bar tự khởi động cả bốn listener từ lúc mở app:

| Dịch vụ | Địa chỉ | Chức năng |
| --- | --- | --- |
| CTSigningHub | `http://127.0.0.1:32001` | Version, GetInfoCert, GetCert, SignHash, SignXML |
| eSigner | `ws://127.0.0.1:8768/plugin/sign` | eTax XML-khai và các lệnh ký XML/bytes đã hỗ trợ |
| eSigner dự phòng | `ws://127.0.0.1:8769/plugin/sign` | Cùng bridge, listener độc lập với 8768 |
| Minvoice | `http://127.0.0.1:16080/signalr` | SignalR classic, TokenInfo, cash đơn |

Menu hiển thị rõ CTSigningHub và hai cổng eSigner cùng trạng thái riêng. Cả
8768 và 8769 được mở đồng thời; nếu một cổng bị chiếm, cổng còn lại vẫn phục vụ.
Không chỉ thử 8769 sau khi bind 8768 thất bại. Đây là hai endpoint WebSocket
plain giống luồng eSigner đã xác minh, không thêm TLS hoặc cài chứng thư hệ thống.

## Tích hợp eSigner

Port từ `claude/beautiful-mcnulty-f9bfbf` tại `f58a51c`: WebSocket handler,
CHOOSE_FILE → OFFLINE_XML_SIGN_002 → OFFLINE_XML_SIGN_003, XMLDSig/CMS core và
xmlsec1 verifier. Giữ nguyên FastCA native, Minvoice cash, NC-CA Le-fix và popup
chọn CKS của app chung; không thay toàn bộ AppModel bằng bản trên nhánh cũ.

- File picker native tự bật trước trình duyệt, chỉ chọn XML. Mỗi origin chỉ dùng
  đường dẫn mà chính origin đó đã được picker cấp. Không đọc filePath tùy ý.
- CER_002 mở chooser chung; không tự lấy CKS đầu tiên khi serial không khớp.
  Serial thập phân của luồng offline được chuyển sang hex theo contract eTax.
- Chọn CKS → duyệt đúng origin → PIN, hash trên host rồi ký RSA_PKCS DigestInfo;
  app xác minh chữ ký token. CKS hết hạn không được dùng cho luồng nghiệp vụ mới.
- Signed XML được xmlsec1 kiểm tra trước khi giữ để upload. Không có xmlsec1 thì
  bỏ qua bước độc lập này theo contract đã có; không bỏ kiểm tra chữ ký token.
- Upload chỉ HTTPS về cùng host origin, không redirect hoặc dùng cookie/cache
  dùng chung. Không ghi frame, cookie, credential hoặc XML nghiệp vụ ra log.
- Đóng WebSocket/HTTP huỷ task đang chờ và đóng popup. Các request dùng chung
  khóa ký với Minvoice/CTSign, không ghi đè PIN/approval của nhau.

## CTSigningHub

Cổng 32001 vốn đã chạy ở bản trước; menu cũ chỉ ghi “Cổng ký”. Bản này thêm tên
rõ ràng và tiếp quản SignXML, route không phân biệt hoa/thường, GET/POST cho các
route đọc theo contract đã có. SignXML chỉ nhận `dataFile` base64, `cks` và
`dataBV`; không đọc `filePath`. Origin từ HTTP được đưa tới popup/approval thật.

Host/Origin được kiểm tra trên cả HTTP và WebSocket trước khi gọi bridge.
Unknown origin nhận 403. Tất cả listener chỉ bind `127.0.0.1`.

## Kiểm tra

```sh
swift test -Xswiftc -plugin-path -Xswiftc /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing
./scripts/package-test-app.sh
python3 scripts/check-integrated-app.py
```

Smoke mở đúng gói app đã đóng, kiểm tra version CTSign, Minvoice SignalR,
CHECK_VERSION qua WebSocket trên cả 8768/8769, route CTSign case/POST/SignXML và
403. Không gửi PIN, ký, đăng nhập cổng thuế/Minvoice hoặc upload thật.

Luồng eTax từng được xác nhận trên nhánh riêng; sau tích hợp cần người dùng
thử lại tờ khai thật với CKS còn hiệu lực. Không coi unit test và handshake là
bằng chứng nộp tờ khai thành công trên bản app mới. Xem
[validation record](re/evidence/all-bridges-validation-2026-10-23.json).

Validation 23/10/2026: 109 tests đạt (7 shim, 35 Core, 56 Bridges, 11 App).
Có kiểm tra XMLDSig bằng xmlsec1 và CMS bằng OpenSSL, origin thực qua HTTP,
cả hai WebSocket, huỷ socket, grant tệp khác origin và luồng popup app. Gói app
qua codesign strict và kiểm tra NC-CA shim. Smoke cả bốn cổng đạt; bản app đã
mở lại và cùng một process đang listen trên cả bốn địa chỉ loopback.
