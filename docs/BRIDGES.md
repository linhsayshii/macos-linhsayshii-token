# Các bridge trong app chung

App menu bar tự khởi động cả sáu listener từ lúc mở app:

| Dịch vụ | Địa chỉ | Chức năng |
| --- | --- | --- |
| CTSigningHub | `http://127.0.0.1:32001` | Version, GetInfoCert, GetCert, SignHash, SignXML |
| eSigner | `ws://127.0.0.1:8768/plugin/sign` | eTax XML-khai và các lệnh ký XML/bytes đã hỗ trợ |
| eSigner dự phòng | `ws://127.0.0.1:8769/plugin/sign` | Cùng bridge, listener độc lập với 8768 |
| VNPT-CA | `wss://localhost:4433/plugin` | Callback DVC, chọn CKS, XML/hash/CMS |
| VNPT-CA dự phòng | `wss://localhost:4434/plugin` | Listener WSS độc lập |
| Minvoice | `http://127.0.0.1:16080/signalr` | SignalR classic, TokenInfo, cash theo nhóm 100 |

Menu hiển thị rõ CTSigningHub và hai cổng eSigner cùng trạng thái riêng. Cả
8768 và 8769 được mở đồng thời; nếu một cổng bị chiếm, cổng còn lại vẫn phục vụ.
Không chỉ thử 8769 sau khi bind 8768 thất bại. Đây là hai endpoint WebSocket
plain giống luồng eSigner đã xác minh, VNPT dùng WSS riêng trên 4433/4434 với CA localhost của TokenSigner.

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

SignXML trả mã chẩn đoán trong `message`, thay cho `badXML` chung chung:

| Mã | Nguyên nhân |
| --- | --- |
| `XML_PARSE` / `XML_ENCODING` | Không đọc được XML hoặc dữ liệu không phải UTF-8 |
| `XML_DTD_ENTITY` | Có khai báo DTD/ENTITY bị chặn |
| `XML_INVALID_ID` / `XML_DUPLICATE_ID` | ID của phần tử được ký không hợp lệ hoặc không duy nhất; xml:id cũng phải hợp lệ/duy nhất |
| `XML_AMBIGUOUS_REFERENCE` | Tên phần tử trong dataBV khớp nhiều phần tử |
| `XML_EXISTING_SIGNATURE` | Tài liệu có sẵn phần tử Signature, kể cả khung chữ ký rỗng |
| `XML_PLACEMENT` / `XML_OPTIONS` | cks/dataBV hoặc tham số chữ ký không phù hợp |
| `XML_SIGNATURE_ID_COLLISION` | Trùng ID chữ ký/SigningTime |
| `XML_REFERENCE_PLACEMENT` | Chèn chữ ký bên trong phần tử dataBV, chưa được hỗ trợ |
| `XML_CERTIFICATE` / `XML_TOO_LARGE` | Chứng thư không có khóa RSA đọc được hoặc XML vượt 20 MiB |

Thuộc tính `id`/`Id`/`ID` thông thường có thể là mã dòng lặp ở nhiều bảng.
App giữ nguyên các mã dữ liệu này. Khi ký theo `dataBV`, phần tử được chọn
phải duy nhất; ID dùng trong `Reference URI="#…"` phải duy nhất trên toàn
tài liệu, kể cả khi đụng ID của phần tử khác hoặc `xml:id`. App không tự đổi
ID có sẵn để che lỗi tham chiếu. ID tự sinh bỏ qua cả mã dòng và `xml:id` đã có.

Chẩn đoán không ghi XML, giá trị ID hoặc lỗi parser chứa dữ liệu tài liệu.
Kiểm tra tham chiếu chạy trước popup chọn CKS/PIN. Báo cáo ngày 23/10 đã
xác nhận `XML_DUPLICATE_ID`; bộ kiểm tra cũ chặn quá rộng cả mã dòng không
được tham chiếu. Mẫu synthetic có mã dòng lặp đã được ký và kiểm tra độc lập
bằng xmlsec1, giữ nguyên phần dữ liệu; vẫn cần người dùng thử lại tờ khai thật.

Host/Origin được kiểm tra trên cả HTTP và WebSocket trước khi gọi bridge.
Unknown origin nhận 403. Tất cả listener chỉ bind `127.0.0.1`.

## Kiểm tra

```sh
swift test -Xswiftc -plugin-path -Xswiftc /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing
./scripts/package-test-app.sh
python3 scripts/check-integrated-app.py
```

Smoke mở đúng gói app đã đóng, kiểm tra CTSign, Minvoice SignalR, CHECK_VERSION
trên cả 8768/8769, VNPT CheckPlugin qua TLS 4433/4434, route CTSign và 403. Không gửi PIN, ký, đăng nhập cổng thuế/Minvoice hoặc upload thật.

Luồng eTax từng được xác nhận trên nhánh riêng; sau tích hợp cần người dùng
thử lại tờ khai thật với CKS còn hiệu lực. Không coi unit test và handshake là
bằng chứng nộp tờ khai thành công trên bản app mới. Xem
[validation record](re/evidence/all-bridges-validation-2026-10-23.json).

Validation trước khi gộp VNPT: 109 tests đạt (7 shim, 35 Core, 56 Bridges, 11 App).
Có kiểm tra XMLDSig bằng xmlsec1 và CMS bằng OpenSSL, origin thực qua HTTP,
cả hai WebSocket, huỷ socket, grant tệp khác origin và luồng popup app. Gói app
qua codesign strict và kiểm tra NC-CA shim. Smoke cả bốn cổng đạt; bản app đã
mở lại và cùng một process đang listen trên cả bốn địa chỉ loopback.


## Hợp nhất toàn bộ nhánh

VNPT 4433/4434 đã bật, cùng shared OriginStore, audit digest-only và service
catalog. Menu “Kết nối và quyền” cho phép user chủ động tin cậy chứng chỉ SSL
localhost trong login keychain; app không tự cài trust. CA và leaf key chỉ ở
Application Support (600/700), không đưa vào repo. Nhật ký ký chỉ giữ hash của
block chuẩn bị ký và metadata kết quả, không giữ nội dung/PIN/cookie.

Xem [đối chiếu nhánh và giới hạn còn lại](BRANCH-CONSOLIDATION.md). Bản hợp nhất
cuối đạt 130 tests (7 shim, 37 Core, 75 Bridges, 11 App).


## Minvoice ký lô cash

`SignInvoices` nhận 1–1000 invoice IDs duy nhất (giới hạn app), chia tuần tự
nhóm tối đa 100. Đã qua mock 300/301 và nhiều XML trong ZIP; một XML có thể
chứa nhiều HDon. Toàn bộ XML của nhóm phải ký/verify đạt trước một upload.
Menu hiện ACK/chưa rõ/chưa chạy theo số hóa đơn và trạng thái từng nhóm, có
nút hủy lô. Không tự retry/rollback, không báo success toàn lô khi còn nhóm lỗi,
hủy hoặc chưa rõ kết quả. [Chi tiết](MINVOICE.md).
