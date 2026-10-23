# Trạng thái hiện tại của TokenSigner

Nhánh tích hợp: **`p1-token-core`**. Đã merge lịch sử cả ba nhánh P2,
eSigner và Minvoice; `master` cũng là tổ tiên. App duy nhất tại checkout gốc
thay thế các bản chạy theo worktree. Chi tiết đối chiếu:
[BRANCH-CONSOLIDATION.md](BRANCH-CONSOLIDATION.md).

Ngày 23/10/2026 đã dọn nhánh thừa: local và origin chỉ còn `p1-token-core`,
GitHub default branch/origin HEAD trỏ đúng nhánh này và bản tích hợp đã push.
Ba worktree cũ giữ nguyên tệp ở detached HEAD; không còn PR đang mở.
[Evidence](re/evidence/branch-cleanup-2026-10-23.json).

| Bridge | Cổng mặc định | Phạm vi |
| --- | --- | --- |
| CTSigningHub | HTTP 32001 | GetCert, SignHash, SignXML; route case/POST tương thích |
| eSigner | WS 8768 và 8769 | XML-khai eTax, chọn tệp/ký/upload và các lệnh XML/bytes đã có |
| VNPT-CA / DVC | WSS 4433 và 4434 | GetCertInfo, callback DVC, XML/hash, CMS attached/detached |
| Minvoice | HTTP/SignalR 16080 | TokenInfo, cash TDiep theo nhóm 100, mock 300 đạt |

Cả sáu listener được khởi động từ một catalog, hiện trạng thái riêng trong menu.
Tất cả bind loopback. WSS dùng CA localhost riêng, không dùng khóa của hãng;
Keychain trust chỉ thực hiện khi user bấm nút, giới hạn SSL/localhost.

Các phần nền đã có:

- Popup native tự bật, chọn CKS → duyệt → PIN; không cần mở menu bar trước.
- Chọn đúng physical token/module/CKA_ID/DER, giữ serial trang yêu cầu, cập nhật
  hotplug trong lúc chọn. Huỷ task/đóng kết nối giải phóng prompt.
- Host-hash + RSA_PKCS DigestInfo. NC-CA có đủ hai bản sửa length APDU; FastCA và
  EFY-CA dùng ESPK/OpenSC 0.27.1 native cho exact profile. CA khác dùng PKCS#11.
- Minvoice cash có REST/ZIP nhiều XML/profile riêng, chia nhóm 100; một phiên
  duyệt/PIN cho cả lô, verify mọi XML trước upload, báo partial/hủy/chưa rõ, không auto retry.
- OriginStore dùng chung, Host/Origin guard, CORS/PNA và preflight X-XSRF-TOKEN.
  Origin lạ bị chặn; cấp quyền riêng trong app, không tự chấp nhận.
- Nhật ký giữ SHA-256 của block chuẩn bị ký, origin, bridge và kết quả; không
  giữ nội dung, PIN hoặc cookie. Các lần nhập PIN/ký có thể xem trong menu.
- Kiểm tra thư viện shim thực trong gói app; khóa dependency; một launcher chung.

Giới hạn còn lại được liệt kê trong báo cáo đối chiếu, gồm hóa đơn Minvoice
ordinary/mixed, PDF/Office/native messaging, signed challenge riêng của hãng,
notarization/phân phối runtime và live regression trên portal sau khi gộp.
Không coi ký mật mã thành công là kiểm tra chain/revocation hay phát hành hồ sơ.

Lịch sử đầy đủ trước dọn được giữ tại
[archive/PROGRESS-before-consolidation.md](archive/PROGRESS-before-consolidation.md).
Các ghi chú “chưa merge”/“Minvoice 501” trong tài liệu cũ là trạng thái lịch sử.

CTSigningHub SignXML hiện trả mã lỗi XML cụ thể thay cho `badXML` chung chung.
Sau báo cáo `XML_DUPLICATE_ID`, đã sửa quy tắc chặn quá rộng: mã dòng id/Id/ID
không được tham chiếu có thể lặp, giữ nguyên dữ liệu; ID được tham chiếu vẫn
phải duy nhất toàn tài liệu. dataBV khớp nhiều phần tử bị chặn trước picker/PIN.
Mẫu có mã dòng lặp qua xmlsec1 cả có/không namespace. User đã xác nhận ký XML
chưa ký thành công; file có chữ ký vẫn bị chặn, chưa hỗ trợ ký lại/ký bổ sung.

Validation cuối: **163 tests đạt**, smoke đủ sáu cổng, TLS VNPT và lỗi XML qua
HTTP đạt; không nhập PIN hoặc gửi nghiệp vụ thật.
[Evidence](re/evidence/efy-packaged-app-2026-10-23.json).

UI đã sửa mũi tên disclosure và nút ký thử bị nhạt/trắng trên nền sáng khi
host macOS dùng giao diện tối; tăng tương phản chữ phụ, divider và viền nhập
PIN. Các popup dùng cùng palette. 13 AppTests đạt, ảnh render trong host
sáng/tối giống nhau, native picker và smoke sáu cổng đạt.
[UI evidence](re/evidence/ui-contrast-2026-10-23.json).


Ký lô Minvoice đã triển khai đến bản app thử: mock 300 = 3 nhóm 100, hỗ trợ
aggregate/nhiều XML; giới hạn app 1000 IDs/64 KiB command, archive 16 MiB,
XML 8 MiB, tổng bung 32 MiB, 100 entries, multipart 40 MiB. Đã kiểm tra timeout
upload nhóm 2 và hủy trong ký/upload, không retry/rollback hoặc success toàn lô.
Chưa ký live300. [Hướng dẫn](MINVOICE.md).

OneCA V3 đã được gộp vào App/Helper/shim chung, giữ experimental và exact ATR,
module hash-pinned, một matching reader/token. App đóng gói đã quảng bá đúng
chứng thư OneCA qua GetCert (so SHA-256 với evidence nghiên cứu), không ký thử
lại hoặc nhập PIN. [Evidence app](re/evidence/oneca-packaged-app-2026-10-23.json).


Minvoice: user đã xác nhận app Mac ký thành công lô **2 hóa đơn** sau bản chẩn
đoán HTTP. Lỗi kết nối trước đó 0/2 không tái hiện; chưa xác định nguyên nhân
mạng gốc. `[MI_HTTP …]` phân biệt bước/reason và mã hệ thống an toàn nếu lỗi
lặp lại; không chứa URL/credential/XML và không thêm retry. Chưa ký live300.

EFY-CA đã tích hợp vào app/helper native ARM64, exact ATR, experimental. Dùng
chung ESPK parser/transport với FastCA nhưng khác profile và serial namespace;
kiểm tra metadata/public key trước PIN, verify chữ ký trước trả kết quả. Runtime
OpenSC/libcrypto ARM64 đã nằm trong bundle thử. Người dùng xác nhận **Ký thử →
Ký và xác minh OK** trên EFY ngày 23/10. Chưa thử hồ sơ/cổng nghiệp vụ EFY.
[Hướng dẫn](EFY-CA.md).
