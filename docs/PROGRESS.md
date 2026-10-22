# Trạng thái hiện tại của TokenSigner

Nhánh tích hợp: **`p1-token-core`**. Đã merge lịch sử cả ba nhánh P2,
eSigner và Minvoice; `master` cũng là tổ tiên. App duy nhất tại checkout gốc
thay thế các bản chạy theo worktree. Chi tiết đối chiếu:
[BRANCH-CONSOLIDATION.md](BRANCH-CONSOLIDATION.md).

| Bridge | Cổng mặc định | Phạm vi |
| --- | --- | --- |
| CTSigningHub | HTTP 32001 | GetCert, SignHash, SignXML; route case/POST tương thích |
| eSigner | WS 8768 và 8769 | XML-khai eTax, chọn tệp/ký/upload và các lệnh XML/bytes đã có |
| VNPT-CA / DVC | WSS 4433 và 4434 | GetCertInfo, callback DVC, XML/hash, CMS attached/detached |
| Minvoice | HTTP/SignalR 16080 | TokenInfo, một hóa đơn cash TDiep mỗi lần |

Cả sáu listener được khởi động từ một catalog, hiện trạng thái riêng trong menu.
Tất cả bind loopback. WSS dùng CA localhost riêng, không dùng khóa của hãng;
Keychain trust chỉ thực hiện khi user bấm nút, giới hạn SSL/localhost.

Các phần nền đã có:

- Popup native tự bật, chọn CKS → duyệt → PIN; không cần mở menu bar trước.
- Chọn đúng physical token/module/CKA_ID/DER, giữ serial trang yêu cầu, cập nhật
  hotplug trong lúc chọn. Huỷ task/đóng kết nối giải phóng prompt.
- Host-hash + RSA_PKCS DigestInfo. NC-CA có đủ hai bản sửa length APDU; FastCA
  dùng ESPK/OpenSC 0.27.1 native cho profile đã xác minh. CA khác dùng PKCS#11.
- Minvoice cash có REST/ZIP/profile riêng, verify trước upload, không auto retry.
- OriginStore dùng chung, Host/Origin guard, CORS/PNA và preflight X-XSRF-TOKEN.
  Origin lạ bị chặn; cấp quyền riêng trong app, không tự chấp nhận.
- Nhật ký giữ SHA-256 của block chuẩn bị ký, origin, bridge và kết quả; không
  giữ nội dung, PIN hoặc cookie. Các lần nhập PIN/ký có thể xem trong menu.
- Kiểm tra thư viện shim thực trong gói app; khóa dependency; một launcher chung.

Giới hạn còn lại được liệt kê trong báo cáo đối chiếu, gồm hóa đơn Minvoice
khác/batch, PDF/Office/native messaging, signed challenge riêng của hãng,
notarization/phân phối runtime và live regression trên portal sau khi gộp.
Không coi ký mật mã thành công là kiểm tra chain/revocation hay phát hành hồ sơ.

Lịch sử đầy đủ trước dọn được giữ tại
[archive/PROGRESS-before-consolidation.md](archive/PROGRESS-before-consolidation.md).
Các ghi chú “chưa merge”/“Minvoice 501” trong tài liệu cũ là trạng thái lịch sử.

Validation cuối: **130 tests đạt**, smoke đủ sáu cổng và TLS VNPT đạt; không
nhập PIN hoặc gửi nghiệp vụ thật. [Evidence](re/evidence/branch-consolidation-validation-2026-10-23.json).
