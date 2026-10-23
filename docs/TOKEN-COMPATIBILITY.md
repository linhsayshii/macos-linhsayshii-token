# Mục tiêu tương thích các dòng token — yêu cầu người dùng 23/10/2026

Người dùng chốt mục tiêu: **nhận và hỗ trợ các dòng token của cùng một hãng CA,
không chỉ chiếc đã cắm hoặc vài exact ATR đã gặp**. Phạm vi này áp dụng chung cho
luồng chính, các phiên FastCA/EFY/OneCA và các adapter MISA/Minvoice.

Đây là yêu cầu đang triển khai, không phải tuyên bố mọi model đã được hỗ trợ.
Danh sách exact ATR hiện có là tập thiết bị đã quan sát và regression fixtures;
không phải định nghĩa cuối cùng của phạm vi sản phẩm.

## Vấn đề thực tế cần loại bỏ

FastCA có hai USB thật cùng CA nhưng ATR khác nhau. Mẫu 22/10 ký được, mẫu
23/10 bị app báo “Chưa hỗ trợ” do chưa nằm trong allowlist. Mẫu mới sau khi đọc
metadata cho thấy cùng họ ESPK, chứng thư/key hợp lệ và đã được app nhận sau khi
thêm ATR. User xác nhận “Đã hiện FastCA”. Không tiếp tục bắt người dùng cung cấp
từng chiếc để thêm riêng một full ATR nếu cùng backend có thể nhận diện chúng.

## Hướng triển khai chung

1. **Tách CA phát hành với nhà sản xuất và giao thức USB.** Một CA có thể dùng
   nhiều OEM, thế hệ token và middleware. Nhãn CA không tự quyết định APDU/PIN.
2. **Inventory provider/model.** Mỗi provider ghi dòng thiết bị, nguồn driver/module,
   kiến trúc, quy tắc ATR/USB/reader có căn cứ và các thao tác được hỗ trợ.
   Thu thập mẫu/mask từ tài liệu, driver và artifact có nguồn hợp lệ; giữ quy định
   license hiện có. USB VID/PID và reader name là tín hiệu, không phải danh tính chắc chắn.
3. **Nhận diện họ thiết bị thay cho so toàn bộ ATR mẫu.** Phân tích cấu trúc ATR,
   byte giao thức, historical bytes và checksum; chỉ wildcard phần có bằng chứng
   là biến thể. ATR hợp lệ mới của cùng họ phải được đưa vào tuyến discovery,
   không bị loại ngay vì chưa có chuỗi hex nguyên vẹn trong danh sách.
4. **Discovery/preflight không dùng PIN.** Backend phù hợp đọc thông tin public,
   catalog/token/certificate/key metadata, xác minh model/protocol và capability.
   Chỉ tạo signing target khi physical reader/token, CKA_ID và public key khớp.
   Không thử tuần tự các công thức PIN/APDU authentication trên thiết bị chưa rõ.
5. **Fallback theo provider có căn cứ.** Cùng CA nhưng OEM/protocol khác cần backend
   tương ứng. Không giả ATR, patch vendor binary hoặc dùng PIN path của model khác
   chỉ vì issuer giống nhau. Không tự nạp mọi binary tìm được trên máy.
6. **Bridge độc lập CA/model.** MISA/Minvoice/CTSigningHub/eSigner/VNPT dùng broker,
   capabilities và chooser chung. Không cài danh sách ATR/serial cố định trong adapter.
7. **Trạng thái có ý nghĩa.** Phân biệt đang nhận diện, đã đọc được, thiếu runtime,
   model chưa có backend, thao tác chưa được hỗ trợ và lỗi transport. Không đánh
   đồng một ATR chưa có trong bảng với mọi token của CA đó chưa được tích hợp.

Giữ approval/PIN của user, không tự retry authentication/sign, verify chữ ký trước
trả kết quả và không lưu PIN/private key. Handshake secure messaging của transport
khác với lần xác thực PIN người dùng; báo cáo phải phân biệt hai việc này.

## Nghiệm thu

- Quy tắc nhận diện có bằng chứng, không chỉ kéo dài danh sách exact ATR.
- Biến thể hợp lệ trong cùng họ/backend được nhận và đọc trước PIN; tests bao phủ
  các trường biến đổi và checksum, cấu trúc sai, CA/OEM khác và metadata/key mismatch.
- Cùng CA trên OEM khác chọn đúng provider hoặc báo rõ backend còn thiếu.
- USB mới cùng họ không cần vá thủ công tên reader, số slot, cert thumbprint,
  serial, FID hoặc key reference của mẫu trước.
- Ma trận coverage theo **CA → OEM/model/generation → firmware/protocol → provider**,
  ghi riêng: có căn cứ nhận diện, đọc thật, xác thực thật, ký/verify thật, portal.
  Không dùng kết quả đọc để tuyên bố đã ký, hoặc kết quả một model để tuyên bố
  đã kiểm chứng mọi thiết bị của hãng.
- Các bridge đều nhận target qua lớp chung; tests giữ đúng cert/token/CKA_ID,
  không phát hành nghiệp vụ thật để thay cho regression offline.

## Điều phối trong workspace chung

- Luồng **Tiếp tục phần còn lại của dự án** sở hữu kiến trúc compatibility,
  routing/transport/UI chung, tích hợp, lịch build và nghiệm thu.
- FastCA/EFY-CA/OneCa bổ sung model inventory, evidence, quy tắc nhận diện,
  preflight và fixtures theo phạm vi CA; thống nhất với main trước sửa file chung.
- **Misa** và **Dò luồng ký minvoice Plugin App 2.0…** tiếp tục adapter/protocol,
  dùng discovery/broker chung và báo giới hạn provider quan sát được.
- Không ghi đè nghiên cứu chưa commit, không stage toàn workspace hoặc build
  đồng thời cùng `.build`. Không bắt đầu lại từ tài liệu handoff lịch sử đã lỗi thời.


## Đã triển khai ở lớp chung — 24/10/2026

- `TokenATR` parse chuỗi interface/historical bytes, kiểm length/TCK trước routing.
- `ESPKFamily` dùng mask OpenSC 0.27.1 làm candidate; firmware/personalization
  biến thiên không cần thêm full ATR để được đọc. FastCA/EFY là issuer hint,
  `espk-discovery` đọc các personalization khác trong cùng họ. Cert issuer DER
  được dùng làm nhãn CA khi native discovery chưa biết nhà phát hành.
- Native transport xác nhận lại ATR/driver sau connect và public ESPK metadata,
  CKA_ID/public key/cert trước sử dụng identity. Tách quyền đọc và PIN contract:
  family candidate mới không tự được xác thực chỉ vì đọc được cert. Swift và C
  đều chặn auth khi chưa có mapping PIN contract; không gửi auth để dò profile.
- Unknown ATR hợp lệ ngoài họ native có thể được dò qua đúng bốn middleware
  PKCS#11 đã đăng ký (VNPT/NC-CA/CMC/I-CA), qua API public. Chỉ nhận target nếu
  module báo đúng reader vật lý; không fallback một slot không rõ tên. Driver
  thiếu được báo riêng; không tìm/nạp mọi dylib trên máy, không tự chạy installer.
  PIN/sign vẫn do middleware đã nhận thiết bị xử lý qua contract PKCS#11 hiện hữu.
  Việc private key ẩn tới sau login trong middleware là giới hạn API vendor,
  không được báo thành public preflight đã chứng minh key. CKA_ID và verify chữ
  ký hiện có vẫn giữ nguyên. Native ESPK có preflight public-key riêng nghiêm hơn.
- Cùng CA nhiều reader dùng chung snapshot module trong một scan, không quảng bá
  trùng target; native discovery được scope từng reader. Candidate metadata lỗi
  không làm mất thiết bị hợp lệ khi helper tìm đúng cardid. Không fallback sau
  lỗi đăng nhập hoặc ký.
- UI phân biệt chưa nhận diện, thiếu backend model, thiếu runtime, lỗi đọc,
  metadata không tương thích và chỉ đọc. OneCA V1 được nhận diện theo registry
  nhưng không tự nạp wrapper F3 có hành vi ghi cấu hình. OneCA V2 đi candidate
  ESPK; OneCA V3 giữ provider hash-pinned đã đo, không nhầm CA với OEM.
- Cert chỉ đọc không có trong inventory quảng bá cho portal; chooser không cho
  qua approval/PIN. Các bridge tiếp tục dùng broker/chooser chung.

### Coverage hiện tại và phần chưa chứng minh

| Issuer / dòng | Discovery | Xác thực/ký | Portal |
|---|---|---|---|
| FastCA ESPK 105239 | Đọc thật | Đã xác minh mẫu cũ; cert mẫu đã hết hạn | Chưa xác minh chung |
| FastCA ESPK 100631 | Đọc thật; user thấy trong app | Contract đã bật; chưa có ký mới trên chiếc này | Chưa xác minh |
| FastCA/EFY firmware mới trong mask | Family + metadata probe; fixtures offline | Chỉ đọc khi chưa map PIN contract; chưa có hardware coverage | Chưa xác minh |
| EFY ESPK 101139 | Đọc thật | User đã xác nhận Ký thử và verify OK | Chưa xác minh |
| OneCA V3 Longmai | Đọc thật trong app | Native ARM64 đã có chứng cứ ký; provider hiện giữ nguyên | Chưa xác minh chung |
| OneCA V1 Longmai | Nhận diện registry | Thiếu provider đã kiểm chứng, không tải F3 tự động | Chưa xác minh |
| OneCA V2 EnterSafe | Candidate ESPK theo registry, chưa đọc hardware mới | Chưa map PIN contract | Chưa xác minh |
| OEM khác qua PKCS#11 đã cài | Dò public, yêu cầu exact reader mapping | Dùng API middleware sau khi reader/cert được nhận; chưa suy coverage mọi model | Cần theo từng portal |

Đây là nền tảng để mở rộng theo provider/capability, chưa phải nghiệm thu “mọi
token của mọi hãng đều ký được”. Không có public metadata descriptor đủ để tự
map mọi ESPK personalization sang PIN scheme; các báo cáo family ghi rõ điểm
này. Chưa triển khai mọi OEM, EC/thuật toán mới hoặc model không có driver.

### Bằng chứng và kiểm chứng

[Source ledger đã rút gọn](re/evidence/token-family-sources-2026-10-24.json)
ghi mask/nguồn/hash/Evidence ID và ranh giới OEM/PIN. Các báo cáo chi tiết
FastCA/EFY/OneCA vẫn giữ local cùng raw analysis; không đẩy raw dump vendor lên Git.

Bản tích hợp đạt **182 Swift tests**, native C mock và bundle/smoke sáu cổng.
App đang đọc 4 chứng thư cho 4 reader hiện cắm, gồm FastCA 0631. Agent không
nhập PIN, xác thực hoặc ký trong lượt này. [Evidence tích hợp](re/evidence/token-compatibility-2026-10-24.json).

Kết quả fixture synthetic không được dùng để tuyên bố số lượng thiết bị thực đã
hỗ trợ, hoặc suy rằng mọi model mới đều có thể xác thực/ký/được portal chấp nhận.
