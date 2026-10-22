# Một lần ký Minvoice qua relay loopback

Mục tiêu: user tự ký đúng một hóa đơn bằng plugin Windows đã cài; thu download ZIP,
signed XML multipart và schema response upload. Đây là **controlled relay**, không
phải capture thụ động của giao dịch nguyên trạng: chỉ BrowserInfo.LinkApi của một
lệnh SignInvoices được đổi sang HTTP loopback. Relay cố định upstream HTTPS
`api-hddt.minvoice.com.vn`, giữ method/path/body và session headers cần thiết;
không tự gọi login, ký hay phát hành khi không có request từ plugin.

Không cài root CA, sửa trust store, proxy hệ thống, plugin config/binary hoặc USB.
Source relay do analyst viết, không load assembly vendor. Listener chỉ ở
`127.0.0.1:17080` trong Windows và cần prefix nonce ngẫu nhiên của phiên.
Chặn route ngoài allowlist, redirect upstream, body >32 MiB, request framing mơ hồ,
login thứ hai và upload thứ hai. Relay hết hạn sau 4 giờ; request đang xử lý được
chờ hoàn tất. Không tự retry upload khi lỗi. Đây là thay đổi có giới hạn về
transport; không dùng kết quả để tuyên bố đã quan sát TLS/header compression của
plugin khi gọi trực tiếp API.

## Chuẩn bị đã kiểm tra

- [Relay C#](../../scripts/re/MinvoiceCaptureRelay.cs), source SHA-256
  `ae0de3a563dbe08786e4db79a4517a8f02d185aca26ab8860426afb755280c55` (v3).
- Compile .NET Framework x86 trên Windows hiện có; exe SHA-256
  `a474c352b02c511487c8fa8af4182bf19084fac95f8558192280f46152ef0f72` (v3).
- Self-test dùng HttpMessageHandler giả, không external network: route allowlist,
  mock forwarding, chunked framing, chặn Content-Length + Transfer-Encoding,
  response shape và redaction đều đạt.
  Từ v2, test gửi raw HTTP với `x_req_id` qua frontend và xác nhận mock upstream nhận
  được header này; không gọi API thật trong self-test. V3 còn kiểm tra health
  GET/OPTIONS không gọi upstream, CORS health, near-expiry và ready=false sau login.
- [Hook template](../../scripts/re/minvoice-capture-hook.js) và
  [tests](../../scripts/re/minvoice-capture-hook.test.mjs): WebSocket/XHR,
  đúng một command/một invoice, fixed API origin, callback redaction, restore,
  giữ nguyên traffic không liên quan đều đạt bằng Node. V3 thêm kiểm tra readiness
  trước cài hook/trước gửi, chặn relay hết hạn/đã dùng, reservation đồng thời, XHR
  đã abort, và restore trong khi chờ health; không gửi command khi kiểm tra lỗi.
  Template còn có `__CAPTURE_PAGE_ORIGIN__`, chỉ điền đúng tenant origin đã quan sát.
  Screenshot đầu tiên cho thấy trang `minvoice.net` bị guard cũ chỉ nhận
  `minvoice.com.vn` chặn trước khi hook được cài. Đã sửa cho đúng origin riêng của
  phiên; không mở wildcard toàn bộ `minvoice.net`. Bundle công khai của trang,
  `main.99bcd98f.js` SHA-256
  `de7ee581ea758146b546aa7d92a5ca2661c4adc1be3947e5ab1ba68363ac7b53`,
  vẫn dùng LinkApi/hub/processMessage/callback như contract nghiên cứu trước.
  [Preparation evidence](evidence/minvoice-capture-preparation.json) giữ source
  hashes, offsets và REA parent ID; semantic graph bị giới hạn nên không dùng để
  suy vắng mặt tính năng.
- Plugin được kiểm tra lại trước capture: PID 10248, version 1.0.3.0, SHA-256
  `4e891736c97f593f4306f56ce645f039ac91aa3e54ed01d81cb7b822093331e0`.
  Không bỏ qua kiểm tra minimumPluginVersion của trang; nếu trang yêu cầu cập
  nhật thì dừng và định danh lại build sau khi user tự xử lý.

## User thao tác

1. Trong **Windows**, mở đúng trang Minvoice đang có hóa đơn user chủ động muốn
   ký. Chọn đúng một hóa đơn; chưa bấm ký.
2. Mở DevTools → Console. Dán **bản hook đã điền địa chỉ của phiên**, không dùng
   template có `__CAPTURE_API__`; bản hiện tại ở file private
   `.local/minvoice-windows-2.0/capture-browser-hook.js` trên Mac. Chạy script.
   Console phải báo `TokenSigner capture armed for one invoice: connection verified`.
   Nếu báo `NOT armed`, không bấm ký; kiểm tra relay/đúng tenant và chuẩn bị lại.
   Hook dùng GET `/status` với credentials omitted, timeout 5 giây, không redirect.
   Kiểm tra này còn được thực hiện ngay trước khi gửi lệnh ký; relay cần còn hạn
   ít nhất 60 giây và chưa nhận login nào.
3. User tự bấm ký một lần. Console cần báo `connection verified; one user-initiated SignInvoices command routed through loopback` trước khi user tiếp tục nhập PIN. Nếu không có dòng này,
   hủy prompt PIN nếu có và báo lại; không bấm thử nhiều lần.
4. User tự nhập PIN trong dialog Windows. Agent không bấm ký/phát hành hay nhập
   PIN. Console chỉ in code/command/status của callback, không raw payload.
5. Báo kết quả màn hình. Hook tự restore sau callback hoặc trước khi relay hết hạn 60 giây; có thể
   chủ động gọi `TokenSignerCapture.restore()` hoặc reload trang. Không tự ký lại
   khi timeout/lỗi, vì trạng thái server có thể đã thay đổi.

## Evidence và bảo mật

Descriptor của phiên ở `.local/minvoice-windows-2.0/active-capture.json`, mode 0600,
giữ PID/start time, nonce, guest output directory và hạn phiên; không đưa lên Git.
Guest output root `%LOCALAPPDATA%\TokenSignerMinvoiceCapture` có ACL riêng cho user
hiện tại và SYSTEM; từng run dùng thư mục mới. Không ghi password, Cookie,
Set-Cookie, XSRF hoặc Authorization vào events.jsonl, kể cả giá trị hash của chúng.
Response JSON chỉ giữ key/type; chỉ whitelist numeric code/errorCode và boolean
status/success/isError. Error chỉ ghi exception type, không ex.Message.

Chỉ giữ raw body ZIP download và signed XML multipart upload. Hai artifact này có
thể chứa thông tin hóa đơn/chứng thư thật nên ở private capture folder, không đưa
vào báo cáo/commit. Events ghi hash của hai artifact, route template bỏ invoice
GUID/serial query values, status, byte lengths và header-presence booleans.
Frontend response Set-Cookie/body vẫn được chuyển nguyên cho plugin trong bộ nhớ.

Sau user thao tác: kiểm tra run có đủ login/bootstrap/download/upload và callback,
copy artifact vào `.local` mode 0600, inventory/hash trước khi đọc; đối chiếu XML
với fixture nghiên cứu trước và verify độc lập. Báo cáo dùng schema đã che thông
tin, giữ rõ giới hạn relay, build/hash và chưa xác định retry/partial-batch.

Chưa có giao dịch hóa đơn thật trong self-tests. Không tuyên bố capture thành công
chỉ từ READY hoặc kiểm tra socket.

## Lần user thao tác lúc 19:54 ngày 22/10/2026

[Live status đã che thông tin](evidence/minvoice-first-live-status.json) lưu 7
records, SHA-256 events nguyên bản đã lọc
`13e5f453ba0789b9332f27d36e8839e0ec5924533eec75f7d16fe9c5a7d28198`.
Sáu request trả HTTP 200: login, application-configuration, current-tenant,
token/by-serial-number hai lần, invoice detail. Record kế tiếp báo
InvalidDataException với route=null. Không có record download/upload, ZIP hay
signed multipart trong run này. HTTP 200 login không khôi phục giá trị numeric
`result` vì capture v1 chỉ giữ type; không diễn giải thành trạng thái nghiệp vụ.

Đã xác định defect trong source relay v1: regex tên header chỉ cho chữ/số/dấu `-`,
trong khi plugin thêm `x_req_id` trước download. Predicate cũ trả false cho header
này trên Windows .NET, predicate v2 trả true; test raw HTTP v2 forward thành công.
Đây là giải thích có căn cứ mạnh cho lỗi record cuối, nhưng header bị từ chối của
giao dịch cũ không được lưu nên không gọi đó là header observation trực tiếp.

V2 cho phép `_` và ghi stage khi thất bại (request-line, request-headers, route,
request-body, upstream, response-body, response-forward), vẫn không ghi giá trị
header/ex.Message. Bản v1 dùng source hash `072b4818...8075dbd`, exe hash
`926a40fc...7dbf14`; identity đầy đủ ở preparation evidence cũ. Phiên v1 hết hạn
lúc 20:14:24; không suy backend down từ việc process relay đã dừng.

Trước một lần thử tiếp, user reload danh sách để kiểm tra trạng thái hóa đơn và
xóa hook cũ, rồi dùng script theo nonce phiên mới. Agent không tự query nghiệp vụ
bằng credential, không tự retry ký hoặc upload để xác minh trạng thái.

## Lần user thao tác lúc 21:04 ngày 22/10/2026 và sửa v3

Relay v2 hết hạn UTC 13:59:45.4400535, tức **20:59:45 ngày 22/10** tại
Asia/Ho_Chi_Minh. Ảnh user lúc 21:04 hiện dialog “One or more errors occurred”.
Kiểm tra guest xác nhận relay đã dừng, plugin Minvoice vẫn chạy, không có
`events.jsonl`, ZIP hay upload artifact trong run v2. Không có bằng chứng request
nghiệp vụ của lần thử này đã tới relay hoặc backend. Dòng console “routed” của
hook cũ chỉ chứng minh lệnh đã được rewrite; không chứng minh HTTP relay sẵn sàng.
Cảnh báo Permissions Policy `unload` không đủ để xác định nguyên nhân backend.

V3 dùng thời hạn 240 phút và health GET/OPTIONS chỉ tại đúng nonce `/status`.
CORS wildcard chỉ áp dụng health endpoint không có credential và không gọi
upstream; business routes không được cấp CORS này. Health trả ready=false sau
login đầu tiên, khi stopping hoặc còn dưới 60 giây. Hook yêu cầu đúng tenant
origin, xác nhận health trước khi cài và ngay trước khi chuyển lệnh SignInvoices.
Nếu health lỗi/hết hạn/đã dùng, hook không gửi lệnh, in thông báo cố định, restore
và đóng socket hoặc abort XHR. Hai lệnh cạnh tranh bị chặn bởi reservation được
đặt đồng bộ trước await; không gửi lệnh thứ hai qua upstream gốc. XHR đã abort
hoặc hook đã restore trong lúc chờ health sẽ không được gửi tiếp.

Các kiểm thử offline không chứng minh browser thật sẽ cho phép fetch loopback
từ trang HTTPS: chính sách CSP/Local Network Access của browser có thể chặn.
Trường hợp đó script báo NOT armed trước khi gửi lệnh ký, giữ chẩn đoán an toàn.
Tại thời điểm chuẩn bị v3 chưa có giao dịch ký thật thành công được thu đủ ZIP/upload/callback.

## Capture thành công lúc 00:24 ngày 23/10/2026

[Live cash evidence](evidence/minvoice-live-cash-success.json) lưu tám response
hoàn tất: bootstrap/detail đều 200, cash ZIP download 200, upload 204/body rỗng.
User xác nhận UI báo ký thành công. ZIP có một XML, signature thật verify bằng
xmlsec1 trên Mac; sửa riêng invoice data, SigningTime hoặc SignatureValue trong
ba bản sao offline đều bị từ chối. Profile cash khớp static/replay. Chưa có raw
callback envelope hoặc callback summary từ console; không yêu cầu ký lại để thu.

Raw hóa đơn/certificate/multipart và log verify giữ private mode 0600. Báo cáo
chỉ có route template, schema, byte lengths, hashes và cấu trúc XML không chứa
identity/value. Sau khi copy/hash và xác nhận upload đã hoàn tất, relay phiên này
được dừng; plugin Windows vẫn chạy. Script/nonce cũ không còn dùng để ký thử tiếp.
