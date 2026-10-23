# Capture MISA KYSO trên Windows — meInvoice / AMIS

Mục tiêu: xác nhận giao thức thật của **meInvoice và AMIS** trước khi làm adapter
macOS. Phân tích bộ cài đã thấy WebSocket `/plugin`, với các cổng ứng viên
`11984, 11985, 12680, 12681, 12683, 11994, 11995, 12690`. Đây là kết luận từ
mã tĩnh, chưa phải endpoint quan sát trên máy của bạn.

## Một lần thử ngắn

1. Dùng MISA KYSO đang cài trên Windows và USB token của bạn. Chọn môi trường
   thử hoặc chứng từ thử; không phát hành/gửi hồ sơ thật để lấy capture.
2. Mở meInvoice hoặc AMIS trong Chrome/Edge. Bấm **F12 → Network**, bật
   **Preserve log**, chọn bộ lọc **WS**. Mở DevTools trước thao tác đọc chứng thư.
   Nếu chưa thấy kết nối, tải lại trang khi DevTools đang mở.
3. Vào thiết lập ký số / chọn **ký trực tiếp qua USB**, thực hiện đọc/chọn chứng
   thư. Trong Network tìm kết nối `...:<một cổng trên>/plugin`. Ghi lại:
   URL WS đầy đủ (scheme, host, port, path), `Origin`, status handshake và
   phiên bản MISA KYSO đang chạy. Không cần gửi các header khác.
4. Mở mục **Messages** (hoặc Frames). Ghi tên `action` cùng request/response
   của bước đọc chứng thư. Sau đó tự ký **một dữ liệu thử** và ghi thêm cặp
   request/response của bước ký. Bạn tự nhập PIN trong hộp thoại Windows.
5. Gửi kết quả tại luồng **Misa**. Trước tiên chỉ cần URL portal + WS, tên
   `action`, phiên bản, thành công/lỗi và các trường có trong JSON. Không cần
   gửi file HAR hay toàn bộ log trình duyệt.

Nếu không có môi trường ký thử, chỉ làm đến bước đọc chứng thư và gửi thông
tin kết nối/tên lệnh; dừng trước nút phát hành/nộp hồ sơ thật. Không cần cài
proxy, chứng chỉ chặn TLS hoặc chạy installer chỉ để capture.

## Thông tin cần giữ khi che dữ liệu

Giữ đúng tên khóa, kiểu giá trị, mảng/object/null, `action`, `productName`,
`DocumentType`, `HashAlgorithm`, `SignatureAlgorithmName`, `is91Circular`,
`isSignTT68`, `isSignTT32`, `status`, `code`, `SettingAlgorithm`. Giữ cấu trúc
`files`, `metaData`, `HashToSigns`, `data` và `data_info`; thay giá trị nhạy cảm
bằng nhãn `<redacted>` và ghi độ dài riêng nếu cần.

Che tên/MST/serial/chủ thể chứng thư, `sessionId`, `sellerInfo`, `buyerInfo`,
đường dẫn máy và nội dung chứng từ thật. Không gửi PIN/mật khẩu, cookie,
Authorization/Bearer token, private key/PFX. Trường `DataAfterCallback` hoặc
metadata có thể chứa dữ liệu nghiệp vụ/credential dù tên trường không nói rõ.
Không gửi log nội bộ của MISA KYSO: cấu hình bộ cài cho thấy có các tùy chọn
log request/XML và chúng chưa được kiểm tra mức độ che dữ liệu.

Để kiểm tra XML/crypto sau đó, cần một cặp **XML đầu vào/đầu ra tổng hợp** và
đúng JSON của ca thử. Việc sửa nội dung XML đã ký để che dữ liệu sẽ làm chữ ký
không còn xác minh được. Với tài liệu thật, chỉ gửi cấu trúc đã che; chưa dùng
nó làm fixture kiểm tra chữ ký. Không xuất khóa riêng.

## Đối chiếu process/listener (tùy chọn, chỉ đọc)

Nếu Network không rõ cổng nào, chạy đoạn sau trong PowerShell thường. Nó chỉ
đọc listener thuộc tám cổng ứng viên, tên process, phiên bản và hash executable;
không đọc document/PIN, không khởi động hay dừng process, không cần quyền admin.

```powershell
$misaPorts = @(11984,11985,12680,12681,12683,11994,11995,12690)
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $_.LocalPort -in $misaPorts } |
  ForEach-Object {
    $misaConnection = $_
    $misaProcess = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    $misaHash = $null
    $misaVersion = $null
    try {
      if ($misaProcess.Path) {
        $misaHash = (Get-FileHash -LiteralPath $misaProcess.Path -Algorithm SHA256 -ErrorAction Stop).Hash
        $misaVersion = $misaProcess.FileVersionInfo.FileVersion
      }
    } catch { }
    [pscustomobject]@{
      LocalAddress = $misaConnection.LocalAddress
      LocalPort = $misaConnection.LocalPort
      PID = $misaConnection.OwningProcess
      ProcessName = $misaProcess.ProcessName
      FileVersion = $misaVersion
      SHA256 = $misaHash
    }
  } | ConvertTo-Json -Depth 3
```

Giá trị version/hash trống nghĩa là không đọc được quyền/metadata tương ứng,
không phải version 0. Danh sách trống chỉ nói tám cổng này không được quan sát
lúc chạy lệnh; không chứng minh không có MISA KYSO hay không có cơ chế khác.

Mẫu trả lời:

```text
Portal: meInvoice / AMIS + URL (bỏ query/token)
MISA KYSO version + executable SHA256 nếu đọc được:
WebSocket URL + Origin + status:
Đọc chứng thư action / kết quả:
Ký dữ liệu thử action / DocumentType / thuật toán / kết quả:
JSON đã che dữ liệu hoặc cấu trúc các trường:
```
