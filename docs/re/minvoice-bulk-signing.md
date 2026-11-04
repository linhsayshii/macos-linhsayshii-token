# Ký lô Minvoice với số lượng thay đổi, mục tiêu 300 hóa đơn/lần

User cho biết thỉnh thoảng cần ký khoảng **300 hóa đơn/lần**. Số 3 trong capture
trước là cỡ mẫu đã thử, không phải giới hạn nghiệp vụ. Phân tích này áp dụng cho
Windows plugin **1.0.3.0**, SHA-256
`4e891736c97f593f4306f56ce645f039ac91aa3e54ed01d81cb7b822093331e0`,
MVID `00bd5b9b-4c09-43d5-a226-01047473e217`.

## Kết luận và mức bằng chứng

- **Đã chạy thật:** cash 1 và 3 hóa đơn. Lô 3: một ZIP entry TDiep chứa ba HDon,
  một chữ ký bao phủ DLieu, một multipart part, upload 204/body rỗng; user xác
  nhận cả ba đổi trạng thái. [Báo cáo](minvoice-batch-live-capture.md).
- **Code tĩnh của đúng build:** cash chia nhóm 100; ordinary lấy Value từ
  tenant-setting-sign, dùng 2 nếu response null. Không có giới hạn tổng bằng 3
  hoặc 100 trong worker/loop/helper đã chọn. Không suy không có giới hạn ở UI,
  backend, timeout, bộ nhớ hoặc các lớp khác.
- **Mô hình offline:** 300 cash → [100,100,100], ba lượt download/ký/upload tuần
  tự nếu các lượt thành công và có document để gửi. Không có giao dịch 300 hóa
  đơn thật trong nghiên cứu này; chưa đo năng lực tải hay thời gian thực tế.
- Số document/chữ ký không cố định bằng số hóa đơn hay số nhóm: phải xử lý toàn
  bộ XML backend trả về cho từng nhóm. Không suy mỗi nhóm 100 chắc chắn chỉ có
  một XML từ sample nhóm 3.

## Thuật toán tổng quát

`bgwProgress_DoWork` 0x060003d0 lấy toàn InvoiceIdArray, bỏ qua array rỗng,
đổi thành danh sách SignedInvoice, lấy detail **hóa đơn đầu tiên** để chọn cash
hoặc ordinary. Không thấy kiểm tra tất cả serial/profile trong worker này;
không dùng điều đó để tuyên bố batch trộn mẫu/ký hiệu được hỗ trợ.

`ChunkBy` 0x06000268 dùng indexed Select, GroupBy rồi ToList; lambda
0x0600044b lấy Index chia nguyên cho chunkSize. Các lambda 0x06000447/448/449
bảo toàn thứ tự giá trị trong từng nhóm. Với n >= 0 và k > 0, nhóm i gồm các
index thỏa floor(index/k)=i; số nhóm là ceil(n/k). ChunkBy materialize danh sách
nhóm trước vòng lặp, không phải pipeline ký/upload song song.

`SignInvoiceCash` 0x060003d2, IL_0002 đặt 100. `SignInvoice` 0x060003d1 gọi
`GetNumberFileGroup` 0x060003dd: default 2, GET cấu hình 0x0600007c, nếu có response
thì Convert.ToInt32(Value). Không có clamp/fallback cho Value sai/0 trong method
này; lỗi HTTP/parse có thể thoát. Không áp dụng giá trị ordinary cho cash.

```text
Một SignInvoices với n invoice IDs
  → login/bootstrap/tenant/token và detail đầu danh sách
  → chia nhóm theo profile
  → với từng nhóm, tuần tự:
      kiểm tra CancellationPending
      POST download-xml[-invoice-cash] với GUID array của nhóm
      đọc tất cả XML trong ZIP; ký từng XML theo profile
      POST Guid.Empty/upload-xml chứa các XML trả về đã ký
      chờ kết quả; ReportProgress; Sleep(800ms)
  → kết thúc worker; trả một kết quả command
```

Vòng cash: Exec IL_0038, Upload IL_0042, Task.Result IL_0047, Sleep IL_0063;
ordinary tương ứng IL_0040/004a/004f/006b. Một nhóm hoàn tất transport rồi mới
bắt đầu nhóm sau. Có khoảng nghỉ cố định 800ms sau mỗi nhóm; không dùng nó để
ước lượng tổng thời gian ký vì network/token/server còn chưa đo.

| Số hóa đơn cash | Nhóm theo code |
|---:|---|
| 99 | 99 |
| 100 | 100 |
| 101 | 100 + 1 |
| 200 | 100 + 100 |
| 201 | 100 + 100 + 1 |
| 300 | 100 + 100 + 100 |
| 301 | 100 + 100 + 100 + 1 |

Ordinary 300 với default k=2 → 150 nhóm; nếu tenant trả k khác thì tính lại.
Đây là suy ra từ code, không phải khuyến nghị sửa cấu hình tenant hay cam kết
backend hỗ trợ một số lượng cụ thể.

## Lỗi, hủy và trạng thái từng nhóm

- Download nằm trước vùng catch ký của ExecSignInvoice/ExecSignInvoiceCash
  0x060003db/3dc. Download throw → worker lỗi, không đi tiếp nhóm sau trong loop.
- Lỗi ký bên trong vùng try của bản 1.0.3.0 → gọi delete-cache cho nhóm request;
  nếu cleanup thành công thì catch **nuốt lỗi**, trả danh sách document đang có.
  Loop có thể tiếp tục gọi upload, gồm document chưa được ký hết. Nếu cleanup
  throw thì lỗi thoát ra. Đây là hệ quả control flow, chưa cố tình gây trên live.
  Không sao chép hành vi này vào TokenSigner: bất kỳ sign/verify lỗi phải dừng
  trước upload của nhóm đó.
- Upload throw → Task.Result throw, worker lỗi, không đi tiếp nhóm sau. Nếu nhóm
  1 đã upload rồi nhóm 2 lỗi, không có rollback nhóm 1 trong các đường đã chọn.
  Trạng thái nhóm 2 có thể không chắc chắn nếu mất kết nối sau server nhận body;
  không tự gửi lại cả lô hay nhóm chưa rõ kết quả.
- `btnCancel_Click` 0x060003ce chỉ gọi CancelAsync. Loop kiểm tra giữa các nhóm;
  không có lệnh abort WebClient/HTTP/token giữa chừng trong nhánh cancel đã chọn.
  Nhóm đang làm có thể hoàn tất trước khi bỏ nhóm kế tiếp.
- `RunWorkerCompleted` 0x060003d8 chỉ chuyển Error vào field `_error`, không đọc
  Cancelled. Business state machine 0x06000483 đặt Status=true nếu Error null.
  Vì vậy callback thành công **có thể** đi cùng việc user hủy giữa các nhóm;
  chưa quan sát trường hợp đó trên portal. Không dùng callback đơn để khẳng
  định toàn bộ n hóa đơn đã hoàn tất.
- Cờ bool từ UploadMultiFilesXml không được dùng để điều khiển loop. Method
  0x060004bc trả false khi list document rỗng, true sau upload hoàn tất; không
  parse phản hồi thành kết quả từng hóa đơn.
- Progress code không phải bộ đếm nghiệp vụ đáng tin: ordinary truyền
  `1 + requestedGroup.Count`; cash truyền `1 + returnedDocuments.Count` vào
  ReportProgress, biến khởi tạo 1 không tăng trong loop. Đây là phân tích tĩnh,
  không phải quan sát UI progress live.

## Đối chiếu phần mềm macOS hiện tại và việc cần tích hợp

Tại thời điểm nghiên cứu, `Sources/Bridges/MinvoiceInvoices.swift` vẫn có guard
`InvoiceIdArray.count == 1`, nên **chưa hỗ trợ 300**. Báo cáo nghiên cứu không
đồng nghĩa tính năng đã được bật trong app.

1. Bỏ giới hạn một invoice theo một giới hạn tài nguyên công khai của app;
   nhận toàn bộ danh sách, kiểm tra rỗng/trùng/profile trước xử lý.
2. Một phiên được user duyệt cho danh sách/certificate cụ thể; giữ signing lock,
   auth/session/PIN trong phiên theo cơ chế hiện có, không hỏi duyệt lặp lại
   từng invoice một cách không cần thiết. Hủy phải được phản ánh thành hủy.
3. Cash lập lịch k=100; ordinary triển khai riêng theo cấu hình đã kiểm tra và
   profile XML ordinary khi đủ bằng chứng. Không hardcode 300 hoặc 3.
4. ZIP reader phải hỗ trợ nhiều entries; một entry TDiep có thể chứa nhiều
   HDon. Ký/verify toàn bộ document của nhóm trước upload multipart của nhóm.
   Không ép ZIP entry GUID bằng tập requested invoice GUID. Mapping từng request
   GUID → HDon chưa được lưu trong capture và còn là giới hạn bằng chứng.
5. Theo dõi group index, requested IDs trong bộ nhớ/metadata được bảo vệ,
   số invoice đã gửi, document đã ký, upload đã xác nhận, nhóm lỗi/chưa rõ/chưa
   chạy. Không lộ identity/credential vào diagnostic; không báo 300/300 chỉ từ
   số chữ ký hay callback code=1.
6. Với 300 cash, test mock có đúng ba download body lần lượt 100 IDs, đúng thứ
   tự, upload nhóm trước kết thúc trước download nhóm sau; XML aggregate và
   nhiều ZIP entries; lỗi tại nhóm 2; cancellation giữa nhóm; timeout upload;
   không tự retry/rollback. Test ordinary riêng, không ép vào cash profile.

## Kiểm tra offline và bước live còn thiếu

- [Control-flow projection](evidence/minvoice-bulk-control-flow.json): 19 method
  có raw IL hash kiểm tra lại trên đúng binary. REA source
  `ev_aa5ce6721cdf82aa7c141d7db7e2a0a312e6a082c157ebf161ee25a28e559708`;
  helper bổ sung `ev_6282aae497cf4e5f2b8c56ba7bf9be4c350219bd3b27394cae17904f6503afcb`.
- [Model](../../scripts/re/model-minvoice-bulk-flow.py) kiểm tra 7175 cặp n/k,
  gồm n=0..1024 với k=1,2,3,7,99,100,128, bảo toàn thứ tự/không mất/trùng index;
  kiểm tra riêng 10000, các biên 100/101/200/201/300/301 và fault scenarios.
  [Kết quả](evidence/minvoice-bulk-model-results.json) ghi rõ đây là analyst model,
  không chạy vendor code/network/chữ ký thật.
- Capture hook đã tổng quát hóa số lượng, tests WS với 2,3,10,99,100,101,200,201,
  **300**,1000 đều giữ nguyên mọi GUID và chỉ chuyển một command. Health count
  phải khớp số user chọn; lệnh gửi sai số hoặc GUID trùng bị chặn. Giới hạn
  capture 2–10000 và body 32MiB là **chính sách công cụ analyst**, không phải
  giới hạn Minvoice. Self-test relay .NET x86 đạt, không network ngoài.
- Chưa chạy giao dịch thật trên 100 hóa đơn; cần user có lô thực sự muốn ký để
  đối chiếu các lượt thực, kích thước ZIP/multipart, thời gian, cancellation và
  kết quả từng nhóm. Không yêu cầu ký/phát hành 300 hóa đơn chỉ để thử nghiệm.
  Không cố tình gây lỗi/đứt mạng trên lô thật để đo rollback.
- Relay live cũ đã dừng. Đợt mới phải có nonce và hook mới cho **đúng số hóa đơn
  và tenant hiện tại**; không dùng lại clipboard/descriptor của lô 3.


## Bổ sung thử thật trên macOS ngày 23/10

User xác nhận lô **2 hóa đơn** đã ký thành công trên Minvoice từ app Mac.
Audit app có Minvoice RSA_PKCS result=ok lúc17:19:36 Asia/Saigon. Xem
[evidence](evidence/minvoice-macos-live-batch-2.json). Audit chỉ xác nhận thao tác
ký, không lưu số invoice hoặc upload ACK; thành công cả lô/số2 là user xác nhận
trên portal. Không có XML/network capture của giao dịch này, không suy đã thử
live300 hoặc nhóm thứhai. Lỗi DNS -1003 trước đó chưa xác định nguyên nhân chỉ
nhờ lần thành công sau.
