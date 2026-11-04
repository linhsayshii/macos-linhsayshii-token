# Bàn giao tích hợp Minvoice và FastCA — 23/10/2026

Người dùng yêu cầu báo cáo về chat chính “Tiếp tục phần còn lại của dự án” và
nhắn chat đó tiếp tục hai nhiệm vụ: tích hợp Minvoice plugin và FastCA vào
TokenSigner. Chat nghiên cứu không tự merge/checkout hoặc ghi đè các thay đổi
chung; báo cáo này và evidence đã có trong cùng workspace để chat chính tiếp quản.

## 1. Minvoice: đã có capture thật để triển khai

- Plugin Windows đang cài/chạy là **1.0.3.0**, SHA-256
  `4e891736c97f593f4306f56ce645f039ac91aa3e54ed01d81cb7b822093331e0`.
  Không nhầm web app 2.0 với assembly version, hay artifact 1.1.1.0 cũ.
- User tự thao tác ký một hóa đơn cash lúc 00:24 ngày 23/10 (giờ Việt Nam).
  Relay ghi tám response hoàn tất: login/bootstrap/token/detail HTTP 200,
  `POST /api/app/release-invoice/download-xml-invoice-cash` 200,
  `POST /api/app/release-invoice/00000000-0000-0000-0000-000000000000/upload-xml`
  **204, body rỗng**. User xác nhận Minvoice báo ký thành công.
- ZIP có một GUID.xml; multipart field `files`, filename trùng ZIP entry,
  Content-Type `text/xml`. XML thật verify độc lập bằng xmlsec1 trên macOS đạt.
  Sửa riêng invoice data, SigningTime hoặc SignatureValue trong ba bản sao offline
  đều bị từ chối. Profile live khớp phân tích tĩnh và replay .NET.
- Cash XML: root TDiep; signature ở TDiep/CKSNNT; reference document trỏ DLieu Id
  bằng entry GUID; reference thứ hai #signtime. Inclusive C14N, RSA-SHA256,
  SHA256 digest; document transforms enveloped-signature rồi C14N. Object thuộc
  namespace XMLDSig, SignatureProperties/SignatureProperty/SigningTime không
  namespace; Target="#signtime". KeyInfo gồm X509SubjectName + X509Certificate,
  không RSAKeyValue. Id đã có trong unsigned XML của sample này.
- Đây là controlled relay thay LinkApi đúng một command user khởi tạo, không phải
  passive TLS capture. Không tự ký/login/PIN hoặc gọi API nghiệp vụ để nghiên cứu.
  Relay đã dừng sau capture; script/nonce cũ không dùng lại. Raw invoice/cert/log
  verify chỉ ở `.local/minvoice-windows-2.0/live-v3`, mode riêng tư và ignored.
- Chưa thu callback envelope thực; casing vẫn từ CIL/web bundle. Chưa có live
  ordinary HDon/BKe, batch/partial failure/cancel hay upload idempotency. Không
  khẳng định những phần này đã hoạt động chỉ từ single cash invoice.

Nguồn cần đọc:

- `docs/re/minvoice-windows-2.0.md`: contract, method/IL/REA IDs và live profile.
- `docs/re/evidence/minvoice-live-cash-success.json`: evidence đã che thông tin.
- `docs/re/evidence/minvoice-live-cash-manifest.json`: integrity các file đợt live.
- `docs/re/minvoice-rest-static.md`: so sánh build cũ/contract REST.
- `docs/re/minvoice-live-capture.md`: phạm vi relay, hai lần lỗi trước và lần thành công.

Việc triển khai: kiểm tra lại bridge tại worktree
`.claude/worktrees/beautiful-shirley-8acdc0`, branch `claude/beautiful-shirley-8acdc0`
(snapshot b472572), tái dùng getVersion/TokenInfo/SignalR và request builder.
Nối dispatch SignInvoices → session REST → download ZIP giới hạn an toàn →
Minvoice XMLDSig profile riêng → chọn đúng chứng thư/khóa → approval/PIN → ký
DigestInfo SHA256 bằng backend token → verify → upload → callback đúng correlation.
Không nối thẳng generic XMLDSigSigner hiện tại vì namespace/time/KeyInfo khác.
Không tự retry upload hoặc coi HTTP 200 chung chung là business success. Không
lưu credential/raw response nghiệp vụ. Phần chưa được live xác nhận cần tests và
trạng thái hỗ trợ rõ ràng, không báo hoàn tất toàn bộ Minvoice quá sớm.

Ghi chú cũ trong `docs/agent-prompt-remaining.md` rằng chưa có endpoint/cần DevTools
page trước đã lỗi thời; dùng evidence mới, không tiếp tục coi cash capture là blocker.

## 2. FastCA: đã tích hợp local, cần tiếp quản và kiểm thử cùng Minvoice

Chat “FastCA” xác nhận hoàn tất tích hợp vào app, không còn chỉ là prototype.
Bằng chứng và source đã ở checkout gốc branch `p1-token-core` (HEAD 626f70e) dưới
các thay đổi chưa commit; giữ nguyên và rà soát trước khi gộp/commit, không reset.

- Backend native ESPK/OpenSC 0.27.1 trong TokenHelper, không route FastCA qua
  generic libcastle. Đọc catalog, ghép chứng thư/khóa bằng CKA_ID/public key;
  không hardcode FID/thumbprint của harness.
- Approval/PIN hiện có; stdin pipe; một authentication/một signature, không
  tự retry. Helper và AppModel verify bằng chứng thư đã duyệt.
- User đã ký qua menu và SignHash local: chữ ký RSA2048 dài 256 B, OpenSSL
  `Verified OK`. Build và **38 tests đạt** trong đợt FastCA; đây là kết quả đã
  ghi nhận của chat đó, không phải lần chạy lại của chat nghiên cứu Minvoice.
- Chưa xác nhận hotplug/nhiều token FastCA, portal, certificate còn hạn hay gói
  runtime/notarization. Certificate FastCA hiện tại hết hạn 30/07/2026; kết quả ký
  mật mã không chứng minh portal chấp nhận. Chưa có end-to-end Minvoice macOS +
  backend FastCA; không gộp kết quả Windows Minvoice với kết quả FastCA Mac thành
  một phép thử chưa diễn ra.

Nguồn cần đọc: `docs/FASTCA.md`, `docs/re/fastca-native-signing.md`,
`docs/re/evidence/fastca-app-signing-validation.json`,
`docs/re/evidence/fastca-app-tests.txt`, `docs/TEST-ENVIRONMENT.md`.

Việc tiếp tục: tiếp quản thay đổi FastCA vào tuyến tích hợp chính, giữ routing các
CA khác, nối chọn serial chứng thư/token/CKA_ID đúng cho Minvoice, kiểm thử hồi quy
menu/SignHash/approval/cancel/PIN/sai chứng thư và XML verify-before-upload. Kiểm tra
cấu hình/runtime và đóng gói phát triển; liệt kê riêng phần phân phối còn thiếu.
Không yêu cầu ký hóa đơn thật để thay cho các bước triển khai/offline tests có thể
làm ngay. Nếu cần live validation, chuẩn bị xong rồi user tự thao tác/PIN.

## Điều phối và nghiệm thu

Repo có nhiều worktree và thay đổi chưa commit của các chat. Không build/test đồng
thời cùng worktree; kiểm tra git status trước khi tích hợp. Không ghi đè file người
dùng hoặc stage/commit toàn bộ working tree thiếu rà soát. Không cần tạo chat mới.
Chat chính tiếp tục cả hai nhiệm vụ, báo kết quả cụ thể: thay đổi, tests, tích hợp
nào đã live xác nhận và giới hạn còn lại. Việc gửi báo cáo không có nghĩa mã đã được
merge vào branch Git chính hoặc hai tích hợp đã hoàn tất.

Giữ PIN ngoài chat/log/argv/đĩa; không auto-sign, chỉ bind 127.0.0.1, không thêm
filePath tùy ý hoặc chạy installer vendor. Không đổi USB/middleware/trust/proxy
âm thầm. Dùng current user authorization để thực hiện công việc đã giao.


## Bổ sung nghiên cứu ký lô lúc 09:59 ngày 23/10

User đã ký thành công lô ba hóa đơn cash cùng mẫu/ký hiệu, xác nhận cả ba đổi
trạng thái. Backend nhận download array 3 GUID nhưng trả **một TDiep có ba HDon**;
plugin ký toàn DLieu bằng **một Signature**, upload một XML/multipart part, HTTP
204/body rỗng. xmlsec verify đạt; sửa riêng HDon 1/2/3, SigningTime hoặc signature
đều bị từ chối. Integration không được ép ZIP/XML/signature count bằng số invoice
IDs. Không có raw callback hoặc thử lỗi từng phần. Xem
[batch report](minvoice-batch-live-capture.md) và
[batch evidence](evidence/minvoice-live-cash-batch-success.json).


## Phạm vi mới: khoảng 300 hóa đơn mỗi lần, không giới hạn theo sample 3

User làm rõ nhu cầu thỉnh thoảng ký khoảng **300 hóa đơn/lần**. Báo cáo mới
[luồng ký lô tổng quát](minvoice-bulk-signing.md) phân tích đúng build 1.0.3.0:
cash chia 100 mỗi nhóm, 300 → 3 nhóm tuần tự download → ký các XML backend trả
→ upload → chờ; ordinary theo tenant setting (default 2 khi response null).
Không ép số XML/chữ ký bằng số invoice, số nhóm hoặc số 3. Static và 7175 model
cases/biên 300 đã kiểm tra; **chưa chạy live lô trên 100**. Runtime thật mới có
cash 1/3; không tuyên bố app đã hỗ trợ 300.

App hiện còn guard `InvoiceIdArray.count == 1` trong MinvoiceInvoices.swift.
Cần mở rộng scheduler và ZIP/approval/progress/error handling để hỗ trợ số lượng
thay đổi, với mục tiêu thực tế 300 cash. Theo dõi kết quả từng nhóm; không tự
retry nhóm upload chưa rõ hoặc toàn lô. Cancel vendor chỉ giữa các nhóm và có
thể vẫn callback success khi không Error; TokenSigner phải báo hủy/partial rõ.
Chi tiết guard, CIL anchors, mô hình fault và checklist integration nằm trong
báo cáo mới; chưa sửa runtime Swift trong đợt nghiên cứu này.
