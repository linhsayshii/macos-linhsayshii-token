# GDT “Content is not allowed in prolog” — điều tra 24/10/2026

**Chưa xác định nguyên nhân live; chưa thay đổi encoding, C14N hoặc giao thức ký.**
Người dùng xác nhận lỗi sau nhập PIN, lúc ký tờ khai trên
`dichvucong.gdt.gov.vn`: “1. Lỗi cấu trúc gói tin không hợp lệ!Content is not allowed in prolog.”

## Xác định luồng

Audit metadata sẵn có (chỉ đọc time/host/bridge/result, không sao chép chứng thư,
serial hoặc nội dung): `2026-10-22T23:05:26Z` = **06:05:26 ngày 23/10 giờ VN**,
host `dichvucong.gdt.gov.vn`, bridge **ctsigninghub**, result `ok`.
Lần eSigner gần nhất `2026-10-23T14:48:56Z` thuộc `thuedientu.gdt.gov.vn`.
Đây là bằng chứng lịch sử. **User xác nhận lần đang lỗi dùng eSigner**; cùng
cổng DVC có cả CTSign và các dịch vụ eSigner Java cũ. Không dùng audit CTSign
lịch sử để gán luồng cho lần lỗi này.

- CTSign: `SignXmlRequestAdapter.parse` decode `dataFile` base64 đúng một lần →
  `AppSigningService.signXML` validate trước picker/PIN → `XMLDSigSigner` →
  `CTSignBridge.signXML` trả JSON `{status:200,data:<base64 XML đã ký>,message:SUCCESS}`.
  Bridge không upload hồ sơ. Trang web chịu trách nhiệm decode/envelope và gửi server.
- eSigner offline: picker đọc XML nguyên byte → `_002` ký → independent verifier →
  lưu signed bytes trong actor theo origin/path → `_003` multipart `uploadfile`,
  `Content-Type: text/xml`, body raw signed XML, các field JFileUpload. Uploader
  kiểm tra HTTP 2xx/giới hạn response 1 MiB nhưng bỏ nội dung response.
  Điểm mù này không phải bằng chứng gây lỗi prolog trên DVC.
- eSigner online: `BASE64_VALUE` ký prepared bytes, trả base64 chữ ký RSA;
  `VALUE` decode base64 cả XML và trả base64 XML. Chưa có frame live mới để chọn nhánh.

Thông báo prolog không phân biệt được XML gốc, XML đã ký, base64/JSON/multipart
bị parse nhầm, hay XML trong phản hồi portal. “RSA_PKCS ok” chỉ xác nhận ký token.

## Kiểm chứng độc lập, không tranh `.build`

```sh
swift scripts/re/esigner-prolog-foundation.swift
python3 scripts/re/check-esigner-prolog.py
node scripts/re/esigner-prolog-diagnostic.test.mjs
```

Foundation fixture UTF-8 (tiếng Việt, CRLF, declaration), có và không BOM đều parse
và serialize được thành UTF-8 không BOM. Double BOM, base64 chưa decode, JSON
bao ngoài và rác trước prolog bị từ chối. HTML hợp lệ có thể parse như XML;
“parse được” chưa chứng minh đó là tờ khai. UTF-16 parse ở Foundation nhưng bị
guard UTF-8 của signer chặn. Evidence:
[`evidence/esigner-prolog-foundation-fixtures.json`](evidence/esigner-prolog-foundation-fixtures.json).

Signing harness compile trực tiếp `XMLDSigSigner.swift`, `MessageSigner.swift`,
`DigestInfo.swift` với `swiftc`, module cache/binary/key/cert/XML tổng hợp trong
thư mục tạm được xóa sau chạy. Có shim **chỉ** `CMSSigner.digest` cùng SHA1/SHA256,
không phải full SwiftPM/integration suite. Không đọc token, không PIN, không mạng,
không app restart/package. Kết quả: **3/3 XML hợp lệ ký, serialize/parse và xmlsec1 verify đạt; tamper
bị chặn cả 3/3. 6/6 input xấu/không hỗ trợ bị từ chối.** Với từng signed XML,
base64 wire text và JSON envelope đều không phải raw XML.
[Evidence signing](evidence/esigner-prolog-signing-fixtures.json). Main đã bàn giao
lịch build sau full 182 tests của compatibility. Sau đó luồng này thêm
`Tests/CoreTests/XMLPrologTests.swift`: **3 test prolog + 11 test eSigner đạt**
bằng SwiftPM, không ký phần cứng/upload/package/restart.
[Evidence targeted tests](evidence/esigner-prolog-swift-tests.json). Test mới
khóa hành vi fixture đã xác minh; không tuyên bố tái hiện lỗi nghiệp vụ gốc.

## Chẩn đoán tại browser cho lần user tự thao tác tiếp

[`../../scripts/re/esigner-prolog-diagnostic.js`](../../scripts/re/esigner-prolog-diagnostic.js)
là observer tạm, chỉ chạy trên đúng hai HTTPS host GDT. Đã test mock fetch/XHR/WS,
base64 một/hai lớp, multipart file bytes, nhận marker prolog, XHR tái dùng,
giới hạn 48 bản ghi, tự gỡ sau 5 phút và restore API.

Không tạo, sửa, trì hoãn để chờ hash, retry hoặc gửi lại request. Chỉ lưu trong
bộ nhớ: route label, command allowlist, numeric status/boolean, container type,
byte length, SHA-256, BOM type, parse kind, số Signature và tax-root boolean.
Không giữ XML, cookie, PIN, auth headers, URL/path, tên file, nội dung lỗi gốc hoặc
chứng thư. Không đọc headers. Các body multipart chỉ lấy Blob/file bytes và field
XML trong allowlist; bỏ field cookie. User đã mở tab Brave; quan sát thực tế thấy
DVC nhúng iframe `https://thuedientu.gdt.gov.vn/etaxnnt/Request`. Phải cài hook
trong **ngữ cảnh iframe**, không chỉ top DVC. Chưa xác minh cài hook thành công. Không thao tác đăng nhập/ký/upload thay user.

Cách dùng khi đã mở đúng tab và user sẵn sàng:

1. Paste script vào DevTools Console của tab GDT (không reload sau khi cài).
2. User tự ký, nhập PIN, quan sát lỗi.
3. Chờ hash hoàn tất: `await TokenSignerProlog.settled()`.
4. Xem/copy **chỉ metadata**: `JSON.stringify(TokenSignerProlog.snapshot(), null, 2)`.
5. Gỡ: `TokenSignerProlog.restore()` hoặc reload tab.

So SHA của `ctsign-response.parts[data].decodedOnce` với file/XML trong
`portal-request`. Nếu decodedOnce là `base64-text`, có thêm lớp base64; nếu
`xml` hợp lệ nhưng portal gửi base64/JSON làm raw XML, lỗi nằm ở packaging hoặc
cách server unwrap. Nếu byte XML giống nhau và server vẫn prolog, cần xác định
server đang parse phần nào; chưa kết luận C14N. Với WS offline, browser không
thấy HTTP uploader native; hook không quan sát được response upload `_003` của
URLSession. Request fetch dạng `Request` có body stream chỉ ghi `unobserved`,
không đọc stream vô hạn. Không capture submit form native hoặc traffic phát ra
trong service worker/extension/native app; không có record không chứng minh
không có request. Metadata `js-string-utf8` là byte khi encode chuỗi JS; XHR
`responseText` có thể đã được browser decode/strip BOM. Chỉ `decodedOnce` base64,
`blob-bytes` và fetch `bodyBytes` biểu diễn byte gốc ở các điểm tương ứng. Không
so hash của wrapper JSON/chuỗi browser với hash XML sau decode.

## Lịch phối hợp

Main đã chốt compatibility và bàn giao `.build`; targeted tests ở trên đã chạy
xong và trả lịch. Chỉ thêm test Swift riêng, script và báo cáo; **không sửa source
bridge/Core ký, không stage/commit vào index chung**, không package/restart app.
Nếu capture sau này chứng minh nguyên nhân cần sửa, phối hợp source App/Helper/Shim
và chạy lại test phù hợp trước đóng gói. Targeted filter đã dùng:

```sh
swift test -Xswiftc -plugin-path -Xswiftc /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing --filter 'xmlProlog|nestedAndFlatCER002Agree|checkVersion|valueSignsWholeXmlAndNeverForwardsPIN|base64ValueSignsPreparedBytesWithSHA1ForCER001|unsupportedBadJsonAndDenial|chooseFileReturnsPortalShapeAndCancelFails|signThenUploadOnlyIssuedPaths|signRejectsWrongSerialAndTin|decimalSerialToHex|filePickerGrantsCannotBeUsedByAnotherOrigin|certificateInfoNeverFallsBackToUnrequestedCertificate'
```

**Quan sát live:** lần đầu không có listener vì user chưa mở TokenSigner
(user xác nhận), không suy diễn là main đang restart/package app. Sau khi user
mở app, cả 8768/8769 LISTEN và **4/4 CHECK_VERSION** qua WebSocket đạt với hai
Origin `https://thuedientu.gdt.gov.vn` và `https://dichvucong.gdt.gov.vn`, version
`1.1.0`. Không restart, ký hoặc upload trong probe.
[Evidence kết nối](evidence/esigner-prolog-live-connectivity.json).

**Kết quả nghiệp vụ do user xác nhận:** chính hồ sơ từng báo prolog trên Mac đã
phải **chuyển sang Windows ký/nộp** do cần gấp. Không coi đó là Mac đã sửa xong.
Hồ sơ đã nộp nên không yêu cầu tái ký/tái nộp để debug. Chưa có payload/response
của lần Mac thất bại hoặc capture đối chiếu Windows; audit không bổ sung lượt ký
GDT mới trong lần kiểm tra này. Chưa xác định code eSigner của request lỗi.

Browser automation đọc được DevTools nhưng các thao tác điều khiển Console không
ổn định (user-changed/timeout/noWindowsAvailable). Chưa xác nhận thực thi/cài hook;
không có snapshot chứng minh observer đã chạy. Không lưu raw page/URL chứa session
vào evidence; không thao tác giấy nộp tiền, tài khoản ngân hàng hoặc hồ sơ.

**Cần tiếp:** metadata ở lần ký eSigner kế tiếp do user tự thực hiện với hồ sơ
mới phù hợp, hoặc fixture/capture tổng hợp đã che dữ liệu; xác định command,
response decode và payload mà portal parse. Sau khi tái hiện nguyên nhân cụ thể
mới sửa/đặt regression test. Không tự theo dõi định kỳ hoặc tự ký lại.
