# M-Invoice REST từ CIL — 2026-10-22

Phạm vi: chỉ đọc artifact, không nạp/chạy assembly, không gọi REST nghiệp vụ, không phát hành hóa đơn. Báo cáo này bổ sung và sửa các suy luận trong `minvoice-plugin.md`; kết quả chỉ áp dụng cho build có identity dưới đây, chưa phải capture runtime.

## Identity và bằng chứng

- Artifact: `MinvoicePlug.exe`, 1,695,432 B, SHA-256 `57ffb22ea1c0555479d88bb120e9e1a09f8658b1fbab3378d9387c78cbc97a2c`.
- Assembly `MinvoicePlug` 1.1.1.0, .NET Framework 4.7.2, MVID `5e073e74-2075-482a-a5e1-f12cb1101106`.
- REA `inspect_managed_artifact`: **E-ID** `ev_13c492e4a84c7dcab685b7aef2c201b6d8635d9fa13ff94355e8a9db3ba52e1e`.
- REA `inspect_managed_members`: **E-MEM** `ev_491c880c5ab83760c01a4a0fb641f1c8aa050568de9e42c5d07b42d0b6577fc9`. Metadata/member coverage complete; user-string coverage partial vì 17 literal có terminal flag khác ECMA-335. Không suy luận sự vắng mặt từ tìm kiếm string.
- REA export cục bộ: `/private/tmp/minvoice-rest-static-evidence.json` (6,038,331 B, 6 records tại lúc export). Không đưa bundle lên Git vì nó có thể chứa constant credential của vendor. Không có credential runtime được thu thập.
- Snapshot bền vững đã lọc: [`evidence/minvoice-rest-cil.json`](evidence/minvoice-rest-cil.json), SHA-256 `1eab56dc8810fe07cb1ea26050310135e7b7419e1b80ae2606225020c68a13d8`. Đây là **local projection của E-MEM**, không phải Evidence ID mới của REA: 34 method với metadata/raw IL hex/hash/header, relevant call edges/fields/member refs; chỉ giữ 43 string thuộc whitelist đường dẫn/header/XML/command, bỏ 18 literal khác trong selection. Raw IL chỉ chứa token tham chiếu #US, không sao chép toàn bộ string heap.
- Raw CIL đọc bổ sung bằng analyst script `/private/tmp/minvoice-cil.py`: opcode table từ parser REA 6.5.0; offset/header/hash/instruction count được đối chiếu với E-MEM. Đây là diễn giải CIL, không phải mã C# gốc hay thực thi quan sát được. Token và IL offsets bên dưới có scope SHA/MVID trên.

## Checklist

| Câu hỏi | Trạng thái |
|---|---|
| ProcessMessage có dẫn đến SignInvoices không? | Đã xác định tĩnh |
| Download URL, method, body, response container | Đã xác định tĩnh |
| Upload URL, method, multipart shape | Đã xác định tĩnh |
| Credential/session headers được lấy từ đâu? | Đã xác định tĩnh; chưa capture cookie/formatter thực |
| XML reference, vị trí, signing time | Đã xác định tĩnh cho invoice thường |
| Algorithm URI mặc định/namespace output/server acceptance | Chưa xác minh runtime |
| Bật luồng ký và phát hành thật | Chưa làm; bridge vẫn 501 |

## Chuỗi gọi quan sát được

`HandlerHub.ProcessMessage` (`0x0600000c`) tạo state machine `<ProcessMessage>d__1.MoveNext` (`0x060003ea`). Nó đặt `HubResult.Code=1`, `Message="Successful"`, gọi `SwichTask`, gán kết quả vào Data, sau đó callback `reponseResult`. Catch đổi Code/Message theo exception. Đây là xác nhận CIL của `code===1` ở trang.

`<SwichTask>d__3.MoveNext` (`0x060003ed`) lấy CommandInfo/PlugCommand.CommandName; nhánh `SignInvoices` gọi `InvoiceBusiness.SignInvoices` (`0x06000377`). Trước dispatcher (trừ nhánh ChangePassword riêng), nó gọi `InvoiceBusiness.Login` (`0x06000375`, IL_011e).

`<SignInvoices>d__2.MoveNext` (`0x0600048d`) tạo InvoiceApiService từ BrowserInfo, gọi GetCurrentTenant, chọn token theo SerialNumber, hỏi xác thực token, mở dialog `ProcessSignInvoice`. `ProcessSignInvoice.bgwProgress_DoWork` (`0x060003d1`) chuyển InvoiceIdArray thành SignedInvoice; lấy detail hóa đơn đầu tiên; chọn SignInvoice hoặc SignInvoiceCash theo InvoiceSerial. Nhánh thường chunk theo setting (mặc định 2, `0x060003df`), gọi ExecSignInvoice rồi UploadMultiFilesXml. Các call này nằm trong thân method, không chỉ là string rời.

## Download và detail

| Bước | Request quan sát từ CIL | Bằng chứng E-MEM |
|---|---|---|
| Tenant | GET `tenant-company/current-tenant` | `0x06000079` |
| Detail đầu tiên | GET `invoice/{invoiceId}/detail` | `0x0600007a`, IL_0001/0019 |
| Setting chunk | GET `release-invoice/tenant-setting-sign` | `0x0600007d` |
| XML invoice thường | POST `release-invoice/download-xml` | `0x06000074`, IL_0032/0038 |
| XML cash | POST `release-invoice/download-xml-invoice-cash` | `0x06000072` |

Base API lấy từ `BrowserInfo.LinkApi`, qua `RestInvoiceClient` constructor `0x06000090`; không phải một base URL hardcode duy nhất. SPA đã quan sát dùng `https://api-hddt.minvoice.com.vn/api/app/` (bằng chứng đợt trước).

**Body download là JSON array GUID**, ví dụ fixture `["12345678-90ab-cdef-1234-567890abcdef"]`. Không phải `{InvoiceIds: [...]}`: `ExecSignInvoice` (`0x060003dc`) chọn SignedInvoice.Id (`0x060004bd`), ToList rồi truyền thẳng list vào GetInvoiceXml. GetInvoiceXml truyền arg đó đến RestInvoiceClient.PostFile (`0x06000094`), method này gọi `HttpClientExtensions.PostAsJsonAsync`, rồi ReadAsStreamAsync. DTO RequestSignInvoiceModel tồn tại nhưng không nằm trong đường gọi này.

GetInvoiceXml thêm header `x_req_id` bằng Guid.NewGuid().ToString() trước POST. `GetSignedInvoices` (`0x06000075`, IL_0009..00a4) đọc response bằng `ZipArchive`, đọc text mỗi entry, lấy **entry.Name bỏ `.xml` rồi Guid.Parse** làm Id, text làm Xml. Vì vậy response là ZIP chứa `<GUID>.xml`, không phải JSON `{xml:...}` và không phải XML đơn. Runtime content-type, giới hạn file, encoding thực, ZIP sample chưa có.

InvoiceInfo có các property `RegisterInvoiceId` (nullable GUID), `RelatedInvoiceId` (nullable GUID), `InvoiceStatus` (nullable int), `InvoiceSerial` (string), `InvoiceNumber` (nullable int), fields `0x040000cc`..`0x040000d0`. GetInvoiceInfo lấy kết quả generic GetAsync, không thấy wrapper riêng trong method; null ném RestException 9020. Wire casing và response JSON mẫu chưa capture.

## Upload batch

UploadMultiFilesXml (`0x060003da`, state machine `0x060004c6`) tạo **ProgressUploadFile** rồi gọi UploadMultiInvoices; đường chính này không dùng RestInvoiceClient.UploadFile của SS04/declaration.

`<UploadMultiInvoices>d__2.MoveNext` (`0x0600041b`) chứng minh:

- IL_0019..0037: URL = BaseAddress + `string.Format("release-invoice/{0}/upload-xml", Guid.Empty)`. Vì vậy route batch là **`release-invoice/00000000-0000-0000-0000-000000000000/upload-xml`**, không thế ID hóa đơn cụ thể.
- IL_0042..0064: boundary = GUID mới bỏ dấu `-`.
- IL_0074..0089: `Content-Type: multipart/form-data; boundary=<boundary>`.
- IL_00ca..0134: mỗi SignedInvoice.Xml là file content; filename `{SignedInvoice.Id}.xml`; field **`files`**; part type **`text/xml`**.
- IL_01c7..01dc: body StringBuilder chuyển bytes bằng WebClient.Encoding đã đặt **UTF-8**.
- IL_01ed/01f8: method **POST**, `WebClient.UploadDataTaskAsync`.

Mẫu multipart (placeholder chỉ dùng fixture, không phải dữ liệu hóa đơn thật):

```text
--<boundary>\r\n
Content-Disposition: form-data; name="files"; filename="<GUID>.xml"\r\n
Content-Type: text/xml\r\n
\r\n
<signed XML>\r\n
--<boundary>--\r\n
```

Result byte[] upload được await; `<UploadMultiFilesXml>d__22` trả nó về và SignInvoice lấy Task.Result nhưng không parse nội dung thành trạng thái nghiệp vụ. Dialog Error quyết định exception; `InvoiceBusiness.SignInvoices` đặt `ResultSignInvoice.Status=true` nếu không có Error. Vì vậy **không suy `HTTP 2xx` đồng nghĩa phát hành thành công**. Response schema/partial-batch semantics còn cần capture.

## Auth chính xác của đường 2.0 này

Quan sát E-MEM:

1. `InvoiceBusiness.Login` (`0x06000375`) reset RequestVerificationToken và chỉ giữ cookie đầu tiên bắt đầu `__tenant` từ BrowserInfo.Cookie, qua GetTenantCookie (`0x06000382`). Không dùng nguyên cookie browser như phiên đăng nhập sẵn.
2. `InvoiceApiService.Login` (`0x06000067`) dựng RequestLoginModel: UserNameOrEmailAddress = BrowserInfo.UserName, Password = BrowserInfo.Pass, RememberMe=false. Đổi base bằng `LinkApi.Replace("app/", "")`, POST `account/login` qua PostAsJsonAsync. Property names đã xác định, casing wire JSON chưa được capture/đối chiếu dependency formatter.
3. SaveCookies (`0x06000069`) đọc Set-Cookie; bỏ cookie `__tenant`, nối phần còn lại vào GlobalData.Cookie; gặp `XSRF-TOKEN` thì lấy phần sau `=` trước `;` làm RequestVerificationToken. Mã vendor xử lý cookie khá thô; không nên chép nguyên cách ghép Set-Cookie attributes sang Cookie header.
4. Sau login gọi GET `abp/application-configuration` (`0x06000068`) dưới base đã bỏ `app/`, SaveCookies lần nữa.
5. InvoiceApiService(BrowserInfo) mới (`0x06000064`) dùng **LinkApi đầy đủ**, `HttpClientHandler.UseCookies=false`, headers User-Agent từ BrowserInfo, Cookie từ GlobalData.Cookie, RequestVerificationToken từ GlobalData.
6. ProgressUploadFile constructor (`0x06000081`) dùng cùng LinkApi/UserAgent/Cookie/RequestVerificationToken; WebClient header enum 40/25 tương ứng User-Agent/Cookie, xác nhận thêm từ ctor InvoiceApiService literal.

**Không có Bearer/api-key trong constructor/đường request này.** Các string Bearer/api-key của RestClient cũ trong assembly không đủ để gán sang luồng SignInvoices. Không hardcode key, không ghi/log BrowserInfo hay password. Không triển khai auto-login ở đợt này.

## XML: sửa kết luận cũ từ VoucherSign

Invoice thường dùng `SignFile.ExecSignXmlInvoice` (`0x0600039e`) → **`SignFile.SignXmlData` (`0x060003a0`)**, không phải VoucherSign.SignXmlData.

- ExecSignXmlInvoice đặt XmlDocument.PreserveWhitespace=true.
- ExecSignInvoice (`0x060003dc`, IL_00a7..0107) lấy SigningTime từ CurrentTenant.CurrentDateTime; dùng Reference URI `#<entry GUID>`.
- IsBKeXml (`0x060003dd`) nhận `(entry GUID, HashSet requested IDs, XML)`: nếu GUID không nằm trong requested set thì trả true ngay; nếu có thì bỏ XML declaration/whitespace và kiểm tra `<BKe`. Điều này cho thấy ZIP có thể gồm bảng kê do backend sinh với GUID riêng; cần fixture trước khi đặt chính sách correlation.
- Vị trí `//HDon/DSCKS/NBan`; nếu IsBKeXml thì **`//BKe/DSCKS/NBan`** (khác buyer path trước đây). Cash dùng `//TDiep//CKSNNT` và method khác, chưa khôi phục đầy đủ profile.
- SignXmlData tạo InvoiceSignXml, SigningKey từ token cert.PrivateKey; KeyInfoX509Data(cert) rồi AddSubjectName. Không thấy RSAKeyValue trong method này.
- Reference tài liệu: enveloped-signature rồi inclusive C14N; Reference thứ hai `#signtime`; Object có `Id="signtime"`.
- CreateObjectSigningTime (`0x060003a1`) tạo SignatureProperties/SignatureProperty Target="#signtime"/SigningTime bằng text CurrentDateTime nhận vào.
- **Không set SignatureMethod hay DigestMethod trong method invoice này.** URI rsa-sha256 ở method khác không chứng minh thuật toán thực của SignInvoices. Cần signed XML sample hoặc đúng phiên bản System.Security.Cryptography.Xml/default runtime để xác định. Không tự chọn SHA-1/SHA-256 theo suy đoán.

## Mã chuẩn bị triển khai

Trong worktree `beautiful-shirley-8acdc0`, file mới `Sources/Bridges/MinvoiceRESTRequests.swift` chỉ dựng URLRequest cho detail/download/upload, **không gọi network** và chưa nối vào MinvoiceBridge. Nó nhận authenticated session đã có, giữ credential trong bộ nhớ. URL API bị giới hạn HTTPS `api-hddt.minvoice.com.vn/api/app/`; cấm header control characters, batch trống/trùng và multipart boundary injection/collision. Các kiểm tra này là quyết định thiết kế của TokenSigner, không claim là hành vi vendor.

Tests fixture ở `Tests/BridgesTests/MinvoiceRESTTests.swift`: JSON array/body route/header, GUID.Empty upload route, nhiều XML part UTF-8, detail GET, chặn credential egress và multipart injection. Không token, không PIN, không request đến Minvoice trong tests.

## Còn cần để nối end-to-end

- Capture traffic **của process plugin Windows** (Fiddler/mitmproxy/proxy được người dùng chấp thuận), bao gồm login/bootstrap/download/upload và một signed XML fixture đã che thông tin. **DevTools của tab không thấy các request do process .NET gửi**; hướng dẫn cũ yêu cầu chỉ DevTools là sai.
- Đối chiếu đang dùng đúng build/hash và endpoint môi trường; static evidence không chứng minh server hôm nay chấp nhận contract này.
- Xác định algorithm URI/namespace/ID thực trong signed XML, charset archive, size bounds và ZIP file-ID correlation; không đọc/extract tên ZIP thành arbitrary path.
- Xác định response upload thực, lỗi từng hóa đơn, retry/idempotency/rollback; không tự retry thao tác có thể phát hành.
- Sau đó mới nối API có allowlist, approval trước mỗi chữ ký, PIN stdin helper, hash host/DigestInfo/CKM_RSA_PKCS, verify XML trước upload. Bridge vẫn trả 501 cho SignInvoices cho đến khi phần phụ thuộc này được chứng minh.

## Validation ban đầu — executor sandbox cũ (2026-10-22)

- Hai file builder/tests được copy nguyên byte vào package cô lập `/private/tmp/minvoice-rest-validation`; build và **5/5 tests đạt**. Log `/private/tmp/minvoice-rest-validation.log`.
- SHA-256 source đã kiểm thử: builder `baf51ed6d84c598c4f943a09ddd652745609816a98bb8fd0c770e83d175d4d93`, tests `d998319bce2fe4953431c5c79ef486eff48261c752ea03e50c1c68786f7ba141`.
- Sandbox compiler ban đầu không ghi được module cache rồi temporary assembler files. Dùng `TMPDIR=/private/tmp`, `CLANG_MODULE_CACHE_PATH=/private/tmp/minvoice-rest-clang-cache`, `SWIFTPM_MODULECACHE_OVERRIDE=/private/tmp/minvoice-rest-swift-cache`, SwiftPM `--disable-sandbox --cache-path /private/tmp/minvoice-rest-spm-cache` giải quyết cho package cô lập; full worktree build đạt (66.66 giây), log `/private/tmp/minvoice-rest-build.log`. Không sửa toolchain, không chạy vendor code.
- `git diff --check` và check riêng file mới không báo whitespace error. Không tạo commit hay merge.

- Full `swift test` với engine mặc định và Testing macro path bị chặn khi clang tạo temporary assembler file (`/private/tmp/minvoice-rest-tests.log`). Fallback được `swift test --help` quảng cáo: `--build-system native`; engine này cần thêm `-Xswiftc -F -Xswiftc /Library/Developer/CommandLineTools/Library/Developer/Frameworks` và linker rpath tới cùng thư mục để thấy Testing.framework đã cài.
- Full suite native **biên dịch thành công và chạy 81 tests; không đạt toàn bộ**, ghi 19 issues: 7 lỗi loopback `bind(...): Operation not permitted`, 12 lỗi tạo RSA key fixture `SecKeyCreateRandomKey` trả nil. Các lỗi nằm trong tests cũ phụ thuộc socket/Security framework dưới sandbox; nguyên nhân riêng của SecKey chưa được đo bằng NSError nên không khẳng định chỉ do sandbox. **Cả 5 tests request builder mới đều đạt trong full suite**. Log `/private/tmp/minvoice-rest-tests-native-framework.log`. Không sửa tests cũ để né môi trường và không suy full suite đạt từ isolated run.

## Môi trường test sẵn sàng — executor host (2026-10-22)

Đã tạo và chạy `scripts/test-minvoice.sh` tại worktree M-Invoice bằng `zsh`, với log `/private/tmp/minvoice-env-parent`. Script tự tìm Swift/CLT/Testing framework/macro, dùng backend native được help quảng cáo, cấu hình cache/tmp riêng và kiểm tra loopback + RSA trước khi build/test. Hướng dẫn đầy đủ: `docs/TEST-MINVOICE.md` trong worktree này.

**Lần chạy host đủ quyền đã đạt preflight, build và toàn bộ 81 tests** (test run 1.010 giây; build 6.55 giây với cache). `loopback_bind=ok`, `ephemeral_rsa_2048=ok`; các tests XMLsec1, CMS/OpenSSL và SignalR đều đạt. Kết quả mới này thay thế giới hạn validation của executor sandbox cũ ở trên; không sửa test để né lỗi.

Evidence bền vững, đã whitelist để không lưu credential: [`evidence/minvoice-env-validation.json`](evidence/minvoice-env-validation.json) lưu command/script hash/source-log hashes và kết quả, [`evidence/minvoice-env-validation.log`](evidence/minvoice-env-validation.log) lưu các dòng status/test names an toàn. Full logs nằm trong `/private/tmp/minvoice-env-parent`; script mặc định ghi vào `.build/minvoice-validation/` bị Git bỏ qua.

Native test setup đã sẵn sàng, không cần token/PIN/Windows. Chưa chạy plugin Windows hay resume VM, chưa cài proxy/trust CA hệ thống; capture process plugin, signed XML profile và response nghiệp vụ vẫn là prerequisites riêng trước khi bật SignInvoices. Bridge tiếp tục trả 501 và không có request REST nghiệp vụ nào được gửi trong đợt setup.
