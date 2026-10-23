# MISA KYSO → TokenSigner macOS

Ngày nghiên cứu: **23/10/2026**. Phạm vi người dùng chọn: **meInvoice, AMIS**.
Trạng thái: đã phân tích tĩnh bộ cài và đường tích hợp; **chưa có capture portal
Windows, chưa triển khai/bật bridge MISA, chưa xác nhận tương thích**.

Không chạy installer/assembly Windows, không nhập PIN, không ký hay gửi hồ sơ.
Không restart/package app chung; sáu listener hiện có giữ nguyên. Raw/vendor
payload và output lớn chỉ ở `.local/re/misa/`, không đưa vào Git.

## Artifact và độ tin cậy

Artifact đầu vào do người dùng cung cấp:
`/Users/linhsayshii/Downloads/MISA.KySo_Setup_latest.exe`.

| Thành phần | Identity quan sát |
| --- | --- |
| Installer | 94.421.832 byte; SHA-256 `5c7533ec1aa31673727affb8f7d2f1a3e8cd06003bffc5bad17c20188ac2c262` |
| Launcher / Setup.ini | ProductVersion `11.4.3.0`; PE32 x86, InstallShield 23 |
| MISA Kyso.msi | 30.347.776 byte; SHA-256 `4531d7ffcd7eb6a247296dac7fecac0e6a90f09ae1e86780bce2d8a2e189ed2e` |
| MISA.KYSO.exe | .NET Framework x86 CIL; assembly version **11.4.4.4**; SHA-256 `cf78cfb44af472cdc3781c7a8a1ff1ca36615e3a47b3ecfec0c6af2a978ac575` |
| MISA.KYSO.Util.dll | assembly version `3.2.5.0`; SHA-256 `b9b562e1d74e29b0b81f0dfbcf86d3c565c30c82e4bf6ed571d0c0b497c7b774` |
| WebSockets.dll | assembly version `1.0.0.0`; SHA-256 `a57e00ab7c2fc7f58c280c180348193118574074a50f916e26027445a247eec7` |

Tên `latest` không chứng minh bản mới nhất toàn hệ thống. Version lớp cài đặt
và version assembly bên trong khác nhau; giữ cả hai để đối chiếu máy Windows.
Hash xác định đúng bytes, chưa phải kiểm chứng Authenticode/nhà phát hành.

PE resource inventory bằng **REA 6.5.0**:
`ev_6edcfee36cece6d705aaaa46c2b8ef6a6e577fe9685adf4344f6b02112bec30b`
(70 resources / 147 entries). Outer EXE không mở được trực tiếp bằng 7zz.
Overlay `ISSetupStream` v3 bắt đầu tại file offset `1918976`: 10 member,
header member 24 byte, tên file UTF-16, filename-derived M1024 transform rồi zlib.
Giải mã MSI và Setup.ini đạt EOF, không dư compressed bytes. MSI Compound và
Data1.cab qua `7zz t`; CAB có 85 file, tổng 102.779.973 byte. CAB member names
là MSI File identifiers, chưa phải toàn bộ installed long paths.

**Giới hạn extraction:** prerequisite .NET 4.6.2 lỗi zlib ở block offset
`35373056`; chưa xác định lỗi source hay giả định decoder. Partial output bị
tách riêng và không dùng làm bằng chứng. Không vì vậy kết luận bộ cài hoạt động
hay không hoạt động. MSI được giải mã riêng lần nữa và so bytes trùng hoàn toàn.

Canonical managed metadata/CIL được lấy bằng REA thực có trong session. Util
member response vượt budget transport; producer đã hoàn tất, nên export retained
Evidence thay vì chạy lại. REA anchors không phải toàn bộ IL: thiếu nhiều opcode
không có operand và đích switch. Dùng dncil offline bổ sung toàn bộ lệnh;
**453 + 1462 + 144** file-backed method bodies đều khớp IL SHA-256 và instruction
count với REA. Không load/reflection hay execute assembly.

[Manifest, hash và kiểm tra](evidence/misa-artifact-manifest.json) chứa MVID,
Evidence IDs, source ranges, tool versions, extraction limitation và hash toàn
bộ CAB. Raw/IL/vendor code không được sao vào báo cáo.

## Browser ↔ plugin: điều đã quan sát trong mã

Đường khởi động `MISA.KYSO.frmMain.j` (`0x06000006`) lấy một mảng 8 cổng từ
FieldRva `t.a`, kiểm tra `IPUtil.PortInUse`, chuyển sang ứng viên kế tiếp nếu
bận, rồi `WebServer.Listen(candidate)`. Mảng theo thứ tự:

```text
11984, 11985, 12680, 12681, 12683, 11994, 11995, 12690
```

`Listen(int)` chuyển vào `Listen(int, null)`; implementation dùng
`IPAddress.Loopback` và `TcpListener`. Nhánh `SslStream` cần certificate khác
null. **Suy luận từ tuyến khởi động này:** signing endpoint là WS plain
loopback, với cổng đầu còn trống; chưa quan sát endpoint chạy thật. Không có cơ
sở để bật cả tám listener như một contract portal đã kiểm chứng.

Factory `m.CreateInstance` (`0x06000076`, IL `00e7–00f7`) so path đúng `/plugin`
trước khi tạo `l` kế thừa WebSocketService. Kết nối HTTP được đưa tới static
HttpService theo web root; đây không phải bằng chứng HTTP signing REST API.
Handshake WebSockets.dll (`0x0600002d`) parse Sec-WebSocket-Key/Version, tạo
101/Accept và có nhánh 426/400. **Chưa có capture WS/WSS/HTTP/native messaging
thực tế từ meInvoice/AMIS**. Mã còn có custom launch/single-instance IPC; không
đồng nhất các cơ chế này với signing transport.

Trong startup/factory/handshake đã đọc không thấy gate Origin/CORS; tập ldstr
của ba assembly không có Origin/access-control literal. Đây là tìm kiếm có
giới hạn, **không chứng minh vắng kiểm tra ở mọi tuyến/runtime**. Origin thực,
browser local-network permission và policy portal vẫn cần capture. Adapter
macOS phải giữ `WebGuard`/`OriginStore` chung, không bắt chước việc bỏ guard.

`l.OnTextFrame` (`0x06000059`) deserialize text thành `PluginData` qua MethodSpec
`0x2b000001` → `SerializeUtil.DeserializeObject`. Nó đọc `action`, sao
`jsObject`/`jsCallBackFn` vào `ServiceResult`, dispatch và serialize result rồi
`WebSocketBase.Send`. Không execute callback JavaScript trong app Mac.

Các **comparison/call site tĩnh** có nhóm đọc/version (`GetVersionNumber`,
`GetRawVersion`, `GetCertInfo`, `GetCertificateInfo`, `GetAllCertificates`,
`GetAllCertificatesV2`, `GetAllMisaCertificate`), ký hash (`SignHash`, `HashFile`),
nhiều profile XML (`SignXML`, `SignReportXML`, `SignInvoiceRegistrationXML`,
`SignXmlInvoiceUsingInfor`, `SignXMLBuyer`, IVAN/HRM/Integrated), PDF, Office và
`MTax.SignDocument`. Chưa biết meInvoice/AMIS gọi nhóm nào, thứ tự gì, productName
và schema cụ thể nào. Không coi tên phương thức là ca ký runtime thành công.

[Transport evidence](evidence/misa-transport-static.json) ghi method tokens,
offset, bytes mảng cổng, call sites và các câu hỏi còn mở.

## Envelope và chứng thư

Metadata `PluginData` có `action`, `productName`, `sessionId`, `jsObject`,
`jsCallBackFn`, `taxcode`, `sellerInfo`, `buyerInfo`, `files`, `invoiceDatas`,
`metaData`, `serialNumbers`, `CurrentSerialNumber`, `HashToSigns` (`List<string>`),
`HashAlgorithm`, `DocumentType` (int), `SignatureAlgorithmName`,
`DataAfterCallback`, `is91Circular`, `isSignTT68`, `isSignTT32` và các cờ lọc.
`serialNumbers` là **string**, không tự biến thành array.

`ServiceResult` có `status` (bool), `data`/`data_info` (object), `message`,
`code` (string), `jsObject`, `jsCallBackFn`, `certExpireDateInfo`,
`SettingAlgorithm`. Đây là property names/types, chưa đủ để chốt JSON casing,
null/omission/coercion cho mọi lệnh. Một số handler serialize object vào chuỗi
`data`; không áp một kiểu `data` chung cho mọi response.

`FuncWS.GetCertInfo` (`0x06000384`) gọi Windows certificate store → filter →
native selection; tạo CertInfo gồm `FullName`, `Subject`, `SerialNumber`,
`CertBase64` (DER base64), `Issuer`, có check private key/revocation tùy cờ.
Các lệnh GetAll/GetCertificateInfo khác có tuyến riêng; cần gắn action thực
portal tới handler đúng trước khi port. Không tự lấy chứng thư đầu tiên nếu
serial không khớp, không gửi PIN qua browser để thay native chooser.

## Hash, XML, PDF/Office và phụ thuộc

**Bẫy chính của `SignHash`:** `FuncWS.SignHash` (`0x06000386`) giải base64 từng
phần tử `HashToSigns`, nhưng `DocumentType` quyết định ý nghĩa bytes:

| DocumentType | Tuyến RSA quan sát trong CIL |
| --- | --- |
| `0` | `SignData`: hash dữ liệu rồi ký PKCS#1 v1.5 |
| `1` | `SignHash`: ký digest đã có; `is91Circular` có thể chọn RSA-PSS |
| khác | nhánh lỗi unsupported; code enum 13 thành string |

Thuật toán có tuyến suy từ độ dài base64 đầu tiên: 20/32/48/64 byte →
SHA-1/256/384/512, với fallback/global configuration/certificate OID ở helper.
Không kết luận trường `HashAlgorithm` luôn điều khiển crypto: configured local
trong handler này không được dùng trực tiếp về sau. Cần đối chiếu dispatcher,
global setter và fixture. Output là danh sách chữ ký base64; `DataAfterCallback`
được gán vào `data_info`. Không rehash một digest chỉ vì tên API dùng “data”.

Core TokenSigner hiện có RSA PKCS#1 + SHA-1/SHA-256. PSS, ECDSA, SHA-384/512
không thể nhận là đã hỗ trợ chỉ vì MISA có nhánh code cho chúng. Không suy
Windows CSP/token nào thực sự chạy được mọi nhánh.

**XML:** helper `ComputeSignature` (`0x06000475`) đặt SignedInfo canonicalization
thành **exclusive C14N** (`http://www.w3.org/2001/10/xml-exc-c14n#`). Các helper
có enveloped transform, content reference và `#SigningTime`, mapping thuật toán
SHA-1/256/384/512/PSS. Core TokenSigner đang dùng **inclusive C14N 1.0**; không
gọi `SigningService.signXML` hiện tại và nhận là MISA-equivalent. Cần fixture
đúng tuyến invoice: reference URI, placement/namespace/ID, timestamp, co-sign và
serialization. Có code XAdES/PDF/Office không chứng minh profile meInvoice đang
dùng chúng.

Payload có iText/iTextSharp, Aspose Words/Cells và các lệnh ký PDF/Office. Đã
xác định call/dependency footprint, chưa tái tạo và kiểm chứng định dạng output.
Trong util call inventory, CMS xuất hiện ở kiểm tra chữ ký PDF/long-term;
**chưa thiết lập một command ký CMS độc lập từ browser**. Không map tùy tiện
MISA PDF/Office vào `CMSSigner` chung.

App Windows là WinForms/.NET 4.6.2 x86, dùng Windows store/CSP, user32/kernel32,
PKCS11Interop và ngoại vi module token. PKCS#11 helper có CKM_RSA_PKCS/DigestInfo
và PSS. Đây là declarations/call sites tĩnh, không phải thư viện đã được load
trên máy Windows. macOS cần dùng backend/chứng thư TokenSigner sẵn có, không
chạy Windows DLL hay port UI PIN của hãng.

[Crypto/DTO evidence](evidence/misa-crypto-static.json) lưu chi tiết branch,
method/IL anchors, SHA/MVID và giới hạn. RSA verify chỉ là kiểm tra chữ ký mật
mã; không thay kiểm tra chain/revocation hoặc xác nhận nộp hồ sơ.

## Plugin portal khác với CA/cloud signing

MISA KYSO là tool desktop kết nối USB-token với các portal. Hướng dẫn chính
thức MISA tách ký USB cần KYSO với **MISA eSign từ xa** không cần tool trong
tuyến eShop tương ứng: [FAQ MISA](https://helpeshop.misa.vn/kb/mot-so-cau-hoi-thuong-gap-lien-quan-den-van-de-ky-so-khi-phat-hanh-hoa-don/),
[hướng dẫn USB](https://helplekima.misa.vn/v2/knowledge-base/cai-dat-cong-cu-misa-kyso-de-ky-so-bang-usb-token/).
Đây là mô tả sản phẩm, không phải protocol capture.

Ngoài WS local, mã còn có tùy chọn ký qua server với HTTP `CheckConnect` /
`SignMulti`. Không đồng nhất tuyến server này với API CA/eSign cloud, không
tự gọi URL external lấy từ binary và không cần mua chứng thư MISA để mô phỏng
giao thức đọc/ký bằng USB đã hỗ trợ. Portal vẫn có thể lọc nhà cung cấp/chứng
thư theo nghiệp vụ; cần kiểm chứng từng ca, không bỏ lọc hay giả identity.

## Vị trí adapter trong repo

Đã đối chiếu `docs/PROGRESS.md`, `docs/UI.md`, `docs/BRIDGES.md` và source tại
checkout chung, không sửa source/khởi động app.

| Phần | Vị trí / cách dùng |
| --- | --- |
| Wire adapter | `Sources/Bridges/SigningService.swift:16`; adapter mới nhận `any SigningService`, `BridgeContext(bridge: "misa", origin: origin thật)` |
| Chooser → approval → PIN | `Sources/App/AppModel.swift:592` performBridgeSign; picker `:407`, approval `:463`, PIN `:501`; không tạo cửa sổ/luồng PIN thứ hai |
| Identity + hotplug | `SigningCertificateChoice.swift:39`, `AppModel.swift:393/:434`; giữ module/token/CKA_ID/DER, serial ràng buộc từ request |
| Sign + verify + audit | `AppModel.swift:517/:527/:484`, `TokenBroker.swift:28`, `AuditLog.swift:15`; giữ log digest/metadata, không log frame/credential/XML/PIN |
| Origin/Host | `WebGuard.swift:9`, `OriginStore.swift:23`; chỉ loopback, grant origin chủ động; không thêm wildcard MISA toàn bộ khi chưa có host thực |
| WS | `WSServer.swift:24/:38/:148`; guarded upgrade, route exact `/plugin`, disconnect hủy task/prompt |
| Catalog + menu | `BridgeCatalog.swift:3/:19`, `AppModel.swift:179`; chỉ thêm endpoint thật đã đối chiếu capture |

Hai bẫy wiring: `AppModel.swift:218` đang đưa mọi endpoint `tls` tới handler
VNPT; nếu sau này MISA cần WSS phải dispatch theo kind. `HTTPServer.swift:11`
đang gắn CTSignBridge, không phải HTTP handler tổng quát. Capture hiện tại chưa
cho phép kết luận MISA cần WSS hay HTTP signing.

XML độc lập bằng xmlsec1 **không tự có ở mọi SigningService call**:
`AppSigningService.signXML` (`AppModel.swift:726`) không đồng nghĩa với tuyến
eSigner offline gọi `XMLSecVerifier` (`ESignerBridge.swift:104`). Verifier hiện
optional khi thiếu xmlsec1 và có ID rules riêng eTax. Adapter MISA cần verify
output theo đúng profile trước trả kết quả, ngoài token signature verify.

### Coverage nhiều CA/model/firmware

Yêu cầu sản phẩm bổ sung ngày 23/10: adapter MISA phải dùng được với mọi
CA/model được tầng provider của TokenSigner xác nhận hỗ trợ; không khóa vào
full ATR, serial hay module của token mẫu. Đích bao phủ các dòng token của một
CA khác với kết luận đã kiểm chứng mọi model. Đây là yêu cầu thiết kế, chưa
phải coverage runtime đạt được.

Tách hai quyết định: protocol MISA quyết định kiểu chứng thư/thuật toán/output
mà portal yêu cầu; provider chung quyết định token vật lý nào có thể thực hiện
thao tác đó. CA/issuer của chứng thư không đồng nhất OEM hay protocol của USB.
Cùng CA có thể có nhiều OEM, model và firmware; adapter không tự chọn ESPK,
PKCS#11 hay backend khác bằng tên hãng CA.

Luồng dự kiến: inventory provider chung → compatibility/capability read-only →
lọc theo yêu cầu thao tác → chooser chung → approval → PIN → ký → verify →
audit. ATR, USB ID và reader chỉ chọn backend ứng viên. Trước PIN cần xác nhận
model/protocol compatibility, liên kết cert/key/CKA_ID và public key theo
backend đó; thiếu bằng chứng thì trả trạng thái chưa đủ hỗ trợ, không thử PIN,
derive tùy tiện, fallback authentication sang backend khác hay tự retry.
Serial portal vẫn là ràng buộc lựa chọn của **request hiện tại**, không phải
allowlist coverage cố định.

`SigningService` hiện có các phép ký nhưng chưa có API công khai mô tả đầy đủ
capabilities từng identity. Khi tầng provider chung bổ sung hợp đồng đó, adapter
phải dùng hợp đồng chung thay vì thêm bộ probe/ATR rules riêng trong MISA.
Capability cần phân biệt raw-message/digest, loại khóa, hash, padding, output
profile và trạng thái evidence; token làm được RSA PKCS1 không suy ra PSS,
ECDSA hoặc profile XML đã hỗ trợ. Không hạ thuật toán hoặc bỏ guard để vượt
giới hạn.

Coverage cần theo **CA + OEM/model/firmware + backend + thao tác** với các mức
độc lập: nhận diện/đọc metadata; xác thực; ký và verify; portal meInvoice/AMIS.
Chưa có model nào được xác nhận qua portal MISA trong nghiên cứu này. Nhận thêm
ATR hoặc đọc thấy chứng thư không tự nâng mức auth/sign/portal.

Fixture adapter sau capture phải có ít nhất hai identity từ provider/model
khác nhau, cùng CA khác model nếu có dữ liệu, serial mismatch, hotplug và trường
hợp đọc được nhưng không có capability ký được yêu cầu. Nếu capture/runtime
thể hiện MISA lọc provider/model/issuer, ghi rõ điều kiện và evidence để tầng
provider/điều phối xử lý; không hardcode token mẫu hoặc giả danh hãng khác.
Các sửa routing/transport/provider chung do luồng chính điều phối; nghiên cứu
MISA hiện chỉ cập nhật thiết kế, không đụng source chung hay build đồng thời.

## Còn thiếu gì trước triển khai

| Câu hỏi | Trạng thái |
| --- | --- |
| Artifact/version/package/managed identity | Đã quan sát, có giới hạn prerequisite .NET |
| Transport/cổng/route trong mã khởi động | Đã quan sát tĩnh; runtime chưa xác nhận |
| Process/service Windows đang chạy | Chưa quan sát; executable ứng viên là MISA.KYSO.exe |
| Origin/CORS/runtime permission | Một phần; chưa có request thật |
| Envelope/DTO/callback | Metadata và dispatcher đã có; serializer/null/escape rules chưa đầy đủ |
| Đọc/chọn cert, sign hash | CIL branch đã có; chưa có portal fixtures |
| XML c14n/profile | Có khác biệt xác định; tuyến invoice/output cụ thể còn thiếu |
| CMS/PDF/Office | Chưa xác nhận command/runtime contract cần port cho meInvoice/AMIS |
| TokenSigner tương thích meInvoice/AMIS | **Chưa kiểm chứng** |

Bước tiếp: làm theo [capture Windows ngắn](misa-windows-capture.md), ưu tiên
**đọc chứng thư + một ca ký dữ liệu thử** trên meInvoice/AMIS. Người dùng tự
nhập PIN. Chỉ cần endpoint, Origin, action và request/response đã che dữ liệu
trước; dữ liệu ký fixture phải là tổng hợp. Không cần gửi toàn bộ HAR/cookie.

Khi có fixture, triển khai phạm vi nhỏ đúng command thực, dùng fake service
kiểm tra forwarding/DocumentType và double encoding, kiểm tra Origin/route/
disconnect cancellation qua socket, kiểm tra XML với verifier độc lập đúng
c14n/reference và bảo toàn payload. Test điểm vào có sẵn:
`FakeSigningService`, `CTSignHTTPTests`, `WSServerTests`, `CertificatePickerTests`,
`XMLDSigTests`, `AuditLogTests`. Không thêm protocol giả, không quảng bá version
đã hỗ trợ trước khi command tương ứng thực sự làm được.

## Kiểm tra đã làm / chưa làm

- Đã đối chiếu SHA-256, REA metadata/resources, extraction boundaries, MSI/CAB
  integrity và toàn bộ file-backed CIL body hash/instruction count ở ba assembly.
- Đã tách findings tĩnh, suy luận và unknown; evidence JSON chỉ chứa kết luận,
  hash, tên/offset và giới hạn, không vendor implementation dump hay capture.
- Chưa chạy app/installer Windows, chưa capture network, chưa ký/PIN, chưa
  kiểm tra portal end-to-end. Không chạy packaging/smoke làm mở lại app chung.
- Không đổi source production; chưa có thay đổi runtime để chạy Swift tests.
  Các file nghiên cứu EFY/OneCA/Minvoice ngoài phạm vi được giữ nguyên.
