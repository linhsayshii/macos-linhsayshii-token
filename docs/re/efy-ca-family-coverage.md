# EFY-CA: nhận diện theo họ token và kiểm tra trước PIN

Ngày: **23/10/2026**. Phạm vi mới theo [mục tiêu tương thích chung](../TOKEN-COMPATIBILITY.md): nhận các biến thể/model tương thích của cùng CA, không dùng tập exact ATR đã gặp làm giới hạn sản phẩm. Đây là báo cáo nghiên cứu và fixture bàn giao cho main; lượt này không sửa/build routing, transport hay app, không có thao tác trên token.

**Kết luận:** EFY v1 có mask nhận diện chính hãng rộng hơn exact ATR hiện tại. Có thể dùng mask đó để đưa biến thể mới vào discovery/preflight ESPK mà không thêm thủ công từng full ATR. Quyền gửi PIN cần được quyết định bằng hợp đồng giao thức/backend và kết quả preflight, không phải masked match đơn lẻ. OEM/giao thức khác cần provider riêng.

## Bằng chứng và trạng thái mới nhất

| ID | Hồ sơ | Kết luận được hỗ trợ |
|---|---|---|
| C01 | [Registry/provenance](evidence/efy-ca-family-registry.json) | Capture Calais Registry32/64, source/hash/module association và kiểm tra lại download |
| C02 | [ATR fixtures](evidence/efy-ca-family-fixtures.json), [generator/checker](evidence/efy-ca-family-matching.py) | Cấu trúc ATR/TCK, positive/negative vectors và sweep offline |
| C03 | [Capability/source inventory](evidence/efy-ca-family-capabilities.json) | OpenSC 0.27.1, nhánh SM, legacy driver, nguồn/giới hạn OEM |
| C04 | [Preflight contract fixtures](evidence/efy-ca-family-preflight-fixtures.json) | Các tình huống đề xuất để main viết tests; chưa phải kết quả chạy backend production |
| C05 | [Validation](evidence/efy-ca-family-validation.json) | Hash nguồn/evidence, links và kiểm tra offline |

Các ID `EFY-CA-C01`…`C05` là local analyst evidence, không phải REA IDs. Dùng capture/source đã có; không mở lại native session Hopper bị cleanup blocker chỉ để lặp kết quả cũ. Không có phân tích native mới hoặc trace vendor call-flow trong lượt này.

Trạng thái thực tế được cập nhật từ [EFY-CA.md](../EFY-CA.md) và [evidence app](evidence/efy-packaged-app-2026-10-23.json): mẫu EFY ATR `…101139…51…6a` đã đọc và auth thật; người dùng đã bấm **Ký thử** trong app, tự nhập PIN và xác nhận **“Ký và xác minh OK”**. Backend verify bằng đúng DER trước khi trả kết quả. Không có signature capture độc lập trong record app; chưa kiểm tra EFY trên cổng nghiệp vụ. Báo cáo PIN-only A/B là lịch sử trước khi main tích hợp, không phải trạng thái cuối hiện nay.

## 1. Mask Calais chính hãng là nguồn thay cho exact firmware list

**Quan sát C01:** capture trên VM Windows đã cài EFY, cả Registry32 và Registry64 cùng giá trị tại:

```text
HKLM\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\EFY-CA Token Manager v1.0
ATR     = 3b9f958131fe9f006646530500000071df000051000000
ATRMask = ffffffffffffffffffffffff000000ffffffffffffff00
Crypto Provider = EFY-CA Token CSP v1.0
```

So khớp: cùng độ dài23 và `(actual[i] & mask[i]) == (template[i] & mask[i])` cho mỗi byte. Chỉ wildcard **12,13,14,22**, đánh số từ0. Byte customer19 vẫn phải là `51`; bytes18/20/21 vẫn là `00`. Không mở wildcard toàn bộ historical bytes chỉ vì driver chung cũng dùng ePass2003.

Nguồn có thể đối chiếu trực tiếp: [capture registry E13](evidence/efy-ca-installed-windows.json), [hash module E14](evidence/efy-ca-installed-hash-crosschecks.json); C01 lưu SHA-256 của hai file và raw query/capture. Raw query mở `LocalMachine` và hai registry views. Đây là cấu hình đã quan sát cùng provider đã cài; chưa trace installer nên không tuyên bố đã chứng minh lệnh setup nào ghi mask.

Các DLL main đã đối chiếu payload và installation:

| Module | SHA-256 |
|---|---|
| Windows x86 `efyca_p11_v1.dll`, 1.1.25.207 | `49b0577682f70ea8208580fb499774c6ac4e3c778df5d76b1ee0b6a6ad2d04e0` |
| Windows x64 cùng tên/version | `4cd6c0b57b35d5ee6109edf020370abfa6d8f63befd150ccd20210a5b1bff010` |

Đã mở lại [thư viện hỗ trợ EFY](https://efyca.vn/page/thu-vien-ho-tro) và tải tĩnh đúng link Token Manager của trang. File nhận được có SHA-256 `55dff7…6f546`, bằng installer khảo sát trước; hash công bố trên trang là `1c288f…e1ba4`, khác file nhận được. C01 giữ URL/final URL/header/hash để không đánh đồng hai giá trị. Không chạy bộ cài hoặc suy diễn lý do khác hash. Trang và package này không phải danh mục đầy đủ mọi thế hệ EFY.

## 2. Cấu trúc ATR và checksum

ATR live đã đo:

```text
3b 9f 95 81 31 fe 9f 00 66 46 53 05 10 11 39 71 df 00 00 51 00 00 6a
```

| Offset từ0 | Vai trò trong cấu trúc này | Chính sách candidate EFY v1 |
|---|---|---|
| 0 | TS=`3B` | Giữ cố định |
| 1 | T0=`9F`:15 historical bytes, TA1+TD1 | Giữ cố định và kiểm tra cấu trúc |
| 2 | TA1=`95` | Giữ cố định |
| 3 | TD1=`81`, T=1, có TD2 | Giữ cố định |
| 4 | TD2=`31`, T=1, có TA3/TB3 | Giữ cố định |
| 5–6 | TA3=`FE`, TB3=`9F` | Giữ cố định |
| 7–21 | Historical bytes15 byte | Chỉ wildcard12–14 theo Calais |
| 12–14 | Mẫu live=`10 11 39` | Vendor cho phép biến đổi; không coi là customer/OEM ID |
| 19 | Customer hint=`51` | Giữ cố định trong mask EFY này; không phải chứng minh issuer/trust |
| 22 | TCK=`6A` | Không hardcode; kiểm tra XOR hợp lệ |

Với ATR T=1 này, `XOR(bytes[1...22]) == 0`; tương đương TCK là XOR bytes từ T0 đến historical byte cuối, bỏ TS. Đây là kiểm tra tính toàn vẹn cấu trúc, không xác thực CA/token. Xem giải thích kỹ thuật từ [Analog Devices](https://www.analog.com/cn/resources/technical-articles/the-ds8007-and-smart-card-interface-fundamentals.html). Calais mask bỏ checksum để một firmware suffix khác có TCK tương ứng vẫn được chọn; mask đó **không tự kiểm tra TCK**.

OpenSC cũng có các triplet version `01:00:11` và `23:00:25` trong ví dụ ePass2003, cùng một mask driver. Điều này củng cố cách coi12–14 là phần version/personalization có biến thể, nhưng không định danh chính xác ý nghĩa từng byte EFY hoặc chứng minh các suffix ấy đã được EFY phát hành. [Source upstream pinned](https://github.com/OpenSC/OpenSC/blob/0.27.1/src/libopensc/card-epass2003.c), source/hash/ranges lưu trong C03.

**C02 chạy offline:**19 vectors,768 single-byte wildcard values và144 bit mutations ở các vị trí fixed đều đạt kỳ vọng. Các ví dụ synthetic `…100631…`, `…105239…`, `…010011…`, `…230025…` có customer51 và TCK tính lại đều qua candidate mask, dù không bằng exact ATR mẫu. Chúng **không phải token/model EFY đã quan sát**. Không suy ra “768 model được hỗ trợ”.

Các negative cases bao gồm TCK sai dù mask khớp, thiếu/thừa byte, sai prefix/FS/personalization, fixed bytes18/20/21 đổi và customer69/59/32. C02 không nạp runtime và không cấp quyền auth/sign.

## 3. Protocol/capability cần xác định trước PIN

**Quan sát source C03:** `epass2003` nhận diện một họ ATR rộng hơn EFY, rồi `GET_DATA 00 CA 01 86` đọc thông tin thẻ để phân loại FIPS/non-FIPS, AES/DES của SM và trường hợp plain/SCP01. Đây là thông tin transport; không phải tên CA, không phải bằng chứng mọi OEM dùng cùng PIN. Public capabilities cũng không chứng minh key thật hỗ trợ tất cả thuật toán mà driver quảng bá.

Đề xuất main triển khai theo các tầng sau:

1. **Candidate discovery:** validate ATR/TCK → mask EFY Calais và/hoặc provider family có nguồn. Không yêu cầu suffix12–14 nằm trong exact list. Exact list cũ giữ làm regression corpus và lịch sử hardware, không làm rào cản firmware.
2. **Transport preflight:** bind đúng physical reader; recheck ATR sau connect, runtime ABI đã đo và driver `epass2003`; reset/SM refresh có kiểm tra return value. `epass2003_init` gọi refresh nhưng không truyền lỗi refresh ra ngoài ở chỗ đó, nên driver name/connect thành công riêng lẻ chưa đủ. SM handshake khác xác thực PIN người dùng.
3. **Public schema preflight:** bounded SELECT/READ catalog `3F00/2003/6F01`; resolve logical cardid/cert*/prvk*, class/type/sign capability, exact CKA_ID và public-key match. FID/key reference đọc động; không hardcode mẫu `24C0`/`A020`. Catalog schema khác phải chọn parser/provider khác hoặc báo rõ chưa có, không tự giả layout.
4. **Auth eligibility:** chọn đúng hợp đồng EFY ESPK v1 challenge-auth đã có nguồn và kiểm chứng; kết quả preflight không xung đột protocol/SM/key/PIN policy. Không dùng exact firmware list để thay hợp đồng này. Nếu cùng family/protocol thì biến thể mới có thể dùng cùng backend ở mức experimental; coverage auth/sign của chính biến thể đó vẫn là “chưa đo” đến khi user thực hiện thành công.
5. **Operation capability:** current native profile chỉ RSA2048/e65537, refs `A000...AFFF`, RSA_PKCS/SHA256_RSA_PKCS đã có implementation. Nếu card trả RSA3072/EC hoặc yêu cầu auth khác, vẫn có thể hiển thị trạng thái nhận/đọc được, nhưng không tạo signing target cho cơ chế chưa hỗ trợ. Không gửi PIN rồi mới phát hiện unsupported key/mechanism.
6. **Single user auth/sign:** user chọn đúng cert và nhập PIN → một auth, không fallback/retry; sign đúng snapshot và verify đúng DER, cleanup. Không suy ra mọi portal pass từ chữ ký test local.

Nếu cần expose GET_DATA để chẩn đoán: giữ actual response length, dùng parser contract của version đã pin; không diễn giải buffer ngắn/marker lạ thành mode mặc định và cho phép auth. Không cast `drv_data` riêng của OpenSC vì có session keys và ABI private. Chỉ lưu mode/boolean/version cần thiết; không log key material. Trong lượt nghiên cứu này không gửi thêm GET_DATA.

Không probe bằng default PIN, `C_Login`/`sc_pin_cmd`, zero-length external-auth để hỏi retries, MSE/PSO, change/unblock/keygen/erase hoặc thử tuần tự nhiều công thức PIN. Native backend dùng external-auth trực tiếp đã đo; không thay bằng generic padding16 của OpenSC PIN command.

**Giới hạn logic:** CKA_ID/public-key match chứng minh association của metadata, không tự chứng minh công thức PIN hoặc possession. Auth protocol phải có nguồn riêng ở lớp provider; suffix/issuer/cert label không thay thế được nguồn đó. OpenSC SM cipher AES không có nghĩa phải đổi user-PIN cryptogram sang AES; hai lớp này độc lập.

## 4. Những dòng khác/OEM khác

| Nhóm | Bằng chứng hiện có | Hướng xử lý |
|---|---|---|
| EFY v1 / ePass2003 / ESPK, ATR đã đo101139 | Read/auth native và ký thử app đã được xác nhận | Giữ provider đã tích hợp, verify và cleanup |
| EFY v1 cùng Calais mask, suffix mới | Vendor candidate mask + protocol/source; chưa có hardware của suffix mới | Discovery/preflight không PIN; không bắt vá exact ATR; capabilities/coverage tách riêng |
| ePass2003 FIPS/AES hoặc plain mode/personalization khác | OpenSC có nhánh source; chưa đo riêng EFY cho từng nhánh | Đọc mode/schema để chọn contract phù hợp; không tự coi mọi nhánh đã hardware verified |
| Legacy EnterSafe/ePass3000/PK-01C | Upstream có **driver khác** `entersafe`, PIN path khác `epass2003`; vendor DLL có ATR-like bytes chưa xref | Backend riêng khi có artifact/model association. Không dùng EFY challenge-auth chỉ vì cùng Feitian/EFY |
| EFY trên OEM khác, nếu gặp | Chưa xác định được artifact/mẫu EFY Longmai/SafeNet/khác trong phạm vi search hiện tại | Candidate/provider tương ứng có nguồn; thiếu backend thì báo rõ, không ép ESPK |

Không có bằng chứng đủ để nói EFY đã phát hành mọi dòng trong bảng; ba dòng cuối là các ranh giới cần giữ khi mở rộng architecture. Query giới hạn hai domain chính hãng và inventory đã khảo sát được ghi trong C03. Không tìm được artifact model khác trong tập này không có nghĩa chúng không tồn tại.

Tên `thunderEFYCA.exe` và `thunderEFYCAun.exe` trong installer dễ bị hiểu là thêm một họ token. Inventory NSIS thực cho thấy thành phần NSS/Thunderbird registration helpers/certificates, không phải bằng chứng một OEM USB khác. C03 giữ hash và archive member list. CCID INF trong package match `USB\Class_0B&SubClass_00`, là class generic, không định danh EFY/model.

## 5. Ma trận coverage cần main giữ

| Profile/model bucket | Detection | Public read | User auth | Sign + verify | Portal |
|---|---|---|---|---|---|
| EFY101139/customer51 đã đo | Thật | Thật | Thật, SW9000 | User xác nhận Ký thử app OK; không signature capture riêng | Chưa đo |
| EFY v1 masked suffix khác | Có nguồn mask + offline fixture | Chưa đo riêng; chờ preflight thực | Chưa đo riêng | Chưa đo riêng | Chưa đo |
| EFY mode/schema/OEM khác | Chưa có model inventory đầy đủ | Tùy provider, chưa đo | Chưa đo | Chưa đo | Chưa đo |

Thêm một device observation phải cập nhật model/protocol/capability và cấp độ evidence; không chuyển cả family thành “đã ký” khi chỉ thêm ATR candidate. Bridge MISA/Minvoice/eTax dùng target/capabilities chung, không cài lại bảng ATR trong adapter.

## 6. Bàn giao để triển khai và nghiệm thu

- **Routing tests:** lấy exact mask từ C01, positive/negative C02. Ưu tiên shared family matcher/preflight; Swift và C phải cùng contract. Không đổi những test “exact mismatch” thành unconditional success: suffix mới đi đến preflight, mismatch về protocol/metadata vẫn phải dừng trước PIN.
- **Preflight tests:** C04 có các tình huống candidate-only, metadata mismatch, SM lỗi, unsupported key, khác OEM và biến thể cùng contract. C04 là specification fixtures, chưa chạy production tests ở chat nghiên cứu.
- **Hardware coverage:** không yêu cầu từng suffix mới để viết detection. Khi user cắm token mới, chỉ đọc metadata/capability trước; auth/sign là thao tác user chủ động và phải ghi mức evidence riêng. Chưa có hardware nào mới được test ở lượt coverage này.
- **File ownership:** main sở hữu `EfyProfile`, `ModuleRegistry`, `CFastCA`, `ESPK`, UI và build; chat EFY chỉ thêm báo cáo/evidence prefix `efy-ca-family-*`. Không sửa/stage tài liệu/source của các chat khác.

Checklist câu hỏi: mask/hash/cấu trúc/checksum đã trả lời; variant fixtures đã có; capability/protocol gates đã có nguồn và đề xuất; danh mục đầy đủ mọi EFY OEM/model **còn thiếu nguồn**, không tuyên bố hoàn tất. Phần implementation và tests production do main điều phối tiếp.
