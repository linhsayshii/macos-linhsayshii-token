# FastCA family: giới hạn bằng chứng về giao thức PIN

Ngày 23/10/2026. Nghiên cứu tĩnh, không chạy DLL, không gửi PIN/APDU xác thực.
Main sở hữu Sources, tests sản phẩm và build; báo cáo này không mở guard runtime.

## Kết luận dùng cho tích hợp

OpenSC family mask có căn cứ cho **discovery và đọc public metadata**. Chuỗi
gọi trong `fca_v1.dll` cho thấy một lớp card và một auth provider dùng cùng
host-PIN path trong phần đã truy vết. Tuy nhiên chưa chứng minh được mọi ATR
khớp mask sẽ vào cùng lớp/schema; chưa tìm được descriptor public có ý nghĩa
“PIN profile này dùng SHA1 + length / 3DES external authentication”. Không nâng
mọi firmware/model trong family thành đã hỗ trợ PIN chỉ từ mask/catalog.

Mẫu FastCA cũ đã ký/verify thật. Mẫu 0631 mới được đọc cert/key metadata và user
xác nhận app hiển thị FastCA; chưa xác thực/ký thật trên mẫu mới. Các fixture
tổng hợp chỉ kiểm tra quy tắc discovery, không tăng coverage thiết bị thật.

## Artifact và chuỗi host-PIN đã xác định

Artifact `fca_v1.dll`, PE32 x86, image base `0x10000000`, SHA-256
`d2c52982f4799b53b308e306a0c22f6cf59ea27d62c8f57ee6199d7f17ddacf3`.
[REA evidence gốc](evidence/fastca-family-auth-static-rea.json) giữ provider,
địa chỉ, evidence ID, pseudocode/assembly và giới hạn. C_Login và hàm derive
đã được lưu trước trong [evidence Windows](evidence/fastca-windows-native-rea.json).
[Byte bảng và vtable trích từ artifact](evidence/fastca-family-auth-artifact.json)
đã đối chiếu SHA-256, không dựa vào tên function do decompiler tự đặt.

| Mốc | Quan sát tĩnh |
|---|---|
| `1009ac05` | Đăng ký địa chỉ factory `100436d1`. Không có ATR argument tại site đăng ký. |
| `100436d1` → `1004340c` | Factory tạo card object; constructor cài vtable `1009f1dc`. Chưa truy ra đầy đủ caller selection contract. |
| `10023069` | Lấy auth provider qua card virtual `+0xd4`. |
| card `+0xd4` → `10041e63` | Lazy getter tạo object bằng `100404f8`; constructor cài vtable `1009e7a0`, lưu owner card tại `+4`. |
| `C_Login` `1006bc34` → `1004a7e4` | Nhánh user type 1 biến raw PIN bytes thành `SHA1(rawPIN) || BE32(rawByteLength)` (24 byte). |
| `1006cf71` | Gọi auth provider virtual `+4`, rồi virtual `+0x14`. |
| auth `+0x14` → `100402f3` | Lấy challenge 8 byte qua virtual `+0xc`, dùng IV 0 và `10040bd1`, gửi cryptogram 8 byte qua virtual `+0x18`. Assembly xác nhận, không dựa vào điều kiện pseudocode bị decompiler diễn giải sai. |
| `10040bd1` | Nhận key length 16 hoặc 24; path từ raw PIN nói trên cho 24 byte và gọi helper 3DES. |
| auth `+0x18` → `100405c7` | Delegate về owner card virtual `+0x34`. |
| card `+0x34` → `10049165` | Xây APDU `CLA=00 INS=82 P1=01 P2=(userType OR 80)`, kiểm tra status 9000; với user 1 là `00 82 01 81`. |

Trong chuỗi đã quan sát không thấy nhánh chọn công thức PIN theo ATR/version.
Đây là bằng chứng cùng implementation cho object class đã truy, **không phải**
chứng minh toàn bộ family được chọn vào class đó. Bằng chứng có thể dùng để
kiểm tra native implementation hiện tại; việc mở coverage cần thêm selection
contract hoặc read-only descriptor được chứng minh gắn với lớp/auth schema.

## Hai tín hiệu không được dùng làm bằng chứng auth family

**Vendor ATR record.** Tại VA `100c0460` / file offset `0xbee60` có cấu trúc
76 byte giống `SCARD_ATRMASK`: cbATR 23, rgbATR tại `+4`, mask tại `+40`.

```text
raw stored pattern 3b9f958131fe9f006646530500000071df000009000000
stored mask        ffffffffffffffffffffffff000000ffff000000000000
```

`1006dcd2` nhánh arg8=0 đọc bảng này. Assembly `1006dd9e..1006dda9` chỉ AND
input với mask; `1006ddab..1006ddb5` so với raw stored pattern. Byte 19 của
pattern là `09` trong khi mask ở byte 19 là `00`. Vì vậy không được tự normalize
pattern rồi khẳng định đây là quy tắc runtime chấp nhận family. Có thể còn setup
khác hoặc caller dùng nhánh bypass arg8!=0; chưa có quan sát runtime giải quyết
điểm này. Source OpenSC đã mask cả hai vế nên không có cùng suy luận mơ hồ.

**Literal `ENTERSAFE-ESPK`.** VA `100be168` có một xref tại `100487aa` trong
`100485b7`; caller đẩy literal cùng FID `2003` vào `10046d49`. Assembly của
`10046d49` dựng FCP và APDU `INS E0` (CREATE FILE). Đây là dữ liệu ghi khi khởi
tạo DF, không phải bằng chứng hàm đọc/kiểm tra magic hay descriptor auth public.
Không thực thi hàm này. Catalog tồn tại hay khớp literal, nếu có, cũng cần chứng
minh liên hệ với auth schema trước khi dùng làm điều kiện cấp PIN capability.

## Metadata public và transport

OpenSC `card-epass2003.c` init đọc GET DATA `0186`; các byte version/FIPS/AES/DES
ảnh hưởng secure messaging của transport. Transport mutual authentication khác
user PIN authentication ở trên. Không suy PIN profile từ byte AES/DES này.
ESPK catalog, CKA_ID, sign flag, modulus/exponent xác minh cert/key binding và
khả năng chọn key; bản thân chúng chưa quảng bá công thức PIN đã chứng minh.

Kết quả bounded: mở discovery theo driver có nguồn; ghi capability đọc được và
thuật toán thật; giữ trạng thái “chưa xác minh giao thức xác thực” khi chưa có
mapping auth đủ căn cứ. Không thử lần lượt protocol hoặc PIN formula để dò.
