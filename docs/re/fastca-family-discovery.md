# FastCA: cơ sở để nhận họ thiết bị thay cho hai exact ATR

Yêu cầu ngày 23/10/2026: [TOKEN-COMPATIBILITY.md](../TOKEN-COMPATIBILITY.md).
Đây là đề xuất cho main tích hợp, chưa phải thay đổi runtime đã triển khai.

OpenSC 0.27.1 có sẵn family matcher trong `src/libopensc/card-epass2003.c`,
bảng `epass2003_atrs` dòng 61–68 và `epass2003_match_card` từ dòng 1675:

```text
pattern 3b9f958131fe9f006646530500000071df000000000000
mask    ffffffffffffffffffffffff000000ffffffff00000000
```

Driver cố định các byte transport/FTCOS, cho phép biến thể ở chỉ số 12–14 và
19–22. Comment upstream minh họa firmware 2012 và 2022, ATR được khởi tạo bởi
OpenSC hoặc Feitian. Đây là bảng trong source driver thực, không suy ra wildcard
chỉ từ hai mẫu. Cả hai ATR FastCA đã cắm đều khớp matcher này và có TCK XOR bằng 0.

[Source hash, fixture comparison và phạm vi](evidence/fastca-family-source.json).
Source upstream LGPL 2.1+ đã nằm local từ đợt chuẩn bị OpenSC, không tải/chạy thêm
installer hoặc nạp module vendor trong lượt nghiên cứu này.

## Cấu trúc ATR và bộ fixture chuyển cho main

Hai mẫu và bảng upstream dài 23 byte: TS ở 0; T0 `9F` ở 1 cho 15 historical
bytes; TA1 ở 2, TD1 ở 3, TD2 ở 4, TA3/TB3 ở 5–6; historical bytes ở 7–21;
TCK ở 22. Có T=1 nên XOR byte 1–22 phải bằng 0. Byte TCK nằm trong phần mask
wildcard, vì vậy **mask match không phát hiện checksum sai**. Hàm parse ATR
OpenSC được xem trong `sc.c` không thực hiện TCK check; không gán kiểm tra này
cho upstream matcher. Main cần kiểm tra cấu trúc/checksum ở lớp chung.

[14 fixture ATR](evidence/fastca-family-fixtures.json) gồm hai mẫu thật, ba ví
dụ source upstream, EFY cùng OEM, OneCA khác OEM, biến thể tổng hợp hợp lệ,
customer chưa biết, checksum sai, thiếu/thừa byte và fixed signature khác.
[Script reference offline](evidence/fastca-family-matching.py) tái tạo và kiểm
tra fixture, không I/O thiết bị, không phải test của parser sản phẩm. Tám case
preflight đi kèm mô tả metadata/key mismatch và capability chưa biết; đây là
đầu vào cho main triển khai tests, chưa phải test preflight đã chạy.

Toàn bộ ATR fixture đều có `signingAuthorizationEstablishedByATR=false`:
mask chỉ chọn family candidate. [Đối chiếu auth tĩnh](fastca-family-auth.md)
phân biệt bằng chứng chung implementation với khoảng trống mapping model/PIN.

## Đề xuất tuyến discovery

- Phân tích ATR hợp lệ trước; family matcher từ driver là đầu vào chọn candidate.
  Không chỉ sửa hai byte khác nhau ở mẫu rồi tiếp tục đoán mọi byte khác cố định.
- Family matcher upstream bỏ qua cả customer byte: nó dùng chung cho nhiều CA.
  Giữ customer/OEM/metadata làm tín hiệu chọn profile/provider; không coi mọi
  ePass2003 là FastCA. EFY và FastCA vẫn cần xác định profile/auth semantics riêng.
- Với candidate FastCA, dùng OpenSC nhận driver thực và đọc public ESPK catalog,
  cardid, cert/key attributes. Catalog phải đúng format; ghép CKA_ID, sign flag,
  thuật toán và public key trước khi quảng bá signing target.
- Firmware/model mới khớp họ nhưng không có ESPK hoặc khác capability chuyển
  sang provider phù hợp hay báo rõ thiếu backend. Không dùng công thức PIN của
  chiếc mẫu với một applet chưa chứng minh tương thích.
- Tách mức nhận diện/đọc và khả năng xác thực/ký đã có căn cứ. Signature operation
  vẫn qua user approval/PIN, không auto retry, verify trước trả kết quả.

Chứng cứ này đủ để mở rộng bước **discovery không PIN** có căn cứ; không tự
chứng minh mọi firmware trong matcher dùng cùng PIN protocol/ESPK applet. Cùng
CA có thể dùng OEM khác ngoài ePass2003, cần inventory/provider riêng để đạt mục
tiêu bao phủ toàn hãng. Tránh nghiệm thu bằng việc matcher này nhận một lượng
lớn chuỗi ATR nhưng backend không thực sự đọc/ký được các model tương ứng.

Main điều phối thay đổi registry, reader filter, C guard và UI chung. Phiên FastCA
không mở matcher runtime ngay trong lượt gửi định hướng để tránh sửa chồng file
chung với main/EFY đang làm việc.
