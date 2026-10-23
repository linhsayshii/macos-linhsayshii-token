# FastCA ATR 0631 — sửa trạng thái “Chưa hỗ trợ”, 23/10/2026

USB FastCA mới dùng reader `FT ePass2003Auto 01`, ATR
`3b9f958131fe9f006646530510063171df00006900004d`.
App đã tích hợp FastCA nhưng chỉ nhận exact ATR mẫu 22/10
`3b9f958131fe9f006646530510523971df000069000011`, nên registry trả nil cho chiếc
mới và UI hiện “Chưa hỗ trợ”. Đây là khác biệt giữa hai thiết bị thực, không phải
FastCA bị mất sau merge vào main.

## Xác minh trước sửa

Probe riêng chỉ đọc metadata trên đúng ATR mới, không nhận PIN, xác thực PIN hoặc ký:

- OpenSC 0.27.1 nhận driver `epass2003`.
- Catalog `6F01` dài 1500 B, 9 logical files, cardid 16 B.
- Certificate và key metadata có CKA_ID khớp, RSA 2048/exponent 65537,
  CKA_SIGN=true, key reference A020; public key trong DER khớp metadata.
- DER 1414 B, SHA-256
  `852a2044fed4395d93ec62fcb49f6da5ac1408b1304953294ca88726377412e9`.
- Issuer `FastCA SHA-256 R1`; hiệu lực 22/12/2025–06/08/2028. Đây là chiếc khác
  mẫu hết hạn tháng 7/2026; không gán kết quả expiry cũ cho thiết bị mới.

[Read-only validation](evidence/fastca-0631-readonly-validation.json),
[probe C](evidence/fastca-0631-readonly.c),
[metadata check](evidence/fastca-0631-metadata-check.swift).
Raw metadata/DER giữ riêng trong `.local/fastca-profile-20261023`, không đưa vào repo.

## Sửa và kiểm tra

Bổ sung exact ATR thứ hai vào `FastCAProfile`, registry, ESPK reader filter và
CFastCA card guard. Không mở wildcard customer byte, không giả ATR hay sửa vendor
binary. Preflight metadata/key/cert và approval/PIN vẫn bắt buộc như trước.

Tests kiểm tra cả hai exact profiles, từ chối thay đổi từng byte, không route
FastCA sang EFY và không gửi xác thực PIN trong bước nhận/read metadata.
Native C mock transport đạt; build và **172 Swift tests** đạt (7/7/47/89/22).

Helper production đã trả đúng label FastCA, token serial ổn định và chứng thư mới
trước PIN. App bundle được đóng gói lại, xác minh shim/runtime/signature và mở lại.
`GET /api/HubClient/GetCert` HTTP/status 200 có đúng DER mới giữa 5 chứng thư đang
cắm. [App validation và tổng hợp kiểm thử](evidence/fastca-0631-app-validation.json).

Phép đo này xác nhận nhận diện và đường đọc thật. Kết quả ký mẫu 22/10 không tự
chứng minh xác thực/ký trên chiếc mới; chỉ ghi nhận ký mới sau khi user tự nhập
PIN và xác nhận kết quả. Không kiểm tra portal, chain hoặc revocation trong lượt
chẩn đoán nhận diện.

OpenSC vẫn thiết lập secure messaging cho transport; các con số authentication=0
ở đây chỉ nói về xác thực PIN người dùng, không phải handshake transport.
