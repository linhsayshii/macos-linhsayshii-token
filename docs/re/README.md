# Ghi chú nghiên cứu

Các báo cáo ở đây ghi lại quan sát tại từng thời điểm, không thay thế trạng thái
app hiện tại ở [PROGRESS](../PROGRESS.md) và [đối chiếu nhánh](../BRANCH-CONSOLIDATION.md).
Những dòng “chưa tích hợp”, “không merge” hoặc blocker cũ được giữ làm lịch sử.

JSON/status, hash manifest, public key và fixture được giữ khi đã che dữ liệu.
Trace `.log`, output `.txt` và thư mục `*-probe/` trong evidence là artifact thô
của môi trường nghiên cứu, ignored và chỉ có ở máy gốc; không coi chúng là dữ
liệu phát hành. Bản gốc trước dọn được snapshot trong `.local/branch-consolidation`.

`scripts/re` là công cụ capture được chuẩn bị cho thao tác nghiên cứu do user
chủ động, không phải dependency/runtime của app. Test JS chỉ dùng dữ liệu giả;
không chạy relay hoặc phát hành hóa đơn trong build/test/smoke của app.
