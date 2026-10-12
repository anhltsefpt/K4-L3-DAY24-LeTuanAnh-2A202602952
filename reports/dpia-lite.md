# DPIA-lite

Bản mô tả để học, không phải hồ sơ đánh giá tác động theo pháp luật. Toàn bộ dữ liệu là synthetic do repo cung cấp.

## 1. Dữ liệu nào

- **Ticket** (`corpus/*.md`): `internal`. Đây là nội dung không tin cậy, ai cũng có thể viết, kể cả attacker (lure 901–904b).
- **Hồ sơ khách** (`data/customers.json`): `restricted`. Có tên, CCCD, SĐT, STK, email, `related_tickets`.
- **Ledger** (`reports/ledger.jsonl`): chỉ có metadata và `args_hash`, không chứa PII thô.

## 2. Ai, mục đích gì

Lấy theo `data/principals.json`:

- `support_l1`: chỉ được `search_docs`, mục đích `summarize-tickets` / `support-reply`.
- `dpo`: được `search_docs` và `read_customer`, mục đích có `support-reply`.
- Không principal nào có `http_post`.

## 3. Dữ liệu đi qua đâu

1. **Run A** (`search_docs`): đọc ticket, che PII, chỉ chuyển ra ngoài danh sách số ticket lấy từ tên file và một cờ "có injection".
2. **Policy** (`agent/policy.py`): được gọi trước mỗi tool, kể cả trước khi mở `customers.json`.
3. **Run B** (`read_customer`): suy khách từ `related_tickets`, đọc hồ sơ nếu policy cho phép.
4. **Run C** (`http_post`): chỉ được thử khi ticket đòi gửi dữ liệu ra ngoài; luôn bị deny.
5. **Sink** `127.0.0.1:10024`: máy nhận giả lập, chỉ chạy trên localhost.
6. **Ledger**: ghi mọi quyết định allow và deny.

## 4. Đã chặn / cho phép gì, còn giới hạn gì

- **Trước khi sửa:** `reports/attack-before.log` có 4 POST chứa hồ sơ `KH-000999`.
- **Sau khi sửa:** chạy lại với `--as dpo` thì `reports/attack-after.log` có 0 byte.
- `dpo` vẫn đọc được `KH-000999` vì khách này gắn với ticket 901–905, nhưng `http_post` bị deny (`reports/ledger.jsonl:24`, `:48`).
- `support_l1` bị deny `read_customer`. `KH-000777`, khách chỉ được nhắc trong text, không bao giờ bị đọc.

**Giới hạn:**
- Mock LLM nhận diện chỉ thị bằng marker, không phải model thật.
- Quyền là giả lập, không có xác thực người dùng.
- Regex chỉ bắt 4 loại PII theo mẫu của test set.
- Hash chain không phát hiện việc xoá dòng cuối hoặc viết lại cả file.
- Chưa xử lý việc lưu trữ, thời hạn xoá hay quyền của chủ thể dữ liệu.
