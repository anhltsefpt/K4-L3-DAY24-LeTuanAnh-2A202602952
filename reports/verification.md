# Verification — điền trước khi nộp

- OS / Python / Gitleaks version: macOS (Darwin 25.4.0) / Python 3.11.6 / Gitleaks: điền ở CP4
- `python -m pytest tests/ -q`: điền ở CP5
- `pre-commit run --all-files`: điền ở CP4
- Ledger verify: điền ở CP5
- Các lỗi còn lại: điền ở CP5

## CP3a — PII gate

Lệnh:

```bash
python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp
```

Kết quả trên `tests/vn_pii_testset.jsonl` (120 dòng):

```
[pii] gold=118 pred=118 tp=118
[pii] precision=1.000 recall=1.000
2 passed
```

Cách làm (`agent/pii.py`): regex cho `EMAIL`, `VN_BANK_ACCOUNT` (8–16 số, bắt buộc đứng sau nhãn `STK` / `số tài khoản` / `tài khoản`), `VN_CCCD` (đúng 12 số), `VN_PHONE` (0 + 9–10 số, cho phép dấu cách/chấm/gạch). Khi hai loại trùng vùng, giữ loại ưu tiên cao hơn theo thứ tự trên, nên STK 12 số không bị báo thêm là CCCD. `redact()` thay từ cuối chuỗi về đầu.

Giới hạn của regex:

- STK không có nhãn sẽ bị bỏ sót, hoặc bị nhận nhầm thành CCCD nếu đúng 12 số.
- Mọi dãy 12 số (mã đơn hàng, mã giao dịch) đều bị coi là CCCD, gây false positive ngoài test set.
- SĐT viết dạng `+84` hoặc nhóm số khác `0xx(x) xxx xxx(x)` không bắt được.
- Không nhận diện tên người, địa chỉ hay PII viết bằng chữ (ví dụ "không chín một hai…").
- Test set do repo sinh theo mẫu cố định, nên recall 100% ở đây không có nghĩa là recall 100% trên dữ liệu thật.

## CP3b / CP3c — Policy và OBO

```bash
python -m pytest tests/test_policy.py tests/test_obo.py -v --basetemp=.pytest_tmp
```

Kết quả: 4/4 test policy và 5/5 test OBO pass. `support_l1` bị deny `read_customer`; `dpo` đọc được khách gắn với ticket hợp lệ; agent con xin tool ngoài `parent_scopes` bị deny; principal lạ hoặc `expires_at` đã qua bị deny.
