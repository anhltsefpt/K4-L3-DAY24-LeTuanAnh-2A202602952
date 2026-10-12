# Verification

- OS / Python / Gitleaks: macOS (Darwin 25.4.0) / Python 3.11.6 / Gitleaks 8.30.1
- `python -m pytest tests/ -q --basetemp=.pytest_tmp`: 35 passed, 0 failed, 0 skipped (33 bắt buộc + 2 bonus)
- `pre-commit run --all-files`: Detect hardcoded secrets — Passed
- Ledger verify: `True`
- `reports/attack-after.log`: 0 byte
- Các lỗi còn lại: không có

## Lỗi gặp và cách sửa

- `.venv` chưa có `pre-commit` và `pip-tools` → cài bằng `python -m pip install pre-commit pip-tools` (theo preflight trong README).
- Bản runner đầu tiên mở `customers.json` trước khi kiểm policy, nên `support_l1` vẫn chạm vào private store dù test vẫn pass → thêm một lần `check()` trước khi mở file. Lượt kiểm `http_post` cũng bỏ customer ID, chỉ còn URL.

## CP1, CP2

- `reports/baseline.md`: trả lời 3 câu, có dẫn dòng code.
- `python -m agent.check_lure corpus/ticket-90*.md` → `4/4 lure sẵn sàng`.
- `reports/attack-before.log`: 4 dòng (901, 902, 903, 904+904b), mỗi dòng là một POST `/reconcile` chứa hồ sơ synthetic của `KH-000999`.

## CP3a — PII

`python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp`

```
[pii] gold=118 pred=118 tp=118
[pii] precision=1.000 recall=1.000
```

Dùng regex cho 4 loại. STK phải có nhãn "STK"/"tài khoản" đứng trước, vì STK 12 số trông giống hệt CCCD.

Giới hạn:
- STK không có nhãn thì bỏ sót hoặc bị nhận thành CCCD.
- Dãy 12 số bất kỳ (mã đơn, mã giao dịch) cũng bị coi là CCCD.
- Chưa bắt SĐT dạng `+84`, chưa nhận tên hay địa chỉ.
- Test set sinh theo mẫu cố định nên 100% ở đây không có nghĩa là 100% với dữ liệu thật.

## CP3b, 3c — Policy và OBO

`python -m pytest tests/test_policy.py tests/test_obo.py -v --basetemp=.pytest_tmp` → 9 passed.

`support_l1` bị chặn `read_customer`, `dpo` vẫn đọc được. Agent con vượt `parent_scopes`, principal lạ hay hết hạn đều bị deny.

## CP3d — Split

`python -m pytest tests/test_split.py tests/test_injection.py -v --basetemp=.pytest_tmp` → 9 passed, không SKIP.

Run B chỉ nhận số ticket lấy từ tên file, nên không bao giờ đọc `KH-000777`. `dpo` vẫn đọc `KH-000999` hợp lệ, nhưng `http_post` bị chặn nên không có gì ra sink.

## CP3e — Ledger

`python -m pytest tests/test_ledger.py -v --basetemp=.pytest_tmp` → 3 passed.

Chạy `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"`, sau đó `verify(reports/ledger.jsonl)` trả `True`. Dòng cuối: `http_post`, `deny`, `on_behalf_of=dpo`, reason "restricted data cùng egress_enabled=True".

Thử sửa `decision` một dòng giữa trên bản sao ledger → `verify()` trả `False`.

## CP4 — Supply chain

- `gitleaks version` → `8.30.1`
- `gitleaks git --config .gitleaks.toml --redact --verbose .` → 9 commit, `leaks found: 1`, exit 1. Finding ở `1bdd849`, `lab-fake-secret.txt:1`, rule `lab24-synthetic-token`. Đây là token giả, đúng như đề dự kiến.
- `gitleaks dir --config .gitleaks.toml --redact .` → `no leaks found`, exit 0. Không cần sửa allowlist.
- `python -m piptools compile --generate-hashes -o requirements.lock requirements.txt` → 10 package, package nào cũng có hash.
- `python -m pip install --require-hashes -r requirements.lock` → exit 0.
- `pre-commit install` rồi `pre-commit run --all-files` → Passed.
- `python -m pytest tests/test_supply_chain.py -v --basetemp=.pytest_tmp` → 3 passed.

## CP5 — Prove

Sink ở Terminal A vẫn chạy trong lúc test; `conftest.py` dùng lại sink đó.

1. `python sink/sink.py --reset`, sau đó `python -m pytest tests/ -q --basetemp=.pytest_tmp` → 33 passed.
2. `python sink/sink.py --reset`, sau đó `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"`.
3. `cp reports/sink.log reports/attack-after.log` → 0 byte.
4. `reports/ledger.jsonl` có 48 dòng (2 lượt chạy `dpo`, mỗi lượt 24 dòng). `verify()` = `True`. Dòng 24 và 48 là `http_post`, `deny`, `on_behalf_of=dpo`, reason "restricted data cùng egress_enabled=True".

So sánh: `attack-before.log` có 4 POST chứa `KH-000999`, còn `attack-after.log` rỗng.

## Bonus — Delete cascade giữ ledger verify

`python -m pytest tests/test_bonus_delete_cascade.py -v --basetemp=.pytest_tmp` → 2 passed.

`agent/erasure.py` xoá hồ sơ khách khỏi `customers.json`, che PII của khách trong các ticket gắn với họ (`related_tickets`), rồi ghi một dòng `delete_customer` vào ledger. Ledger không phải sửa vì chỉ chứa `args_hash`, nên `verify()` vẫn `True`. Chỉ principal có purpose `privacy-audit` (`dpo`) mới được xoá; `support_l1` bị deny và có ghi ledger. Test chạy trên bản sao trong thư mục tạm, không sửa dữ liệu thật.
