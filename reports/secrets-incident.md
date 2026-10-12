# Secret giả trong lịch sử Git

- **Scanner và phiên bản:** Gitleaks 8.30.1, config `.gitleaks.toml` (rule mặc định + rule `lab24-synthetic-token`).
- **Commit chứa token giả:** `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c`).
- **File, rule và kết quả quét lịch sử:** `gitleaks git --config .gitleaks.toml --redact --verbose .` → 9 commit, `leaks found: 1`, exit 1. Finding nằm ở `lab-fake-secret.txt:1`, rule `lab24-synthetic-token`. Đây là token giả, vô hiệu do đề bài cài sẵn, đúng kết quả mong đợi.
- **Kết quả quét file hiện tại:** `gitleaks dir --config .gitleaks.toml --redact .` → `no leaks found`, exit 0. Không có false positive trong `.venv/` nên không chỉnh allowlist.
- **Nếu đây là credential thật, cần xử lý thế nào:**
  1. Thu hồi / rotate ngay tại dịch vụ đã cấp token, cấp token mới qua secret manager.
  2. Xem log của dịch vụ đó để tìm lần sử dụng sai từ lúc commit tới lúc thu hồi.
  3. Xử lý các bản sao: fork, clone, CI cache, artifact. Có thể viết lại lịch sử (`git filter-repo`) nhưng chỉ làm sau khi đã rotate.
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:** file đã bị xoá ở commit sau nhưng token vẫn còn trong lịch sử và mọi bản clone, ai có repo đều lấy lại được. Xoá file không làm token mất hiệu lực, chỉ dịch vụ cấp token mới thu hồi được. Hook pre-commit chỉ chặn lần lộ tiếp theo, còn lock file có hash chỉ bảo vệ dependency, cả hai đều không làm được gì với một token đã lộ.
