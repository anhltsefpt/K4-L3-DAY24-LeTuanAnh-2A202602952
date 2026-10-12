# Baseline — checkpoint 1

1. **Agent có identity mỗi run chưa?** Chưa. `_naive_loop(message, llm)`. _naive_loop chi gom 2 tham so message va LLM

2. **Ai cho phép `http_post`?** Không ai. Trước `read_customer` (`agent/loop.py:39`)
   và `http_post` (`agent/loop.py:44`) không có policy nào. Customer ID và URL đích
   lấy thông tin từ trong ticket (`agent/loop.py:34`). Bởi vì
   baseline làm theo yêu cầu như trong ticket, nên attacker là người quyết định gửi.
   `agent/tools.py:77` chỉ chặn URL ngoài localhost, không kiểm tra dữ liệu gửi đi.

3. **Bằng chứng gửi sai PII ở đâu?** Body `{"records": collected}` được tạo ở
   `agent/loop.py:44`. Sink ghi body nhận được vào `reports/sink.log`
   (`sink/sink.py:47`). Agent không có ledger riêng.
