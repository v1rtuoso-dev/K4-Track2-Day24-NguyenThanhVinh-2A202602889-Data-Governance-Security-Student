# Baseline — luồng trước containment

1. **Chưa có identity riêng mỗi run.** `agent/loop.py:27`, `_naive_loop`,
   nhận message/llm, không tạo agent_id/run_id, principal, scope hoặc TTL.
   Đây là baseline; runner sau sửa đã có các trường đó.
2. **Không có policy cho phép ở boundary.** `_naive_loop` tin kết quả
   find_injection từ text tìm kiếm, đọc khách tại `agent/loop.py:39` rồi
   gọi http_post tại `agent/loop.py:44`. `agent/tools.py`, `http_post`,
   chỉ allowlist localhost cho an toàn lab, không kiểm mục đích/OBO/PII.
3. **Bằng chứng gửi sai:** `reports/attack-before.log:1` đến dòng 4 có POST
   `/reconcile`, body chứa record synthetic KH-000999 và CCCD/SĐT/STK.
   Sink ghi request trong `sink/sink.py`, `make_handler().Handler.do_POST`.
   Baseline không ghi ledger để giải thích quyền gửi. Sau sửa, CP5 có
   `reports/attack-after.log` 0 byte và `reports/ledger.jsonl:72` http_post
   deny thay mặt dpo; xem reports/cp5-evidence.json.
