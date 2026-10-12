# Compliance mapping — đối chiếu kỹ thuật, 12/10/2026

Đã mở và kiểm tên/số văn bản trên trang nguồn chính thức bên dưới. Chưa
đối chiếu điều khoản cụ thể trong toàn văn pháp luật: **chưa xác minh**.
Control được liên hệ theo chủ đề học tập, không chứng nhận tuân thủ.
Số dòng code/report kiểm bằng rg; số dòng ledger của lượt CP5 là 72.

| Nguồn/chủ đề | Control đã làm | Bằng chứng file:dòng thật | Giới hạn |
|---|---|---|---|
| [Luật 91/2025/QH15 — Bảo vệ dữ liệu cá nhân](https://vanban.chinhphu.vn/?docid=214590&pageid=27160) | Phát hiện/che PII, kiểm purpose trước tool | `agent/pii.py:50`, `agent/pii.py:63`, `agent/policy.py:73`, `reports/pii-test.log:10` | Điều khoản áp dụng: chưa xác minh; regex không bao phủ mọi PII; dữ liệu synthetic |
| [NĐ 356/2025/NĐ-CP](https://chinhphu.vn/?docid=216387&pageid=27160) — bảo vệ dữ liệu và audit | Kiểm restricted + egress; lưu quyết định với hash tham số | `agent/policy.py:63`, `agent/runner.py:94`, `reports/ledger.jsonl:72` | Điều khoản áp dụng: chưa xác minh; JSONL/hash chain không tự phát hiện cắt đuôi |
| [Luật AI 134/2025/QH15](https://congbao.chinhphu.vn/van-ban/luat-so-134-2025-qh15-468694/61695.htm) — kiểm soát hành động agent | Tách ID ticket khỏi chỉ thị trong text; egress kiểm riêng | `agent/runner.py:109`, `agent/runner.py:121`, `agent/runner.py:116`, `reports/cp5-tests.log:2` | Điều khoản áp dụng: chưa xác minh; run chỉ phân tách logic trong cùng tiến trình |
| [OWASP ASI01 — Agent Goal Hijack](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) | ID từ tên file; mapping trusted related_tickets; chặn egress | `agent/runner.py:109`, `agent/runner.py:121`, `reports/split-ledger-test.log:22`, `reports/attack-before.log:1`, `reports/ledger.jsonl:72` | Mapping kỹ thuật của lab; mock marker không chứng minh toàn bộ prompt injection trên model thật |
| [OWASP ASI03 — Identity & Privilege Abuse](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) | Giao quyền principal/agent/parent, kiểm purpose và TTL | `agent/policy.py:73`, `agent/policy.py:79`, `agent/policy.py:87`, `reports/policy-obo-test.log:41` | Registry/--as mô phỏng quyền; chưa có xác thực hoặc isolation production |
| [OWASP ASI04 — Agentic Supply Chain Vulnerabilities](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) | Pin/hash dependencies; hook scanner; incident token giả | `requirements.lock:7`, `.pre-commit-config.yaml:3`, `reports/pre-commit.log:2`, `reports/gitleaks-history.json:3`, `reports/gitleaks-history.json:13` | Pin/hash không xác minh package vô hại; already satisfied không tái kiểm artifact đã cài; secret thật vẫn cần thu hồi/rotate |

`reports/attack-after.log` rỗng nên không có dòng để trỏ; kích thước và
verify có trong `reports/cp5-evidence.json`. Dòng 72 ledger chứa http_post
deny, reason non-empty và on_behalf_of dpo. Những lần chạy tiếp sẽ thêm
ledger; giữ số dòng 72 để trỏ đúng evidence CP5 đã lưu.
