# DPIA-lite — bốn câu hỏi của lab

## 1. Dữ liệu nào?

Ticket trong corpus là nội dung không tin cậy, có thể chứa chỉ thị attacker
và PII giả. Hồ sơ trong data/customers.json chứa tên, CCCD, điện thoại,
tài khoản, email và related_tickets synthetic; xử lý như restricted.
Không dùng PII hoặc credential thật. KH-000999 là khách của baseline;
KH-000777 không gắn ticket, dùng để kiểm không đọc theo free text.

## 2. Ai và mục đích nào?

support_l1 chỉ search_docs để summarize-tickets; dpo có thể read_customer
cho support-reply. Quyền lấy từ data/principals.json và giao với scope
agent/parent; TTL UTC năm phút. --as mô phỏng principal, không xác thực
người đang ngồi trước máy và không phải chứng minh OBO production.

## 3. Đi qua đâu?

Run A search_docs sau policy và ledger, nhận toàn văn ticket, trích ID số
từ tên file và che PII trước summarize. Run B chỉ nhận list[int]; policy
cho phép mới mở private mapping store, tra related_tickets và kiểm lại
trước từng read_customer. Run egress kiểm riêng URL, không nhận hồ sơ.
Đích lab duy nhất http://127.0.0.1:10024/reconcile; restricted + egress bị
deny. Ledger JSONL ghi metadata, reason, args_hash, prev_hash/hash, không
lưu hồ sơ thô. Các run là phân tách logic/capability trong cùng tiến trình.

## 4. Cho phép/chặn gì, giới hạn gì?

CP5: 45 pass, 0 fail, 0 skip (`reports/cp5-tests.log:2`). Test split chứng
minh KH-000777 không bị đọc từ lời attacker, nhưng vẫn đọc khách hợp lệ.
Injection test đủ 4 lure × 2 principal; dpo vẫn đọc KH-000999 hợp lệ, policy
chặn gửi. Baseline có 4 POST (`reports/attack-before.log:1`); replay sau
pytest với sink thật và cùng query cho attack-after.log 0 byte. Ledger
verify True, `reports/ledger.jsonl:72` http_post deny thay mặt dpo với reason.
Chứng cứ: reports/cp5-evidence.json. Bản sao sửa dòng giữa verify False;
ledger gốc giữ nguyên (reports/ledger-verification.json).

Mock chỉ nhận marker, regex không bao phủ mọi PII và có thể nhầm số không
nhãn. Chưa có authentication, process isolation hay khóa nhiều writer.
Hash chain không tự phát hiện cắt đuôi/viết lại toàn bộ nếu thiếu mốc bên
ngoài. Localhost sink và dữ liệu synthetic giới hạn phạm vi thử nghiệm;
không chứng minh an toàn mọi workload/model hoặc tuân thủ pháp luật.
Đây là bản mô tả học tập, không phải đánh giá tác động pháp lý chính thức.
