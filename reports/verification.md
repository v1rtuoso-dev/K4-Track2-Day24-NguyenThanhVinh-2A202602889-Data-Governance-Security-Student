# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
- `python -m pytest tests/ -q`:
- `pre-commit run --all-files`:
- Ledger verify:
- Các lỗi còn lại:

## CP3a — Phát hiện và che PII (12/10/2026)

Kết quả thật, lưu ở [pii-test.log](pii-test.log):

```text
[pii] gold=118 pred=118 tp=118
[pii] precision=1.000 recall=1.000
4 passed in 0.05s
```

Precision = 118/118 = 100%; recall = 118/118 = 100%, vượt ngưỡng
recall >95% của mức cao nhất trong RUBRIC.md trên bộ mẫu này.
Test đo TP theo cùng loại và vùng giao nhau, không đòi offset trùng tuyệt
đối với gold. Test bổ sung kiểm `text[start:end]` bằng đúng giá trị mong
đợi, end exclusive, nhãn STK không nằm trong vùng che, ưu tiên tài khoản
có nhãn khi trùng CCCD/điện thoại, redaction nhiều vùng và không khớp mảnh
số trong chuỗi dài hơn. Không thay đổi bộ gold hoặc cách tính điểm.

`agent/pii.py` dùng regex trên chuỗi gốc để giữ offset ký tự Unicode.
Ưu tiên EMAIL, tài khoản có nhãn, CCCD, rồi điện thoại; bỏ vùng giao với
vùng đã nhận diện. `redact` thay từ cuối về đầu bằng `[REDACTED_<TYPE>]`.

Giới hạn: regex nhận dạng hình thức, không xác thực CCCD, số điện thoại
hay tài khoản có thật. Số 12 chữ số không có nhãn vẫn có thể là mã khác;
tài khoản thiếu nhãn STK/số tài khoản có thể bị bỏ sót hoặc nhầm thành
CCCD/điện thoại. Điện thoại hỗ trợ đầu 0, tổng 10–11 số và dấu cách/gạch
ngang, chưa hỗ trợ +84 hoặc dấu ngoặc. CCCD/tài khoản phải là số ASCII
liền nhau; email chỉ hỗ trợ dạng ASCII thông dụng, không bao quát toàn
bộ chuẩn email. Chưa nhận PERSON, địa chỉ hoặc dữ liệu bị cố ý làm rối
bằng zero-width. Kết quả 100% trên bộ synthetic không chứng minh độ phủ
100% trên dữ liệu thực; tích hợp gate vào boundary của runner thuộc CP3
tiếp theo.

## CP3b / CP3c — Policy và OBO (12/10/2026)

`agent/policy.py` kiểm classification, chặn restricted + egress trước
mọi quyền DPO, rồi kiểm registry principal, purpose, requested tool,
agent scope, parent scope khi delegation_depth > 0 và expires_at UTC
chưa hết hạn. Mọi allow/deny có reason. Thời hạn sai định dạng, thiếu múi
giờ hoặc không phải UTC đều bị deny.

`agent/runner.py` gọi policy và ledger trước search_docs/read_customer.
support_l1 bị deny trước cả lúc mở customers.json để tra mapping; dpo
vẫn đọc được hồ sơ có related_tickets hợp lệ. Run A chỉ chuyển ticket ID
số lấy từ tên file sang Run B; mã khách trong text không quyết định tool.
Ledger ghi on_behalf_of, agent_id, run_id riêng, expires_at và reason;
args_hash thay cho tham số thô. Run có TTL năm phút. Ledger scaffold đã
được hoàn thiện vì là phụ thuộc bắt buộc để chạy OBO, có hash chain và verify.

Lệnh yêu cầu tương ứng:

```powershell
python -m pytest tests/test_policy.py -v --basetemp=.pytest_tmp
python -m pytest tests/test_obo.py -v --basetemp=.pytest_tmp
```

Kết quả: **31 passed in 5.51s**, không skip. Policy: 4 test; OBO: 15 test
(gồm các case bổ sung kiểm trường sai và private store không bị mở bởi
support_l1); split: 1; ledger: 3; injection: 8. Log đầy đủ:
[policy-obo-test.log](policy-obo-test.log). Lượt đầu trong sandbox có lỗi
fixture kết nối sink; chạy ngoài sandbox với cùng sink localhost thì pass.
Các fixture reset sink.log; attack-before.log vẫn là bằng chứng baseline.

Giới hạn: principal registry và --as chỉ mô phỏng quyền, không xác thực
người dùng. Ledger phục vụ tuần tự trong lab, chưa có khóa cho nhiều writer;
hash chain không phát hiện cắt đuôi/viết lại toàn bộ nếu không có mốc tin
cậy bên ngoài. Kết quả này chưa thay cho kiểm toàn bộ suite ở checkpoint
Prove hoặc chứng cứ attack-after.log/ledger chạy tay.

## CP3d / CP3e — Split và ledger thật (12/10/2026)

Chạy bằng Python 3.12.12 trong `.venv`:

```powershell
python -m pytest tests/test_split.py tests/test_injection.py tests/test_ledger.py -v --basetemp=.pytest_tmp
python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"
python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"
```

Thực gọi `.venv/Scripts/python.exe` để chọn đúng interpreter; stdout UTF-8.
Fixture sink bị sandbox chặn kết nối ở lượt đầu; chạy lại ngoài sandbox
thành công: **12 passed in 4.78s**, không SKIP. Split: 1; injection: 8
(4 lure × 2 principal); ledger: 3. Log: [split-ledger-test.log](split-ledger-test.log).
Split test chứng minh KH-000777 không bị đọc từ text attacker nhưng vẫn
đọc khách hợp lệ. Các lure vẫn được đọc và nhận diện trong injection test.

Run A chỉ trích số từ tên ticket và che PII trước summarize. Run B chỉ
nhận list[int], tra related_tickets sau khi được policy cho phép mở private
store và kiểm lần nữa trước từng read_customer. Kiểm gửi nằm ở run-egress
riêng, chỉ hash tham số URL của lure; không truyền hồ sơ hay text sang đó.
Policy restricted + egress từ chối trước khi thực hiện network.

Lượt chạy tay trả “Đã tổng hợp 45 ticket”; output đầy đủ:
[dpo-run.log](dpo-run.log). Ledger thật: [ledger.jsonl](ledger.jsonl).
verify trả **True**. Dòng deny của lượt này có:

```json
{"tool":"http_post","classification":"restricted","decision":"deny","reason":"Restricted data cannot enter an egress-enabled run","on_behalf_of":"dpo","agent_id":"lab24-agent/run-egress","run_id":"d7ea490b8e65401691540fa74c6328fd/run-egress"}
```

Đây là trích các field của dòng thật, không thay thế nguyên dòng ledger.
Mỗi entry còn có args_hash, ts, expires_at, prev_hash và hash. Ledger không
ghi hồ sơ hoặc tham số PII thô. Lượt kiểm gửi không gọi tools.http_post.

Tự kiểm tamper: sao chép ledger vào thư mục tạm, thêm ` TAMPERED` vào
reason của dòng giữa, giữ nguyên hash. verify bản sao trả **False**,
verify bản gốc vẫn **True**; kết quả và số dòng:
[ledger-verification.json](ledger-verification.json). Không sửa ledger thật.
Số dòng tăng khi chạy lại agent. Hash chain không tự phát hiện cắt đuôi
nếu thiếu mốc tin cậy bên ngoài.
