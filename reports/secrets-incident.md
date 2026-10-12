# CP4 — Token giả trong lịch sử Git

Scanner: Gitleaks **8.30.1**, xác nhận bằng `gitleaks version`.
Token của bài là synthetic, cố ý vô hiệu; không sử dụng token hoặc secret thật.

`gitleaks git --config .gitleaks.toml --redact .` trả exit **1** như mong đợi:
6 commit được quét, đúng 1 finding. Rule **lab24-synthetic-token**,
file `lab-fake-secret.txt`, dòng 1, commit
**1bdd849922156c868a5ee9293d68f5b72e242d2c** (viết ngắn **1bdd849**).
Bằng chứng: [gitleaks-history.log](gitleaks-history.log) và
[gitleaks-history.json](gitleaks-history.json). Match/Secret đều REDACTED.

`gitleaks dir --config .gitleaks.toml --redact .` lần đầu trả exit **0**,
không finding: [gitleaks-current-first.log](gitleaks-current-first.log).
Không phát hiện false positive trong `.venv/`, nên không chỉnh allowlist
và không tắt rule token giả. Lịch sử vẫn có finding dù file đã bị xóa ở HEAD.

Nếu đây là secret thật: thu hồi/rotate tại dịch vụ cấp token ngay, rà audit
log để kiểm sử dụng trái phép và phạm vi ảnh hưởng, cập nhật ứng dụng sang
credential mới, rồi xử lý bản sao trong lịch sử Git, fork, clone, CI/cache
và artifact theo phạm vi kiểm soát. Không in secret vào báo cáo.
Xóa file ở commit mới không thu hồi credential và không xóa bản sao cũ.

Hook `.pre-commit-config.yaml` dùng repo chính thức
`https://github.com/gitleaks/gitleaks`, pin `rev: v8.30.1`,
`id: gitleaks-system`, `pass_filenames: false`. `python -m pre_commit install`
đã cài `.git/hooks/pre-commit`; `python -m pre_commit run --all-files` Passed
([pre-commit.log](pre-commit.log)). Hook chạy trên file được Git theo dõi;
không thay thế quét lịch sử hoặc quét thư mục có file chưa được theo dõi.

Pin phiên bản và hash giúp kiểm artifact dependency khi cài; hook giúp
phát hiện trước commit. Cả hai không vô hiệu hóa token đã lộ và không bảo
đảm package không chứa mã độc. Thu hồi/rotate vẫn cần thiết với secret thật.

`python -m piptools compile --generate-hashes -o requirements.lock requirements.txt`
đã thành công, tạo 11 package pin phiên bản và SHA-256, gồm requests 2.34.2
và pytest 9.1.1. Lượt đầu bị sandbox chặn DNS PyPI; lượt ngoài sandbox
thành công: [lock-compile.log](lock-compile.log).
`python -m pip install --require-hashes -r requirements.lock` exit **0**:
[lock-install.log](lock-install.log). Các phiên bản đã có trong `.venv`
nên pip báo already satisfied; đây chưa phải bằng chứng cài sạch từ môi
trường trống hoặc tái kiểm hash của file đã cài.

CP4: **3 passed** ([supply-chain-test.log](supply-chain-test.log)); toàn bộ
suite: **45 passed** ([full-test.log](full-test.log)). Quét thư mục sau
khi sinh lock và báo cáo vẫn exit **0**, no leaks found:
[gitleaks-current-final.log](gitleaks-current-final.log).
