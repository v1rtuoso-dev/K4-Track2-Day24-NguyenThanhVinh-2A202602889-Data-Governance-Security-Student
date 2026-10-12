"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

from pathlib import Path
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from uuid import uuid4

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    path = Path(log_dir) / "ledger.jsonl" if log_dir is not None else DEFAULT_LEDGER_PATH
    session = uuid4().hex
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    parent_scopes = ("search_docs", "read_customer")

    def gate(tool, args, classification, purpose, stage, scopes, depth=0, egress=False):
        context = policy.PolicyContext(
            data_classification=classification, request_purpose=purpose,
            agent_owner=f"lab24-agent/{stage}", delegation_depth=depth,
            egress_enabled=egress, principal_id=principal_id,
            requested_tool=tool, agent_scopes=scopes,
            parent_scopes=parent_scopes if depth else (), expires_at=expires_at)
        allowed, reason = policy.check(context)
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": context.agent_owner, "run_id": f"{session}/{stage}",
            "tool": tool, "args_hash": hashlib.sha256(
                json.dumps(args, sort_keys=True).encode("utf-8")).hexdigest(),
            "classification": classification, "decision": "allow" if allowed else "deny",
            "reason": reason, "on_behalf_of": principal_id, "expires_at": expires_at,
        }, path)
        return allowed

    # Run A: untrusted text is confined to this stage; only filename IDs leave it.
    if not gate("search_docs", {"query": message}, "internal", "summarize-tickets",
                "run-a", ("search_docs",)):
        return "Không được phép tìm ticket."
    docs = tools.search_docs(message)
    ticket_ids = sorted({int(match.group(1)) for doc in docs
                         if (match := re.fullmatch(r"ticket-([0-9]+)(?:b)?\.md", doc["id"]))})
    injected = llm.find_injection("\n\n".join(doc["text"] for doc in docs))
    safe_docs = [{"id": doc["id"], "text": pii.redact(doc["text"])} for doc in docs]
    _read_related_customers(ticket_ids, gate)
    # Record the denied egress capability without executing an attacker instruction.
    if injected is not None:
        gate("http_post", {"url": injected.target_url}, "restricted",
             "support-reply", "run-egress", ("http_post",), depth=1, egress=True)
    return llm.summarize(safe_docs)


def _read_related_customers(ticket_ids: list[int], gate) -> None:
    """Run B accepts typed IDs only and never reads attacker-provided customer IDs."""
    if not ticket_ids:
        return
    # Authorize BEFORE opening even the private mapping store.
    if not gate("read_customer", {"ticket_ids": ticket_ids}, "restricted", "support-reply",
                "run-b", ("read_customer",), depth=1):
        return
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    selected = set(ticket_ids)
    for customer in customers:
        if selected.intersection(customer.get("related_tickets", [])):
            customer_id = customer["customer_id"]
            if gate("read_customer", {"customer_id": customer_id}, "restricted", "support-reply",
                    "run-b", ("read_customer",), depth=1):
                tools.read_customer(customer_id)
