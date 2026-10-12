"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path

PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def check(context: PolicyContext) -> tuple[bool, str]:
    if context.data_classification not in {"public", "internal", "restricted"}:
        return False, "Unknown data classification"
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "Restricted data cannot enter an egress-enabled run"
    if not context.agent_owner or context.delegation_depth < 0:
        return False, "Invalid agent identity or delegation depth"
    try:
        principals = json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False, "Trusted principal registry unavailable"
    principal = principals.get(context.principal_id)
    if not isinstance(principal, dict):
        return False, "Unknown principal"
    if context.request_purpose not in principal.get("purposes", []):
        return False, "Purpose not authorized for principal"
    if not context.requested_tool or context.requested_tool not in principal.get("allowed_tools", []):
        return False, "Tool not authorized for principal"
    if context.requested_tool not in context.agent_scopes:
        return False, "Tool missing from agent scope"
    if context.delegation_depth > 0 and context.requested_tool not in context.parent_scopes:
        return False, "Tool missing from parent scope"
    try:
        expires = datetime.fromisoformat(context.expires_at.replace("Z", "+00:00"))
        if expires.tzinfo is None or expires.utcoffset().total_seconds() != 0:
            return False, "Expiry must be timezone-aware UTC"
    except (ValueError, TypeError, AttributeError):
        return False, "Invalid expiry timestamp"
    if expires <= datetime.now(timezone.utc):
        return False, "Delegation expired"
    return True, "Principal, purpose, effective tool scope and UTC expiry authorized"
