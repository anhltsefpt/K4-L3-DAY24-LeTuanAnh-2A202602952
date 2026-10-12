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

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"
CLASSIFICATIONS = ("public", "internal", "restricted")


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


def _load_principals() -> dict:
    return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))


def _parse_utc(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    return parsed if parsed.tzinfo is not None else None


def check(context: PolicyContext) -> tuple[bool, str]:
    c = context
    if c.data_classification not in CLASSIFICATIONS:
        return False, f"deny: data_classification {c.data_classification!r} không thuộc {CLASSIFICATIONS}"

    # Rule tối thiểu, đặt trước mọi kiểm OBO: không principal nào vượt được.
    if c.data_classification == "restricted" and c.egress_enabled:
        return False, "deny: restricted data cùng egress_enabled=True (rule tối thiểu, áp cho mọi principal)"

    principal = _load_principals().get(c.principal_id)
    if principal is None:
        return False, f"deny: unknown principal {c.principal_id!r}"

    if c.request_purpose not in principal["purposes"]:
        return False, f"deny: purpose {c.request_purpose!r} không thuộc purposes của {c.principal_id}"

    expires = _parse_utc(c.expires_at)
    if expires is None:
        return False, f"deny: expires_at {c.expires_at!r} thiếu hoặc không phải ISO-8601 có timezone"
    if expires <= datetime.now(timezone.utc):
        return False, f"deny: run đã hết hạn lúc {c.expires_at}"

    if c.requested_tool not in principal["allowed_tools"]:
        return False, f"deny: principal {c.principal_id} không được dùng {c.requested_tool!r}"
    if c.requested_tool not in c.agent_scopes:
        return False, f"deny: {c.requested_tool!r} nằm ngoài agent_scopes của {c.agent_owner}"
    if c.delegation_depth > 0 and c.requested_tool not in c.parent_scopes:
        return False, f"deny: agent con (depth={c.delegation_depth}) xin {c.requested_tool!r} vượt parent_scopes"

    return True, (f"allow: {c.principal_id} dùng {c.requested_tool} cho {c.request_purpose}, "
                  f"{c.data_classification}, egress={c.egress_enabled}, trong scope, còn hạn")
