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

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-agent"
RUN_TTL = timedelta(minutes=5)
# Agent cha giữ trần quyền; mỗi run con chỉ nhận đúng một chân trifecta.
PARENT_SCOPES = ("search_docs", "read_customer", "http_post")
RUN_A_SCOPES = ("search_docs",)
RUN_B_SCOPES = ("read_customer",)
RUN_C_SCOPES = ("http_post",)
EGRESS_URL = f"http://{tools.ALLOWED_EGRESS_HOST}:{tools.ALLOWED_EGRESS_PORT}/reconcile"

_TICKET_FILE_RE = re.compile(r"^ticket-(\d+)\.md$")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _args_hash(args: dict) -> str:
    payload = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class _Gate:
    """PEP dùng chung cho mọi run con: check() -> ledger.append() -> tool."""

    def __init__(self, principal_id: str, ledger_path: Path):
        self.principal_id = principal_id
        self.ledger_path = ledger_path
        self.run_id = uuid.uuid4().hex
        self.expires_at = (datetime.now(timezone.utc) + RUN_TTL).isoformat()

    def call(self, run: str, scopes: tuple[str, ...], tool: str, args: dict,
             classification: str, purpose: str, egress: bool, fn):
        agent_id = f"{AGENT_ID}/run-{run}"
        context = PolicyContext(
            data_classification=classification,
            request_purpose=purpose,
            agent_owner=agent_id,
            delegation_depth=1,
            egress_enabled=egress,
            principal_id=self.principal_id,
            requested_tool=tool,
            agent_scopes=scopes,
            parent_scopes=PARENT_SCOPES,
            expires_at=self.expires_at,
        )
        allow, reason = check(context)
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": f"{self.run_id}-{run}",
            "on_behalf_of": self.principal_id,
            "expires_at": self.expires_at,
            "tool": tool,
            "args_hash": _args_hash(args),
            "classification": classification,
            "purpose": purpose,
            "egress": egress,
            "decision": "allow" if allow else "deny",
            "reason": reason,
        }, self.ledger_path)
        return (True, fn()) if allow else (False, None)


def _run_a(gate: _Gate, message: str, llm) -> tuple[list[dict], list[int], bool]:
    """Chân 1: đọc corpus. Chỉ trả ra ticket_id số lấy từ TÊN FILE."""
    allowed, docs = gate.call("a", RUN_A_SCOPES, "search_docs", {"query": message},
                              "internal", "summarize-tickets", False,
                              lambda: tools.search_docs(message))
    if not allowed:
        return [], [], False
    ticket_ids = sorted({int(m.group(1)) for d in docs if (m := _TICKET_FILE_RE.match(d["id"]))})
    # Chỉ thị injection chỉ được ghi nhận dưới dạng cờ bool; customer_id và
    # URL trong free text không bao giờ rời Run A.
    injected = llm.find_injection("\n\n".join(d["text"] for d in docs)) is not None
    redacted_docs = [{"id": d["id"], "text": pii.redact(d["text"])} for d in docs]
    return redacted_docs, ticket_ids, injected


def _run_b(gate: _Gate, ticket_ids: list[int]) -> list[dict]:
    """Chân 2: đọc private store. customer_id suy từ related_tickets."""
    # Policy phải cho phép mở private store trước khi tra customers.json.
    allowed, customers = gate.call("b", RUN_B_SCOPES, "read_customer", {"ticket_ids": ticket_ids},
                                   "restricted", "support-reply", False,
                                   lambda: json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8")))
    if not allowed:
        return []
    wanted = set(ticket_ids)
    customer_ids = [c["customer_id"] for c in customers if wanted & set(c.get("related_tickets", []))]
    records = []
    for customer_id in customer_ids:
        allowed, record = gate.call("b", RUN_B_SCOPES, "read_customer", {"customer_id": customer_id},
                                    "restricted", "support-reply", False,
                                    lambda cid=customer_id: tools.read_customer(cid))
        if allowed:
            records.append(record)
    return records


def _run_c(gate: _Gate) -> None:
    """Chân 3: egress mà chỉ thị trong ticket đòi. Lượt kiểm chỉ mang URL."""
    gate.call("c", RUN_C_SCOPES, "http_post", {"url": EGRESS_URL},
              "restricted", "support-reply", True,
              lambda: tools.http_post(EGRESS_URL, {}))


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    gate = _Gate(principal_id, ledger_path)

    docs, ticket_ids, injected = _run_a(gate, message, llm)
    _run_b(gate, ticket_ids)
    if injected:
        _run_c(gate)

    return llm.summarize(docs)
