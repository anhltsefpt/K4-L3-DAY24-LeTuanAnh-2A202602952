"""Bonus — delete cascade: xoá một khách mà ledger vẫn verify được.

    python -m agent.erasure KH-000001 --as dpo        # thao tác trên dữ liệu thật của repo

Xoá hồ sơ trong customers.json, che PII của khách trong các ticket gắn với
họ (related_tickets), rồi ghi một dòng ledger. Ledger không cần sửa vì nó
chỉ chứa args_hash, không chứa PII thô — nên hash chain vẫn nguyên vẹn.

Chỉ principal có purpose "privacy-audit" trong data/principals.json mới được
xoá. Test chạy trên bản sao trong thư mục tạm, không đụng dữ liệu thật.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger
from agent.policy import PRINCIPALS_FILE
from agent.runner import DEFAULT_LEDGER_PATH
from agent.tools import CORPUS_DIR, CUSTOMERS_FILE

ERASURE_PURPOSE = "privacy-audit"
PII_FIELDS = {"name": "NAME", "cccd": "VN_CCCD", "phone": "VN_PHONE",
              "bank_account": "VN_BANK_ACCOUNT", "email": "EMAIL"}


def delete_customer(customer_id: str, principal_id: str = "dpo",
                    customers_file: Path = CUSTOMERS_FILE, corpus_dir: Path = CORPUS_DIR,
                    ledger_path: Path = DEFAULT_LEDGER_PATH,
                    principals_file: Path = PRINCIPALS_FILE) -> dict:
    principals = json.loads(Path(principals_file).read_text(encoding="utf-8"))
    principal = principals.get(principal_id)
    customers = json.loads(Path(customers_file).read_text(encoding="utf-8"))
    record = next((c for c in customers if c["customer_id"] == customer_id), None)

    if principal is None or ERASURE_PURPOSE not in principal["purposes"]:
        allow, reason = False, f"deny: {principal_id} không có purpose {ERASURE_PURPOSE}"
    elif record is None:
        allow, reason = False, f"deny: không có khách {customer_id}"
    else:
        allow, reason = True, f"allow: {principal_id} xoá {customer_id} cho {ERASURE_PURPOSE}"

    scrubbed: list[str] = []
    if allow:
        Path(customers_file).write_text(
            json.dumps([c for c in customers if c is not record], ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        for ticket_id in record.get("related_tickets", []):
            path = Path(corpus_dir) / f"ticket-{ticket_id:03d}.md"
            if not path.exists():
                continue
            text = original = path.read_text(encoding="utf-8")
            for field, label in PII_FIELDS.items():
                text = text.replace(str(record[field]), f"[REDACTED_{label}]")
            if text != original:
                path.write_text(text, encoding="utf-8")
                scrubbed.append(path.name)

    ledger.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": "lab24-agent/erasure",
        "run_id": hashlib.sha256(f"erasure-{customer_id}-{datetime.now().isoformat()}".encode()).hexdigest()[:32],
        "on_behalf_of": principal_id,
        "expires_at": datetime.now(timezone.utc).isoformat(),
        "tool": "delete_customer",
        "args_hash": hashlib.sha256(json.dumps({"customer_id": customer_id}).encode()).hexdigest(),
        "classification": "restricted",
        "purpose": ERASURE_PURPOSE,
        "egress": False,
        "decision": "allow" if allow else "deny",
        "reason": reason,
    }, Path(ledger_path))
    return {"allow": allow, "reason": reason, "scrubbed_tickets": scrubbed}


def main() -> None:
    parser = argparse.ArgumentParser(description="Delete cascade cho một khách hàng")
    parser.add_argument("customer_id")
    parser.add_argument("--as", dest="principal_id", default="dpo")
    args = parser.parse_args()
    print(delete_customer(args.customer_id, principal_id=args.principal_id))


if __name__ == "__main__":
    main()
