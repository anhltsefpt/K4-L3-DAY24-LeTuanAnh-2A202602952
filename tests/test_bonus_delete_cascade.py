"""Bonus — delete cascade giữ ledger verify. Chạy trên bản sao, không sửa dữ liệu thật."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agent import ledger
from agent.erasure import delete_customer

ROOT = Path(__file__).resolve().parent.parent
VICTIM = "KH-000001"


@pytest.fixture
def workspace(tmp_path):
    shutil.copy(ROOT / "data" / "customers.json", tmp_path / "customers.json")
    shutil.copytree(ROOT / "corpus", tmp_path / "corpus")
    shutil.copy(ROOT / "reports" / "ledger.jsonl", tmp_path / "ledger.jsonl")
    return tmp_path


def _victim() -> dict:
    customers = json.loads((ROOT / "data" / "customers.json").read_text(encoding="utf-8"))
    return next(c for c in customers if c["customer_id"] == VICTIM)


def _run(ws: Path, principal_id: str) -> dict:
    return delete_customer(VICTIM, principal_id=principal_id,
                           customers_file=ws / "customers.json", corpus_dir=ws / "corpus",
                           ledger_path=ws / "ledger.jsonl")


def test_dpo_erasure_cascades_and_ledger_still_verifies(workspace):
    victim = _victim()
    assert ledger.verify(workspace / "ledger.jsonl")
    lines_before = len((workspace / "ledger.jsonl").read_text(encoding="utf-8").splitlines())

    result = _run(workspace, "dpo")

    assert result["allow"] and result["scrubbed_tickets"] == ["ticket-014.md", "ticket-015.md"]
    customers = (workspace / "customers.json").read_text(encoding="utf-8")
    assert VICTIM not in customers
    corpus = "".join(p.read_text(encoding="utf-8") for p in (workspace / "corpus").glob("*.md"))
    ledger_text = (workspace / "ledger.jsonl").read_text(encoding="utf-8")
    for field in ("name", "cccd", "phone", "bank_account", "email"):
        assert victim[field] not in customers + corpus + ledger_text, f"{field} còn sót sau khi xoá"

    lines = ledger_text.splitlines()
    assert len(lines) == lines_before + 1
    assert json.loads(lines[-1])["tool"] == "delete_customer"
    assert ledger.verify(workspace / "ledger.jsonl") is True


def test_support_l1_cannot_erase(workspace):
    before = (workspace / "customers.json").read_text(encoding="utf-8")
    result = _run(workspace, "support_l1")
    assert not result["allow"] and result["reason"]
    assert (workspace / "customers.json").read_text(encoding="utf-8") == before
    last = json.loads((workspace / "ledger.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert last["decision"] == "deny" and last["reason"]
    assert ledger.verify(workspace / "ledger.jsonl") is True
