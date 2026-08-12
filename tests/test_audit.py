import json

from guardrails.audit import AuditLogger
from guardrails.policy import Decision


def test_audit_log_writes_jsonl_record(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(log_path))
    decision = Decision(action="BLOCK", reason="test reason", matched_rule="some_rule")

    logger.log("rm -rf /", decision, context={"actor": "test-agent"})

    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["command"] == "rm -rf /"
    assert record["action"] == "BLOCK"
    assert record["reason"] == "test reason"
    assert record["matched_rule"] == "some_rule"
    assert record["context"] == {"actor": "test-agent"}
    assert "timestamp" in record


def test_audit_log_appends_multiple_records(tmp_path):
    log_path = tmp_path / "nested" / "audit.jsonl"
    logger = AuditLogger(log_path=str(log_path))
    decision = Decision(action="ALLOW", reason="fine", matched_rule=None)

    logger.log("ls -la", decision)
    logger.log("git status", decision)

    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 2
