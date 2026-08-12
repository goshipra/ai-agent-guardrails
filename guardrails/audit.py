"""Structured audit logging.

Every `PolicyEngine.evaluate()` call made through `AuditLogger.log()` writes
one line-delimited JSON record. This is the observability hook: the file is
plain JSONL by design so it can be tailed straight into Loki, ELK/Elasticsearch,
Langfuse, or any other log pipeline without this project taking on a
dependency on any of them.

Record shape::

    {
      "timestamp": "2026-08-11T14:03:22.123456+00:00",
      "command": "terraform destroy",
      "action": "BLOCK",
      "reason": "...",
      "matched_rule": "terraform_destroy_unreviewed",
      "context": {...}
    }
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from guardrails.policy import Decision

DEFAULT_AUDIT_LOG_PATH = os.path.expanduser("~/.guardrails/audit.jsonl")


class AuditLogger:
    def __init__(self, log_path: str | None = None):
        self.log_path = log_path or DEFAULT_AUDIT_LOG_PATH

    def log(self, command: str, decision: Decision, context: dict[str, Any] | None = None) -> dict:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "command": command,
            "action": decision.action,
            "reason": decision.reason,
            "matched_rule": decision.matched_rule,
            "context": context or {},
        }
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        with open(self.log_path, "a") as f:
            f.write(json.dumps(record) + "\n")
        return record
