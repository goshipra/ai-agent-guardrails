"""The policy engine: the deterministic core of ai-agent-guardrails.

`PolicyEngine` loads a set of declarative rules from YAML files and, given a
proposed shell command (and optional context), returns a `Decision`. See the
README's "Design decisions" section for why this is rule-based rather than
an LLM classifier.
"""

from __future__ import annotations

import glob
import os
import re
from dataclasses import dataclass, field
from typing import Any, Literal

import yaml

from guardrails.checks import CHECKS

Action = Literal["ALLOW", "BLOCK", "WARN"]

# Worse (more restrictive) wins when multiple rules match the same command.
_ACTION_SEVERITY = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}

DEFAULT_POLICY_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "policies")


@dataclass
class Decision:
    action: Action
    reason: str
    matched_rule: str | None = None


@dataclass
class _Rule:
    id: str
    action: Action
    reason: str
    patterns: list[re.Pattern] = field(default_factory=list)
    check: str | None = None

    def matches(self, command: str, context: dict) -> bool:
        if self.check is not None:
            fn = CHECKS.get(self.check)
            if fn is None:
                raise ValueError(f"Rule {self.id!r} references unknown check {self.check!r}")
            return bool(fn(command, context))
        return any(p.search(command) for p in self.patterns)


class PolicyEngine:
    """Loads rules from one or more YAML files and evaluates commands against them.

    Usage:
        engine = PolicyEngine()  # loads policies/*.yaml from the package root
        decision = engine.evaluate("terraform destroy")
    """

    def __init__(self, policy_dir: str | None = None, policy_files: list[str] | None = None):
        self.rules: list[_Rule] = []
        if policy_files:
            files = list(policy_files)
        else:
            policy_dir = policy_dir or DEFAULT_POLICY_DIR
            files = sorted(glob.glob(os.path.join(policy_dir, "*.yaml"))) + sorted(
                glob.glob(os.path.join(policy_dir, "*.yml"))
            )
        for path in files:
            self._load_file(path)

    def _load_file(self, path: str) -> None:
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        for raw in data.get("rules", []):
            patterns = []
            if "pattern" in raw:
                patterns.append(re.compile(raw["pattern"]))
            for p in raw.get("patterns", []):
                patterns.append(re.compile(p))
            self.rules.append(
                _Rule(
                    id=raw["id"],
                    action=raw["action"],
                    reason=" ".join(raw["reason"].split()),  # collapse YAML folding whitespace
                    patterns=patterns,
                    check=raw.get("check"),
                )
            )

    def evaluate(self, command: str, context: dict[str, Any] | None = None) -> Decision:
        """Evaluate `command` against all loaded rules.

        `context` is an optional dict carrying session/environment info that
        some rules need, e.g.:
            - "history": list[str] of prior commands this session (used by
              the terraform-destroy-without-reviewed-plan rule)
            - "branch" / "current_branch": str (used by force-push rules)
            - "file_path": str (used by the destructive-SQL-outside-migration rule)
            - "plan_reviewed": bool (explicit override for terraform)
            - "policy_json": str (extra IAM policy document text to scan)

        Returns the single worst-severity matching Decision. If nothing
        matches, returns ALLOW.
        """
        context = context or {}
        best: Decision | None = None
        for rule in self.rules:
            if not rule.matches(command, context):
                continue
            if best is None or _ACTION_SEVERITY[rule.action] > _ACTION_SEVERITY[best.action]:
                best = Decision(action=rule.action, reason=rule.reason, matched_rule=rule.id)
        if best is None:
            return Decision(action="ALLOW", reason="No policy violation detected.", matched_rule=None)
        return best
