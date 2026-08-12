"""`guard` — the standalone CLI entrypoint.

    guard check "terraform destroy"          # evaluate only, exit 1 on BLOCK
    guard exec -- ls -la                      # evaluate, then run if not BLOCKed
    guard check "rm -rf /" --json             # machine-readable output

This proves the policy engine works independent of any AI agent product —
it's just a command-line safety gate that any script, hook, or human can
call.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys

from guardrails.audit import AuditLogger
from guardrails.policy import Decision, PolicyEngine

_COLOR = {
    "BLOCK": "\033[31m",  # red
    "WARN": "\033[33m",  # yellow
    "ALLOW": "\033[32m",  # green
}
_RESET = "\033[0m"


def _print_decision(command: str, decision: Decision, use_json: bool) -> None:
    if use_json:
        print(
            json.dumps(
                {
                    "command": command,
                    "action": decision.action,
                    "reason": decision.reason,
                    "matched_rule": decision.matched_rule,
                }
            )
        )
        return
    color = _COLOR.get(decision.action, "")
    print(f"{color}[{decision.action}]{_RESET} {command!r}")
    if decision.matched_rule:
        print(f"  rule:   {decision.matched_rule}")
    print(f"  reason: {decision.reason}")


def _build_parser() -> argparse.ArgumentParser:
    # NOTE: these global flags must be given *before* the subcommand, e.g.
    # `guard --json check "..."`, not `guard check --json "..."` — argparse
    # subparsers parse into a fresh namespace and merge it over the parent's,
    # so duplicating these flags on each subparser would let an unset
    # subparser-level default silently clobber a flag set at the top level.
    parser = argparse.ArgumentParser(
        prog="guard",
        description="ai-agent-guardrails: a policy layer for autonomous agent commands. "
        "Global flags go before the subcommand, e.g. `guard --json check \"...\"`.",
    )
    parser.add_argument("--policy-dir", default=None, help="Directory of policy YAML files (default: bundled policies/)")
    parser.add_argument("--audit-log", default=None, help="Path to the JSONL audit log (default: ~/.guardrails/audit.jsonl)")
    parser.add_argument("--no-audit", action="store_true", help="Skip writing an audit log record")
    parser.add_argument("--context", default=None, help="JSON object of extra context, e.g. '{\"branch\": \"main\"}'")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON instead of human-readable text")

    sub = parser.add_subparsers(dest="subcommand", required=True)

    check_p = sub.add_parser("check", help="Evaluate a command without running it")
    check_p.add_argument("command", help="The shell command to evaluate (quote it)")

    exec_p = sub.add_parser("exec", help="Evaluate a command, then run it if ALLOW/WARN")
    exec_p.add_argument("command_parts", nargs=argparse.REMAINDER, help="-- <command and its args>")

    return parser


def _parse_context(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"error: --context is not valid JSON: {e}", file=sys.stderr)
        sys.exit(2)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    engine = PolicyEngine(policy_dir=args.policy_dir)
    audit = None if args.no_audit else AuditLogger(log_path=args.audit_log)
    context = _parse_context(args.context)

    if args.subcommand == "check":
        command = args.command
        decision = engine.evaluate(command, context)
        if audit:
            audit.log(command, decision, context)
        _print_decision(command, decision, args.json)
        return 1 if decision.action == "BLOCK" else 0

    if args.subcommand == "exec":
        parts = args.command_parts
        if parts and parts[0] == "--":
            parts = parts[1:]
        if not parts:
            print("error: 'guard exec --' requires a command, e.g. `guard exec -- ls -la`", file=sys.stderr)
            return 2
        command = shlex.join(parts)
        decision = engine.evaluate(command, context)
        if audit:
            audit.log(command, decision, context)
        _print_decision(command, decision, args.json)

        if decision.action == "BLOCK":
            print("refusing to execute: command blocked by policy.", file=sys.stderr)
            return 1

        sys.stdout.flush()
        sys.stderr.flush()
        result = subprocess.run(parts)
        return result.returncode

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
