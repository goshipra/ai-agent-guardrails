import json

import pytest

from guardrails.cli import main


def _no_audit_args(*extra):
    return ["--no-audit", *extra]


def test_cli_check_allow_exits_zero(capsys):
    code = main(_no_audit_args("check", "ls -la"))
    assert code == 0
    out = capsys.readouterr().out
    assert "ALLOW" in out


def test_cli_check_block_exits_one(capsys):
    code = main(_no_audit_args("check", "rm -rf /"))
    assert code == 1
    out = capsys.readouterr().out
    assert "BLOCK" in out


def test_cli_check_json_output(capsys):
    code = main(_no_audit_args("--json", "check", "terraform destroy"))
    assert code == 1
    out = capsys.readouterr().out.strip()
    payload = json.loads(out)
    assert payload["action"] == "BLOCK"
    assert payload["matched_rule"] == "terraform_destroy_unreviewed"


def test_cli_exec_runs_allowed_command(capsys):
    code = main(_no_audit_args("exec", "--", "echo", "hello-guardrails"))
    assert code == 0
    out = capsys.readouterr().out
    assert "hello-guardrails" in out


def test_cli_exec_refuses_blocked_command(capsys):
    code = main(_no_audit_args("exec", "--", "rm", "-rf", "/"))
    assert code == 1
    captured = capsys.readouterr()
    assert "BLOCK" in captured.out
    assert "refusing to execute" in captured.err


def test_cli_exec_with_no_command_errors(capsys):
    code = main(_no_audit_args("exec", "--"))
    assert code == 2


def test_cli_writes_audit_log_by_default(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    code = main(["--audit-log", str(log_path), "check", "ls -la"])
    assert code == 0
    assert log_path.exists()
    record = json.loads(log_path.read_text().strip().splitlines()[0])
    assert record["action"] == "ALLOW"
