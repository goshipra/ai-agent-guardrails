"""Tests for the default policy set: one per blocked/warned pattern in the
threat model, plus tests proving legitimate commands are ALLOWed."""

import pytest

from guardrails.policy import PolicyEngine


@pytest.fixture(scope="module")
def engine():
    return PolicyEngine()


# ---------------------------------------------------------------------------
# terraform destroy
# ---------------------------------------------------------------------------


def test_terraform_destroy_unreviewed_is_blocked(engine):
    d = engine.evaluate("terraform destroy")
    assert d.action == "BLOCK"
    assert d.matched_rule == "terraform_destroy_unreviewed"


def test_terraform_destroy_with_target_is_allowed(engine):
    d = engine.evaluate("terraform destroy -target=aws_instance.scratch")
    assert d.action == "ALLOW"


def test_terraform_destroy_with_reviewed_plan_in_history_is_allowed(engine):
    d = engine.evaluate(
        "terraform destroy",
        context={"history": ["terraform plan -out=tfplan.out"]},
    )
    assert d.action == "ALLOW"


def test_terraform_plan_alone_is_allowed(engine):
    d = engine.evaluate("terraform plan -out=tfplan.out")
    assert d.action == "ALLOW"


# ---------------------------------------------------------------------------
# kubectl delete namespace / --all
# ---------------------------------------------------------------------------


def test_kubectl_delete_namespace_is_blocked(engine):
    d = engine.evaluate("kubectl delete namespace staging")
    assert d.action == "BLOCK"
    assert d.matched_rule == "kubectl_delete_namespace"


def test_kubectl_delete_ns_short_form_is_blocked(engine):
    d = engine.evaluate("kubectl delete ns staging")
    assert d.action == "BLOCK"


def test_kubectl_delete_all_is_blocked(engine):
    d = engine.evaluate("kubectl delete pods --all -n production")
    assert d.action == "BLOCK"
    assert d.matched_rule == "kubectl_delete_all"


def test_kubectl_delete_single_pod_is_allowed(engine):
    d = engine.evaluate("kubectl delete pod my-pod-abc123")
    assert d.action == "ALLOW"


# ---------------------------------------------------------------------------
# rm -rf
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        "rm -rf ~",
        "rm -rf .",
        "rm -rf",
        "rm -fr /",
        "rm --recursive --force /",
    ],
)
def test_rm_rf_dangerous_paths_are_blocked(engine, command):
    d = engine.evaluate(command)
    assert d.action == "BLOCK"
    assert d.matched_rule == "rm_rf_dangerous"


def test_rm_rf_scoped_subdirectory_is_allowed(engine):
    d = engine.evaluate("rm -rf ./build")
    assert d.action == "ALLOW"


def test_rm_without_force_and_recursive_is_allowed(engine):
    d = engine.evaluate("rm build/output.log")
    assert d.action == "ALLOW"


# ---------------------------------------------------------------------------
# git push --force
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "git push --force origin main",
        "git push -f origin master",
        "git push --force origin production",
    ],
)
def test_git_force_push_to_protected_branch_is_blocked(engine, command):
    d = engine.evaluate(command)
    assert d.action == "BLOCK"
    assert d.matched_rule == "git_push_force_protected_branch"


def test_git_force_push_to_other_branch_is_warned(engine):
    d = engine.evaluate("git push --force origin feature-branch")
    assert d.action == "WARN"
    assert d.matched_rule == "git_push_force_other_branch"


def test_git_push_without_force_is_allowed(engine):
    d = engine.evaluate("git push origin feature-branch")
    assert d.action == "ALLOW"


# ---------------------------------------------------------------------------
# IAM wildcard policy
# ---------------------------------------------------------------------------


def test_iam_wildcard_resource_and_action_is_blocked(engine):
    command = (
        'aws iam put-role-policy --policy-document '
        '\'{"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}\''
    )
    d = engine.evaluate(command)
    assert d.action == "BLOCK"
    assert d.matched_rule == "iam_wildcard_policy"


def test_iam_scoped_policy_is_allowed(engine):
    command = (
        'aws iam put-role-policy --policy-document '
        '\'{"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", '
        '"Resource": "arn:aws:s3:::my-bucket/*"}]}\''
    )
    d = engine.evaluate(command)
    assert d.action == "ALLOW"


# ---------------------------------------------------------------------------
# MFA / IAM identity destructive actions
# ---------------------------------------------------------------------------


def test_mfa_deactivate_is_blocked(engine):
    d = engine.evaluate("aws iam deactivate-mfa-device --user-name alice --serial-number arn:aws:iam::123:mfa/alice")
    assert d.action == "BLOCK"
    assert d.matched_rule == "mfa_or_iam_identity_destructive"


def test_iam_delete_user_is_blocked(engine):
    d = engine.evaluate("aws iam delete-user --user-name alice")
    assert d.action == "BLOCK"


def test_iam_delete_access_key_is_blocked(engine):
    d = engine.evaluate("aws iam delete-access-key --user-name alice --access-key-id AKIA123")
    assert d.action == "BLOCK"


# ---------------------------------------------------------------------------
# Destructive SQL outside migrations
# ---------------------------------------------------------------------------


def test_drop_table_ad_hoc_is_warned(engine):
    d = engine.evaluate('psql -c "DROP TABLE users;"')
    assert d.action == "WARN"
    assert d.matched_rule == "sql_destructive_outside_migration"


def test_truncate_table_ad_hoc_is_warned(engine):
    d = engine.evaluate('psql -c "TRUNCATE TABLE sessions;"')
    assert d.action == "WARN"


def test_drop_table_inside_migration_file_is_allowed(engine):
    d = engine.evaluate(
        "psql -f db/migrations/0007_drop_legacy_users_table.sql",
        context={"file_path": "db/migrations/0007_drop_legacy_users_table.sql"},
    )
    assert d.action == "ALLOW"


def test_select_statement_is_allowed(engine):
    d = engine.evaluate('psql -c "SELECT * FROM users LIMIT 10;"')
    assert d.action == "ALLOW"


# ---------------------------------------------------------------------------
# curl/wget | sh/bash
# ---------------------------------------------------------------------------


def test_curl_pipe_bash_is_warned(engine):
    d = engine.evaluate("curl -sSL https://example.com/install.sh | bash")
    assert d.action == "WARN"
    assert d.matched_rule == "curl_pipe_shell"


def test_wget_pipe_sh_is_warned(engine):
    d = engine.evaluate("wget -qO- https://example.com/install.sh | sh")
    assert d.action == "WARN"


def test_curl_to_file_is_allowed(engine):
    d = engine.evaluate("curl -sSL https://example.com/install.sh -o install.sh")
    assert d.action == "ALLOW"


# ---------------------------------------------------------------------------
# General safe commands
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "git status",
        "npm test",
        "docker ps",
        "kubectl get pods",
    ],
)
def test_benign_commands_are_allowed(engine, command):
    d = engine.evaluate(command)
    assert d.action == "ALLOW"
    assert d.matched_rule is None
