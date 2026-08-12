"""Context-aware rule checks.

Some policy decisions can't be expressed as a single regex against the raw
command string — they need a bit of parsing (e.g. "does 'rm -rf' actually
have both the recursive and force flags, and is the path a root-ish path?")
or session context (e.g. "was a terraform plan reviewed earlier?"). Each
function here takes `(command: str, context: dict) -> bool` and returns
True if the *dangerous* condition the rule is guarding against is met.

These are referenced by name from policies/*.yaml via the `check:` field.
"""

from __future__ import annotations

import os
import re
import shlex

_TERRAFORM_DESTROY_RE = re.compile(r"\bterraform\s+destroy\b", re.IGNORECASE)
_TERRAFORM_TARGET_RE = re.compile(r"(?:^|\s)-target(?:=|\s)", re.IGNORECASE)
_TERRAFORM_PLAN_REVIEWED_RE = re.compile(
    r"\bterraform\s+plan\b[^&|;\n]*-out=", re.IGNORECASE
)

_RM_RE = re.compile(r"\brm\b([^;&|\n]*)")
_HOME = os.path.expanduser("~")
_ROOT_PATH_LITERALS = {"~", ".", "/", "./", "../", "~/"}

_GIT_PUSH_RE = re.compile(r"\bgit\s+push\b(.*)", re.IGNORECASE)
_GIT_FORCE_FLAG_RE = re.compile(r"(--force(?:-with-lease)?\b|(?<![\w-])-f\b)")
_PROTECTED_BRANCHES = {"main", "master", "production", "prod"}

_IAM_RESOURCE_WILDCARD_RE = re.compile(r'"?Resource"?\s*:\s*(\[[^\]]*"\*"[^\]]*\]|"\*")', re.IGNORECASE)
_IAM_BROAD_ACTION_RE = re.compile(r'"(iam:\*|\*:\*)"', re.IGNORECASE)

_SQL_DESTRUCTIVE_RE = re.compile(
    r"\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE)\b", re.IGNORECASE
)
_MIGRATION_HINT_RE = re.compile(r"(migrat|rollback)", re.IGNORECASE)


def terraform_destroy_unreviewed(command: str, context: dict) -> bool:
    """True (dangerous) if `terraform destroy` has no -target and no
    evidence a plan was generated and reviewed first in this session."""
    if not _TERRAFORM_DESTROY_RE.search(command):
        return False
    if _TERRAFORM_TARGET_RE.search(command):
        return False  # blast radius explicitly scoped
    if context.get("plan_reviewed"):
        return False
    history = context.get("history") or []
    combined = command + "\n" + "\n".join(history)
    if _TERRAFORM_PLAN_REVIEWED_RE.search(combined):
        return False
    return True


def _flags_and_paths(rm_args: str) -> tuple[bool, bool, list[str]]:
    try:
        tokens = shlex.split(rm_args)
    except ValueError:
        tokens = rm_args.split()

    has_force = False
    has_recursive = False
    paths: list[str] = []
    for tok in tokens:
        if tok in ("--force",):
            has_force = True
        elif tok in ("--recursive",):
            has_recursive = True
        elif tok.startswith("--"):
            continue  # other long flags, ignored
        elif tok.startswith("-") and len(tok) > 1:
            if "f" in tok[1:]:
                has_force = True
            if "r" in tok[1:] or "R" in tok[1:]:
                has_recursive = True
        else:
            paths.append(tok)
    return has_force, has_recursive, paths


def _is_dangerous_path(path: str) -> bool:
    if path in _ROOT_PATH_LITERALS:
        return True
    expanded = os.path.expanduser(path)
    normalized = os.path.normpath(expanded)
    return normalized in ("/", ".", _HOME)


def rm_rf_dangerous(command: str, context: dict) -> bool:
    """True (dangerous) for any `rm -rf`-equivalent invocation that targets
    a filesystem root / home / cwd, or has no path argument at all."""
    for match in _RM_RE.finditer(command):
        has_force, has_recursive, paths = _flags_and_paths(match.group(1))
        if not (has_force and has_recursive):
            continue
        if not paths:
            return True  # rm -rf with no path scoping at all
        if any(_is_dangerous_path(p) for p in paths):
            return True
    return False


def _extract_force_push_branch(command: str, context: dict) -> tuple[bool, str | None]:
    push_match = _GIT_PUSH_RE.search(command)
    if not push_match:
        return False, None
    rest = push_match.group(1)
    is_force = bool(_GIT_FORCE_FLAG_RE.search(rest))
    if not is_force:
        return False, None

    tokens = [t for t in rest.split() if not t.startswith("-")]
    branch = None
    if len(tokens) >= 2:
        branch = tokens[-1]
    elif context.get("branch"):
        branch = context["branch"]
    elif context.get("current_branch"):
        branch = context["current_branch"]
    return True, branch


def git_push_force_protected_branch(command: str, context: dict) -> bool:
    is_force, branch = _extract_force_push_branch(command, context)
    if not is_force:
        return False
    return bool(branch) and branch.lower() in _PROTECTED_BRANCHES


def git_push_force_other_branch(command: str, context: dict) -> bool:
    is_force, branch = _extract_force_push_branch(command, context)
    if not is_force:
        return False
    if branch and branch.lower() in _PROTECTED_BRANCHES:
        return False  # handled (as BLOCK) by git_push_force_protected_branch
    return True  # non-protected or unknown branch: still warn


def iam_wildcard_policy(command: str, context: dict) -> bool:
    policy_text = command
    if context.get("policy_json"):
        policy_text += "\n" + str(context["policy_json"])
    return bool(
        _IAM_RESOURCE_WILDCARD_RE.search(policy_text)
        and _IAM_BROAD_ACTION_RE.search(policy_text)
    )


def sql_destructive_outside_migration(command: str, context: dict) -> bool:
    if not _SQL_DESTRUCTIVE_RE.search(command):
        return False
    file_path = context.get("file_path") or context.get("file") or ""
    combined = f"{file_path}\n{command}"
    return not bool(_MIGRATION_HINT_RE.search(combined))


CHECKS = {
    "terraform_destroy_unreviewed": terraform_destroy_unreviewed,
    "rm_rf_dangerous": rm_rf_dangerous,
    "git_push_force_protected_branch": git_push_force_protected_branch,
    "git_push_force_other_branch": git_push_force_other_branch,
    "iam_wildcard_policy": iam_wildcard_policy,
    "sql_destructive_outside_migration": sql_destructive_outside_migration,
}
