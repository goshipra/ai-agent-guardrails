#!/usr/bin/env python3
"""Claude Code PreToolUse hook: gate Bash tool calls through the guardrails
PolicyEngine before Claude Code executes them.

=====================  How this integrates  =====================

ASSUMPTIONS (please verify against Claude Code's current published hook
schema before relying on this in production — hook I/O has changed across
Claude Code versions and this file is a best-effort reference, not a
guarantee):

  * Claude Code invokes a PreToolUse hook as a subprocess and writes a JSON
    object to its stdin describing the pending tool call. This script
    assumes that object contains (at minimum):
        {
          "hook_event_name": "PreToolUse",
          "tool_name": "Bash",
          "tool_input": {"command": "<the shell command>"},
          "session_id": "...",
          "cwd": "..."
        }
    Field names/nesting may differ by Claude Code version — adjust
    `_extract_command()` below if your version's schema differs.

  * A hook can influence Claude Code's permission decision in (at least)
    two ways, and this script does BOTH for robustness:
      1. Exit code: exit 0 = allow the tool call to proceed (stdout may be
         shown to the user); a non-zero, hook-specific "blocking" exit code
         (this script uses 2) signals Claude Code to treat stderr as the
         reason and stop the tool call.
      2. Structured JSON on stdout: this script also prints an object with
         both an older-style `"decision": "block"` field and a newer-style
         `"hookSpecificOutput": {"permissionDecision": "deny", ...}` field,
         since the exact shape of the "block a PreToolUse call" contract
         has evolved across Claude Code releases. Emitting both increases
         the odds this works against whatever version you're running, but
         you should confirm against your installed Claude Code's docs
         (`claude --help`, the Claude Code hooks reference) and prune
         whichever field your version doesn't recognize.

  * WARN-level decisions are treated as non-blocking: the command is
    allowed to proceed, but the WARN reason is printed to stderr so it
    shows up in Claude Code's transcript for a human to notice.

  * Every invocation is still logged to the guardrails audit log
    (~/.guardrails/audit.jsonl by default) regardless of how — or whether —
    Claude Code ends up honoring the block signal, so you have an
    independent record even if the hook contract assumption above is
    wrong for your version.

===================================================================

Wire-up: see the sample CLAUDE.md snippet in this directory, or Claude
Code's own hooks configuration (typically a `hooks` block in
`.claude/settings.json` mapping `PreToolUse` -> a matcher for `Bash` ->
this script).
"""

from __future__ import annotations

import json
import sys

# Make the guardrails package importable when this script is invoked
# directly (e.g. as a hook) rather than via `pip install -e .`.
import os

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from guardrails.audit import AuditLogger  # noqa: E402
from guardrails.policy import PolicyEngine  # noqa: E402

BLOCKING_EXIT_CODE = 2


def _extract_command(payload: dict) -> str | None:
    """Best-effort extraction of the shell command from a PreToolUse payload.

    Assumes the Bash tool's input is under tool_input["command"]; falls back
    to a couple of alternate shapes seen across tool schemas in case
    tool_name isn't exactly "Bash" or the nesting differs.
    """
    tool_input = payload.get("tool_input") or payload.get("input") or {}
    if isinstance(tool_input, dict):
        for key in ("command", "cmd", "script"):
            if key in tool_input and isinstance(tool_input[key], str):
                return tool_input[key]
    # Some hook payload shapes put the command directly on the payload.
    for key in ("command", "cmd"):
        if key in payload and isinstance(payload[key], str):
            return payload[key]
    return None


def main() -> int:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        # Can't parse the hook payload at all — fail open rather than
        # crash Claude Code, but say so loudly on stderr.
        print("guardrails pretooluse_hook: could not parse stdin as JSON; allowing.", file=sys.stderr)
        return 0

    tool_name = payload.get("tool_name") or payload.get("tool") or ""
    if tool_name not in ("Bash", "bash", "shell", "Shell"):
        # Not a shell-command tool call; nothing for this hook to police.
        return 0

    command = _extract_command(payload)
    if not command:
        print("guardrails pretooluse_hook: no command found in payload; allowing.", file=sys.stderr)
        return 0

    engine = PolicyEngine()
    context = {
        "session_id": payload.get("session_id"),
        "cwd": payload.get("cwd"),
    }
    decision = engine.evaluate(command, context)

    audit = AuditLogger()
    audit.log(command, decision, context={**context, "source": "claude_code_pretooluse_hook"})

    if decision.action == "BLOCK":
        result = {
            "decision": "block",
            "reason": decision.reason,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": decision.reason,
            },
        }
        print(json.dumps(result))
        print(f"[guardrails] BLOCKED ({decision.matched_rule}): {decision.reason}", file=sys.stderr)
        return BLOCKING_EXIT_CODE

    if decision.action == "WARN":
        print(f"[guardrails] WARNING ({decision.matched_rule}): {decision.reason}", file=sys.stderr)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
