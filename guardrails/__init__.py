"""ai-agent-guardrails: a tool-agnostic policy layer for autonomous AI agents.

The core primitive is `PolicyEngine.evaluate(command, context)`, which returns a
`Decision` (ALLOW / WARN / BLOCK). It is designed to be called by any agent
integration (Claude Code, Cursor, a CI bot, a custom LangGraph tool wrapper,
etc.) before a shell command is actually executed.
"""

from guardrails.policy import Decision, PolicyEngine

__all__ = ["Decision", "PolicyEngine"]
__version__ = "0.1.0"
