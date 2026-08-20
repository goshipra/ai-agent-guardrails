# NEXT.md

Working notes for picking this repo back up — current state, what's
deliberately unfinished, and what a next session should know before
touching it. See `README.md` for the project's own explanation of itself
and `.claude/skills/guardrails-dev/SKILL.md` for how to actually work in
the code; this file is the "where were we" layer, not a design doc.

## Session Update (2026-08-20)

**Learning & Interview Preparation Session**

✅ **Completed:**
- Environment setup: venv created, `pip install -e ".[test]"`, all 47 tests passing
- Full codebase walkthrough: policy engine, checks, CLI, audit logger, integration
- Comprehensive interview prep document created (covers threat model Q&A, design rationales, packaging incident, common pitfalls)
- Persistent memory saved: user role, project overview, setup procedures, setup checklist
- Interview prep artifact published: https://claude.ai/code/artifact/52309618-afa0-466e-8081-8501552aaff1
- **Security: Zero-tolerance policy implemented:**
  - `SECURITY.md` created with mandatory pre-commit checklist (secrets, PII, data leaks)
  - `README.md` updated with security section linking to `SECURITY.md`
  - Memory file `security_zero_tolerance_policy.md` saved for cross-session consistency
  - Policy: ZERO exceptions for any leaks, even "tiny" ones; pre-commit scanning mandatory

**Key Learning Outputs:**
- Deep understanding of PolicyEngine decision flow: rule matching → worst-severity wins → Decision
- Why each design decision matters: rule-based (not LLM) for BLOCK determinism, regex (not parser) for simplicity, local JSONL (not external) for zero deps
- The v0.1.0 packaging incident walkthrough: top-level `policies/` → zero rules in wheel → caught by real external dependent → fix verified with wheel-in-venv test
- Interview talking points ready for all 6 open follow-ups and 10 rules

**For Next Session:**
- Interview prep artifact is URL-stable and shared in memory
- Setup is verified and documented (quick checklist in memory)
- Ready to tackle any of the open follow-ups or interview questions
- All learnings saved to memory system — no context loss on session restart

## Current state (as of v0.1.1)

- Published on PyPI as `ai-agent-guardrails`, MIT licensed, `guard` console
  script installed via `[project.scripts]`.
- 10 rules in `guardrails/policies/default.yaml`, 47 tests, all passing,
  CI green on Python 3.9–3.12 (`.github/workflows/ci.yml`).
- Two real callers: the `guard` CLI and the Claude Code `PreToolUse` hook
  (`integrations/claude_code/pretooluse_hook.py`).
- One real external dependent: `ai-incident-copilot` depends on the
  published package (not a local path) to gate every remediation command
  it proposes.
- `demo.gif` / `demo.tape` (VHS) embedded in the README; CI/PyPI/Python-
  versions/license badges present.
- Working tree is clean; `dist/` has a built `0.1.1` wheel + sdist checked
  out locally (not committed — see `.gitignore`).

## The one real incident so far, and why it matters going forward

v0.1.0 shipped with `policies/` as a **top-level** directory, outside the
`guardrails/` package. `package-data` globs only match inside the package,
so the wheel built and installed without error but loaded **zero rules** —
every command, including `terraform destroy` and `kubectl delete namespace
prod`, evaluated to `ALLOW`. The 47-test suite stayed green throughout
because it ran against an editable install, which reads the YAML from the
working tree regardless of packaging correctness. It was only caught
because `ai-incident-copilot` installed the *published* wheel for real and
got `ALLOW` where a test expected `BLOCK`.

Fixed in v0.1.1 (`guardrails/policies/` + `package-data =
["*.yaml", "policies/*.yaml"]`), and the packaging-trap verification steps
in the skill file exist specifically so this class of bug can't recur
silently. **Any future change to `guardrails/`'s file layout, package-data,
or `pyproject.toml` packaging config must be re-verified against a real
built wheel in a clean venv before being considered safe** — the test
suite passing is not evidence of that on its own.

## Critical Architectural Limitation (Not a Bug — By Design)

**Guardrails does NOT protect raw shell commands.**

```
terraform destroy                    # RUNS - no protection
guard exec -- terraform destroy      # BLOCKED by guardrails ✓
claude code + hook                   # BLOCKED by guardrails ✓
CI/CD with guard gate                # BLOCKED by guardrails ✓
```

**Why:** Guardrails is a policy *layer*, not a sandbox. It only protects commands that flow through it.

**How to enforce in practice:**
1. **For agents:** Integrate PolicyEngine into execution path (Claude Code hook, custom agents)
2. **For CI/CD:** Gate all deployments through `guard exec --` wrapper
3. **For humans:** Use shell alias wrapper (`terraform() { guard exec -- /usr/bin/terraform "$@"; }`)
4. **For teams:** Pre-commit hooks + discipline, not technical enforcement

This is intentional: guardrails preserves developer flexibility while providing protection where integrated. Real safety comes from:
- AI agents using guardrails (incident-copilot)
- CI/CD pipeline enforcement
- Audit trail (everything logged)
- Team discipline

**For interviews:** This is actually a design strength, not a limitation. Shows honest scope.

## Deliberately out of scope (per README's "Status" section) — not bugs, don't "fix" without discussion

- **Regex/shlex parsing, not a real shell parser.** Determined obfuscation
  (`rm -rf $(echo /)`, base64-piped commands, variable-expanded paths) can
  evade the current rules. This is accepted scope for a reference project,
  not an oversight — see README "Why regex + small Python checks instead
  of a full AST/shell parser?".
- **One real integration (Claude Code).** No Cursor or CI-bot adapter
  exists yet; both would be thin wrappers around `PolicyEngine.evaluate()`
  and wouldn't touch `guardrails/` itself.
- **Local JSONL audit log only.** No shipped Loki/ELK/Langfuse exporter —
  by design (zero extra dependencies); wiring one in today is "tail the
  file," not a code change here.

## Open follow-ups (roughly in order of leverage)

1. **A second real integration (Cursor or a generic CI-bot adapter).**
   The architecture explicitly anticipates this (`PolicyEngine.evaluate()`
   is caller-agnostic) but nothing has exercised that seam except Claude
   Code. Writing one would be the first real test that the "thin adapter"
   claim in the README is actually true, not just asserted.
2. **Re-verify the `pretooluse_hook.py` schema assumptions against the
   Claude Code version actually installed.** The hook's own docstring
   flags this as best-effort and version-sensitive; it has not been
   re-checked since it was written. Worth a quick sanity run (see the
   `echo ... | python3 pretooluse_hook.py` check in the skill file) any
   time Claude Code itself updates.
3. **LLM-classifier layer for the WARN tier**, per the README's stated
   design ("a genuinely good complement for the fuzzy cases... where a
   human is going to look at the output anyway"). Explicitly scoped to
   *never* touch the BLOCK path — the whole point of the rule-based core is
   that BLOCK stays deterministic. This is additive, not a replacement for
   anything existing.
4. **Obfuscation-resistant matching for the highest-severity rules**
   specifically (`rm_rf_dangerous`, `terraform_destroy_unreviewed`) —
   e.g. resolving simple `$()`/backtick substitution or base64 before
   matching — without turning the whole engine into a full shell parser.
   Worth scoping narrowly; the README's "not a hardened sandbox" framing
   is a real design choice, not something to walk back wholesale.
5. **More rule coverage** if a concrete new dangerous pattern shows up in
   practice (e.g. via `ai-incident-copilot` usage) — add it the same way
   as the packaging bug was found: by depending on the published package
   for something real, not by brainstorming hypothetical rules in the
   abstract. Prefer rules motivated by an actual near-miss over
   speculative ones.

## Things to check before resuming work here

- `pytest -q` still green (47 tests) — confirm before assuming the
  baseline is unchanged from what's described above.
- `git log --oneline -10` for anything landed since this file was last
  updated — this file is a snapshot, not a live view; trust `git log` and
  the code over this document if they disagree.
- Whether `ai-incident-copilot`'s pinned `ai-agent-guardrails` version has
  moved past `0.1.1` — if so, some of the "current state" numbers above
  (rule count, test count) may be stale and should be re-derived from the
  code rather than assumed.
