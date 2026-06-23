# Patcher Module Documentation

This module orchestrates the full patch pipeline for findings.

## Patch Generator

The Patch Generator owns the decision of which underlying strategy to try and in what order. This is the only module that callers (the CLI, the FastAPI webhook receiver) should import to get a patch.

**Flowchart:**
Auto-fixable? -> deterministic rule table -> (fail) -> LLM with minimal AST context -> validate -> ready for review.

## Patch Validator

Re-checks a proposed patch (deterministic OR LLM-generated) against the SAME rule that originally flagged it, before the patch is ever shown to a developer.

This exists because an LLM-generated fix can plausibly look right while still being wrong — e.g., "fixing" a SQL injection by switching to an f-string with different formatting that the original regex/taint rule still flags, or a fix that breaks syntactically. Re-validating closes the loop: "every patch is verified with rescan or formal grammars" before a developer ever sees it.

**Validation Strategies:**
1. **Semgrep-sourced findings** (`semantics_checker`): writes the patched snippet to a temp file and re-runs the SAME Semgrep rule against just that file. If the rule still fires, the patch failed.
2. **Regex-sourced findings** (`entropy_checker`): re-runs the same regex against the patched line. If it still matches, the patch failed.
3. **Syntax check** (always, regardless of source): the patched snippet must parse as valid Python. A patch that breaks syntax is rejected even if it would have satisfied the original rule, since "fixes the security issue but doesn't compile" is not a usable patch.
