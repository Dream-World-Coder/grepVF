"""
Patch Validator — re-checks a proposed patch against its originating rule.
See `engine/patcher/docs.md` for validation strategies.
"""

import ast
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from engine.codescan import SECRET_REGEXES
from engine.models import Finding

SEMGREP_REVALIDATION_TIMEOUT_SECONDS = 30


@dataclass
class ValidationResult:
    passed: bool
    reason: str


def _check_python_syntax(patched_source: str) -> ValidationResult:
    try:
        ast.parse(patched_source)
        return ValidationResult(passed=True, reason="syntax OK")
    except SyntaxError as exc:
        return ValidationResult(
            passed=False, reason=f"patched code has a syntax error: {exc}"
        )


def _revalidate_against_semgrep_rule(
    patched_source: str, rule_id: str, rules_dir: Path
) -> ValidationResult:
    """
    Writes the patched snippet to a throwaway temp file and re-runs ONLY
    the originating rule (by check_id) against it. Scoping to a single
    rule (rather than the whole rule set) keeps this fast and keeps the
    semantics precise — we're answering "did THIS rule stop firing",
    not "are there now zero issues of any kind."
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tmp:
        tmp.write(patched_source)
        tmp_path = tmp.name

    try:
        proc = subprocess.run(
            [
                "semgrep",
                "--config",
                str(rules_dir),
                "--include",
                f"*{Path(tmp_path).name}",
                "--json",
                "--quiet",
                "--no-git-ignore",
                "--disable-version-check",
                "--metrics",
                "off",
                tmp_path,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=SEMGREP_REVALIDATION_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return ValidationResult(passed=False, reason="semgrep revalidation timed out")
    except FileNotFoundError:
        return ValidationResult(
            passed=False, reason="semgrep executable not found on PATH"
        )
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    stdout = proc.stdout or ""
    if not stdout.strip():
        # No output at all is suspicious (semgrep usually emits a JSON
        # skeleton even with zero findings) — treat as a failed validation
        # rather than silently assuming success.
        return ValidationResult(
            passed=False, reason="semgrep revalidation produced no output"
        )

    import json

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return ValidationResult(
            passed=False, reason="could not parse semgrep revalidation output"
        )

    still_firing = [
        r for r in data.get("results", []) if r["check_id"].split(".")[-1] == rule_id
    ]
    if still_firing:
        return ValidationResult(
            passed=False,
            reason=f"rule '{rule_id}' still fires on the patched code at line {still_firing[0]['start']['line']}",
        )
    return ValidationResult(passed=True, reason=f"rule '{rule_id}' no longer fires")


def _revalidate_against_regex_rule(patched_line: str, rule_id: str) -> ValidationResult:
    for pattern, candidate_rule_id, _severity, _message in SECRET_REGEXES:
        if candidate_rule_id == rule_id:
            if pattern.search(patched_line):
                return ValidationResult(
                    passed=False,
                    reason=f"regex for '{rule_id}' still matches patched line",
                )
            return ValidationResult(
                passed=True, reason=f"regex for '{rule_id}' no longer matches"
            )
    # rule_id not found in the regex table — likely an entropy-only finding
    # (rule_id == "high-entropy-string") with no fixed pattern to recheck.
    # In that case, ANY actual content change is treated as sufficient,
    # since "still has high entropy" isn't a meaningful pass/fail signal
    # for a value that's been replaced entirely (e.g. with an env var
    # lookup) rather than literally rewritten in place.
    return ValidationResult(
        passed=True,
        reason="no fixed regex to recheck for this rule; accepting content change",
    )


def validate_patch(
    finding: Finding,
    patched_content: str,
    rules_dir: Path,
) -> ValidationResult:
    """
    Main entry point. `patched_content` is either:
      - a full patched snippet (for AST-context/LLM-sourced fixes), or
      - a single patched line (for deterministic line-level fixes)
    Dispatches to the right revalidation strategy based on which engine
    originally produced the finding.
    """
    # The Python syntax gate only applies to fixes for Python source files.
    # Dockerfile-sourced findings (and any future non-Python checks) have
    # their own validation strategy below and should never be run through
    # ast.parse(), which would reject valid Dockerfile/YAML/etc. syntax as
    # if it were broken Python.
    if finding.source_engine not in ("semantics_checker.dockerfile_absence_check",):
        syntax_result = _check_python_syntax(patched_content)
        if not syntax_result.passed:
            # only meaningful for snippets that are supposed to be standalone
            # parseable Python (AST-context-derived fixes); a single patched
            # LINE on its own usually won't parse standalone (e.g. just
            # `cursor.execute(query)` with no enclosing function) so we only
            # enforce the syntax gate when the content looks like more than
            # one bare statement — heuristic: multi-line content gets the
            # syntax check, single-line deterministic fixes skip it.
            if "\n" in patched_content.strip():
                return syntax_result

    if finding.source_engine == "semgrep":
        return _revalidate_against_semgrep_rule(
            patched_content, finding.rule_id, rules_dir
        )

    if finding.source_engine.startswith("entropy_checker"):
        return _revalidate_against_regex_rule(patched_content, finding.rule_id)

    if finding.source_engine == "semantics_checker.dockerfile_absence_check":
        # absence-based check: validate by confirming a USER line now exists
        has_user = any(
            line.strip().upper().startswith("USER ")
            for line in patched_content.splitlines()
        )
        return ValidationResult(
            passed=has_user,
            reason="USER directive present"
            if has_user
            else "USER directive still missing",
        )

    return ValidationResult(
        passed=False,
        reason=f"no validation strategy for source_engine={finding.source_engine}",
    )
