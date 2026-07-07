"""
ZoneScan — taint verifier.

Takes a `ZoneCandidate` (a code chunk that cleared the similarity threshold)
and runs a *scoped* Semgrep taint call to confirm or reject the candidate.

"Scoped" means:
  - Only the single rule file corresponding to the matched CWE (not the
    full ruleset).
  - Only the single file containing the candidate function.
  - We check whether any Semgrep result falls within the candidate's
    [line_start, line_end] range.

This reuses `run_semgrep_scoped()` extracted from `semantics_checker.py`,
so there's no subprocess-invocation duplication between the normal scanner
and this targeted verifier.

Why Semgrep instead of Joern here: GrepVF already depends on Semgrep and
already runs it in taint mode. Standing up Joern (JVM, CPG extraction, a
new query language) is real scope for a capability that for MVP just needs
to answer "does a taint path reach a sink in this one function." Reusing
what's already there is faster and is itself a clean interview point: the
new layer makes the existing scanner smarter (scoped, targeted) rather than
replacing it.
"""

from __future__ import annotations

import logging
from pathlib import Path

from engine.codescan.semantics_checker import run_semgrep_scoped

from .models import ZoneCandidate

logger = logging.getLogger(__name__)

# Map CWE ID → rule file name (relative to the codescan rules directory).
# Extend this dict as new CWEs are added to Phase 2+.
_CWE_TO_RULE_FILE: dict[str, str] = {
    "CWE-89": "injection.yml",
    # Phase 2:
    # "CWE-22": "path_traversal.yml",
    # "CWE-79": "xss.yml",
}

_RULES_BASE = Path(__file__).parent.parent / "codescan" / "rules"


def verify(
    candidate: ZoneCandidate,
    repo_root: str,
) -> tuple[bool, str]:
    """
    Run a scoped Semgrep taint call to confirm or reject a `ZoneCandidate`.

    Parameters
    ----------
    candidate : ZoneCandidate
        The chunk that passed the CWE similarity threshold.
    repo_root : str
        Absolute path to the repository root (needed for resolving
        relative file paths and as the Semgrep `cwd`).

    Returns
    -------
    (verified, rule_id)
        `verified=True` when a Semgrep result falls within the candidate's
        line range. `rule_id` is the Semgrep check_id that fired, or ""
        if not verified.
    """
    rule_file_name = _CWE_TO_RULE_FILE.get(candidate.matched_cwe)
    if not rule_file_name:
        logger.debug(
            "[zonescan/taint_verifier] No rule file mapped for %s; skipping verification.",
            candidate.matched_cwe,
        )
        return False, ""

    rule_file = _RULES_BASE / rule_file_name
    if not rule_file.exists():
        logger.warning(
            "[zonescan/taint_verifier] Rule file not found: %s", rule_file
        )
        return False, ""

    # Resolve the target file path. Semgrep accepts both absolute and
    # repo-relative paths; we pass the candidate's file_path as-is since
    # it may already be repo-relative (matches how the rest of the pipeline
    # handles paths).
    target = candidate.file_path

    raw = run_semgrep_scoped(
        target_paths=[target],
        repo_root=repo_root,
        rule_files=[str(rule_file)],
    )

    for result in raw.get("results", []):
        start_line: int = result.get("start", {}).get("line", 0)
        end_line: int = result.get("end", {}).get("line", start_line)

        # Check for overlap with the candidate function's line range.
        if start_line <= candidate.line_end and end_line >= candidate.line_start:
            rule_id = result.get("check_id", "").split(".")[-1]
            logger.debug(
                "[zonescan/taint_verifier] Verified %s in %s:%d-%d (rule: %s)",
                candidate.matched_cwe,
                candidate.file_path,
                candidate.line_start,
                candidate.line_end,
                rule_id,
            )
            return True, rule_id

    return False, ""
