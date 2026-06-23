"""
Patch Generator — orchestrates the full patch pipeline for a single Finding.
See `engine/patcher/docs.md` for flowchart and architecture notes.
"""

import asyncio
from dataclasses import dataclass
from pathlib import Path

from engine.models import Finding, FixType
from engine.patcher.ast_context_extractor import extract_minimal_context
from engine.patcher.deterministic_fixes import try_deterministic_fix
from engine.patcher.llm_patcher import (
    LlmPatchError,
    generate_llm_patch_async,
    is_llm_configured,
)
from engine.patcher.patch_validator import validate_patch

RULES_DIR = Path(__file__).parent.parent / "scanner" / "rules"


@dataclass
class PatchOutcome:
    finding: Finding
    fix_type: FixType
    patched_content: str | None  # None when no fix could be produced at all
    explanation: str
    validated: bool
    diff_preview: str | None = (
        None  # human-readable before/after, set by caller with file context
    )


def _get_source_line(repo_root: str, finding: Finding) -> str | None:
    abs_path = Path(repo_root) / finding.file_path
    try:
        lines = abs_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None
    if 1 <= finding.line <= len(lines):
        return lines[finding.line - 1]
    return None


def _get_full_source(repo_root: str, finding: Finding) -> str | None:
    abs_path = Path(repo_root) / finding.file_path
    try:
        return abs_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


async def generate_patch_async(repo_root: str, finding: Finding) -> PatchOutcome:
    """
    Attempts to produce a validated patch for a single finding, trying
    each strategy in order and stopping at the first one that produces a
    fix that passes validation. If nothing validates, returns a
    MANUAL_REVIEW outcome rather than ever showing an unverified fix.
    """
    source_line = _get_source_line(repo_root, finding)

    # --- Strategy 1: deterministic fix ---
    if source_line is not None:
        det_result = try_deterministic_fix(source_line, finding)
        if det_result is not None:
            validation = validate_patch(finding, det_result.fixed_line, RULES_DIR)
            if validation.passed:
                return PatchOutcome(
                    finding=finding,
                    fix_type=FixType.DETERMINISTIC,
                    patched_content=det_result.fixed_line,
                    explanation=det_result.explanation,
                    validated=True,
                )
            # deterministic fix existed but failed validation — this is a
            # signal the fix function itself has a bug; fall through to LLM
            # rather than silently presenting a fix we know is wrong.

    # --- Strategy 2: LLM with minimal AST context ---
    if is_llm_configured():
        full_source = _get_full_source(repo_root, finding)
        if full_source is not None:
            context = extract_minimal_context(full_source, finding.line)
            if context is not None:
                try:
                    llm_result = await generate_llm_patch_async(finding, context)
                except LlmPatchError as exc:
                    return PatchOutcome(
                        finding=finding,
                        fix_type=FixType.MANUAL_REVIEW,
                        patched_content=None,
                        explanation=f"LLM patch generation failed: {exc}",
                        validated=False,
                    )

                validation = validate_patch(
                    finding, llm_result.patched_source, RULES_DIR
                )
                if validation.passed:
                    return PatchOutcome(
                        finding=finding,
                        fix_type=FixType.LLM,
                        patched_content=llm_result.patched_source,
                        explanation=(
                            f"LLM-generated fix (model: {llm_result.model_used}), "
                            f"validated: {validation.reason}"
                        ),
                        validated=True,
                    )
                return PatchOutcome(
                    finding=finding,
                    fix_type=FixType.MANUAL_REVIEW,
                    patched_content=llm_result.patched_source,
                    explanation=(
                        f"LLM produced a fix but it failed re-validation ({validation.reason}). "
                        "Flagging for manual review rather than presenting an unverified patch."
                    ),
                    validated=False,
                )

    # --- Strategy 3: nothing worked ---
    return PatchOutcome(
        finding=finding,
        fix_type=FixType.MANUAL_REVIEW,
        patched_content=None,
        explanation=(
            "No deterministic fix is registered for this rule and no LLM endpoint is "
            "configured (or the source line/file could not be read). Flagged for manual review."
        ),
        validated=False,
    )


def generate_patch(repo_root: str, finding: Finding) -> PatchOutcome:
    """Synchronous wrapper for non-async callers (e.g. the CLI)."""
    return asyncio.run(generate_patch_async(repo_root, finding))


async def generate_patches_for_findings_async(
    repo_root: str, findings: list[Finding]
) -> list[PatchOutcome]:
    """
    Batches patch generation across many findings concurrently — LLM calls
    in particular benefit from this since they're I/O-bound network
    requests, not CPU-bound work competing for the same core.
    """
    return await asyncio.gather(*[generate_patch_async(repo_root, f) for f in findings])
