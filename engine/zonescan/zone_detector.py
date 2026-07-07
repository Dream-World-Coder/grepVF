"""
ZoneScan — zone detector.

Orchestrates the full zonescan pipeline for a list of Python source files:

  chunk → embed → query index → taint verify → emit Finding

Returns a list of `engine.models.Finding` objects so `core.py` can pass
this into `aggregate()` without any changes to the aggregation or SARIF
layers.

Concurrency note: `run_zone_detector()` is synchronous. `core.py` dispatches
it via `loop.run_in_executor()` (the same pattern used for entropy_checker
and semantics_checker) so it runs concurrently with the async CVE checker
HTTP calls without blocking the event loop.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from engine.models import Category, Finding, ScanResult, Severity

from .chunker import extract_function_chunks
from .cwe_index import CWEIndex, build_m1_index, load_index, query as index_query
from .embedder import embed_chunk
from .models import ZoneFinding
from .taint_verifier import verify

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rule IDs used in emitted Findings (distinct from Semgrep rule IDs so SARIF
# `partialFingerprints` dedup doesn't collide with semantics_checker results)
# ---------------------------------------------------------------------------
_RULE_VERIFIED = "zonescan/cwe-89-verified"
_RULE_PROBABLE = "zonescan/cwe-89-probable"

# CWE → rule ID mapping (mirrors taint_verifier._CWE_TO_RULE_FILE, but for
# the Finding output — decoupled so Phase 2 CWEs get their own rule IDs)
_CWE_TO_RULE: dict[str, dict[str, str]] = {
    "CWE-89": {
        "verified": _RULE_VERIFIED,
        "probable": _RULE_PROBABLE,
    }
}

# Similarity threshold for surfacing probable (unverified) findings.
# Verified findings surface regardless of this threshold (they already
# cleared centroid_threshold in cwe_index.query); this controls whether
# a *failed* verification still gets reported.
_PROBABLE_THRESHOLD = float(os.environ.get("ZONESCAN_THRESHOLD", "0.80"))

# Module-level cached index (loaded once per process; reset in tests via
# _reset_index_cache() below)
_cached_index: CWEIndex | None = None


def _get_index(index_path: str | None) -> CWEIndex:
    global _cached_index
    if _cached_index is None:
        if index_path:
            _cached_index = load_index(index_path)
        else:
            _cached_index = build_m1_index()
    return _cached_index


def _reset_index_cache() -> None:
    """For use in tests that need a fresh index per test run."""
    global _cached_index
    _cached_index = None


def _zone_finding_to_finding(
    zf: ZoneFinding,
    repo_root: str,
) -> Finding:
    """
    Convert a `ZoneFinding` to the `Finding` type expected by the aggregator.

    Rule-ID assignment:
      zonescan/cwe-89-verified  → severity HIGH  (similarity match + taint confirmed)
      zonescan/cwe-89-probable  → severity MEDIUM (similarity match only)

    ZoneScan fields are stored in `Finding.extra` so the SARIF writer and
    aggregator don't need to know about zonescan internals.
    """
    rules = _CWE_TO_RULE.get(zf.matched_cwe, {})
    rule_id = rules.get("verified" if zf.verified else "probable", "zonescan/unknown")

    severity = Severity.HIGH if zf.verified else Severity.MEDIUM

    if zf.verified:
        message = (
            f"[ZoneScan] Function '{zf.function_name}' is semantically similar to "
            f"known {zf.matched_cwe} (SQL Injection) patterns "
            f"(centroid_sim={zf.centroid_similarity:.3f}) AND a scoped Semgrep "
            f"taint check confirmed a taint path (rule: {zf.verification_rule}). "
            "Use parameterized queries instead of string-concatenated SQL."
        )
    else:
        message = (
            f"[ZoneScan] Function '{zf.function_name}' is semantically similar to "
            f"known {zf.matched_cwe} (SQL Injection) patterns "
            f"(centroid_sim={zf.centroid_similarity:.3f}). "
            "Scoped taint verification did not fire — this may be a novel variant "
            "or a false positive. Review the function for unsanitized SQL construction."
        )

    # Read the function's first line as matched_code (same pattern as the
    # semantics_checker's _read_source_line)
    matched_code: str | None = None
    try:
        abs_path = Path(repo_root) / zf.file_path
        lines = abs_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if 1 <= zf.line_start <= len(lines):
            matched_code = lines[zf.line_start - 1].strip()
    except OSError:
        pass

    return Finding(
        rule_id=rule_id,
        file_path=zf.file_path,
        line=zf.line_start,
        end_line=zf.line_end,
        severity=severity,
        category=Category.INJECTION,
        message=message,
        cwe=zf.matched_cwe,
        matched_code=matched_code,
        source_engine="zonescan",
        extra={
            "function_name": zf.function_name,
            "centroid_similarity": zf.centroid_similarity,
            "nearest_instance_similarity": zf.nearest_instance_similarity,
            "verified": zf.verified,
            "verification_rule": zf.verification_rule,
        },
    )


def run_zone_detector(
    repo_root: str,
    file_paths: list[str],
    index_path: str | None = None,
    centroid_threshold: float = _PROBABLE_THRESHOLD,
) -> ScanResult:
    """
    Entry point called by `core.py` via `run_in_executor`.

    Parameters
    ----------
    repo_root : str
        Absolute path to the repository root.
    file_paths : str
        List of repo-relative paths to Python source files
        (the `files.code` queue from the file router).
    index_path : str | None
        Path to a pre-built CWE index directory. If None, uses the
        built-in M1 zero-shot centroid.
    centroid_threshold : float
        Minimum centroid cosine similarity to process a candidate.

    Returns
    -------
    ScanResult
        Compatible with the existing `aggregate()` call in `core.py`.
    """
    if not file_paths:
        return ScanResult(findings=[], engine="zonescan", files_scanned=0)

    py_files = [p for p in file_paths if p.endswith(".py")]
    if not py_files:
        return ScanResult(
            findings=[], engine="zonescan", files_scanned=len(file_paths)
        )

    index = _get_index(index_path)
    findings: list[Finding] = []
    errors: list[str] = []

    for rel_path in py_files:
        # Resolve to absolute for chunker, but keep rel_path for Finding
        abs_path = str(Path(repo_root) / rel_path)
        try:
            chunks = extract_function_chunks(abs_path)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"chunker failed on {rel_path}: {exc}")
            continue

        for chunk in chunks:
            try:
                embedding = embed_chunk(chunk.text)
            except Exception as exc:  # noqa: BLE001
                errors.append(
                    f"embed failed on {rel_path}:{chunk.function_name}: {exc}"
                )
                continue

            candidates = index_query(embedding, index, threshold=centroid_threshold)

            for candidate in candidates:
                # Inject chunk metadata that cwe_index.query() leaves blank
                candidate.file_path = rel_path
                candidate.function_name = chunk.function_name
                candidate.line_start = chunk.line_start
                candidate.line_end = chunk.line_end

                try:
                    verified, verification_rule = verify(candidate, repo_root)
                except Exception as exc:  # noqa: BLE001
                    errors.append(
                        f"taint verify failed on {rel_path}:{chunk.function_name}: {exc}"
                    )
                    verified, verification_rule = False, ""

                # Surface both verified and high-similarity unverified findings.
                # Unverified findings are the novel-variant signal that the
                # exact-match scanners structurally cannot produce.
                zf = ZoneFinding(
                    file_path=rel_path,
                    function_name=chunk.function_name,
                    line_start=chunk.line_start,
                    line_end=chunk.line_end,
                    matched_cwe=candidate.matched_cwe,
                    centroid_similarity=candidate.centroid_similarity,
                    nearest_instance_similarity=candidate.nearest_instance_similarity,
                    verified=verified,
                    verification_rule=verification_rule or "",
                )
                findings.append(_zone_finding_to_finding(zf, repo_root))

    logger.info(
        "[zonescan] Scanned %d Python files, produced %d finding(s), %d error(s)",
        len(py_files),
        len(findings),
        len(errors),
    )

    return ScanResult(
        findings=findings,
        engine="zonescan",
        files_scanned=len(file_paths),
        errors=errors,
    )
