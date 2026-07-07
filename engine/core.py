"""
GrepVF — core

Primary orchestrator for the scanning pipeline. See `engine/docs.md` for detailed
architectural design, pipeline order, and concurrency notes.
"""

import asyncio
import time
from pathlib import Path

from typing_extensions import override

from engine.codescan import (
    check_dependencies_async,
    parse_all_manifests,
    run_entropy_checker,
    run_semantics_checker,
)
from engine.filescan import RoutedFiles, scan_files
from engine.models import Finding, FixType, ScanResult
from engine.patcher import PatchOutcome, generate_patches_for_findings_async
from engine.reports import AggregatedReport, aggregate
from engine.zonescan import run_zone_detector

# ---------------------------------------------------------------------------
# Module-level helpers  (not part of GrepVF's public surface)
# ---------------------------------------------------------------------------


def _fmt(elapsed: float) -> str:
    return f"{elapsed:.2f}s"


def _plural(n: int, singular: str, plural: str | None = None) -> str:
    return f"{n} {singular if n == 1 else (plural or singular + 's')}"


def _print_routing_summary(files: RoutedFiles) -> None:
    print(
        f"  routed   secrets:{len(files.secrets)}  "
        + f"\nmanifests:{len(files.manifests)}  "
        + f"\ncode:{len(files.code)}"
    )
    if files.skipped_binary:
        print(f"  skipped  {_plural(len(files.skipped_binary), 'binary file')}")
    if files.skipped_too_large:
        print(f"  skipped  {_plural(len(files.skipped_too_large), 'oversized file')}")


def _print_scanner_errors(engine_name: str, result: ScanResult) -> None:
    """Surface non-fatal scanner warnings so they're visible without crashing."""
    for err in result.errors:
        print(f"  [{engine_name}] warning: {err}")


def _print_scanner_summary(
    entropy: ScanResult,
    cve: ScanResult,
    semantics: ScanResult,
    elapsed: float,
    zone: ScanResult | None = None,
) -> None:
    for name, result in (("entropy", entropy), ("cve", cve), ("semantics", semantics)):
        print(
            f"  {name:<12} "
            + f"\n{len(result.findings):>3} finding(s)  "
            + f"\n{result.files_scanned} file(s) scanned"
        )
    if zone is not None:
        print(
            f"  {'zonescan':<12} "
            + f"\n{len(zone.findings):>3} finding(s)  "
            + f"\n{zone.files_scanned} file(s) scanned"
        )
    print(f"  ({_fmt(elapsed)})")


def _print_severity_breakdown(report: AggregatedReport) -> None:
    parts = [
        f"{sev}: {report.counts_by_severity[sev]}"
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        if report.counts_by_severity.get(sev)
    ]
    if parts:
        print(f"  severity  {', '.join(parts)}")


def _print_patch_summary(outcomes: list[PatchOutcome]) -> None:
    det = sum(1 for o in outcomes if o.fix_type == FixType.DETERMINISTIC)
    llm = sum(1 for o in outcomes if o.fix_type == FixType.LLM)
    manual = sum(1 for o in outcomes if o.fix_type == FixType.MANUAL_REVIEW)
    valid = sum(1 for o in outcomes if o.validated)
    print(
        f"  deterministic:{det}  llm:{llm}  "
        + f"\nmanual-review:{manual}  validated:{valid}/{len(outcomes)}"
    )


def _apply_patch_outcomes(
    findings: list[Finding],
    outcomes: list[PatchOutcome],
) -> None:
    """
    Write patch results back onto Finding objects in-place.

    asyncio.gather preserves ordering, so outcomes[i] corresponds to
    findings[i] — no identity lookup needed.
    """
    for finding, outcome in zip(findings, outcomes):
        finding.fix_type = outcome.fix_type
        finding.suggested_fix = outcome.patched_content
        finding.fix_validated = outcome.validated


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class GrepVF:
    """
    Orchestrates the full GrepVF pipeline for a single repository root.

    Attributes
    ----------
    root_path      : Path  — resolved absolute path of the scanned repo
    files          : RoutedFiles | None — populated after run_file_scan or run_scan
    scan_results   : dict[str, ScanResult] | None — per-engine results keyed by
                     "entropy", "cve", "semantics"; populated after run_scan
    report         : AggregatedReport | None — populated after run_scan
    patch_outcomes : list[PatchOutcome] | None — populated when patch=True
    """

    def __init__(self, root_path: str) -> None:
        if not root_path or not isinstance(root_path, str):
            raise ValueError("root_path must be a valid, non-empty string.")

        self.root_path: Path = Path(root_path).resolve()
        if not self.root_path.is_dir():
            raise FileNotFoundError(
                f"Target directory does not exist: {self.root_path}"
            )

        # populated progressively as the pipeline runs
        self.files: RoutedFiles | None = None
        self.scan_results: dict[str, ScanResult] | None = None
        self.report: AggregatedReport | None = None
        self.patch_outcomes: list[PatchOutcome] | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_file_scan(self) -> RoutedFiles:
        """
        Routing-only pass.

        Classifies every file in the repo into typed queues without
        invoking any vulnerability scanner.  Useful for:
          - Debugging routing configuration before a full scan
          - Dry-run mode to inspect coverage before a long scan
          - Unit tests that only need to verify routing logic
        """
        print(f"[GrepVF] Routing: {self.root_path}")
        self.files = scan_files(str(self.root_path))
        _print_routing_summary(self.files)
        return self.files

    async def run_scan_async(
        self,
        patch: bool = False,
        zone_detect: bool = False,
        zone_index_path: str | None = None,
    ) -> AggregatedReport:
        """
        Full pipeline, async variant.

        Parameters
        ----------
        patch : bool
            When True, runs patch generation after aggregation and writes
            fix_type / suggested_fix / fix_validated back onto each Finding
            in the returned report.
        zone_detect : bool
            When True, enables the ZoneScan retrieval+verification layer as a
            4th concurrent scanner. Requires the embedding model to be
            available (transformers + torch). Default off — use `--zone-detect`
            to enable.
        zone_index_path : str | None
            Path to a pre-built CWE index directory (M2+ artifacts). When None,
            uses the built-in M1 zero-shot centroid.

        Returns
        -------
        AggregatedReport
            Also stored as self.report for post-scan inspection.
        """
        t_total = time.perf_counter()
        root = str(self.root_path)
        loop = asyncio.get_running_loop()

        # ------------------------------------------------------------------
        # Stage 1: file routing
        # ------------------------------------------------------------------
        print(f"[GrepVF] Scanning: {self.root_path}")
        t0 = time.perf_counter()
        self.files = await loop.run_in_executor(None, scan_files, root)
        _print_routing_summary(self.files)
        print(f"  ({_fmt(time.perf_counter() - t0)})")

        if self.files.total_routed == 0:
            print("[GrepVF] No scannable files found — nothing to report.")
            self.report = aggregate([[], [], [], []])
            return self.report

        # ------------------------------------------------------------------
        # Stage 2: manifest parse  (prerequisite for CVE scanner)
        # ------------------------------------------------------------------
        t0 = time.perf_counter()
        dependencies = await loop.run_in_executor(
            None, parse_all_manifests, root, self.files.manifests
        )
        print(
            f"  {_plural(len(dependencies), 'pinned dependency', 'pinned dependencies')} "
            + f"\nfrom {_plural(len(self.files.manifests), 'manifest')} "
            + f"\n({_fmt(time.perf_counter() - t0)})"
        )

        # ------------------------------------------------------------------
        # Stage 3: three (or four) scanners, concurrent
        #
        # entropy_checker and semantics_checker are synchronous; dispatched
        # to a thread pool so they don't block the event loop during the
        # CVE checker's HTTP calls.
        # zone_detector is also synchronous (CPU-bound: embedding inference
        # + a Semgrep subprocess); dispatched the same way.
        # ------------------------------------------------------------------
        print("[GrepVF] Running scanners...")
        t0 = time.perf_counter()

        entropy_task = loop.run_in_executor(
            None, run_entropy_checker, root, self.files.secrets
        )
        semantics_task = loop.run_in_executor(
            None, run_semantics_checker, root, self.files.code
        )

        if zone_detect:
            zone_task = loop.run_in_executor(
                None,
                run_zone_detector,
                root,
                self.files.code,
                zone_index_path,
            )
            (
                entropy_result,
                semantics_result,
                cve_result,
                zone_result,
            ) = await asyncio.gather(
                entropy_task,
                semantics_task,
                check_dependencies_async(dependencies),
                zone_task,
            )
        else:
            entropy_result, semantics_result, cve_result = await asyncio.gather(
                entropy_task,
                semantics_task,
                check_dependencies_async(dependencies),
            )
            zone_result = ScanResult(
                findings=[], engine="zonescan", files_scanned=0
            )

        self.scan_results = {
            "entropy": entropy_result,
            "cve": cve_result,
            "semantics": semantics_result,
            "zonescan": zone_result,
        }

        _print_scanner_errors("entropy", entropy_result)
        _print_scanner_errors("cve", cve_result)
        _print_scanner_errors("semantics", semantics_result)
        if zone_detect:
            _print_scanner_errors("zonescan", zone_result)
        _print_scanner_summary(
            entropy_result,
            cve_result,
            semantics_result,
            time.perf_counter() - t0,
            zone=zone_result if zone_detect else None,
        )

        # ------------------------------------------------------------------
        # Stage 4: aggregation
        # ------------------------------------------------------------------
        self.report = aggregate(
            [
                entropy_result.findings,
                cve_result.findings,
                semantics_result.findings,
                zone_result.findings,
            ]
        )

        print(
            f"[GrepVF] {self.report.total_after_dedup} unique finding(s) \n({self.report.duplicates_removed} duplicate(s) removed)"
        )
        _print_severity_breakdown(self.report)

        # ------------------------------------------------------------------
        # Stage 5: patch generation (opt-in)
        # ------------------------------------------------------------------
        if patch and self.report.findings:
            n = len(self.report.findings)
            print(f"[GrepVF] Generating patches for {_plural(n, 'finding')}...")
            t0 = time.perf_counter()

            self.patch_outcomes = await generate_patches_for_findings_async(
                root, self.report.findings
            )
            _apply_patch_outcomes(self.report.findings, self.patch_outcomes)
            _print_patch_summary(self.patch_outcomes)
            print(f"  ({_fmt(time.perf_counter() - t0)})")

        print(f"[GrepVF] Done — {_fmt(time.perf_counter() - t_total)} total")
        return self.report

    def run_scan(
        self,
        patch: bool = False,
        zone_detect: bool = False,
        zone_index_path: str | None = None,
    ) -> AggregatedReport:
        """Synchronous wrapper around run_scan_async for CLI / test callers."""
        return asyncio.run(
            self.run_scan_async(
                patch=patch,
                zone_detect=zone_detect,
                zone_index_path=zone_index_path,
            )
        )

    def has_blocking_criticals(self) -> bool:
        """
        CI gate check.

        Returns True when the completed report contains any unresolved
        CRITICAL finding — the condition that causes the pipeline to
        hard-block a PR merge.

        Raises
        ------
        RuntimeError
            If called before any scan has completed.
        """
        if self.report is None:
            raise RuntimeError(
                "has_blocking_criticals() called before run_scan().\n Run engine.run_scan() first."
            )
        return self.report.has_unresolved_critical()

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    @override
    def __repr__(self) -> str:
        if self.report:
            status = "Scanned"
            extra = f", findings={self.report.total_after_dedup}"
        elif self.files:
            status = "Routed"
            extra = f", routed={self.files.total_routed}"
        else:
            status = "Pending"
            extra = ""
        return f"<GrepVF(path='{self.root_path.name}', status='{status}'{extra})>"
