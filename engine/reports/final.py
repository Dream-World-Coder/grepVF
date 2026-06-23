"""
Report Aggregator — merges findings into a deduplicated, hazard-ranked manifest.
See `engine/reports/docs.md` for deduplication and hazard scoring rules.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from engine.models import Category, Finding, Severity

# Filename/path fragments that suggest a file is reachable from untrusted
# network input — used only as a coarse hazard-score signal, never to
# suppress a finding outright.
_INTERNET_FACING_HINTS = (
    "view",
    "views",
    "route",
    "routes",
    "handler",
    "handlers",
    "controller",
    "controllers",
    "api",
    "endpoint",
    "webhook",
)

# Rule IDs where Semgrep's taint-mode (cross-line data-flow tracking) was
# used rather than a purely structural pattern match. Findings from these
# rules get a hazard-score bump because a confirmed taint path is a
# stronger exploitability signal than "this pattern shape appeared."
_TAINT_CONFIRMED_RULES = {
    "sql-injection-string-concat",
}


@dataclass
class AggregatedReport:
    findings: list[Finding]
    total_before_dedup: int
    total_after_dedup: int
    duplicates_removed: int
    counts_by_severity: dict[str, int] = field(default_factory=dict)
    counts_by_category: dict[str, int] = field(default_factory=dict)
    counts_by_engine: dict[str, int] = field(default_factory=dict)

    def has_unresolved_critical(self) -> bool:
        return any(
            f.severity == Severity.CRITICAL
            and f.fix_type.value != "deterministic_validated"
            for f in self.findings
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "total_findings": self.total_after_dedup,
                "duplicates_removed": self.duplicates_removed,
                "by_severity": self.counts_by_severity,
                "by_category": self.counts_by_category,
                "by_engine": self.counts_by_engine,
            },
            "findings": [f.to_dict() for f in self.findings],
        }


def _is_internet_facing(file_path: str) -> bool:
    lowered = file_path.lower()
    return any(hint in lowered for hint in _INTERNET_FACING_HINTS)


def get_hazard_score(finding: Finding) -> float:
    """
    Starts from the severity's base hazard value (CRITICAL=9, HIGH=7,
    MEDIUM=4, LOW=2 — see Severity.base_hazard) and adds small bumps for
    exploitability signals, capped at 10. The base/bump split keeps the
    score interpretable: you can always recover "what severity bucket was
    this" just by looking at which decade the score falls in, while still
    getting a meaningful ordering of findings within a CRITICAL pile-up.
    """
    score = finding.severity.base_hazard

    if finding.rule_id in _TAINT_CONFIRMED_RULES:
        score += 1.0

    if _is_internet_facing(finding.file_path):
        score += 1.0

    # CVEs with a known fixed version available are slightly more urgent to
    # act on than ones with no fix yet, since "just bump the version" is a
    # low-effort remediation that should be prioritized while it's cheap.
    if finding.category == Category.CVE and finding.extra.get("fixed_version"):
        score += 0.5

    return min(score, 10.0)


def _dedup_key(finding: Finding) -> tuple[str, int]:
    """
    Two findings are considered duplicates if they land on the exact same
    file + line. This is intentionally coarser than Finding.dedup_key()
    (which also includes rule_id) — dedup_key() is for "did this exact
    rule already report this exact spot before" (used for SARIF result
    identity), whereas aggregation-level dedup is for "are two DIFFERENT
    rules describing what is really the same underlying issue."
    """
    return (finding.file_path, finding.line)


def aggregate(scan_results_findings: list[list[Finding]]) -> AggregatedReport:
    """
    Takes the raw findings lists from each scanner (entropy, CVE,
    semantics — in any order) and produces one merged, deduplicated,
    hazard-ranked report.
    """
    all_findings: list[Finding] = [
        f for findings in scan_results_findings for f in findings
    ]
    total_before = len(all_findings)

    # group candidates by dedup key, keep the highest-severity one per group
    groups: dict[tuple[str, int], list[Finding]] = defaultdict(list)
    for f in all_findings:
        groups[_dedup_key(f)].append(f)

    deduped: list[Finding] = []
    for _, candidates in groups.items():
        if len(candidates) == 1:
            deduped.append(candidates[0])
            continue

        # CVE findings never collide with secret/semantic findings in a way
        # that means "same issue" — a CVE's line number is a manifest line,
        # which is a coincidental collision, not a real duplicate. Split
        # CVE candidates out and never merge them with anything else.
        cve_candidates = [c for c in candidates if c.category == Category.CVE]
        non_cve_candidates = [c for c in candidates if c.category != Category.CVE]
        deduped.extend(cve_candidates)

        if not non_cve_candidates:
            continue

        # SECRET and MISCONFIGURATION findings on the same line are treated
        # as describing the same underlying issue (e.g. a hardcoded secret
        # flagged once by the entropy/regex engine as SECRET and once by a
        # Semgrep config-pattern rule as MISCONFIGURATION — both describing
        # "this Dockerfile ENV line leaks a credential"). Merge these into
        # one equivalence class; everything else dedups strictly within its
        # own category only.
        merge_classes: dict[str, list[Finding]] = defaultdict(list)
        for c in non_cve_candidates:
            class_key = (
                "secret_or_misconfig"
                if c.category in (Category.SECRET, Category.MISCONFIGURATION)
                else c.category.value
            )
            merge_classes[class_key].append(c)

        for class_candidates in merge_classes.values():
            winner = max(class_candidates, key=lambda f: f.severity.base_hazard)
            deduped.append(winner)

    for f in deduped:
        f.hazard_score = get_hazard_score(f)

    # deduped.sort(key=lambda f: f.hazard_score, reverse=True)
    deduped.sort(
        key=lambda f: f.hazard_score if f.hazard_score is not None else float("-inf"),
        reverse=True,
    )

    counts_by_severity: dict[str, int] = defaultdict(int)
    counts_by_category: dict[str, int] = defaultdict(int)
    counts_by_engine: dict[str, int] = defaultdict(int)
    for f in deduped:
        counts_by_severity[f.severity.value] += 1
        counts_by_category[f.category.value] += 1
        counts_by_engine[f.source_engine] += 1

    return AggregatedReport(
        findings=deduped,
        total_before_dedup=total_before,
        total_after_dedup=len(deduped),
        duplicates_removed=total_before - len(deduped),
        counts_by_severity=dict(counts_by_severity),
        counts_by_category=dict(counts_by_category),
        counts_by_engine=dict(counts_by_engine),
    )
