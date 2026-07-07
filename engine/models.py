"""
Shared data models used across every scanner, the aggregator, the patcher,
and the SARIF writer.

Keeping these in one place avoids the classic problem where the entropy
checker's "finding" dict has different keys than the Semgrep wrapper's, and
the aggregator has to special-case both. Every scanner returns a list of
`Finding` objects, full stop.
"""

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def base_hazard(self) -> float:
        return {
            Severity.CRITICAL: 9.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 2.0,
        }[self]

    @property
    def sarif_level(self) -> str:
        # SARIF only has error/warning/note/none — we fold CRITICAL+HIGH to error
        return {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
        }[self]


class Category(str, Enum):
    SECRET = "secret"
    CVE = "cve"
    MISCONFIGURATION = "misconfiguration"
    INJECTION = "injection"
    WEAK_CRYPTO = "weak_crypto"
    AUTH = "auth"
    TLS = "tls"
    SUPPLY_CHAIN = "supply_chain"
    OTHER = "other"


class FixType(str, Enum):
    NONE = "none"  # no fix attempted
    DETERMINISTIC = "deterministic"  # rule-table / AST-rewrite fix
    LLM = "llm"  # LLM-generated fix
    MANUAL_REVIEW = "manual_review"  # flagged, no automated fix possible


@dataclass
class Finding:
    """A single normalized vulnerability/misconfiguration finding."""

    rule_id: str
    file_path: str
    line: int
    end_line: int
    severity: Severity
    category: Category
    message: str
    cwe: Optional[str] = None
    matched_code: Optional[str] = None  # the offending snippet
    column: int = 1
    end_column: int = 1
    source_engine: str = "unknown"  # "entropy" | "cve" | "semgrep" | "zonescan"
    extra: dict = field(default_factory=dict)  # engine-specific payload
    hazard_score: Optional[float] = None  # filled in by aggregator
    fix_type: FixType = FixType.NONE
    suggested_fix: Optional[str] = None
    fix_validated: bool = False

    def dedup_key(self) -> str:
        """
        Stable key for deduplication across scanners. Two findings on the
        same file+line+rule are considered the same finding even if produced
        by different engines (e.g. a secret found by both regex and entropy).
        """
        raw = f"{self.file_path}:{self.line}:{self.rule_id}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = {
            "rule_id": self.rule_id,
            "file": self.file_path,
            "line": self.line,
            "end_line": self.end_line,
            "column": self.column,
            "end_column": self.end_column,
            "severity": self.severity.value,
            "category": self.category.value,
            "message": self.message,
            "cwe": self.cwe,
            "matched_code": self.matched_code,
            "source_engine": self.source_engine,
            "hazard_score": self.hazard_score,
            "fix_type": self.fix_type.value,
            "suggested_fix": self.suggested_fix,
            "fix_validated": self.fix_validated,
        }
        return d


@dataclass
class ScanResult:
    """Output of a single scanner module before aggregation."""

    findings: list[Finding]
    engine: str
    files_scanned: int
    errors: list[str] = field(default_factory=list)
