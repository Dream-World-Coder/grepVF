"""
SARIF Writer — serializes an AggregatedReport into SARIF 2.1.0 format.
See `engine/sarif/docs.md` for structure decisions and GitHub-specific tags.
"""

from __future__ import annotations

import json
from pathlib import Path

from engine.models import Finding
from engine.reports.final import AggregatedReport

SARIF_SCHEMA_URL = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "CodeScan"
TOOL_ORGANIZATION = "System Callers"

# GitHub's Security tab reads this 0.0-10.0 value (as a string) from
# properties["security-severity"] to rank/color findings. This is separate
# from our own Finding.hazard_score so a change to our internal scoring
# heuristic doesn't silently change what GitHub displays — this mapping is
# deliberately a stable, simple function of severity alone.
_SECURITY_SEVERITY_SCORE = {
    "CRITICAL": "9.5",
    "HIGH": "7.5",
    "MEDIUM": "5.0",
    "LOW": "2.5",
}


def _rule_definition(finding: Finding) -> dict:
    """
    One `reportingDescriptor` entry for the rule registry. Called once per
    unique rule_id — see _build_rules_array for the dedup pass.
    """
    rule: dict = {
        "id": finding.rule_id,
        "name": finding.rule_id,
        "shortDescription": {"text": finding.message[:120]},
        "fullDescription": {"text": finding.message},
        "help": {
            "text": finding.message,
            "markdown": f"**{finding.rule_id}**\n\n{finding.message}",
        },
        "defaultConfiguration": {"level": finding.severity.sarif_level},
        "properties": {
            "security-severity": _SECURITY_SEVERITY_SCORE.get(
                finding.severity.value, "5.0"
            ),
            "tags": ["security", finding.category.value],
        },
    }
    if finding.cwe:
        cwe_number = finding.cwe.replace("CWE-", "")
        rule["properties"]["tags"].append(f"external/cwe/cwe-{cwe_number}")
        # NOTE: SARIF supports a `relationships` block to formally link a
        # rule to an external CWE taxonomy entry, but that requires the
        # document to also define a full `toolComponent` taxonomy object
        # elsewhere (with a real, registered GUID) — a placeholder GUID
        # fails strict schema validation. The `external/cwe/cwe-NNN` tag
        # convention above is what GitHub's own Security tab and most
        # third-party SARIF producers (Checkov, KICS) actually use for
        # CWE association in practice, so we stick to that simpler,
        # schema-valid approach rather than a half-implemented taxonomy.
    return rule


def _build_rules_array(findings: list[Finding]) -> list[dict]:
    seen: dict[str, dict] = {}
    for f in findings:
        if f.rule_id not in seen:
            seen[f.rule_id] = _rule_definition(f)
    # stable order: sorted by rule_id so output is deterministic across runs
    # (important for diffing SARIF output between CI runs / golden-file tests)
    return [seen[rule_id] for rule_id in sorted(seen.keys())]


def _build_result(finding: Finding, rule_index_by_id: dict[str, int]) -> dict:
    result: dict = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index_by_id[finding.rule_id],
        "level": finding.severity.sarif_level,
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _normalize_path(finding.file_path)},
                    "region": {
                        "startLine": max(finding.line, 1),
                        "endLine": max(finding.end_line, finding.line, 1),
                        "startColumn": max(finding.column, 1),
                        "endColumn": max(finding.end_column, finding.column, 1),
                    },
                }
            }
        ],
        # partialFingerprints lets GitHub track "is this the same finding
        # across commits" independent of exact line number. GitHub's own
        # documentation uses "primaryLocationLineHash" as the conventional
        # key name for this purpose (combined internally with repo/path/
        # rule data) — we use that same key name so GitHub's matching
        # logic engages the way it does for CodeQL and other producers,
        # rather than inventing our own key that GitHub doesn't recognize.
        "partialFingerprints": {"primaryLocationLineHash": finding.dedup_key()},
        "properties": {
            "security-severity": _SECURITY_SEVERITY_SCORE.get(
                finding.severity.value, "5.0"
            ),
        },
    }

    if finding.matched_code:
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
            "text": finding.matched_code
        }

    if finding.fix_type.value != "none" and finding.suggested_fix:
        result["fixes"] = [
            {
                "description": {"text": f"Suggested fix ({finding.fix_type.value})"},
                "artifactChanges": [
                    {
                        "artifactLocation": {"uri": _normalize_path(finding.file_path)},
                        "replacements": [
                            {
                                "deletedRegion": {
                                    "startLine": finding.line,
                                    "endLine": finding.end_line,
                                },
                                "insertedContent": {"text": finding.suggested_fix},
                            }
                        ],
                    }
                ],
            }
        ]

    return result


def _normalize_path(file_path: str) -> str:
    """
    SARIF artifact URIs are conventionally forward-slash, repo-relative,
    with no leading slash. Path.as_posix() handles the Windows-backslash
    case if this ever runs on a Windows CI runner.
    """
    return Path(file_path).as_posix().lstrip("/")


def build_sarif(report: AggregatedReport, repo_uri: str | None = None) -> dict:
    """
    Builds the full SARIF document as a Python dict (caller decides whether
    to write it to disk via write_sarif_file, or use it directly e.g. for
    a test assertion).
    """
    rules = _build_rules_array(report.findings)
    rule_index_by_id = {rule["id"]: i for i, rule in enumerate(rules)}

    run: dict = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "organization": TOOL_ORGANIZATION,
                "informationUri": "https://github.com/yourorg/codescan",
                "version": "1.0.0",
                "rules": rules,
            }
        },
        "results": [_build_result(f, rule_index_by_id) for f in report.findings],
    }

    if repo_uri:
        run["originalUriBaseIds"] = {"SRCROOT": {"uri": repo_uri}}

    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def write_sarif_file(
    report: AggregatedReport, output_path: str, repo_uri: str | None = None
) -> None:
    """Builds the SARIF document and writes it to `output_path` as UTF-8 JSON."""
    sarif_doc = build_sarif(report, repo_uri=repo_uri)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
