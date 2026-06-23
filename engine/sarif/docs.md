# SARIF Module Documentation

This module serializes an `AggregatedReport` into SARIF 2.1.0, the format `github/codeql-action/upload-sarif` consumes to populate the native GitHub Security tab and inline PR annotations under "Files changed."

Spec reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

## Key Structural Decisions

- **One `rule` entry per unique rule_id**: Deduplicated, with the rule's description/help text attached once — not repeated on every result. This is what makes the Security tab's per-rule grouping and the rule detail panel work correctly.
- **`partialFingerprints`**: Set on every result using `Finding.dedup_key()`. This is what lets GitHub recognize "this is the same finding as last scan" across commits even when line numbers shift slightly, so a finding doesn't get marked as newly-introduced on every push just because an unrelated earlier line in the file changed.
- **Severity mapping**: Goes through `Severity.sarif_level` (CRITICAL/HIGH -> "error", MEDIUM -> "warning", LOW -> "note") since SARIF's `level` field only has those three meaningful values for results.
- **`security-severity`**: (a `properties` bag entry, not part of core SARIF) is what GitHub's Security tab actually uses to color-code and sort by severity in its UI — this is a de facto GitHub extension, not core SARIF, but omitting it means everything shows up uncategorized in the tab.
- **CWE Association**: The `external/cwe/cwe-NNN` tag convention is what GitHub's own Security tab and most third-party SARIF producers (Checkov, KICS) actually use for CWE association in practice, so we stick to that simpler, schema-valid approach rather than a half-implemented taxonomy.
