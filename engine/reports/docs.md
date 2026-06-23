# Reports Module Documentation

This module merges the three independent finding streams (entropy, CVE, semantics) into a single deduplicated, hazard-ranked vulnerability manifest.

## Responsibilities

1. **Deduplication.** The same underlying issue can surface from more than one engine — e.g. a hardcoded hex secret triggers both `generic-hardcoded-credential` (regex) and `hardcoded-hex-secret` (also regex) on the same line, or in principle a Semgrep rule and the entropy checker could both flag the same line. We don't want a developer to see the same vulnerability reported twice with two different rule IDs.
   Dedup here intentionally keeps the HIGHER-severity finding when two findings collide on file+line, on the theory that a more specific rule firing alongside a generic catch-all should win, and the generic one is noise once the specific one is present.

2. **Hazard scoring.** Severity alone (CRITICAL/HIGH/MEDIUM/LOW) is a coarse 4-bucket scale. The hazard score is a continuous 0-10 value that breaks ties within a severity bucket using exploitability signals — currently:
   - whether the data-flow into the vulnerable sink was taint-confirmed (rather than just a structural pattern match)
   - whether the finding sits in a file that looks internet-facing (e.g. a web framework route handler vs. an offline batch script).
   This produces a stable ranking for "which CRITICAL finding do we show first."
