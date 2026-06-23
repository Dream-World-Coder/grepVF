# Codescan Module Documentation

This directory contains the core vulnerability scanners. They are designed to run concurrently.

## Entropy Checker

Detects hardcoded secrets via two complementary methods:

1. Regex matching against known credential *shapes* (AWS keys, Stripe keys, JWTs, generic `api_key = "..."` assignments). High precision, but only catches secret formats we've explicitly enumerated.
2. Shannon-entropy scanning over string literals as a catch-all for secrets that don't match any known shape (custom internal tokens, random API keys with no recognizable prefix).

Running only regex misses novel secret formats; running only entropy produces too many false positives on things like UUIDs, hashes, and base64 config blobs. Combining both, with regex matches taking priority and entropy only flagged at MEDIUM severity, is the standard approach used by tools like GitLeaks and TruffleHog.

## CVE Checker

Audits resolved dependency versions against the OSV.dev vulnerability database.

**Design notes**:
- Uses OSV's `querybatch` endpoint rather than looping one `query` call per package. A real lockfile easily has 200+ transitive dependencies; batching keeps this to a handful of HTTP round-trips instead of hundreds.
- Sends ONLY package name + version + ecosystem to the external API — never source code. This is what makes the "source code never leaves the network" claim in the banking deployment model true even though this specific scanner does call out to the internet.
- `querybatch` returns vulnerability IDs only (no full details) to keep the batch endpoint fast; we then resolve full details via a second call to `/v1/vulns/{id}` only for the IDs that actually came back, not for every dependency.

## Semantics Checker

Wraps Semgrep to run AST-aware, taint-tracking analysis across the code queue using our custom rule registry (`scanner/rules/`).

Two things this module does beyond "shell out to semgrep":

1. Normalizes Semgrep's JSON output into our shared `Finding` model so the aggregator never needs to know which engine produced a finding.
2. Runs a small set of "structural absence" checks directly in Python instead of via Semgrep. Semgrep's pattern language is built to match the *presence* of a pattern; checks like "this Dockerfile has no USER directive anywhere" are absence-based and are fragile/unreliable to express as a Semgrep pattern. Splitting these into a dedicated Python pass is more maintainable than fighting the rule grammar.
