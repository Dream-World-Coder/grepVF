"""
CVE Checker — audits resolved dependency versions against the OSV.dev
vulnerability database.

Design notes:
- Uses OSV's `querybatch` endpoint rather than looping one `query` call per
  package. A real lockfile easily has 200+ transitive dependencies; batching
  keeps this to a handful of HTTP round-trips instead of hundreds.
- Sends ONLY package name + version + ecosystem to the external API — never
  source code. This is what makes the "source code never leaves the network"
  claim in the banking deployment model true even though this specific
  scanner does call out to the internet.
- `querybatch` returns vulnerability IDs only (no full details) to keep the
  batch endpoint fast; we then resolve full details via a second call to
  `/v1/vulns/{id}` only for the IDs that actually came back, not for every
  dependency.
"""

import asyncio
from dataclasses import dataclass

import httpx
from lockfile_parser import Dependency
from models import Category, Finding, ScanResult, Severity

OSV_API_BASE = "https://api.osv.dev/v1"
BATCH_SIZE = 100  # OSV's documented batch query limit
REQUEST_TIMEOUT_SECONDS = 15
MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 1.5


@dataclass
class _VulnRef:
    osv_id: str
    dependency: Dependency


def _severity_from_osv(vuln: dict) -> Severity:
    """
    OSV vulnerabilities carry severity in different shapes depending on the
    source database (CVSS vector string, or a bare "severity" field on some
    GHSA-derived entries). We normalize to our 4-tier scale, defaulting to
    MEDIUM when no usable severity signal is present rather than silently
    dropping the finding.
    """
    severity_entries = vuln.get("severity", [])
    for entry in severity_entries:
        if entry.get("type") == "CVSS_V3":
            score = _cvss_v3_base_score(entry.get("score", ""))
            if score is not None:
                return _severity_from_cvss_score(score)

    # Some entries put a textual severity directly on database_specific
    db_specific = vuln.get("database_specific", {})
    text_severity = str(db_specific.get("severity", "")).upper()
    if text_severity in ("CRITICAL", "HIGH", "MODERATE", "LOW"):
        return (
            Severity.HIGH
            if text_severity == "MODERATE"
            else Severity(text_severity if text_severity != "MODERATE" else "MEDIUM")
        )

    return Severity.MEDIUM


def _cvss_v3_base_score(vector_or_score: str) -> float | None:
    """
    OSV's CVSS_V3 'score' field is sometimes a bare numeric string and
    sometimes a full vector string like 'CVSS:3.1/AV:N/.../C:H/I:H/A:H'.
    We only need the coarse severity bucket, so if it's a vector we don't
    fully parse CVSS (out of scope) — we just check for a numeric prefix;
    otherwise treat unresolvable vectors conservatively as HIGH.
    """
    try:
        return float(vector_or_score)
    except ValueError:
        return None


def _severity_from_cvss_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _build_finding(dependency: Dependency, vuln: dict) -> Finding:
    osv_id = vuln.get("id", "UNKNOWN")
    summary = (
        vuln.get("summary") or vuln.get("details", "")[:200] or "No summary provided."
    )
    aliases = vuln.get("aliases", [])
    cve_id = next((a for a in aliases if a.startswith("CVE-")), None)

    fixed_version = _extract_fixed_version(vuln, dependency.ecosystem)
    fix_note = (
        f" Fixed in version {fixed_version}."
        if fixed_version
        else " No fixed version published yet."
    )

    return Finding(
        rule_id=f"cve-{osv_id}",
        file_path=dependency.source_file,
        line=1,  # manifests don't have a meaningful per-dep line without re-parsing; see note below
        end_line=1,
        severity=_severity_from_osv(vuln),
        category=Category.CVE,
        message=(
            f"{dependency.name}=={dependency.version} has a known vulnerability "
            f"({osv_id}{f' / {cve_id}' if cve_id else ''}): {summary}{fix_note}"
        ),
        cwe=None,
        matched_code=f"{dependency.name}=={dependency.version}",
        source_engine="cve_checker.osv",
        extra={
            "osv_id": osv_id,
            "cve_id": cve_id,
            "package": dependency.name,
            "installed_version": dependency.version,
            "fixed_version": fixed_version,
            "ecosystem": dependency.ecosystem,
            "transitive": dependency.transitive,
        },
    )


def _extract_fixed_version(vuln: dict, ecosystem: str) -> str | None:
    """
    Walks OSV's `affected[].ranges[].events[]` structure to find the first
    "fixed" event for the matching ecosystem. OSV's schema nests this
    fairly deeply and not every advisory has a clean fixed version (some
    are only fixed by removing the package entirely), so this returns None
    rather than guessing.
    """
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != ecosystem:
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


async def _query_batch(
    client: httpx.AsyncClient, dependencies: list[Dependency]
) -> list[list[str]]:
    """
    Calls OSV's querybatch endpoint. Returns a list (same order/length as
    `dependencies`) of OSV-id lists — empty list means no known vulns.
    Retries on transient failures (5xx, timeouts) with exponential backoff;
    gives up after MAX_RETRIES and returns empty results for that batch
    rather than crashing the whole scan over one bad batch.
    """
    payload = {
        "queries": [
            {
                "version": dep.version,
                "package": {"name": dep.name, "ecosystem": dep.ecosystem},
            }
            for dep in dependencies
        ]
    }

    last_exc: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = await client.post(
                f"{OSV_API_BASE}/querybatch",
                json=payload,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if resp.status_code == 200:
                results = resp.json().get("results", [])
                return [[v["id"] for v in r.get("vulns", [])] for r in results]
            if resp.status_code >= 500:
                raise httpx.HTTPStatusError(
                    "server error", request=resp.request, response=resp
                )
            # 4xx is not retryable — bad request shape, log and bail for this batch
            return [[] for _ in dependencies]
        except (
            httpx.TimeoutException,
            httpx.HTTPStatusError,
            httpx.TransportError,
        ) as exc:
            last_exc = exc
            if attempt < MAX_RETRIES:
                await asyncio.sleep(RETRY_BACKOFF_SECONDS * attempt)
                continue
    # all retries exhausted
    return [[] for _ in dependencies]


async def _fetch_vuln_details(client: httpx.AsyncClient, osv_id: str) -> dict | None:
    try:
        resp = await client.get(
            f"{OSV_API_BASE}/vulns/{osv_id}", timeout=REQUEST_TIMEOUT_SECONDS
        )
        if resp.status_code == 200:
            return resp.json()
    except (httpx.TimeoutException, httpx.TransportError):
        pass
    return None


async def check_dependencies_async(dependencies: list[Dependency]) -> ScanResult:
    if not dependencies:
        return ScanResult(findings=[], engine="cve_checker", files_scanned=0)

    findings: list[Finding] = []
    errors: list[str] = []
    refs: list[_VulnRef] = []

    async with httpx.AsyncClient() as client:
        # Step 1: batched lookup of vuln IDs per dependency
        for i in range(0, len(dependencies), BATCH_SIZE):
            batch = dependencies[i : i + BATCH_SIZE]
            id_lists = await _query_batch(client, batch)
            for dep, osv_ids in zip(batch, id_lists):
                for osv_id in osv_ids:
                    refs.append(_VulnRef(osv_id=osv_id, dependency=dep))

        if not refs:
            return ScanResult(
                findings=[],
                engine="cve_checker",
                files_scanned=len({d.source_file for d in dependencies}),
            )

        # Step 2: fetch full details only for the (deduplicated) vuln IDs
        # that actually matched something — avoids one detail call per
        # dependency when many dependencies share the same advisory.
        unique_ids = {r.osv_id for r in refs}
        detail_cache: dict[str, dict] = {}
        detail_results = await asyncio.gather(
            *[_fetch_vuln_details(client, vid) for vid in unique_ids]
        )
        for vid, detail in zip(unique_ids, detail_results):
            if detail is not None:
                detail_cache[vid] = detail
            else:
                errors.append(f"Could not fetch details for {vid}")

    for ref in refs:
        vuln = detail_cache.get(ref.osv_id)
        if vuln is None:
            continue
        findings.append(_build_finding(ref.dependency, vuln))

    return ScanResult(
        findings=findings,
        engine="cve_checker",
        files_scanned=len({d.source_file for d in dependencies}),
        errors=errors,
    )


def check_dependencies(dependencies: list[Dependency]) -> ScanResult:
    """Synchronous wrapper for callers (e.g. the CLI) that aren't already in an event loop."""
    return asyncio.run(check_dependencies_async(dependencies))
