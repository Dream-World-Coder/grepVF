"""
Semantics Checker — wraps Semgrep to run AST-aware, taint-tracking analysis.
See `engine/codescan/docs.md` for normalization and structural-absence checks.
"""

import json
import subprocess
from pathlib import Path

from engine.models import Category, Finding, ScanResult, Severity

RULES_DIR = Path(__file__).parent / "rules"
SEMGREP_TIMEOUT_SECONDS = 300

_SEMGREP_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

# metadata.category strings (as set in our rule YAMLs) -> our Category enum
_CATEGORY_MAP = {
    "weak_crypto": Category.WEAK_CRYPTO,
    "tls": Category.TLS,
    "injection": Category.INJECTION,
    "misconfiguration": Category.MISCONFIGURATION,
    "auth": Category.AUTH,
    "supply_chain": Category.SUPPLY_CHAIN,
}


def _severity_override_from_metadata(metadata: dict, fallback: Severity) -> Severity:
    """
    Our rules optionally carry a 0-10 `hazard_point` in metadata, which is a
    finer-grained signal than Semgrep's 3-tier ERROR/WARNING/INFO severity.
    When present, map it to our 4-tier scale so a hazard_point=9 finding
    (e.g. eval-on-input) is correctly CRITICAL even though Semgrep only
    has an ERROR bucket to put it in.
    """
    hazard_point = metadata.get("hazard_point")
    if hazard_point is None:
        return fallback
    try:
        hp = float(hazard_point)
    except (TypeError, ValueError):
        return fallback
    if hp >= 9.0:
        return Severity.CRITICAL
    if hp >= 7.0:
        return Severity.HIGH
    if hp >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def run_semgrep_scoped(
    target_paths: list[str],
    repo_root: str,
    rule_files: list[str] | None = None,
) -> dict:
    """
    Invokes the semgrep CLI as a subprocess with an explicit list of rule
    files (or the full RULES_DIR when none are specified).

    This is the canonical subprocess invocation used by both:
      - `run_semantics_checker` (full ruleset, all code files)
      - `taint_verifier.verify` (single rule file, single candidate file)

    Using the CLI rather than semgrep's internal Python API is intentional:
    the CLI's --json output is a stable, documented contract, whereas
    semgrep's internal Python modules are not a supported public API and
    change between versions.

    --quiet suppresses the human-readable status panel that would otherwise
    interleave with --json output on stdout (discovered the hard way —
    without it, `json.loads()` on stdout fails).

    Parameters
    ----------
    target_paths : list[str]
        File paths to scan (absolute or repo-relative).
    repo_root : str
        Working directory for the semgrep subprocess.
    rule_files : list[str] | None
        Explicit list of rule file paths. When None, defaults to the full
        RULES_DIR (same behaviour as before the refactor).
    """
    config_args = []
    for cfg in rule_files or [str(RULES_DIR)]:
        config_args += ["--config", cfg]

    cmd = [
        "semgrep",
        *config_args,
        "--json",
        "--quiet",
        "--no-git-ignore",  # benchmark/test repos may not be git repos
        "--disable-version-check",
        "--metrics",
        "off",  # don't phone home telemetry during scans
        *target_paths,
    ]

    try:
        proc = subprocess.run(
            cmd,
            cwd=repo_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=SEMGREP_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return {"results": [], "errors": [{"message": "semgrep timed out"}]}
    except FileNotFoundError:
        return {
            "results": [],
            "errors": [{"message": "semgrep executable not found on PATH"}],
        }

    stdout = proc.stdout or ""
    if not stdout.strip():
        return {
            "results": [],
            "errors": [{"message": proc.stderr or "semgrep produced no output"}],
        }

    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        return {
            "results": [],
            "errors": [{"message": f"failed to parse semgrep output: {exc}"}],
        }


# Keep a private alias so callers within this module use the same function.
_run_semgrep = run_semgrep_scoped


def _finding_from_semgrep_result(result: dict, repo_root: str) -> Finding:
    check_id = result["check_id"].split(".")[-1]  # strip "scanner.rules." prefix
    metadata = result.get("extra", {}).get("metadata", {})
    base_severity = _SEMGREP_SEVERITY_MAP.get(
        result.get("extra", {}).get("severity", "WARNING"), Severity.MEDIUM
    )
    severity = _severity_override_from_metadata(metadata, base_severity)
    category = _CATEGORY_MAP.get(metadata.get("category"), Category.OTHER)

    start = result.get("start", {})
    end = result.get("end", {})

    # IMPORTANT: do NOT use extra["lines"] here. Semgrep's OSS CLI returns
    # the literal placeholder string "requires login" for both
    # extra["lines"] and extra["fingerprint"] when not authenticated to the
    # Semgrep AppSec Platform — this is gated premium output, not a code
    # snippet. Discovered by inspecting raw CLI output directly; trusting
    # this field silently corrupted every matched_code value with a
    # nonsensical placeholder. We read the actual line straight from the
    # source file instead, using the line number Semgrep does give us
    # unconditionally.
    matched_code = _read_source_line(repo_root, result["path"], start.get("line", 1))

    return Finding(
        rule_id=check_id,
        file_path=result["path"],
        line=start.get("line", 1),
        end_line=end.get("line", start.get("line", 1)),
        column=start.get("col", 1),
        end_column=end.get("col", 1),
        severity=severity,
        category=category,
        message=result.get("extra", {}).get("message", "").strip(),
        cwe=metadata.get("cwe"),
        matched_code=matched_code,
        source_engine="semgrep",
        extra={"references": metadata.get("references", [])},
    )


def _read_source_line(repo_root: str, rel_path: str, line_no: int) -> str | None:
    """Reads a single 1-indexed line directly from disk for use as matched_code."""
    try:
        abs_path = Path(repo_root) / rel_path
        lines = abs_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()
    return None


def _check_dockerfile_missing_user(
    repo_root: str, dockerfile_paths: list[str]
) -> list[Finding]:
    """
    Python-side absence check: flags any Dockerfile that defines a CMD or
    ENTRYPOINT but never has a USER directive switching away from root.
    This is intentionally NOT a Semgrep rule — see module docstring.
    """
    findings: list[Finding] = []
    for rel_path in dockerfile_paths:
        abs_path = Path(repo_root) / rel_path
        try:
            lines = abs_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        has_user = any(line.strip().upper().startswith("USER ") for line in lines)
        has_entrypoint_or_cmd = any(
            line.strip().upper().startswith(("CMD ", "CMD[", "ENTRYPOINT "))
            for line in lines
        )

        if has_entrypoint_or_cmd and not has_user:
            # report on the last line as a reasonable anchor point
            findings.append(
                Finding(
                    rule_id="dockerfile-missing-user-directive",
                    file_path=rel_path,
                    line=len(lines),
                    end_line=len(lines),
                    severity=Severity.MEDIUM,
                    category=Category.MISCONFIGURATION,
                    message=(
                        "This Dockerfile has no USER directive, so the container runs as root "
                        "by default. Add a non-root USER directive before the final CMD/ENTRYPOINT."
                    ),
                    cwe="CWE-250",
                    source_engine="semantics_checker.dockerfile_absence_check",
                )
            )
    return findings


def _is_dockerfile(rel_path: str) -> bool:
    name = Path(rel_path).name
    return (
        name == "Dockerfile"
        or name.startswith("Dockerfile.")
        or name.endswith(".dockerfile")
    )


def run_semantics_checker(repo_root: str, code_paths: list[str]) -> ScanResult:
    """
    Entry point called by the orchestrator with the "code" queue produced
    by file_router.route_files(). Runs Semgrep across all files at once
    (much faster than per-file invocation — Semgrep batches its own
    internal parallelism) and supplements with Python-side absence checks.
    """
    if not code_paths:
        return ScanResult(findings=[], engine="semantics_checker", files_scanned=0)

    errors: list[str] = []
    findings: list[Finding] = []

    raw = run_semgrep_scoped(code_paths, repo_root)
    for err in raw.get("errors", []):
        msg = (
            err.get("message")
            or err.get("long_msg")
            or err.get("short_msg")
            or str(err)
        )
        errors.append(msg)

    for result in raw.get("results", []):
        try:
            findings.append(_finding_from_semgrep_result(result, repo_root))
        except (KeyError, TypeError) as exc:
            errors.append(f"malformed semgrep result skipped: {exc}")

    dockerfile_paths = [p for p in code_paths if _is_dockerfile(p)]
    findings.extend(_check_dockerfile_missing_user(repo_root, dockerfile_paths))

    return ScanResult(
        findings=findings,
        engine="semantics_checker",
        files_scanned=len(code_paths),
        errors=errors,
    )
