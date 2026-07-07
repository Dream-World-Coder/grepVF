"""
main.py —:- GrepVF CLI entry point.

Usage
-----
    # full scan, no patches
    python main.py /path/to/repo

    # full scan + auto-patch generation
    python main.py /path/to/repo --patch

    # routing dry-run only (no vulnerability scanning)
    python main.py /path/to/repo --route-only

    # write JSON report to a file
    python main.py /path/to/repo --output report.json

    # exit with code 1 if any CRITICAL findings exist (CI gate)
    python main.py /path/to/repo --ci

    # combine: patch + CI gate + write report
    python main.py /path/to/repo --patch --ci --output report.json

    # container / GitHub Action mode: write findings.json + report.sarif
    # into a directory (used as the Docker ENTRYPOINT by the codescan-action
    # composite action — see action.yml in codescan-action/)
    python main.py --repo /workspace --out /workspace/.codescan \
        --repo-uri "https://github.com/owner/repo" --patch

Exit codes
----------
    0   scan completed, no CRITICAL findings (or --ci not passed)
    1   CRITICAL finding(s) found and --ci flag was set
    2   bad arguments / target path doesn't exist

Note on --out vs --ci: when invoked via --out (container mode), this CLI
deliberately always exits 0 regardless of findings — even if --ci is also
passed. The pass/fail decision for the PR check is made by
codescan-action's evaluate_gate.py, which reads findings.json against the
repo's configured threshold. This keeps "the scan ran successfully" and
"the scan found something that should block the PR" as two independent
signals — a transient OSV.dev network blip becomes a visible warning in
the step output, not a false "no vulnerabilities found."
"""

import argparse
import json
import sys
from pathlib import Path

from engine import GrepVF
from engine.sarif.writer import write_sarif_file


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="GrepVF",
        description="GrepVF — static analysis engine for open-source dependency misconfigurations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "repo_positional",
        metavar="REPO_PATH",
        nargs="?",
        default=None,
        help="Absolute or relative path to the repository root to scan. "
        "May also be given as --repo.",
    )
    p.add_argument(
        "--repo",
        dest="repo_flag",
        metavar="REPO_PATH",
        default=None,
        help="Same as the positional REPO_PATH argument; provided as a flag "
        "for callers (e.g. the Docker ENTRYPOINT) that always pass named args.",
    )
    p.add_argument(
        "--patch",
        action="store_true",
        default=False,
        help="Attempt deterministic + LLM-assisted patch generation for each finding.",
    )
    p.add_argument(
        "--route-only",
        action="store_true",
        default=False,
        help="Run file routing only — print queue sizes without scanning for vulnerabilities.",
    )
    p.add_argument(
        "--ci",
        action="store_true",
        default=False,
        help="Exit with code 1 if any unresolved CRITICAL findings are present (CI gate mode). "
        "Ignored when --out is set — see the note above.",
    )
    p.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Write the aggregated JSON report to FILE (default: stdout only).",
    )
    p.add_argument(
        "--out",
        metavar="DIR",
        default=None,
        help="Container/CI mode: write findings.json and report.sarif into DIR "
        "(created if missing). This is what the codescan-action composite "
        "action expects the engine image to produce.",
    )
    p.add_argument(
        "--repo-uri",
        metavar="URI",
        default=None,
        help="Repository URI (e.g. https://github.com/owner/repo) embedded in the "
        "SARIF output's originalUriBaseIds, so GitHub's Security tab can resolve "
        "file paths. Only used when --out is set.",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help="Suppress all informational output; only errors and the final JSON report are printed.",
    )
    p.add_argument(
        "--zone-detect",
        action="store_true",
        default=False,
        help="Enable ZoneScan: a retrieval+verification layer that flags code semantically similar "
        "to known-vulnerable CWE patterns, then uses scoped Semgrep taint analysis to confirm. "
        "Requires 'transformers' and 'torch' to be installed. Off by default until M2 artifacts "
        "are available — use the built-in M1 zero-shot centroid for initial testing.",
    )
    p.add_argument(
        "--zone-index",
        metavar="PATH",
        default=None,
        help="Path to a pre-built CWE index directory (centroids.json + cwe_index.faiss). "
        "Only used when --zone-detect is set. Omit to use the built-in M1 zero-shot centroid.",
    )
    return p


def _validate_repo_path(raw: str) -> Path:
    path = Path(raw).resolve()
    if not path.exists():
        print(f"[ERROR] Path does not exist: {path}", file=sys.stderr)
        sys.exit(2)
    if not path.is_dir():
        print(f"[ERROR] Path is not a directory: {path}", file=sys.stderr)
        sys.exit(2)
    return path


def _print_findings_table(report) -> None:
    """Prints a compact, human-readable findings table to stdout."""
    if not report.findings:
        print("\n✓ No findings.\n")
        return

    print(f"\n{'─' * 80}")
    print(f"  {'SEV':<10} {'RULE':<40} {'FILE:LINE'}")
    print(f"{'─' * 80}")
    for f in report.findings:
        loc = f"{f.file_path}:{f.line}"
        sev_label = f.severity.value
        print(f"  {sev_label:<10} {f.rule_id:<40} {loc}")
        if f.message:
            # wrap message at 76 chars for readability
            msg = f.message if len(f.message) <= 76 else f.message[:73] + "..."
            print(f"  {'':10} {msg}")
        if f.suggested_fix and f.fix_validated:
            print(f"  {'':10} ✓ Patch available ({f.fix_type.value})")
        print()
    print(f"{'─' * 80}\n")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    container_mode = args.out is not None

    repo_arg = args.repo_flag or args.repo_positional
    if not repo_arg:
        print(
            "[ERROR] No repository path given. Pass it positionally or via --repo.",
            file=sys.stderr,
        )
        return 2

    repo_path = _validate_repo_path(repo_arg)

    # Redirect stdout to /dev/null when --quiet; stderr still gets errors.
    if args.quiet:
        import os

        sys.stdout = open(os.devnull, "w")

    try:
        engine = GrepVF(str(repo_path))
    except (ValueError, FileNotFoundError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    # ── routing-only mode
    if args.route_only:
        files = engine.run_file_scan()
        summary = {
            "secrets": files.secrets,
            "manifests": files.manifests,
            "code": files.code,
            "skipped_binary": files.skipped_binary,
            "skipped_too_large": files.skipped_too_large,
            "total_routed": files.total_routed,
        }
        if args.output:
            Path(args.output).write_text(
                json.dumps(summary, indent=2), encoding="utf-8"
            )
            print(f"[GrepVF] Route map written to {args.output}")
        else:
            print(json.dumps(summary, indent=2))
        return 0

    # ── full scan
    try:
        report = engine.run_scan(
            patch=args.patch,
            zone_detect=args.zone_detect,
            zone_index_path=args.zone_index,
        )
    except Exception as exc:
        # Surface unexpected scan errors without a traceback wall. In
        # container mode this is intentionally non-fatal to the exit code
        # (see module docstring) — we still try to write an empty-findings
        # report so the action's downstream steps have a file to read
        # rather than failing the whole job on a scan-level hiccup.
        print(f"[ERROR] Scan failed: {exc}", file=sys.stderr)
        if not container_mode:
            return 2
        report = None

    # Restore stdout if we silenced it, so the table/JSON still reaches the user.
    if args.quiet:
        sys.stdout = sys.__stdout__

    if report is not None:
        _print_findings_table(report)
        report_dict = report.to_dict()
    else:
        report_dict = {
            "summary": {
                "total_findings": 0,
                "duplicates_removed": 0,
                "by_severity": {},
            },
            "findings": [],
        }

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(report_dict, indent=2), encoding="utf-8")
        print(f"[GrepVF] Report written to {args.output}")
    elif not container_mode:
        print(json.dumps(report_dict, indent=2))

    # ── container / CI Action mode: write findings.json + report.sarif
    if container_mode:
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)

        findings_path = out_dir / "findings.json"
        findings_path.write_text(json.dumps(report_dict, indent=2), encoding="utf-8")
        print(f"[GrepVF] findings.json written to {findings_path}")

        sarif_path = out_dir / "report.sarif"
        if report is not None:
            write_sarif_file(report, str(sarif_path), repo_uri=args.repo_uri)
        else:
            # Scan failed entirely — still emit a structurally valid, empty
            # SARIF run rather than leaving the upload-sarif step with a
            # missing file.
            from engine.reports.final import aggregate

            write_sarif_file(
                aggregate([[], [], []]), str(sarif_path), repo_uri=args.repo_uri
            )
        print(f"[GrepVF] report.sarif written to {sarif_path}")

        # Container always exits 0 here — see module docstring. The PR
        # gate decision is made downstream by evaluate_gate.py.
        return 0

    # ── CI gate (non-container CLI usage only)
    if args.ci and engine.has_blocking_criticals():
        print(
            "\n[GrepVF] ✗ CRITICAL findings detected — blocking PR merge.\n",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
