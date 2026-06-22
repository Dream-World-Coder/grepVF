"""
main.py — GrepVF CLI entry point.

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

Exit codes
----------
    0   scan completed, no CRITICAL findings (or --ci not passed)
    1   CRITICAL finding(s) found and --ci flag was set
    2   bad arguments / target path doesn't exist
"""

import argparse
import json
import sys
from pathlib import Path

from engine import GrepVF


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="GrepVF",
        description="GrepVF — static analysis engine for open-source dependency misconfigurations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "repo",
        metavar="REPO_PATH",
        help="Absolute or relative path to the repository root to scan.",
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
        help="Exit with code 1 if any unresolved CRITICAL findings are present (CI gate mode).",
    )
    p.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Write the aggregated JSON report to FILE (default: stdout only).",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help="Suppress all informational output; only errors and the final JSON report are printed.",
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

    repo_path = _validate_repo_path(args.repo)

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
            Path(args.output).write_text(json.dumps(summary, indent=2))
            print(f"[GrepVF] Route map written to {args.output}")
        else:
            print(json.dumps(summary, indent=2))
        return 0

    # ── full scan
    try:
        report = engine.run_scan(patch=args.patch)
    except Exception as exc:
        # Surface unexpected scan errors without a traceback wall
        print(f"[ERROR] Scan failed: {exc}", file=sys.stderr)
        return 2

    # Restore stdout if we silenced it, so the table/JSON still reaches the user.
    if args.quiet:
        sys.stdout = sys.__stdout__

    _print_findings_table(report)

    report_dict = report.to_dict()

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(report_dict, indent=2))
        print(f"[GrepVF] Report written to {args.output}")
    else:
        print(json.dumps(report_dict, indent=2))

    # ── CI gate
    if args.ci and engine.has_blocking_criticals():
        print(
            "\n[GrepVF] ✗ CRITICAL findings detected — blocking PR merge.\n",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
