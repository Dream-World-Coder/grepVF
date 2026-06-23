# Core Module Documentation

This module (`engine.core.py`) contains the primary entry point `GrepVF` that orchestrates the entire scan pipeline.

## Pipeline Order

1. **File routing**: `engine.filescan.scanner.scan_files`
   - Classifies files into `RoutedFiles` (secrets | manifests | code).
2. **Manifest parse**: `engine.codescan.lockfile_parser.parse_all_manifests`
   - Produces a `list[Dependency]` (prerequisite for the CVE scanner).
3. **Three concurrent scanners**:
   - `entropy_checker`: regex + Shannon entropy (sync → thread pool)
   - `cve_checker`: OSV.dev querybatch (native async / httpx)
   - `semantics_checker`: Semgrep subprocess (sync → thread pool)
4. **Aggregation**: `engine.reports.final.aggregate`
   - Handles deduplication and hazard-ranking of findings.
5. **Patch generation**: `engine.patcher.patch_generator` (opt-in, if `patch=True`)

## Public API

```python
# sync (CLI, tests)
engine = GrepVF("/path/to/repo")
report = engine.run_scan(patch=True)

# async (FastAPI webhook handler, Celery task, …)
engine = GrepVF(repo_root)
report = await engine.run_scan_async(patch=True)

# routing-only introspection
engine.run_file_scan()

# CI gate
if engine.has_blocking_criticals():
    sys.exit(1)
```

## Design Notes

- **Concurrency**: `entropy_checker` and `semantics_checker` are both synchronous (file I/O and a Semgrep subprocess respectively). They are dispatched to the default `ThreadPoolExecutor` via `loop.run_in_executor` so they run concurrently with the CVE checker's async HTTP round-trips to OSV.dev without blocking the event loop.
- **Ordering**: `asyncio.gather` preserves return order, so `_apply_patch_outcomes` can safely `zip(findings, outcomes)` rather than doing an identity-based lookup.
- **State management**: Scan state (`files`, `scan_results`, `report`, `patch_outcomes`) is stored on the instance so callers can inspect intermediate results after the scan, e.g., `engine.scan_results["entropy"].errors` for diagnostics.
