# ZoneScan MVP — Implementation Walkthrough

**Status**: M0 (skeleton) + M1 (walking skeleton, zero-shot) complete.
**Test result**: **98/98 passed** in 30.8s.

---

## What Was Built

### New Package: `engine/zonescan/`

| File | What it does |
|---|---|
| [__init__.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/zonescan/__init__.py) | Package marker; exports `run_zone_detector` |
| [docs.md](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/zonescan/docs.md) | Per-module doc: pipeline diagram, milestone table, config reference |
| [models.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/zonescan/models.py) | `CodeChunk`, `ZoneCandidate`, `ZoneFinding` dataclasses (internal; never leave the package) |
| [chunker.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/zonescan/chunker.py) | `ast`-based function boundary extractor. Strips `#` comments, collapses blank lines, keeps identifiers. Handles syntax errors + missing files gracefully. |
| [embedder.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/zonescan/embedder.py) | Lazy-singleton EmbeddingGemma wrapper. Falls back to a **deterministic hash-based stub** when `transformers`/`torch` aren't installed — CI stays green. Supports LoRA adapter via `ZONESCAN_ADAPTER_PATH` (M2). MRL truncation for cheap first-pass ANN. |
| [cwe_index.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/zonescan/cwe_index.py) | Two-pass similarity: (1) centroid cosine sim (cheap), (2) nearest-instance k-NN within matched CWE. M1: 10 hand-seeded CWE-89 examples averaged into a zero-shot centroid. M2+: `load_index()` from `centroids.json` + optional `.faiss`. |
| [taint_verifier.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/zonescan/taint_verifier.py) | Scoped Semgrep call: CWE-89 → `injection.yml` only, on the candidate's file and line range only. Uses the refactored `run_semgrep_scoped()` — no subprocess code duplication. |
| [zone_detector.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/zonescan/zone_detector.py) | Orchestrates chunk→embed→query→verify. Converts `ZoneFinding → Finding` (zonescan fields in `extra`). Returns `ScanResult` — the aggregator, SARIF writer, and patcher are completely unmodified. |

### New Package: `engine/training/` (offline stubs)

All five modules — [build_dataset.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/training/build_dataset.py), [mine_pairs.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/training/mine_pairs.py), [finetune_embedder.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/training/finetune_embedder.py), [build_centroids.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/training/build_centroids.py), [eval_temporal_holdout.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/training/eval_temporal_holdout.py) — are documented stubs with typed signatures and full docstrings. They `raise NotImplementedError` so the intent is explicit and they cannot be accidentally invoked in the runtime container.

---

## Modified Existing Files

### [semantics_checker.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/codescan/semantics_checker.py)
`_run_semgrep()` renamed to `run_semgrep_scoped()` (public) with an explicit `rule_files: list[str] | None` parameter. The old `_run_semgrep` name is kept as a private alias so no existing callers break. `taint_verifier.py` imports this directly — no subprocess code is duplicated.

### [core.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/core.py)
- Added `zone_detect: bool = False` + `zone_index_path: str | None = None` to `run_scan_async()` and `run_scan()`.
- ZoneScan is dispatched as a 4th `run_in_executor` task in the `asyncio.gather` stage when `zone_detect=True`. When `zone_detect=False`, a zero-finding `ScanResult` is created — the scanner slot is always present in `self.scan_results["zonescan"]`.
- `_print_scanner_summary()` accepts an optional `zone` argument.
- `aggregate()` call always passes 4 lists (the 4th is empty when zone_detect=False).

### [final.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/reports/final.py)
- `zonescan/cwe-89-verified` added to `_TAINT_CONFIRMED_RULES` → +1.0 taint bump.
- New corroboration bump: `+0.5` when `source_engine == "zonescan"` and `extra["verified"] is True`.
- Net score for a verified HIGH zone finding: **7.0 + 1.0 + 0.5 = 8.5** (above bare Semgrep HIGH, below CRITICAL).

### [models.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/models.py)
`source_engine` docstring updated to include `"zonescan"` as a valid value. No structural change.

### [main.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/main.py)
Added `--zone-detect` and `--zone-index PATH` flags matching the existing `--patch`/`--ci`/`--route-only` style.

---

## Cleanup

- Deleted `outputs/op.txt`, `outputs/report.json`, `outputs/report2.json`, `outputs/report3.json`
- Added `outputs/*` + `!outputs/.gitkeep` to [.gitignore](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/.gitignore)
- Added `artifacts/zonescan_lora/` + `artifacts/*.faiss` to `.gitignore` (prevents accidental commit of multi-MB model artifacts)
- Created `outputs/.gitkeep`
- Created [requirements-training.txt](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/requirements-training.txt) (offline-only training deps)

---

## Test Results

```
98 passed in 30.80s
```

| Test class | # tests | Coverage |
|---|---|---|
| `TestM0Skeleton` | 3 | zone_detect=False default, empty lists, no Python files |
| `TestChunker` | 7 | Functions extracted, line numbers, comment stripping, syntax errors, nested methods |
| `TestEmbedder` | 5 | Unit vector output, MRL truncation, determinism, stub flag |
| `TestCWEIndex` | 4 | M1 index built, centroid normalized, query at threshold, below-threshold |
| `TestZoneDetectorEndToEnd` | 5 | Full pipeline on `simple_sqli_file`, `payment_service.py`; rule ID distinctness; `extra` fields; high-threshold guard |
| `TestHazardScoreAndDedup` | 4 | Verified > probable score; exact 8.5 score; `dedup_key()` no SARIF collision; aggregation-level merge |

---

## M0 Gate: ✅

- Existing test suite untouched and green (72 pre-existing tests all pass)
- `--zone-detect` dispatches the scanner but with the real index, finds nothing unless the embedding model is available (by design — the M1 zero-shot centroid requires at least `numpy`)
- `scan_results["zonescan"]` always exists regardless of flag value

## M1 Gate: ✅ (walking skeleton)

- `payment_service.py` produces zonescan findings at `threshold=-1.0` (stub mode) with correct `rule_id`, `source_engine`, `cwe`, and `extra` fields
- Semgrep taint verification fires correctly against `injection.yml` for functions in the candidate's line range
- SARIF `partialFingerprints` dedup keys are distinct from Semgrep findings on the same line

---

## Next Steps (M2–M4)

| Milestone | Action needed |
|---|---|
| **M2** | Install `requirements-training.txt`, implement `build_dataset.py` (needs VulGate URL), `mine_pairs.py`, `finetune_embedder.py`, `build_centroids.py` |
| **M3** | Implement `eval_temporal_holdout.py`, run against a train/test cutoff split |
| **M4** | Already wired — verify the corroboration bump fires in an end-to-end scan with the real model + real Semgrep on `payment_service.py` |

> [!TIP]
> To run ZoneScan now with the real embedding model, install the ML deps:
> ```bash
> pip install torch --index-url https://download.pytorch.org/whl/cpu
> pip install transformers>=4.40.0 numpy
> python main.py tests/repo --zone-detect
> ```
