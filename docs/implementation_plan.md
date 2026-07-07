# ZoneScan MVP — Implementation Plan

ZoneScan is a fourth, structurally distinct signal source for GrepVF: **retrieval + targeted-verification**. It embeds function-level code chunks, queries a FAISS index of known-vulnerable CWE patterns (centroid similarity), then uses a scoped Semgrep taint call to confirm or reject candidates — surfacing likely variants of seen vulnerabilities that exact-match scanners structurally cannot produce.

This plan covers **M0 through M4** as described in the build spec, with explicit cross-checks against the existing codebase.

---

## Cross-checks Completed

The following was verified against the live code before writing this plan:

| Area | Finding |
|---|---|
| `engine/models.py` — `Finding` | Has `extra: dict` field; `source_engine`, `cwe`, `line/end_line` all present. `dedup_key()` uses `file_path:line:rule_id` — zonescan rule IDs like `zonescan/cwe-89-probable` will not collide with semgrep rule IDs like `sql-injection-string-concat`. |
| `engine/reports/final.py` — `_dedup_key()` | Uses `(file_path, line)` — a zonescan finding on the same line as a Semgrep finding *will* be aggregation-deduped unless it's a CVE or different category. **Decision:** give zonescan findings `Category.INJECTION` — they may validly merge with Semgrep injection findings on the same line since they're describing the same underlying issue. |
| `engine/reports/final.py` — `get_hazard_score()` | `_TAINT_CONFIRMED_RULES` is a set of rule IDs that get +1.0 bump. We'll add `zonescan/cwe-89-verified` to this set AND add a new bump for `verified=True` zone findings. |
| `engine/codescan/semantics_checker.py` — `_run_semgrep()` | Takes `target_paths: list[str]` + `repo_root: str` + optional `extra_config`. We'll extract this into a standalone `run_semgrep_scoped()` callable. |
| `engine/core.py` — scanners stage | Three concurrent tasks via `asyncio.gather`. ZoneScan goes in as a 4th `run_in_executor` task (CPU-bound: inference + subprocess). |
| `engine/codescan/rules/injection.yml` | Has `sql-injection-string-concat` (taint-mode) and `sql-injection-fstring`. CWE-89 → `injection.yml` mapping is confirmed. |
| `tests/repo/payment_service.py` | Contains `get_transaction_by_reference()` (string concat SQL injection) and `get_account_balance()` (f-string SQL injection). Both are good M1 end-to-end targets. |
| Root vs. `tests/` conftest | Root `conftest.py` is intentionally empty (sys.path anchor only). `tests/conftest.py` has all fixtures. No shadowing issue. |

---

## Open Questions

> [!IMPORTANT]
> **EmbeddingGemma availability**: The spec calls for `EmbeddingGemma-308M`. This is a Gemma-based embedding model. The primary source for this is likely `google/gemma-embedding` or a HuggingFace checkpoint. Clarify: (a) which HuggingFace model ID to use, and (b) whether the model weights are already downloaded locally or should be fetched on first run. The plan defaults to `google/gemma-embedding-exp-03-07` (768-dim) as the nearest candidate, but this needs confirmation before M1.
>
> **Fallback**: If EmbeddingGemma isn't available, the plan includes a fallback to `sentence-transformers/all-MiniLM-L6-v2` (384-dim) for M0/M1 unblocking — it's well-understood, installable via pip, and fits the "text/code encoder" profile described in the spec.

> [!IMPORTANT]
> **FAISS and torch dependencies**: Adding `faiss-cpu`, `torch`, and `transformers` to `requirements.txt` will significantly inflate the Docker image. The spec says the training package stays out of the container, but the *runtime* embedding model and FAISS index must be in it. Confirm whether we should use a conditional requirements split (`requirements-zonescan.txt`) loaded only when `--zone-detect` is passed, or absorb these into the base image.

> [!NOTE]
> **VulGate dataset for M2**: The spec references "VulGate subset, CWE-89, Python only" for `build_dataset.py`. VulGate is a research dataset; verify which public mirror or download URL to use before starting M2.

---

## Proposed Changes

### New Package: `engine/zonescan/`

#### [NEW] `engine/zonescan/__init__.py`
Empty package marker with `__all__` export of `run_zone_detector`.

#### [NEW] `engine/zonescan/docs.md`
Per-module doc matching the existing convention — explains the retrieval+verify loop, the two-pass similarity strategy (centroid → nearest-instance), and the M1 zero-shot / M2 fine-tuned split.

#### [NEW] `engine/zonescan/models.py`
```python
@dataclass
class CodeChunk:
    file_path: str
    function_name: str
    line_start: int
    line_end: int
    text: str  # normalized source text

@dataclass
class ZoneCandidate:
    file_path: str
    function_name: str
    line_start: int
    line_end: int
    matched_cwe: str          # e.g. "CWE-89"
    centroid_similarity: float
    nearest_instance_similarity: float

@dataclass
class ZoneFinding(ZoneCandidate):
    verified: bool
    verification_rule: str    # which scoped semgrep rule fired, if any
```
**Relationship to `Finding`**: `ZoneFinding` is *not* a subclass of `Finding`. `zone_detector.py` converts `ZoneFinding` → `Finding` before returning, storing zonescan-specific fields in `Finding.extra` (`centroid_similarity`, `nearest_instance_similarity`, `verified`, `verification_rule`). This keeps the rest of the pipeline — aggregator, SARIF writer — completely unmodified.

#### [NEW] `engine/zonescan/chunker.py`
Uses Python's `ast` stdlib module to walk a file and yield one `CodeChunk` per `FunctionDef`/`AsyncFunctionDef`. Normalization: strip `#` comments and collapse consecutive blank lines. Identifiers are preserved. Handles `ast.parse` failures gracefully (returns empty list + logs error).

#### [NEW] `engine/zonescan/embedder.py`
- Loads the embedding model (HuggingFace `transformers` + `torch`) lazily on first call; model is module-level singleton to avoid re-loading per chunk.
- M1: zero-shot base model. M2: swap in LoRA adapter via `ZONESCAN_ADAPTER_PATH` env var / config flag.
- Supports MRL truncation via `truncate_dim` for cheap first-pass ANN; full-dim for rescoring.
- Returns `np.ndarray` (shape `[embed_dim]`), normalized to unit length.

#### [NEW] `engine/zonescan/cwe_index.py`
- `CWEIndex` dataclass: holds a FAISS `IndexFlatIP` (inner-product for cosine similarity on unit-normalized vectors) + a list of `(cwe_id, example_source_text)` metadata.
- `load_index(index_path)`: loads from a `.json` + `.faiss` pair.
- `query(embedding, index, threshold)`: 
  1. Centroid pass — cosine sim against per-CWE centroids (cheap, one vector per CWE).
  2. For CWEs above threshold: nearest-instance pass within that CWE cluster (precision pass, `k=5`).
  3. Returns `list[ZoneCandidate]` above the threshold.
- **M1 fallback**: if no index file exists, uses a hand-seeded in-memory centroid built from 5–10 hardcoded CWE-89 example embeddings computed at startup.

#### [NEW] `engine/zonescan/taint_verifier.py`
- `CWE_TO_RULE_FILE`: mapping `"CWE-89" → "injection.yml"` (one entry for MVP; extendable).
- `verify(candidate, repo_root)`:
  - Looks up the rule file for `candidate.matched_cwe`.
  - Calls the extracted `run_semgrep_scoped()` from `semantics_checker.py` with:
    - only the CWE-specific rule file
    - `--include` restricted to just the candidate's file path  
    - checks if any result falls within `[line_start, line_end]`
  - Returns `(verified: bool, rule_id: str | None)`.

#### [NEW] `engine/zonescan/zone_detector.py`
- `run(file_paths, repo_root, index_path, threshold) -> list[Finding]`:
  - For each `.py` file: `chunker.extract_function_chunks()`
  - For each chunk: `embedder.embed_chunk()` → `cwe_index.query()`
  - For candidates above threshold: `taint_verifier.verify()` → `ZoneFinding`
  - Converts every `ZoneFinding` → `Finding` for pipeline compatibility:
    - `verified=True`: `rule_id="zonescan/cwe-89-verified"`, `severity=HIGH`, stores in `_TAINT_CONFIRMED_RULES`
    - `verified=False` (high-similarity only): `rule_id="zonescan/cwe-89-probable"`, `severity=MEDIUM`
  - Runs synchronously; called via `run_in_executor` from `core.py`.

---

### New Package: `engine/training/` (offline, not in Docker image)

#### [NEW] `engine/training/__init__.py`
Empty marker.

#### [NEW] `engine/training/build_dataset.py`
Pulls VulGate CWE-89 Python subset, filters to function-level snippets, writes `dataset/cwe89_python.jsonl`.

#### [NEW] `engine/training/mine_pairs.py`
Generates positive pairs (same CWE, different code) + hard negatives (benign, structurally similar). Outputs `dataset/pairs.jsonl`.

#### [NEW] `engine/training/finetune_embedder.py`
LoRA contrastive fine-tune with InfoNCE loss. Saves adapter to `artifacts/zonescan_lora/`.

#### [NEW] `engine/training/build_centroids.py`
Runs fine-tuned model over the dataset, computes per-CWE centroids, builds FAISS index, serializes to `artifacts/centroids.json` + `artifacts/cwe_index.faiss`.

#### [NEW] `engine/training/eval_temporal_holdout.py`
Train/index cutoff vs. post-cutoff CVEs. Outputs precision/recall table.

---

### Modified: `engine/codescan/semantics_checker.py`

#### [MODIFY] [semantics_checker.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/codescan/semantics_checker.py)

Extract `_run_semgrep()` into a new **public** callable `run_semgrep_scoped(target_paths, repo_root, rule_files)` that:
- Accepts a list of specific rule file paths (instead of defaulting to the full `RULES_DIR`)
- Can be imported by `taint_verifier.py` without creating a circular dependency

The existing `run_semantics_checker()` is updated to call this shared function. No behavior change for existing scanner.

---

### Modified: `engine/core.py`

#### [MODIFY] [core.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/core.py)

Add ZoneScan as a 4th concurrent task in Stage 3, gated behind a `zone_detect: bool = False` parameter:

```python
# Stage 3 — four scanners, concurrent (when zone_detect=True)
zone_task = (
    loop.run_in_executor(None, run_zone_detector, root, self.files.code, index_path)
    if zone_detect
    else asyncio.coroutine(lambda: ScanResult(findings=[], engine="zonescan", files_scanned=0))()
)

entropy_result, semantics_result, cve_result, zone_result = await asyncio.gather(
    entropy_task, semantics_task, check_dependencies_async(dependencies), zone_task
)
```

`scan_results` dict gains a `"zonescan"` key. `aggregate()` call adds `zone_result.findings`.

Update `_print_scanner_summary()` to handle the optional 4th result. Update `run_scan_async()` signature to accept `zone_detect: bool = False`. Update `run_scan()` wrapper and `__repr__` accordingly.

---

### Modified: `engine/reports/final.py`

#### [MODIFY] [final.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/reports/final.py)

Two changes:

1. **Add `zonescan/cwe-89-verified` to `_TAINT_CONFIRMED_RULES`** — gets the existing +1.0 taint-confirmed bump.

2. **Add a corroboration bump** in `get_hazard_score()`:
```python
# Corroboration: semantic-similarity hit + independent scoped-taint confirmation
# is a stronger signal than either alone.
if (
    finding.source_engine == "zonescan"
    and finding.extra.get("verified") is True
):
    score += 0.5
```
   This is on top of the +1.0 from `_TAINT_CONFIRMED_RULES`, so a verified zone finding at HIGH base gets 7.0 + 1.0 + 0.5 = 8.5 — below CRITICAL but noticeably above a bare Semgrep HIGH.

3. **Dedup behavior** (`_dedup_key` uses `(file_path, line)`): A `zonescan/cwe-89-verified` finding on the same line as `sql-injection-string-concat` will compete in the `merge_classes["injection"]` bucket — the winner is the one with higher severity. If Semgrep already caught it, zonescan's finding merges in and doesn't duplicate. If Semgrep *missed* it (the valuable case), zonescan's finding stands alone. No change needed to dedup logic.

---

### Modified: `engine/models.py`

#### [MODIFY] [models.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/engine/models.py)

No structural change needed. The `extra: dict` field already carries arbitrary engine-specific payload. We use it to store:
```python
extra={
    "centroid_similarity": float,
    "nearest_instance_similarity": float,
    "verified": bool,
    "verification_rule": str | None,
}
```
Update the docstring on `Finding.source_engine` to document `"zonescan"` as a valid value.

---

### Modified: `main.py`

#### [MODIFY] [main.py](file:///Users/subhajitgorai/Codes/current_projects/uco/grepVF/main.py)

Add `--zone-detect` flag (default off):
```
--zone-detect    Enable ZoneScan retrieval+verification layer (requires
                 model artifacts; off by default for M0/M1 zero-shot,
                 then behind a flag until M2 artifacts are downloaded).
```
Add `--zone-index` flag (optional path to FAISS index; if omitted, falls back to hand-seeded M1 centroid):
```
--zone-index PATH   Path to pre-built CWE index (centroids.json + .faiss).
                    Omit to use the built-in zero-shot M1 centroid.
```
Pass `zone_detect=args.zone_detect` to `engine.run_scan()`.

---

### Cleanup

#### [MODIFY] `.gitignore`
Add `outputs/*` and `!outputs/.gitkeep` entries.

#### [DELETE] `outputs/op.txt`, `outputs/report.json`, `outputs/report2.json`, `outputs/report3.json`
Stale scratch output; not tracked going forward.

#### [NEW] `outputs/.gitkeep`
Keeps the `outputs/` directory in the repo without tracking its contents.

---

## New Test File

#### [NEW] `tests/test_zonescan.py`
Unit tests for M0 (stub returns `[]`, existing suite green), M1 (chunker extracts functions from `payment_service.py`, end-to-end zone finding on SQL injection pattern). Uses pytest fixtures from `tests/conftest.py`.

Specific M1 done-when criterion: running against `tests/repo/payment_service.py` produces at least one `Finding` with `rule_id="zonescan/cwe-89-verified"` or `"zonescan/cwe-89-probable"` and a `source_engine="zonescan"`.

---

## New Dependencies (to add to `requirements.txt`)

For runtime (zonescan engine, behind `--zone-detect` flag):
```
faiss-cpu>=1.8.0
torch>=2.2.0          # CPU-only; swap for torch+cu121 in GPU Dockerfile variant
transformers>=4.40.0
numpy>=1.26.0
```

For training (offline only — add to a new `requirements-training.txt`):
```
datasets>=2.19.0      # HuggingFace datasets for VulGate
peft>=0.11.0          # LoRA via PEFT
accelerate>=0.30.0
```

> [!WARNING]
> `torch` adds ~800MB to the base image. Consider a multi-stage Dockerfile with a separate `zonescan`-capable image variant, or use `--zone-detect` as the gating mechanism so users who don't need ZoneScan don't pay the download cost. Confirm before M1 whether the base Docker image should absorb torch or use a separate image tag.

---

## Build Order / Milestones

| Milestone | Gate Criterion |
|---|---|
| **M0** — Skeleton & wiring | Existing test suite green; `--zone-detect` dispatches a no-op that returns `[]` |
| **M1** — Walking skeleton, zero-shot | `payment_service.py` produces ≥1 correctly flagged+verified `zonescan/cwe-89-*` SARIF entry |
| **M2** — Real data + fine-tuning | Precision/recall table on held-out split vs. M1 zero-shot baseline |
| **M3** — Temporal holdout | One honest recall number: "finds X% of post-cutoff CWE-89 CVEs" |
| **M4** — Aggregator integration | Hazard bump wired, dedup confirmed not to collide with Semgrep findings |

---

## Verification Plan

### Automated Tests

```bash
# Full existing suite — must stay green after every milestone
pytest tests/ -v

# ZoneScan-specific tests (new)
pytest tests/test_zonescan.py -v

# M1 end-to-end integration smoke test
python main.py tests/repo --zone-detect --output /tmp/zone_test.json
# Verify zone findings appear in output JSON
```

### Manual Verification
- After M1: inspect that SARIF `ruleId` values include `zonescan/cwe-89-verified` or `zonescan/cwe-89-probable`, distinct from `sql-injection-string-concat`.
- After M4: run on `tests/repo/payment_service.py` and confirm a Semgrep finding + ZoneScan finding on the same injection line de-duplicates correctly (one winner in output, not two).
