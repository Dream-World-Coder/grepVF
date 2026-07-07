# ZoneScan MVP — Task Checklist

## M0 — Skeleton & Wiring
- [ ] Create `engine/zonescan/__init__.py`
- [ ] Create `engine/zonescan/docs.md`
- [ ] Create `engine/zonescan/models.py` (CodeChunk, ZoneCandidate, ZoneFinding)
- [ ] Create `engine/zonescan/chunker.py` (stub → NotImplementedError)
- [ ] Create `engine/zonescan/embedder.py` (stub → NotImplementedError)
- [ ] Create `engine/zonescan/cwe_index.py` (stub → NotImplementedError)
- [ ] Create `engine/zonescan/taint_verifier.py` (stub → NotImplementedError)
- [ ] Create `engine/zonescan/zone_detector.py` (stub returns [])
- [ ] Create `engine/training/__init__.py`
- [ ] Create `engine/training/build_dataset.py` (stub)
- [ ] Create `engine/training/mine_pairs.py` (stub)
- [ ] Create `engine/training/finetune_embedder.py` (stub)
- [ ] Create `engine/training/build_centroids.py` (stub)
- [ ] Create `engine/training/eval_temporal_holdout.py` (stub)
- [ ] Refactor `semantics_checker.py` — extract `run_semgrep_scoped()`
- [ ] Modify `engine/core.py` — add zone_detect flag + 4th scanner slot
- [ ] Modify `engine/models.py` — update source_engine docstring
- [ ] Modify `engine/reports/final.py` — add zonescan rule to _TAINT_CONFIRMED_RULES + corroboration bump
- [ ] Modify `main.py` — add --zone-detect and --zone-index flags
- [ ] Cleanup: delete outputs/op.txt, outputs/report*.json; add outputs/* to .gitignore; add outputs/.gitkeep
- [ ] Create `tests/test_zonescan.py` (M0 smoke tests)
- [ ] Verify existing test suite is green

## M1 — Walking Skeleton, Zero-Shot
- [ ] Implement `chunker.py` (real ast-based function extraction)
- [ ] Implement `embedder.py` (zero-shot model, lazy singleton)
- [ ] Implement `cwe_index.py` (hand-seeded M1 centroid for CWE-89)
- [ ] Implement `taint_verifier.py` (scoped semgrep call via run_semgrep_scoped)
- [ ] Implement `zone_detector.py` (full orchestration, Finding conversion)
- [ ] Add numpy, faiss-cpu, torch, transformers to requirements.txt
- [ ] Expand `tests/test_zonescan.py` (M1 end-to-end against payment_service.py)
- [ ] Verify payment_service.py produces ≥1 zonescan finding end-to-end

## M2 — Real Data + Fine-tuning (offline)
- [ ] Implement `build_dataset.py`
- [ ] Implement `mine_pairs.py`
- [ ] Implement `finetune_embedder.py` (LoRA + InfoNCE)
- [ ] Implement `build_centroids.py`
- [ ] Swap M1 hand-seeded centroid for trained artifacts

## M3 — Temporal Holdout
- [ ] Implement `eval_temporal_holdout.py`
- [ ] Report recall on post-cutoff CVEs

## M4 — Aggregator Integration (already wired in M0 plan; verify)
- [ ] Confirm hazard bump in final.py fires correctly for verified findings
- [ ] Confirm SARIF has distinct ruleId for zonescan vs semgrep on same line
- [ ] Confirm dedup doesn't double-count same-line findings
