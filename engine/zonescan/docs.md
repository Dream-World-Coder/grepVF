# ZoneScan Module

ZoneScan is the fourth signal source in GrepVF: a **retrieval + targeted-verification** layer
that flags code *semantically* close to known-vulnerable patterns, then uses GrepVF's existing
Semgrep taint infrastructure — scoped down to one rule file + one line range — to confirm or
reject the guess.

This is structurally different from the other three scanners:

| Scanner | What it does | Generalizes? |
|---|---|---|
| Entropy Checker | Regex + Shannon entropy | No — exact pattern match |
| Semantics Checker | Semgrep taint/structural rules | No — exact AST pattern match |
| CVE Checker | OSV.dev lookup by package@version | No — exact version match |
| **ZoneScan** | Embedding similarity → scoped taint verify | **Yes** — catches semantic variants |

## Pipeline

```
File (.py)
  │
  ▼
chunker.py — ast-based function boundary extraction
  │  yields CodeChunk per FunctionDef / AsyncFunctionDef
  ▼
embedder.py — EmbeddingGemma (zero-shot M1, LoRA-fine-tuned M2)
  │  → np.ndarray (unit-normalized, full dim or MRL-truncated)
  ▼
cwe_index.py — two-pass similarity
  │  1. Centroid pass: cosine sim vs per-CWE centroids (cheap)
  │  2. Nearest-instance pass: k-NN within matched CWE cluster (precision)
  │  → list[ZoneCandidate] above threshold
  ▼
taint_verifier.py — scoped Semgrep call
  │  CWE-89 → injection.yml, restricted to candidate file + line range
  │  → (verified: bool, rule_id: str | None)
  ▼
zone_detector.py — converts ZoneFinding → Finding
  │  verified=True  → rule_id="zonescan/cwe-89-verified",  severity=HIGH
  │  verified=False → rule_id="zonescan/cwe-89-probable", severity=MEDIUM
  ▼
engine/core.py asyncio.gather (4th concurrent task)
```

## Milestones

- **M1 (zero-shot)**: Hand-seeded CWE-89 centroid (5–10 examples averaged), base EmbeddingGemma,
  `injection.yml` for verification. Done when `payment_service.py` produces ≥1 correctly flagged,
  verified zone finding in SARIF.
- **M2 (fine-tuned)**: LoRA contrastive fine-tune on VulGate CWE-89 subset, trained FAISS index.
  Done when precision/recall table exists vs. M1 baseline.
- **M3 (temporal holdout)**: Train/index on pre-cutoff CVEs, measure recall on post-cutoff CVEs.

## Scope (MVP)

| Dimension | MVP | Phase 2 |
|---|---|---|
| CWE coverage | CWE-89 only | CWE-22, CWE-79, broader |
| Language | Python only | JS/TS, Java |
| Code representation | Function-level source text | CPG (Joern) for flow-sensitive embeddings |
| Verification | Scoped Semgrep (`injection.yml`) | Joern CPGQL `reachableByFlows` |
| Embedding model | EmbeddingGemma-308M, zero-shot → LoRA | Full fine-tune, benchmark vs UniXcoder |

## Configuration

| Env var / flag | Default | Purpose |
|---|---|---|
| `--zone-detect` | off | Enable the scanner (requires model on PATH) |
| `--zone-index PATH` | built-in M1 centroid | Path to `centroids.json` + `.faiss` artifacts |
| `ZONESCAN_ADAPTER_PATH` | `""` (base model) | LoRA adapter directory for M2+ |
| `ZONESCAN_THRESHOLD` | `0.80` | Minimum centroid cosine similarity to surface a candidate |
