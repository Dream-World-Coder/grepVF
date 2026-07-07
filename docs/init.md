# GrepVF — Zonescan MVP Build Spec

## Why this stage exists

The interviewer's critique was: Entropy Checker + Semantics Checker (Semgrep) + CVE Checker (OSV.dev) are three exact-match systems glued together — none of them generalizes to a variant they haven't seen. This stage adds a fourth, structurally different capability: a **retrieval + targeted-verification** layer that flags code *semantically* close to known-vulnerable patterns, then uses your existing Semgrep taint infrastructure — scoped down — to confirm or reject the guess.

This is additive. Nothing in the current architecture needs to be torn out to make room for it. See "Cleanup" at the end for the few small housekeeping items that *do* need deleting.

---

## MVP scope decisions (read this before building)

Explicit scope cuts, so this reads as deliberate engineering judgment in the interview, not as things you forgot:

| Decision | MVP choice | Deferred to Phase 2 |
|---|---|---|
| CWE coverage | CWE-89 (SQL injection) only | CWE-22, CWE-79, then broader |
| Language | Python only (matches your `tests/repo` fixtures) | JS/TS, Java |
| Code representation | Function-level source text (light normalization: strip comments, collapse whitespace) fed straight to EmbeddingGemma | Joern-derived CPG (AST+CFG+PDG) embeddings for flow-sensitive representation |
| Verification tool | Reuse your existing Semgrep subprocess (`semantics_checker.py`), scoped to one rule file + one line range | Joern CPGQL taint queries (`reachableByFlows`) |
| Embedding model | EmbeddingGemma-308M, zero-shot first (M1), LoRA-fine-tuned second (M2) | Full fine-tune, benchmark vs. UniXcoder/GraphCodeBERT |

**Why source text, not a serialized AST, for the embedder input:** EmbeddingGemma is a pretrained text/code encoder — it already knows that a variable named `query` next to a call named `execute` is meaningful. Stripping identifiers down to a bare tree throws away signal a token-based pretrained model can use. AST only matters here for finding clean function boundaries to chunk on — not for changing what gets embedded. (This is a deliberate refinement from the earlier "AST → embedding" framing, now that we're using a pretrained text encoder rather than training a bespoke tree encoder from scratch.)

**Why Semgrep instead of Joern for MVP verification:** you already depend on Semgrep and already run it in taint mode in `semantics_checker.py`. Standing up Joern (JVM, CPG extraction, a new query language) is real scope for a capability that, for MVP, just needs to answer "does tainted input reach a sink in this one flagged function." Reusing what you have is faster and is itself a good interview point: *the new layer makes your existing scanner smarter (scoped, targeted) rather than replacing it.*

---

## New package: `engine/zonescan/`

```
engine/
└── zonescan/
    ├── __init__.py
    ├── docs.md                 # matches your existing per-module doc convention
    ├── models.py                # ZoneCandidate, ZoneFinding dataclasses
    ├── chunker.py                # ast-based function-boundary extraction
    ├── embedder.py                # loads EmbeddingGemma, embeds a chunk
    ├── cwe_index.py               # loads centroids + FAISS index, queries nearest CWE
    ├── taint_verifier.py           # scoped call into semantics_checker's semgrep invocation
    └── zone_detector.py            # orchestrates the above into one scanner
```

### `models.py`
```python
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
**VERIFY:** check `engine/models.py`'s existing `Finding` class and `dedup_key()` before finalizing this — `ZoneFinding` needs to either subclass/adapt to whatever the Aggregator already expects, or `final.py` needs a small adapter. You have this file locally; I don't, so don't take this schema as final without cross-checking.

### `chunker.py`
```python
def extract_function_chunks(file_path: str) -> list[CodeChunk]:
    """Walk the file with Python's `ast` module, yield one CodeChunk per
    function/method definition: (name, line_start, line_end, normalized_text).
    Normalization = strip comments, collapse blank lines. Keep identifiers as-is."""
```

### `embedder.py`
```python
def embed_chunk(code_text: str, truncate_dim: int | None = None) -> np.ndarray:
    """Load EmbeddingGemma (base model for M1; swap in the LoRA adapter path
    for M2 via a config flag). Supports MRL truncation for the cheap first-pass
    ANN search; full-dim for rescoring shortlisted candidates."""
```

### `cwe_index.py`
```python
def load_index(index_path: str) -> CWEIndex: ...

def query(embedding: np.ndarray, index: CWEIndex, threshold: float) -> list[ZoneCandidate]:
    """Cosine similarity against per-CWE centroids first (cheap), then nearest-
    instance similarity within the matched CWE cluster (precision pass)."""
```

### `taint_verifier.py`
```python
def verify(candidate: ZoneCandidate, repo_root: str) -> bool:
    """Map matched_cwe -> a specific rule file (CWE-89 -> rules/injection.yml).
    Call semantics_checker's existing subprocess invocation, but pass:
      - only that one rule file (not the full ruleset)
      - a --include or line-range restriction to just this function
    Return whether the scoped rule fired."""
```
This is the refactor point in `semantics_checker.py`: pull the "run semgrep with this rule file against this file/range" logic into a standalone callable both the normal scanner and `taint_verifier.py` can call, instead of duplicating subprocess-invocation code.

### `zone_detector.py`
```python
async def run(file_paths: list[str], repo_root: str) -> list[ZoneFinding]:
    """For each file: chunk -> embed -> query index -> for candidates above
    threshold, call taint_verifier scoped to matched_cwe -> emit ZoneFinding
    (verified=True/False either way; unverified-but-high-similarity findings
    still get surfaced at lower hazard score, not discarded — a novel pattern
    your regex/CVE checkers structurally cannot produce)."""
```

---

## New package: `engine/training/` (offline — not shipped in the Docker image)

```
engine/
└── training/
    ├── build_dataset.py       # pull VulGate subset, CWE-89, Python only
    ├── mine_pairs.py            # positive (same CWE) + hard-negative (benign, shape-similar) pairs
    ├── finetune_embedder.py      # LoRA contrastive fine-tune, InfoNCE loss
    ├── build_centroids.py         # serialize centroid(s) + FAISS index from fine-tuned model
    └── eval_temporal_holdout.py    # train/index cutoff vs. post-cutoff CVEs — your credibility number
```

Keep this out of the runtime container. Its output artifacts (fine-tuned adapter weights, `centroids.json`, FAISS index file) get versioned and pulled into the `zonescan` runtime path at container build time or on first run — don't commit multi-MB model artifacts straight into git.

---

## Modifications to existing files

- **`engine/core.py`** — add `zone_detector.run()` as a fourth concurrent task in the `asyncio.gather` stage, dispatched via `run_in_executor` (like Entropy/Semantics — it's CPU-bound: embedding inference + a subprocess call), not the async event-loop path used for the CVE Checker's HTTP batches.
- **`engine/codescan/semantics_checker.py`** — extract the "run semgrep with rule file X against target Y" logic into a reusable function so `taint_verifier.py` calls it instead of duplicating subprocess handling.
- **`engine/reports/final.py`** — teach the Aggregator to bump hazard score when a `ZoneFinding.verified == True`: a semantic-similarity match *and* an independent scoped-taint hit agreeing is a stronger signal than either alone, and is a clean story for why this beats running the three original tools separately. Also confirm `dedup_key()` handles the new finding type without colliding with existing Semgrep findings on the same line.
- **`engine/models.py`** — extend or adapt `Finding` so it can represent `matched_cwe` / `centroid_similarity` / `verification_rule`. Check this file first — don't assume the schema.
- **`main.py`** — add a `--zone-detect` flag (default off, since M2+ needs the trained artifacts downloaded), matching your existing `--patch` / `--route-only` / `--ci` style.

---

## Build order (milestones)

**M0 — Skeleton & wiring**
Create the `zonescan/` package with typed interfaces, stub implementations (`raise NotImplementedError`), wire a feature-flagged no-op into `core.py` behind `--zone-detect`. *Done when:* existing test suite is untouched and green, new scanner is dispatched but returns `[]`.

**M1 — Walking skeleton, zero-shot, single CWE**
Real `chunker.py`, zero-shot EmbeddingGemma in `embedder.py`, a hand-seeded centroid (5–10 manually chosen CWE-89 examples, averaged — no training pipeline yet), `taint_verifier.py` wired to `rules/injection.yml`. *Done when:* running against `tests/repo/payment_service.py` produces at least one correctly flagged, correctly verified zone finding end-to-end into a SARIF entry with a distinct rule id (e.g. `zonescan/cwe-89-probable`).

**M2 — Real data + fine-tuning**
`build_dataset.py` against a VulGate CWE-89 subset, `mine_pairs.py`, `finetune_embedder.py` (LoRA), `build_centroids.py`. Swap M1's hand-seeded centroid for the trained one. *Done when:* you can report precision/recall on a held-out split, compared against the M1 zero-shot baseline. This comparison table is your interview evidence.

**M3 — Temporal holdout**
`eval_temporal_holdout.py`: build the index from CVEs before a cutoff date, measure recall on CVEs published after it. *Done when:* you have one honest number you can say out loud when asked "does this actually catch new CVEs."

**M4 — Aggregator integration**
Wire the corroboration hazard bump, confirm SARIF distinguishes zonescan findings from Semgrep findings on the same file/line rather than colliding in dedup.

**M5 — Phase 2 (explicitly not MVP)**
Joern/CPG-based representation for flow-sensitive embeddings; expand to CWE-22 and CWE-79; multi-language.

---

## Cleanup (the actual "what to delete" answer)

There isn't much — this is additive, not a replacement. Two small items:

1. `outputs/op.txt`, `report.json`, `report2.json`, `report3.json` — stale scratch output, shouldn't be tracked. Delete them and add `outputs/*` to `.gitignore` (keep a `.gitkeep` if you want the dir to exist).
2. You have `conftest.py` at repo root *and* inside `tests/` — probably intentional (root for container/integration-level fixtures, `tests/` for unit fixtures), but worth a quick check that nothing in the root one is silently shadowed or duplicated.

That's it. Resist the urge to invent deletions just to have an answer for "what did you remove" — the honest answer is "nothing architectural; we added a fourth signal source and made the existing Semgrep scanner reusable in scoped mode."

---

## One line for the interview

*"The original three tools are exact-match: a rule fires, a signature matches, or it doesn't. Zonescan adds a fourth, different kind of signal — semantic similarity to known-vulnerable code — and instead of trusting that guess blindly, it re-uses our own Semgrep taint engine, scoped down to just the matched CWE and just the flagged function, to confirm it. Two independent methods agreeing is what actually reduces false positives, and the M2/M3 numbers show it's not just re-detecting what Semgrep already knows — it generalizes to code shaped like CVEs it never trained on."*