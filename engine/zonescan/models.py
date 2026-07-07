"""
ZoneScan data models.

These are internal to the zonescan package. `zone_detector.py` converts
ZoneFinding → engine.models.Finding before returning results, so the rest
of the pipeline (aggregator, SARIF writer, patcher) never sees these types.
"""

from dataclasses import dataclass, field


@dataclass
class CodeChunk:
    """
    A single function extracted from a source file, ready for embedding.

    `text` is normalized (comments stripped, consecutive blank lines
    collapsed) but identifiers are left intact — EmbeddingGemma is a
    pretrained text/code encoder that uses token-level semantics, so
    variable names like `query` near `execute` carry real signal.
    """

    file_path: str
    function_name: str
    line_start: int
    line_end: int
    text: str


@dataclass
class ZoneCandidate:
    """
    A code chunk that passed the similarity threshold against a CWE centroid.

    Produced by `cwe_index.query()`; consumed by `taint_verifier.verify()`.
    Both similarity values are cosine similarity in [0, 1].
    """

    file_path: str
    function_name: str
    line_start: int
    line_end: int
    matched_cwe: str  # e.g. "CWE-89"
    centroid_similarity: float
    nearest_instance_similarity: float


@dataclass
class ZoneFinding(ZoneCandidate):
    """
    A ZoneCandidate after taint verification has been attempted.

    `verified=True` means the scoped Semgrep call fired on this function —
    both the semantic-similarity signal *and* an independent taint-path
    check agree. This corroboration is the core interview story: it's a
    stronger signal than either alone, and is what separates zonescan from
    just running the three existing tools in parallel.

    `verified=False` findings above a high similarity threshold are still
    surfaced (as MEDIUM severity, `zonescan/cwe-89-probable`) because a
    pattern that looks like CWE-89 but that scoped Semgrep couldn't confirm
    may represent a novel variant the exact-match taint rules haven't yet
    been written for — which is precisely the value proposition.
    """

    verified: bool
    verification_rule: str  # rule_id that fired, or "" if not verified
    extra_metadata: dict = field(default_factory=dict)  # room for future fields
