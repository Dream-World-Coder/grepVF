"""
ZoneScan — retrieval-augmented vulnerability detection.

Embeds function-level code chunks, queries a FAISS index of known-vulnerable
CWE patterns for semantic similarity, then uses a scoped Semgrep taint call
to confirm or reject high-similarity candidates.

Public surface: `run_zone_detector` returns a list of `Finding` objects
compatible with the existing aggregation pipeline, so `core.py` can treat
this as a 4th concurrent scanner without any changes to reports, SARIF, or
the patcher.
"""

from .zone_detector import run_zone_detector

__all__ = ["run_zone_detector"]
