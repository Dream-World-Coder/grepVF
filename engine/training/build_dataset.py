"""
build_dataset.py — M2 training data preparation.

Pulls the VulGate CWE-89 Python subset and writes function-level snippets
to `dataset/cwe89_python.jsonl` for use by `mine_pairs.py`.

VulGate reference: https://github.com/VulGate/VulGate
Each JSONL record: {"cwe_id": "CWE-89", "language": "python",
                    "function_name": str, "source": str,
                    "is_vulnerable": bool, "cve_id": str | null}

Usage (offline, not in Docker image):
    python -m engine.training.build_dataset --out dataset/ --limit 5000
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# M2 implementation placeholder
# ---------------------------------------------------------------------------
# This module is intentionally not implemented for M0/M1. The training
# pipeline is offline-only and requires:
#   - VulGate dataset access (download URL TBD)
#   - datasets, huggingface_hub (requirements-training.txt)
#
# Stub raises NotImplementedError to make the intent explicit and prevent
# accidental invocation in the runtime container.
# ---------------------------------------------------------------------------

import argparse


def build(out_dir: str, limit: int = 5000) -> None:
    """Download and filter VulGate CWE-89 Python subset."""
    raise NotImplementedError(
        "M2 training pipeline not yet implemented. "
        "See engine/training/__init__.py for the M2 milestone description."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="dataset/", help="Output directory")
    parser.add_argument("--limit", type=int, default=5000, help="Max examples")
    args = parser.parse_args()
    build(args.out, args.limit)


if __name__ == "__main__":
    main()
