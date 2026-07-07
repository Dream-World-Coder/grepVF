"""
eval_temporal_holdout.py — M3 temporal generalization evaluation.

Measures how well the trained index generalizes to vulnerabilities it has
never seen. Methodology:

  1. Split the dataset by CVE publication date (cutoff = configurable, e.g.
     2023-01-01).
  2. Build the FAISS index using only pre-cutoff examples.
  3. Evaluate recall on post-cutoff CVE examples at various similarity
     thresholds.

This produces the honest number you can cite in an interview:
  "The M2 index, trained on CVEs published before 2023, recalls X% of
   CWE-89 vulnerabilities published after that date at a 0.80 threshold
   with a Y% false-positive rate on clean code."

Usage (offline):
    python -m engine.training.eval_temporal_holdout \
        --dataset dataset/cwe89_python.jsonl \
        --adapter artifacts/zonescan_lora/ \
        --cutoff 2023-01-01 \
        --thresholds 0.70,0.75,0.80,0.85,0.90
"""

from __future__ import annotations

import argparse


def evaluate(
    dataset_path: str,
    adapter_path: str = "",
    cutoff_date: str = "2023-01-01",
    thresholds: list[float] | None = None,
) -> dict:
    """
    Run temporal holdout evaluation.

    Returns a dict of {threshold: {precision, recall, f1}} for the report.
    """
    raise NotImplementedError(
        "M3 temporal holdout evaluation not yet implemented. "
        "Requires M2 artifacts (build_centroids.py output)."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--adapter", default="")
    parser.add_argument("--cutoff", default="2023-01-01")
    parser.add_argument(
        "--thresholds", default="0.70,0.75,0.80,0.85,0.90",
        help="Comma-separated similarity thresholds to evaluate"
    )
    args = parser.parse_args()
    thresholds = [float(t) for t in args.thresholds.split(",")]
    results = evaluate(args.dataset, args.adapter, args.cutoff, thresholds)
    import json
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
