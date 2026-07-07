"""
mine_pairs.py — M2 contrastive pair mining.

Generates positive pairs (same CWE, different code) and hard-negative pairs
(benign code that is structurally similar to vulnerable patterns) from the
dataset produced by `build_dataset.py`.

Hard negatives are crucial for fine-tuning: an embedder that separates
"SQLi" from "benign SELECT" is easy; one that also separates "SQLi" from
"benign string concat near a DB call" is actually useful.

Usage (offline):
    python -m engine.training.mine_pairs \
        --dataset dataset/cwe89_python.jsonl \
        --out dataset/pairs.jsonl \
        --hard-negative-ratio 3
"""

from __future__ import annotations

import argparse


def mine(dataset_path: str, out_path: str, hard_negative_ratio: int = 3) -> None:
    """Generate contrastive pairs from the dataset."""
    raise NotImplementedError(
        "M2 training pipeline not yet implemented. "
        "Run build_dataset.py first, then implement this module for M2."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--out", default="dataset/pairs.jsonl")
    parser.add_argument("--hard-negative-ratio", type=int, default=3)
    args = parser.parse_args()
    mine(args.dataset, args.out, args.hard_negative_ratio)


if __name__ == "__main__":
    main()
