"""
build_centroids.py — M2 FAISS index construction.

Runs the fine-tuned EmbeddingGemma over the full dataset to produce:
  - Per-CWE centroid vectors (mean of all positive examples)
  - Per-instance vectors for the nearest-instance precision pass
  - A FAISS IndexFlatIP (inner-product on unit-normalized vectors = cosine sim)

Serializes to:
  artifacts/centroids.json    — centroid + instance vectors + metadata
  artifacts/cwe_index.faiss   — FAISS index for optional GPU-accelerated ANN

These artifacts are then referenced at runtime by `cwe_index.load_index()`.

Usage (offline):
    python -m engine.training.build_centroids \
        --dataset dataset/cwe89_python.jsonl \
        --adapter artifacts/zonescan_lora/ \
        --out artifacts/
"""

from __future__ import annotations

import argparse


def build_centroids(
    dataset_path: str,
    out_dir: str,
    adapter_path: str = "",
    batch_size: int = 64,
) -> None:
    """Compute centroids and build FAISS index from fine-tuned embeddings."""
    raise NotImplementedError(
        "M2 training pipeline not yet implemented. "
        "Run finetune_embedder.py first, then implement this module."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--adapter", default="")
    parser.add_argument("--out", default="artifacts/")
    parser.add_argument("--batch-size", type=int, default=64)
    args = parser.parse_args()
    build_centroids(args.dataset, args.out, args.adapter, args.batch_size)


if __name__ == "__main__":
    main()
