"""
finetune_embedder.py — M2 LoRA contrastive fine-tuning.

Fine-tunes EmbeddingGemma with a LoRA adapter using InfoNCE contrastive loss
on the pairs produced by `mine_pairs.py`. The adapter (not the full model
weights) is saved to `artifacts/zonescan_lora/`.

The adapter is then loaded at runtime by `embedder.py` when
`ZONESCAN_ADAPTER_PATH=artifacts/zonescan_lora/` is set.

Usage (offline, requires GPU recommended):
    python -m engine.training.finetune_embedder \
        --pairs dataset/pairs.jsonl \
        --out artifacts/zonescan_lora/ \
        --epochs 5 \
        --batch-size 32 \
        --lora-r 16 \
        --lora-alpha 32
"""

from __future__ import annotations

import argparse


def finetune(
    pairs_path: str,
    out_dir: str,
    epochs: int = 5,
    batch_size: int = 32,
    lora_r: int = 16,
    lora_alpha: int = 32,
    learning_rate: float = 2e-4,
) -> None:
    """Run LoRA contrastive fine-tune with InfoNCE loss."""
    raise NotImplementedError(
        "M2 training pipeline not yet implemented. "
        "Requires: peft, accelerate, datasets (requirements-training.txt). "
        "Run mine_pairs.py first."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pairs", required=True)
    parser.add_argument("--out", default="artifacts/zonescan_lora/")
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--lora-r", type=int, default=16)
    parser.add_argument("--lora-alpha", type=int, default=32)
    parser.add_argument("--lr", type=float, default=2e-4)
    args = parser.parse_args()
    finetune(
        args.pairs, args.out, args.epochs, args.batch_size,
        args.lora_r, args.lora_alpha, args.lr
    )


if __name__ == "__main__":
    main()
