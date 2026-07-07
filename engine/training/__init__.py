"""
ZoneScan training package — offline scripts for M2+ fine-tuning.

This package is NOT included in the Docker runtime image. Its outputs
(fine-tuned LoRA adapter, centroids.json, cwe_index.faiss) are versioned
artifacts that get pulled into the zonescan runtime path at build time or
on first run.

Modules
-------
build_dataset   : Pull VulGate CWE-89 Python subset
mine_pairs      : Generate contrastive pairs (positive + hard-negative)
finetune_embedder : LoRA contrastive fine-tune with InfoNCE loss
build_centroids : Build FAISS index from fine-tuned embeddings
eval_temporal_holdout : Measure recall on post-cutoff CVEs
"""
