"""
ZoneScan — embedder.

Loads an EmbeddingGemma (or fallback sentence-transformer) model and
produces unit-normalized embeddings for code chunks.

Design decisions
----------------
- **Lazy singleton**: the model is loaded on first call and cached at
  module level. Re-loading a ~300M model per chunk would be unusable.
- **M1 / M2 split**: M1 uses the zero-shot base model. M2 swaps in a
  LoRA adapter via the `ZONESCAN_ADAPTER_PATH` environment variable (or
  the `adapter_path` parameter to `load_embedder()`). The rest of the
  pipeline is unchanged — adapters plug into the same `embed_chunk()` call.
- **MRL truncation**: `embed_chunk(text, truncate_dim=128)` returns a
  lower-dimensional vector for cheap first-pass ANN search. The full-dim
  embedding is used for rescoring shortlisted candidates.
- **Graceful fallback**: if the primary model can't be loaded (no internet,
  `transformers` not installed), falls back to a deterministic random
  projection so M0/M1 skeletons remain runnable in CI without GPU or
  network access. The fallback logs a warning and sets
  `EMBEDDER_IS_STUB = True` so tests can assert the right code path.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Primary model: gemma-embedding (text + code encoder, ~300M params).
# Override via env var for local dev / CI.
_DEFAULT_MODEL_ID = os.environ.get(
    "ZONESCAN_MODEL_ID",
    "google/gemma-embedding-exp-03-07",
)

# Set to a local directory path to load a LoRA adapter for M2+.
_ADAPTER_PATH = os.environ.get("ZONESCAN_ADAPTER_PATH", "")

# Embedding dimension for the default model; update if using a different model.
_DEFAULT_EMBED_DIM = 768

# ---------------------------------------------------------------------------
# Module-level singleton state
# ---------------------------------------------------------------------------

_model = None  # transformers AutoModel instance
_tokenizer = None  # transformers AutoTokenizer instance
_embed_dim: int = _DEFAULT_EMBED_DIM

#: Set to True when the real model failed to load and we're using the stub.
EMBEDDER_IS_STUB: bool = False


def _try_load_model(
    model_id: str, adapter_path: str
) -> tuple[object, object, int] | None:
    """
    Attempt to load the HuggingFace model + tokenizer.
    Returns (model, tokenizer, embed_dim) or None on failure.
    """
    try:
        from transformers import AutoModel, AutoTokenizer  # type: ignore[import]
        import torch  # type: ignore[import]
    except ImportError:
        logger.warning(
            "[zonescan/embedder] 'transformers' or 'torch' not installed. "
            "Running with stub embedder — install requirements-zonescan.txt for real embeddings."
        )
        return None

    try:
        tokenizer = AutoTokenizer.from_pretrained(model_id)
        model = AutoModel.from_pretrained(model_id)
        model.eval()

        if adapter_path:
            try:
                from peft import PeftModel  # type: ignore[import]

                model = PeftModel.from_pretrained(model, adapter_path)
                logger.info(
                    "[zonescan/embedder] Loaded LoRA adapter from %s", adapter_path
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "[zonescan/embedder] Failed to load LoRA adapter from %s: %s. "
                    "Using base model.",
                    adapter_path,
                    exc,
                )

        # Probe the embedding dimension from the model config.
        embed_dim = getattr(
            model.config, "hidden_size", _DEFAULT_EMBED_DIM
        )
        logger.info(
            "[zonescan/embedder] Loaded model '%s' (dim=%d)", model_id, embed_dim
        )
        return model, tokenizer, embed_dim

    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "[zonescan/embedder] Failed to load model '%s': %s. "
            "Running with stub embedder.",
            model_id,
            exc,
        )
        return None


def load_embedder(
    model_id: str = _DEFAULT_MODEL_ID,
    adapter_path: str = _ADAPTER_PATH,
) -> None:
    """
    Explicitly pre-load the embedding model. Optional — `embed_chunk` will
    call this lazily on first use. Useful for tests that want to pre-warm
    the model or force the stub path.
    """
    global _model, _tokenizer, _embed_dim, EMBEDDER_IS_STUB

    result = _try_load_model(model_id, adapter_path)
    if result is not None:
        _model, _tokenizer, _embed_dim = result
        EMBEDDER_IS_STUB = False
    else:
        EMBEDDER_IS_STUB = True
        _embed_dim = _DEFAULT_EMBED_DIM


def _stub_embed(text: str, dim: int) -> np.ndarray:
    """
    Deterministic stub: hash the text into a reproducible unit vector.
    Used when the real model isn't available (CI without GPU/internet).
    """
    rng = np.random.default_rng(abs(hash(text)) % (2**31))
    vec = rng.standard_normal(dim).astype(np.float32)
    norm = np.linalg.norm(vec)
    return (vec / norm) if norm > 0 else vec


def embed_chunk(
    code_text: str,
    truncate_dim: int | None = None,
) -> np.ndarray:
    """
    Embed a code chunk using the loaded model (or stub).

    Parameters
    ----------
    code_text : str
        Normalized source text from `chunker.extract_function_chunks`.
    truncate_dim : int | None
        If set, truncate the embedding to this many dimensions (MRL).
        Use a small value (e.g. 128) for the cheap first-pass ANN search,
        then re-embed at full dimension for rescoring shortlisted candidates.

    Returns
    -------
    np.ndarray
        Unit-normalized 1-D float32 array of shape (embed_dim,) or (truncate_dim,).
    """
    global _model, _tokenizer, _embed_dim, EMBEDDER_IS_STUB

    # Lazy init
    if _model is None and not EMBEDDER_IS_STUB:
        load_embedder()

    if EMBEDDER_IS_STUB or _model is None:
        dim = truncate_dim if truncate_dim else _embed_dim
        return _stub_embed(code_text, dim)

    import torch  # type: ignore[import]

    inputs = _tokenizer(
        code_text,
        return_tensors="pt",
        truncation=True,
        max_length=512,
        padding=True,
    )

    with torch.no_grad():
        outputs = _model(**inputs)

    # Mean-pool the last hidden state over the token dimension
    last_hidden = outputs.last_hidden_state  # [1, seq_len, hidden]
    attention_mask = inputs["attention_mask"]  # [1, seq_len]
    mask_expanded = attention_mask.unsqueeze(-1).float()
    pooled = (last_hidden * mask_expanded).sum(dim=1) / mask_expanded.sum(dim=1)
    vec: np.ndarray = pooled.squeeze(0).cpu().numpy().astype(np.float32)

    # MRL truncation
    if truncate_dim and truncate_dim < len(vec):
        vec = vec[:truncate_dim]

    # Unit normalize
    norm = np.linalg.norm(vec)
    return (vec / norm) if norm > 0 else vec
