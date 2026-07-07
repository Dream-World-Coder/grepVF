"""
ZoneScan — CWE index.

Manages the FAISS-backed similarity index of known-vulnerable code patterns,
organized by CWE ID. Implements a two-pass retrieval strategy:

  Pass 1 (centroid pass): cosine similarity against a single centroid vector
    per CWE. Cheap — one dot product per CWE, regardless of how many training
    examples are in the cluster. Filters out clearly-unrelated CWEs.

  Pass 2 (nearest-instance pass): k-NN search within the matched CWE's
    per-instance vectors. Gives a finer-grained nearest_instance_similarity
    value that the verifier and hazard scorer can use.

M1 strategy: the index is bootstrapped from 10 hand-chosen CWE-89 example
functions (hardcoded below). Their embeddings are averaged to form the M1
centroid. No training pipeline is needed. The M1 centroid is replaced by
a trained FAISS index in M2.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from .embedder import embed_chunk
from .models import ZoneCandidate

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# M1 hand-seeded CWE-89 examples
# (representative SQL injection patterns in Python, used to build the
# zero-shot centroid without any training pipeline)
# ---------------------------------------------------------------------------

_CWE89_SEED_EXAMPLES: list[str] = [
    # String concatenation into execute()
    'def get_user(db, username):\n    query = "SELECT * FROM users WHERE name = \'" + username + "\'"\n    db.cursor().execute(query)\n    return db.cursor().fetchall()',
    # f-string interpolation
    'def get_balance(conn, account_id):\n    cursor = conn.cursor()\n    cursor.execute(f"SELECT balance FROM accounts WHERE id = {account_id}")\n    return cursor.fetchone()',
    # %-format
    'def find_order(conn, order_id):\n    sql = "SELECT * FROM orders WHERE id = %s" % order_id\n    conn.execute(sql)',
    # .format() interpolation
    'def search_product(db, name):\n    q = "SELECT * FROM products WHERE name = \'{}\'".format(name)\n    db.cursor().execute(q)',
    # Multi-step concatenation
    'def delete_record(conn, table, row_id):\n    query = "DELETE FROM " + table + " WHERE id = " + str(row_id)\n    conn.cursor().execute(query)\n    conn.commit()',
    # ORM raw() with string concat
    'def raw_lookup(model_cls, user_input):\n    return model_cls.objects.raw("SELECT * FROM table WHERE val = \'" + user_input + "\'")',
    # SQLite3 execute with fstring
    'def sqlite_lookup(path, key):\n    import sqlite3\n    conn = sqlite3.connect(path)\n    conn.execute(f"SELECT * FROM kv WHERE k = \'{key}\'")',
    # asyncpg-style (pool.fetch)
    'async def fetch_user(pool, uid):\n    q = "SELECT * FROM users WHERE id = " + str(uid)\n    return await pool.fetch(q)',
    # psycopg2 with % formatting
    'def pg_query(cur, name):\n    cur.execute("SELECT * FROM accounts WHERE owner = \'%s\'" % name)',
    # Stored in a variable then executed later
    'def run_report(conn, dept):\n    sql = "SELECT * FROM employees WHERE dept = \'" + dept + "\'"\n    with conn.cursor() as cur:\n        cur.execute(sql)\n        return cur.fetchall()',
]


# ---------------------------------------------------------------------------
# Index data structures
# ---------------------------------------------------------------------------


@dataclass
class _CWECluster:
    """Per-CWE data: one centroid vector + one vector per training example."""

    cwe_id: str
    centroid: np.ndarray  # unit-normalized, shape (dim,)
    instance_vectors: np.ndarray  # shape (n_examples, dim)
    instance_texts: list[str] = field(default_factory=list)


@dataclass
class CWEIndex:
    """
    Loaded index. Contains one `_CWECluster` per CWE.

    Built either from the M1 hand-seeded examples or from the M2 trained
    FAISS artifacts loaded via `load_index()`.
    """

    clusters: dict[str, _CWECluster] = field(default_factory=dict)
    embed_dim: int = 768


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_m1_index() -> CWEIndex:
    """
    Build the zero-shot M1 index by embedding the hand-seeded CWE-89
    examples and averaging them to form the centroid.

    This is called lazily on first `query()` call when no external index
    file is provided. Takes a few seconds on CPU (10 embed_chunk calls).
    """
    logger.info("[zonescan/cwe_index] Building M1 zero-shot CWE-89 index...")
    vecs: list[np.ndarray] = []
    for text in _CWE89_SEED_EXAMPLES:
        v = embed_chunk(text)
        vecs.append(v)

    matrix = np.stack(vecs, axis=0).astype(np.float32)  # (n, dim)
    centroid = matrix.mean(axis=0)
    norm = np.linalg.norm(centroid)
    centroid = (centroid / norm) if norm > 0 else centroid

    dim = matrix.shape[1]
    cluster = _CWECluster(
        cwe_id="CWE-89",
        centroid=centroid,
        instance_vectors=matrix,
        instance_texts=list(_CWE89_SEED_EXAMPLES),
    )
    logger.info(
        "[zonescan/cwe_index] M1 index built: 1 CWE, %d examples, dim=%d",
        len(vecs),
        dim,
    )
    return CWEIndex(clusters={"CWE-89": cluster}, embed_dim=dim)


def load_index(index_path: str) -> CWEIndex:
    """
    Load a pre-built CWE index from disk (M2+ artifacts).

    Expects a directory containing:
      - `centroids.json`: list of {cwe_id, centroid (list[float]),
                          instance_vectors (list[list[float]]),
                          instance_texts (list[str])}
      - (Optionally) `cwe_index.faiss` for GPU-accelerated ANN search.
        If absent, falls back to numpy dot-product k-NN.

    Falls back to the M1 zero-shot index if loading fails.
    """
    path = Path(index_path)
    centroids_file = path / "centroids.json" if path.is_dir() else path

    if not centroids_file.exists():
        logger.warning(
            "[zonescan/cwe_index] Index file not found at %s; "
            "falling back to M1 zero-shot index.",
            centroids_file,
        )
        return build_m1_index()

    try:
        data = json.loads(centroids_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(
            "[zonescan/cwe_index] Failed to load index from %s: %s; "
            "falling back to M1 zero-shot index.",
            centroids_file,
            exc,
        )
        return build_m1_index()

    clusters: dict[str, _CWECluster] = {}
    for entry in data:
        cwe_id = entry["cwe_id"]
        centroid = np.array(entry["centroid"], dtype=np.float32)
        norm = np.linalg.norm(centroid)
        centroid = (centroid / norm) if norm > 0 else centroid

        instance_vecs = np.array(entry.get("instance_vectors", []), dtype=np.float32)
        if instance_vecs.ndim == 1:
            instance_vecs = instance_vecs.reshape(1, -1)

        clusters[cwe_id] = _CWECluster(
            cwe_id=cwe_id,
            centroid=centroid,
            instance_vectors=instance_vecs,
            instance_texts=entry.get("instance_texts", []),
        )

    dim = clusters[next(iter(clusters))].centroid.shape[0] if clusters else 768
    logger.info(
        "[zonescan/cwe_index] Loaded index: %d CWE(s), dim=%d",
        len(clusters),
        dim,
    )
    return CWEIndex(clusters=clusters, embed_dim=dim)


def query(
    embedding: np.ndarray,
    index: CWEIndex,
    threshold: float = 0.80,
    k_nearest: int = 5,
) -> list[ZoneCandidate]:
    """
    Two-pass similarity search against the CWE index.

    Parameters
    ----------
    embedding : np.ndarray
        Unit-normalized chunk embedding from `embedder.embed_chunk`.
    index : CWEIndex
        Loaded index (from `build_m1_index` or `load_index`).
    threshold : float
        Minimum centroid cosine similarity to consider a CWE match.
        Default 0.80 (tunable via caller / CLI flag).
    k_nearest : int
        Number of nearest instances to retrieve in the precision pass.

    Returns
    -------
    list[ZoneCandidate]
        One entry per CWE that cleared both passes. In practice for MVP
        this is 0 or 1 entries (only CWE-89 is in the index).

    Notes
    -----
    This function deliberately returns a *stub* ZoneCandidate (file_path=""
    etc.) because the caller (`zone_detector.py`) injects the chunk metadata.
    `query()` only fills in the CWE and similarity fields.
    """
    if embedding.ndim != 1:
        embedding = embedding.flatten()

    results: list[ZoneCandidate] = []

    for cwe_id, cluster in index.clusters.items():
        # Pass 1: centroid cosine similarity (cheap)
        centroid_sim: float = float(np.dot(embedding, cluster.centroid))
        if centroid_sim < threshold:
            continue

        # Pass 2: nearest-instance cosine similarity (precision pass)
        if cluster.instance_vectors.size > 0:
            sims = cluster.instance_vectors @ embedding  # (n,)
            top_k = min(k_nearest, len(sims))
            top_indices = np.argpartition(sims, -top_k)[-top_k:]
            nearest_sim: float = float(sims[top_indices].max())
        else:
            nearest_sim = centroid_sim

        results.append(
            ZoneCandidate(
                file_path="",  # filled in by zone_detector
                function_name="",
                line_start=0,
                line_end=0,
                matched_cwe=cwe_id,
                centroid_similarity=centroid_sim,
                nearest_instance_similarity=nearest_sim,
            )
        )

    return results
