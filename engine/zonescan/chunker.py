"""
ZoneScan — chunker.

Extracts function-level code chunks from Python source files using the
`ast` stdlib module for clean boundary detection.

Why `ast` for boundaries and source text for the embedded content:
EmbeddingGemma is a pretrained text/code encoder — it already understands
that `query` next to `execute` is meaningful. Stripping identifiers down to
a bare AST throws away the very signal a token-based encoder is trained on.
`ast` is used here *only* to find where functions start and end, not to
transform what gets embedded.
"""

import ast
import re
from pathlib import Path

from .models import CodeChunk

# Matches a Python comment from `#` to end of line.
_COMMENT_RE = re.compile(r"#.*$", re.MULTILINE)
# Two or more consecutive newlines → one blank line.
_MULTI_BLANK_RE = re.compile(r"\n{3,}")


def _normalize(source: str) -> str:
    """
    Light normalization for embedding input.

    Rules (intentionally minimal — don't throw away signal):
    1. Strip inline and full-line `#` comments.
    2. Collapse runs of 3+ newlines to a single blank line.
    3. Strip leading/trailing whitespace.

    Identifiers, string literals, and all other tokens are left intact.
    """
    without_comments = _COMMENT_RE.sub("", source)
    collapsed = _MULTI_BLANK_RE.sub("\n\n", without_comments)
    return collapsed.strip()


def extract_function_chunks(file_path: str) -> list[CodeChunk]:
    """
    Walk a Python source file with `ast` and yield one `CodeChunk` per
    top-level or nested `FunctionDef` / `AsyncFunctionDef`.

    Returns an empty list on parse error (encoding issues, syntax errors in
    the scanned file) — ZoneScan degrades gracefully rather than crashing
    the scan.

    Parameters
    ----------
    file_path : str
        Absolute or repo-relative path to the `.py` file.

    Returns
    -------
    list[CodeChunk]
        One entry per function/method definition found in the file.
        `line_start` and `line_end` are 1-indexed, inclusive.
    """
    path = Path(file_path)
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []

    source_lines = source.splitlines()
    chunks: list[CodeChunk] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        line_start: int = node.lineno  # 1-indexed
        # `end_lineno` was added in Python 3.8; always available here since
        # we parse with the same interpreter that runs the scanner.
        line_end: int = node.end_lineno or node.lineno  # type: ignore[attr-defined]

        # Slice the source lines (0-indexed slice of 1-indexed line numbers)
        func_lines = source_lines[line_start - 1 : line_end]
        raw_text = "\n".join(func_lines)
        normalized = _normalize(raw_text)

        if not normalized:
            continue

        chunks.append(
            CodeChunk(
                file_path=file_path,
                function_name=node.name,
                line_start=line_start,
                line_end=line_end,
                text=normalized,
            )
        )

    return chunks
