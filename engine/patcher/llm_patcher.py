"""
LLM Patcher — the fallback path when no deterministic fix exists for a
finding's rule_id. Called ONLY with the minimal "Best Related Neighbours"
subgraph produced by ast_context_extractor.py, never the whole file.

This module is intentionally provider-agnostic at the HTTP layer: it speaks
the OpenAI-compatible chat-completions shape, which DeepSeek Coder (the
deck's stated self-hosted model), Ollama, vLLM, and most self-hosted
inference servers all implement. Swapping providers is a base-URL change,
not a code change.

Token-efficiency note: the prompt deliberately does NOT ask the model to
explain its reasoning or wrap the answer in prose — we want exactly one
code block back, because every extra token here is context that the
"Best Related Neighbours" extraction worked hard to avoid spending on.
"""

import os
import re
from dataclasses import dataclass

import httpx
from dotenv import load_dotenv

from engine.models import Finding
from engine.patcher.ast_context_extractor import ExtractedContext

load_dotenv()

LLM_API_URL = os.environ.get(
    "LLM_API_URL", "http://localhost:11434/v1/chat/completions"
)
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_MODEL = os.environ.get("LLM_MODEL", "deepseek-coder")
LLM_REQUEST_TIMEOUT_SECONDS = 60
LLM_MAX_TOKENS = 600  # the whole point of minimal context is a small response too

_SYSTEM_PROMPT = """You are a security patch generator. You will be given:
1. A vulnerability rule ID and CWE reference
2. A minimal code snippet containing ONLY the vulnerable code and its \
direct dependencies (not the whole file)

Your job: rewrite the snippet to fix the security issue while preserving \
its exact behavior for all non-malicious inputs. Do not change the \
function signature, do not rename variables, do not add error handling \
beyond what the fix strictly requires, and do not add explanatory comments.

Respond with ONLY the corrected code in a single ```python code block. \
No prose before or after the code block."""

_USER_PROMPT_TEMPLATE = """Rule: {rule_id}
CWE: {cwe}
Issue: {message}

Vulnerable snippet:
```python
{snippet}
```

Return the fixed version of this exact snippet."""


@dataclass
class LlmPatchResult:
    patched_source: str
    raw_model_output: str
    model_used: str


class LlmPatchError(Exception):
    """Raised when the LLM call fails or returns an unusable response."""


def _build_messages(finding: Finding, context: ExtractedContext) -> list[dict]:
    user_prompt = _USER_PROMPT_TEMPLATE.format(
        rule_id=finding.rule_id,
        cwe=finding.cwe or "N/A",
        message=finding.message,
        snippet=context.source,
    )
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]


def _extract_code_block(model_output: str) -> str | None:
    """
    Pulls the contents of the first ```python ... ``` (or bare ``` ... ```)
    fenced block out of the model's response. Returns None if no fenced
    block is found, since that means the model didn't follow the
    "code only" instruction and we shouldn't guess at parsing prose as code.
    """
    fenced = re.search(r"```(?:python)?\s*\n(.*?)```", model_output, re.DOTALL)
    if fenced:
        return fenced.group(1).rstrip()
    return None


async def generate_llm_patch_async(
    finding: Finding, context: ExtractedContext
) -> LlmPatchResult:
    messages = _build_messages(finding, context)
    payload = {
        "model": LLM_MODEL,
        "messages": messages,
        "max_tokens": LLM_MAX_TOKENS,
        "temperature": 0.0,  # deterministic-as-possible; this is a patch, not creative writing
    }
    headers = {"Content-Type": "application/json"}
    if LLM_API_KEY:
        headers["Authorization"] = f"Bearer {LLM_API_KEY}"

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                LLM_API_URL,
                json=payload,
                headers=headers,
                timeout=LLM_REQUEST_TIMEOUT_SECONDS,
            )
    except (httpx.TimeoutException, httpx.TransportError) as exc:
        raise LlmPatchError(f"LLM request failed: {exc}") from exc

    if resp.status_code != 200:
        raise LlmPatchError(
            f"LLM endpoint returned HTTP {resp.status_code}: {resp.text[:300]}"
        )

    try:
        data = resp.json()
        model_output = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, ValueError) as exc:
        raise LlmPatchError(f"Unexpected LLM response shape: {exc}") from exc

    patched = _extract_code_block(model_output)
    if patched is None:
        raise LlmPatchError("LLM response did not contain a fenced code block")

    return LlmPatchResult(
        patched_source=patched,
        raw_model_output=model_output,
        model_used=data.get("model", LLM_MODEL),
    )


def is_llm_configured() -> bool:
    """
    Lets callers check whether an LLM endpoint is actually reachable-in-
    principle before attempting a call — e.g. the CLI can skip straight to
    "flag for manual review" instead of waiting out a connection-refused
    timeout when no LLM_API_URL was ever configured for this environment.
    """
    return bool(os.environ.get("LLM_API_URL"))
