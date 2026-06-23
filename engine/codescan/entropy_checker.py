"""
Entropy Checker — detects hardcoded secrets via two complementary methods:

1. Regex matching against known credential *shapes* (AWS keys, Stripe keys,
   JWTs, generic `api_key = "..."` assignments). High precision, but only
   catches secret formats we've explicitly enumerated.
2. Shannon-entropy scanning over string literals as a catch-all for secrets
   that don't match any known shape (custom internal tokens, random API
   keys with no recognizable prefix).

Running only regex misses novel secret formats; running only entropy
produces too many false positives on things like UUIDs, hashes, and base64
config blobs. Combining both, with regex matches taking priority and entropy
only flagged at MEDIUM severity, is the standard approach used by tools like
GitLeaks and TruffleHog.
"""

import math
import re
from dataclasses import dataclass
from pathlib import Path

from engine.models import Category, Finding, ScanResult, Severity

DEFAULT_MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB; secrets are never huge
ENTROPY_THRESHOLD = 4.3  # bits/char; tuned against benchmark fixture
MIN_TOKEN_LENGTH = 20  # shorter strings rarely carry real secrets
MAX_TOKEN_LENGTH = 200  # avoid flagging minified JS blobs etc.

# (compiled_pattern, rule_id, severity, human message)
SECRET_REGEXES: list[tuple[re.Pattern[str], str, Severity, str]] = [
    (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "aws-access-key-id",
        Severity.CRITICAL,
        "Hardcoded AWS Access Key ID detected.",
    ),
    (
        re.compile(r'(?i)aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
        "aws-secret-access-key",
        Severity.CRITICAL,
        "Hardcoded AWS Secret Access Key detected.",
    ),
    (
        re.compile(r"sk_live_[0-9a-zA-Z]{16,}"),
        "stripe-live-secret-key",
        Severity.CRITICAL,
        "Hardcoded Stripe LIVE secret key detected.",
    ),
    (
        re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
        "openai-style-api-key",
        Severity.HIGH,
        "Hardcoded API key matching OpenAI-style secret format.",
    ),
    (
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
        "github-personal-access-token",
        Severity.CRITICAL,
        "Hardcoded GitHub Personal Access Token detected.",
    ),
    (
        re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        "slack-token",
        Severity.HIGH,
        "Hardcoded Slack token detected.",
    ),
    (
        re.compile(r"https://hooks\.slack\.com/services/[A-Z0-9/]{20,}"),
        "slack-webhook-url",
        Severity.MEDIUM,
        "Hardcoded Slack webhook URL detected — allows posting to the channel without auth.",
    ),
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "jwt-token",
        Severity.HIGH,
        "Hardcoded JWT detected.",
    ),
    (
        re.compile(
            r'(?i)(postgres|postgresql|mysql|mongodb)://[^:\s]+:[^@\s]+@[^\s"\']+'
        ),
        "hardcoded-db-connection-string",
        Severity.CRITICAL,
        "Database connection string with embedded credentials detected.",
    ),
    (
        re.compile(
            r"(?i)(?:^|[^A-Za-z0-9])(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*"
            r'["\']([A-Za-z0-9_\-/+=!@#$%^&*]{12,})["\']'
        ),
        "generic-hardcoded-credential",
        Severity.HIGH,
        "Hardcoded credential-like assignment detected.",
    ),
    (
        re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----"),
        "private-key-in-source",
        Severity.CRITICAL,
        "Private key material embedded directly in a tracked file.",
    ),
    (
        # Catches long hex tokens (e.g. hand-rolled JWT secrets, API tokens)
        # assigned to a credential-sounding variable. Pure Shannon entropy
        # scanning misses these because hex strings have a small 16-char
        # alphabet and therefore inherently low entropy per character —
        # this regex exists specifically to cover that gap.
        re.compile(
            r"(?i)(?:^|[^A-Za-z0-9])(secret|token|key|signing[_-]?key)\s*[:=]\s*"
            r'["\']([0-9a-fA-F]{32,})["\']'
        ),
        "hardcoded-hex-secret",
        Severity.HIGH,
        "Hardcoded hex-encoded secret/token assigned to a credential variable.",
    ),
]

# Lines containing these tokens are almost always false positives even if
# they match a generic regex (placeholders, examples, test fixtures).
PLACEHOLDER_MARKERS = (
    "example",
    "xxxxxxxx",
    "your_",
    "changeme",
    "placeholder",
    "<",
    ">",
    "${",
    "{{",  # templating syntax
)


@dataclass
class _StringLiteral:
    value: str
    line: int
    column: int


def shannon_entropy(s: str) -> float:
    """Classic Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


_STRING_LITERAL_RE = re.compile(
    r'["\']([A-Za-z0-9_\-/+=]{%d,%d})["\']' % (MIN_TOKEN_LENGTH, MAX_TOKEN_LENGTH)
)


def _extract_string_literals(content: str) -> list[_StringLiteral]:
    """
    Pulls quoted string literals out of source text. This is a lightweight
    regex-based extraction (not a full tokenizer) so it works across any
    language without per-language parsers — acceptable here because the
    entropy pass is a catch-all, not the primary detection mechanism.
    """
    literals: list[_StringLiteral] = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        for m in _STRING_LITERAL_RE.finditer(line):
            literals.append(
                _StringLiteral(value=m.group(1), line=line_no, column=m.start() + 1)
            )
    return literals


def _looks_like_placeholder(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def _value_is_placeholder(value: str) -> bool:
    """
    Distinct from _looks_like_placeholder: this checks the *secret value
    itself* rather than the whole line, so a line containing a comment with
    "example" doesn't suppress a real-looking adjacent secret. A value is
    placeholder-like if it's a long run of a single repeated character
    (XXXX..., 0000...) or literally the word "example"/"changeme".
    """
    lowered = value.lower()
    if lowered in ("changeme", "placeholder") or "your_secret" in lowered:
        return True
    if len(set(value)) <= 2 and len(value) >= 8:
        return True  # e.g. "XXXXXXXXXXXX" or "00000000000"
    return False


def _looks_like_hash_or_uuid(token: str) -> bool:
    """
    Filters out common high-entropy-but-benign tokens: hex hashes (md5/sha
    digests, git commit SHAs) and UUIDs. These have high entropy by
    construction but are not secrets.
    """
    if re.fullmatch(r"[0-9a-fA-F]{32}", token):  # md5-length hex
        return True
    if re.fullmatch(r"[0-9a-fA-F]{40}", token):  # sha1-length hex
        return True
    if re.fullmatch(r"[0-9a-fA-F]{64}", token):  # sha256-length hex
        return True
    if re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        token,
    ):
        return True
    return False


def scan_file_for_secrets(file_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()

    # --- Pass 1: regex shape matching (high precision) ---
    matched_spans_by_line: dict[int, list[tuple[int, int]]] = {}
    for pattern, rule_id, severity, message in SECRET_REGEXES:
        for m in pattern.finditer(content):
            line_no = content.count("\n", 0, m.start()) + 1
            line_text = lines[line_no - 1] if line_no - 1 < len(lines) else ""

            # Prefer checking the captured secret value itself (group 1 or
            # the full match if the pattern has no groups) so an incidental
            # word like "example" elsewhere on the line doesn't suppress a
            # genuine adjacent secret.
            captured_value = m.group(m.lastindex) if m.lastindex else m.group(0)
            if _value_is_placeholder(captured_value):
                continue

            # Prevent double-reporting the same secret via multiple regexes
            is_overlap = False
            for start, end in matched_spans_by_line.get(line_no, []):
                if max(m.start(), start) < min(m.end(), end):
                    is_overlap = True
                    break
            if is_overlap:
                continue

            findings.append(
                Finding(
                    rule_id=rule_id,
                    file_path=file_path,
                    line=line_no,
                    end_line=line_no,
                    column=1,
                    end_column=len(line_text) + 1,
                    severity=severity,
                    category=Category.SECRET,
                    message=message,
                    cwe="CWE-798",
                    matched_code=_redact(line_text),
                    source_engine="entropy_checker.regex",
                )
            )
            matched_spans_by_line.setdefault(line_no, []).append((m.start(), m.end()))

    # --- Pass 2: entropy catch-all over remaining string literals ---
    for literal in _extract_string_literals(content):
        # skip if this exact line already produced a regex match — avoids
        # double-reporting the same secret via two engines
        if literal.line in matched_spans_by_line:
            continue

        line_text = lines[literal.line - 1] if literal.line - 1 < len(lines) else ""
        if _looks_like_placeholder(line_text):
            continue
        if _looks_like_hash_or_uuid(literal.value):
            continue

        entropy = shannon_entropy(literal.value)
        if entropy >= ENTROPY_THRESHOLD:
            findings.append(
                Finding(
                    rule_id="high-entropy-string",
                    file_path=file_path,
                    line=literal.line,
                    end_line=literal.line,
                    column=literal.column,
                    end_column=literal.column + len(literal.value),
                    severity=Severity.MEDIUM,
                    category=Category.SECRET,
                    message=(
                        f"String literal with high Shannon entropy "
                        f"({entropy:.2f} bits/char) resembles a hardcoded secret."
                    ),
                    cwe="CWE-798",
                    matched_code=_redact(line_text),
                    source_engine="entropy_checker.entropy",
                    extra={"entropy": round(entropy, 3)},
                )
            )

    return findings


def _redact(line: str, keep_prefix: int = 12) -> str:
    """Avoid echoing full secret values back into reports/PR comments."""
    stripped = line.strip()
    if len(stripped) <= keep_prefix:
        return "*" * len(stripped)
    return stripped[:keep_prefix] + "..." + "*" * 8


def run_entropy_checker(
    repo_root: str,
    relative_paths: list[str],
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
) -> ScanResult:
    """
    Entry point called by the orchestrator with the "secrets" queue produced
    by file_router.route_files(). `relative_paths` are relative to
    `repo_root`.
    """
    findings: list[Finding] = []
    errors: list[str] = []
    scanned = 0

    for rel_path in relative_paths:
        abs_path = Path(repo_root) / rel_path
        try:
            if abs_path.stat().st_size > max_file_size_bytes:
                continue
            content = abs_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            errors.append(f"{rel_path}: {exc}")
            continue

        findings.extend(scan_file_for_secrets(rel_path, content))
        scanned += 1

    return ScanResult(
        findings=findings,
        engine="entropy_checker",
        files_scanned=scanned,
        errors=errors,
    )
