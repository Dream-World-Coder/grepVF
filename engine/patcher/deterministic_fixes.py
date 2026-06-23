"""
Deterministic Fixes — a rule_id -> fix-function table for vulnerabilities
where the correct remediation is mechanical and doesn't require an LLM to
reason about. This is always tried BEFORE falling back to the LLM patcher
(see patcher/patch_generator.py for the orchestration order).

Each fix function takes the offending line's raw text and the Finding that
described it, and returns either a replacement line string, or None if it
cannot confidently produce a fix for this specific occurrence (in which
case the caller falls through to the LLM path).

Design constraint: every fix here is a *textual, single-line* rewrite. This
keeps the fix trivially diffable and avoids needing a full AST rewrite
engine for the cases that don't actually need one. Multi-line or
structural rewrites (e.g. "wrap this in a parameterized query") are
deliberately NOT handled here — they get routed to the LLM with AST
context instead, because a wrong mechanical guess at a multi-line
rewrite is more dangerous than admitting "this needs judgment."
"""

import re
from dataclasses import dataclass
from typing import Callable, Optional

from engine.models import Finding


@dataclass
class DeterministicFixResult:
    fixed_line: str
    explanation: str


FixFunction = Callable[[str, Finding], Optional[DeterministicFixResult]]


def _fix_tls_verify_disabled(
    line: str, finding: Finding
) -> Optional[DeterministicFixResult]:
    if "verify=False" not in line:
        return None
    fixed = line.replace("verify=False", "verify=True")
    return DeterministicFixResult(
        fixed_line=fixed,
        explanation="Changed verify=False to verify=True to re-enable TLS certificate validation.",
    )


def _fix_tls_check_hostname_disabled(
    line: str, finding: Finding
) -> Optional[DeterministicFixResult]:
    m = re.search(r"(\w+)\.check_hostname\s*=\s*False", line)
    if not m:
        return None
    fixed = line.replace("check_hostname = False", "check_hostname = True").replace(
        "check_hostname=False", "check_hostname=True"
    )
    return DeterministicFixResult(
        fixed_line=fixed,
        explanation="Re-enabled hostname verification on the SSL context.",
    )


def _fix_weak_crypto_md5(
    line: str, finding: Finding
) -> Optional[DeterministicFixResult]:
    if "hashlib.md5(" in line:
        fixed = line.replace("hashlib.md5(", "hashlib.sha256(")
        return DeterministicFixResult(
            fixed_line=fixed,
            explanation=(
                "Replaced hashlib.md5 with hashlib.sha256. NOTE: if this hash is used for "
                "password storage (not just general integrity checking), sha256 is still not "
                "sufficient on its own — use a dedicated password-hashing KDF "
                "(bcrypt/argon2/scrypt) instead. This deterministic fix only addresses the "
                "'broken hash algorithm' issue, not password-storage best practice; flag for "
                "manual review if the call site is hashing a password."
            ),
        )
    m = re.search(r'hashlib\.new\(\s*["\']md5["\']', line)
    if m:
        fixed = re.sub(r'hashlib\.new\(\s*["\']md5["\']', 'hashlib.new("sha256"', line)
        return DeterministicFixResult(
            fixed_line=fixed, explanation="Replaced md5 with sha256 in hashlib.new()."
        )
    return None


def _fix_weak_crypto_sha1(
    line: str, finding: Finding
) -> Optional[DeterministicFixResult]:
    if "hashlib.sha1(" in line:
        fixed = line.replace("hashlib.sha1(", "hashlib.sha256(")
        return DeterministicFixResult(
            fixed_line=fixed, explanation="Replaced hashlib.sha1 with hashlib.sha256."
        )
    m = re.search(r'hashlib\.new\(\s*["\']sha1["\']', line)
    if m:
        fixed = re.sub(r'hashlib\.new\(\s*["\']sha1["\']', 'hashlib.new("sha256"', line)
        return DeterministicFixResult(
            fixed_line=fixed, explanation="Replaced sha1 with sha256 in hashlib.new()."
        )
    return None


def _fix_insecure_yaml_load(
    line: str, finding: Finding
) -> Optional[DeterministicFixResult]:
    patterns = [
        (
            r"yaml\.load\(([^,)]+),\s*Loader\s*=\s*yaml\.(Loader|UnsafeLoader|FullLoader)\)",
            r"yaml.safe_load(\1)",
        ),
        (r"yaml\.load\(([^,)]+)\)$", r"yaml.safe_load(\1)"),
    ]
    for pattern, replacement in patterns:
        if re.search(pattern, line):
            fixed = re.sub(pattern, replacement, line)
            return DeterministicFixResult(
                fixed_line=fixed,
                explanation="Replaced yaml.load() with yaml.safe_load() to prevent arbitrary object instantiation.",
            )
    return None


def _fix_debug_mode_enabled(
    line: str, finding: Finding
) -> Optional[DeterministicFixResult]:
    if re.search(r"\bDEBUG\s*=\s*True\b", line):
        fixed = re.sub(
            r"\bDEBUG\s*=\s*True\b",
            'DEBUG = os.environ.get("DJANGO_DEBUG", "False") == "True"',
            line,
        )
        return DeterministicFixResult(
            fixed_line=fixed,
            explanation=(
                "Replaced hardcoded DEBUG=True with an environment-variable-driven flag "
                "that defaults to False. Requires `import os` at the top of the file if "
                "not already present — flagged separately since this fix is single-line."
            ),
        )
    if re.search(r"\bapp\.debug\s*=\s*True\b", line):
        fixed = re.sub(
            r"\bapp\.debug\s*=\s*True\b",
            'app.debug = os.environ.get("FLASK_DEBUG") == "1"',
            line,
        )
        return DeterministicFixResult(
            fixed_line=fixed,
            explanation="Replaced hardcoded app.debug=True with an environment-driven flag.",
        )
    return None


def _fix_cors_wildcard_origin(
    line: str, finding: Finding
) -> Optional[DeterministicFixResult]:
    if 'CORS_ALLOWED_ORIGINS = ["*"]' in line or "CORS_ALLOWED_ORIGINS = ['*']" in line:
        fixed = line.replace('["*"]', '["https://yourdomain.example"]').replace(
            "['*']", "['https://yourdomain.example']"
        )
        return DeterministicFixResult(
            fixed_line=fixed,
            explanation=(
                "Replaced wildcard CORS origin with a placeholder explicit origin. "
                "REQUIRES MANUAL REVIEW: the placeholder domain must be replaced with "
                "your actual trusted origin(s) before merging — this cannot be inferred "
                "automatically."
            ),
        )
    return None


def _fix_insecure_cookie_flags(
    line: str, finding: Finding
) -> Optional[DeterministicFixResult]:
    for setting in (
        "SESSION_COOKIE_SECURE",
        "SESSION_COOKIE_HTTPONLY",
        "CSRF_COOKIE_SECURE",
    ):
        pattern = rf"\b{setting}\s*=\s*False\b"
        if re.search(pattern, line):
            fixed = re.sub(pattern, f"{setting} = True", line)
            return DeterministicFixResult(
                fixed_line=fixed, explanation=f"Set {setting} to True."
            )
    return None


def _fix_empty_database_password(
    line: str, finding: Finding
) -> Optional[DeterministicFixResult]:
    # Never auto-generate a password value — that would just hardcode a new
    # secret. Instead point at environment-variable loading, which is the
    # only safe mechanical fix here; the actual password value is a human
    # decision (rotate the DB credential, store in a secrets manager).
    if '"PASSWORD": ""' in line:
        fixed = line.replace(
            '"PASSWORD": ""', '"PASSWORD": os.environ.get("DB_PASSWORD", "")'
        )
        return DeterministicFixResult(
            fixed_line=fixed,
            explanation=(
                "Routed the PASSWORD field through an environment variable instead of "
                "an empty literal. REQUIRES MANUAL ACTION: set DB_PASSWORD in your "
                "deployment environment/secrets manager — this fix does not create a "
                "password, it only removes the hardcoded empty one."
            ),
        )
    return None


def _fix_weak_random_for_security(
    line: str, finding: Finding
) -> Optional[DeterministicFixResult]:
    if "random.randint(" in line:
        m = re.search(r"random\.randint\((\d+),\s*(\d+)\)", line)
        if m:
            lo, hi = m.group(1), m.group(2)
            replacement = f"secrets.randbelow({int(hi) - int(lo) + 1}) + {lo}"
            fixed = re.sub(r"random\.randint\(\d+,\s*\d+\)", replacement, line)
            return DeterministicFixResult(
                fixed_line=fixed,
                explanation=(
                    "Replaced random.randint() with secrets.randbelow() for a "
                    "cryptographically secure equivalent. Requires `import secrets`."
                ),
            )
    return None


def _fix_dockerfile_secret_env(
    line: str, finding: Finding
) -> Optional[DeterministicFixResult]:
    # Cannot be mechanically fixed without knowing the build system's
    # secret-injection mechanism — flag for manual review rather than
    # guess at a BuildKit --mount=type=secret rewrite that may not match
    # the team's actual CI setup.
    return None


def _fix_cve_dependency(line: str, finding: Finding) -> Optional[DeterministicFixResult]:
    fixed_version = finding.extra.get("fixed_version")
    if not fixed_version:
        return None

    installed_version = finding.extra.get("installed_version")
    package = finding.extra.get("package")
    canonical_line = finding.matched_code or line

    if installed_version and installed_version in canonical_line:
        fixed = canonical_line.replace(installed_version, fixed_version)
        return DeterministicFixResult(
            fixed_line=fixed,
            explanation=f"Bumped {package} from {installed_version} to {fixed_version} to fix {finding.rule_id}.",
        )
    return None

# Dispatch table: rule_id -> fix function. Rule IDs not present here always
# fall through to the LLM patcher (or manual review if LLM is unavailable).
DETERMINISTIC_FIX_TABLE: dict[str, FixFunction] = {
    "tls-verify-disabled": _fix_tls_verify_disabled,
    "tls-context-check-hostname-disabled": _fix_tls_check_hostname_disabled,
    "weak-crypto-md5": _fix_weak_crypto_md5,
    "weak-crypto-sha1": _fix_weak_crypto_sha1,
    "insecure-yaml-load": _fix_insecure_yaml_load,
    "debug-mode-enabled": _fix_debug_mode_enabled,
    "cors-wildcard-origin": _fix_cors_wildcard_origin,
    "insecure-cookie-flags": _fix_insecure_cookie_flags,
    "empty-database-password": _fix_empty_database_password,
    "weak-random-for-security": _fix_weak_random_for_security,
}


def try_deterministic_fix(
    line: str, finding: Finding
) -> Optional[DeterministicFixResult]:
    """
    Looks up the fix function for finding.rule_id and attempts it. Returns
    None (not an exception) for both "no fix function registered for this
    rule" and "fix function declined to handle this specific occurrence" —
    callers should treat both identically: fall through to the LLM path.
    """
    if finding.rule_id.startswith("cve-"):
        fix_fn = _fix_cve_dependency
    else:
        fix_fn = DETERMINISTIC_FIX_TABLE.get(finding.rule_id)
    if fix_fn is None:
        return None
    try:
        return fix_fn(line, finding)
    except re.error:
        return None
