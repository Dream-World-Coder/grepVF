"""
tests/test_entropy_checker.py

Covers: shannon_entropy(), scan_file_for_secrets(), run_entropy_checker(),
SECRET_REGEXES shape, placeholder suppression, false-positive guards.
"""

import math

import pytest

from engine.codescan.entropy_checker import (
    SECRET_REGEXES,
    _looks_like_hash_or_uuid,
    _value_is_placeholder,
    run_entropy_checker,
    scan_file_for_secrets,
    shannon_entropy,
)
from engine.models import Category, Severity


class TestShannonEntropy:
    def test_empty_string_returns_zero(self):
        assert shannon_entropy("") == 0.0

    def test_single_char_returns_zero(self):
        assert shannon_entropy("aaaaaaa") == 0.0

    def test_two_equal_chars_returns_one(self):
        # "ababab" → 50/50 split → exactly 1.0 bit
        assert math.isclose(shannon_entropy("abababab"), 1.0, abs_tol=1e-9)

    def test_uniform_returns_log2_alphabet(self):
        # 4 equally frequent chars → log2(4) = 2.0 bits
        s = "abcdabcdabcdabcd"
        assert math.isclose(shannon_entropy(s), 2.0, abs_tol=0.01)

    def test_high_entropy_random_string(self):
        # base64-ish token should be well above threshold (4.3)
        token = "aB3dEf7GhIjKlMnOpQrStUvWxYz012345"
        assert shannon_entropy(token) > 4.0

    def test_low_entropy_repeated_string(self):
        assert shannon_entropy("aaaaaaaaaaaaaaaaaaaaaa") < 1.0


class TestPlaceholderGuard:
    def test_changeme_is_placeholder(self):
        assert _value_is_placeholder("changeme")

    def test_long_repeated_char_is_placeholder(self):
        assert _value_is_placeholder("XXXXXXXXXXXXXXXXXXXX")

    def test_all_zeros_is_placeholder(self):
        assert _value_is_placeholder("00000000000000000000")

    def test_real_token_is_not_placeholder(self):
        assert not _value_is_placeholder("aB3dEf7GhIjKlMnOpQrS")


class TestHashOrUuidGuard:
    def test_md5_hex_is_hash(self):
        assert _looks_like_hash_or_uuid("d41d8cd98f00b204e9800998ecf8427e")

    def test_sha1_hex_is_hash(self):
        assert _looks_like_hash_or_uuid("da39a3ee5e6b4b0d3255bfef95601890afd80709")

    def test_sha256_hex_is_hash(self):
        assert _looks_like_hash_or_uuid(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_uuid_is_uuid(self):
        assert _looks_like_hash_or_uuid("550e8400-e29b-41d4-a716-446655440000")

    def test_random_token_is_not_hash(self):
        assert not _looks_like_hash_or_uuid("aB3dEf7GhIjKlMnOpQrStUvWxYz012345")


class TestSecretRegexes:
    def test_each_entry_has_four_fields(self):
        for entry in SECRET_REGEXES:
            assert len(entry) == 4, f"Expected 4 fields, got {len(entry)}: {entry}"

    def test_aws_access_key_pattern_matches(self):
        pattern = next(p for p, rid, *_ in SECRET_REGEXES if rid == "aws-access-key-id")
        assert pattern.search("AKIAIOSFODNN7EXAMPLEKEY")

    def test_aws_access_key_pattern_no_match_short(self):
        pattern = next(p for p, rid, *_ in SECRET_REGEXES if rid == "aws-access-key-id")
        assert not pattern.search("AKIA123")

    def test_stripe_live_key_pattern_matches(self):
        pattern = next(
            p for p, rid, *_ in SECRET_REGEXES if rid == "stripe-live-secret-key"
        )
        assert pattern.search("sk_live_abcdef1234567890abcd")

    def test_github_pat_pattern_matches(self):
        pattern = next(
            p for p, rid, *_ in SECRET_REGEXES if rid == "github-personal-access-token"
        )
        assert pattern.search("ghp_" + "A" * 36)

    def test_jwt_pattern_matches(self):
        pattern = next(p for p, rid, *_ in SECRET_REGEXES if rid == "jwt-token")
        assert pattern.search(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )

    def test_private_key_pattern_matches(self):
        pattern = next(
            p for p, rid, *_ in SECRET_REGEXES if rid == "private-key-in-source"
        )
        assert pattern.search("-----BEGIN RSA PRIVATE KEY-----")


class TestScanFileForSecrets:
    def test_aws_key_detected(self):
        content = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLEKEY"\n'
        findings = scan_file_for_secrets("test.env", content)
        rule_ids = [f.rule_id for f in findings]
        assert "aws-access-key-id" in rule_ids

    def test_aws_key_finding_is_critical(self):
        content = 'key = "AKIAIOSFODNN7EXAMPLEKEY"\n'
        findings = scan_file_for_secrets("test.env", content)
        critical = [f for f in findings if f.rule_id == "aws-access-key-id"]
        assert all(f.severity == Severity.CRITICAL for f in critical)

    def test_github_pat_detected(self):
        pat = "ghp_" + "B" * 36
        content = f'token = "{pat}"\n'
        findings = scan_file_for_secrets("config.py", content)
        assert any(f.rule_id == "github-personal-access-token" for f in findings)

    def test_db_connection_string_detected(self):
        content = 'DB = "postgres://user:password@host:5432/db"\n'
        findings = scan_file_for_secrets("settings.py", content)
        assert any(f.rule_id == "hardcoded-db-connection-string" for f in findings)

    def test_private_key_detected(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n"
        findings = scan_file_for_secrets("id_rsa", content)
        assert any(f.rule_id == "private-key-in-source" for f in findings)

    def test_placeholder_suppressed(self):
        # "your_secret_here" should not trigger generic credential rule
        content = 'api_key = "your_secret_here_replace_me"\n'
        findings = scan_file_for_secrets("config.py", content)
        assert len(findings) == 0

    def test_no_false_positive_on_safe_code(self):
        content = (
            "import os\nSECRET_KEY = os.environ.get('SECRET_KEY')\nDEBUG = False\n"
        )
        findings = scan_file_for_secrets("settings.py", content)
        assert len(findings) == 0

    def test_finding_has_correct_category(self):
        content = 'key = "AKIAIOSFODNN7EXAMPLEKEY"\n'
        findings = scan_file_for_secrets("f.env", content)
        assert all(f.category == Category.SECRET for f in findings)

    def test_finding_has_correct_file_path(self):
        content = 'key = "AKIAIOSFODNN7EXAMPLEKEY"\n'
        findings = scan_file_for_secrets("my/path/f.env", content)
        assert all(f.file_path == "my/path/f.env" for f in findings)

    def test_finding_has_cwe_798(self):
        content = 'key = "AKIAIOSFODNN7EXAMPLEKEY"\n'
        findings = scan_file_for_secrets("f.env", content)
        assert any(f.cwe == "CWE-798" for f in findings)

    def test_matched_code_is_redacted(self):
        """Secret values must never appear verbatim in the report output."""
        secret = "AKIAIOSFODNN7EXAMPLEKEY"
        content = f'key = "{secret}"\n'
        findings = scan_file_for_secrets("f.env", content)
        for f in findings:
            assert secret not in (f.matched_code or "")

    def test_high_entropy_string_detected(self):
        # 34-char mixed alphanum token with high entropy — no matching regex
        content = 'token = "aB3dEf7GhIjKlMnOpQrStUvWxYz012345"\n'
        findings = scan_file_for_secrets("app.py", content)
        entropy_findings = [f for f in findings if f.rule_id == "high-entropy-string"]
        assert len(entropy_findings) >= 1

    def test_high_entropy_finding_is_medium_severity(self):
        content = 'token = "aB3dEf7GhIjKlMnOpQrStUvWxYz012345"\n'
        findings = scan_file_for_secrets("app.py", content)
        for f in findings:
            if f.rule_id == "high-entropy-string":
                assert f.severity == Severity.MEDIUM

    def test_no_double_report_on_same_line(self):
        """A regex match on a line must suppress the entropy pass for that line."""
        pat = "ghp_" + "Z" * 36
        content = f'GITHUB_TOKEN = "{pat}"\n'
        findings = scan_file_for_secrets("env.py", content)
        # should only appear once (regex), not twice (regex + entropy)
        assert len(findings) == 1

    def test_empty_content_returns_no_findings(self):
        assert scan_file_for_secrets("empty.py", "") == []


class TestRunEntropyChecker:
    def test_detects_secret_in_env_file(self, repo_with_secrets, tmp_path):
        result = run_entropy_checker(str(repo_with_secrets), [".env"])
        assert len(result.findings) > 0

    def test_returns_scan_result_with_engine_name(self, repo_with_secrets):
        result = run_entropy_checker(str(repo_with_secrets), [".env"])
        assert result.engine == "entropy_checker"

    def test_files_scanned_count(self, repo_with_secrets):
        result = run_entropy_checker(str(repo_with_secrets), [".env", "config.py"])
        assert result.files_scanned == 2

    def test_empty_paths_list_returns_no_findings(self, tmp_repo):
        result = run_entropy_checker(str(tmp_repo), [])
        assert result.findings == []
        assert result.files_scanned == 0

    def test_missing_file_adds_error_not_crash(self, tmp_repo):
        result = run_entropy_checker(str(tmp_repo), ["does_not_exist.env"])
        # Should gracefully record an error instead of raising
        assert result.errors  # at least one error recorded
        assert result.findings == []

    def test_clean_file_produces_no_findings(self, repo_clean):
        result = run_entropy_checker(str(repo_clean), ["safe.py"])
        assert result.findings == []
