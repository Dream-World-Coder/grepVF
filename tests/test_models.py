"""
tests/test_models.py — unit tests for engine/models.py

Covers: Severity enum helpers, Category enum, FixType enum,
Finding.dedup_key(), Finding.to_dict(), ScanResult dataclass.
"""

from engine.models import Category, Finding, FixType, ScanResult, Severity


class TestSeverity:
    def test_values_are_strings(self):
        for sev in Severity:
            assert isinstance(sev.value, str)

    def test_base_hazard_order(self):
        assert Severity.CRITICAL.base_hazard > Severity.HIGH.base_hazard
        assert Severity.HIGH.base_hazard > Severity.MEDIUM.base_hazard
        assert Severity.MEDIUM.base_hazard > Severity.LOW.base_hazard

    def test_base_hazard_values(self):
        assert Severity.CRITICAL.base_hazard == 9.0
        assert Severity.HIGH.base_hazard == 7.0
        assert Severity.MEDIUM.base_hazard == 4.0
        assert Severity.LOW.base_hazard == 2.0

    def test_sarif_level_critical_and_high_are_error(self):
        assert Severity.CRITICAL.sarif_level == "error"
        assert Severity.HIGH.sarif_level == "error"

    def test_sarif_level_medium_is_warning(self):
        assert Severity.MEDIUM.sarif_level == "warning"

    def test_sarif_level_low_is_note(self):
        assert Severity.LOW.sarif_level == "note"

    def test_enum_members(self):
        assert set(Severity) == {
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        }


class TestCategory:
    def test_all_expected_categories_present(self):
        expected = {
            "secret",
            "cve",
            "misconfiguration",
            "injection",
            "weak_crypto",
            "auth",
            "tls",
            "supply_chain",
            "other",
        }
        assert {c.value for c in Category} == expected


class TestFixType:
    def test_none_is_default_name(self):
        assert FixType.NONE.value == "none"

    def test_deterministic_value(self):
        assert FixType.DETERMINISTIC.value == "deterministic"

    def test_llm_value(self):
        assert FixType.LLM.value == "llm"

    def test_manual_review_value(self):
        assert FixType.MANUAL_REVIEW.value == "manual_review"


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        rule_id="test-rule",
        file_path="src/app.py",
        line=42,
        end_line=42,
        severity=Severity.HIGH,
        category=Category.INJECTION,
        message="Test finding message",
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestFinding:
    def test_dedup_key_is_16_hex_chars(self):
        f = _make_finding()
        key = f.dedup_key()
        assert len(key) == 16
        assert all(c in "0123456789abcdef" for c in key)

    def test_dedup_key_same_for_identical_file_line_rule(self):
        f1 = _make_finding()
        f2 = _make_finding(message="different message", category=Category.SECRET)
        assert f1.dedup_key() == f2.dedup_key()

    def test_dedup_key_differs_for_different_line(self):
        f1 = _make_finding(line=1)
        f2 = _make_finding(line=2)
        assert f1.dedup_key() != f2.dedup_key()

    def test_dedup_key_differs_for_different_rule(self):
        f1 = _make_finding(rule_id="rule-a")
        f2 = _make_finding(rule_id="rule-b")
        assert f1.dedup_key() != f2.dedup_key()

    def test_dedup_key_differs_for_different_file(self):
        f1 = _make_finding(file_path="a.py")
        f2 = _make_finding(file_path="b.py")
        assert f1.dedup_key() != f2.dedup_key()

    def test_to_dict_contains_required_keys(self):
        d = _make_finding().to_dict()
        required = {
            "rule_id",
            "file",
            "line",
            "end_line",
            "column",
            "end_column",
            "severity",
            "category",
            "message",
            "cwe",
            "matched_code",
            "source_engine",
            "hazard_score",
            "fix_type",
            "suggested_fix",
            "fix_validated",
        }
        assert required.issubset(d.keys())

    def test_to_dict_severity_is_string(self):
        d = _make_finding(severity=Severity.CRITICAL).to_dict()
        assert d["severity"] == "CRITICAL"

    def test_to_dict_category_is_string(self):
        d = _make_finding(category=Category.TLS).to_dict()
        assert d["category"] == "tls"

    def test_to_dict_fix_type_is_string(self):
        d = _make_finding(fix_type=FixType.DETERMINISTIC).to_dict()
        assert d["fix_type"] == "deterministic"

    def test_defaults_fix_type_none(self):
        f = _make_finding()
        assert f.fix_type == FixType.NONE
        assert f.suggested_fix is None
        assert f.fix_validated is False

    def test_extra_defaults_to_empty_dict(self):
        f = _make_finding()
        assert f.extra == {}

    def test_hazard_score_defaults_to_none(self):
        f = _make_finding()
        assert f.hazard_score is None


class TestScanResult:
    def test_basic_construction(self):
        findings = [_make_finding()]
        sr = ScanResult(findings=findings, engine="test_engine", files_scanned=3)
        assert sr.engine == "test_engine"
        assert sr.files_scanned == 3
        assert len(sr.findings) == 1

    def test_errors_default_to_empty_list(self):
        sr = ScanResult(findings=[], engine="e", files_scanned=0)
        assert sr.errors == []

    def test_errors_can_be_set(self):
        sr = ScanResult(findings=[], engine="e", files_scanned=0, errors=["oops"])
        assert sr.errors == ["oops"]
