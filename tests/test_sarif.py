"""Tests for SARIF output formatter."""

import json
import pytest
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from deepsweep.reporters.sarif import (
    generate_sarif,
    format_sarif,
    _severity_to_level,
    _severity_to_score,
)
from deepsweep.core.types import ValidationResult, Finding


class TestSarifGeneration:
    """Test SARIF document generation."""

    def test_basic_sarif_structure(self):
        """SARIF document has required structure."""
        result = ValidationResult(
            version="1.2.0",
            score=85,
            grade="B",
            findings=[],
        )

        sarif = generate_sarif(result)

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "DeepSweep"

    def test_finding_to_result(self):
        """Findings are correctly mapped to SARIF results."""
        finding = Finding(
            pattern_id="DS-CRED-001",
            severity="critical",
            title="Hardcoded Credentials",
            description="Password found in source code",
            plain_english="Anyone who sees your code can log into your database",
            file_path="config.py",
            line_number=42,
            remediation="Move to environment variable",
        )

        result = ValidationResult(
            version="1.2.0",
            score=60,
            grade="D",
            findings=[finding],
        )

        sarif = generate_sarif(result)

        assert len(sarif["runs"][0]["results"]) == 1
        sarif_result = sarif["runs"][0]["results"][0]

        assert sarif_result["ruleId"] == "DS-CRED-001"
        assert sarif_result["level"] == "error"
        assert "log into your database" in sarif_result["message"]["text"]
        assert sarif_result["locations"][0]["physicalLocation"]["region"]["startLine"] == 42

    def test_remediation_as_fix(self):
        """Remediation text appears in SARIF fixes."""
        finding = Finding(
            pattern_id="DS-PI-001",
            severity="high",
            title="Prompt Injection",
            description="Instruction override detected",
            file_path=".cursorrules",
            line_number=15,
            remediation="Remove 'ignore previous' patterns",
        )

        result = ValidationResult(
            version="1.2.0",
            score=70,
            grade="C",
            findings=[finding],
        )

        sarif = generate_sarif(result)
        sarif_result = sarif["runs"][0]["results"][0]

        assert "fixes" in sarif_result
        assert "How to address" in sarif_result["fixes"][0]["description"]["text"]

    def test_multiple_findings_same_rule(self):
        """Multiple findings with same pattern_id produce one rule."""
        finding1 = Finding(
            pattern_id="DS-CRED-001",
            severity="critical",
            title="Hardcoded Credentials",
            description="Password found in source code",
            file_path="config.py",
            line_number=42,
        )

        finding2 = Finding(
            pattern_id="DS-CRED-001",
            severity="critical",
            title="Hardcoded Credentials",
            description="Password found in source code",
            file_path="settings.py",
            line_number=15,
        )

        result = ValidationResult(
            version="1.2.0",
            score=40,
            grade="F",
            findings=[finding1, finding2],
        )

        sarif = generate_sarif(result)

        # Should have 2 results but only 1 rule
        assert len(sarif["runs"][0]["results"]) == 2
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1

    def test_cve_ids_as_tags(self):
        """CVE IDs appear as tags in rule properties."""
        finding = Finding(
            pattern_id="DS-VULN-001",
            severity="critical",
            title="Known Vulnerability",
            description="Vulnerable dependency",
            file_path="package.json",
            line_number=10,
            cve_ids=["CVE-2024-1234", "CVE-2024-5678"],
        )

        result = ValidationResult(
            version="1.2.0",
            score=50,
            grade="F",
            findings=[finding],
        )

        sarif = generate_sarif(result)
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]

        assert "tags" in rule["properties"]
        assert "CVE-2024-1234" in rule["properties"]["tags"]


class TestSeverityMapping:
    """Test severity to SARIF level mapping."""

    @pytest.mark.parametrize("severity,expected", [
        ("critical", "error"),
        ("high", "error"),
        ("medium", "warning"),
        ("low", "note"),
        ("info", "note"),
    ])
    def test_severity_to_level(self, severity, expected):
        assert _severity_to_level(severity) == expected

    @pytest.mark.parametrize("severity,expected", [
        ("critical", "9.0"),
        ("high", "7.0"),
        ("medium", "4.0"),
        ("low", "2.0"),
    ])
    def test_severity_to_score(self, severity, expected):
        assert _severity_to_score(severity) == expected

    def test_unknown_severity_defaults(self):
        """Unknown severity returns default values."""
        assert _severity_to_level("unknown") == "warning"
        assert _severity_to_score("unknown") == "5.0"


class TestSarifJson:
    """Test SARIF JSON output."""

    def test_valid_json(self):
        """Output is valid JSON."""
        result = ValidationResult(
            version="1.2.0",
            score=100,
            grade="A",
            findings=[],
        )

        sarif_str = format_sarif(result)

        # Should not raise
        parsed = json.loads(sarif_str)
        assert parsed["version"] == "2.1.0"

    def test_json_is_indented(self):
        """JSON output is properly indented for readability."""
        result = ValidationResult(
            version="1.2.0",
            score=100,
            grade="A",
            findings=[],
        )

        sarif_str = format_sarif(result)

        # Check for indentation (multiple lines)
        assert "\n" in sarif_str
        assert "  " in sarif_str  # 2-space indent


class TestValidationResultProperties:
    """Test ValidationResult dataclass properties."""

    def test_findings_count(self):
        """findings_count property returns correct count."""
        finding = Finding(
            pattern_id="DS-TEST-001",
            severity="low",
            title="Test",
            description="Test finding",
            file_path="test.py",
            line_number=1,
        )

        result = ValidationResult(
            version="1.2.0",
            score=90,
            grade="A",
            findings=[finding, finding, finding],
        )

        assert result.findings_count == 3

    def test_empty_findings(self):
        """Empty findings list works correctly."""
        result = ValidationResult(
            version="1.2.0",
            score=100,
            grade="A",
            findings=[],
        )

        assert result.findings_count == 0
        sarif = generate_sarif(result)
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
