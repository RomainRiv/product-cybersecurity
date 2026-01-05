"""Unit tests for CLI functions."""

import pytest

from product_cybersecurity.cli.main import _get_severity


class TestGetSeverity:
    """Tests for _get_severity helper function."""

    def test_cvss_v4_preferred(self):
        """CVSS v4.0 should be preferred over other versions."""
        row = {
            "cvss_v4": 8.5,
            "cvss_v3_1": 7.5,
            "cvss_v3": 7.0,
            "cvss_v2": 6.5,
            "severity_text": "High",
        }
        score, version = _get_severity(row)
        assert score == "8.5"
        assert version == "v4.0"

    def test_cvss_v3_1_second(self):
        """CVSS v3.1 should be used when v4.0 not available."""
        row = {
            "cvss_v4": None,
            "cvss_v3_1": 7.5,
            "cvss_v3": 7.0,
            "cvss_v2": 6.5,
            "severity_text": "High",
        }
        score, version = _get_severity(row)
        assert score == "7.5"
        assert version == "v3.1"

    def test_cvss_v3_fallback(self):
        """CVSS v3.0 should be used when v3.1 not available."""
        row = {
            "cvss_v4": None,
            "cvss_v3_1": None,
            "cvss_v3": 7.0,
            "cvss_v2": 6.5,
            "severity_text": None,
        }
        score, version = _get_severity(row)
        assert score == "7.0"
        assert version == "v3.0"

    def test_adp_cvss_with_asterisk(self):
        """ADP scores should be marked with asterisk."""
        row = {
            "cvss_v4": None,
            "cvss_v3_1": None,
            "cvss_v3": None,
            "adp_cvss_v4": None,
            "adp_cvss_v3_1": 9.8,
            "adp_cvss_v3": None,
            "cvss_v2": None,
            "adp_cvss_v2": None,
            "severity_text": None,
        }
        score, version = _get_severity(row)
        assert score == "9.8"
        assert version == "v3.1*"

    def test_cvss_v2_fallback(self):
        """CVSS v2.0 should be used as last CVSS fallback."""
        row = {
            "cvss_v4": None,
            "cvss_v3_1": None,
            "cvss_v3": None,
            "adp_cvss_v4": None,
            "adp_cvss_v3_1": None,
            "adp_cvss_v3": None,
            "cvss_v2": 5.0,
            "adp_cvss_v2": None,
            "severity_text": None,
        }
        score, version = _get_severity(row)
        assert score == "5.0"
        assert version == "v2.0"

    def test_text_severity_fallback(self):
        """Text severity should be used when no CVSS available."""
        row = {
            "cvss_v4": None,
            "cvss_v3_1": None,
            "cvss_v3": None,
            "adp_cvss_v4": None,
            "adp_cvss_v3_1": None,
            "adp_cvss_v3": None,
            "cvss_v2": None,
            "adp_cvss_v2": None,
            "severity_text": "High",
        }
        score, version = _get_severity(row)
        assert score == "High"
        assert version == "text"

    def test_no_severity_returns_dash(self):
        """No severity info should return dashes."""
        row = {
            "cvss_v4": None,
            "cvss_v3_1": None,
            "cvss_v3": None,
            "adp_cvss_v4": None,
            "adp_cvss_v3_1": None,
            "adp_cvss_v3": None,
            "cvss_v2": None,
            "adp_cvss_v2": None,
            "severity_text": None,
        }
        score, version = _get_severity(row)
        assert score == "-"
        assert version == "-"

    def test_empty_row(self):
        """Empty row should return dashes."""
        score, version = _get_severity({})
        assert score == "-"
        assert version == "-"

    def test_score_formatting(self):
        """Score should be formatted with one decimal place."""
        row = {"cvss_v3_1": 7.123456}
        score, version = _get_severity(row)
        assert score == "7.1"  # Rounded to one decimal

    def test_zero_score(self):
        """Zero score should be displayed, not treated as missing."""
        row = {"cvss_v3_1": 0.0}
        score, version = _get_severity(row)
        assert score == "0.0"
        assert version == "v3.1"


class TestOutputFormat:
    """Tests for output format options."""

    def test_output_format_values(self):
        """OutputFormat should have expected values."""
        from product_cybersecurity.cli.main import OutputFormat

        assert OutputFormat.JSON == "json"
        assert OutputFormat.TABLE == "table"
        assert OutputFormat.MARKDOWN == "markdown"
