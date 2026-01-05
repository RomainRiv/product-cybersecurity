"""Unit tests for CLI functions."""

from unittest.mock import MagicMock

import pytest

from product_cybersecurity.cli.main import _get_severity


class TestGetSeverity:
    """Tests for _get_severity helper function using search_service.get_best_metric()."""

    def test_cvssv4_preferred(self):
        """CVSS v4.0 should be preferred over other versions."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV4_0",
            "source": "cna",
            "base_score": 8.5,
            "base_severity": "HIGH",
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version = _get_severity(row, mock_service)
        assert score == "8.5"
        assert version == "v4.0"

    def test_cvssv3_1_second(self):
        """CVSS v3.1 should be used when v4.0 not available."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV3_1",
            "source": "cna",
            "base_score": 7.5,
            "base_severity": "HIGH",
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version = _get_severity(row, mock_service)
        assert score == "7.5"
        assert version == "v3.1"

    def test_cvssv3_fallback(self):
        """CVSS v3.0 should be used when v3.1 not available."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV3_0",
            "source": "cna",
            "base_score": 7.0,
            "base_severity": "HIGH",
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version = _get_severity(row, mock_service)
        assert score == "7.0"
        assert version == "v3.0"

    def test_adp_cvss_with_asterisk(self):
        """ADP scores should be marked with asterisk."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV3_1",
            "source": "adp:CISA-ADP",
            "base_score": 9.8,
            "base_severity": "CRITICAL",
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version = _get_severity(row, mock_service)
        assert score == "9.8"
        assert version == "v3.1*"

    def test_cvssv2_fallback(self):
        """CVSS v2.0 should be used as last CVSS fallback."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV2_0",
            "source": "cna",
            "base_score": 5.0,
            "base_severity": "MEDIUM",
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version = _get_severity(row, mock_service)
        assert score == "5.0"
        assert version == "v2.0"

    def test_text_severity_fallback(self):
        """Text severity should return dash when metric only has base_severity but no score."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "other",
            "source": "cna",
            "base_score": None,
            "base_severity": "High",
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version = _get_severity(row, mock_service)
        # When there's no numeric score but there is severity text, show it
        assert score == "High"
        assert version == "text"

    def test_no_metric_returns_dash(self):
        """No metric should return dashes."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = None
        row = {"cve_id": "CVE-2024-1234"}
        score, version = _get_severity(row, mock_service)
        assert score == "-"
        assert version == "-"

    def test_no_service_returns_dash(self):
        """No search_service should return dashes."""
        row = {"cve_id": "CVE-2024-1234"}
        score, version = _get_severity(row, None)
        assert score == "-"
        assert version == "-"

    def test_score_formatting(self):
        """Score should be formatted with one decimal place."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV3_1",
            "source": "cna",
            "base_score": 7.123456,
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version = _get_severity(row, mock_service)
        assert score == "7.1"  # Rounded to one decimal

    def test_zero_score(self):
        """Zero score should be displayed, not treated as missing."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV3_1",
            "source": "cna",
            "base_score": 0.0,
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version = _get_severity(row, mock_service)
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
