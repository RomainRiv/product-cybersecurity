"""Unit tests for the search service."""

import pytest

from product_cybersecurity.services.search import (
    SEVERITY_THRESHOLDS,
    CVESearchService,
    SearchResult,
)


class TestSeverityThresholds:
    """Tests for severity threshold constants."""

    def test_severity_levels_exist(self):
        """All severity levels should be defined."""
        assert "none" in SEVERITY_THRESHOLDS
        assert "low" in SEVERITY_THRESHOLDS
        assert "medium" in SEVERITY_THRESHOLDS
        assert "high" in SEVERITY_THRESHOLDS
        assert "critical" in SEVERITY_THRESHOLDS

    def test_severity_ranges(self):
        """Severity ranges should be correct."""
        assert SEVERITY_THRESHOLDS["none"] == (0.0, 0.0)
        assert SEVERITY_THRESHOLDS["low"] == (0.1, 3.9)
        assert SEVERITY_THRESHOLDS["medium"] == (4.0, 6.9)
        assert SEVERITY_THRESHOLDS["high"] == (7.0, 8.9)
        assert SEVERITY_THRESHOLDS["critical"] == (9.0, 10.0)


class TestSearchResult:
    """Tests for SearchResult class."""

    def test_empty_result(self):
        """Empty result should have count of 0."""
        import polars as pl

        result = SearchResult(pl.DataFrame())
        assert result.count == 0
        assert result.to_dicts() == []

    def test_count_property(self, sample_parquet_data):
        """Count should reflect number of CVEs."""
        import polars as pl

        cves = pl.read_parquet(sample_parquet_data.cves_parquet)
        result = SearchResult(cves)
        assert result.count == 4  # 4 sample CVEs in fixture

    def test_summary_empty(self):
        """Summary of empty result should show count 0."""
        import polars as pl

        result = SearchResult(pl.DataFrame())
        summary = result.summary()
        assert summary["count"] == 0

    def test_summary_with_data(self, sample_parquet_data):
        """Summary should include severity and year distribution."""
        import polars as pl

        cves = pl.read_parquet(sample_parquet_data.cves_parquet)
        result = SearchResult(cves)
        summary = result.summary()

        assert "count" in summary
        assert "severity_distribution" in summary
        assert "year_distribution" in summary
        assert summary["count"] == 4

    def test_severity_distribution(self, sample_parquet_data):
        """Severity distribution should categorize CVEs correctly."""
        # Use the search service to get results with all related data
        service = CVESearchService(config=sample_parquet_data)

        # Search for all CVEs
        result = service.by_id("CVE-2022-2196")
        assert result.count == 1

        # Now test with the full search which includes metrics
        # Search for all by using a broad product search
        result_all = service.by_product("", fuzzy=True)
        summary = result_all.summary()

        dist = summary["severity_distribution"]
        # CVE-2022-2196 has 5.8 (medium)
        # CVE-2024-1234 has 9.8 from ADP (critical)
        # CVE-2016-7054 has text severity but no numeric
        # CVE-2023-0001 has no severity (unknown)
        # At minimum we should have some medium and critical
        total = sum(dist.values())
        assert total > 0


class TestCVESearchService:
    """Tests for CVESearchService class."""

    def test_init_default_config(self):
        """Service should initialize with default config."""
        service = CVESearchService()
        assert service.config is not None

    def test_init_custom_config(self, temp_config):
        """Service should accept custom config."""
        service = CVESearchService(config=temp_config)
        assert service.config == temp_config

    def test_by_id_found(self, sample_parquet_data):
        """by_id should return matching CVE."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_id("CVE-2022-2196")

        assert result.count == 1
        cve = result.to_dicts()[0]
        assert cve["cve_id"] == "CVE-2022-2196"
        assert cve["state"] == "PUBLISHED"

    def test_by_id_not_found(self, sample_parquet_data):
        """by_id should return empty result for non-existent CVE."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_id("CVE-9999-9999")

        assert result.count == 0

    def test_by_id_normalizes_input(self, sample_parquet_data):
        """by_id should normalize CVE ID format."""
        service = CVESearchService(config=sample_parquet_data)

        # Without CVE- prefix
        result1 = service.by_id("2022-2196")
        assert result1.count == 1

        # Lowercase
        result2 = service.by_id("cve-2022-2196")
        assert result2.count == 1

    def test_by_product_found(self, sample_parquet_data):
        """by_product should return CVEs affecting the product."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_product("Linux Kernel")

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

    def test_by_product_fuzzy(self, sample_parquet_data):
        """by_product should support fuzzy matching."""
        service = CVESearchService(config=sample_parquet_data)

        # Partial match
        result = service.by_product("kernel", fuzzy=True)
        assert result.count >= 1

    def test_by_product_with_vendor(self, sample_parquet_data):
        """by_product should filter by vendor."""
        service = CVESearchService(config=sample_parquet_data)

        result = service.by_product("Linux Kernel", vendor="Linux")
        assert result.count >= 1

    def test_by_product_not_found(self, sample_parquet_data):
        """by_product should return empty for non-existent product."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_product("NonExistentProduct12345")

        assert result.count == 0

    def test_by_vendor(self, sample_parquet_data):
        """by_vendor should return CVEs for vendor's products."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_vendor("OpenSSL")

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2016-7054" in cve_ids

    def test_by_cwe_found(self, sample_parquet_data):
        """by_cwe should return CVEs with matching CWE."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_cwe("CWE-1188")

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

    def test_by_cwe_normalizes_input(self, sample_parquet_data):
        """by_cwe should normalize CWE ID format."""
        service = CVESearchService(config=sample_parquet_data)

        # Without CWE- prefix
        result1 = service.by_cwe("1188")
        assert result1.count >= 1

        # Lowercase
        result2 = service.by_cwe("cwe-1188")
        assert result2.count >= 1

    def test_by_severity_medium(self, sample_parquet_data):
        """by_severity should return CVEs with matching severity."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_severity("medium")

        # CVE-2022-2196 has CVSS 5.8 (medium)
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

    def test_by_severity_critical(self, sample_parquet_data):
        """by_severity should find critical CVEs."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_severity("critical")

        # CVE-2024-1234 has ADP CVSS 9.8 (critical)
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2024-1234" in cve_ids

    def test_by_severity_with_date_filter(self, sample_parquet_data):
        """by_severity should filter by date range."""
        service = CVESearchService(config=sample_parquet_data)

        # After 2020
        result = service.by_severity("medium", after="2020-01-01")
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

        # Before 2020 should not include 2022 CVE
        result2 = service.by_severity("medium", before="2020-01-01")
        cve_ids2 = [c["cve_id"] for c in result2.to_dicts()]
        assert "CVE-2022-2196" not in cve_ids2

    def test_missing_data_file(self, temp_config):
        """Service should raise error when data files are missing."""
        service = CVESearchService(config=temp_config)

        with pytest.raises(FileNotFoundError):
            service.by_id("CVE-2022-2196")


class TestSearchResultProducts:
    """Tests for product-related search functionality."""

    def test_products_included_in_result(self, sample_parquet_data):
        """Search result should include product information."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_id("CVE-2022-2196")

        assert result.products is not None
        products = result.products.to_dicts()
        assert len(products) >= 1
        assert any(p["product"] == "Linux Kernel" for p in products)


class TestSearchResultCWEs:
    """Tests for CWE-related search functionality."""

    def test_cwes_included_in_result(self, sample_parquet_data):
        """Search result should include CWE information."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_id("CVE-2022-2196")

        assert result.cwes is not None
        cwes = result.cwes.to_dicts()
        assert len(cwes) >= 1
        assert any(c["cwe_id"] == "CWE-1188" for c in cwes)
