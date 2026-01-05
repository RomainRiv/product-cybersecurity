"""Integration tests for the CVE analyzer."""

import polars as pl
import pytest

from product_cybersecurity.core.config import Config
from product_cybersecurity.models.cve_model import CveJsonRecordFormat
from product_cybersecurity.services.extractor import (
    ExtractorService,
    _extract_single_cve,
)
from product_cybersecurity.services.search import CVESearchService


class TestExtractionToSearchPipeline:
    """Integration tests for the extract -> search pipeline."""

    def test_extract_and_search_single_cve(self, sample_cve_files):
        """Test extracting a CVE and then searching for it."""
        # Extract
        extractor = ExtractorService(config=sample_cve_files)
        result = extractor.extract_all(years=[2022])

        assert "cves" in result
        assert result["cves"].exists()

        # Search
        search = CVESearchService(config=sample_cve_files)
        search_result = search.by_id("CVE-2022-2196")

        assert search_result.count == 1
        cve = search_result.to_dicts()[0]
        assert cve["id"] == "CVE-2022-2196"
        assert cve["cvss_v3_1"] == 5.8

    def test_extract_and_search_by_product(self, sample_cve_files):
        """Test extracting CVEs and searching by product."""
        # Extract all sample years
        extractor = ExtractorService(config=sample_cve_files)
        extractor.extract_all(years=[2016, 2022, 2023, 2024])

        # Search by product
        search = CVESearchService(config=sample_cve_files)
        result = search.by_product("OpenSSL")

        assert result.count >= 1
        cve_ids = [c["id"] for c in result.to_dicts()]
        assert "CVE-2016-7054" in cve_ids

    def test_extract_and_search_by_cwe(self, sample_cve_files):
        """Test extracting CVEs and searching by CWE."""
        extractor = ExtractorService(config=sample_cve_files)
        extractor.extract_all(years=[2022])

        search = CVESearchService(config=sample_cve_files)
        result = search.by_cwe("CWE-1188")

        assert result.count >= 1
        cve_ids = [c["id"] for c in result.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

    def test_extract_preserves_severity_text(self, sample_cve_files):
        """Test that text severity is preserved through extraction."""
        extractor = ExtractorService(config=sample_cve_files)
        extractor.extract_all(years=[2016])

        search = CVESearchService(config=sample_cve_files)
        result = search.by_id("CVE-2016-7054")

        assert result.count == 1
        cve = result.to_dicts()[0]
        assert cve["severity_text"] == "High"
        assert cve["cvss_v3_1"] is None

    def test_extract_adp_metrics(self, sample_cve_files):
        """Test that ADP metrics are extracted."""
        extractor = ExtractorService(config=sample_cve_files)
        extractor.extract_all(years=[2024])

        search = CVESearchService(config=sample_cve_files)
        result = search.by_id("CVE-2024-1234")

        assert result.count == 1
        cve = result.to_dicts()[0]
        assert cve["adp_cvss_v3_1"] == 9.8


class TestCVEDataIntegrity:
    """Tests for data integrity through the pipeline."""

    def test_all_fields_extracted(self, sample_cve_files):
        """Test that all expected fields are extracted."""
        from tests.conftest import SAMPLE_CVE_2022_2196

        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_2022_2196)
        result = _extract_single_cve(cve_model)

        cve = result.cve
        assert cve.id == "CVE-2022-2196"
        assert cve.state == "PUBLISHED"
        assert cve.assigner == "Google"
        assert cve.title is not None
        assert cve.description is not None
        assert cve.date_published is not None
        assert cve.cvss_v3_1 == 5.8
        assert cve.cvss_v3_1_vector is not None

    def test_products_have_required_fields(self, sample_cve_files):
        """Test that products have required fields."""
        from tests.conftest import SAMPLE_CVE_2022_2196

        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_2022_2196)
        result = _extract_single_cve(cve_model)

        assert len(result.products) >= 1
        product = result.products[0]
        assert product.cve_id == "CVE-2022-2196"
        assert product.vendor == "Linux"
        assert product.product == "Linux Kernel"

    def test_cwes_have_required_fields(self, sample_cve_files):
        """Test that CWE mappings have required fields."""
        from tests.conftest import SAMPLE_CVE_2022_2196

        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_2022_2196)
        result = _extract_single_cve(cve_model)

        assert len(result.cwes) >= 1
        cwe = result.cwes[0]
        assert cwe.cve_id == "CVE-2022-2196"
        assert cwe.cwe_id == "CWE-1188"


class TestParquetOutput:
    """Tests for Parquet file output."""

    def test_parquet_files_created(self, sample_cve_files):
        """Test that extraction creates Parquet files."""
        extractor = ExtractorService(config=sample_cve_files)
        extractor.extract_all(years=[2022])

        assert sample_cve_files.cves_parquet.exists()
        assert sample_cve_files.cve_products_parquet.exists()
        assert sample_cve_files.cve_cwe_parquet.exists()

    def test_parquet_readable(self, sample_cve_files):
        """Test that Parquet files are readable."""
        extractor = ExtractorService(config=sample_cve_files)
        extractor.extract_all(years=[2022])

        cves_df = pl.read_parquet(sample_cve_files.cves_parquet)
        assert len(cves_df) >= 1
        assert "id" in cves_df.columns
        assert "state" in cves_df.columns
        assert "cvss_v3_1" in cves_df.columns

    def test_parquet_schema(self, sample_cve_files):
        """Test that Parquet files have expected schema."""
        extractor = ExtractorService(config=sample_cve_files)
        extractor.extract_all(years=[2022])

        cves_df = pl.read_parquet(sample_cve_files.cves_parquet)

        expected_columns = [
            "id",
            "state",
            "assigner",
            "title",
            "description",
            "date_published",
            "cvss_v3_1",
            "severity_text",
        ]
        for col in expected_columns:
            assert col in cves_df.columns, f"Missing column: {col}"


class TestSearchWithRealData:
    """Tests using real CVE data from the repository (if available)."""

    @pytest.fixture
    def real_config(self):
        """Get config pointing to real data directory."""
        config = Config()
        if not config.cves_parquet.exists():
            pytest.skip("Real CVE data not available - run 'cve extract' first")
        return config

    def test_search_known_cve(self, real_config):
        """Test searching for a known CVE in real data."""
        search = CVESearchService(config=real_config)
        result = search.by_id("CVE-2024-6387")  # regreSSHion

        if result.count == 0:
            pytest.skip("CVE-2024-6387 not in extracted data")

        cve = result.to_dicts()[0]
        assert cve["id"] == "CVE-2024-6387"
        assert cve["state"] == "PUBLISHED"

    def test_search_openssl_cves(self, real_config):
        """Test searching for OpenSSL CVEs in real data."""
        search = CVESearchService(config=real_config)
        result = search.by_product("openssl", fuzzy=True)

        # There should be many OpenSSL CVEs
        assert result.count > 0

    def test_search_critical_severity(self, real_config):
        """Test searching for critical CVEs in real data."""
        search = CVESearchService(config=real_config)
        result = search.by_severity("critical")

        # There should be many critical CVEs
        assert result.count > 0

        # All should have high CVSS
        for cve in result.to_dicts()[:10]:  # Check first 10
            # Get best score
            best = (
                cve.get("cvss_v4")
                or cve.get("cvss_v3_1")
                or cve.get("cvss_v3")
                or cve.get("adp_cvss_v4")
                or cve.get("adp_cvss_v3_1")
                or cve.get("adp_cvss_v3")
                or cve.get("cvss_v2")
                or cve.get("adp_cvss_v2")
            )
            if best is not None:
                assert best >= 9.0, f"CVE {cve['id']} has score {best}, expected >= 9.0"
