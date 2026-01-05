"""Unit tests for the extractor service."""

from product_cybersecurity.models.cve_model import CveJsonRecordFormat
from product_cybersecurity.services.extractor import (
    CVEProduct,
    CVERecord,
    ExtractedData,
    _extract_single_cve,
    _get_iterable,
    _get_value,
)


class TestGetIterable:
    """Tests for _get_iterable helper function."""

    def test_none_returns_empty_list(self):
        """None should return empty list."""
        assert list(_get_iterable(None)) == []

    def test_list_returns_list(self):
        """List should be returned as-is."""
        items = [1, 2, 3]
        result = _get_iterable(items)
        assert list(result) == items

    def test_tuple_returns_tuple(self):
        """Tuple should be returned as-is."""
        items = (1, 2, 3)
        result = _get_iterable(items)
        assert list(result) == [1, 2, 3]

    def test_object_with_root_returns_root(self):
        """Object with .root attribute should return .root."""

        class MockPydantic:
            root = [1, 2, 3]

        result = _get_iterable(MockPydantic())
        assert list(result) == [1, 2, 3]

    def test_single_value_wrapped_in_list(self):
        """Single value should be wrapped in list."""
        result = _get_iterable("single")
        assert list(result) == ["single"]


class TestGetValue:
    """Tests for _get_value helper function."""

    def test_none_returns_none(self):
        """None should return None."""
        assert _get_value(None) is None

    def test_string_returns_string(self):
        """String should be returned as-is."""
        assert _get_value("test") == "test"

    def test_int_returns_string(self):
        """Integer should be converted to string."""
        assert _get_value(123) == "123"

    def test_object_with_root(self):
        """Object with .root should unwrap to .root value."""

        class MockPydantic:
            root = "wrapped_value"

        assert _get_value(MockPydantic()) == "wrapped_value"

    def test_nested_root(self):
        """Nested .root should be fully unwrapped."""

        class Inner:
            root = "final_value"

        class Outer:
            root = Inner()

        assert _get_value(Outer()) == "final_value"

    def test_enum_with_value(self):
        """Enum-like object with _value_ should return _value_."""
        from enum import Enum

        class State(Enum):
            PUBLISHED = "PUBLISHED"

        # After unwrapping, if it has _value_, use that
        assert _get_value(State.PUBLISHED) == "PUBLISHED"

    def test_object_with_root_and_value(self):
        """Object with both root and _value_ should unwrap root first."""

        class MockEnum:
            _value_ = "enum_val"

        class MockWrapper:
            root = MockEnum()

        result = _get_value(MockWrapper())
        assert result == "enum_val"


class TestCVERecordModel:
    """Tests for CVERecord Pydantic model."""

    def test_minimal_record(self):
        """Test creating a minimal CVE record."""
        record = CVERecord(id="CVE-2024-1234", state="PUBLISHED")
        assert record.id == "CVE-2024-1234"
        assert record.state == "PUBLISHED"
        assert record.cvss_v3_1 is None
        assert record.severity_text is None

    def test_full_record(self):
        """Test creating a full CVE record."""
        record = CVERecord(
            id="CVE-2024-1234",
            state="PUBLISHED",
            assigner="test",
            title="Test vulnerability",
            description="This is a test",
            cvss_v3_1=7.5,
            cvss_v3_1_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            severity_text=None,
        )
        assert record.cvss_v3_1 == 7.5
        assert record.description == "This is a test"


class TestCVEProductModel:
    """Tests for CVEProduct model."""

    def test_minimal_product(self):
        """Test creating a minimal product record."""
        product = CVEProduct(
            cve_id="CVE-2024-1234", vendor="TestVendor", product="TestProduct"
        )
        assert product.cve_id == "CVE-2024-1234"
        assert product.vendor == "TestVendor"
        assert product.product == "TestProduct"

    def test_product_with_version(self):
        """Test creating a product with version info."""
        product = CVEProduct(
            cve_id="CVE-2024-1234",
            vendor="Linux",
            product="Linux Kernel",
            version="5.0",
            less_than="6.2",
            status="affected",
        )
        assert product.less_than == "6.2"
        assert product.status == "affected"


class TestExtractSingleCVE:
    """Tests for _extract_single_cve function."""

    def test_extract_basic_cve(self):
        """Test extracting a basic CVE from JSON."""
        from tests.conftest import SAMPLE_CVE_2022_2196

        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_2022_2196)
        result = _extract_single_cve(cve_model)

        assert result.cve.id == "CVE-2022-2196"
        assert result.cve.state == "PUBLISHED"
        assert result.cve.cvss_v3_1 == 5.8
        assert result.cve.title == "KVM nVMX Spectre v2 vulnerability"
        assert "KVM" in (result.cve.description or "")

    def test_extract_products(self):
        """Test extracting affected products."""
        from tests.conftest import SAMPLE_CVE_2022_2196

        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_2022_2196)
        result = _extract_single_cve(cve_model)

        assert len(result.products) >= 1
        products = {(p.vendor, p.product) for p in result.products}
        assert ("Linux", "Linux Kernel") in products

    def test_extract_cwes(self):
        """Test extracting CWE mappings."""
        from tests.conftest import SAMPLE_CVE_2022_2196

        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_2022_2196)
        result = _extract_single_cve(cve_model)

        cwes = [c.cwe_id for c in result.cwes]
        assert "CWE-1188" in cwes

    def test_extract_text_severity(self):
        """Test extracting text severity when no CVSS present."""
        from tests.conftest import SAMPLE_CVE_TEXT_SEVERITY

        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_TEXT_SEVERITY)
        result = _extract_single_cve(cve_model)

        assert result.cve.cvss_v3_1 is None
        assert result.cve.severity_text == "High"

    def test_extract_no_severity(self):
        """Test extracting CVE with no severity info."""
        from tests.conftest import SAMPLE_CVE_NO_SEVERITY

        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_NO_SEVERITY)
        result = _extract_single_cve(cve_model)

        assert result.cve.cvss_v3_1 is None
        assert result.cve.cvss_v2 is None
        assert result.cve.severity_text is None

    def test_extract_adp_metrics(self):
        """Test extracting ADP metrics."""
        from tests.conftest import SAMPLE_CVE_WITH_ADP

        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_WITH_ADP)
        result = _extract_single_cve(cve_model)

        # CNA has no CVSS, but ADP should
        assert result.cve.cvss_v3_1 is None
        assert result.cve.adp_cvss_v3_1 == 9.8
