"""Pytest fixtures for CVE analyzer tests."""

import json
import tempfile
from pathlib import Path
from typing import Generator

import polars as pl
import pytest

from product_cybersecurity.core.config import Config

# =============================================================================
# Sample CVE Data - Real-world examples
# =============================================================================

SAMPLE_CVE_2022_2196 = {
    "dataType": "CVE_RECORD",
    "dataVersion": "5.1",
    "cveMetadata": {
        "cveId": "CVE-2022-2196",
        "assignerOrgId": "14ed7db2-1595-443d-9d34-6215bf890778",
        "state": "PUBLISHED",
        "assignerShortName": "Google",
        "dateReserved": "2022-06-24T13:29:09.969Z",
        "datePublished": "2023-01-09T10:59:53.099Z",
        "dateUpdated": "2025-02-13T16:28:57.097Z",
    },
    "containers": {
        "cna": {
            "affected": [
                {
                    "defaultStatus": "unaffected",
                    "packageName": "KVM",
                    "product": "Linux Kernel",
                    "vendor": "Linux",
                    "versions": [
                        {
                            "lessThan": "6.2",
                            "status": "affected",
                            "version": "0",
                            "versionType": "custom",
                        }
                    ],
                }
            ],
            "descriptions": [
                {
                    "lang": "en",
                    "value": "A regression exists in the Linux Kernel within KVM.",
                }
            ],
            "metrics": [
                {
                    "cvssV3_1": {
                        "attackComplexity": "HIGH",
                        "attackVector": "LOCAL",
                        "availabilityImpact": "LOW",
                        "baseScore": 5.8,
                        "baseSeverity": "MEDIUM",
                        "confidentialityImpact": "LOW",
                        "integrityImpact": "HIGH",
                        "privilegesRequired": "LOW",
                        "scope": "UNCHANGED",
                        "userInteraction": "NONE",
                        "vectorString": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L",
                        "version": "3.1",
                    }
                }
            ],
            "problemTypes": [
                {
                    "descriptions": [
                        {
                            "cweId": "CWE-1188",
                            "description": "CWE-1188 Insecure Default Initialization",
                            "lang": "en",
                            "type": "CWE",
                        }
                    ]
                }
            ],
            "providerMetadata": {
                "orgId": "14ed7db2-1595-443d-9d34-6215bf890778",
                "shortName": "Google",
                "dateUpdated": "2023-05-03T00:06:59.149Z",
            },
            "references": [{"url": "https://kernel.dance/#2e7eab81425a"}],
            "title": "KVM nVMX Spectre v2 vulnerability",
        }
    },
}

# CVE with text severity (no CVSS)
SAMPLE_CVE_TEXT_SEVERITY = {
    "dataType": "CVE_RECORD",
    "dataVersion": "5.1",
    "cveMetadata": {
        "cveId": "CVE-2016-7054",
        "assignerOrgId": "3a12439a-4ef3-4c79-92e6-6081a721f1e5",
        "state": "PUBLISHED",
        "assignerShortName": "openssl",
        "datePublished": "2017-05-04T00:00:00.000Z",
    },
    "containers": {
        "cna": {
            "affected": [
                {
                    "product": "OpenSSL",
                    "vendor": "OpenSSL",
                    "versions": [{"status": "affected", "version": "1.1.0"}],
                }
            ],
            "descriptions": [
                {"lang": "en", "value": "ChaCha20/Poly1305 heap-buffer-overflow"}
            ],
            "metrics": [{"other": {"content": {"value": "High"}, "type": "unknown"}}],
            "problemTypes": [
                {
                    "descriptions": [
                        {
                            "cweId": "CWE-119",
                            "description": "CWE-119 Buffer Errors",
                            "lang": "en",
                            "type": "CWE",
                        }
                    ]
                }
            ],
            "providerMetadata": {
                "orgId": "3a12439a-4ef3-4c79-92e6-6081a721f1e5",
                "shortName": "openssl",
            },
            "references": [{"url": "https://www.openssl.org/news/secadv/20161110.txt"}],
            "title": "ChaCha20/Poly1305 heap-buffer-overflow",
        }
    },
}

# CVE with no severity at all
SAMPLE_CVE_NO_SEVERITY = {
    "dataType": "CVE_RECORD",
    "dataVersion": "5.1",
    "cveMetadata": {
        "cveId": "CVE-2023-0001",
        "assignerOrgId": "14ed7db2-4595-443d-9d34-6215bf890778",
        "state": "PUBLISHED",
        "assignerShortName": "test",
        "datePublished": "2023-01-01T00:00:00.000Z",
    },
    "containers": {
        "cna": {
            "affected": [{"product": "TestProduct", "vendor": "TestVendor"}],
            "descriptions": [
                {"lang": "en", "value": "Test vulnerability with no severity"}
            ],
            "providerMetadata": {
                "orgId": "14ed7db2-4595-443d-9d34-6215bf890778",
                "shortName": "test",
            },
            "references": [{"url": "https://example.com/advisory"}],
        }
    },
}

# CVE with ADP metrics
SAMPLE_CVE_WITH_ADP = {
    "dataType": "CVE_RECORD",
    "dataVersion": "5.1",
    "cveMetadata": {
        "cveId": "CVE-2024-1234",
        "assignerOrgId": "14ed7db2-4595-443d-9d34-6215bf890778",
        "state": "PUBLISHED",
        "assignerShortName": "test",
        "datePublished": "2024-06-01T00:00:00.000Z",
    },
    "containers": {
        "cna": {
            "affected": [{"product": "SomeProduct", "vendor": "SomeVendor"}],
            "descriptions": [{"lang": "en", "value": "Test with ADP metrics"}],
            "providerMetadata": {
                "orgId": "14ed7db2-4595-443d-9d34-6215bf890778",
                "shortName": "test",
            },
            "references": [{"url": "https://example.com/advisory"}],
        },
        "adp": [
            {
                "providerMetadata": {
                    "orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                    "shortName": "CISA-ADP",
                },
                "metrics": [
                    {
                        "cvssV3_1": {
                            "attackComplexity": "LOW",
                            "attackVector": "NETWORK",
                            "availabilityImpact": "HIGH",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "HIGH",
                            "privilegesRequired": "NONE",
                            "scope": "UNCHANGED",
                            "userInteraction": "NONE",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "version": "3.1",
                        }
                    }
                ],
            }
        ],
    },
}


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def temp_data_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test data."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_config(temp_data_dir: Path) -> Config:
    """Create a Config pointing to temporary directories."""
    # Create subdirectories - Config will derive cve_dir from data_dir
    cve_dir = temp_data_dir / "cve_github" / "individual"
    cve_dir.mkdir(parents=True)

    config = Config(
        data_dir=temp_data_dir,
    )
    return config


@pytest.fixture
def sample_cve_files(temp_config: Config) -> Config:
    """Create sample CVE JSON files in temp directory."""
    # Create year directories and files
    for sample, year in [
        (SAMPLE_CVE_2022_2196, "2022"),
        (SAMPLE_CVE_TEXT_SEVERITY, "2016"),
        (SAMPLE_CVE_NO_SEVERITY, "2023"),
        (SAMPLE_CVE_WITH_ADP, "2024"),
    ]:
        year_dir = temp_config.cve_dir / year
        year_dir.mkdir(parents=True, exist_ok=True)

        cve_id = sample["cveMetadata"]["cveId"]
        filepath = year_dir / f"{cve_id}.json"
        with open(filepath, "w") as f:
            json.dump(sample, f)

    return temp_config


@pytest.fixture
def sample_parquet_data(temp_config: Config) -> Config:
    """Create sample Parquet files for search tests."""
    # CVEs table
    cves_data = [
        {
            "id": "CVE-2022-2196",
            "assigner": "Google",
            "state": "PUBLISHED",
            "date_published": "2023-01-09",
            "title": "KVM nVMX Spectre v2 vulnerability",
            "description": "A regression exists in the Linux Kernel within KVM.",
            "cvss_v3_1": 5.8,
            "cvss_v3_1_vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L",
            "severity_text": None,
        },
        {
            "id": "CVE-2016-7054",
            "assigner": "openssl",
            "state": "PUBLISHED",
            "date_published": "2017-05-04",
            "title": "ChaCha20/Poly1305 heap-buffer-overflow",
            "description": "Heap buffer overflow in OpenSSL",
            "cvss_v3_1": None,
            "cvss_v3_1_vector": None,
            "severity_text": "High",
        },
        {
            "id": "CVE-2023-0001",
            "assigner": "test",
            "state": "PUBLISHED",
            "date_published": "2023-01-01",
            "title": "Test vulnerability",
            "description": "Test vulnerability with no severity",
            "cvss_v3_1": None,
            "cvss_v3_1_vector": None,
            "severity_text": None,
        },
        {
            "id": "CVE-2024-1234",
            "assigner": "test",
            "state": "PUBLISHED",
            "date_published": "2024-06-01",
            "title": "Test with ADP",
            "description": "Test with ADP metrics",
            "cvss_v3_1": None,
            "cvss_v3_1_vector": None,
            "adp_cvss_v3_1": 9.8,
            "severity_text": None,
        },
    ]

    # Add missing columns to all rows
    for row in cves_data:
        for col in [
            "cvss_v2",
            "cvss_v3",
            "cvss_v4",
            "adp_cvss_v2",
            "adp_cvss_v3",
            "adp_cvss_v3_1",
            "adp_cvss_v4",
        ]:
            if col not in row:
                row[col] = None

    cves_df = pl.DataFrame(cves_data)
    cves_df.write_parquet(temp_config.cves_parquet)

    # Products table
    products_data = [
        {"cve_id": "CVE-2022-2196", "vendor": "Linux", "product": "Linux Kernel"},
        {"cve_id": "CVE-2016-7054", "vendor": "OpenSSL", "product": "OpenSSL"},
        {"cve_id": "CVE-2023-0001", "vendor": "TestVendor", "product": "TestProduct"},
        {"cve_id": "CVE-2024-1234", "vendor": "SomeVendor", "product": "SomeProduct"},
    ]
    products_df = pl.DataFrame(products_data)
    products_df.write_parquet(temp_config.cve_products_parquet)

    # CWE table
    cwe_data = [
        {"cve_id": "CVE-2022-2196", "cwe_id": "CWE-1188"},
        {"cve_id": "CVE-2016-7054", "cwe_id": "CWE-119"},
    ]
    cwe_df = pl.DataFrame(cwe_data)
    cwe_df.write_parquet(temp_config.cve_cwe_parquet)

    return temp_config


@pytest.fixture
def mock_row_with_cvss() -> dict:
    """Sample row with CVSS v3.1 score."""
    return {
        "id": "CVE-2022-2196",
        "cvss_v4": None,
        "cvss_v3_1": 5.8,
        "cvss_v3": None,
        "cvss_v2": None,
        "adp_cvss_v4": None,
        "adp_cvss_v3_1": None,
        "adp_cvss_v3": None,
        "adp_cvss_v2": None,
        "severity_text": None,
    }


@pytest.fixture
def mock_row_with_text_severity() -> dict:
    """Sample row with text severity only."""
    return {
        "id": "CVE-2016-7054",
        "cvss_v4": None,
        "cvss_v3_1": None,
        "cvss_v3": None,
        "cvss_v2": None,
        "adp_cvss_v4": None,
        "adp_cvss_v3_1": None,
        "adp_cvss_v3": None,
        "adp_cvss_v2": None,
        "severity_text": "High",
    }


@pytest.fixture
def mock_row_no_severity() -> dict:
    """Sample row with no severity information."""
    return {
        "id": "CVE-2023-0001",
        "cvss_v4": None,
        "cvss_v3_1": None,
        "cvss_v3": None,
        "cvss_v2": None,
        "adp_cvss_v4": None,
        "adp_cvss_v3_1": None,
        "adp_cvss_v3": None,
        "adp_cvss_v2": None,
        "severity_text": None,
    }


@pytest.fixture
def mock_row_with_adp() -> dict:
    """Sample row with ADP CVSS score."""
    return {
        "id": "CVE-2024-1234",
        "cvss_v4": None,
        "cvss_v3_1": None,
        "cvss_v3": None,
        "cvss_v2": None,
        "adp_cvss_v4": None,
        "adp_cvss_v3_1": 9.8,
        "adp_cvss_v3": None,
        "adp_cvss_v2": None,
        "severity_text": None,
    }
