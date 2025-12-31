# AGENTS.md - AI Agent Guidelines for CVE Analyzer

This document provides guidance for AI agents working with this codebase.

## Project Overview

**cve-analyzer** is an LLM-oriented CVE (Common Vulnerabilities and Exposures) analysis tool. It provides Python tooling to:

1. Download CVE data from the official [cvelistV5](https://github.com/CVEProject/cvelistV5) repository
2. Extract and process CVE information into queryable formats (Parquet)
3. Search CVEs by product, vendor, severity, CWE, date range
4. Analyze dependency security history for SBOM integration

## Project Structure

```
product-cybersecurity/
├── AGENTS.md                 # This file - AI agent guidelines
├── README.md                 # User-facing documentation
├── pyproject.toml            # Python project configuration
├── justfile                  # Task runner commands
├── data/                     # Downloaded and processed CVE data
│   ├── cve_github/           # Raw CVE JSON files organized by year
│   │   └── individual/
│   │       └── {year}/       # CVE-YYYY-XXXX.json files
│   ├── cves.parquet          # Extracted CVE metadata
│   ├── cve_cwe.parquet       # CVE to CWE mappings
│   ├── cve_products.parquet  # CVE affected products
│   ├── capec.json            # CAPEC attack patterns
│   └── cwe.json              # CWE weakness definitions
├── download/                 # Temporary download location
└── src/product_cybersecurity/
    ├── __init__.py
    ├── cli/                  # CLI commands (Typer-based)
    │   ├── __init__.py
    │   └── main.py           # Main CLI entry point
    ├── core/                 # Core business logic
    │   ├── __init__.py
    │   └── config.py         # Configuration management
    ├── models/               # Pydantic data models
    │   ├── __init__.py
    │   ├── cve_model.py      # CVE JSON schema models (auto-generated)
    │   ├── capecparser.py    # CAPEC XML parser
    │   └── cweparser.py      # CWE XML parser
    ├── services/             # Service layer
    │   ├── __init__.py
    │   ├── downloader.py     # CVE/CWE/CAPEC download service
    │   ├── extractor.py      # CVE data extraction service
    │   └── search.py         # CVE search service
    └── utils/                # Utility functions
        ├── __init__.py
        └── output.py         # Output formatting (JSON, Markdown)
```

## CLI Commands

The main CLI is invoked via `cve` (or `uv run cve`):

```bash
# Download CVE data (last 10 years by default)
cve download [--years N] [--all]

# Extract CVE data into Parquet files
cve extract [--years N] [--verbose]

# Search CVEs by product, vendor, or CWE
cve search "openssl"                      # By product name
cve search "apache" --vendor "apache"     # With vendor filter
cve search "CWE-79"                       # By CWE (auto-detected)
cve search "nginx" --severity high        # By severity
cve search "log4j" --after 2024-01-01     # By date

# Get details for a specific CVE
cve get CVE-2024-1234
cve get CVE-2024-1234 --format json       # JSON output for LLMs
cve get CVE-2024-1234 --format markdown   # Markdown output

# Show recent CVEs
cve recent [--days 30]

# Database statistics
cve stats

# Output formats
cve search "nginx" --format table         # Human-readable (default)
cve search "nginx" --format json          # LLM-friendly JSON
cve search "nginx" --format markdown      # Markdown output
cve search "nginx" --verbose              # Include summary statistics
```

## Data Model

### CVE Record Fields

When working with CVE data, these are the key fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | str | CVE identifier (e.g., "CVE-2024-1234") |
| `state` | str | "PUBLISHED", "REJECTED", "RESERVED" |
| `date_published` | str | ISO timestamp of publication |
| `date_reserved` | str | ISO timestamp of reservation |
| `cvss_v3_1` | float | CVSS 3.1 base score (0.0-10.0) |
| `cvss_v4` | float | CVSS 4.0 base score |
| `cna_provider` | str | CVE Numbering Authority name |
| `assigner` | str | Organization that assigned the CVE |

### Severity Mapping

| CVSS Score | Severity |
|------------|----------|
| 0.0 | None |
| 0.1 - 3.9 | Low |
| 4.0 - 6.9 | Medium |
| 7.0 - 8.9 | High |
| 9.0 - 10.0 | Critical |

### Related Data

- **CWE (Common Weakness Enumeration)**: Describes the type of vulnerability
- **CAPEC (Common Attack Pattern Enumeration)**: Describes attack patterns
- **CPE (Common Platform Enumeration)**: Standardized product identifiers

## Key Modules for Agents

### For Searching CVEs

```python
from product_cybersecurity.core.config import Config
from product_cybersecurity.services.search import CVESearchService

config = Config()
search = CVESearchService(config)

# Search by product
results = search.by_product("openssl", fuzzy=True)
print(f"Found {len(results.cves)} CVEs")

# Search by CWE
results = search.by_cwe("CWE-79")

# Search by severity
results = search.by_severity("critical", after="2024-01-01")

# Get specific CVE
result = search.by_id("CVE-2024-1234")
```

### For Downloading Data

```python
from product_cybersecurity.core.config import Config
from product_cybersecurity.services.downloader import DownloadService

config = Config()
dl = DownloadService(config)
dl.download_cves()          # Downloads zip
dl.extract_cves()           # Extracts JSON files
dl.download_cwe()           # Download CWE data
dl.download_capec()         # Download CAPEC data
```

### For Extracting Data

```python
from product_cybersecurity.core.config import Config
from product_cybersecurity.services.extractor import ExtractorService

config = Config()
extractor = ExtractorService(config)
result = extractor.extract_all()
print(f"Extracted {result['cves']} CVEs")
```

## Common Tasks for Agents

### Task: Check if a dependency has security issues

```bash
# Quick search
cve search "requests" --format json

# With vendor filter
cve search "requests" --vendor "python" --format json
```

### Task: Get CVEs for an SBOM

When given a list of dependencies, iterate:

```python
from product_cybersecurity.core.config import Config
from product_cybersecurity.services.search import CVESearchService

config = Config()
search = CVESearchService(config)

for dep in dependencies:
    results = search.by_product(dep.name, vendor=dep.vendor, fuzzy=True)
    # Filter by version if needed
```

### Task: Understand a specific CVE

```bash
cve get CVE-2024-1234 --format markdown --verbose
```

## Configuration

Configuration is managed via environment variables or `~/.config/cve-analyzer/config.toml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `CVE_DATA_DIR` | `./data` | Directory for CVE data |
| `CVE_DOWNLOAD_DIR` | `./download` | Temporary download directory |
| `CVE_DEFAULT_YEARS` | `10` | Default number of years to download |

## Error Handling

- All CLI commands return exit code 0 on success, non-zero on error
- JSON output includes an `"error"` field on failure
- Use `--quiet` to suppress progress output for scripted usage

## Performance Notes

- Initial download: ~2GB for 10 years of CVEs, takes 5-10 minutes
- Extraction: ~280k CVEs processed in parallel, takes 2-5 minutes
- Search: Parquet files enable fast columnar queries
- For repeated queries, data is cached in Parquet format

## Development

```bash
# Install dependencies
uv sync

# Run tests
just test

# Download and extract fresh data
just download
just extract

# Full pipeline
just all
```

## Extending This Project

### Adding MCP Server Support

The CLI is built with Typer, which maps cleanly to MCP tools:

1. Each CLI subcommand can become an MCP tool
2. Arguments become tool parameters
3. JSON output format is already MCP-compatible

### Adding New Search Criteria

1. Add column to extraction in `services/extractor.py`
2. Add filter method in `services/search.py`
3. Add CLI option in `cli/main.py`
