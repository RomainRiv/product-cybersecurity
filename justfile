# Justfile for CVE Analyzer

# Show help when running 'just' with no arguments
default:
    @just --list

# Run all steps: download and extract CVE data
all: download extract

# Download CAPEC, CWE and CVE data
download:
    uv run cve download --all

# Extract CVE data to Parquet format
extract:
    uv run cve extract --verbose

# Search CVEs by product name
search product:
    uv run cve search "{{product}}"

# Get details for a specific CVE
get cve_id:
    uv run cve get "{{cve_id}}"

# Show database statistics
stats:
    uv run cve stats

# Show recent CVEs (last 30 days)
recent:
    uv run cve recent

# Search CVEs in JSON format (for LLM consumption)
search-json product:
    uv run cve search "{{product}}" --format json

# Clean all generated artifacts
clean:
    rm -rf download data/*.parquet

# Full clean including all data
clean-all:
    rm -rf download data
