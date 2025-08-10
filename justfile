# Justfile for temp-product-cyber-data

# Show help when running 'just' with no arguments
default:
    @just --list

# Run all steps in order
all: download install generate

# Download CAPEC, CWE and CVE data
download:
    uv run src/product_cybersecurity/cli/downloader.py --capec-output download/capec/attack_patterns.xml --cwe-output download/cwe/cwec_v4.13.xml --cve-github-download-dir download/cve_github 


# Install (convert) CAPEC and CWE data to JSON and decompress CVEs
install: 
    uv run src/product_cybersecurity/cli/installer.py --capec-xml download/capec/attack_patterns.xml --capec-json data/capec.json --cwe-xml download/cwe/cwec_v4.13.xml --cwe-json data/cwe.json --github-cve-zip download/cve_github/cvelistV5-main.zip --github-cve-output-dir data/cve_github

# Generate graphs from JSON data
generate:
    uv run src/product_cybersecurity/cli/graph.py --capec-json data/capec.json --cwe-json data/cwe.json --graph-dir www/static/gen/graphs --md-dir www/content/gen/

build-local:
    hugo server -D --disableFastRender -b http://localhost:1313/

# Clean all generated artifacts
clean:
    rm -rf download data www/public/ docs/
