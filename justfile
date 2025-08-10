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
    cyber-data-graph-generator --capec-json data/capec.json --cwe-json data/cwe.json --graph-dir web/gen/graphs --md-dir web/gen

# Serve the website
serve:
    mkdir -p web/dist
    cp -r web/static/* web/dist/
    cp -r web/gen/* web/dist/
    open http://localhost:8000/visualizer.html?jsonfile=CAPEC-FULL.json
    (cd web/dist && python -m http.server 8000)

# Clean all generated artifacts
clean:
    rm -rf download data web/gen web/dist

# Visualize CVE data
cve-viz:
    cyber-data-cve-visualizer --cve-dir data/cve_github/individual/ --output-dir data