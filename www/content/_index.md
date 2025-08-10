---
title: "Welcome"
date: 2025-08-10
type: page
---
# Product Cybersecurity Data

## Mitre data
### CAPECs
- [Complete CAPEC graph](visualizer.html?jsonfile=CAPEC-FULL.json) : contains every CAPECs, with edges between CAPECs that are related (`ChildOf` relationship)
- [Subgraphs per META CAPEC](gen/capecs/)

### CWEs
- [Complete CWE graph](visualizer.html?jsonfile=CWE-FULL.json) : contains every CWEs, with edges between CWEs that are related (`ChildOf` relationship)
- [Subgraphs per Pillar and Class CWEs](gen/cwes/)

### CAPECs + CWE
- ⚠️ This is quite resource heavy
- [CAPECs + CWE Graph](visualizer.html?jsonfile=FULL-FULL.json)

## CVEs
### CVEs, per CNA, per Year since 2015 (excluding MITRE)
<iframe src="datarace.html?csv=data/cve_per_cna_per_year_no_mitre_2015.csv&topN=10" width="100%" height="400"></iframe>

### CVEs, per CNA, per Year
<iframe src="datarace.html?csv=data/cve_per_cna_per_month_full.csv&topN=10" width="100%" height="400"></iframe>

### Number of CVEs
<iframe src="line_graph.html?csv=data/total_cves_per_month_cumulative.csv" width="100%" height="400"></iframe>

<iframe src="line_graph.html?csv=data/total_cves_per_month_published_cumulative.csv" width="100%" height="400"></iframe>

### CVEs per CWE per Year
<iframe src="datarace.html?csv=data/cve_per_cwe_per_year.csv&topN=10" width="100%" height="400"></iframe>