"""CVE data extraction service."""

import json
import os
from pathlib import Path
from typing import List, Optional, NamedTuple, Any, Iterable
import concurrent.futures

from pydantic import BaseModel
import polars as pl
from tqdm import tqdm

from product_cybersecurity.core.config import Config, get_config
from product_cybersecurity.models.cve_model import (
    CnaPublishedContainer, 
    CveJsonRecordFormat, 
    NoneScoreType, 
    Containers
)


def _get_iterable(obj: Any) -> Iterable:
    """Get an iterable from an object that may have .root or be a list itself."""
    if obj is None:
        return []
    if hasattr(obj, "root"):
        return obj.root
    if isinstance(obj, (list, tuple)):
        return obj
    return [obj]


def _get_value(obj: Any) -> Optional[str]:
    """Get string value from an object that may have .root or be a primitive.
    
    Recursively unwraps nested .root attributes until we get a primitive value.
    """
    if obj is None:
        return None
    
    # Recursively unwrap .root until we get to the actual value
    unwrapped = obj
    max_depth = 5  # Safety limit
    depth = 0
    while hasattr(unwrapped, "root") and depth < max_depth:
        unwrapped = unwrapped.root
        depth += 1
    
    # Handle enum-like objects with _value_
    if hasattr(unwrapped, "_value_"):
        return str(unwrapped._value_)
    
    return str(unwrapped) if unwrapped is not None else None


# =============================================================================
# Data Models - Comprehensive CVE representation
# =============================================================================

class CVERecord(BaseModel):
    """Extracted CVE metadata - main record."""
    # Identifiers
    id: str
    assigner: Optional[str] = None
    assigner_org_id: Optional[str] = None
    state: str
    
    # Dates
    date_reserved: Optional[str] = None
    date_published: Optional[str] = None
    date_updated: Optional[str] = None
    date_public: Optional[str] = None
    
    # Content
    title: Optional[str] = None
    description: Optional[str] = None
    
    # Severity - CNA scores
    cvss_v2: Optional[float] = None
    cvss_v2_vector: Optional[str] = None
    cvss_v3: Optional[float] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v3_1: Optional[float] = None
    cvss_v3_1_vector: Optional[str] = None
    cvss_v4: Optional[float] = None
    cvss_v4_vector: Optional[str] = None
    
    # Text-based severity (for CVEs without CVSS scores)
    severity_text: Optional[str] = None  # e.g., "High", "Medium", "Low", "Critical"
    
    # Severity - ADP scores (e.g., from CISA)
    adp_cvss_v2: Optional[float] = None
    adp_cvss_v2_vector: Optional[str] = None
    adp_cvss_v3: Optional[float] = None
    adp_cvss_v3_vector: Optional[str] = None
    adp_cvss_v3_1: Optional[float] = None
    adp_cvss_v3_1_vector: Optional[str] = None
    adp_cvss_v4: Optional[float] = None
    adp_cvss_v4_vector: Optional[str] = None
    
    # Provider info
    cna_provider: Optional[str] = None
    source_discovery: Optional[str] = None


class CVECWEMapping(BaseModel):
    """CVE to CWE mapping with description."""
    cve_id: str
    cwe_id: str
    cwe_description: Optional[str] = None
    source: str = "cna"  # "cna" or "adp"


class CVEProduct(BaseModel):
    """CVE affected product with version information."""
    cve_id: str
    vendor: str
    product: str
    # Version constraints
    version: Optional[str] = None
    version_type: Optional[str] = None  # semver, custom, etc.
    less_than: Optional[str] = None
    less_than_or_equal: Optional[str] = None
    status: Optional[str] = None  # affected, unaffected
    default_status: Optional[str] = None
    # Platform info
    platforms: Optional[str] = None  # comma-separated
    # Collector info (for deduplication)
    collector_product: Optional[str] = None
    collection_url: Optional[str] = None


class CVEReference(BaseModel):
    """CVE reference URL with metadata."""
    cve_id: str
    url: str
    name: Optional[str] = None
    tags: Optional[str] = None  # comma-separated: vendor-advisory, patch, etc.
    source: str = "cna"  # "cna" or "adp"


class CVECredit(BaseModel):
    """Credit for CVE discovery/remediation."""
    cve_id: str
    value: str  # Name/organization
    credit_type: Optional[str] = None  # finder, remediation developer, etc.
    lang: Optional[str] = None


class ExtractedData(NamedTuple):
    """Complete extracted data from a CVE."""
    cve: CVERecord
    cwes: List[CVECWEMapping]
    products: List[CVEProduct]
    references: List[CVEReference]
    credits: List[CVECredit]


# =============================================================================
# Extraction Logic
# =============================================================================

def _extract_single_cve(cve: CveJsonRecordFormat) -> ExtractedData:
    """Extract structured data from a single CVE record.
    
    Args:
        cve: Parsed CVE JSON record.
    
    Returns:
        ExtractedData with all CVE information.
    """
    cve_id = str(cve.root.cveMetadata.cveId.root)
    
    # Metadata
    assigner = cve.root.cveMetadata.assignerShortName.root if cve.root.cveMetadata.assignerShortName else None
    assigner_org_id = _get_value(cve.root.cveMetadata.assignerOrgId) if cve.root.cveMetadata.assignerOrgId else None
    state = cve.root.cveMetadata.state._value_
    
    # Dates from metadata
    date_reserved = cve.root.cveMetadata.dateReserved.root if cve.root.cveMetadata.dateReserved else None
    date_published = cve.root.cveMetadata.datePublished.root if cve.root.cveMetadata.datePublished else None
    date_updated = cve.root.cveMetadata.dateUpdated.root if cve.root.cveMetadata.dateUpdated else None
    
    # Initialize extraction variables
    title: Optional[str] = None
    description: Optional[str] = None
    date_public: Optional[str] = None
    source_discovery: Optional[str] = None
    severity_text: Optional[str] = None  # Text-based severity (High, Medium, Low, Critical)
    
    # CVSS scores and vectors
    cna_cvss_v2 = None
    cna_cvss_v2_vector = None
    cna_cvss_v3 = None
    cna_cvss_v3_vector = None
    cna_cvss_v3_1 = None
    cna_cvss_v3_1_vector = None
    cna_cvss_v4 = None
    cna_cvss_v4_vector = None
    
    adp_cvss_v2 = None
    adp_cvss_v2_vector = None
    adp_cvss_v3 = None
    adp_cvss_v3_vector = None
    adp_cvss_v3_1 = None
    adp_cvss_v3_1_vector = None
    adp_cvss_v4 = None
    adp_cvss_v4_vector = None
    
    cwe_list: List[CVECWEMapping] = []
    products: List[CVEProduct] = []
    references: List[CVEReference] = []
    credits_list: List[CVECredit] = []
    
    provider: Optional[str] = None
    
    # ==========================================================================
    # Extract from CNA container
    # ==========================================================================
    if isinstance(cve.root.containers.cna, CnaPublishedContainer):
        cna = cve.root.containers.cna
        
        # Title
        if hasattr(cna, "title") and cna.title:
            title = str(cna.title)
        
        # Description - get first English description
        if hasattr(cna, "descriptions") and cna.descriptions:
            for desc in cna.descriptions.root:
                if hasattr(desc, "value") and desc.value:
                    description = str(desc.value)
                    break
        
        # Date public
        if hasattr(cna, "datePublic") and cna.datePublic:
            date_public = str(cna.datePublic.root) if hasattr(cna.datePublic, "root") else str(cna.datePublic)
        
        # Source discovery
        if hasattr(cna, "source") and cna.source:
            if hasattr(cna.source, "discovery"):
                source_discovery = str(cna.source.discovery._value_) if hasattr(cna.source.discovery, "_value_") else str(cna.source.discovery)
        
        # CVSS scores from metrics
        if cna.metrics:
            for met in cna.metrics.root:
                if met.cvssV2_0 and met.cvssV2_0.baseScore:
                    cna_cvss_v2 = met.cvssV2_0.baseScore.root
                    if hasattr(met.cvssV2_0, "vectorString"):
                        cna_cvss_v2_vector = str(met.cvssV2_0.vectorString)
                if met.cvssV3_0 and met.cvssV3_0.baseScore and not isinstance(met.cvssV3_0.baseScore, NoneScoreType):
                    cna_cvss_v3 = met.cvssV3_0.baseScore.value
                    if hasattr(met.cvssV3_0, "vectorString"):
                        cna_cvss_v3_vector = str(met.cvssV3_0.vectorString)
                if met.cvssV3_1 and met.cvssV3_1.baseScore and not isinstance(met.cvssV3_1.baseScore, NoneScoreType):
                    cna_cvss_v3_1 = met.cvssV3_1.baseScore.value
                    if hasattr(met.cvssV3_1, "vectorString"):
                        cna_cvss_v3_1_vector = str(met.cvssV3_1.vectorString)
                if met.cvssV4_0 and met.cvssV4_0.root.baseScore:
                    cna_cvss_v4 = met.cvssV4_0.root.baseScore.value
                    if hasattr(met.cvssV4_0.root, "vectorString"):
                        cna_cvss_v4_vector = str(met.cvssV4_0.root.vectorString)
                
                # Extract "other" severity (for CVEs without CVSS scores)
                if hasattr(met, "other") and met.other:
                    if hasattr(met.other, "content") and isinstance(met.other.content, dict):
                        # Extract value from content dict (e.g., {"value": "High", ...})
                        sev_val = met.other.content.get("value")
                        if sev_val and isinstance(sev_val, str):
                            severity_text = sev_val
        
        # CWEs (problem types)
        if hasattr(cna, "problemTypes") and cna.problemTypes:
            for pt in cna.problemTypes.root:
                if hasattr(pt, "descriptions") and pt.descriptions:
                    for desc in pt.descriptions:
                        if hasattr(desc, "cweId") and desc.cweId:
                            cwe_desc = str(desc.description) if hasattr(desc, "description") and desc.description else None
                            cwe_list.append(CVECWEMapping(
                                cve_id=cve_id,
                                cwe_id=str(desc.cweId),
                                cwe_description=cwe_desc,
                                source="cna"
                            ))
        
        # Affected products with version info
        if getattr(cna, "affected", None):
            for prod in cna.affected.root:
                vendor = str(prod.vendor) if prod.vendor else None
                product_name = str(prod.product) if prod.product else None
                default_status = str(prod.defaultStatus._value_) if hasattr(prod, "defaultStatus") and prod.defaultStatus and hasattr(prod.defaultStatus, "_value_") else None
                
                # Get platforms
                platforms = None
                if hasattr(prod, "platforms") and prod.platforms:
                    platforms = ",".join([str(p) for p in _get_iterable(prod.platforms)])
                
                # Get collector info
                collector_product = None
                collection_url = None
                if hasattr(prod, "collectionURL") and prod.collectionURL:
                    collection_url = str(prod.collectionURL)
                
                if vendor and product_name:
                    # Extract version ranges
                    if hasattr(prod, "versions") and prod.versions:
                        # Handle both list and object with .root
                        for ver in _get_iterable(prod.versions):
                            version_val = _get_value(ver.version) if hasattr(ver, "version") and ver.version else None
                            version_type = _get_value(ver.versionType) if hasattr(ver, "versionType") and ver.versionType else None
                            less_than = _get_value(ver.lessThan) if hasattr(ver, "lessThan") and ver.lessThan else None
                            less_than_or_equal = _get_value(ver.lessThanOrEqual) if hasattr(ver, "lessThanOrEqual") and ver.lessThanOrEqual else None
                            status = _get_value(ver.status) if hasattr(ver, "status") and ver.status else None
                            
                            products.append(CVEProduct(
                                cve_id=cve_id,
                                vendor=vendor,
                                product=product_name,
                                version=version_val,
                                version_type=version_type,
                                less_than=less_than,
                                less_than_or_equal=less_than_or_equal,
                                status=status,
                                default_status=default_status,
                                platforms=platforms,
                                collector_product=collector_product,
                                collection_url=collection_url,
                            ))
                    else:
                        # No version info, add product without version
                        products.append(CVEProduct(
                            cve_id=cve_id,
                            vendor=vendor,
                            product=product_name,
                            default_status=default_status,
                            platforms=platforms,
                            collector_product=collector_product,
                            collection_url=collection_url,
                        ))
        
        # References
        if hasattr(cna, "references") and cna.references:
            for ref in _get_iterable(cna.references):
                url = _get_value(ref.url) if hasattr(ref, "url") and ref.url else None
                if url:
                    name = _get_value(ref.name) if hasattr(ref, "name") and ref.name else None
                    tags = None
                    if hasattr(ref, "tags") and ref.tags:
                        tag_values = [_get_value(t) for t in _get_iterable(ref.tags)]
                        tags = ",".join([t for t in tag_values if t])
                    references.append(CVEReference(
                        cve_id=cve_id,
                        url=url,
                        name=name,
                        tags=tags,
                        source="cna"
                    ))
        
        # Credits
        if hasattr(cna, "credits") and cna.credits:
            for credit in _get_iterable(cna.credits):
                value = _get_value(credit.value) if hasattr(credit, "value") and credit.value else None
                if value:
                    credit_type = _get_value(credit.type) if hasattr(credit, "type") and credit.type else None
                    lang = _get_value(credit.lang) if hasattr(credit, "lang") and credit.lang else None
                    credits_list.append(CVECredit(
                        cve_id=cve_id,
                        value=value,
                        credit_type=credit_type,
                        lang=lang
                    ))
        
        # Provider
        if hasattr(cna, "providerMetadata") and cna.providerMetadata:
            if hasattr(cna.providerMetadata, "shortName") and cna.providerMetadata.shortName:
                provider = str(cna.providerMetadata.shortName.root) if hasattr(cna.providerMetadata.shortName, "root") else str(cna.providerMetadata.shortName)
    
    # ==========================================================================
    # Extract from ADP containers (additional enrichment from CISA, etc.)
    # ==========================================================================
    if isinstance(cve.root.containers, Containers) and cve.root.containers.adp:
        for adp in cve.root.containers.adp:
            # ADP CVSS scores
            if adp.metrics:
                for met in adp.metrics.root:
                    if met.cvssV2_0 and met.cvssV2_0.baseScore:
                        adp_cvss_v2 = met.cvssV2_0.baseScore.root
                        if hasattr(met.cvssV2_0, "vectorString"):
                            adp_cvss_v2_vector = str(met.cvssV2_0.vectorString)
                    if met.cvssV3_0 and met.cvssV3_0.baseScore and not isinstance(met.cvssV3_0.baseScore, NoneScoreType):
                        adp_cvss_v3 = met.cvssV3_0.baseScore.value
                        if hasattr(met.cvssV3_0, "vectorString"):
                            adp_cvss_v3_vector = str(met.cvssV3_0.vectorString)
                    if met.cvssV3_1 and met.cvssV3_1.baseScore and not isinstance(met.cvssV3_1.baseScore, NoneScoreType):
                        adp_cvss_v3_1 = met.cvssV3_1.baseScore.value
                        if hasattr(met.cvssV3_1, "vectorString"):
                            adp_cvss_v3_1_vector = str(met.cvssV3_1.vectorString)
                    if met.cvssV4_0 and met.cvssV4_0.root.baseScore:
                        adp_cvss_v4 = met.cvssV4_0.root.baseScore.value
                        if hasattr(met.cvssV4_0.root, "vectorString"):
                            adp_cvss_v4_vector = str(met.cvssV4_0.root.vectorString)
            
            # ADP CWEs
            if hasattr(adp, "problemTypes") and adp.problemTypes:
                for pt in adp.problemTypes.root:
                    if hasattr(pt, "descriptions") and pt.descriptions:
                        for desc in pt.descriptions:
                            if hasattr(desc, "cweId") and desc.cweId:
                                cwe_desc = str(desc.description) if hasattr(desc, "description") and desc.description else None
                                cwe_list.append(CVECWEMapping(
                                    cve_id=cve_id,
                                    cwe_id=str(desc.cweId),
                                    cwe_description=cwe_desc,
                                    source="adp"
                                ))
            
            # ADP affected products
            aff = adp.affected
            if aff is not None and getattr(aff, "root", None):
                for prod in aff.root:
                    vendor = str(prod.vendor) if prod.vendor else None
                    product_name = str(prod.product) if prod.product else None
                    if vendor and product_name:
                        products.append(CVEProduct(
                            cve_id=cve_id,
                            vendor=vendor,
                            product=product_name,
                        ))
            
            # ADP references
            if hasattr(adp, "references") and adp.references:
                for ref in _get_iterable(adp.references):
                    url = _get_value(ref.url) if hasattr(ref, "url") and ref.url else None
                    if url:
                        name = _get_value(ref.name) if hasattr(ref, "name") and ref.name else None
                        tags = None
                        if hasattr(ref, "tags") and ref.tags:
                            tag_values = [_get_value(t) for t in _get_iterable(ref.tags)]
                            tags = ",".join([t for t in tag_values if t])
                        references.append(CVEReference(
                            cve_id=cve_id,
                            url=url,
                            name=name,
                            tags=tags,
                            source="adp"
                        ))
    
    # ==========================================================================
    # Build final record
    # ==========================================================================
    cve_record = CVERecord(
        id=cve_id,
        assigner=str(assigner) if assigner else None,
        assigner_org_id=assigner_org_id,
        state=state,
        date_reserved=date_reserved,
        date_published=date_published,
        date_updated=date_updated,
        date_public=date_public,
        title=title,
        description=description,
        cvss_v2=cna_cvss_v2,
        cvss_v2_vector=cna_cvss_v2_vector,
        cvss_v3=cna_cvss_v3,
        cvss_v3_vector=cna_cvss_v3_vector,
        cvss_v3_1=cna_cvss_v3_1,
        cvss_v3_1_vector=cna_cvss_v3_1_vector,
        cvss_v4=cna_cvss_v4,
        cvss_v4_vector=cna_cvss_v4_vector,
        severity_text=severity_text,
        adp_cvss_v2=adp_cvss_v2,
        adp_cvss_v2_vector=adp_cvss_v2_vector,
        adp_cvss_v3=adp_cvss_v3,
        adp_cvss_v3_vector=adp_cvss_v3_vector,
        adp_cvss_v3_1=adp_cvss_v3_1,
        adp_cvss_v3_1_vector=adp_cvss_v3_1_vector,
        adp_cvss_v4=adp_cvss_v4,
        adp_cvss_v4_vector=adp_cvss_v4_vector,
        cna_provider=provider,
        source_discovery=source_discovery,
    )
    
    return ExtractedData(
        cve=cve_record, 
        cwes=cwe_list, 
        products=products,
        references=references,
        credits=credits_list
    )


def _process_file(args: tuple) -> Optional[ExtractedData]:
    """Process a single CVE file.
    
    Args:
        args: Tuple of (year, file_path).
    
    Returns:
        ExtractedData or None on error.
    """
    year, file_path = args
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            cve_data = json.load(f)
        cve_model = CveJsonRecordFormat.model_validate(cve_data)
        return _extract_single_cve(cve_model)
    except Exception:
        # Silently skip errors for now, could add logging
        return None


# =============================================================================
# Parquet Schemas
# =============================================================================

CVE_SCHEMA = {
    "id": pl.Utf8,
    "assigner": pl.Utf8,
    "assigner_org_id": pl.Utf8,
    "state": pl.Utf8,
    "date_reserved": pl.Utf8,
    "date_published": pl.Utf8,
    "date_updated": pl.Utf8,
    "date_public": pl.Utf8,
    "title": pl.Utf8,
    "description": pl.Utf8,
    "cvss_v2": pl.Float64,
    "cvss_v2_vector": pl.Utf8,
    "cvss_v3": pl.Float64,
    "cvss_v3_vector": pl.Utf8,
    "cvss_v3_1": pl.Float64,
    "cvss_v3_1_vector": pl.Utf8,
    "cvss_v4": pl.Float64,
    "cvss_v4_vector": pl.Utf8,
    "severity_text": pl.Utf8,
    "adp_cvss_v2": pl.Float64,
    "adp_cvss_v2_vector": pl.Utf8,
    "adp_cvss_v3": pl.Float64,
    "adp_cvss_v3_vector": pl.Utf8,
    "adp_cvss_v3_1": pl.Float64,
    "adp_cvss_v3_1_vector": pl.Utf8,
    "adp_cvss_v4": pl.Float64,
    "adp_cvss_v4_vector": pl.Utf8,
    "cna_provider": pl.Utf8,
    "source_discovery": pl.Utf8,
}

CWE_SCHEMA = {
    "cve_id": pl.Utf8,
    "cwe_id": pl.Utf8,
    "cwe_description": pl.Utf8,
    "source": pl.Utf8,
}

PRODUCT_SCHEMA = {
    "cve_id": pl.Utf8,
    "vendor": pl.Utf8,
    "product": pl.Utf8,
    "version": pl.Utf8,
    "version_type": pl.Utf8,
    "less_than": pl.Utf8,
    "less_than_or_equal": pl.Utf8,
    "status": pl.Utf8,
    "default_status": pl.Utf8,
    "platforms": pl.Utf8,
    "collector_product": pl.Utf8,
    "collection_url": pl.Utf8,
}

REFERENCE_SCHEMA = {
    "cve_id": pl.Utf8,
    "url": pl.Utf8,
    "name": pl.Utf8,
    "tags": pl.Utf8,
    "source": pl.Utf8,
}

CREDIT_SCHEMA = {
    "cve_id": pl.Utf8,
    "value": pl.Utf8,
    "credit_type": pl.Utf8,
    "lang": pl.Utf8,
}


# =============================================================================
# Extractor Service
# =============================================================================

class ExtractorService:
    """Service for extracting CVE data from JSON files to Parquet."""
    
    def __init__(self, config: Optional[Config] = None, quiet: bool = False):
        """Initialize the extractor service.
        
        Args:
            config: Configuration instance. Uses default if not provided.
            quiet: If True, suppress progress output.
        """
        self.config = config or get_config()
        self.quiet = quiet
    
    def extract_all(
        self, 
        years: Optional[List[int]] = None,
        output_dir: Optional[Path] = None
    ) -> dict:
        """Extract all CVE data to Parquet files.
        
        Args:
            years: List of years to process. Uses config default if not provided.
            output_dir: Output directory for Parquet files. Uses config if not provided.
        
        Returns:
            Dictionary with paths to created files.
        """
        cve_dir = self.config.cve_dir
        output_dir = output_dir or self.config.data_dir
        
        # Determine year range
        if years:
            year_set = set(years)
            start_year = min(years)
            end_year = max(years)
        else:
            start_year, end_year = self.config.get_year_range()
            year_set = None
        
        # Find year directories
        year_dirs = []
        for entry in os.scandir(cve_dir):
            if entry.is_dir():
                try:
                    year = int(entry.name)
                    if year_set:
                        if year in year_set:
                            year_dirs.append((year, entry.path))
                    elif start_year is None or (start_year <= year <= end_year):
                        year_dirs.append((year, entry.path))
                except ValueError:
                    continue
        
        # Gather all files
        file_args = []
        for year, root in sorted(year_dirs):
            for filename in sorted(os.listdir(root)):
                if filename.endswith(".json"):
                    file_path = os.path.join(root, filename)
                    file_args.append((year, file_path))
        
        if not self.quiet:
            print(f"Processing {len(file_args)} CVE files...")
        
        # Process in parallel
        cve_records: List[CVERecord] = []
        cwe_mappings: List[CVECWEMapping] = []
        product_records: List[CVEProduct] = []
        reference_records: List[CVEReference] = []
        credit_records: List[CVECredit] = []
        
        with concurrent.futures.ProcessPoolExecutor() as executor:
            if self.quiet:
                results = list(executor.map(_process_file, file_args))
            else:
                results = list(tqdm(
                    executor.map(_process_file, file_args), 
                    total=len(file_args), 
                    desc="Extracting"
                ))
        
        # Aggregate results
        for result in results:
            if result is None:
                continue
            cve_records.append(result.cve)
            cwe_mappings.extend(result.cwes)
            product_records.extend(result.products)
            reference_records.extend(result.references)
            credit_records.extend(result.credits)
        
        # Write to Parquet
        results_paths = {}
        
        # CVE records
        cves_path = output_dir / "cves.parquet"
        df_cves = pl.DataFrame([r.model_dump() for r in cve_records], schema=CVE_SCHEMA)
        df_cves.write_parquet(cves_path)
        results_paths['cves'] = cves_path
        
        if not self.quiet:
            print(f"Wrote {len(cve_records)} CVE records to {cves_path}")
        
        # CWE mappings
        if cwe_mappings:
            cwe_path = output_dir / "cve_cwe.parquet"
            df_cwe = pl.DataFrame([m.model_dump() for m in cwe_mappings], schema=CWE_SCHEMA)
            df_cwe.write_parquet(cwe_path)
            results_paths['cve_cwe'] = cwe_path
            
            if not self.quiet:
                print(f"Wrote {len(cwe_mappings)} CWE mappings to {cwe_path}")
        
        # Product records
        if product_records:
            products_path = output_dir / "cve_products.parquet"
            df_products = pl.DataFrame([p.model_dump() for p in product_records], schema=PRODUCT_SCHEMA)
            df_products.write_parquet(products_path)
            results_paths['cve_products'] = products_path
            
            if not self.quiet:
                print(f"Wrote {len(product_records)} product records to {products_path}")
        
        # Reference records
        if reference_records:
            refs_path = output_dir / "cve_references.parquet"
            df_refs = pl.DataFrame([r.model_dump() for r in reference_records], schema=REFERENCE_SCHEMA)
            df_refs.write_parquet(refs_path)
            results_paths['cve_references'] = refs_path
            
            if not self.quiet:
                print(f"Wrote {len(reference_records)} reference records to {refs_path}")
        
        # Credit records
        if credit_records:
            credits_path = output_dir / "cve_credits.parquet"
            df_credits = pl.DataFrame([c.model_dump() for c in credit_records], schema=CREDIT_SCHEMA)
            df_credits.write_parquet(credits_path)
            results_paths['cve_credits'] = credits_path
            
            if not self.quiet:
                print(f"Wrote {len(credit_records)} credit records to {credits_path}")
        
        return results_paths
    
    def get_cve(self, cve_id: str) -> Optional[ExtractedData]:
        """Get a single CVE by ID from raw JSON files.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234").
        
        Returns:
            ExtractedData for the CVE, or None if not found.
        """
        # Parse year from CVE ID
        parts = cve_id.split("-")
        if len(parts) < 2:
            return None
        
        try:
            year = parts[1]
            file_path = self.config.cve_dir / year / f"{cve_id}.json"
            
            if not file_path.exists():
                return None
            
            with open(file_path, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)
            
            cve_model = CveJsonRecordFormat.model_validate(cve_data)
            return _extract_single_cve(cve_model)
        except Exception:
            return None
