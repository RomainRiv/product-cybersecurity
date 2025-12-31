"""CVE data extraction service."""

import json
import os
from pathlib import Path
from typing import List, Optional, NamedTuple
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


class CVERecord(BaseModel):
    """Extracted CVE metadata."""
    id: str
    assigner: Optional[str]
    state: str
    cvss_v2: Optional[float] = None
    cvss_v3: Optional[float] = None
    cvss_v3_1: Optional[float] = None
    cvss_v4: Optional[float] = None
    adp_cvss_v2: Optional[float] = None
    adp_cvss_v3: Optional[float] = None
    adp_cvss_v3_1: Optional[float] = None
    adp_cvss_v4: Optional[float] = None
    date_reserved: Optional[str] = None
    date_published: Optional[str] = None
    cna_provider: Optional[str] = None


class CVECWEMapping(BaseModel):
    """CVE to CWE mapping."""
    cve_id: str
    cwe: str


class CVEProduct(BaseModel):
    """CVE affected product."""
    cve_id: str
    vendor: str
    product: str


class ExtractedData(NamedTuple):
    """Complete extracted data from a CVE."""
    cve: CVERecord
    cwes: List[str]
    products: List[CVEProduct]


def _extract_single_cve(cve: CveJsonRecordFormat) -> ExtractedData:
    """Extract structured data from a single CVE record.
    
    Args:
        cve: Parsed CVE JSON record.
    
    Returns:
        ExtractedData with CVE metadata, CWEs, and affected products.
    """
    cve_id = str(cve.root.cveMetadata.cveId.root)
    assigner = cve.root.cveMetadata.assignerShortName.root if cve.root.cveMetadata.assignerShortName else None
    state = cve.root.cveMetadata.state._value_
    
    # Initialize scores
    cna_cvss_v2 = None
    cna_cvss_v3 = None
    cna_cvss_v3_1 = None
    cna_cvss_v4 = None
    adp_cvss_v2 = None
    adp_cvss_v3 = None
    adp_cvss_v3_1 = None
    adp_cvss_v4 = None
    
    date_reserved = cve.root.cveMetadata.dateReserved.root if cve.root.cveMetadata.dateReserved else None
    date_published = cve.root.cveMetadata.datePublished.root if cve.root.cveMetadata.datePublished else None
    
    cwe_list: List[str] = []
    products: List[CVEProduct] = []
    seen_pairs: set = set()
    
    # Extract from CNA container
    if isinstance(cve.root.containers.cna, CnaPublishedContainer):
        # Extract CVSS scores
        if cve.root.containers.cna.metrics:
            for met in cve.root.containers.cna.metrics.root:
                if met.cvssV2_0 and met.cvssV2_0.baseScore:
                    cna_cvss_v2 = met.cvssV2_0.baseScore.root
                if met.cvssV3_0 and met.cvssV3_0.baseScore and not isinstance(met.cvssV3_0.baseScore, NoneScoreType):
                    cna_cvss_v3 = met.cvssV3_0.baseScore.value
                if met.cvssV3_1 and met.cvssV3_1.baseScore and not isinstance(met.cvssV3_1.baseScore, NoneScoreType):
                    cna_cvss_v3_1 = met.cvssV3_1.baseScore.value
                if met.cvssV4_0 and met.cvssV4_0.root.baseScore:
                    cna_cvss_v4 = met.cvssV4_0.root.baseScore.value
        
        # Extract CWEs
        if hasattr(cve.root.containers.cna, "problemTypes") and cve.root.containers.cna.problemTypes:
            for pt in cve.root.containers.cna.problemTypes.root:
                if hasattr(pt, "descriptions") and pt.descriptions:
                    for desc in pt.descriptions:
                        if hasattr(desc, "cweId") and desc.cweId:
                            cwe_list.append(str(desc.cweId))
        
        # Extract affected products
        if getattr(cve.root.containers.cna, "affected", None):
            for prod in cve.root.containers.cna.affected.root:
                vendor = str(prod.vendor) if prod.vendor else None
                product = str(prod.product) if prod.product else None
                if vendor and product:
                    key = (vendor, product)
                    if key not in seen_pairs:
                        seen_pairs.add(key)
                        products.append(CVEProduct(cve_id=cve_id, vendor=vendor, product=product))
    
    # Get provider
    provider = getattr(getattr(cve.root.containers.cna, "providerMetadata", None), "shortName", None)
    
    # Extract from ADP containers
    if isinstance(cve.root.containers, Containers) and cve.root.containers.adp:
        for adp in cve.root.containers.adp:
            # Extract ADP CVSS scores
            if adp.metrics:
                for met in adp.metrics.root:
                    if met.cvssV2_0 and met.cvssV2_0.baseScore:
                        adp_cvss_v2 = met.cvssV2_0.baseScore.root
                    if met.cvssV3_0 and met.cvssV3_0.baseScore and not isinstance(met.cvssV3_0.baseScore, NoneScoreType):
                        adp_cvss_v3 = met.cvssV3_0.baseScore.value
                    if met.cvssV3_1 and met.cvssV3_1.baseScore and not isinstance(met.cvssV3_1.baseScore, NoneScoreType):
                        adp_cvss_v3_1 = met.cvssV3_1.baseScore.value
                    if met.cvssV4_0 and met.cvssV4_0.root.baseScore:
                        adp_cvss_v4 = met.cvssV4_0.root.baseScore.value
            
            # Extract ADP CWEs
            if hasattr(adp, "problemTypes") and adp.problemTypes:
                for pt in adp.problemTypes.root:
                    if hasattr(pt, "descriptions") and pt.descriptions:
                        for desc in pt.descriptions:
                            if hasattr(desc, "cweId") and desc.cweId:
                                cwe_list.append(str(desc.cweId))
            
            # Extract ADP affected products
            aff = adp.affected
            if aff is not None and getattr(aff, "root", None):
                for prod in aff.root:
                    vendor = str(prod.vendor) if prod.vendor else None
                    product = str(prod.product) if prod.product else None
                    if vendor and product:
                        key = (vendor, product)
                        if key not in seen_pairs:
                            seen_pairs.add(key)
                            products.append(CVEProduct(cve_id=cve_id, vendor=vendor, product=product))
    
    cve_record = CVERecord(
        id=cve_id,
        assigner=str(assigner) if assigner else None,
        state=state,
        cvss_v2=cna_cvss_v2,
        cvss_v3=cna_cvss_v3,
        cvss_v3_1=cna_cvss_v3_1,
        cvss_v4=cna_cvss_v4,
        adp_cvss_v2=adp_cvss_v2,
        adp_cvss_v3=adp_cvss_v3,
        adp_cvss_v3_1=adp_cvss_v3_1,
        adp_cvss_v4=adp_cvss_v4,
        date_reserved=date_reserved,
        date_published=date_published,
        cna_provider=(
            str(provider.root) if provider and getattr(provider, "root", None) 
            else (str(provider) if provider else None)
        )
    )
    
    return ExtractedData(cve=cve_record, cwes=cwe_list, products=products)


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


class ExtractorService:
    """Service for extracting CVE data into queryable formats."""
    
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
        cve_dir: Optional[Path] = None,
        output_dir: Optional[Path] = None,
        years: Optional[int] = None
    ) -> dict:
        """Extract all CVE data into Parquet files.
        
        Args:
            cve_dir: Directory containing CVE JSON files. Uses config default if not provided.
            output_dir: Directory for output files. Uses config default if not provided.
            years: Filter to last N years. If None, processes all available.
        
        Returns:
            Dictionary with paths to generated files.
        """
        cve_dir = Path(cve_dir) if cve_dir else self.config.cve_dir
        output_dir = Path(output_dir) if output_dir else self.config.data_dir
        
        if not cve_dir.exists():
            raise FileNotFoundError(f"CVE directory not found: {cve_dir}")
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Determine year range if filtering
        start_year = None
        end_year = None
        if years:
            start_year, end_year = self.config.get_year_range(years)
        
        # Collect year directories
        year_dirs = []
        for entry in os.scandir(cve_dir):
            if entry.is_dir():
                try:
                    year = int(entry.name)
                    if start_year is None or (start_year <= year <= end_year):
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
            for cwe in result.cwes:
                cwe_mappings.append(CVECWEMapping(cve_id=result.cve.id, cwe=cwe))
            for prod in result.products:
                product_records.append(prod)
        
        # Write to Parquet
        results_paths = {}
        
        # CVE records - specify schema to handle None values correctly
        cves_path = output_dir / "cves.parquet"
        cve_schema = {
            "id": pl.Utf8,
            "assigner": pl.Utf8,
            "state": pl.Utf8,
            "cvss_v2": pl.Float64,
            "cvss_v3": pl.Float64,
            "cvss_v3_1": pl.Float64,
            "cvss_v4": pl.Float64,
            "adp_cvss_v2": pl.Float64,
            "adp_cvss_v3": pl.Float64,
            "adp_cvss_v3_1": pl.Float64,
            "adp_cvss_v4": pl.Float64,
            "date_reserved": pl.Utf8,
            "date_published": pl.Utf8,
            "cna_provider": pl.Utf8,
        }
        df_cves = pl.DataFrame([r.model_dump() for r in cve_records], schema=cve_schema)
        df_cves.write_parquet(cves_path)
        results_paths['cves'] = cves_path
        
        if not self.quiet:
            print(f"Wrote {len(cve_records)} CVE records to {cves_path}")
        
        # CWE mappings
        if cwe_mappings:
            cwe_path = output_dir / "cve_cwe.parquet"
            df_cwe = pl.DataFrame([m.model_dump() for m in cwe_mappings])
            df_cwe.write_parquet(cwe_path)
            results_paths['cve_cwe'] = cwe_path
            
            if not self.quiet:
                print(f"Wrote {len(cwe_mappings)} CWE mappings to {cwe_path}")
        
        # Product records
        if product_records:
            products_path = output_dir / "cve_products.parquet"
            df_products = pl.DataFrame([p.model_dump() for p in product_records])
            df_products.write_parquet(products_path)
            results_paths['cve_products'] = products_path
            
            if not self.quiet:
                print(f"Wrote {len(product_records)} product records to {products_path}")
        
        return results_paths
    
    def get_cve(self, cve_id: str, cve_dir: Optional[Path] = None) -> Optional[ExtractedData]:
        """Extract data for a single CVE by ID.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234").
            cve_dir: Directory containing CVE JSON files.
        
        Returns:
            ExtractedData or None if not found.
        """
        cve_dir = Path(cve_dir) if cve_dir else self.config.cve_dir
        
        # Parse year from CVE ID
        parts = cve_id.split("-")
        if len(parts) < 3:
            return None
        
        year = parts[1]
        file_name = f"{cve_id}.json"
        file_path = cve_dir / year / file_name
        
        if not file_path.exists():
            return None
        
        return _process_file((int(year), str(file_path)))
