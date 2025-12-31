"""CVE search service."""

from typing import Optional, List, Literal
from datetime import datetime

import polars as pl

from product_cybersecurity.core.config import Config, get_config


# Severity levels based on CVSS scores
SEVERITY_THRESHOLDS = {
    "none": (0.0, 0.0),
    "low": (0.1, 3.9),
    "medium": (4.0, 6.9),
    "high": (7.0, 8.9),
    "critical": (9.0, 10.0),
}

SeverityLevel = Literal["none", "low", "medium", "high", "critical"]


class SearchResult:
    """Container for search results with metadata."""
    
    def __init__(
        self, 
        cves: pl.DataFrame, 
        products: Optional[pl.DataFrame] = None,
        cwes: Optional[pl.DataFrame] = None
    ):
        self.cves = cves
        self.products = products
        self.cwes = cwes
    
    @property
    def count(self) -> int:
        """Number of CVE results."""
        return len(self.cves)
    
    def to_dicts(self) -> List[dict]:
        """Convert results to list of dictionaries."""
        return self.cves.to_dicts()
    
    def to_json(self) -> str:
        """Convert results to JSON string."""
        return self.cves.write_json()
    
    def summary(self) -> dict:
        """Get a summary of the search results."""
        if self.count == 0:
            return {"count": 0, "cves": []}
        
        # Get best CVSS score for each CVE
        df = self.cves.with_columns([
            pl.coalesce(["cvss_v4", "cvss_v3_1", "cvss_v3", "adp_cvss_v4", "adp_cvss_v3_1", "adp_cvss_v3", "cvss_v2", "adp_cvss_v2"]).alias("best_cvss")
        ])
        
        return {
            "count": self.count,
            "severity_distribution": self._get_severity_distribution(df),
            "year_distribution": self._get_year_distribution(df),
        }
    
    def _get_severity_distribution(self, df: pl.DataFrame) -> dict:
        """Get count of CVEs by severity."""
        result = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0, "unknown": 0}
        
        for row in df.iter_rows(named=True):
            score = row.get("best_cvss")
            if score is None:
                result["unknown"] += 1
            elif score >= 9.0:
                result["critical"] += 1
            elif score >= 7.0:
                result["high"] += 1
            elif score >= 4.0:
                result["medium"] += 1
            elif score >= 0.1:
                result["low"] += 1
            else:
                result["none"] += 1
        
        return result
    
    def _get_year_distribution(self, df: pl.DataFrame) -> dict[str, int]:
        """Get count of CVEs by year."""
        result: dict[str, int] = {}
        for row in df.iter_rows(named=True):
            cve_id = row.get("id", "")
            if cve_id.startswith("CVE-"):
                parts = cve_id.split("-")
                if len(parts) >= 2:
                    year = parts[1]
                    result[year] = result.get(year, 0) + 1
        return dict(sorted(result.items()))


class CVESearchService:
    """Service for searching CVE data."""
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize the search service.
        
        Args:
            config: Configuration instance. Uses default if not provided.
        """
        self.config = config or get_config()
        self._cves_df: Optional[pl.DataFrame] = None
        self._products_df: Optional[pl.DataFrame] = None
        self._cwe_df: Optional[pl.DataFrame] = None
    
    def _load_data(self) -> None:
        """Load data from Parquet files if not already loaded."""
        if self._cves_df is None:
            cves_path = self.config.cves_parquet
            if not cves_path.exists():
                raise FileNotFoundError(
                    f"CVE data not found at {cves_path}. Run 'cve extract' first."
                )
            self._cves_df = pl.read_parquet(cves_path)
        
        if self._products_df is None:
            products_path = self.config.cve_products_parquet
            if products_path.exists():
                self._products_df = pl.read_parquet(products_path)
        
        if self._cwe_df is None:
            cwe_path = self.config.cve_cwe_parquet
            if cwe_path.exists():
                self._cwe_df = pl.read_parquet(cwe_path)
    
    def _ensure_cves_loaded(self) -> pl.DataFrame:
        """Load data and return CVEs dataframe (guaranteed non-None)."""
        self._load_data()
        assert self._cves_df is not None
        return self._cves_df
    
    def by_id(self, cve_id: str) -> SearchResult:
        """Search for a specific CVE by ID.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234").
        
        Returns:
            SearchResult with matching CVE(s).
        """
        cves_df = self._ensure_cves_loaded()
        
        # Normalize ID
        cve_id = cve_id.upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"
        
        result = cves_df.filter(pl.col("id") == cve_id)
        
        # Get related products and CWEs
        products = None
        cwes = None
        if self._products_df is not None:
            products = self._products_df.filter(pl.col("cve_id") == cve_id)
        if self._cwe_df is not None:
            cwes = self._cwe_df.filter(pl.col("cve_id") == cve_id)
        
        return SearchResult(result, products, cwes)
    
    def by_product(
        self, 
        product: str, 
        vendor: Optional[str] = None,
        fuzzy: bool = True
    ) -> SearchResult:
        """Search CVEs affecting a product.
        
        Args:
            product: Product name to search for.
            vendor: Optional vendor name to filter by.
            fuzzy: If True, use case-insensitive substring matching.
        
        Returns:
            SearchResult with matching CVEs.
        """
        cves_df = self._ensure_cves_loaded()
        
        if self._products_df is None:
            return SearchResult(pl.DataFrame())
        
        # Filter products
        if fuzzy:
            product_filter = pl.col("product").str.to_lowercase().str.contains(product.lower())
        else:
            product_filter = pl.col("product") == product
        
        if vendor:
            if fuzzy:
                vendor_filter = pl.col("vendor").str.to_lowercase().str.contains(vendor.lower())
            else:
                vendor_filter = pl.col("vendor") == vendor
            product_filter = product_filter & vendor_filter
        
        matching_products = self._products_df.filter(product_filter)
        cve_ids = matching_products.select("cve_id").unique()
        
        # Get CVE details
        result = cves_df.filter(pl.col("id").is_in(cve_ids.to_series()))
        
        return SearchResult(result, matching_products)
    
    def by_vendor(self, vendor: str, fuzzy: bool = True) -> SearchResult:
        """Search CVEs affecting products from a vendor.
        
        Args:
            vendor: Vendor name to search for.
            fuzzy: If True, use case-insensitive substring matching.
        
        Returns:
            SearchResult with matching CVEs.
        """
        cves_df = self._ensure_cves_loaded()
        
        if self._products_df is None:
            return SearchResult(pl.DataFrame())
        
        if fuzzy:
            vendor_filter = pl.col("vendor").str.to_lowercase().str.contains(vendor.lower())
        else:
            vendor_filter = pl.col("vendor") == vendor
        
        matching_products = self._products_df.filter(vendor_filter)
        cve_ids = matching_products.select("cve_id").unique()
        
        result = cves_df.filter(pl.col("id").is_in(cve_ids.to_series()))
        
        return SearchResult(result, matching_products)
    
    def by_cwe(self, cwe_id: str) -> SearchResult:
        """Search CVEs by CWE identifier.
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-79" or "79").
        
        Returns:
            SearchResult with matching CVEs.
        """
        cves_df = self._ensure_cves_loaded()
        
        if self._cwe_df is None:
            return SearchResult(pl.DataFrame())
        
        # Normalize CWE ID
        cwe_id = cwe_id.upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
        
        matching_cwes = self._cwe_df.filter(pl.col("cwe") == cwe_id)
        cve_ids = matching_cwes.select("cve_id").unique()
        
        result = cves_df.filter(pl.col("id").is_in(cve_ids.to_series()))
        
        return SearchResult(result, cwes=matching_cwes)
    
    def by_severity(
        self, 
        severity: SeverityLevel,
        after: Optional[str] = None,
        before: Optional[str] = None
    ) -> SearchResult:
        """Search CVEs by severity level.
        
        Args:
            severity: Severity level (none, low, medium, high, critical).
            after: Only include CVEs published after this date (YYYY-MM-DD).
            before: Only include CVEs published before this date (YYYY-MM-DD).
        
        Returns:
            SearchResult with matching CVEs.
        """
        cves_df = self._ensure_cves_loaded()
        
        min_score, max_score = SEVERITY_THRESHOLDS[severity]
        
        # Create best CVSS score column
        df = cves_df.with_columns([
            pl.coalesce(["cvss_v4", "cvss_v3_1", "cvss_v3", "adp_cvss_v4", "adp_cvss_v3_1", "adp_cvss_v3", "cvss_v2", "adp_cvss_v2"]).alias("best_cvss")
        ])
        
        # Filter by severity
        result = df.filter(
            (pl.col("best_cvss") >= min_score) & 
            (pl.col("best_cvss") <= max_score)
        )
        
        # Apply date filters
        if after:
            result = result.filter(pl.col("date_published") >= after)
        if before:
            result = result.filter(pl.col("date_published") <= before)
        
        # Remove temporary column
        result = result.drop("best_cvss")
        
        return SearchResult(result)
    
    def by_date_range(
        self, 
        after: Optional[str] = None,
        before: Optional[str] = None
    ) -> SearchResult:
        """Search CVEs by publication date range.
        
        Args:
            after: Only include CVEs published after this date (YYYY-MM-DD).
            before: Only include CVEs published before this date (YYYY-MM-DD).
        
        Returns:
            SearchResult with matching CVEs.
        """
        cves_df = self._ensure_cves_loaded()
        
        result = cves_df
        
        if after:
            result = result.filter(pl.col("date_published") >= after)
        if before:
            result = result.filter(pl.col("date_published") <= before)
        
        return SearchResult(result)
    
    def recent(self, days: int = 30) -> SearchResult:
        """Get recently published CVEs.
        
        Args:
            days: Number of days to look back.
        
        Returns:
            SearchResult with recent CVEs.
        """
        from datetime import timedelta
        
        cves_df = self._ensure_cves_loaded()
        
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        result = cves_df.filter(pl.col("date_published") >= cutoff)
        
        return SearchResult(result)
    
    def stats(self) -> dict:
        """Get overall statistics about the CVE database.
        
        Returns:
            Dictionary with statistics.
        """
        cves_df = self._ensure_cves_loaded()
        
        total_cves = len(cves_df)
        
        # Count by state
        state_counts = cves_df.group_by("state").count().to_dicts()
        
        # Count by year
        year_counts: dict[str, int] = {}
        for row in cves_df.iter_rows(named=True):
            cve_id = row.get("id", "")
            if cve_id.startswith("CVE-"):
                parts = cve_id.split("-")
                if len(parts) >= 2:
                    year = parts[1]
                    year_counts[year] = year_counts.get(year, 0) + 1
        
        # Product/vendor stats
        product_count = len(self._products_df) if self._products_df is not None else 0
        unique_products = 0
        unique_vendors = 0
        if self._products_df is not None:
            unique_products = self._products_df.select("product").n_unique()
            unique_vendors = self._products_df.select("vendor").n_unique()
        
        return {
            "total_cves": total_cves,
            "states": {d["state"]: d["count"] for d in state_counts},
            "by_year": dict(sorted(year_counts.items())),
            "total_product_entries": product_count,
            "unique_products": unique_products,
            "unique_vendors": unique_vendors,
        }
