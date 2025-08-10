import argparse
import os
import json
from pydantic import BaseModel
import polars as pl
from typing import List, Optional, NamedTuple
import concurrent.futures
from tqdm import tqdm

from product_cybersecurity.models.cve_model import CnaPublishedContainer, CveJsonRecordFormat, NoneScoreType, Containers

class CveData(BaseModel):
    id : str
    assigner : str
    state : str
    cvss_v2: Optional[float]
    cvss_v3: Optional[float]
    cvss_v3_1: Optional[float]
    cvss_v4: Optional[float]
    adp_cvss_v2: Optional[float]
    adp_cvss_v3: Optional[float]
    adp_cvss_v3_1: Optional[float]
    adp_cvss_v4: Optional[float]
    date_reserved: Optional[str]
    date_published: Optional[str]

# New model for CVE-CWE pairs
class CveCweData(BaseModel):
    cve_id: str
    cwe: str


class ExtractedCveData(NamedTuple):
    cve_data: CveData
    cwe_list: List[str]

def extract_cve_data(cve: CveJsonRecordFormat) -> ExtractedCveData:
    id = str(cve.root.cveMetadata.cveId.root)
    assigner = cve.root.cveMetadata.assignerShortName.root if cve.root.cveMetadata.assignerShortName else None
    state = cve.root.cveMetadata.state._value_
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
    # Extract CWEs from CNA container if present
    if isinstance(cve.root.containers.cna, CnaPublishedContainer):
        if cve.root.containers.cna.metrics:
            for met in cve.root.containers.cna.metrics.root:
                if met.cvssV2_0:
                    cna_cvss_v2 = met.cvssV2_0.baseScore.root if met.cvssV2_0.baseScore else None
                if met.cvssV3_0 and met.cvssV3_0.baseScore and not isinstance(met.cvssV3_0.baseScore, NoneScoreType):
                    cna_cvss_v3 = met.cvssV3_0.baseScore.value if met.cvssV3_0.baseScore else None
                if met.cvssV3_1 and not isinstance(met.cvssV3_1.baseScore, NoneScoreType):
                    cna_cvss_v3_1 = met.cvssV3_1.baseScore.value if met.cvssV3_1.baseScore else None
                if met.cvssV4_0:
                    cna_cvss_v4 = met.cvssV4_0.root.baseScore.value if met.cvssV4_0.root.baseScore else None
        # Extract CWEs from CNA problemTypes
        if hasattr(cve.root.containers.cna, "problemTypes") and cve.root.containers.cna.problemTypes:
            for pt in cve.root.containers.cna.problemTypes.root:
                if hasattr(pt, "descriptions") and pt.descriptions:
                    for desc in pt.descriptions:
                        if hasattr(desc, "cweId") and desc.cweId:
                            cwe_list.append(str(desc.cweId))

    # Extract CWEs from ADP containers if present
    if isinstance(cve.root.containers, Containers):
        if cve.root.containers.adp:
            for a in cve.root.containers.adp:
                if a.metrics:
                    for met in a.metrics.root:
                        if met.cvssV2_0:
                            adp_cvss_v2 = met.cvssV2_0.baseScore.root
                        if met.cvssV3_0 and met.cvssV3_0.baseScore and not isinstance(met.cvssV3_0.baseScore, NoneScoreType):
                            adp_cvss_v3 = met.cvssV3_0.baseScore.value
                        if met.cvssV3_1 and not isinstance(met.cvssV3_1.baseScore, NoneScoreType):
                            adp_cvss_v3_1 = met.cvssV3_1.baseScore.value
                        if met.cvssV4_0:
                            adp_cvss_v4 = met.cvssV4_0.root.baseScore.value
                # Extract CWEs from ADP problemTypes
                if hasattr(a, "problemTypes") and a.problemTypes:
                    for pt in a.problemTypes.root:
                        if hasattr(pt, "descriptions") and pt.descriptions:
                            for desc in pt.descriptions:
                                if hasattr(desc, "cweId") and desc.cweId:
                                    cwe_list.append(str(desc.cweId))

    cve_data = CveData(
        id=id,
        assigner=str(assigner),
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
        date_published=date_published
    )
    return ExtractedCveData(cve_data=cve_data, cwe_list=cwe_list)

def process_cve_file(args) -> Optional[ExtractedCveData]:
    year, file_path = args
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            cve_data = json.load(f)
        cve_model = CveJsonRecordFormat.model_validate(cve_data)
        return extract_cve_data(cve_model)
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Load and validate CVE JSON data from the data/github_cve directory and count submissions by source.")
    default_cve_dir = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "data",
            "github_cve"
        )
    )
    # Set default output directory to the dataset directory (data)
    default_output_dir = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "data"
        )
    )
    parser.add_argument(
        "--cve-dir",
        required=False,
        default=default_cve_dir,
        help="Path to the directory containing CVE JSON files. Defaults to data/github_cve."
    )
    parser.add_argument(
        "--output-dir",
        required=False,
        default=default_output_dir,
        help="Directory to store the extracted CSV and Parquet files. Defaults to the dataset directory (data)."
    )
    args = parser.parse_args()

    print(f"Loading CVE data from {args.cve_dir}")
    print(f"Extracted data will be saved to {args.output_dir}")

    if not os.path.isdir(args.cve_dir):
        print(f"Error: Directory not found at {args.cve_dir}")
        return
    if not os.path.isdir(args.output_dir):
        os.makedirs(args.output_dir, exist_ok=True)

    cve_compact_data: List[CveData] = []
    cve_cwe_data: List[CveCweData] = []

    # Collect subdirectories (years), sort, and process in order
    year_dirs = []
    for entry in os.scandir(args.cve_dir):
        if entry.is_dir():
            try:
                year = int(entry.name)
                year_dirs.append((year, entry.path))
            except ValueError:
                continue  # Skip non-year directories

    # Gather all (year, file_path) pairs
    file_args = []
    for year, root in sorted(year_dirs):
        for filename in sorted(os.listdir(root)):
            if filename.endswith(".json"):
                file_path = os.path.join(root, filename)
                file_args.append((year, file_path))

    # Process files in parallel with progress bar
    with concurrent.futures.ProcessPoolExecutor() as executor:
        results = list(tqdm(executor.map(process_cve_file, file_args), total=len(file_args), desc="Processing CVE files"))

    for result in results:
        if result is None:
            continue
        cve_data_obj = result.cve_data
        cwe_list = result.cwe_list
        cve_compact_data.append(cve_data_obj)
        for cwe in cwe_list:
            cve_cwe_data.append(CveCweData(cve_id=cve_data_obj.id, cwe=cwe))

    df = pl.DataFrame(cve_compact_data)
    print(df)
    # Write output files to the specified output directory
    df.write_csv(os.path.join(args.output_dir, "test.csv"))
    df.write_parquet(os.path.join(args.output_dir, "test.parquet"))

    # Write CVE-CWE pairs to a separate Parquet file
    if cve_cwe_data:
        df_cwe = pl.DataFrame(cve_cwe_data)
        print(df_cwe)
        df_cwe.write_parquet(os.path.join(args.output_dir, "cve_cwe.parquet"))


if __name__ == "__main__":
    main()
