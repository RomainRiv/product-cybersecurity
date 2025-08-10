import argparse
import os
import gzip
import glob
import zipfile
from tqdm import tqdm
from product_cybersecurity.models.capecparser import parse_capec_xml_pydantic
from product_cybersecurity.models.cweparser import parse_cwe_xml, CweStatusEnum

def decompress_cves(source_dir, dest_dir):
    """
    Decompresses all .gz files from source_dir to dest_dir.
    """
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)

    source_files = glob.glob(os.path.join(source_dir, '*.json.gz'))
    
    if not source_files:
        print(f"No .json.gz files found in {source_dir}")
        return

    for source_path in source_files:
        filename = os.path.basename(source_path)
        dest_path = os.path.join(dest_dir, filename.replace('.gz', ''))
        
        print(f"Decompressing {source_path} to {dest_path}")
        try:
            with gzip.open(source_path, 'rb') as f_in:
                with open(dest_path, 'wb') as f_out:
                    f_out.write(f_in.read())
        except gzip.BadGzipFile:
            print(f"Could not decompress {filename}, it might not be a valid gzip file. Skipping.")
            continue
        except Exception as e:
            print(f"An error occurred while decompressing {filename}: {e}. Skipping.")
            continue

def unzip_github_cves(zip_path, dest_dir):
    """
    Unzips CVEs from a GitHub repository zip archive and extracts them,
    stripping the top-level directory from the archive and organizing by year.
    """
    if not os.path.exists(zip_path):
        print(f"Zip file not found at {zip_path}")
        return

    print(f"Unzipping CVEs from {zip_path} to {dest_dir}")
    dest_dir_individual = os.path.join(dest_dir, "individual")
    with zipfile.ZipFile(zip_path, 'r') as z:
        namelist = z.namelist()
        if not namelist:
            print("Zip file is empty.")
            return

        root_dir = os.path.commonpath(namelist)

        # Count total JSON files for progress
        json_members = [m for m in z.infolist() if not m.is_dir() and m.filename[len(root_dir)+1:].endswith('.json')]
        total_json = len(json_members)
        if total_json == 0:
            print("No JSON files found in the zip archive.")
            return

        print(f"Found {total_json} JSON files to extract.")

        for member_info in tqdm(json_members, desc="Extracting JSON files", unit="file"):
            # Path inside the zip, relative to the root dir
            relative_path = member_info.filename[len(root_dir)+1:]

            # Extract the base filename (e.g., CVE-2025-0001.json)
            file_name = os.path.basename(relative_path)

            # Try to find the year in the path
            year = None
            path_parts = relative_path.split(os.sep)
            for part in path_parts:
                if part.isdigit() and len(part) == 4: # Assuming year is 4 digits
                    year = part
                    break

            if year:
                # Store in dest_dir/year/filename.json
                year_dest_dir = os.path.join(dest_dir_individual, year)
                os.makedirs(year_dest_dir, exist_ok=True)
                target_path = os.path.join(year_dest_dir, file_name)
            else:
                # If no year found, place directly in dest_dir/filename.json
                target_path = os.path.join(dest_dir_individual, file_name)
                os.makedirs(dest_dir_individual, exist_ok=True) # Ensure dest_dir exists

            with z.open(member_info) as source, open(target_path, 'wb') as target:
                target.write(source.read())
    print(f"CVE files unzipped to {dest_dir}")


def main():
    parser = argparse.ArgumentParser(description="Convert CAPEC and CWE XML files to JSON and decompress CVEs.")
    parser.add_argument("--capec-xml", help="Path to CAPEC XML file.")
    parser.add_argument("--capec-json", help="Path to output CAPEC JSON file.")
    parser.add_argument("--cwe-xml", help="Path to CWE XML file.")
    parser.add_argument("--cwe-json", help="Path to output CWE JSON file.")
    parser.add_argument("--cve-download-dir", help="Input directory for compressed CVE JSON files (NVD). ")
    parser.add_argument("--cve-data-dir", help="Output directory for decompressed CVE JSON files (NVD). ")
    parser.add_argument("--github-cve-zip", help="Path to the downloaded GitHub CVE zip file.")
    parser.add_argument("--github-cve-output-dir", help="Output directory for unzipped GitHub CVE JSON files.")
    args = parser.parse_args()

    if args.capec_xml and args.capec_json:
        print("Converting CAPECs to JSON")
        file_path = args.capec_xml
        with open(file_path, 'r', encoding='UTF-8') as file:
            xml_content = file.read()

        attack_patterns_pydantic = parse_capec_xml_pydantic(xml_content)
        print(len(attack_patterns_pydantic.Capecs))

        os.makedirs(os.path.dirname(args.capec_json), exist_ok=True)
        with open(args.capec_json, 'w') as f:
            f.write(attack_patterns_pydantic.model_dump_json(indent=2))

    if args.cwe_xml and args.cwe_json:
        print("Converting CWEs to JSON")

        cwe_path = args.cwe_xml
        with open(cwe_path, 'r', encoding='UTF-8') as file:
            xml_content = file.read()
        
        cwes_col = parse_cwe_xml(xml_content)

        print(len(cwes_col.CWEs))

        os.makedirs(os.path.dirname(args.cwe_json), exist_ok=True)
        with open(args.cwe_json, 'w') as f:
            f.write(cwes_col.model_dump_json(indent=2))

        i = 0
        for k in cwes_col.CWEs:
            status_to_be_removed = [CweStatusEnum.DEPRECATED, CweStatusEnum.OBSOLETE]
            if (cwes_col.CWEs[k].Status in status_to_be_removed ):
                i += 1
        print("Elements to be removed ", i)

    if args.cve_download_dir and args.cve_data_dir:
        print("Decompressing NVD CVEs")
        decompress_cves(args.cve_download_dir, args.cve_data_dir)

    if args.github_cve_zip and args.github_cve_output_dir:
        print("Unzipping GitHub CVEs")
        unzip_github_cves(args.github_cve_zip, args.github_cve_output_dir)

if __name__ == "__main__":
    main()