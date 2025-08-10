import argparse
import requests
import os
import zipfile
from tqdm import tqdm

CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
CWEC_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CVES_GITHUB_URL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
CVE_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/"

def download_with_progress(url, dest_path):
    """Download a file with tqdm progress bar."""
    response = requests.get(url, stream=True)
    response.raise_for_status()
    total = int(response.headers.get('content-length', 0))
    with open(dest_path, "wb") as f, tqdm(
        total=total, unit='B', unit_scale=True, desc=os.path.basename(dest_path)
    ) as pbar:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
                pbar.update(len(chunk))

def download_capec(url, dest_path):
    dest_folder = os.path.dirname(dest_path)
    if not os.path.exists(dest_folder):
        os.makedirs(dest_folder)
    print(f"Downloading CAPEC from {url}")
    download_with_progress(url, dest_path)
    print(f"CAPEC file saved to {dest_path}")

def download_cwe(url, dest_path):
    dest_folder = os.path.dirname(dest_path)
    if not os.path.exists(dest_folder):
        os.makedirs(dest_folder)
    print(f"Downloading CWE from {url}")
    # Download zip to temp file with progress
    temp_zip = dest_path + ".tmp"
    download_with_progress(url, temp_zip)
    with zipfile.ZipFile(temp_zip) as z:
        xml_filename = [name for name in z.namelist() if name.endswith('.xml')][0]
        with z.open(xml_filename) as source, open(dest_path, 'wb') as target:
            target.write(source.read())
    os.remove(temp_zip)
    print(f"CWE file saved to {dest_path}")


def download_cves_from_github(url, dest_dir):
    """
    Downloads the CVEs GitHub repository zip archive.
    """
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
    zip_filename = os.path.join(dest_dir, "cvelistV5-main.zip")
    print(f"Downloading CVEs from GitHub repository at {url} to {zip_filename}")
    try:
        download_with_progress(url, zip_filename)
        print(f"CVE GitHub zip file saved to {zip_filename}")
    except requests.exceptions.RequestException as e:
        print(f"Could not download {url}: {e}. Aborting.")
        return


def main():
    parser = argparse.ArgumentParser(description="Download CAPEC, CWE, and CVE files.")
    parser.add_argument("--capec-url", default=CAPEC_URL, help="URL for CAPEC XML file.")
    parser.add_argument("--cwe-url", default=CWEC_URL, help="URL for CWE XML zip file.")
    parser.add_argument("--capec-output", help="Output path for CAPEC XML file.")
    parser.add_argument("--cwe-output", help="Output path for CWE XML file.")
    parser.add_argument("--cve-github-download-dir", help="Output directory for CVE Github Zip archive.")
    parser.add_argument("--cve-github-url", default=CVES_GITHUB_URL, help="URL for CVE GitHub repository zip file.")
    args = parser.parse_args()

    if args.capec_output:
        download_capec(args.capec_url, args.capec_output)
    
    if args.cwe_output:
        download_cwe(args.cwe_url, args.cwe_output)

    if args.cve_github_download_dir:
        download_cves_from_github(args.cve_github_url, args.cve_github_download_dir)

if __name__ == "__main__":
    main()
