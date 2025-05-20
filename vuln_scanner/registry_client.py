# vuln_scanner/registry_client.py
import requests
import json
import tarfile
import gzip
import io
from pathlib import Path
from packaging.version import parse as parse_version_string, InvalidVersion # Still needed for app packages

# Import your project's modules
from .models import Package, Vulnerability, ScanResult
from . import image_parser
from . import parser as app_parser
from . import scanner
from . import vulndb

# --- Constants for Docker Hub ---
DOCKER_HUB_AUTH_URL = "https://auth.docker.io/token"
DOCKER_HUB_REGISTRY_URL = "https://registry-1.docker.io/v2"

# --- Manifest Media Types ---
MANIFEST_V2_SCHEMA2_TYPE = "application/vnd.docker.distribution.manifest.v2+json"
MANIFEST_LIST_V2_TYPE = "application/vnd.docker.distribution.manifest.list.v2+json"
OCI_MANIFEST_V1_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX_V1_TYPE = "application/vnd.oci.image.index.v1+json"

ACCEPT_HEADERS_MANIFEST_FIRST = f"{MANIFEST_V2_SCHEMA2_TYPE}, {OCI_MANIFEST_V1_TYPE}"
ACCEPT_HEADERS_MANIFEST_LIST_FIRST = f"{MANIFEST_LIST_V2_TYPE}, {OCI_INDEX_V1_TYPE}, {MANIFEST_V2_SCHEMA2_TYPE}, {OCI_MANIFEST_V1_TYPE}"


def parse_full_image_name(full_image_name: str) -> tuple[str, str, str]:
    name_part = full_image_name
    reference = "latest" 
    if "@sha256:" in full_image_name:
        name_part, reference = full_image_name.split("@", 1)
    elif ":" in full_image_name:
        try:
            name_part, reference = full_image_name.rsplit(":", 1)
            if '/' in reference: 
                name_part = full_image_name
                reference = "latest"
        except ValueError:
            name_part = full_image_name
            reference = "latest"
    if "/" not in name_part:
        repository_path_for_api = f"library/{name_part}"
        repository_path_for_auth_scope = f"library/{name_part}"
    else:
        repository_path_for_api = name_part
        repository_path_for_auth_scope = name_part
    return repository_path_for_api, reference, repository_path_for_auth_scope

def get_docker_hub_auth_token(repository_path_for_auth_scope: str) -> str | None:
    params = {"service": "registry.docker.io", "scope": f"repository:{repository_path_for_auth_scope}:pull"}
    try:
        # print(f"Attempting to get auth token for scope: {params['scope']}...")
        response = requests.get(DOCKER_HUB_AUTH_URL, params=params, timeout=10)
        response.raise_for_status()
        token_info = response.json(); token = token_info.get("token") 
        if not token and "access_token" in token_info: token = token_info.get("access_token")
        if token: 
            # print("Successfully obtained Docker Hub auth token.")
            return token
        else: print(f"Error: 'token' or 'access_token' not found in Docker Hub auth response: {token_info}")
    except requests.exceptions.RequestException as e: print(f"Error getting Docker Hub auth token for {repository_path_for_auth_scope}: {e}")
    except json.JSONDecodeError as e: print(f"Error decoding Docker Hub auth token response: {e}")
    return None

def fetch_image_manifest_from_docker_hub(repository_path_for_api: str, reference: str, auth_token: str) -> dict | None:
    manifest_url = f"{DOCKER_HUB_REGISTRY_URL}/{repository_path_for_api}/manifests/{reference}"
    headers = {"Authorization": f"Bearer {auth_token}", "Accept": ACCEPT_HEADERS_MANIFEST_LIST_FIRST}
    # print(f"Fetching manifest from: {manifest_url}")
    try:
        response = requests.get(manifest_url, headers=headers, timeout=20); response.raise_for_status(); manifest_data = response.json()
        media_type = manifest_data.get("mediaType", "")
        if media_type == MANIFEST_LIST_V2_TYPE or media_type == OCI_INDEX_V1_TYPE:
            # print(f"Received a manifest list/index. Searching for linux/amd64...")
            for manifest_entry in manifest_data.get("manifests", []):
                platform = manifest_entry.get("platform", {});
                if platform.get("os") == "linux" and platform.get("architecture") == "amd64":
                    digest = manifest_entry.get("digest")
                    if digest: 
                        # print(f"Found linux/amd64 manifest digest: {digest}. Fetching it...")
                        return fetch_image_manifest_from_docker_hub(repository_path_for_api, digest, auth_token)
            print("Error: linux/amd64 manifest not found in manifest list."); return None
        if media_type == MANIFEST_V2_SCHEMA2_TYPE or media_type == OCI_MANIFEST_V1_TYPE:
            # print(f"Successfully fetched image manifest (MediaType: {media_type}).")
            return manifest_data
        print(f"Warning: Received manifest with unexpected mediaType: {media_type}."); return manifest_data
    except requests.exceptions.RequestException as e: print(f"Error fetching manifest for {repository_path_for_api}:{reference}: {e}")
    except json.JSONDecodeError as e: print(f"Error decoding manifest JSON for {repository_path_for_api}:{reference}: {e}")
    return None

def fetch_layer_blob(repository_path_for_api: str, layer_digest: str, auth_token: str) -> bytes | None:
    layer_url = f"{DOCKER_HUB_REGISTRY_URL}/{repository_path_for_api}/blobs/{layer_digest}"
    headers = {"Authorization": f"Bearer {auth_token}"}
    # print(f"Fetching layer blob: {layer_digest} from {layer_url}")
    try:
        response = requests.get(layer_url, headers=headers, timeout=300, stream=True); response.raise_for_status()
        layer_content = b'';
        for chunk in response.iter_content(chunk_size=8192 * 10): layer_content += chunk
        # print(f"Successfully fetched layer blob: {layer_digest} (Size: {len(layer_content)} bytes)")
        return layer_content
    except requests.exceptions.RequestException as e: print(f"Error fetching layer blob {layer_digest}: {e}")
    except Exception as e: print(f"An unexpected error occurred fetching layer blob {layer_digest}: {e}")
    return None

# --- MODIFIED FUNCTION TO PROCESS DOWNLOADED LAYERS ---
def process_image_layers(layers_data: list[bytes], image_name_for_scan_hint: str) -> tuple[dict | None, list[dict], list[Package]]:
    """
    Processes downloaded layer blobs to extract OS info, OS packages (as dicts), and App packages (as Package objects).
    Returns: (os_info_dict, os_package_dicts, app_package_objects)
    """
    print(f"\n--- Processing {len(layers_data)} downloaded layers for {image_name_for_scan_hint} ---")
    
    image_filesystem_view = {}
    whiteout_paths = set()

    for i, layer_blob_bytes in enumerate(layers_data):
        if not layer_blob_bytes: continue
        try:
            decompressed_tar_bytes = gzip.decompress(layer_blob_bytes)
            layer_tar_file_object = io.BytesIO(decompressed_tar_bytes)
            with tarfile.open(fileobj=layer_tar_file_object, mode='r') as layer_tar:
                for member in layer_tar.getmembers():
                    member_path = Path(member.name)
                    if member_path.name.startswith(".wh."):
                        original_name = member_path.name[len(".wh."):]
                        whited_out_path_str = str(member_path.parent / original_name).replace("\\", "/").lstrip('./').lstrip('/')
                        whiteout_paths.add(whited_out_path_str)
                        if whited_out_path_str in image_filesystem_view:
                            del image_filesystem_view[whited_out_path_str]
                        continue
                    normalized_path_str = member.name.lstrip('./').lstrip('/')
                    if member.isfile():
                        file_content_reader = layer_tar.extractfile(member)
                        if file_content_reader:
                            image_filesystem_view[normalized_path_str] = file_content_reader.read()
                            file_content_reader.close()
        except Exception as e:
            print(f"  Error processing layer {i+1}: {e}. Skipping.")

    final_image_files = {
        path: content for path, content in image_filesystem_view.items()
        if path not in whiteout_paths
    }
    print(f"--- Extracted {len(final_image_files)} files from layers (after whiteouts). Analyzing... ---")
    
    os_info = None
    # Store OS packages as list of dicts, preserving original version strings
    os_package_dicts = []
    app_package_objects = [] # App packages will still be Package objects

    for file_path_str, file_content_bytes in final_image_files.items():
        if file_path_str == "etc/os-release" or file_path_str == "usr/lib/os-release":
            if not os_info: 
                os_info = image_parser.parse_os_release(file_content_bytes)
        elif 'var/lib/dpkg/status' in file_path_str: # Check if path contains the target
            os_package_dicts.extend(image_parser.parse_dpkg_status(file_content_bytes))
        elif 'lib/apk/db/installed' in file_path_str:
            os_package_dicts.extend(image_parser.parse_apk_installed(file_content_bytes, source_hint=file_path_str))
        elif file_path_str.endswith("requirements.txt"):
            app_package_objects.extend(app_parser.parse_requirements(file_content_bytes.decode('utf-8', errors='ignore'), source_hint=file_path_str))
        elif file_path_str.endswith("package-lock.json"):
            app_package_objects.extend(app_parser.parse_package_lock(file_content_bytes.decode('utf-8', errors='ignore'), source_hint=file_path_str))

    if os_info: print(f"Detected OS Info: {os_info.get('PRETTY_NAME', 'N/A')}")
    if os_package_dicts: print(f"Parsed {len(os_package_dicts)} OS package entries (as dicts). First few: {os_package_dicts[:2]}")
    if app_package_objects: print(f"Parsed {len(app_package_objects)} App packages (as Package objects). First few: {app_package_objects[:2]}")
    
    return os_info, os_package_dicts, app_package_objects


# --- MODIFIED FUNCTION TO SCAN IMAGE FROM REGISTRY ---
def scan_image_from_registry(full_image_name: str) -> list[ScanResult]:
    """
    Orchestrates fetching an image from registry, processing its layers, and scanning.
    """
    print(f"\n--- Starting REGISTRY SCAN for image: {full_image_name} ---")
    all_scan_results = []
    
    try:
        vulndb.get_db_connection()
    except Exception as db_err:
        print(f"Fatal: Could not connect to vulnerability database: {db_err}")
        return []

    repository_path_for_api, reference, repository_path_for_auth_scope = parse_full_image_name(full_image_name)
    auth_token = get_docker_hub_auth_token(repository_path_for_auth_scope)
    if not auth_token:
        vulndb.close_db_connection()
        return []
        
    manifest = fetch_image_manifest_from_docker_hub(repository_path_for_api, reference, auth_token)
    collected_layers_data = []

    if manifest:
        layers_metadata = manifest.get('layers', [])
        print(f"Manifest has {len(layers_metadata)} layers. Downloading...")
        for i, layer_meta in enumerate(layers_metadata):
            layer_digest = layer_meta.get('digest')
            if layer_digest:
                layer_blob_bytes = fetch_layer_blob(repository_path_for_api, layer_digest, auth_token)
                if layer_blob_bytes:
                    collected_layers_data.append(layer_blob_bytes)
                else:
                    print(f"    Warning: Failed to download layer {layer_digest}. Scan might be incomplete.")
        
        if collected_layers_data:
            # Process layers to get OS info, OS package dicts, and App Package objects
            os_info, os_package_dicts, app_package_objects = process_image_layers(
                collected_layers_data,
                image_name_for_scan_hint=full_image_name
            )

            # Perform OS Package Scanning (using the list of dicts)
            if os_info and os_package_dicts:
                distro_id = os_info.get('ID', '').lower()
                release_identifier_for_vuln_db = os_info.get('VERSION_CODENAME', '').lower()
                if distro_id == 'debian' and not release_identifier_for_vuln_db and os_info.get('VERSION_ID') == '10': # Specific buster fallback
                    release_identifier_for_vuln_db = 'buster'
                elif distro_id == 'alpine' and not release_identifier_for_vuln_db:
                    version_id = os_info.get('VERSION_ID', '')
                    if version_id:
                        major_minor = '.'.join(version_id.split('.')[:2])
                        release_identifier_for_vuln_db = f"v{major_minor}"
                
                if release_identifier_for_vuln_db:
                    print(f"\nScanning {len(os_package_dicts)} OS packages for {distro_id} {release_identifier_for_vuln_db}...")
                    os_vuln_db_data = vulndb.load_os_vulnerabilities(distro_id, release_identifier_for_vuln_db)
                    if os_vuln_db_data:
                        if distro_id in ['debian', 'ubuntu']:
                            all_scan_results.extend(scanner.scan_debian_os_packages(os_package_dicts, distro_id, release_identifier_for_vuln_db, os_vuln_db_data))
                        elif distro_id == 'alpine':
                             all_scan_results.extend(scanner.scan_alpine_os_packages(os_package_dicts, distro_id, release_identifier_for_vuln_db, os_vuln_db_data))
                    else:
                        print(f"Warning: No OS vulnerability data loaded for {distro_id} {release_identifier_for_vuln_db}. Skipping OS scan.")
                else:
                    print(f"Warning: Could not determine release identifier for OS {distro_id} {os_info.get('VERSION_ID', '')}. Skipping OS scan.")
            
            # Perform Application Dependency Scanning
            if app_package_objects:
                print(f"\nScanning {len(app_package_objects)} application packages found in image layers...")
                all_scan_results.extend(scanner.scan_application_dependencies(app_package_objects))
        else:
            print("No layers were successfully downloaded for processing.")
    else:
        print(f"--- Failed to retrieve manifest for {full_image_name}. Cannot scan. ---")
    
    vulndb.close_db_connection()
    print(f"--- REGISTRY SCAN for {full_image_name} finished. Found {len(all_scan_results)} total vulnerabilities. ---")
    return all_scan_results


# --- Example Usage (for testing this module directly) ---
if __name__ == "__main__":
    # Step 1: Ensure the local database has OS vulnerability data for Debian Stretch
    # This part is important for the OS scan to find vulnerabilities.
    print("--- Pre-Test: Ensuring local DB has Debian Stretch data ---")
    try:
        vulndb.get_db_connection() # Open connection
        from . import fetcher # Ensure fetcher is imported
        
        print("Fetching Debian Stretch OS vulnerability data into local DB (if not recent)...")
        # Ideally, you'd check if data for 'debian_stretch' already exists and is recent.
        # For this test, we'll just call the fetcher.
        fetcher.fetch_and_store_debian_data('stretch') # This will use the local DB path
        print("Debian Stretch OS data fetch attempt complete.")
    except Exception as e:
        print(f"Error during pre-test DB setup for Debian Stretch: {e}")
    finally:
        vulndb.close_db_connection() # Close connection if opened by this block
    
    print("-" * 70)

    # Step 2: Scan an older image known to likely have vulnerabilities
    VULNERABLE_IMAGE_NAME_TAG = "debian:9-slim" # Debian Stretch Slim
    
    # Call scan_image_from_registry directly with the name:tag
    # The function itself will handle resolving to the correct manifest (including multi-arch)
    results_vulnerable_image = scan_image_from_registry(VULNERABLE_IMAGE_NAME_TAG)
    
    print(f"\nScan results for {VULNERABLE_IMAGE_NAME_TAG} : {len(results_vulnerable_image)} vulnerabilities.")
    
    if results_vulnerable_image:
        print(f"\nTop Vulnerabilities Found in {VULNERABLE_IMAGE_NAME_TAG} (example):")
        # Ensure SEVERITY_ORDER is defined or imported if scanner.py is not directly run
        SEVERITY_ORDER = { "UNKNOWN": 0, "NONE": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5 } 
        sorted_results = sorted(results_vulnerable_image, key=lambda r: (SEVERITY_ORDER.get(r.vulnerability.severity.upper(), 0)), reverse=True)
        for res in sorted_results[:25]: # Print top 25 or fewer
            print(f"  Severity: {res.vulnerability.severity:<8} CVE: {res.vulnerability.cve_id:<20} Package: {res.package.name:<25} Version: {str(res.package.version):<20}")
    else:
        print(f"No vulnerabilities found for {VULNERABLE_IMAGE_NAME_TAG} (or scan failed to retrieve data).")
