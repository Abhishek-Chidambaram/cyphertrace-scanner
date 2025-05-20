# vuln_scanner/osv_scanner.py
import requests
import json
import time # Added for OSV delay
from .models import Package # Import Package to use type hint

OSV_API_BATCH_URL = "https://api.osv.dev/v1/querybatch"
# Timeout for API requests in seconds
OSV_TIMEOUT = 30
# --- NEW Function to Get Vuln Details ---
OSV_API_VULN_URL = "https://api.osv.dev/v1/vulns/" # Note the trailing slash

# Mapping our internal/parser ecosystem names to OSV ecosystem names
# OSV ecosystems list: https://osv.dev/docs/#tag/ecosystems
ECOSYSTEM_MAP = {
    "python": "PyPI",
    "pypi": "PyPI",     # Allow both common names for Python
    "node.js": "npm",
    "npm": "npm",       # Allow both common names for Node.js
    "maven": "Maven",   # +++ ADDED/UNCOMMENTED for Java GAVs +++
    # Add other ecosystems as we support their parsers
    # "go": "Go",
    # "rubygems": "RubyGems",
    # "crates.io": "crates.io", # For Rust
    # "composer": "Packagist", # For PHP
    # "nuget": "NuGet", # For .NET
}

def get_osv_ecosystem(package_name: str, source_hint: str) -> str | None:
    """
    Determines the OSV ecosystem based on package name or source hint.
    NOTE: This function is a fallback. Prefer setting ecosystem directly on Package objects.
    """
    # This function's logic remains as is, but it's less critical if Package.ecosystem is set.
    if source_hint.endswith('.txt') or 'python' in package_name.lower():
        return ECOSYSTEM_MAP.get('python')
    if source_hint.endswith('.json') or 'node' in source_hint:
        return ECOSYSTEM_MAP.get('npm')

    if package_name.startswith('@'): # Common for scoped npm packages
        return ECOSYSTEM_MAP.get('npm')

    # If ecosystem can be guessed from package name structure (e.g., for Go, Maven)
    # This is where more sophisticated guessing could go if needed, but direct setting is better.
    # For Maven, the name will be "groupId:artifactId", which doesn't directly scream "Maven"
    # without prior knowledge.

    print(f"Warning: Could not reliably determine OSV ecosystem for package '{package_name}' from source '{source_hint}'.")
    return None


def query_osv_for_packages(packages: list[Package]) -> dict | None:
    """
    Queries the OSV API batch endpoint for vulnerabilities affecting the given packages.
    Returns the parsed JSON response from OSV or None on error.
    The returned dictionary will also include a '_package_registry' key mapping
    query index to the original Package object.
    """
    if not packages:
        return {"results": [], "_package_registry": {}} # Return structure similar to OSV for empty input

    print(f"Querying OSV API for {len(packages)} application packages...")
    queries = []
    skipped_packages = 0
    package_registry = {} # Track which original Package object corresponds to query index

    for i, pkg in enumerate(packages):
        osv_ecosystem_name = None
        if pkg.ecosystem: # Check if ecosystem is set on the package
            osv_ecosystem_name = ECOSYSTEM_MAP.get(pkg.ecosystem.lower()) # Map to OSV's specific name
            if not osv_ecosystem_name:
                 print(f"Warning: Ecosystem '{pkg.ecosystem}' for package '{pkg.name}' is not mapped in ECOSYSTEM_MAP. Trying direct use.")
                 osv_ecosystem_name = pkg.ecosystem # Try direct use if not in map (e.g. if user provides "Maven" directly)
        else:
            # Fallback if pkg.ecosystem is not set (less ideal)
            # Assuming source_hint might be available on pkg or passed differently.
            # For now, this path is less likely with our Java GAV to Package conversion.
            # source_hint_for_pkg = getattr(pkg, 'source_hint', str(pkg.name)) # Example
            # osv_ecosystem_name = get_osv_ecosystem(pkg.name, source_hint_for_pkg)
            print(f"Warning: Ecosystem not provided for package '{pkg.name}@{pkg.version}'. Cannot query OSV without it.")


        if not osv_ecosystem_name:
            print(f"Warning: Skipping OSV query for '{pkg.name}@{pkg.version}' - unknown or unmapped ecosystem '{pkg.ecosystem}'.")
            skipped_packages += 1
            continue
        
        # Ensure pkg.name is a string (it should be based on your Package model)
        # For Maven, pkg.name will be "groupId:artifactId"
        package_name_str = str(pkg.name)
        package_version_str = str(pkg.version) # OSV expects string version

        package_registry[i] = pkg # Store original package by index (using original query index)
        queries.append({
            "version": package_version_str,
            "package": {
                "name": package_name_str,
                "ecosystem": osv_ecosystem_name
                # "purl": pkg.purl # Using Package URL would be more robust if available
            }
        })

    if not queries:
        print("No packages could be mapped to a known OSV ecosystem for OSV query.")
        return {"results": [], "_package_registry": {}}

    request_body = {"queries": queries}
    # print(f"DEBUG OSV: Request body: {json.dumps(request_body, indent=2)}") # Very verbose

    try:
        response = requests.post(OSV_API_BATCH_URL, json=request_body, timeout=OSV_TIMEOUT)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        
        original_response_json = response.json() 

        # print("\n" + "-"*10 + " RAW OSV API BATCH RESPONSE " + "-"*10)
        # print(json.dumps(original_response_json, indent=2)) 
        # print("-" * 10 + " END RAW OSV API BATCH RESPONSE " + "-"*10 + "\n")

        print(f"OSV API batch query successful ({response.status_code}). OSV returned {len(original_response_json.get('results', []))} result entries.")
        if skipped_packages > 0:
            print(f"Skipped {skipped_packages} packages due to missing/unmapped ecosystem.")

        # Add our internal mapping to the dictionary we will return
        # This maps the index in the 'queries' list (and thus 'results' list from OSV)
        # back to the original Package object.
        original_response_json['_package_registry'] = package_registry 
        return original_response_json

    except requests.exceptions.RequestException as e:
        print(f"Error querying OSV API: {e}")
    except json.JSONDecodeError as e:
        print(f"Error decoding OSV API response: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during OSV query: {e}")
    return None # Return None on any error

def get_osv_vuln_details(vuln_id: str) -> dict | None:
    """
    Fetches detailed information for a single OSV vulnerability ID.
    Returns the parsed JSON details or None on error.
    """
    if not vuln_id:
        return None

    # print(f"DEBUG OSV: Fetching details for {vuln_id}...") 
    details_url = OSV_API_VULN_URL + vuln_id 
    try:
        response = requests.get(details_url, timeout=OSV_TIMEOUT)
        response.raise_for_status()
        
        parsed_details_json = response.json()
        # print(f"\n--- RAW OSV DETAIL RESPONSE for {vuln_id} ---") # Keep for debugging if needed
        # print(json.dumps(parsed_details_json, indent=2))
        # print(f"--- END RAW OSV DETAIL RESPONSE for {vuln_id} ---\n")
        
        return parsed_details_json
    except requests.exceptions.RequestException as e:
        print(f"Error fetching OSV details for {vuln_id}: {e}")
    except json.JSONDecodeError as e:
        print(f"Error decoding OSV details JSON for {vuln_id}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred fetching OSV details for {vuln_id}: {e}")
    return None
