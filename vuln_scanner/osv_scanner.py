# vuln_scanner/osv_scanner.py
import requests
import json
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
    "pypi": "PyPI", # Allow both
    "node.js": "npm",
    "npm": "npm", # Allow both
    # Add other ecosystems as we support their parsers
    # "maven": "Maven",
    # "go": "Go",
    # "rubygems": "RubyGems",
}

def get_osv_ecosystem(package_name: str, source_hint: str) -> str | None:
    """Determines the OSV ecosystem based on package name or source hint."""
    # Basic logic - needs improvement for robustness
    # For now, assume python files are PyPI and node files are npm
    # This won't work well if analyzing mixed files or needing more context.
    # A better approach might involve passing the parser type or using PURLs if available.
    if source_hint.endswith('.txt') or 'python' in package_name.lower(): # Very rough guess
         return ECOSYSTEM_MAP.get('python')
    if source_hint.endswith('.json') or 'node' in source_hint: # Rough guess
         return ECOSYSTEM_MAP.get('npm')

    # Check common node scoped packages
    if package_name.startswith('@'):
         return ECOSYSTEM_MAP.get('npm')

    # Default guess (highly unreliable) - return None to indicate uncertainty
    print(f"Warning: Could not determine OSV ecosystem for package '{package_name}' from source '{source_hint}'.")
    return None


def query_osv_for_packages(packages: list[Package]) -> dict | None:
    """
    Queries the OSV API batch endpoint for vulnerabilities affecting the given packages.
    Returns the parsed JSON response from OSV or None on error.
    """
    if not packages:
        return {"results": []} # Return structure similar to OSV for empty input

    print(f"Querying OSV API for {len(packages)} application packages...")
    queries = []
    skipped_packages = 0
    package_registry = {} # Track which original Package object corresponds to query index

    for i, pkg in enumerate(packages):
        osv_ecosystem_name = None
        if pkg.ecosystem: # Check if ecosystem is set on the package
            osv_ecosystem_name = ECOSYSTEM_MAP.get(pkg.ecosystem.lower()) # Map to OSV's specific name

        if not osv_ecosystem_name:
            print(f"Warning: Skipping OSV query for '{pkg.name}@{pkg.version}' - unknown or unmapped ecosystem '{pkg.ecosystem}'.")
            skipped_packages += 1
            continue
        # --- End ecosystem handling ---

        package_registry[i] = pkg # Store original package by index
        queries.append({
            "version": str(pkg.version),
            "package": {
                "name": pkg.name,
                "ecosystem": osv_ecosystem_name
                # "purl": pkg.purl # Using Package URL would be more robust if available
            }
        })

    if not queries:
         print("No packages could be mapped to a known OSV ecosystem for OSV query.")
         return {"results": []}

    request_body = {"queries": queries}
    # print(f"DEBUG OSV: Request body: {json.dumps(request_body, indent=2)}") # Very verbose

    try:
        response = requests.post(OSV_API_BATCH_URL, json=request_body, timeout=OSV_TIMEOUT)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        # --- Corrected Debug Print Logic ---
        original_response_json = response.json() # Parse original JSON first

        # Print the ORIGINAL response BEFORE modifying it
        #print("\n" + "-"*10 + " RAW OSV API RESPONSE " + "-"*10)
        #print(json.dumps(original_response_json, indent=2)) # Dump original data
        #print("-" * 10 + " END RAW OSV API RESPONSE " + "-"*10 + "\n")

        print(f"OSV API query successful ({response.status_code}). Found results for {len(original_response_json.get('results', []))} queries.")

        # NOW, add our internal mapping to the dictionary we will return
        original_response_json['_package_registry'] = package_registry
        return original_response_json
        # --- End Corrected Logic ---

    except requests.exceptions.RequestException as e:
        print(f"Error querying OSV API: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding OSV API response: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during OSV query: {e}")
        return None

def get_osv_vuln_details(vuln_id: str) -> dict | None:
    """
    Fetches detailed information for a single OSV vulnerability ID.
    Returns the parsed JSON details or None on error.
    """
    if not vuln_id:
        return None

    # print(f"DEBUG OSV: Fetching details for {vuln_id}...") # Optional Debug
    details_url = OSV_API_VULN_URL + vuln_id # Construct URL like https://api.osv.dev/v1/vulns/GHSA-XXXX-...
    try:
        response = requests.get(details_url, timeout=OSV_TIMEOUT)
        response.raise_for_status()
        # print(f"DEBUG OSV: Details fetched successfully for {vuln_id}") # Optional Debug
        # *** ADD THIS BLOCK TO PRINT DETAILED RESPONSE ***
        parsed_details_json = response.json()
        print(f"\n--- RAW OSV DETAIL RESPONSE for {vuln_id} ---")
        print(json.dumps(parsed_details_json, indent=2))
        print(f"--- END RAW OSV DETAIL RESPONSE for {vuln_id} ---\n")
        # *** END ADDED BLOCK ***

        return parsed_details_json
        #return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching OSV details for {vuln_id}: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding OSV details JSON for {vuln_id}: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred fetching OSV details for {vuln_id}: {e}")
        return None