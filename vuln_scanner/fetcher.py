# vuln_scanner/fetcher.py
import requests
import time
import json
import math
import bz2
import re
import gzip 
import io
import xml.etree.ElementTree as ET # For parsing XML data
from . import vulndb # Import our database module

# Constants for NVD API v2.0
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEBIAN_DATA_URL_TEMPLATE = "https://security-tracker.debian.org/tracker/data/json/{codename}.json"
# NVD recommended max results per page is 2000
RESULTS_PER_PAGE = 2000
# Public rate limit delay (without API key) - NVD requests ~6 seconds wait
# Using an API Key is HIGHLY recommended for faster/more reliable fetching
# See: https://nvd.nist.gov/developers/request-an-api-key
REQUEST_DELAY_SECONDS = 6 # Increase if you get rate limited, decrease/remove if using an API key
DEBIAN_OVAL_URL_TEMPLATE = "https://www.debian.org/security/oval/oval-definitions-{codename}.xml.bz2"
ALPINE_SECDB_URL_TEMPLATE = "https://secdb.alpinelinux.org/{version_branch}/{repository}.json"

def fetch_page_from_nvd(start_index=0):
    """Fetches a single page of CVE data from the NVD API."""
    params = {
        'resultsPerPage': RESULTS_PER_PAGE,
        'startIndex': start_index
        # Add other parameters here if needed (e.g., lastModStartDate)
        # 'lastModStartDate': '2023-01-01T00:00:00.000'
    }
    # Define headers here, including API key if you get one from NVD
    headers = {
        # 'apiKey': 'YOUR_NVD_API_KEY_GOES_HERE'
    }
    print(f"Fetching NVD data starting at index {start_index}...")

    try:
        # Make sure to add a timeout to prevent hanging indefinitely
        response = requests.get(NVD_API_BASE_URL, params=params, headers=headers, timeout=60) # Increased timeout
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        print(f"Successfully fetched page (status {response.status_code}).")
        return response.json() # Return parsed JSON

    except requests.exceptions.Timeout:
        print(f"Error: Request timed out while fetching NVD data (startIndex={start_index}).")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error fetching NVD data (startIndex={start_index}): {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding NVD JSON response (startIndex={start_index}): {e}")
        # It might be useful to see the text that failed to parse
        # print(f"Response text: {response.text[:500]}") # Limit output length
        return None
    finally:
        # IMPORTANT: Wait to comply with NVD public rate limits
        # Remove or reduce significantly if using an API key
        # Only sleep if no API key is provided in headers
        if not headers.get('apiKey'):
            print(f"Waiting {REQUEST_DELAY_SECONDS} seconds before next request (public rate limit)...")
            time.sleep(REQUEST_DELAY_SECONDS)
        else:
            # Even with an API key, a small delay might be polite
            time.sleep(0.5)

# Add this function to vuln_scanner/fetcher.py

def fetch_and_store_single_cve(cve_id: str | None):
    """Fetches and stores data for a single CVE ID."""
    # --- SAFETY CHECK ADDED ---
    if not cve_id or not isinstance(cve_id, str) or not cve_id.upper().startswith("CVE-"):
         print(f"Error: Invalid or missing CVE ID provided for fetch: {cve_id}")
         return # Stop execution if ID is invalid
    # --- END CHECK ---

    cve_id = cve_id.upper() # Ensure uppercase
    print(f"Attempting to fetch specific CVE: {cve_id}...")
    single_cve_url = f"{NVD_API_BASE_URL}?cveId={cve_id}"
    headers = { # Add API key header if using NVD API key
         # 'apiKey': os.environ.get("NVD_API_KEY")
    }

    try:
        response = requests.get(single_cve_url, headers=headers, timeout=30)
        response.raise_for_status()
        nvd_data = response.json()
        print(f"Successfully fetched {cve_id}.")

        # Reuse the existing parse_and_store_cves logic
        # It expects the full response structure containing 'vulnerabilities' list
        conn = vulndb.get_db_connection() # Need connection/cursor
        cursor = conn.cursor()
        stored_count = parse_and_store_cves(nvd_data) # Pass full dict

        if stored_count > 0:
            print(f"Successfully stored/updated data for {cve_id} in the database.")
        else:
            # parse_and_store_cves might return 0 if vuln already existed and was identical
            # or if parsing failed (check its logs)
            print(f"Data for {cve_id} processed, stored count: {stored_count}.")
        conn.commit() # Commit after storing

    except requests.exceptions.RequestException as e:
        print(f"Error fetching NVD data for {cve_id}: {e}")
    except json.JSONDecodeError as e:
        print(f"Error decoding NVD JSON response for {cve_id}: {e}")
    except Exception as e:
         print(f"An unexpected error occurred storing details for {cve_id}: {e}")

    # Connection closed by finally block in main.py, no need to close here generally


def parse_and_store_cves(nvd_response_json):
    """Parses NVD JSON response and stores CVEs in the database."""
    if not nvd_response_json or 'vulnerabilities' not in nvd_response_json:
        print("No vulnerabilities found in the NVD response or invalid response.")
        return 0 # Return count of stored CVEs

    vulnerabilities = nvd_response_json.get('vulnerabilities', [])
    stored_count = 0
    skipped_count = 0

    # Get DB connection and cursor (should already be open if called from update_vulnerability_db)
    conn = vulndb.get_db_connection()
    cursor = conn.cursor()

    for item in vulnerabilities:
        cve = item.get('cve', {})
        if not cve:
            skipped_count += 1
            continue

        cve_id = cve.get('id')
        if not cve_id:
            skipped_count += 1
            continue

        # --- Basic Parsing (Simplified) ---
        description = "No description available."
        # Find English description
        for desc_data in cve.get('descriptions', []):
            if desc_data.get('lang') == 'en':
                description = desc_data.get('value', description)
                break

        last_modified = cve.get('lastModified')

        # Extract CVSS V3.1 metrics if available
        cvss_v3_score = None
        cvss_v3_vector = None
        metrics = cve.get('metrics', {})
        # Prefer CVSS V3.1, fall back to V3.0 if necessary
        # NVD JSON structure can place metrics directly or within cvssMetricV31/V30 arrays
        cvss_metrics = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))

        if cvss_metrics:
            # NVD typically provides one primary metric in this list per type (V31/V30)
            # Use the first entry which is usually the NVD analysis
            cvss_data = cvss_metrics[0].get('cvssData', {})
            cvss_v3_score = cvss_data.get('baseScore')
            cvss_v3_vector = cvss_data.get('vectorString')
        else:
            # Handle cases where metrics might be structured differently or absent
            pass # Keep score/vector as None

        # Store configurations as raw JSON string for now
        configurations = None
        if 'configurations' in cve:
             # Ensure it's stored as a JSON string, even if it's None/empty
             configurations = json.dumps(cve['configurations'])


        cve_detail = {
            "cve_id": cve_id,
            "description": description,
            "cvss_v3_score": cvss_v3_score,
            "cvss_v3_vector": cvss_v3_vector,
            "configurations": configurations,
            "last_modified": last_modified
        }

        # --- Store in DB ---
        try:
            # Pass the cursor and the parsed details
            vulndb.insert_vulnerability(cursor, cve_detail)
            stored_count += 1
        except Exception as e: # Catch specific DB errors if needed
            print(f"Error inserting/replacing CVE {cve_id}: {e}")
            skipped_count += 1

    # Commit changes made in this batch
    try:
        conn.commit()
        print(f"Committed {stored_count} CVEs to database for this page.")
    except Exception as e:
        print(f"Database commit failed: {e}")
        # Consider rolling back if necessary conn.rollback()

    if skipped_count > 0:
        print(f"Skipped {skipped_count} entries during parsing/storage for this page.")

    return stored_count

def fetch_and_store_debian_data(release_codename: str):
    """
    Fetches Debian OVAL vulnerability data (bz2 compressed) for a specific
    release codename, parses the XML, and stores relevant info.
    """
    if not release_codename:
        print("Error: Debian release codename required.")
        return

    print(f"Attempting to fetch and store Debian OVAL data for '{release_codename}'...")
    data_url = DEBIAN_OVAL_URL_TEMPLATE.format(codename=release_codename)
    print(f"Using data URL: {data_url}")
    xml_content = None

    try:
        response = requests.get(data_url, timeout=120, stream=True) # Increased timeout slightly
        response.raise_for_status()

        # Decompress bz2 content in memory
        print("Decompressing downloaded bz2 data...")
        # Use bz2.decompress
        xml_content = bz2.decompress(response.content)
        print(f"Successfully downloaded and decompressed OVAL data for {release_codename}.")

    except requests.exceptions.RequestException as e:
        print(f"Error fetching Debian OVAL data for {release_codename} from {data_url}: {e}")
        return
    # Add specific check for bz2 errors if needed, though decompress handles basic ones
    except Exception as e:
        print(f"An unexpected error occurred during download/decompression: {e}")
        return

    if not xml_content:
        print("Failed to get XML content.")
        return

    # --- Parsing OVAL XML ---
    print("Parsing OVAL XML data (this can take a while)...")
    conn = vulndb.get_db_connection()
    cursor = conn.cursor()
    stored_count = 0
    processed_count = 0
    skipped_count = 0

    try:
        # Register namespaces (same as before)
        temp_root = ET.fromstring(xml_content)
        namespaces = dict([ node for _, node in ET.iterparse(io.BytesIO(xml_content), events=['start-ns']) ])
        main_ns_uri = temp_root.tag.split('}')[0][1:]
        if main_ns_uri and 'oval-def' not in namespaces: namespaces['oval-def'] = main_ns_uri
        if not namespaces: namespaces = {'oval-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5'}
        print(f"Using XML Namespaces: {namespaces}")
        root = temp_root

        definitions = root.find('.//oval-def:definitions', namespaces)
        if definitions is None: print("Error: Could not find 'definitions' element."); return

        print(f"Processing {len(definitions)} definitions...")
        comment_regex = re.compile(r"(\S+)\s+DPKG\s+is\s+earlier\s+than\s+(\S+)")

        for definition in definitions.findall('.//oval-def:definition', namespaces):
            processed_count += 1
            # ... (Keep the existing extraction logic using find and namespaces) ...
            vuln_id=None; package_name=None; fixed_version=None; status="unknown"; severity=None

            cve_ref_element = definition.find('.//oval-def:reference[@source="CVE"]', namespaces)
            if cve_ref_element is not None: vuln_id = cve_ref_element.get('ref_id')
            if not vuln_id: skipped_count += 1; continue

            prod_element = definition.find('.//oval-def:affected/oval-def:product', namespaces)
            if prod_element is not None and prod_element.text: package_name = prod_element.text.strip()
            else: skipped_count += 1; continue

            criteria = definition.findall('.//oval-def:criterion', namespaces)
            for criterion in criteria:
                comment = criterion.get('comment', '')
                if "DPKG is earlier than" in comment:
                    match = comment_regex.search(comment)
                    if match:
                        # Basic check: ensure package name in comment matches product tag
                        # This avoids mismatches if multiple packages are in one definition (less common)
                        comment_pkg = match.group(1)
                        if comment_pkg == package_name:
                             fixed_version = match.group(2)
                             status = "resolved"
                             break # Found the primary fix version for this package

            # Store if we have the core info
            if package_name and fixed_version:
                vuln_record = {
                    "vuln_id": vuln_id, "os_distro": "debian",
                    "os_release_codename": release_codename, "package_name": package_name,
                    "fixed_version": fixed_version, "status": status, "severity": severity
                }
                vulndb.insert_os_vulnerability(cursor, vuln_record)
                stored_count += 1
            else:
                skipped_count += 1

    except ET.ParseError as e: print(f"Error parsing Debian OVAL XML: {e}"); return
    except Exception as e: print(f"An unexpected error occurred during OVAL parsing: {e}"); return

    # Commit all insertions
    try:
        conn.commit()
        print(f"\nProcessed {processed_count} definitions.")
        print(f"Committed {stored_count} Debian ({release_codename}) vulnerability entries.")
        if skipped_count > 0: print(f"Skipped {skipped_count} entries during parsing.")
        # --- ADD THIS LINE ---
        vulndb.update_data_source_timestamp(f"debian_{release_codename.lower()}")
        # --- END ADD ---
    except Exception as e:
        print(f"Database commit failed for Debian ({release_codename}) data: {e}")

def fetch_and_store_alpine_data(alpine_version_branch: str):
    """
    Fetches Alpine Linux vulnerability data (secdb) for a specific version branch
    (e.g., 'v3.18', 'v3.19') from main and community repositories, parses it,
    and stores relevant info in the os_vulnerabilities table.
    """
    if not alpine_version_branch:
        print("Error: Alpine version branch required (e.g., 'v3.21').")
        return

    print(f"Attempting to fetch and store Alpine secdb data for '{alpine_version_branch}'...")
    conn = vulndb.get_db_connection()
    cursor = conn.cursor()
    total_stored_count = 0

    for repository in ["main", "community"]:
        data_url = ALPINE_SECDB_URL_TEMPLATE.format(version_branch=alpine_version_branch, repository=repository)
        print(f"Using data URL: {data_url}")
        alpine_data = None

        try:
            response = requests.get(data_url, timeout=30)
            response.raise_for_status()
            alpine_data = response.json()
            print(f"Successfully downloaded secdb for {alpine_version_branch}/{repository}.")
        except requests.exceptions.RequestException as e:
            print(f"Error fetching Alpine secdb for {alpine_version_branch}/{repository} from {data_url}: {e}")
            continue # Try next repository
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON for Alpine secdb {alpine_version_branch}/{repository} from {data_url}: {e}")
            continue # Try next repository
        except Exception as e:
            print(f"An unexpected error occurred during download for {alpine_version_branch}/{repository}: {e}")
            continue # Try next repository

        if not alpine_data or 'packages' not in alpine_data:
            print(f"Warning: No 'packages' array found in {data_url}")
            continue

        # --- Parsing Alpine SecDB JSON ---
        print(f"Parsing {len(alpine_data['packages'])} package entries from {repository} secdb...")
        repo_stored_count = 0
        repo_skipped_count = 0

        for package_entry in alpine_data.get('packages', []):
            pkg_info = package_entry.get('pkg')
            if not pkg_info or not isinstance(pkg_info, dict):
                repo_skipped_count += 1
                continue

            package_name = pkg_info.get('name')
            secfixes = pkg_info.get('secfixes')

            if not package_name or not isinstance(secfixes, dict):
                repo_skipped_count += 1
                continue

            for fixed_version, vuln_ids in secfixes.items():
                if isinstance(vuln_ids, list):
                    for vuln_id_str in vuln_ids:
                        # Alpine secdb often lists multiple CVEs separated by spaces for one fix
                        for actual_vuln_id in vuln_id_str.split():
                            if not actual_vuln_id.upper().startswith("CVE-"):
                                # print(f"Skipping non-CVE ID {actual_vuln_id} for {package_name}")
                                continue # For now, only interested in CVEs

                            vuln_record = {
                                "vuln_id": actual_vuln_id.upper(),
                                "os_distro": "alpine",
                                # Store the version branch (e.g., v3.21) as the codename/release identifier
                                "os_release_codename": alpine_version_branch,
                                "package_name": package_name,
                                "fixed_version": fixed_version,
                                "status": "resolved", # Assumed if a fixed_version is listed
                                "severity": None # Alpine secdb JSON doesn't usually provide severity directly
                            }
                            vulndb.insert_os_vulnerability(cursor, vuln_record)
                            repo_stored_count += 1
                # else: # Should be a list
                    # print(f"Warning: Expected list of vuln_ids for {package_name}@{fixed_version}, got {type(vuln_ids)}")


        try:
            conn.commit()
            print(f"Committed {repo_stored_count} Alpine ({alpine_version_branch}/{repository}) vulnerability entries.")
            if repo_skipped_count > 0: print(f"Skipped {repo_skipped_count} package entries during parsing for {repository}.")
            total_stored_count += repo_stored_count
        except Exception as e:
            print(f"Database commit failed for Alpine ({alpine_version_branch}/{repository}) data: {e}")

    print(f"\nFinished fetching Alpine data. Total committed entries for {alpine_version_branch}: {total_stored_count}")
    # --- ADD THIS LINE (if total_stored_count > 0 or some other success criteria) ---
    if total_stored_count > 0: # Only update timestamp if we actually stored something
        vulndb.update_data_source_timestamp(f"alpine_{alpine_version_branch.lower()}")
    # --- END ADD ---


def update_vulnerability_db(max_pages=None):
    """Fetches CVEs from NVD and updates the local SQLite DB."""
    print("Starting NVD vulnerability database update...") # Clarified NVD
    start_index = 0
    total_results = -1 # Unknown initially
    total_stored_cves_in_session = 0 # Renamed for clarity vs stored_on_page
    pages_fetched = 0
    fetch_error_occurred = False

    try:
        # Ensure DB connection is established at the beginning of the update process
        conn = vulndb.get_db_connection()
    except Exception as db_conn_err:
        print(f"Failed to establish initial DB connection for NVD update: {db_conn_err}")
        return # Cannot proceed without DB connection

    while True:
        nvd_data = fetch_page_from_nvd(start_index) # This function includes its own rate limit delay

        if nvd_data is None:
            print("Failed to fetch data from NVD. Aborting NVD update (check network/API limits).")
            fetch_error_occurred = True
            break # Exit loop on fetch failure

        if total_results == -1: # First successful fetch
            total_results = nvd_data.get('totalResults', 0)
            print(f"NVD reports total results: {total_results}")
            if total_results == 0:
                print("No results reported by NVD. Stopping.")
                break

        # Process the current page (parse_and_store_cves commits per page)
        # Ensure conn is passed if parse_and_store_cves needs it, or relies on module-level _connection
        stored_on_page = parse_and_store_cves(nvd_data) # Assuming this uses the established conn
        total_stored_cves_in_session += stored_on_page
        pages_fetched += 1

        current_results_count = len(nvd_data.get('vulnerabilities', []))
        # Check if we are done
        if current_results_count == 0 and start_index < total_results and total_results > 0 :
            print("Received page with 0 results before expected end. Stopping NVD update.")
            break

        start_index += current_results_count
        print(f"NVD Progress: Processed {start_index}/{total_results} results. Stored {total_stored_cves_in_session} total CVEs this session.")

        # Check stopping conditions
        if current_results_count < RESULTS_PER_PAGE and total_results > 0: # Also check total_results to avoid breaking if 0 results initially
            print("Reached the last page of NVD results.")
            break

        if start_index >= total_results and total_results > 0:
             print(f"NVD Processed index ({start_index}) reached or exceeded total results ({total_results}).")
             break

        if max_pages is not None and pages_fetched >= max_pages:
            print(f"Reached specified maximum NVD pages ({max_pages}). Stopping.")
            break

    # --- After the loop ---
    if not fetch_error_occurred and pages_fetched > 0:
        try:
            # Ensure the connection is still valid / re-establish if necessary
            # vulndb.get_db_connection() # Already called at start of function
            vulndb.update_data_source_timestamp("nvd") # Update timestamp for "nvd"
        except Exception as e_ts:
            print(f"Error updating NVD timestamp: {e_ts}")
    elif fetch_error_occurred:
        print("NVD data fetch was not fully successful. Timestamp not updated.")
    elif pages_fetched == 0 and total_results == 0:
        print("No NVD data to update timestamp for (0 results reported by NVD).")
    elif pages_fetched == 0:
         print("No NVD pages were fetched. Timestamp not updated.")


    print(f"\nNVD Database update finished. Fetched {pages_fetched} pages.")
    print(f"Attempted to store/update {total_stored_cves_in_session} NVD CVEs in total this session.")
    # Connection is closed by main.py's finally block, so no vulndb.close_db_connection() here.