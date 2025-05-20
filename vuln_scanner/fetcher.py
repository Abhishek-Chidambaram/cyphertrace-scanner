# vuln_scanner/fetcher.py
import requests
import time
import json
import sqlite3
import math
import bz2
import re
import gzip 
import io
from lxml import etree as ET
#import xml.etree.ElementTree as ET # For parsing XML data
from . import vulndb # Import our database module
from datetime import datetime, timezone # For timestamping

# Constants for NVD API v2.0
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD recommended max results per page is 2000
RESULTS_PER_PAGE = 2000 
REQUEST_DELAY_SECONDS = 6 # For NVD public rate limit without API key

# OS Vulnerability Data URLs
DEBIAN_OVAL_URL_TEMPLATE = "https://www.debian.org/security/oval/oval-definitions-{codename}.xml.bz2"
UBUNTU_OVAL_URL_TEMPLATE =  "https://security-metadata.canonical.com/oval/com.ubuntu.{codename}.cve.oval.xml.bz2" # Canonical's OVAL feed
ALPINE_SECDB_URL_TEMPLATE = "https://secdb.alpinelinux.org/{version_branch}/{repository}.json"
CENTOS_OVAL_URL_TEMPLATE = "https://access.redhat.com/security/data/oval/v2/RHEL{major_version}/rhel-{major_version}-including-unpatched.oval.xml.bz2"


def fetch_page_from_nvd(start_index=0, api_key=None): # Added api_key parameter
    """Fetches a single page of CVE data from the NVD API."""
    params = {
        'resultsPerPage': RESULTS_PER_PAGE,
        'startIndex': start_index
    }
    headers = {}
    if api_key:
        headers['apiKey'] = api_key
    
    # print(f"Fetching NVD data starting at index {start_index}...")
    actual_request_delay = 0.5 if api_key else REQUEST_DELAY_SECONDS


    try:
        response = requests.get(NVD_API_BASE_URL, params=params, headers=headers, timeout=60)
        response.raise_for_status()
        # print(f"Successfully fetched page (status {response.status_code}).")
        return response.json()
    except requests.exceptions.Timeout:
        print(f"Error: Request timed out while fetching NVD data (startIndex={start_index}).")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching NVD data (startIndex={start_index}): {e}")
    except json.JSONDecodeError as e:
        print(f"Error decoding NVD JSON response (startIndex={start_index}): {e}")
    finally:
        if actual_request_delay > 0:
            # print(f"Waiting {actual_request_delay} seconds before next request...")
            time.sleep(actual_request_delay)
    return None

def fetch_and_store_single_cve(cve_id: str | None, api_key=None): # Added api_key
    if not cve_id or not isinstance(cve_id, str) or not cve_id.upper().startswith("CVE-"):
        print(f"Error: Invalid or missing CVE ID provided for fetch: {cve_id}")
        return
    cve_id = cve_id.upper()
    print(f"Attempting to fetch specific CVE: {cve_id}...")
    single_cve_url = f"{NVD_API_BASE_URL}?cveId={cve_id}"
    headers = {}
    if api_key:
        headers['apiKey'] = api_key
    
    try:
        response = requests.get(single_cve_url, headers=headers, timeout=30)
        response.raise_for_status()
        nvd_data = response.json()
        print(f"Successfully fetched {cve_id}.")
        conn = vulndb.get_db_connection()
        cursor = conn.cursor()
        stored_count = parse_and_store_cves(nvd_data, cursor) # Pass cursor
        if stored_count > 0:
            print(f"Successfully stored/updated data for {cve_id} in the database.")
            conn.commit() # Commit after storing
        else:
            print(f"Data for {cve_id} processed, stored count: {stored_count}.")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching NVD data for {cve_id}: {e}")
    except json.JSONDecodeError as e:
        print(f"Error decoding NVD JSON response for {cve_id}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred storing details for {cve_id}: {e}")

def parse_and_store_cves(nvd_response_json, db_cursor): # Takes cursor now
    """Parses NVD JSON response and stores CVEs in the database using the provided cursor."""
    if not nvd_response_json or 'vulnerabilities' not in nvd_response_json:
        print("No vulnerabilities found in the NVD response or invalid response.")
        return 0
    vulnerabilities = nvd_response_json.get('vulnerabilities', [])
    stored_count = 0; skipped_count = 0
    for item in vulnerabilities:
        cve = item.get('cve', {});
        if not cve: skipped_count += 1; continue
        cve_id = cve.get('id');
        if not cve_id: skipped_count += 1; continue
        description = "No description available."
        for desc_data in cve.get('descriptions', []):
            if desc_data.get('lang') == 'en': description = desc_data.get('value', description); break
        last_modified = cve.get('lastModified')
        cvss_v3_score = None; cvss_v3_vector = None
        metrics = cve.get('metrics', {})
        cvss_metrics = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))
        if cvss_metrics:
            cvss_data = cvss_metrics[0].get('cvssData', {})
            cvss_v3_score = cvss_data.get('baseScore')
            cvss_v3_vector = cvss_data.get('vectorString')
        configurations_str = json.dumps(cve.get('configurations')) if 'configurations' in cve else None
        cve_detail = {
            "cve_id": cve_id, "description": description, "cvss_v3_score": cvss_v3_score,
            "cvss_v3_vector": cvss_v3_vector, "configurations": configurations_str, "last_modified": last_modified
        }
        try:
            vulndb.insert_vulnerability(db_cursor, cve_detail)
            stored_count += 1
        except Exception as e:
            print(f"Error inserting/replacing CVE {cve_id}: {e}")
            skipped_count += 1
    # Commit is handled by the calling function (update_vulnerability_db or fetch_and_store_single_cve)
    if skipped_count > 0: print(f"Skipped {skipped_count} entries during parsing/storage for this page.")
    return stored_count

# --- OS OVAL Parsing Logic (Using LXML with Enhanced Debug - V3) ---
# --- OS OVAL Parsing Logic (Adapted for DPKG and RPM, using LXML) ---
def _parse_and_store_oval_definitions(xml_content: bytes, distro_name: str, release_identifier: str, db_cursor):
    # release_identifier for CentOS/RHEL is major version like "7", "8"
    # release_identifier for Debian/Ubuntu is codename like "buster", "focal"
    stored_count = 0
    processed_definitions_count = 0
    skipped_definitions_due_to_class_or_vuln_id = 0
    definitions_with_no_package_fix_found = 0
    debug_map_population_printed = False
    raw_def_xml_printed_count = 0
    
    try:
        parser = ET.XMLParser(remove_blank_text=True, resolve_entities=False) 
        root = ET.fromstring(xml_content, parser=parser)
        
        ns = {
            'oval-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
            'oval': 'http://oval.mitre.org/XMLSchema/oval-common-5',
            'linux-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux',
            # Add other common OVAL namespaces if needed
        }
        if root.nsmap: # lxml specific
            for prefix, uri in root.nsmap.items():
                if prefix and prefix not in ns: ns[prefix] = uri
                # Ensure our conventional prefixes point to the right URIs if doc uses them differently or as default
                if uri == ns['oval-def'] and prefix != 'oval-def': ns.setdefault(prefix if prefix else 'default_oval_def', uri)
                if uri == ns['linux-def'] and prefix != 'linux-def': ns.setdefault(prefix if prefix else 'default_linux_def', uri)
        
        # Determine if we are parsing for DPKG or RPM based on distro_name
        is_rpm_based = distro_name.lower() in ['centos', 'rhel', 'fedora', 'oraclelinux', 'amazon', 'almalinux', 'rocky']
        
        if is_rpm_based:
            test_xpath = ".//linux-def:rpminfo_test | .//oval-def:rpminfo_test[not(ancestor::linux-def:rpminfo_test)]"
            object_xpath = ".//linux-def:rpminfo_object | .//oval-def:rpminfo_object[not(ancestor::linux-def:rpminfo_object)]"
            state_xpath = ".//linux-def:rpminfo_state | .//oval-def:rpminfo_state[not(ancestor::linux-def:rpminfo_state)]"
            test_type_name = "rpminfo_test"
            object_type_name = "rpminfo_object"
            state_type_name = "rpminfo_state"
        else: # DPKG-based (Debian, Ubuntu)
            test_xpath = ".//linux-def:dpkginfo_test | .//oval-def:dpkginfo_test[not(ancestor::linux-def:dpkginfo_test)]"
            object_xpath = ".//linux-def:dpkginfo_object | .//oval-def:dpkginfo_object[not(ancestor::linux-def:dpkginfo_object)]"
            state_xpath = ".//linux-def:dpkginfo_state | .//oval-def:dpkginfo_state[not(ancestor::linux-def:dpkginfo_state)]"
            test_type_name = "dpkginfo_test"
            object_type_name = "dpkginfo_object"
            state_type_name = "dpkginfo_state"

        tests_map = {test.get('id'): test for test in root.xpath(test_xpath, namespaces=ns)}
        objects_map = {obj.get('id'): obj for obj in root.xpath(object_xpath, namespaces=ns)}
        states_map = {state.get('id'): state for state in root.xpath(state_xpath, namespaces=ns)}

        if not debug_map_population_printed:
            print(f"DEBUG MAPS (lxml for {distro_name}): Found {len(tests_map)} {test_type_name}s, {len(objects_map)} {object_type_name}s, {len(states_map)} {state_type_name}s.")
            if not tests_map or not objects_map or not states_map:
                print(f"Warning: For {distro_name}, one or more essential maps ({test_type_name}, {object_type_name}, {state_type_name}) are empty. Parsing will likely fail.")
            debug_map_population_printed = True

        definitions_element_list = root.xpath('./oval-def:definitions', namespaces=ns)
        if not definitions_element_list: 
            print("Error: Could not find 'definitions' element."); return 0
        
        definitions = definitions_element_list[0].xpath('./oval-def:definition', namespaces=ns)
        print(f"Processing {len(definitions)} definitions for {distro_name} {release_identifier} using lxml...")

        for definition_element in definitions:
            processed_definitions_count += 1
            if definition_element.get('class') != 'vulnerability':
                skipped_definitions_due_to_class_or_vuln_id += 1
                continue
            
            # --- PRINT RAW XML FOR FIRST FEW CentOS/RHEL DEFINITIONS ---
            if is_rpm_based and raw_def_xml_printed_count < 3: # Print first 3 for RPM-based
                try:
                    def_id_for_print = definition_element.get('id', 'N/A_DEF_ID')
                    raw_xml_snippet = ET.tostring(definition_element, pretty_print=True, encoding='unicode')
                    print(f"\n--- DEBUG RAW {distro_name.upper()} OVAL VULNERABILITY DEFINITION (ID: {def_id_for_print}) ---")
                    print(raw_xml_snippet[:3000]) # Print a sizable snippet
                    print("--- END DEBUG RAW ---")
                    raw_def_xml_printed_count += 1
                except Exception as e_print:
                    print(f"Error printing raw def XML: {e_print}")
            # --- END PRINT RAW XML ---

            vuln_id = None; severity_str = None
            definition_had_at_least_one_fix = False
            
            metadata_list = definition_element.xpath('./oval-def:metadata', namespaces=ns)
            if metadata_list:
                metadata = metadata_list[0]
                for ref in metadata.xpath('./oval-def:reference', namespaces=ns):
                    source, ref_id_val = ref.get('source'), ref.get('ref_id')
                    if source == "CVE" and ref_id_val: vuln_id = ref_id_val; break
                    if not vuln_id and source in ["USN", "DSA", "RHSA"] and ref_id_val: vuln_id = ref_id_val
                if not vuln_id:
                    title_el_list = metadata.xpath('./oval-def:title', namespaces=ns)
                    if title_el_list and title_el_list[0].text is not None:
                        match = re.search(r"(CVE-\d{4}-\d{4,})", title_el_list[0].text)
                        if match: vuln_id = match.group(1)
                advisory_el_list = metadata.xpath('./oval-def:advisory', namespaces=ns)
                if advisory_el_list:
                    severity_el_list = advisory_el_list[0].xpath('./oval-def:severity', namespaces=ns)
                    if severity_el_list and severity_el_list[0].text is not None:
                        severity_str = severity_el_list[0].text.strip().upper()
            
            if not vuln_id:
                skipped_definitions_due_to_class_or_vuln_id += 1
                continue

            criteria_list = definition_element.xpath('./oval-def:criteria', namespaces=ns)
            if criteria_list:
                criteria = criteria_list[0]
                for criterion in criteria.xpath('.//oval-def:criterion', namespaces=ns): 
                    test_ref_id = criterion.get('test_ref')
                    if not test_ref_id: continue

                    test_element = tests_map.get(test_ref_id)
                    if test_element is None: continue
                        
                    # Children <object> and <state> of <rpminfo_test> or <dpkginfo_test>
                    # are defined in the linux-def namespace according to OVAL schema structure.
                    object_ref_node_list = test_element.xpath('./linux-def:object', namespaces=ns)
                    state_ref_node_list = test_element.xpath('./linux-def:state', namespaces=ns)
                    
                    object_ref_node = object_ref_node_list[0] if object_ref_node_list else None
                    state_ref_node = state_ref_node_list[0] if state_ref_node_list else None
                    
                    if object_ref_node is None or state_ref_node is None: continue
                    
                    object_ref_id = object_ref_node.get('object_ref')
                    state_ref_id = state_ref_node.get('state_ref')

                    object_element = objects_map.get(object_ref_id)
                    state_element = states_map.get(state_ref_id)

                    if object_element is None or state_element is None: continue
                    
                    # <name> is child of <rpminfo_object>/<dpkginfo_object> (in linux-def ns)
                    name_element_list = object_element.xpath('./linux-def:name', namespaces=ns)
                    current_package_name = name_element_list[0].text.strip() if name_element_list and name_element_list[0].text is not None else None
                    
                    current_fixed_version = None
                    # <evr> is child of <rpminfo_state>/<dpkginfo_state> (in linux-def ns)
                    # For RPM, the version string is in 'evr'. It also has 'epoch', 'version', 'release', 'arch' sub-elements.
                    # For DPKG, it's 'evr'.
                    # The operation "less than" is key.
                    
                    # For RPM, the state might be <rpminfo_state> which has <version operation="less than">
                    # or it might have <evr operation="less than">.
                    # Let's prioritize <evr> if present, then look for <version> if RPM.
                    version_tag_to_check = "linux-def:evr" # Default for DPKG
                    if is_rpm_based:
                        # RHEL OVAL often uses <version> inside <rpminfo_state>
                        # and sometimes <epoch>, <release> are separate or part of <evr>
                        # The EVR string itself (epoch:version-release) is what we need for comparison.
                        # The state might directly have an <evr> or separate <epoch>, <version>, <release>
                        # Let's try to find a single EVR string first.
                        evr_el_list = state_element.xpath('./linux-def:evr', namespaces=ns)
                        if evr_el_list and evr_el_list[0].text is not None:
                             evr_element = evr_el_list[0]
                             operation = evr_element.get('operation', 'equals')
                             if operation == "less than":
                                 current_fixed_version = evr_element.text.strip()
                        else: # If no direct EVR, try to construct from epoch, version, release for RPM
                            epoch_el_list = state_element.xpath('./linux-def:epoch', namespaces=ns)
                            ver_el_list = state_element.xpath('./linux-def:version', namespaces=ns)
                            rel_el_list = state_element.xpath('./linux-def:release', namespaces=ns)
                            
                            # Check operation on the version element if EVR is not present
                            operation_el = ver_el_list[0] if ver_el_list else state_element # Check state itself for operation
                            operation = operation_el.get('operation', 'equals')

                            if operation == "less than":
                                epoch = epoch_el_list[0].text.strip() if epoch_el_list and epoch_el_list[0].text is not None else "0" # Default epoch if not present
                                version = ver_el_list[0].text.strip() if ver_el_list and ver_el_list[0].text is not None else None
                                release = rel_el_list[0].text.strip() if rel_el_list and rel_el_list[0].text is not None else None
                                if version: # Version is mandatory
                                    current_fixed_version = f"{epoch}:{version}"
                                    if release:
                                        current_fixed_version += f"-{release}"
                    else: # DPKG
                        evr_element_list = state_element.xpath('./linux-def:evr', namespaces=ns)
                        if evr_element_list and evr_element_list[0].text is not None:
                            evr_element = evr_element_list[0]
                            operation = evr_element.get('operation', 'equals')
                            if operation == "less than":
                                current_fixed_version = evr_element.text.strip()
                    
                    if current_package_name and current_fixed_version:
                        vuln_record = {
                            "vuln_id": vuln_id, "os_distro": distro_name.lower(),
                            "os_release_codename": release_identifier.lower(), 
                            "package_name": current_package_name, "fixed_version": current_fixed_version,
                            "status": "resolved", "severity": severity_str
                        }
                        try:
                            vulndb.insert_os_vulnerability(db_cursor, vuln_record)
                            stored_count += 1
                            definition_had_at_least_one_fix = True
                        except sqlite3.IntegrityError: pass 
                        except Exception as e_ins: print(f"DB Error inserting {vuln_id} for {current_package_name}: {e_ins}")
            
            if not definition_had_at_least_one_fix:
                definitions_with_no_package_fix_found +=1
        
        print(f"\nProcessed {processed_definitions_count} definitions for {distro_name} {release_identifier}.")
        print(f"  Stored {stored_count} vulnerability entries.")
        print(f"  Skipped {skipped_definitions_due_to_class_or_vuln_id} definitions (not vulnerability class or no vuln_id).")
        print(f"  Vulnerability definitions where no package/fix was successfully parsed: {definitions_with_no_package_fix_found}")
        return stored_count

    except ET.LxmlError as e: 
        print(f"LXML Error parsing {distro_name} OVAL XML for {release_identifier}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during {distro_name} OVAL parsing for {release_identifier}: {e}")
        import traceback
        traceback.print_exc()
    return 0

# --- OS Data Fetching Functions ---
def _fetch_and_store_os_oval_data(distro_name: str, release_identifier: str, oval_url_template: str, **url_format_kwargs):
    if not release_identifier:
        print(f"Error: {distro_name} release identifier required.")
        return
    
    url_params = {'codename': release_identifier, 'major_version': release_identifier} # Allow both keys
    url_params.update(url_format_kwargs)

    data_url = ""
    try:
        # Choose the correct key for formatting based on what's in the template
        if "{major_version}" in oval_url_template:
            data_url = oval_url_template.format(major_version=url_params['major_version'])
        elif "{codename}" in oval_url_template:
            data_url = oval_url_template.format(codename=url_params['codename'])
        else:
            raise ValueError("URL template does not contain {major_version} or {codename}")
    except KeyError as e:
        print(f"Error: Missing key for URL formatting: {e}. Template: '{oval_url_template}', Params: {url_params}")
        return
        
    print(f"Attempting to fetch and store {distro_name} OVAL data for '{release_identifier}' from {data_url}...")
    xml_content = None
    try:
        response = requests.get(data_url, timeout=120, stream=True)
        response.raise_for_status()
        print("Decompressing downloaded bz2 data...")
        xml_content = bz2.decompress(response.content)
        print(f"Successfully downloaded and decompressed OVAL data for {distro_name} {release_identifier}.")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {distro_name} OVAL data for {release_identifier} from {data_url}: {e}")
        return
    except Exception as e: 
        print(f"An unexpected error during download/decompression for {distro_name} {release_identifier}: {e}")
        return
    if not xml_content:
        print(f"Failed to get XML content for {distro_name} {release_identifier}.")
        return

    conn = vulndb.get_db_connection()
    cursor = conn.cursor()
    stored_count = _parse_and_store_oval_definitions(xml_content, distro_name, release_identifier, cursor)
    try:
        if stored_count > 0:
            conn.commit()
            print(f"Committed {stored_count} {distro_name} ({release_identifier}) vulnerability entries.")
            vulndb.update_data_source_timestamp(f"{distro_name.lower()}_{release_identifier.lower()}")
        else:
            print(f"No new {distro_name} ({release_identifier}) entries to commit.")
    except Exception as e:
        print(f"Database commit failed for {distro_name} ({release_identifier}) data: {e}")

def fetch_and_store_debian_data(release_codename: str):
    """Fetches Debian OVAL data."""
    _fetch_and_store_os_oval_data("debian", release_codename, DEBIAN_OVAL_URL_TEMPLATE)

# --- NEW FUNCTION FOR UBUNTU ---
def fetch_and_store_ubuntu_data(release_codename: str):
    """Fetches Ubuntu OVAL data."""
    _fetch_and_store_os_oval_data("ubuntu", release_codename, UBUNTU_OVAL_URL_TEMPLATE)
# --- END NEW FUNCTION ---

# --- NEW FUNCTION FOR CENTOS ---
def fetch_and_store_centos_data(major_version: str):
    """Fetches RHEL/CentOS OVAL data based on major version (e.g., "7", "8")."""
    # The release_identifier passed to _parse_and_store_oval_definitions will be the major_version
    _fetch_and_store_os_oval_data("centos", major_version, CENTOS_OVAL_URL_TEMPLATE)
# --- END NEW FUNCTION ---

def fetch_and_store_alpine_data(alpine_version_branch: str):
    if not alpine_version_branch:
        print("Error: Alpine version branch required (e.g., 'v3.20').")
        return
    print(f"Attempting to fetch and store Alpine secdb data for '{alpine_version_branch}'...")
    conn = vulndb.get_db_connection(); cursor = conn.cursor(); total_stored_count = 0
    for repository in ["main", "community"]: # Alpine splits by repo
        data_url = ALPINE_SECDB_URL_TEMPLATE.format(version_branch=alpine_version_branch, repository=repository)
        # print(f"Using data URL: {data_url}") # Debug
        alpine_data = None
        try:
            response = requests.get(data_url, timeout=30); response.raise_for_status(); alpine_data = response.json()
            # print(f"Successfully downloaded secdb for {alpine_version_branch}/{repository}.") # Debug
        except requests.exceptions.RequestException as e: print(f"Error fetching Alpine secdb for {alpine_version_branch}/{repository}: {e}"); continue
        except json.JSONDecodeError as e: print(f"Error decoding JSON for Alpine secdb {alpine_version_branch}/{repository}: {e}"); continue
        except Exception as e: print(f"An unexpected error occurred during download for {alpine_version_branch}/{repository}: {e}"); continue
        if not alpine_data or 'packages' not in alpine_data: print(f"Warning: No 'packages' array found in {data_url}"); continue
        
        repo_stored_count = 0; repo_skipped_count = 0
        for package_entry in alpine_data.get('packages', []):
            pkg_info = package_entry.get('pkg');
            if not pkg_info or not isinstance(pkg_info, dict): repo_skipped_count += 1; continue
            package_name = pkg_info.get('name'); secfixes = pkg_info.get('secfixes')
            if not package_name or not isinstance(secfixes, dict): repo_skipped_count += 1; continue
            for fixed_version, vuln_ids in secfixes.items():
                if isinstance(vuln_ids, list):
                    for vuln_id_str in vuln_ids:
                        for actual_vuln_id in vuln_id_str.split(): # Handle space-separated CVEs
                            if not actual_vuln_id.upper().startswith("CVE-"): continue # Only CVEs for now
                            vuln_record = {
                                "vuln_id": actual_vuln_id.upper(), "os_distro": "alpine",
                                "os_release_codename": alpine_version_branch, # Use version_branch as release_id
                                "package_name": package_name, "fixed_version": fixed_version,
                                "status": "resolved", "severity": None # Alpine secdb doesn't usually have severity
                            }
                            vulndb.insert_os_vulnerability(cursor, vuln_record); repo_stored_count += 1
        try:
            if repo_stored_count > 0: conn.commit(); print(f"Committed {repo_stored_count} Alpine ({alpine_version_branch}/{repository}) entries.")
            if repo_skipped_count > 0: print(f"Skipped {repo_skipped_count} package entries for {repository}.")
            total_stored_count += repo_stored_count
        except Exception as e: print(f"Database commit failed for Alpine ({alpine_version_branch}/{repository}): {e}")
    
    print(f"\nFinished fetching Alpine data. Total committed entries for {alpine_version_branch}: {total_stored_count}")
    if total_stored_count > 0: vulndb.update_data_source_timestamp(f"alpine_{alpine_version_branch.lower()}")

def update_vulnerability_db(max_pages=None, api_key=None): # Added api_key
    print("Starting NVD vulnerability database update...")
    start_index = 0; total_results = -1; total_stored_cves_in_session = 0; pages_fetched = 0; fetch_error_occurred = False
    try:
        conn = vulndb.get_db_connection(); cursor = conn.cursor()
    except Exception as db_conn_err: print(f"Failed to establish DB connection for NVD update: {db_conn_err}"); return
    
    while True:
        nvd_data = fetch_page_from_nvd(start_index, api_key=api_key)
        if nvd_data is None: fetch_error_occurred = True; print("Failed to fetch data from NVD. Aborting NVD update."); break
        if total_results == -1:
            total_results = nvd_data.get('totalResults', 0); print(f"NVD reports total results: {total_results}")
            if total_results == 0: print("No results reported by NVD. Stopping."); break
        
        stored_on_page = parse_and_store_cves(nvd_data, cursor) # Pass cursor
        if stored_on_page > 0: conn.commit(); print(f"Committed {stored_on_page} CVEs to database for this page.") # Commit after each page
        
        total_stored_cves_in_session += stored_on_page; pages_fetched += 1
        current_results_count = len(nvd_data.get('vulnerabilities', []))
        if current_results_count == 0 and start_index < total_results and total_results > 0: print("Received page with 0 results before expected end. Stopping NVD update."); break
        start_index += current_results_count
        print(f"NVD Progress: Processed {start_index}/{total_results} results. Stored {total_stored_cves_in_session} total CVEs this session.")
        if (current_results_count < RESULTS_PER_PAGE and total_results > 0) or \
           (start_index >= total_results and total_results > 0) or \
           (max_pages is not None and pages_fetched >= max_pages):
            break # Exit conditions
            
    if not fetch_error_occurred and pages_fetched > 0:
        try: vulndb.update_data_source_timestamp("nvd")
        except Exception as e_ts: print(f"Error updating NVD timestamp: {e_ts}")
    # ... (rest of the logging as before) ...
    print(f"\nNVD Database update finished. Fetched {pages_fetched} pages. Stored {total_stored_cves_in_session} CVEs this session.")
