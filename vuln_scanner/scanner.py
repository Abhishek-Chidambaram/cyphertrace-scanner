# vuln_scanner/scanner.py
import re
import json
import time # Added for OSV delay
from collections import defaultdict # Added for packages_by_name
from packaging.version import parse as parse_version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from cvss import CVSS3 # For parsing OSV CVSS vectors
from . import vulndb # Import vulndb for fetching details
from .models import Package, Vulnerability, ScanResult
try:
    # Aliased for clarity
    from debian.debian_support import version_compare as debian_version_compare
    debian_compare_available = True
except ImportError:
    debian_compare_available = False

# --- Package Name to CPE Vendor/Product Mapping ---
PACKAGE_CPE_MAP = {
    # package_name: [(vendor1, product1), ...]
    'django': [('djangoproject', 'django')],
    'requests': [('python-requests', 'requests'), ('requests_project', 'requests'),('python','requests')],
    'flask': [('palletsprojects', 'flask')],
    'numpy': [('numpy', 'numpy')],
    'express': [('expressjs', 'express'), ('openjsf', 'express')],
    'lodash': [('lodash', 'lodash')],
}

# --- CPE Parsing Helper ---
def parse_cpe(cpe_string: str) -> dict | None:
    if not cpe_string or not cpe_string.startswith("cpe:2.3:"): return None
    parts = cpe_string.split(':'); len_parts = len(parts)
    if len_parts < 6: return None
    try: return { "part": parts[2] if len_parts > 2 else '', "vendor": parts[3] if len_parts > 3 else '', "product": parts[4] if len_parts > 4 else '', "version": parts[5] if len_parts > 5 else '', "update": parts[6] if len_parts > 6 else '', "edition": parts[7] if len_parts > 7 else '', "language": parts[8] if len_parts > 8 else '', "sw_edition": parts[9] if len_parts > 9 else '', "target_sw": parts[10] if len_parts > 10 else '', "target_hw": parts[11] if len_parts > 11 else '', "other": parts[12] if len_parts > 12 else '' }
    except IndexError: return None

# --- NVD Configuration Evaluation Helpers ---
def evaluate_cpe_match(cpe_match_item: dict, pkg_instance: Package) -> bool:
    if not isinstance(cpe_match_item, dict): return False
    is_vulnerable_criterion = cpe_match_item.get("vulnerable", False)
    criteria_str = cpe_match_item.get("criteria")
    if not is_vulnerable_criterion or not criteria_str: return False
    parsed_cpe = parse_cpe(criteria_str)
    if not parsed_cpe: return False
    pkg_name = pkg_instance.name
    if pkg_name not in PACKAGE_CPE_MAP: return False

    possible_cpe_parts = PACKAGE_CPE_MAP[pkg_name]; cpe_vendor = parsed_cpe['vendor']; cpe_product = parsed_cpe['product']
    vendor_product_match = False
    for expected_vendor, expected_product in possible_cpe_parts:
        if cpe_vendor == expected_vendor and cpe_product == expected_product: vendor_product_match = True; break
    if not vendor_product_match: return False

    spec_parts = []; vs_inc = cpe_match_item.get("versionStartIncluding"); vs_exc = cpe_match_item.get("versionStartExcluding")
    ve_inc = cpe_match_item.get("versionEndIncluding"); ve_exc = cpe_match_item.get("versionEndExcluding")
    if vs_inc: spec_parts.append(f">={vs_inc}");
    if vs_exc: spec_parts.append(f">{vs_exc}");
    if ve_inc: spec_parts.append(f"<={ve_inc}");
    if ve_exc: spec_parts.append(f"<{ve_exc}")
    specifier_string = ",".join(spec_parts); cpe_version_str = parsed_cpe['version']
    if not specifier_string and cpe_version_str not in ('*', '-'):
        try: parse_version(cpe_version_str); specifier_string = f"=={cpe_version_str}"
        except InvalidVersion: return False
    if specifier_string is None: return False
    try: spec_set = SpecifierSet(specifier_string if specifier_string else ""); return pkg_instance.version in spec_set
    except InvalidSpecifier: return False

def evaluate_node(node: dict, pkg_instance: Package) -> bool | None:
    if not isinstance(node, dict): return None
    operator = node.get("operator", "AND").upper(); negate = node.get("negate", False)
    children = node.get("children", []); cpe_matches = node.get("cpeMatch", [])
    results = []
    for cpe_match_item in cpe_matches: results.append(evaluate_cpe_match(cpe_match_item, pkg_instance))
    for child_node in children: results.append(evaluate_node(child_node, pkg_instance))
    valid_results = [r for r in results if r is not None]
    if not valid_results: return False if not negate else True
    final_result = False
    if operator == "OR": final_result = any(valid_results)
    elif operator == "AND": final_result = all(valid_results)
    else: final_result = all(valid_results) # Default AND
    return not final_result if negate else final_result

# --- Application Dependency Scanner (Using OSV) ---
from . import osv_scanner

def scan_application_dependencies(packages: list[Package]) -> list[ScanResult]:
    print(f"\nScanning {len(packages)} application packages using OSV API...")
    final_app_vulns = []; unique_findings_set = set(); matches_confirmed_count = 0
    if not packages: return final_app_vulns
    initial_osv_response = osv_scanner.query_osv_for_packages(packages)
    if not initial_osv_response or 'results' not in initial_osv_response: print("Error: Failed OSV batch API."); return final_app_vulns
    package_registry = initial_osv_response.get('_package_registry', {}); initial_results = initial_osv_response.get('results', [])
    unique_vuln_ids_to_fetch = set()
    for i, result in enumerate(initial_results):
         if result and 'vulns' in result:
              for vuln_entry in result['vulns']:
                   if 'id' in vuln_entry: unique_vuln_ids_to_fetch.add(vuln_entry['id'])
    if not unique_vuln_ids_to_fetch: print("OSV batch query returned no vulnerabilities."); return final_app_vulns
    print(f"Found {len(unique_vuln_ids_to_fetch)} unique OSV IDs potentially affecting packages. Fetching details...")
    vuln_details_cache = {}; fetch_errors = 0
    for vuln_id in unique_vuln_ids_to_fetch:
        time.sleep(0.1); details = osv_scanner.get_osv_vuln_details(vuln_id)
        if details: vuln_details_cache[vuln_id] = details
        else: fetch_errors += 1; print(f"Warning: Failed to fetch details for {vuln_id}")
    if fetch_errors > 0: print(f"Warning: Failed detail fetch for {fetch_errors} OSV IDs.")
    print(f"Processing results using fetched details...")
    for i, result in enumerate(initial_results):
         original_pkg = package_registry.get(i);
         if not original_pkg: continue
         if result and 'vulns' in result:
              for vuln_entry in result['vulns']:
                   vuln_id = vuln_entry.get('id');
                   if not vuln_id: continue
                   full_details = vuln_details_cache.get(vuln_id)
                   report_id = vuln_id; description = "No description available."; cvss_score = None; cvss_vector = None
                   if full_details:
                       for alias in full_details.get('aliases', []):
                           if alias.startswith('CVE-'): report_id = alias; break
                       details_text=full_details.get('details', ''); summary_text=full_details.get('summary', '')
                       description = details_text if details_text else (summary_text if summary_text else f"Details fetch successful, but no description for {report_id}.")
                       severity_list = full_details.get('severity', [])
                       if isinstance(severity_list, list):
                           for severity_entry in severity_list:
                               if isinstance(severity_entry, dict) and severity_entry.get('type') == 'CVSS_V3':
                                   vector_string = severity_entry.get('score');
                                   if isinstance(vector_string, str) and vector_string.startswith('CVSS:3'):
                                       cvss_vector = vector_string
                                       try: c = CVSS3(cvss_vector); cvss_score = c.base_score; # print(f"DEBUG OSV Parse: Parsed Vector '{cvss_vector}', Score: {cvss_score}") # Optional Debug
                                       except Exception as e_cvss: print(f"Warning: Failed CVSS parse for {report_id}: {e_cvss}"); cvss_score = None
                                       break # Found CVSS3
                   vuln_obj = Vulnerability(cve_id=report_id, description=description, cvss_v3_score=cvss_score, cvss_v3_vector=cvss_vector, configurations=None)
                   result_key = (original_pkg.name, str(original_pkg.version), report_id)
                   if result_key not in unique_findings_set:
                       matches_confirmed_count += 1; unique_findings_set.add(result_key)
                       final_app_vulns.append(ScanResult(package=original_pkg, vulnerability=vuln_obj))
                       print(f"  APP VULN FOUND (OSV): {original_pkg.name}=={original_pkg.version} vulnerable to {report_id} (Severity: {vuln_obj.severity})")
    print(f"\nOSV scan completed. Found {matches_confirmed_count} unique application vulnerabilities.")
    return final_app_vulns

# --- NEW Helper for Creating OS Scan Results ---
def _create_os_scan_result(pkg_info: dict, vuln_id: str, fixed_version_str: str, status: str | None, os_severity: str | None) -> ScanResult | None:
    pkg_name = pkg_info.get("name")
    installed_version_str = pkg_info.get("version")
    if not pkg_name or not installed_version_str: return None
    pkg_obj = None
    try:
        pkg_version_obj = parse_version(installed_version_str)
        pkg_obj = Package(name=pkg_name, version=pkg_version_obj)
    except InvalidVersion:
        print(f"Warning: Could not parse OS pkg version for reporting: {pkg_name}=={installed_version_str}")
        return None
    nvd_details: Vulnerability | None = None
    if vuln_id.upper().startswith("CVE-"):
        nvd_details = vulndb.get_full_vulnerability_details(vuln_id.upper())
    description = f"Vulnerability {vuln_id} affecting {pkg_name}, fixed in version {fixed_version_str}. (OS Status: {status or 'N/A'})"
    cvss_score = None; cvss_vector = None
    if nvd_details:
        description = nvd_details.description if nvd_details.description else description
        cvss_score = nvd_details.cvss_v3_score
        cvss_vector = nvd_details.cvss_v3_vector
    vuln_obj = Vulnerability(cve_id=vuln_id, description=description, cvss_v3_score=cvss_score, cvss_v3_vector=cvss_vector, configurations=None)
    print(f"  OS VULN FOUND ({pkg_obj.name}): {pkg_name}=={installed_version_str} is vulnerable to {vuln_id} (Fixed in {fixed_version_str}, Severity: {vuln_obj.severity})")
    return ScanResult(package=pkg_obj, vulnerability=vuln_obj)

# --- Modified function for OS Packages (Debian specific for now) ---
def scan_debian_os_packages(os_packages: list[dict], os_distro: str, os_release_codename: str, os_vuln_data: dict) -> list[ScanResult]:
    print(f"Scanning {len(os_packages)} detected OS packages for {os_distro} {os_release_codename}...")
    final_os_vulns = []
    found_vulns_set = set()
    if not debian_compare_available: print("Error: Cannot scan Debian without 'python-debian'."); return []
    # comparison_count = 0 # Debug
    for pkg_info in os_packages:
        pkg_name = pkg_info.get("name"); installed_version_str = pkg_info.get("version")
        if not pkg_name or not installed_version_str: continue
        if pkg_name in os_vuln_data:
            for vuln_id, fixed_version_str, status, severity_str in os_vuln_data[pkg_name]:
                # comparison_count += 1 # Debug
                is_vulnerable = False
                try:
                    # Use aliased debian_version_compare
                    comparison = debian_version_compare(installed_version_str, fixed_version_str)
                    if comparison is not None and comparison < 0: is_vulnerable = True
                except Exception as e: print(f"Warning: Debian version compare failed for {pkg_name} ('{installed_version_str}' vs '{fixed_version_str}'): {e}")
                if is_vulnerable:
                    scan_result = _create_os_scan_result(pkg_info, vuln_id, fixed_version_str, status, severity_str)
                    if scan_result:
                        result_key = (scan_result.package.name, str(scan_result.package.version), scan_result.vulnerability.cve_id)
                        if result_key not in found_vulns_set:
                             final_os_vulns.append(scan_result); found_vulns_set.add(result_key)
    # print(f"DEBUG Debian Scan: Performed {comparison_count} version comparisons.") # Debug
    print(f"Debian OS package scan completed. Found {len(final_os_vulns)} unique potential vulnerabilities.")
    return final_os_vulns

# --- NEW Alpine Version Comparison Helper ---
def compare_alpine_versions(v1: str, v2: str) -> int:
    """
    Compares two Alpine version strings based on apk logic (simplified).
    Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
    Handles basic numeric parts and the -rX revision suffix.
    """
    v1_parts = v1.split('-r')
    v2_parts = v2.split('-r')
    v1_main = v1_parts[0]
    v2_main = v2_parts[0]
    try:
        pv1 = parse_version(v1_main)
        pv2 = parse_version(v2_main)
        if pv1 < pv2: return -1
        if pv1 > pv2: return 1
    except InvalidVersion:
        if v1_main < v2_main: return -1
        if v1_main > v2_main: return 1
    v1_rev = int(v1_parts[1]) if len(v1_parts) > 1 else 0
    v2_rev = int(v2_parts[1]) if len(v2_parts) > 1 else 0
    if v1_rev < v2_rev: return -1
    if v1_rev > v2_rev: return 1
    return 0

# --- Modified function for OS Packages (Alpine specific) ---
def scan_alpine_os_packages(os_packages: list[dict], os_distro: str, alpine_version_branch: str, alpine_vuln_data: dict) -> list[ScanResult]:
    """Scans detected Alpine OS packages against loaded Alpine secdb vulnerability data."""
    print(f"Scanning {len(os_packages)} detected OS packages for {os_distro} {alpine_version_branch}...")
    final_os_vulns = []
    found_vulns_set = set()
    comparison_count = 0
    for pkg_info in os_packages:
        pkg_name = pkg_info.get("name"); installed_version_str = pkg_info.get("version")
        if not pkg_name or not installed_version_str: continue
        if pkg_name in alpine_vuln_data:
            for vuln_id, fixed_version_str, status, severity_str in alpine_vuln_data[pkg_name]:
                comparison_count += 1
                is_vulnerable = False
                try:
                    # *** USE NEW COMPARISON FUNCTION ***
                    comparison_result = compare_alpine_versions(installed_version_str, fixed_version_str)
                    if comparison_result < 0: # Vulnerable if installed < fixed
                        is_vulnerable = True
                except Exception as e:
                    print(f"Warning (Alpine Scan): Version comparison failed for {pkg_name} ('{installed_version_str}' vs '{fixed_version_str}'): {e}")

                if is_vulnerable:
                    scan_result = _create_os_scan_result(pkg_info, vuln_id, fixed_version_str, status, severity_str)
                    if scan_result:
                        result_key = (scan_result.package.name, str(scan_result.package.version), scan_result.vulnerability.cve_id)
                        if result_key not in found_vulns_set:
                             final_os_vulns.append(scan_result)
                             found_vulns_set.add(result_key)
    print(f"DEBUG Alpine Scan: Performed {comparison_count} version comparisons.")
    print(f"Alpine OS package scan completed. Found {len(final_os_vulns)} unique potential vulnerabilities.")
    return final_os_vulns