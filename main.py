# main.py
from datetime import datetime, timedelta, timezone 
import argparse
import sys
import json
import yaml  # For config file
import html  # For HTML escaping
from vuln_scanner import java_analyser
from typing import Optional, Union 
import os
from pathlib import Path
from collections import defaultdict # Used in scanner, maybe useful here later
from typing import Optional # For type hints
from packaging.version import Version,InvalidVersion
from packaging.version import parse as parse_version # For version parsing  

# Import all necessary functions and modules from our scanner
from vuln_scanner.parser import parse_requirements, parse_package_lock
from vuln_scanner import vulndb, fetcher, scanner, image_parser, ai_analyzer # ai_analyzer might be optional
from vuln_scanner.models import ScanResult, Package # For type hinting
from vuln_scanner import registry_client # <-- NEW: Import the registry client
from vuln_scanner.go_parser import parse_go_dependencies

# --- Config File Handling ---
CONFIG_FILENAME = "config.yaml"

def load_config(config_path: str = CONFIG_FILENAME) -> dict:
    config = {}
    path = Path(config_path)
    if path.is_file():
        print(f"Attempting to load configuration from '{path.resolve()}'...")
        try:
            with open(path, 'r', encoding='utf-8') as f:
                loaded_yaml = yaml.safe_load(f)
            if isinstance(loaded_yaml, dict):
                config = loaded_yaml
                print(f"Successfully loaded configuration from {path.resolve()}")
            else:
                print(f"Warning: Config file '{path.resolve()}' does not contain a valid dictionary structure.")
        except yaml.YAMLError as e:
            print(f"Error parsing YAML configuration file '{path.resolve()}': {e}")
        except Exception as e:
            print(f"An unexpected error occurred loading configuration '{path.resolve()}': {e}")
    else:
        print(f"Info: Configuration file '{config_path}' not found in current directory. Using defaults/CLI args.")
    return config

# --- Reporting Functions (Keep these as they are) ---
SEVERITY_ORDER = { "UNKNOWN": 0, "NONE": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5 }

def print_text_report(results: list[ScanResult]):
    print("\n--- Scan Report (Text) ---")
    if not results:
        print("No vulnerabilities found.")
    else:
        print(f"Found {len(results)} vulnerabilities:")
        results.sort(key=lambda r: (SEVERITY_ORDER.get(r.vulnerability.severity.upper(), 0), r.package.name, r.vulnerability.cve_id), reverse=True)
        for result in results:
            vuln = result.vulnerability; pkg = result.package
            print(f"  - Package: {pkg.name}=={str(pkg.version)} (Ecosystem: {pkg.ecosystem or 'N/A'})") # Added ecosystem
            print(f"    CVE:      {vuln.cve_id}")
            print(f"    Severity: {vuln.severity} ({vuln.cvss_v3_score if vuln.cvss_v3_score is not None else 'N/A'})")
            print(f"    Desc:     {vuln.description}")
            print("-" * 20)
    print("--- End Report ---")

def print_json_report(results: list[ScanResult]):
    output_data = []
    results.sort(key=lambda r: (SEVERITY_ORDER.get(r.vulnerability.severity.upper(), 0), r.package.name, r.vulnerability.cve_id), reverse=True)
    for result in results:
        vuln = result.vulnerability; pkg = result.package
        output_data.append({
            "packageName": pkg.name, "packageVersion": str(pkg.version), "ecosystem": pkg.ecosystem, # Added ecosystem
            "cveId": vuln.cve_id, "severity": vuln.severity,
            "cvssV3Score": float(vuln.cvss_v3_score) if vuln.cvss_v3_score is not None else None,
            "cvssV3Vector": vuln.cvss_v3_vector, "description": vuln.description,
        })
    print(json.dumps(output_data, indent=2))

def print_html_report(results: list[ScanResult], output_filename: Optional[str]):
    if not output_filename:
        output_filename = "scan_report.html"
    print(f"\nGenerating HTML report: {output_filename}...")
    html_css = """<style>
body { font-family: sans-serif; margin: 20px; background-color: #f4f7f6; color: #333; }
table { border-collapse: collapse; margin: 1em 0; width: 100%; box-shadow: 0 2px 8px rgba(0,0,0,0.1); background-color: #fff; }
th, td { border: 1px solid #ddd; padding: 10px 15px; text-align: left; vertical-align: top; }
th { background-color: #6c7ae0; color: white; font-weight: bold; text-transform: uppercase; letter-spacing: 0.05em; }
tr:nth-child(even) { background-color: #f9f9f9; }
tr:hover { background-color: #f1f1f1; }
caption { caption-side: top; font-size: 1.5em; font-weight: bold; margin-bottom: 15px; text-align: left; color: #444; }
.severity-CRITICAL { color: #FF0000; font-weight: bold; } .severity-HIGH { color: #FF8C00; font-weight: bold; }
.severity-MEDIUM { color: #DAA520; } .severity-LOW { color: #32CD32; }
.severity-UNKNOWN, .severity-NONE { color: #808080; }
pre { white-space: pre-wrap; word-wrap: break-word; margin: 0; font-family: inherit; font-size: 0.95em; }
h1 { color: #333; border-bottom: 2px solid #6c7ae0; padding-bottom: 10px;}
p { line-height: 1.6; }
</style>"""
    html_content = f"""<!DOCTYPE html><html lang="en"><head><title>CypherTrace Vulnerability Scan Report</title><meta charset="UTF-8">{html_css}</head><body><h1>CypherTrace Scan Report</h1>"""
    if not results:
        html_content += "<p>No vulnerabilities found.</p>"
    else:
        num_vulns = len(results)
        html_content += f"<p>Found {num_vulns} vulnerabilities.</p><table><caption>Vulnerability Details</caption><thead><tr><th>Severity</th><th>Score</th><th>Vulnerability ID</th><th>Package</th><th>Version</th><th>Ecosystem</th><th>Description</th></tr></thead><tbody>\n"""
        results.sort(key=lambda r: (SEVERITY_ORDER.get(r.vulnerability.severity.upper(), 0), r.package.name, r.vulnerability.cve_id), reverse=True)
        for result in results:
            vuln = result.vulnerability; pkg = result.package
            severity_class = f"severity-{vuln.severity.upper()}"
            pkg_name_esc = html.escape(pkg.name); pkg_version_esc = html.escape(str(pkg.version)); ecosystem_esc = html.escape(pkg.ecosystem or "N/A")
            vuln_id_esc = html.escape(vuln.cve_id); severity_esc = html.escape(vuln.severity)
            score_str = str(vuln.cvss_v3_score) if vuln.cvss_v3_score is not None else "N/A"
            score_esc = html.escape(score_str); desc_esc = html.escape(vuln.description)
            desc_html = f"<pre>{desc_esc}</pre>"
            html_content += f"""<tr><td class="{severity_class}">{severity_esc}</td><td>{score_esc}</td><td>{vuln_id_esc}</td><td>{pkg_name_esc}</td><td>{pkg_version_esc}</td><td>{ecosystem_esc}</td><td>{desc_html}</td></tr>\n"""
        html_content += "</tbody></table>"
    html_content += "\n</body></html>"
    try:
        path = Path(output_filename)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"HTML report saved to: {path.resolve()}")
    except Exception as e:
        print(f"Error writing HTML report to {output_filename}: {e}")


# --- NEW Function to Handle Registry Scans ---
def handle_registry_scan(args: argparse.Namespace, config: dict) -> list[ScanResult]:
    """
    Handles scanning an image directly from a registry.
    """
    print(f"\n--- Starting REGISTRY SCAN for image: {args.registry_image} ---")
    
    # Ensure DB connection is established for the registry client and subsequent scanning
    try:
        vulndb.get_db_connection()
    except Exception as db_err:
        print(f"Error: Could not connect to vulnerability database: {db_err}", file=sys.stderr)
        return [] # Cannot proceed

    scan_results = registry_client.scan_image_from_registry(args.registry_image)
    
    # The registry_client.scan_image_from_registry should ideally close the DB connection
    # or this function should manage it if registry_client doesn't.
    # For now, assuming scan_image_from_registry handles its DB connection lifecycle internally
    # or leaves it open for main.py to close. (Current registry_client.py closes it)

    return scan_results

# --- NEW Function to Handle Go Module Scans ---
def handle_go_module_scan(args: argparse.Namespace, config: dict) -> list[ScanResult]:
    """
    Handles scanning Go module dependencies from go.mod file.
    """
    go_mod_path = Path(args.go_mod)
    go_sum_path = Path(args.go_sum) if args.go_sum else None
    
    print(f"\n--- Starting GO MODULE SCAN for: {go_mod_path} ---")
    
    if not go_mod_path.is_file():
        print(f"Error: Go module file not found: {go_mod_path}", file=sys.stderr)
        return []
    
    if go_sum_path and not go_sum_path.is_file():
        print(f"Warning: Go sum file not found: {go_sum_path}. Proceeding without checksum verification.")
        go_sum_path = None
    
    try:
        # Ensure DB connection is established for vulnerability scanning
        vulndb.get_db_connection()
        
        # Parse Go dependencies
        go_deps = parse_go_dependencies(str(go_mod_path), str(go_sum_path) if go_sum_path else None)
        
        if not go_deps:
            print("No Go dependencies found in the module file.")
            return []
        
        print(f"Found {len(go_deps)} Go dependencies to scan for vulnerabilities...")
        
        # Convert dicts to Package objects
        go_packages = []
        for dep in go_deps:
            try:
                pkg = Package(
                    name=dep['name'],
                    version=dep['version'],
                    ecosystem='Go'
                )
                go_packages.append(pkg)
            except Exception as e:
                print(f"Warning: Could not create Package object for {dep}: {e}")
        
        # Scan for vulnerabilities using the existing scanner
        scan_results = scanner.scan_application_dependencies(go_packages)
        
        return scan_results
        
    except Exception as e:
        print(f"Error during Go module scan: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return []

def detect_file_type(file_path: str) -> str:
    """Detect the type of dependency file."""
    filename = os.path.basename(file_path).lower()
    
    if filename == 'go.mod':
        return 'go_mod'
    elif filename == 'go.sum':
        return 'go_sum'
    elif filename.endswith('.txt'):  # For requirements.txt
        return 'python'
    elif filename == 'package-lock.json':
        return 'npm'
    elif filename.endswith(('.war', '.jar', '.ear')):
        return 'java_archive'
    
    return 'unknown'

# --- Main Execution Logic ---
def main():
    # print("### EXECUTING MAIN FUNCTION ###") # Keep your checkpoint if needed
    config = load_config()

    parser = argparse.ArgumentParser(description="CypherTrace Vulnerability Scanner", add_help=False)
    
    # --- Scan Target Group ---
    input_group = parser.add_argument_group('Scan Target (Specify one)')
    target_exclusive_group = input_group.add_mutually_exclusive_group(required=False) # Will be required if no update action
    target_exclusive_group.add_argument("input_file", type=str, nargs='?', help="Path to input file (requirements*.txt, package-lock.json, go.mod).")
    target_exclusive_group.add_argument("--image-tar", type=str, metavar='TAR_PATH', help="Path to a local container image tarball ('docker save' output).")
    target_exclusive_group.add_argument("--registry-image", type=str, metavar='IMAGE_NAME:TAG', help="Name of container image in a remote registry (e.g., ubuntu:latest). Currently supports public Docker Hub images.")
    target_exclusive_group.add_argument("--java-archive", type=str, metavar='ARCHIVE_PATH_IN_CONTAINER', help="Path to Java archive (WAR, JAR, EAR) inside the container to scan.")
    target_exclusive_group.add_argument("--go-mod", type=str, metavar='GO_MOD_PATH', help="Path to Go module file (go.mod) to scan for dependency vulnerabilities.")
    
    # --- Go-specific options (outside the exclusive group) ---
    go_group = parser.add_argument_group('Go Module Options')
    go_group.add_argument( "--go-sum", type=str, metavar='GO_SUM_PATH', help="Path to go.sum file for dependency verification (optional, used with --go-mod).") # <-- NEW: Go sum argument)
    
    # --- Database Update Group ---
    update_group = parser.add_argument_group('Database Update Options')
    update_group.add_argument( "--update-db", action="store_true", help="Fetch/Update NVD data." )
    update_group.add_argument( "--max-pages", type=int, default=config.get('nvd_max_pages', None), help="Limit NVD pages during --update-db." )
    update_group.add_argument( "--fetch-cve", type=str, metavar='CVE_ID', help="Fetch specific CVE ID (NVD)." )
    update_group.add_argument( "--update-os", type=str, metavar='DISTRO=RELEASE', help="Update OS vulnerability data (e.g., debian=buster, alpine=v3.18 , ubuntu=precise)." )
    update_group.add_argument( "--no-auto-update", action="store_true", help="Disable automatic checking and updating of vulnerability databases before scanning." )

    # --- Output and Filtering Group ---
    output_group = parser.add_argument_group('Output and Filtering Options')
    output_group.add_argument( "--format", type=str, choices=['text', 'json', 'html'], default=config.get('format', 'text').lower(), help="Output format." )
    output_group.add_argument( "-o", "--output-file", type=str, default=config.get('output_file', None), help="Path to save report output (especially for HTML/JSON)." )
    output_group.add_argument( "--severity-threshold", type=str, choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'], default=config.get('severity_threshold', None), help="Minimum severity to report." )
    output_group.add_argument( "--ignore", type=str, default=config.get('ignore_vulnerabilities_str', None), help="Comma-separated vulnerability IDs to ignore (e.g., CVE-2020-123,GHSA-abc-123)." )
    
    parser.add_argument( '-h', '--help', action='help', default=argparse.SUPPRESS, help='Show this help message and exit.' )
    args = parser.parse_args()

    # --- Handle --ignore from config and CLI ---
    # Config 'ignore_vulnerabilities' is expected to be a list
    config_ignored_list = config.get('ignore_vulnerabilities', [])
    if not isinstance(config_ignored_list, list): # Ensure it's a list
        print(f"Warning: 'ignore_vulnerabilities' in config is not a list, ignoring config ignores. Found: {type(config_ignored_list)}")
        config_ignored_list = []
    config_ignored_ids = {str(v).strip().lower() for v in config_ignored_list}
    
    cli_ignored_ids = set()
    if args.ignore: # args.ignore is the comma-separated string from CLI
        cli_ignored_ids = {v.strip().lower() for v in args.ignore.split(',')}
    
    # Combine and store in args for consistent use later
    args.effective_ignore_ids = config_ignored_ids.union(cli_ignored_ids)


    # === Handle Update Actions First and Exit (Keep this logic as is) ===
    is_update_action = args.update_db or args.fetch_cve or args.update_os
    if args.fetch_cve:
        print(f"ACTION: Fetching specific CVE: {args.fetch_cve}")
        try: vulndb.get_db_connection(); fetcher.fetch_and_store_single_cve(args.fetch_cve)
        except Exception as e: print(f"Error during specific CVE fetch: {e}", file=sys.stderr)
        finally: vulndb.close_db_connection(); print("Exiting after fetch attempt."); sys.exit(0)
    elif args.update_os:
        print(f"ACTION: Updating OS DB: {args.update_os}")
        try:
            distro, release_identifier = args.update_os.lower().split('=', 1)
            if not distro or not release_identifier: raise ValueError("Invalid format.")
            vulndb.get_db_connection()
            if distro == 'debian': fetcher.fetch_and_store_debian_data(release_identifier)
            elif distro == 'alpine': fetcher.fetch_and_store_alpine_data(release_identifier)
            elif distro == 'ubuntu': fetcher.fetch_and_store_ubuntu_data(release_identifier)
            elif distro.lower() in ['centos', 'rhel']: fetcher.fetch_and_store_centos_data(release_identifier)

            else: print(f"Error: Unsupported OS for update: {distro}")
        except ValueError: print(f"Error parsing --update-os: Expected 'distro=release'.", file=sys.stderr)
        except Exception as e: print(f"Error during OS DB update for {args.update_os}: {e}", file=sys.stderr)
        finally: vulndb.close_db_connection(); print("Exiting after OS DB update attempt."); sys.exit(0)
    elif args.update_db:
        print(f"ACTION: Updating NVD DB")
        try: vulndb.get_db_connection(); fetcher.update_vulnerability_db(max_pages=args.max_pages)
        except Exception as e: print(f"Error during NVD DB update: {e}", file=sys.stderr)
        finally: vulndb.close_db_connection(); print("Exiting after NVD DB update attempt."); sys.exit(0)
    
    # --- Auto-Update Logic (Keep this as is, but ensure DB is connected if needed) ---
    if not is_update_action and not args.no_auto_update:
        print("\n--- Checking Data Freshness for Auto-Update ---")
        config_update_interval_days = config.get('auto_update_interval_days', 7)
        try:
            vulndb.get_db_connection() # Ensure DB is connected for freshness checks
            # NVD Check
            last_nvd_update = vulndb.get_data_source_last_updated("nvd")
            nvd_needs_update = False
            if last_nvd_update is None: nvd_needs_update = True; print("NVD data never updated. Triggering update.")
            else:
                age = datetime.now(timezone.utc) - last_nvd_update
                if age > timedelta(days=config_update_interval_days): nvd_needs_update = True; print(f"NVD data is {age.days} days old. Triggering update.")
                else: print(f"NVD data is up-to-date (last updated {age.days} days ago).")
            if nvd_needs_update:
                print("Attempting automatic NVD data update...")
                auto_update_max_pages = config.get('nvd_max_pages_auto_update', args.max_pages or 20)
                fetcher.update_vulnerability_db(max_pages=auto_update_max_pages)
            # OS Data Check (will be done before specific OS scan if needed by registry_client or image_tar logic)
        except Exception as e:
            print(f"Error during auto-update check or process: {e}. Proceeding with existing data.")
        # DB connection will be closed at the end of main by the main try/finally block

    # --- Determine Scan Target & Perform Scan ---
    final_results: list[ScanResult] = []
    scan_target_path_obj: Optional[Path] = None # For file-based scans

    # Ensure at least one scan target is provided if no update action was performed
    if not is_update_action and not args.input_file and not args.image_tar and not args.registry_image and not args.java_archive and not args.go_mod:
        parser.error("No scan target specified (input_file, --image-tar, --registry-image, --java-archive, or --go-mod) and no update action was taken.")

    try: # Main try block for scanning, ensures DB connection is closed
        if args.go_mod:
            final_results = handle_go_module_scan(args, config)
        elif args.registry_image: # <-- NEW: Handle registry image scan
            # handle_registry_scan will manage its own DB connection if registry_client.py does
            # Or, we ensure it's open here and closed in finally.
            # Current registry_client.scan_image_from_registry handles its own DB connection lifecycle.
            final_results = handle_registry_scan(args, config)
        
        elif args.image_tar:
            scan_target_path_obj = Path(args.image_tar)
            print(f"Selected target: Image Tarball '{scan_target_path_obj}'")
            if not scan_target_path_obj.is_file(): print(f"Error: Scan target file not found: {scan_target_path_obj}", file=sys.stderr); sys.exit(1)
            
            print("\n--- Image Scan ---"); os_scan_results = []; app_scan_results = []
            # Ensure DB connection for image scan
            vulndb.get_db_connection()

            print("\n--- Starting OS Package Scan ---"); os_info = image_parser.detect_os_from_tar(str(scan_target_path_obj))
            if os_info:
                distro_id = os_info.get('ID', '').lower()
                distro_version_id = os_info.get('VERSION_ID', '')
                distro_codename = os_info.get('VERSION_CODENAME', '').lower()
                if not distro_codename and distro_id == 'debian' and distro_version_id == '11': distro_codename = 'bullseye' # Buster was 10
                if not distro_codename and distro_id == 'debian' and distro_version_id == '10': distro_codename = 'buster'


                release_identifier_for_vuln_db = None
                if distro_id == 'alpine':
                    if distro_version_id: major_minor = '.'.join(distro_version_id.split('.')[:2]); release_identifier_for_vuln_db = f"v{major_minor}"
                elif distro_codename: release_identifier_for_vuln_db = distro_codename
                
                if release_identifier_for_vuln_db and not args.no_auto_update: # Auto-update OS data if needed
                    os_source_name = f"{distro_id}_{release_identifier_for_vuln_db}"
                    last_os_update = vulndb.get_data_source_last_updated(os_source_name)
                    os_needs_update = False
                    if last_os_update is None: os_needs_update = True; print(f"OS data for {os_source_name} never updated. Triggering update.")
                    else:
                        age = datetime.now(timezone.utc) - last_os_update
                        if age > timedelta(days=config.get('auto_update_interval_days', 7)): os_needs_update = True; print(f"OS data for {os_source_name} is {age.days} days old. Triggering update.")
                        else: print(f"OS data for {os_source_name} is up-to-date.")
                    if os_needs_update:
                        print(f"Attempting automatic OS data update for {distro_id}={release_identifier_for_vuln_db}...")
                        if distro_id == 'debian': fetcher.fetch_and_store_debian_data(release_identifier_for_vuln_db)
                        elif distro_id == 'alpine': fetcher.fetch_and_store_alpine_data(release_identifier_for_vuln_db)

                os_packages_dicts = []
                if distro_id in ['debian', 'ubuntu']:
                    dpkg_status_content = image_parser.find_latest_file_in_tar(str(scan_target_path_obj), '/var/lib/dpkg/status')
                    if dpkg_status_content: os_packages_dicts = image_parser.parse_dpkg_status(dpkg_status_content)
                elif distro_id == 'alpine':
                    apk_installed_content = image_parser.find_latest_file_in_tar(str(scan_target_path_obj), '/lib/apk/db/installed')
                    if apk_installed_content: os_packages_dicts = image_parser.parse_apk_installed(apk_installed_content, f"image:{scan_target_path_obj.name}")
                
                if os_packages_dicts and release_identifier_for_vuln_db:
                    os_vuln_db_data = vulndb.load_os_vulnerabilities(distro_id, release_identifier_for_vuln_db)
                    if os_vuln_db_data:
                        if distro_id in ['debian', 'ubuntu']: os_scan_results = scanner.scan_debian_os_packages(os_packages_dicts, distro_id, release_identifier_for_vuln_db, os_vuln_db_data)
                        elif distro_id == 'alpine': os_scan_results = scanner.scan_alpine_os_packages(os_packages_dicts, distro_id, release_identifier_for_vuln_db, os_vuln_db_data)
                    else: print(f"Warning: No OS vuln data loaded for {distro_id} {release_identifier_for_vuln_db}.")
                else: print("Skipping OS vulnerability scan (missing package list, OS info, or release identifier).")
            else: print("Could not detect OS. Skipping OS package scan.")
            
            print("\n--- Starting Application Dependency Scan within Image ---")
            APP_MANIFEST_TARGETS = config.get('app_manifest_targets_in_image', ['requirements.txt', 'package-lock.json'])
            app_manifests = image_parser.find_app_manifests_in_tar(str(scan_target_path_obj), APP_MANIFEST_TARGETS)
            all_app_packages_from_image = []
            if app_manifests:
                for filepath, content_bytes in app_manifests.items():
                    filename = Path(filepath).name; source_hint = f"image:{filepath}"
                    content_str = content_bytes.decode('utf-8', errors='ignore')
                    if filename.endswith('.txt'): all_app_packages_from_image.extend(parse_requirements(content_str, source_hint))
                    elif filename == 'package-lock.json': all_app_packages_from_image.extend(parse_package_lock(content_str, source_hint))
                if all_app_packages_from_image: app_scan_results = scanner.scan_application_dependencies(all_app_packages_from_image)
            final_results = os_scan_results + app_scan_results

        elif args.input_file:
            scan_target_path_obj = Path(args.input_file)
            file_type = detect_file_type(str(scan_target_path_obj))
            
            if file_type == 'go_mod':
                # If a go.mod file is provided as input_file, use it with handle_go_module_scan
                args.go_mod = str(scan_target_path_obj)  # Set the go_mod argument
                final_results = handle_go_module_scan(args, config)
            elif file_type == 'python':
                print(f"Selected target: Requirements File '{scan_target_path_obj}'")
                print("\n--- Application Dependency Scan ---")
                vulndb.get_db_connection()
                app_packages = parse_requirements(scan_target_path_obj.read_text(encoding='utf-8', errors='ignore'), str(scan_target_path_obj))
                if app_packages:
                    final_results = scanner.scan_application_dependencies(app_packages)
                else:
                    print("No packages parsed from input file.")
            elif file_type == 'npm':
                print(f"Selected target: Lockfile '{scan_target_path_obj}'")
                print("\n--- Application Dependency Scan ---")
                vulndb.get_db_connection()
                app_packages = parse_package_lock(scan_target_path_obj.read_text(encoding='utf-8', errors='ignore'), str(scan_target_path_obj))
                if app_packages:
                    final_results = scanner.scan_application_dependencies(app_packages)
                else:
                    print("No packages parsed from input file.")
            else:
                print(f"Error: Unsupported input file type: {scan_target_path_obj.name}.", file=sys.stderr)
                sys.exit(1)

            if not scan_target_path_obj.is_file():
                print(f"Error: Scan target file not found: {scan_target_path_obj}", file=sys.stderr)
                sys.exit(1)

        elif args.java_archive: # +++ THIS IS YOUR EXISTING BLOCK +++
            scan_target_path_obj = Path(args.java_archive)
            print(f"Selected target: Java Archive '{scan_target_path_obj}'") # Using print like other parts of your main.py
            if not scan_target_path_obj.is_file():
                print(f"Error: Java archive not found inside container: {scan_target_path_obj}", file=sys.stderr)
                sys.exit(1)
            
            print("\n--- Java Archive Dependency Scan ---")
            # vulndb.get_db_connection() # Ensure DB is connected if scan_application_dependencies needs it immediately

            all_extracted_library_details = [] 
            archive_filename_for_logging = os.path.basename(args.java_archive)

            # Determine archive type and analyze
            if args.java_archive.lower().endswith('.war'):
                all_extracted_library_details = java_analyser.analyze_war_file(args.java_archive)
            elif args.java_archive.lower().endswith('.jar'):
                all_extracted_library_details = java_analyser.analyze_spring_boot_jar(args.java_archive)
                if not all_extracted_library_details: 
                    print(f"INFO: {args.java_archive} not a Spring Boot fat JAR or no libs found, trying as single library.")
                    try:
                        with open(args.java_archive, 'rb') as f_jar:
                            jar_bytes = f_jar.read()
                        single_gav_details = java_analyser.extract_gav_from_jar_bytes(jar_bytes, archive_filename_for_logging)
                        if any(val for key, val in single_gav_details.items() if key in ['groupId', 'artifactId', 'version']):
                            single_gav_details['filename_in_archive'] = archive_filename_for_logging 
                            all_extracted_library_details = [single_gav_details]
                    except Exception as e:
                        print(f"ERROR: Could not analyze {args.java_archive} as simple library: {e}", file=sys.stderr)
            elif args.java_archive.lower().endswith('.ear'):
                all_extracted_library_details = java_analyser.analyze_ear_file(args.java_archive) 
            else:
                print(f"Error: Unsupported Java archive type: {args.java_archive}", file=sys.stderr)
                sys.exit(1)

            if not all_extracted_library_details:
                print("No libraries found or GAVs extracted from the Java archive.")
                final_results = [] 
            else:
                print(f"Extracted {len(all_extracted_library_details)} potential libraries. Preparing for vulnerability scan...")
                maven_packages_to_scan = []
                
                for lib_detail in all_extracted_library_details:
                    group_id = lib_detail.get('groupId')
                    artifact_id = lib_detail.get('artifactId')
                    version_str = lib_detail.get('version')
                    filename_in_archive = lib_detail.get('filename_in_archive', 'N/A') 

                    if group_id and artifact_id and version_str:
                        package_version_representation: Union[Version, str] # Type hint for clarity
                        try:
                            # --- MODIFIED SECTION FOR VERSION PARSING ---
                            package_version_representation = parse_version(version_str) 
                        except InvalidVersion:
                            # If parsing fails, use the original string.
                            # OSV API can often handle non-standard version strings.
                            print(f"INFO: Version string '{version_str}' for Java lib {group_id}:{artifact_id} from '{filename_in_archive}' is non-standard. Using raw string for OSV query.", file=sys.stdout) # Changed to stdout for INFO
                            package_version_representation = version_str
                        # --- END OF MODIFIED SECTION ---
                            
                        package_name_for_osv = f"{group_id}:{artifact_id}"
                        
                        try:
                            pkg = Package(name=package_name_for_osv, 
                                          version=package_version_representation, # Use parsed Version or raw string
                                          ecosystem="Maven")
                            maven_packages_to_scan.append(pkg)
                        except Exception as e_pkg: # Catch any other error during Package creation
                             print(f"Warning: Error creating Package object for Java lib {group_id}:{artifact_id}@{version_str} from '{filename_in_archive}': {e_pkg}", file=sys.stderr)
                    else:
                        print(f"Warning: Incomplete GAV for library '{filename_in_archive}', skipping: {lib_detail}", file=sys.stderr)
                
                if maven_packages_to_scan:
                    # Ensure DB is connected before calling scanner.scan_application_dependencies
                    # if it relies on an active connection passed implicitly or via a global.
                    # Your existing scan_file and scan_image_tar might already do this.
                    # If vulndb.get_db_connection() is idempotent or managed, calling it here is safe.
                    try:
                        vulndb.get_db_connection() # Ensure connection for the scan
                        final_results = scanner.scan_application_dependencies(maven_packages_to_scan)
                    except Exception as e_scan:
                        print(f"ERROR: Failed during application dependency scan for Java libs: {e_scan}", file=sys.stderr)
                        final_results = []
                    # The vulndb.close_db_connection() is in your main 'finally' block, which is good.
                else:
                    print("No valid Java libraries to submit for vulnerability scanning after GAV processing.")
                    final_results = []
            
            # The existing filtering and reporting logic that processes 'final_results' should now work correctly
            # as the Package objects within ScanResult will have the correct Version type.

        # --- Apply Filters (Moved here to apply to all scan types) ---
        filtered_results = final_results
        if args.severity_threshold:
            try:
                threshold_str = args.severity_threshold.upper(); threshold_value = SEVERITY_ORDER[threshold_str]
                print(f"\nApplying severity threshold: {threshold_str} (Minimum value: {threshold_value})")
                original_count = len(filtered_results)
                filtered_results = [r for r in filtered_results if SEVERITY_ORDER.get(r.vulnerability.severity.upper(), 0) >= threshold_value]
                print(f"Filtered {original_count - len(filtered_results)} vulnerabilities by severity. Remaining: {len(filtered_results)}")
            except KeyError:
                print(f"Warning: Invalid severity threshold '{args.severity_threshold}'. Ignoring filter.")
        
        if args.effective_ignore_ids: # Use the combined ignore set
            print(f"\nIgnoring {len(args.effective_ignore_ids)} vulnerability IDs specified via config or CLI.")
            results_to_keep = []; removed_count = 0
            for result in filtered_results:
                if result.vulnerability.cve_id.lower() not in args.effective_ignore_ids:
                    results_to_keep.append(result)
                else: removed_count +=1
            filtered_results = results_to_keep
            print(f"Ignored {removed_count} specified vulnerabilities. Remaining: {len(filtered_results)}")

        # --- Report Results ---
        print("\n--- Final Scan Report ---")
        if args.format == 'json': print_json_report(filtered_results)
        elif args.format == 'html': print_html_report(filtered_results, args.output_file)
        else: print_text_report(filtered_results)

    except Exception as e:
        print(f"\nAn unexpected error occurred during the scan process: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc() # Print full traceback for debugging
    finally:
        vulndb.close_db_connection() # Ensure DB connection is always closed
        print("\nScan process finished.")


if __name__ == "__main__":
    main()
