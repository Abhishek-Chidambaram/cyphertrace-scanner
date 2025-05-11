# main.py
from datetime import datetime, timedelta, timezone 
import argparse
import sys
import json
import yaml  # For config file
import html  # For HTML escaping
import os
from pathlib import Path
from collections import defaultdict # Used in scanner, maybe useful here later

# Import all necessary functions and modules from our scanner
from vuln_scanner.parser import parse_requirements, parse_package_lock
from vuln_scanner import vulndb, fetcher, scanner, image_parser,ai_analyzer
from vuln_scanner.models import ScanResult # For type hinting

# --- Config File Handling ---
CONFIG_FILENAME = "config.yaml" # Default config file name

def load_config(config_path: str = CONFIG_FILENAME) -> dict:
    """Loads configuration from a YAML file."""
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

# --- Reporting Functions ---
def print_text_report(results: list[ScanResult]):
    """Prints the scan results in a human-readable text format."""
    print("\n--- Scan Report (Text) ---")
    if not results:
        print("No vulnerabilities found.")
    else:
        print(f"Found {len(results)} vulnerabilities:")
        results.sort(key=lambda r: (SEVERITY_ORDER.get(r.vulnerability.severity.upper(), 0), r.package.name, r.vulnerability.cve_id), reverse=True) # Sort by severity
        for result in results:
            vuln = result.vulnerability; pkg = result.package
            print(f"  - Package: {pkg.name}=={pkg.version}")
            print(f"    CVE:     {vuln.cve_id}")
            print(f"    Severity:{vuln.severity} ({vuln.cvss_v3_score if vuln.cvss_v3_score is not None else 'N/A'})")
            print(f"    Desc:    {vuln.description}")
            print("-" * 20)
    print("--- End Report ---")

def print_json_report(results: list[ScanResult]):
    """Prints the scan results as a JSON object."""
    output_data = []
    results.sort(key=lambda r: (SEVERITY_ORDER.get(r.vulnerability.severity.upper(), 0), r.package.name, r.vulnerability.cve_id), reverse=True) # Sort by severity
    for result in results:
        vuln = result.vulnerability; pkg = result.package
        output_data.append({
            "packageName": pkg.name, "packageVersion": str(pkg.version),
            "cveId": vuln.cve_id, "severity": vuln.severity,
            "cvssV3Score": float(vuln.cvss_v3_score) if vuln.cvss_v3_score is not None else None,
            "cvssV3Vector": vuln.cvss_v3_vector, "description": vuln.description,
        })
    print(json.dumps(output_data, indent=2))

# --- HTML Report Function (Included Here) ---
def print_html_report(results: list[ScanResult], output_filename: str | None):
    """Generates and saves the scan results as an HTML file."""
    if not output_filename:
        output_filename = "scan_report.html" # Default filename if none provided

    print(f"\nGenerating HTML report: {output_filename}...")

    # Basic CSS for table styling
    html_css = """
<style>
  body { font-family: sans-serif; margin: 20px; }
  table { border-collapse: collapse; margin: 1em 0; width: 95%; box-shadow: 0 2px 3px rgba(0,0,0,0.1); }
  th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; vertical-align: top; }
  th { background-color: #f2f2f2; font-weight: bold; }
  tr:nth-child(even) { background-color: #f9f9f9; }
  caption { caption-side: top; font-size: 1.2em; font-weight: bold; margin-bottom: 10px; text-align: left;}
  .severity-CRITICAL { color: #FF0000; font-weight: bold; }
  .severity-HIGH { color: #FF8C00; font-weight: bold; }
  .severity-MEDIUM { color: #DAA520; } /* Darker Yellow */
  .severity-LOW { color: #32CD32; } /* LimeGreen */
  .severity-UNKNOWN, .severity-NONE { color: #808080; }
  pre { white-space: pre-wrap; word-wrap: break-word; margin: 0; font-family: inherit;}
</style>
"""
    # Start HTML Document
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <title>Vulnerability Scan Report</title>
  <meta charset="UTF-8">
  {html_css}
</head>
<body>
  <h1>Vulnerability Scan Report</h1>
"""
    if not results:
        html_content += "<p>No vulnerabilities found.</p>"
    else:
        num_vulns = len(results)
        html_content += f"<p>Found {num_vulns} vulnerabilities.</p>"
        html_content += "<table>\n"
        html_content += "<caption>Vulnerability Details</caption>\n"
        html_content += """<thead>
<tr>
  <th>Severity</th>
  <th>Score</th>
  <th>Vulnerability ID</th>
  <th>Package</th>
  <th>Version</th>
  <th>Description</th>
</tr>
</thead>
<tbody>\n"""

        # Sort results (e.g., by severity high to low, then package name)
        results.sort(key=lambda r: (SEVERITY_ORDER.get(r.vulnerability.severity.upper(), 0), r.package.name, r.vulnerability.cve_id), reverse=True)

        for result in results:
            vuln = result.vulnerability; pkg = result.package
            severity_class = f"severity-{vuln.severity.upper()}"
            pkg_name_esc = html.escape(pkg.name); pkg_version_esc = html.escape(str(pkg.version))
            vuln_id_esc = html.escape(vuln.cve_id); severity_esc = html.escape(vuln.severity)
            score_str = str(vuln.cvss_v3_score) if vuln.cvss_v3_score is not None else "N/A"
            score_esc = html.escape(score_str); desc_esc = html.escape(vuln.description)
            desc_html = f"<pre>{desc_esc}</pre>" # Use pre for better formatting

            html_content += f"""<tr>
<td class="{severity_class}">{severity_esc}</td>
<td>{score_esc}</td>
<td>{vuln_id_esc}</td>
<td>{pkg_name_esc}</td>
<td>{pkg_version_esc}</td>
<td>{desc_html}</td>
</tr>\n"""

        html_content += "</tbody>\n</table>"

    # End HTML Document
    html_content += "\n</body>\n</html>"

    # Write to file
    try:
        path = Path(output_filename)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"HTML report saved to: {path.resolve()}")
    except Exception as e:
        print(f"Error writing HTML report to {output_filename}: {e}")

# --- Severity Order for Filtering ---
SEVERITY_ORDER = { "UNKNOWN": 0, "NONE": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5 }

# --- Main Execution Logic ---
def main():
    print("### EXECUTING MAIN FUNCTION - VERSION CHECKPOINT (RESPONSE #102/104) ###") # Keep your checkpoint
    config = load_config() # Assumes load_config() is defined globally in main.py

    # --- Argument Parsing (copied from your latest version shared) ---
    parser = argparse.ArgumentParser(description="Simple Vulnerability Scanner", add_help=False)
    input_group = parser.add_argument_group('Scan Target (Required unless updating DB)')
    target_exclusive_group = input_group.add_mutually_exclusive_group(required=False)
    target_exclusive_group.add_argument( "input_file", type=str, nargs='?', help="Path to input file (requirements*.txt, package-lock.json)." )
    target_exclusive_group.add_argument( "--image-tar", type=str, metavar='TAR_PATH', help="Path to a container image tarball ('docker save')." )
    update_group = parser.add_argument_group('Database Update Options')
    update_group.add_argument( "--update-db", action="store_true", help="Fetch/Update NVD data." )
    update_group.add_argument( "--max-pages", type=int, default=config.get('nvd_max_pages', None), help="Limit NVD pages during --update-db." )
    update_group.add_argument( "--fetch-cve", type=str, metavar='CVE_ID', help="Fetch specific CVE ID (NVD)." )
    update_group.add_argument( "--update-os", type=str, metavar='DISTRO=RELEASE', help="Update OS vulnerability data (e.g., debian=bullseye, alpine=v3.18)." )
    output_group = parser.add_argument_group('Output and Filtering Options')
    # AI Argument was removed as per earlier request, so it's not here. If you want it back, let me know.
    #output_group.add_argument( "--ai-summary", action="store_true", help="Use AI to generate summary.")
    output_group.add_argument( "--format", type=str, choices=['text', 'json', 'html'], default=config.get('format', 'text').lower(), help="Output format." )
    output_group.add_argument( "-o", "--output-file", type=str, default=config.get('output_file', None), help="Path to save report output (HTML)." )
    output_group.add_argument( "--severity-threshold", type=str, choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'], default=config.get('severity_threshold', None), help="Minimum severity to report." )
    output_group.add_argument( "--ignore", type=str, default=None, help="Comma-separated vulnerability IDs to ignore." )
    output_group.add_argument( # Or create a new group for update behavior
    "--no-auto-update",
    action="store_true",
    help="Disable automatic checking and updating of vulnerability databases before scanning."
    )
    parser.add_argument( '-h', '--help', action='help', default=argparse.SUPPRESS, help='Show this help message and exit.' )

    args = parser.parse_args()

    # === Explicitly Handle Update Actions First and Exit ===
    if args.fetch_cve:
        print(f"ACTION: Fetching specific CVE: {args.fetch_cve}")
        try:
            vulndb.get_db_connection()
            fetcher.fetch_and_store_single_cve(args.fetch_cve)
        except Exception as e: print(f"Error during specific CVE fetch: {e}", file=sys.stderr)
        finally:
            print("DEBUG: Running fetch_cve finally block...")
            vulndb.close_db_connection()
            print("Exiting after fetch attempt.")
            sys.exit(0) # Exit after this action

    elif args.update_os:
        print(f"ACTION: Updating OS DB: {args.update_os}")
        try:
            distro, release_identifier = args.update_os.lower().split('=', 1)
            if not distro or not release_identifier: raise ValueError("Invalid format.")
            vulndb.get_db_connection()
            if distro == 'debian': fetcher.fetch_and_store_debian_data(release_identifier)
            elif distro == 'alpine': fetcher.fetch_and_store_alpine_data(release_identifier)
            else: print(f"Error: Unsupported OS for update: {distro}")
        except ValueError: print(f"Error parsing --update-os: Expected 'distro=release'.", file=sys.stderr)
        except Exception as e: print(f"Error during OS DB update for {args.update_os}: {e}", file=sys.stderr)
        finally:
            print("DEBUG: Running update_os finally block...")
            vulndb.close_db_connection()
            print("Exiting after OS DB update attempt.")
            sys.exit(0) # Exit after this action

    elif args.update_db:
        print(f"ACTION: Updating NVD DB")
        try:
            vulndb.get_db_connection()
            fetcher.update_vulnerability_db(max_pages=args.max_pages)
        except Exception as e: print(f"Error during NVD DB update: {e}", file=sys.stderr)
        finally:
            print("DEBUG: Running update_db finally block...")
            vulndb.close_db_connection()
            print("Exiting after NVD DB update attempt.")
            sys.exit(0) # Exit after this action
    
    is_update_action = args.update_db or args.fetch_cve or args.update_os
    if not is_update_action and not args.no_auto_update:
        print("\n--- Checking Data Freshness for Auto-Update ---")
        config_update_interval_days = config.get('auto_update_interval_days', 7) # Default to 7 days

        # --- Check NVD Data ---
        print("Checking NVD data freshness...")
        last_nvd_update = vulndb.get_data_source_last_updated("nvd")
        nvd_needs_update = False
        if last_nvd_update is None:
            print("NVD data never updated or timestamp missing. Triggering update.")
            nvd_needs_update = True
        else:
            age = datetime.now(timezone.utc) - last_nvd_update
            if age > timedelta(days=config_update_interval_days):
                print(f"NVD data is {age.days} days old (older than {config_update_interval_days} days). Triggering update.")
                nvd_needs_update = True
            else:
                print(f"NVD data is up-to-date (last updated {age.days} days ago).")

        if nvd_needs_update:
            print("Attempting automatic NVD data update...")
            try:
                # Ensure DB connection is available if not already made by a prior update action
                vulndb.get_db_connection()
                # Use configured max_pages for auto-update, or a smaller default
                auto_update_max_pages = config.get('nvd_max_pages_auto_update', args.max_pages or 20)
                fetcher.update_vulnerability_db(max_pages=auto_update_max_pages)
                # The fetcher now calls update_data_source_timestamp("nvd") on success
            except Exception as e:
                print(f"Automatic NVD update failed: {e}. Proceeding with existing data.")
            # DB connection will be closed at the end of main

        # TODO: Add similar check for OS data here IF scan_target_type is 'image_tar'
        # This is more complex as it needs os_info first.
        # For now, NVD auto-update will cover app scans and NVD enrichment for OS scans.

    # --- If NO update action was specified (script hasn't exited), then proceed to scan ---
    print("DEBUG: No update action specified or completed, proceeding to scan.")

    # --- Determine Scan Target ---
    scan_target_type = None; scan_target_path = None
    if args.image_tar:
        scan_target_type = "image_tar"; scan_target_path = Path(args.image_tar)
        print(f"Selected target: Image Tarball '{scan_target_path}'")
    elif args.input_file:
        scan_target_path = Path(args.input_file); file_name = scan_target_path.name
        if file_name.endswith('.txt'): scan_target_type = "requirements"; print(f"Selected target: Requirements File '{scan_target_path}'")
        elif file_name == 'package-lock.json': scan_target_type = "package-lock"; print(f"Selected target: Lockfile '{scan_target_path}'")
        else: print(f"Error: Unsupported input file type: {file_name}.", file=sys.stderr); sys.exit(1)
    else:
        # This should only be reached if user provides NO arguments at all
        parser.error("No scan target specified (input_file or --image-tar) and no update action was taken.")

    if not scan_target_path or not scan_target_path.is_file(): print(f"Error: Scan target file not found: {scan_target_path}", file=sys.stderr); sys.exit(1)

    print(f"\nStarting scan for {scan_target_path}...")
    final_results: list[ScanResult] = []

    # --- Branch based on scan type ---
    if scan_target_type == "image_tar":
        print("\n--- Image Scan ---"); os_scan_results = []; app_scan_results = []
        print("\n--- Starting OS Package Scan ---"); os_info = image_parser.detect_os_from_tar(str(scan_target_path))
        if os_info:
            distro_id = os_info.get('ID', '').lower()
            distro_version_id = os_info.get('VERSION_ID', '')
            distro_codename = os_info.get('VERSION_CODENAME', '').lower()
            
            # Ensure Debian 11 has a codename if missing from os-release
            if not distro_codename and distro_id == 'debian' and distro_version_id == '11':
                distro_codename = 'bullseye'
            
            print(f"Detected OS: {distro_id} Version: {distro_version_id} Codename: {distro_codename or 'N/A'}")

            # --- Determine the release identifier for vulnerability database ---
            release_identifier_for_vuln_db = None
            if distro_id == 'alpine':
                if distro_version_id:
                    major_minor = '.'.join(distro_version_id.split('.')[:2]) # e.g., "3.18" from "3.18.4"
                    release_identifier_for_vuln_db = f"v{major_minor}"
                else:
                    print(f"Warning: Missing VERSION_ID for Alpine, cannot determine vuln DB branch.")
            elif distro_codename: # Primarily for Debian/Ubuntu
                release_identifier_for_vuln_db = distro_codename
            # Add other OS specific logic for release_identifier here if needed
            # else:
            #     print(f"Warning: Could not determine a primary release identifier for {distro_id} {distro_version_id}.")

            if release_identifier_for_vuln_db:
                 print(f"DEBUG: Using release identifier '{release_identifier_for_vuln_db}' for OS vulnerability data.")
            else:
                 print(f"Warning: No release identifier determined for {distro_id} {distro_version_id}. OS vuln scan might fail to load data.")


            # --- AUTO-UPDATE CHECK FOR OS DATA ---
            if not args.no_auto_update and distro_id and release_identifier_for_vuln_db:
                os_source_name = f"{distro_id}_{release_identifier_for_vuln_db}"
                print(f"\nChecking OS data freshness for {os_source_name}...")
                last_os_update = vulndb.get_data_source_last_updated(os_source_name)
                os_needs_update = False
                config_update_interval_days = config.get('auto_update_interval_days', 7)

                if last_os_update is None:
                    print(f"OS data for {os_source_name} never updated or timestamp missing. Triggering update.")
                    os_needs_update = True
                else:
                    age = datetime.now(timezone.utc) - last_os_update
                    if age > timedelta(days=config_update_interval_days):
                        print(f"OS data for {os_source_name} is {age.days} days old (older than {config_update_interval_days} days). Triggering update.")
                        os_needs_update = True
                    else:
                        print(f"OS data for {os_source_name} is up-to-date (last updated {age.days} days ago).")

                if os_needs_update:
                    print(f"Attempting automatic OS data update for {distro_id}={release_identifier_for_vuln_db}...")
                    try:
                        vulndb.get_db_connection() # Ensure connection
                        if distro_id == 'debian':
                            fetcher.fetch_and_store_debian_data(release_identifier_for_vuln_db)
                        elif distro_id == 'alpine':
                            fetcher.fetch_and_store_alpine_data(release_identifier_for_vuln_db)
                        # fetcher functions call update_data_source_timestamp on success
                    except Exception as e:
                        print(f"Automatic OS data update for {os_source_name} failed: {e}. Proceeding with existing data.")
            # --- END OS AUTO-UPDATE CHECK ---

            os_packages = [] # Initialize os_packages list
            if distro_id in ['debian', 'ubuntu']:
                print("Attempting to parse dpkg database...")
                dpkg_status_content = image_parser.find_latest_file_in_tar(str(scan_target_path), '/var/lib/dpkg/status')
                if dpkg_status_content:
                    os_packages = image_parser.parse_dpkg_status(dpkg_status_content)
                else: print("Could not find /var/lib/dpkg/status file.")
            elif distro_id == 'alpine':
                print("Attempting to parse apk database...")
                apk_installed_content = image_parser.find_latest_file_in_tar(str(scan_target_path), '/lib/apk/db/installed')
                if apk_installed_content:
                    os_packages = image_parser.parse_apk_installed(apk_installed_content, f"image:{scan_target_path.name}")
                else: print("Could not find /lib/apk/db/installed file.")
            else:
                print(f"OS '{distro_id}' package parsing not supported yet.")

            print(f"Found {len(os_packages)} OS packages.")
            if os_packages:
                 print("First few packages (example):")
                 for i, pkg_info_dict in enumerate(os_packages[:5]):
                     print(f"  - {pkg_info_dict.get('name')} == {pkg_info_dict.get('version')}")

            # Scan OS Packages
            if os_packages and distro_id and release_identifier_for_vuln_db:
                try: vulndb.get_db_connection()
                except Exception as db_err: print(f"Error connecting to DB: {db_err}"); sys.exit(1)
                
                os_vuln_data = vulndb.load_os_vulnerabilities(distro_id, release_identifier_for_vuln_db)
                if os_vuln_data:
                    if distro_id in ['debian', 'ubuntu']:
                         os_scan_results = scanner.scan_debian_os_packages(os_packages, distro_id, release_identifier_for_vuln_db, os_vuln_data)
                    elif distro_id == 'alpine':
                         os_scan_results = scanner.scan_alpine_os_packages(os_packages, distro_id, release_identifier_for_vuln_db, os_vuln_data)
                    else:
                         print(f"No specific OS scanning logic implemented for {distro_id}")
                         os_scan_results = []
                else:
                    print(f"Warning: No OS vuln data loaded for {distro_id} {release_identifier_for_vuln_db}.")
                    os_scan_results = []
            else:
                print("Skipping OS vulnerability scan (missing package list, OS info, or determined release identifier).")
                os_scan_results = []
        else:
            print("Could not detect OS. Skipping OS package scan.")
            os_scan_results = []
        print("--- OS Package Scan Finished ---")

        # --- Perform Application Dependency Scan within Image ---
        # (This part of your pasted code already looks correct for app scan within image)
        print("\n--- Starting Application Dependency Scan within Image ---")
        APP_MANIFEST_TARGETS = ['requirements.txt', 'package-lock.json'] # TODO: Make configurable
        try:
            app_manifests = image_parser.find_app_manifests_in_tar(str(scan_target_path), APP_MANIFEST_TARGETS)
            all_app_packages = []
            if not app_manifests: print("No application manifest files found in image.")
            else:
                print(f"Found {len(app_manifests)} application manifest files to analyze.")
                for filepath, content_bytes in app_manifests.items():
                     print(f"  Analyzing: {filepath}"); filename = Path(filepath).name
                     try:
                          content_str = content_bytes.decode('utf-8', errors='ignore'); source_hint = f"image:{filepath}"
                          if filename.endswith('.txt'): all_app_packages.extend(parse_requirements(content_str, source_hint))
                          elif filename == 'package-lock.json': all_app_packages.extend(parse_package_lock(content_str, source_hint))
                     except Exception as parse_err: print(f"  Error parsing {filepath}: {parse_err}")
                if all_app_packages:
                     print(f"\nScanning {len(all_app_packages)} application packages...");
                     try: vulndb.get_db_connection();
                     except Exception as db_err: print(f"Error connecting to DB: {db_err}"); sys.exit(1)
                     app_scan_results = scanner.scan_application_dependencies(all_app_packages)
                else: print("No application packages successfully parsed.")
        except Exception as app_scan_err: print(f"An error occurred during application scan: {app_scan_err}")
        print("--- Application Dependency Scan Finished ---")
        final_results = os_scan_results + app_scan_results

    elif scan_target_type in ["requirements", "package-lock"]:
        print("\n--- Application Dependency Scan ---")
        app_packages = []
        input_filepath_str = str(scan_target_path)
        try: file_content = scan_target_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as read_err: print(f"Error reading input file {input_filepath_str}: {read_err}"); vulndb.close_db_connection(); sys.exit(1)
        file_name = scan_target_path.name
        if file_name.endswith('.txt'): app_packages = parse_requirements(file_content, input_filepath_str)
        elif file_name == 'package-lock.json': app_packages = parse_package_lock(file_content, input_filepath_str)
        if not app_packages: print("No packages parsed."); vulndb.close_db_connection(); sys.exit(1)
        try: vulndb.get_db_connection()
        except Exception as db_err: print(f"Error connecting to DB: {db_err}"); sys.exit(1)
        final_results = scanner.scan_application_dependencies(app_packages)

    else: print(f"Error: Unknown scan target type '{scan_target_type}'", file=sys.stderr); final_results = []

    # --- Apply Filters ---
    filtered_results = final_results
    if args.severity_threshold:
        try: threshold_str = args.severity_threshold.upper(); threshold_value = SEVERITY_ORDER[threshold_str]; print(f"\nApplying severity threshold: {threshold_str} (Minimum value: {threshold_value})"); original_count = len(filtered_results); filtered_results = [ r for r in filtered_results if SEVERITY_ORDER.get(r.vulnerability.severity.upper(), 0) >= threshold_value ]; print(f"Filtered {original_count - len(filtered_results)} vulnerabilities by severity. Remaining: {len(filtered_results)}")
        except KeyError: print(f"Warning: Invalid severity threshold '{args.severity_threshold}'. Ignoring filter.")
    config_ignored_list = config.get('ignore_vulnerabilities', []); config_ignored_ids = {str(v).strip().lower() for v in config_ignored_list if isinstance(v, (str, int))}
    cli_ignored_ids = set()
    if args.ignore: cli_ignored_ids = {v.strip().lower() for v in args.ignore.split(',')}
    ignored_ids = config_ignored_ids.union(cli_ignored_ids)
    if ignored_ids:
        print(f"\nIgnoring {len(ignored_ids)} vulnerability IDs specified via config or CLI."); results_to_keep = []; removed_count = 0
        for result in filtered_results:
            if result.vulnerability.cve_id.lower() not in ignored_ids: results_to_keep.append(result)
            else: removed_count +=1
        filtered_results = results_to_keep; print(f"Ignored {removed_count} specified vulnerabilities. Remaining: {len(filtered_results)}")

    # --- Section 4: Report Results ---
    print("\n--- Final Scan Report ---")
    # AI related code is removed as per previous discussion
    if args.format == 'json': print_json_report(filtered_results)
    elif args.format == 'html':
        try: print_html_report(filtered_results, args.output_file) # Assumes function defined above
        except NameError: print("HTML report function not defined - printing text."); print_text_report(filtered_results)
        except Exception as html_err: print(f"Error generating HTML report: {html_err}"); print_text_report(filtered_results)
    else: print_text_report(filtered_results)

    vulndb.close_db_connection()

if __name__ == "__main__":
    main()

# --- Ensure print_html_report function definition is included ---
# Add the definition here if it's not already present