# vuln_scanner/parser.py
import re
import json
from packaging.version import parse as parse_version, InvalidVersion
from .models import Package

# Regex to find package==version lines, ignoring comments and extras
REQ_PATTERN = re.compile(r'^\s*([a-zA-Z0-9_.-]+)\s*==\s*([a-zA-Z0-9_.*+-]+)')

def parse_requirements(content: str, source_hint: str = "input") -> list[Package]:
    """Parses requirements.txt content."""
    packages = []
    print(f"Parsing requirements content from {source_hint}...")
    lines = content.splitlines() # Split content into lines
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        match = REQ_PATTERN.match(line)
        if match:
            name = match.group(1).lower()
            version_str = match.group(2)
            try:
                version_obj = parse_version(version_str)
                packages.append(Package(name=name, version=version_obj,ecosystem="PyPI"))
            except InvalidVersion:
                print(f"Warning ({source_hint}): Skipping line {line_num}: Invalid version '{version_str}' for package '{name}'")
        # else: # Optional warning for non-matching lines
            # if not line.startswith('-'):
            #      print(f"Warning ({source_hint}): Skipping line {line_num}: Could not parse format 'package==version' from '{line}'")

    print(f"Parsed {len(packages)} packages from requirements content ({source_hint}).")
    return packages


# Add this function after parse_requirements
def parse_package_lock(content: str, source_hint: str = "input") -> list[Package]:
    """
    Parses package-lock.json content (v2/v3 format with 'packages' key).
    """
    print(f"Parsing package-lock.json content from {source_hint}...")
    packages_found = {} # Use dict keyed by (name, version_str) to store unique Packages

    try:
        data = json.loads(content) # Load JSON from string content

        if 'packages' not in data:
            print(f"Warning ({source_hint}): Lockfile content does not contain 'packages' key. Might be v1 format (unsupported) or invalid.")
            return []

        for path, details in data.get('packages', {}).items():
            if not path or not path.startswith('node_modules/') or '/node_modules/' in path[len('node_modules/'):]:
                 continue # Skip root, nested node_modules for simplicity now

            name_part = path[len('node_modules/'):]
            package_name = name_part

            if 'version' in details:
                version_str = details['version']
                # Optional: Skip dev deps check: if details.get('dev'): continue
                try:
                    version_obj = parse_version(version_str)
                    packages_found[(package_name, version_str)] = Package(name=package_name, version=version_obj , ecosystem="npm")
                except InvalidVersion:
                    print(f"Warning ({source_hint}): Skipping entry for '{package_name}': Invalid version format '{version_str}'")
            # else: # Skip entries without version
                # print(f"Warning ({source_hint}): Skipping entry '{path}': Missing 'version' field.")

    except json.JSONDecodeError:
        print(f"Error ({source_hint}): Could not decode JSON content.")
        return []
    except Exception as e:
         print(f"An unexpected error occurred parsing lockfile content ({source_hint}): {e}")
         return []

    package_list = list(packages_found.values())
    print(f"Parsed {len(package_list)} unique packages from package-lock content ({source_hint}).")
    return package_list