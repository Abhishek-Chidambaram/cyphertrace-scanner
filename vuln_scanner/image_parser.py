# vuln_scanner/image_parser.py
from packaging.version import parse as parse_version, InvalidVersion
import tarfile
import io
import re
import json
from pathlib import Path

# In vuln_scanner/image_parser.py

# Add this import if it's not already there globally
# from packaging.version import parse as parse_version, InvalidVersion

# [ Keep the parse_cpe function definition here ]
def parse_cpe(cpe_string: str) -> dict | None: # ... (implementation from before) ...
    if not cpe_string or not cpe_string.startswith("cpe:2.3:"): return None
    parts = cpe_string.split(':')
    if len(parts) < 13: return None
    try: return { "part": parts[2], "vendor": parts[3], "product": parts[4], "version": parts[5], "update": parts[6], "edition": parts[7], "language": parts[8], "sw_edition": parts[9], "target_sw": parts[10], "target_hw": parts[11], "other": parts[12] }
    except IndexError: return None

# In vuln_scanner/image_parser.py

def find_app_manifests_in_tar(tar_path: str, target_filenames: list[str]) -> dict[str, bytes]:
    """
    Finds specified application manifest filenames within an OCI-layout tar archive.
    Handles layers and returns a dictionary mapping the found file paths (relative
    to image root) to their latest content (bytes).
    """
    found_files: dict[str, bytes] = {} # Store path -> content mapping
    target_platform = {"os": "linux", "architecture": "amd64"} # Default target platform

    print(f"DEBUG OCI App Scan: Searching for {target_filenames} in OCI tar {tar_path}")

    try:
        with tarfile.open(tar_path, 'r') as tar:

            def read_blob(digest: str) -> bytes | None: # ... (implementation from before) ...
                blob_path = f"blobs/sha256/{digest.split(':')[-1]}"; member = tar.getmember(blob_path); file = tar.extractfile(member)
                if file: blob_content = file.read(); file.close(); return blob_content
                else: print(f"Warning: Could not extract blob file: {blob_path}"); return None

            # 1. Find and read index.json, handle nested index to get image_manifest_digest
            # ... (Condensed manifest finding logic from previous find_latest_file_in_tar - keep it!) ...
            index_json_content=None; index_data=None; manifest_list_to_search=None; selected_manifest_digest=None
            try: index_member=tar.getmember('index.json'); index_file=tar.extractfile(index_member); index_json_content=index_file.read(); index_file.close()
            except KeyError: pass
            if not index_json_content: print("Error: index.json not found."); return {}
            index_data=json.loads(index_json_content); # print(f"DEBUG OCI: Parsed index.json.")
            if 'manifests' not in index_data or not isinstance(index_data['manifests'], list) or not index_data['manifests']: print("Error: Invalid/empty 'manifests' in index.json"); return {}
            manifest_list_to_search = index_data['manifests']; first_ref_is_index = False
            if isinstance(manifest_list_to_search[0], dict) and "index" in manifest_list_to_search[0].get("mediaType", ""):
                first_ref_is_index = True; nested_index_digest = manifest_list_to_search[0].get("digest")
                # print(f"DEBUG OCI: First entry is index (Digest: {nested_index_digest}). Reading nested index...")
                if nested_index_digest: nested_index_content = read_blob(nested_index_digest)
                else: print("Error: Nested index digest missing."); return {}
                if nested_index_content: nested_index_data = json.loads(nested_index_content); manifest_list_to_search = nested_index_data.get('manifests', [])
                else: print(f"Error: Could not read nested index blob {nested_index_digest}."); return {}
                if not manifest_list_to_search or not isinstance(manifest_list_to_search, list): print("Error: Nested index 'manifests' invalid."); return {}

            # print(f"DEBUG OCI: Searching for platform {target_platform} in {len(manifest_list_to_search)} references...")
            for manifest_ref in manifest_list_to_search:
                 if isinstance(manifest_ref, dict) and 'platform' in manifest_ref and isinstance(manifest_ref['platform'], dict):
                     platform = manifest_ref['platform']
                     if platform.get('os') == target_platform['os'] and platform.get('architecture') == target_platform['architecture']:
                          selected_manifest_digest = manifest_ref.get('digest'); print(f"DEBUG OCI: Found platform manifest digest: {selected_manifest_digest}"); break
            if not selected_manifest_digest and not first_ref_is_index:
                 print(f"Warning: Platform {target_platform} not found. Using fallback.");
                 if manifest_list_to_search and isinstance(manifest_list_to_search[0], dict): selected_manifest_digest = manifest_list_to_search[0].get('digest')
            if not selected_manifest_digest: print("Error: Could not determine final image manifest digest."); return {}
            # print(f"DEBUG OCI: Using final image manifest digest: {selected_manifest_digest}")

            # 3. Read final image manifest
            manifest_json_content = read_blob(selected_manifest_digest)
            if not manifest_json_content: print(f"Error: Could not read final manifest {selected_manifest_digest}"); return {}
            manifest_data = json.loads(manifest_json_content); manifest_media_type = manifest_data.get("mediaType", "")
            if "index" in manifest_media_type or "manifests" in manifest_data: print(f"Error: Final digest {selected_manifest_digest} points to an index!"); return {}

            # 4. Get Layer Digests
            layers_digests = [layer['digest'] for layer in manifest_data.get('layers', []) if isinstance(layer, dict) and 'digest' in layer]
            # print(f"DEBUG OCI: Parsed final image manifest. Found {len(layers_digests)} layers.")
            if not layers_digests: print("Warning: Final manifest contains no layers.")

            # 5. Process layers to find target files
            for i, layer_digest in enumerate(layers_digests):
                layer_blob_content = read_blob(layer_digest)
                if not layer_blob_content: continue # Skip layer if blob unreadable
                short_digest = layer_digest.split(':')[-1][:12] if ':' in layer_digest else layer_digest[:12]
                # print(f"DEBUG OCI App Scan: Processing Layer {i+1}/{len(layers_digests)}: {short_digest}...")

                try:
                    with tarfile.open(fileobj=io.BytesIO(layer_blob_content), mode='r:*') as layer_tar:
                        for layer_member in layer_tar.getmembers():
                             # Check for whiteout files later if needed (.wh. prefix)
                             if layer_member.isfile(): # Only consider regular files
                                 member_name = layer_member.name
                                 normalized_name = member_name.strip('/.')
                                 # Check if the *filename* part matches one of our targets
                                 filename = Path(normalized_name).name # Use pathlib for robust filename extraction
                                 if filename in target_filenames:
                                     print(f"DEBUG OCI App Scan:   Found potential target: '{normalized_name}' (filename: '{filename}') in layer {i+1}")
                                     file_reader = layer_tar.extractfile(layer_member)
                                     if file_reader:
                                         # Store content, overwriting if found in later layer
                                         found_files[normalized_name] = file_reader.read()
                                         file_reader.close()
                except tarfile.ReadError as layer_err: print(f"Warning: Could not read layer tarball {short_digest}...: {layer_err}. Skipping layer.")
                except Exception as layer_exc: print(f"Warning: Unexpected error processing layer {short_digest}...: {layer_exc}. Skipping layer.")

        # Outer exceptions
    except Exception as e: print(f"An unexpected error occurred during tar processing: {e}"); return {}

    print(f"DEBUG OCI App Scan: Found {len(found_files)} potential manifest files: {list(found_files.keys())}")
    return found_files

def find_latest_file_in_tar(tar_path: str, target_filepath: str, fallback_filepath: str | None = None) -> bytes | None:
    """
    Finds the 'latest' version of target_filepath or fallback_filepath within
    an OCI-layout tar archive. Handles layers and returns content from the last
    layer containing either file (prioritizing target_filepath if both exist as files).
    """
    content = None
    fallback_content = None # Store content if fallback path is found
    target_platform = {"os": "linux", "architecture": "amd64"}

    # Normalize target paths
    target_filepath_norm = target_filepath.strip('/.')
    fallback_filepath_norm = fallback_filepath.strip('/.') if fallback_filepath else None

    print(f"DEBUG OCI: Searching for '{target_filepath_norm}'"
          f"{f' (or fallback {fallback_filepath_norm})' if fallback_filepath_norm else ''}"
          f" in OCI tar {tar_path}")

    try:
        with tarfile.open(tar_path, 'r') as tar:

            def read_blob(digest: str) -> bytes | None: # ... (implementation from before) ...
                blob_path = f"blobs/sha256/{digest.split(':')[-1]}"; member = tar.getmember(blob_path); file = tar.extractfile(member)
                if file: blob_content = file.read(); file.close(); return blob_content
                else: print(f"Warning: Could not extract blob file: {blob_path}"); return None
            # Added error handling for read_blob in previous steps

            # 1. Find and read index.json, handle nested index to get image_manifest_digest
            # ... (Condensed manifest finding logic from previous version - keep it!) ...
            index_json_content=None; index_data=None; manifest_list_to_search=None; selected_manifest_digest=None
            try: index_member=tar.getmember('index.json'); index_file=tar.extractfile(index_member); index_json_content=index_file.read(); index_file.close()
            except KeyError: pass
            if not index_json_content: print("Error: index.json not found."); return None
            index_data=json.loads(index_json_content); print(f"DEBUG OCI: Parsed index.json.")
            if 'manifests' not in index_data or not isinstance(index_data['manifests'], list) or not index_data['manifests']: print("Error: Invalid/empty 'manifests' in index.json"); return None
            manifest_list_to_search = index_data['manifests']; first_ref_is_index = False
            if isinstance(manifest_list_to_search[0], dict) and "index" in manifest_list_to_search[0].get("mediaType", ""):
                first_ref_is_index = True; nested_index_digest = manifest_list_to_search[0].get("digest")
                if nested_index_digest: nested_index_content = read_blob(nested_index_digest)
                else: print("Error: Nested index digest missing."); return None
                if nested_index_content: nested_index_data = json.loads(nested_index_content); manifest_list_to_search = nested_index_data.get('manifests', [])
                else: print(f"Error: Could not read nested index blob {nested_index_digest}."); return None
                if not manifest_list_to_search or not isinstance(manifest_list_to_search, list): print("Error: Nested index 'manifests' invalid."); return None
            print(f"DEBUG OCI: Searching for platform {target_platform} in {len(manifest_list_to_search)} references...")
            for manifest_ref in manifest_list_to_search:
                 if isinstance(manifest_ref, dict) and 'platform' in manifest_ref and isinstance(manifest_ref['platform'], dict):
                     platform = manifest_ref['platform']
                     if platform.get('os') == target_platform['os'] and platform.get('architecture') == target_platform['architecture']:
                          selected_manifest_digest = manifest_ref.get('digest'); print(f"DEBUG OCI: Found matching platform manifest digest: {selected_manifest_digest}"); break
            if not selected_manifest_digest and not first_ref_is_index:
                 print(f"Warning: Platform {target_platform} not found. Using fallback.");
                 if manifest_list_to_search and isinstance(manifest_list_to_search[0], dict): selected_manifest_digest = manifest_list_to_search[0].get('digest')
            if not selected_manifest_digest: print("Error: Could not determine final image manifest digest."); return None
            print(f"DEBUG OCI: Using final image manifest digest: {selected_manifest_digest}")
            # ... (End condensed manifest finding) ...

            # 3. Read final image manifest
            manifest_json_content = read_blob(selected_manifest_digest)
            if not manifest_json_content: print(f"Error: Could not read final manifest {selected_manifest_digest}"); return None
            manifest_data = json.loads(manifest_json_content); manifest_media_type = manifest_data.get("mediaType", "")
            if "index" in manifest_media_type or "manifests" in manifest_data: print(f"Error: Final digest {selected_manifest_digest} points to an index!"); return None

            # 4. Get Layer Digests
            layers_digests = [layer['digest'] for layer in manifest_data.get('layers', []) if isinstance(layer, dict) and 'digest' in layer]
            print(f"DEBUG OCI: Parsed final image manifest. Found {len(layers_digests)} layers.")
            if not layers_digests: print("Warning: Final manifest contains no layers.")

            # 5. Process layers
            content = None # Content for primary target path
            fallback_content = None # Content for fallback path

            for i, layer_digest in enumerate(layers_digests):
                layer_blob_content = read_blob(layer_digest)
                if not layer_blob_content: print(f"Warning: Could not read layer blob {layer_digest}. Skipping layer {i+1}."); continue
                short_digest = layer_digest.split(':')[-1][:12] if ':' in layer_digest else layer_digest[:12]
                print(f"DEBUG OCI: Processing Layer {i+1}/{len(layers_digests)}: {short_digest}...")

                try:
                    with tarfile.open(fileobj=io.BytesIO(layer_blob_content), mode='r:*') as layer_tar:
                        layer_members = [];
                        try: layer_members = layer_tar.getmembers()
                        except Exception as e_members: print(f"DEBUG OCI:   Opened layer tar but failed to get members: {e_members}")
                        # print(f"DEBUG OCI:   Successfully opened layer tar. Found {len(layer_members)} members.")

                        for layer_member in layer_members:
                            member_name = layer_member.name
                            normalized_name = member_name.strip('/.')

                            is_regular_file = layer_member.isfile() # Check if it's a regular file

                            # Check for PRIMARY target path
                            if normalized_name == target_filepath_norm:
                                if is_regular_file:
                                    print(f"DEBUG OCI:   Found primary target '{target_filepath_norm}' as file in layer {i+1}.")
                                    file_reader = layer_tar.extractfile(layer_member)
                                    if file_reader:
                                        content = file_reader.read() # Overwrite previous layer's content
                                        file_reader.close()
                                else:
                                     print(f"DEBUG OCI:   Found primary target '{target_filepath_norm}' but it's not a regular file (Type: {layer_member.type}).")


                            # Check for FALLBACK target path (only if provided)
                            elif fallback_filepath_norm and normalized_name == fallback_filepath_norm:
                                if is_regular_file:
                                    print(f"DEBUG OCI:   Found fallback target '{fallback_filepath_norm}' as file in layer {i+1}.")
                                    file_reader = layer_tar.extractfile(layer_member)
                                    if file_reader:
                                        fallback_content = file_reader.read() # Overwrite previous layer's fallback content
                                        file_reader.close()
                                else:
                                     print(f"DEBUG OCI:   Found fallback target '{fallback_filepath_norm}' but it's not a regular file (Type: {layer_member.type}).")

                except tarfile.ReadError as layer_err: print(f"Warning: Could not read layer tarball {short_digest}...: {layer_err}. Skipping layer.")
                except Exception as layer_exc: print(f"Warning: Unexpected error processing layer {short_digest}...: {layer_exc}. Skipping layer.")

        # Outer exceptions
    except Exception as e: print(f"An unexpected error occurred: {e}"); return None

    # Prioritize primary content, use fallback if primary wasn't found as a file
    final_content = content if content is not None else fallback_content

    if final_content:
        print(f"Successfully extracted latest '{target_filepath_norm if content is not None else fallback_filepath_norm}' from OCI layers.")
    # else: # Warning moved to calling function

    return final_content


# --- Keep other functions (parse_os_release, detect_os_from_tar, parse_dpkg_status) ---
# --- Keep other functions (parse_os_release, detect_os_from_tar, parse_dpkg_status) as they were ---
# Make sure the 'from packaging.version...' import is at the top of the file

def parse_os_release(content: bytes) -> dict:
    """Parses the content of an os-release file into a dictionary."""
    data = {}
    if not content:
        return data
    try:
        # Decode bytes, handle potential errors, split lines
        lines = content.decode('utf-8', errors='ignore').splitlines()
    except Exception as e:
        print(f"Error decoding os-release content: {e}")
        return data

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'): # Skip empty lines and comments
            continue
        # Use regex to handle potential quoting and split key=value
        match = re.match(r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^#\s]+))\s*(?:#.*)?$', line)
        if match:
            key = match.group(1)
            # Value is the first non-None group among quoted or unquoted options
            value = next((g for g in match.groups()[1:] if g is not None), '')
            data[key] = value
            # print(f"DEBUG OS_RELEASE: Parsed {key}={value}") # Debug
    return data


def detect_os_from_tar(tar_path: str) -> dict | None:
    """Detects OS information by reading os-release files from a tarball."""
    print(f"Attempting OS detection from {tar_path}...")
    # Search for /etc/os-release first, fall back to /usr/lib/os-release
    os_release_content = find_latest_file_in_tar(tar_path, '/etc/os-release', '/usr/lib/os-release')

    if os_release_content:
        os_info = parse_os_release(os_release_content)
        if os_info.get("ID") and os_info.get("VERSION_ID"):
             print(f"Detected OS: ID={os_info.get('ID')}, VERSION_ID={os_info.get('VERSION_ID')}")
             return os_info
        else:
             print("Warning: Found os-release content but could not parse required ID and VERSION_ID fields.")
             return None
    else:
        print("Could not find '/etc/os-release' or '/usr/lib/os-release' in the image tarball.")
        return None

# --- Placeholder for Package Parsing ---
def parse_dpkg_status(content: bytes) -> list[dict]:
    """
    Parses dpkg status file content to extract package names and versions.
    Stores the full, unmodified version string reported by dpkg.
    Basic implementation focusing on Package and Version fields.
    """
    print("Parsing dpkg status file...") # Removed "(Not fully implemented)"
    packages = []
    current_pkg = {}
    try:
        text_content = content.decode('utf-8', errors='ignore')
        lines = text_content.splitlines()

        for i, line in enumerate(lines):
            if line.startswith("Package:"):
                # If we were processing a package, store it before starting new one
                # (Handles packages where Version might appear before Package in rare cases)
                if 'name' in current_pkg and 'version' in current_pkg:
                     packages.append(current_pkg)
                # Start new package, extract name
                current_pkg = {'name': line.split(":", 1)[1].strip()}

            elif line.startswith("Version:") and 'name' in current_pkg: # Ensure we have a package context
                # Extract the full version string exactly as presented
                current_pkg['version'] = line.split(":", 1)[1].strip()

            elif line == "" and 'name' in current_pkg: # Blank line signals end of stanza
                # If we have accumulated a name and version, store it
                if 'version' in current_pkg:
                    packages.append(current_pkg)
                else:
                     print(f"Warning (dpkg): Found package '{current_pkg['name']}' without a 'Version:' field before blank line.")
                current_pkg = {} # Reset for next package

        # Handle the last package if the file doesn't end with a blank line
        if 'name' in current_pkg and 'version' in current_pkg:
            packages.append(current_pkg)

    except Exception as e:
        print(f"Error decoding/parsing dpkg status content: {e}")

    print(f"Parsed {len(packages)} dpkg packages.")
    return packages

def parse_apk_installed(content: bytes, source_hint: str = "apk_db") -> list[dict]:
    """
    Parses the content of Alpine's /lib/apk/db/installed file.
    Returns a list of dictionaries, each with 'name' and 'version'.
    """
    print(f"Parsing Alpine APK installed database content from {source_hint}...")
    packages = []
    current_pkg = {}

    if not content:
        return packages

    try:
        text_content = content.decode('utf-8', errors='ignore')
        # Split by double newline (blank line) to separate package stanzas
        stanzas = text_content.strip().split('\n\n')

        for stanza in stanzas:
            if not stanza.strip(): # Skip empty stanzas
                continue

            pkg_name = None
            pkg_version = None
            lines = stanza.splitlines()
            for line in lines:
                line = line.strip()
                if line.startswith('P:'):
                    pkg_name = line[2:].strip()
                elif line.startswith('V:'):
                    pkg_version = line[2:].strip()
                # We can extract other fields like 'A:' (architecture), 'L:' (license) if needed later

            if pkg_name and pkg_version:
                packages.append({'name': pkg_name, 'version': pkg_version})
            # else: # Optionally warn about incomplete stanzas
                # print(f"Warning (apk): Stanza missing Package or Version: {stanza[:100]}...")

    except Exception as e:
        print(f"Error decoding/parsing APK installed content from {source_hint}: {e}")

    print(f"Parsed {len(packages)} APK packages from {source_hint}.")
    return packages
