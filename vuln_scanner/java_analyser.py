# java_analyzer.py
# Placeholder for the new Java analysis module

import zipfile
import io
import xml.etree.ElementTree as ET
import re # For glob-like pattern matching for pom.xml/properties paths
import logging # It's good practice to add logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

logger = logging.getLogger(__name__) # Or use your existing logger from CypherTrace

# --- GAV Extraction Logic ---

def _parse_pom_xml_from_jar_bytes(jar_bytes: bytes, library_filename: str = "unknown.jar") -> dict | None:
    """
    Tries to find and parse pom.xml from JAR file bytes.
    Looks for META-INF/maven/<groupId>/<artifactId>/pom.xml
    Returns a dictionary {'groupId': ..., 'artifactId': ..., 'version': ...} or None.
    """
    gav = {'groupId': None, 'artifactId': None, 'version': None}
    pom_xml_path = None # For logging in case of error

    try:
        with io.BytesIO(jar_bytes) as jar_bio, zipfile.ZipFile(jar_bio, 'r') as jar_zip:
            # Search for pom.xml
            for member_name in jar_zip.namelist():
                if member_name.startswith('META-INF/maven/') and member_name.endswith('/pom.xml'):
                    pom_xml_path = member_name
                    logger.debug(f"Found potential pom.xml at: {pom_xml_path} in {library_filename}")
                    break # Take the first one found
            
            if pom_xml_path:
                pom_xml_content_raw = jar_zip.read(pom_xml_path)
                try:
                    pom_xml_content = pom_xml_content_raw.decode('utf-8')
                except UnicodeDecodeError:
                    logger.warning(f"pom.xml in {library_filename} is not valid UTF-8, trying 'latin-1'")
                    pom_xml_content = pom_xml_content_raw.decode('latin-1', errors='replace')

                # Remove default namespace for easier parsing, if present
                # A common namespace is "http://maven.apache.org/POM/4.0.0"
                pom_xml_content = pom_xml_content.replace('xmlns="http://maven.apache.org/POM/4.0.0"', '', 1)
                
                root = ET.fromstring(pom_xml_content)
                
                # Helper to find text, preferring direct child
                def find_text_direct(element, tag_name):
                    node = element.find(tag_name) # Finds direct children
                    if node is not None and node.text:
                        return node.text.strip()
                    return None

                # Try to get GAV from current project level first
                gav['groupId'] = find_text_direct(root, 'groupId')
                gav['artifactId'] = find_text_direct(root, 'artifactId')
                gav['version'] = find_text_direct(root, 'version')

                # If groupId or version are missing, check the parent
                # (artifactId is usually defined in the project itself, not inherited from parent for the project's own artifactId)
                if gav['groupId'] is None or gav['version'] is None:
                    parent_node = root.find('parent')
                    if parent_node is not None:
                        if gav['groupId'] is None:
                            gav['groupId'] = find_text_direct(parent_node, 'groupId')
                        if gav['version'] is None: # Version can also come from parent
                            gav['version'] = find_text_direct(parent_node, 'version')
                
                if any(gav.values()):
                    logger.info(f"Extracted from pom.xml in {library_filename}: {gav}")
                    return gav
                else:
                    logger.debug(f"pom.xml found in {library_filename} but could not extract GAV values.")
                    return None
            else:
                logger.debug(f"pom.xml not found in {library_filename}")
                return None
    except ET.ParseError:
        logger.error(f"Could not parse pom.xml for {library_filename} (XML malformed). Path: {pom_xml_path}", exc_info=True)
    except zipfile.BadZipFile:
        logger.error(f"Bad ZIP file encountered when parsing pom.xml for {library_filename}", exc_info=True)
    except Exception as e:
        logger.error(f"Error parsing pom.xml from {library_filename}: {e}", exc_info=True)
    return None

def _parse_pom_properties_from_jar_bytes(jar_bytes: bytes, library_filename: str = "unknown.jar") -> dict | None:
    """
    Tries to find and parse pom.properties from JAR file bytes.
    Searches for META-INF/maven/<any_group_id>/<any_artifact_id>/pom.properties
    Returns a dictionary {'groupId': ..., 'artifactId': ..., 'version': ...} or None.
    """
    props_gav = {'groupId': None, 'artifactId': None, 'version': None}
    found_pom_properties = False
    
    try:
        with io.BytesIO(jar_bytes) as jar_bio, zipfile.ZipFile(jar_bio, 'r') as jar_zip:
            pom_props_path = None
            # Search for pom.properties. The exact path includes groupId and artifactId.
            # We need to find a file that matches the pattern.
            for member_name in jar_zip.namelist():
                if member_name.startswith('META-INF/maven/') and member_name.endswith('/pom.properties'):
                    # Example path: META-INF/maven/commons-io/commons-io/pom.properties
                    pom_props_path = member_name
                    logger.debug(f"Found potential pom.properties at: {pom_props_path} in {library_filename}")
                    break # Take the first one found
            
            if pom_props_path:
                pom_props_content_raw = jar_zip.read(pom_props_path)
                try:
                    pom_props_content = pom_props_content_raw.decode('utf-8')
                except UnicodeDecodeError:
                    logger.warning(f"pom.properties in {library_filename} is not valid UTF-8, trying 'latin-1'")
                    pom_props_content = pom_props_content_raw.decode('latin-1', errors='replace')

                for line in pom_props_content.splitlines():
                    line = line.strip()
                    if line.startswith('#') or '=' not in line: # Skip comments and lines without '='
                        continue
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # We are interested in 'groupId', 'artifactId', 'version'
                    if key in props_gav:
                        props_gav[key] = value
                        found_pom_properties = True
                
                if found_pom_properties:
                    logger.info(f"Extracted from pom.properties in {library_filename}: {props_gav}")
                    return props_gav
                else:
                    logger.debug(f"pom.properties found in {library_filename} but did not contain GAV keys.")
                    return None
            else:
                logger.debug(f"pom.properties not found in {library_filename}")
                return None
    except zipfile.BadZipFile:
        logger.error(f"Bad ZIP file encountered when parsing pom.properties for {library_filename}", exc_info=True)
    except Exception as e:
        logger.error(f"Error parsing pom.properties from {library_filename}: {e}", exc_info=True)
    return None

def _parse_manifest_mf_from_jar_bytes(jar_bytes: bytes, library_filename: str = "unknown.jar") -> dict | None:
    """
    Finds and parses META-INF/MANIFEST.MF from JAR file bytes.
    Handles continuation lines.
    Returns a dictionary of manifest attributes or None if not found/error.
    """
    manifest_attributes = {}
    try:
        with io.BytesIO(jar_bytes) as jar_bio, zipfile.ZipFile(jar_bio, 'r') as jar_zip:
            manifest_path = 'META-INF/MANIFEST.MF'
            if manifest_path in jar_zip.namelist():
                logger.debug(f"Found MANIFEST.MF in {library_filename}")
                
                # Read manifest content
                # Manifests are typically 7-bit ASCII or UTF-8.
                # Using UTF-8 with error replacement is generally safe.
                manifest_content_raw = jar_zip.read(manifest_path)
                manifest_content_lines = []
                try:
                    manifest_content_lines = manifest_content_raw.decode('utf-8').splitlines()
                except UnicodeDecodeError:
                    logger.warning(f"MANIFEST.MF in {library_filename} is not valid UTF-8, trying 'latin-1'")
                    manifest_content_lines = manifest_content_raw.decode('latin-1', errors='replace').splitlines()

                current_key = None
                current_value_lines = [] # Store lines for a value before joining

                for line_number, line in enumerate(manifest_content_lines):
                    # End of manifest or empty line might signify end of a value
                    if not line.strip() and current_key:
                        if current_value_lines:
                            manifest_attributes[current_key] = "".join(current_value_lines)
                            logger.debug(f"  Parsed MANIFEST attribute: {current_key} = {manifest_attributes[current_key]}")
                        current_key = None
                        current_value_lines = []
                        continue

                    if line.startswith(' '):  # Continuation of the previous line
                        if current_key:
                            current_value_lines.append(line[1:]) # Remove the leading space
                        else:
                            logger.warning(f"MANIFEST.MF in {library_filename} has continuation line without prior key (line {line_number + 1}): {line}")
                    else:  # New key-value pair
                        if current_key and current_value_lines: # Store previous complete attribute
                            manifest_attributes[current_key] = "".join(current_value_lines)
                            logger.debug(f"  Parsed MANIFEST attribute: {current_key} = {manifest_attributes[current_key]}")
                        
                        if ':' in line:
                            key_part, value_part = line.split(':', 1)
                            current_key = key_part.strip()
                            current_value_lines = [value_part.strip()]
                        else:
                            logger.warning(f"Skipping malformed line in MANIFEST.MF for {library_filename} (line {line_number + 1}): {line}")
                            current_key = None
                            current_value_lines = []
                
                # Store the last attribute after the loop
                if current_key and current_value_lines:
                    manifest_attributes[current_key] = "".join(current_value_lines)
                    logger.debug(f"  Parsed MANIFEST attribute (last): {current_key} = {manifest_attributes[current_key]}")
                
                if manifest_attributes:
                    logger.info(f"Successfully extracted {len(manifest_attributes)} attributes from MANIFEST.MF for {library_filename}")
                    return manifest_attributes
                else:
                    logger.info(f"MANIFEST.MF found in {library_filename} but no attributes parsed (or empty).")
                    return None # Or {} if you prefer an empty dict for "found but empty"
            else:
                logger.debug(f"MANIFEST.MF not found in {library_filename}")
                return None # Manifest file itself not found
    except zipfile.BadZipFile:
        logger.error(f"Bad ZIP file encountered when parsing MANIFEST.MF for {library_filename}", exc_info=True)
    except Exception as e:
        logger.error(f"Error parsing MANIFEST.MF from {library_filename}: {e}", exc_info=True)
    return None

def _update_gav_from_manifest_data(gav_info: dict, manifest_data: dict | None):
    """
    Updates GAV info with data from MANIFEST.MF, preferring existing reliable values.
    Modifies gav_info in place.
    Records 'MANIFEST.MF' in gav_info['source'] if data is used.
    """
    if not manifest_data:
        return

    updated_by_manifest = False

    # Version: Implementation-Version or Bundle-Version
    if gav_info.get('version') is None:
        if manifest_data.get('Implementation-Version'):
            gav_info['version'] = manifest_data.get('Implementation-Version')
            updated_by_manifest = True
        elif manifest_data.get('Bundle-Version'):
            gav_info['version'] = manifest_data.get('Bundle-Version')
            updated_by_manifest = True

    # ArtifactId: Implementation-Title or Bundle-Name or parts of Automatic-Module-Name/Bundle-SymbolicName
    if gav_info.get('artifactId') is None:
        if manifest_data.get('Implementation-Title'):
            gav_info['artifactId'] = manifest_data.get('Implementation-Title')
            updated_by_manifest = True
        elif manifest_data.get('Bundle-Name'):
            gav_info['artifactId'] = manifest_data.get('Bundle-Name')
            updated_by_manifest = True
        # Add more heuristics for artifactId from Automatic-Module-Name or Bundle-SymbolicName if needed,
        # e.g., if they contain the groupId as a prefix.
        # Example: if BSN is "group.artifact" and group is known, artifact can be inferred.

    # GroupId: Implementation-Vendor-Id, or parts of Automatic-Module-Name/Bundle-SymbolicName
    if gav_info.get('groupId') is None:
        bsn = manifest_data.get('Bundle-SymbolicName') # e.g., org.apache.commons.io or sometimes just org.apache.commons
        amn = manifest_data.get('Automatic-Module-Name') # e.g., org.apache.commons.io

        # Heuristic: If artifactId is known and BSN/AMN is like "groupId.artifactId"
        current_artifact_id = gav_info.get('artifactId')
        candidate_group_id = None

        for name_field in [bsn, amn]: # Prefer BSN then AMN for this logic
            if name_field:
                if current_artifact_id and name_field.endswith(f".{current_artifact_id}"):
                    candidate_group_id = name_field[:-len(f".{current_artifact_id}")]
                    break
                elif '.' in name_field: # If it looks like a group id itself
                    candidate_group_id = name_field 
                    # (Could be group.artifact if artifactId is not yet known from here, or just group)
                    # This part is tricky. A simple assignment if it contains '.' might be a start.
                    # If artifactId is NOT known, BSN/AMN is often 'groupId.artifactId'. We'd need to split.
                    # For now, this is a simplification. A more robust solution might involve
                    # checking if the part after the last dot matches a known artifactId pattern if artifactId is unknown.
                    if not current_artifact_id and '.' in name_field:
                         last_dot = name_field.rfind('.')
                         gav_info['groupId'] = name_field[:last_dot]
                         gav_info['artifactId'] = name_field[last_dot+1:]
                         updated_by_manifest = True
                         break # Found both from one field
                    elif current_artifact_id: # AMN/BSN might just be the group if artifactId is already known
                        gav_info['groupId'] = name_field
                        updated_by_manifest = True
                        break


        if gav_info.get('groupId') is None and candidate_group_id:
            gav_info['groupId'] = candidate_group_id
            updated_by_manifest = True
        
        if gav_info.get('groupId') is None and manifest_data.get('Implementation-Vendor-Id'):
            gav_info['groupId'] = manifest_data.get('Implementation-Vendor-Id')
            updated_by_manifest = True
        elif gav_info.get('groupId') is None and manifest_data.get('Implementation-Vendor'): # Less common but possible
            gav_info['groupId'] = manifest_data.get('Implementation-Vendor')
            updated_by_manifest = True

    if updated_by_manifest and 'MANIFEST.MF' not in gav_info['source']:
        gav_info['source'].append('MANIFEST.MF')
    logger.debug(f"GAV after attempting manifest update: {gav_info}")

def extract_gav_from_jar_bytes(jar_library_bytes: bytes, library_filename: str = "unknown.jar") -> dict:
    """
    Orchestrates GAV extraction from a library JAR's bytes using various methods.
    Prioritizes pom.xml, then pom.properties, then MANIFEST.MF.
    Returns a dictionary like {'groupId': ..., 'artifactId': ..., 'version': ..., 'source': [...]}
    """
    gav_info = {'groupId': None, 'artifactId': None, 'version': None, 'source': []}
    logger.info(f"Attempting GAV extraction for: {library_filename}")

    # 1. Try pom.xml (most authoritative)
    pom_xml_data = _parse_pom_xml_from_jar_bytes(jar_library_bytes, library_filename)
    if pom_xml_data:
        logger.debug(f"Data from pom.xml for {library_filename}: {pom_xml_data}")
        if pom_xml_data.get('groupId'): gav_info['groupId'] = pom_xml_data['groupId']
        if pom_xml_data.get('artifactId'): gav_info['artifactId'] = pom_xml_data['artifactId']
        if pom_xml_data.get('version'): gav_info['version'] = pom_xml_data['version']
        if any(pom_xml_data.values()): # If pom.xml provided any GAV part
            gav_info['source'].append('pom.xml')

    # 2. Try pom.properties (authoritative, fills gaps from pom.xml or confirms)
    # Only proceed if not all GAV components are found, or to confirm/override if pom.xml was minimal
    # For simplicity, we'll fill if missing. A more complex logic could compare/validate.
    if not all([gav_info['groupId'], gav_info['artifactId'], gav_info['version']]):
        pom_props_data = _parse_pom_properties_from_jar_bytes(jar_library_bytes, library_filename)
        if pom_props_data:
            logger.debug(f"Data from pom.properties for {library_filename}: {pom_props_data}")
            updated_by_props = False
            if gav_info['groupId'] is None and pom_props_data.get('groupId'):
                gav_info['groupId'] = pom_props_data['groupId']; updated_by_props = True
            if gav_info['artifactId'] is None and pom_props_data.get('artifactId'):
                gav_info['artifactId'] = pom_props_data['artifactId']; updated_by_props = True
            if gav_info['version'] is None and pom_props_data.get('version'):
                gav_info['version'] = pom_props_data['version']; updated_by_props = True
            
            if updated_by_props and 'pom.properties' not in gav_info['source']:
                gav_info['source'].append('pom.properties')

    # 3. Try MANIFEST.MF (less authoritative, fills remaining gaps)
    if not all([gav_info['groupId'], gav_info['artifactId'], gav_info['version']]):
        manifest_mf_data = _parse_manifest_mf_from_jar_bytes(jar_library_bytes, library_filename)
        if manifest_mf_data:
            logger.debug(f"Data from MANIFEST.MF for {library_filename}: {manifest_mf_data}")
            _update_gav_from_manifest_data(gav_info, manifest_mf_data) # This will append 'MANIFEST.MF' to source if used

    # 4. (Future) Filename heuristics - could be added here if GAV is still incomplete.
    # if not all([gav_info['groupId'], gav_info['artifactId'], gav_info['version']]):
    #    logger.debug(f"Attempting filename heuristic for {library_filename}")
    #    # Call a _parse_gav_from_filename(library_filename) function
    #    # and update gav_info, append 'filename' to source.

    if not gav_info['source']: # If no source contributed, mark as unknown
        gav_info['source'].append('unknown')
        
    logger.info(f"Consolidated GAV for {library_filename}: {gav_info}")
    return gav_info


# --- Archive Scanning Functions ---

def analyze_war_file(file_path: str) -> list[dict]:
    """Analyzes a WAR file to find GAV for libraries in WEB-INF/lib."""
    identified_libraries_gav = []
    logger.info(f"Analyzing WAR file: {file_path}")
    try:
        with zipfile.ZipFile(file_path, 'r') as war_file:
            for member_info in war_file.infolist(): # Use infolist to get ZipInfo objects
                member_name = member_info.filename
                # Check if it's a JAR in WEB-INF/lib and not a directory
                if member_name.startswith('WEB-INF/lib/') and \
                   member_name.lower().endswith('.jar') and \
                   not member_info.is_dir(): # member_info.is_dir() requires Python 3.8+
                                            # if using older, check if filename ends with '/'

                    logger.debug(f"Found library in WAR: {member_name}")
                    try:
                        library_bytes = war_file.read(member_name)
                        # Pass the actual filename of the library for better logging inside extract_gav
                        gav = extract_gav_from_jar_bytes(library_bytes, member_name.split('/')[-1])

                        # Only add if we have at least some GAV info
                        if any(val for key, val in gav.items() if key in ['groupId', 'artifactId', 'version']):
                            gav['filename_in_archive'] = member_name # Store its path in the WAR
                            identified_libraries_gav.append(gav)
                        else:
                            logger.warning(f"Could not extract significant GAV for {member_name} in {file_path}")
                    except Exception as e_inner:
                        logger.error(f"Failed to process library {member_name} in {file_path}: {e_inner}", exc_info=True)
    except zipfile.BadZipFile:
        logger.error(f"Bad ZIP file (WAR): {file_path}")
    except Exception as e:
        logger.error(f"Error processing WAR file {file_path}: {e}", exc_info=True)
    return identified_libraries_gav


def analyze_spring_boot_jar(file_path: str) -> list[dict]:
    """Analyzes a Spring Boot executable JAR for libraries in BOOT-INF/lib."""
    identified_libraries_gav = []
    logger.info(f"Analyzing Spring Boot JAR: {file_path}")
    try:
        with zipfile.ZipFile(file_path, 'r') as main_jar_file:
            logger.debug(f"Listing all members in Spring Boot JAR {file_path}:")
            for member_info in main_jar_file.infolist():
                member_name = member_info.filename
                logger.debug(f"  Checking Spring Boot JAR member: '{member_name}'") # More verbose logging

                is_directory = False
                if hasattr(member_info, 'is_dir'):  # Python 3.8+
                    is_directory = member_info.is_dir()
                else:  # Fallback
                    is_directory = member_name.endswith('/')

                if is_directory:
                    logger.debug(f"    '{member_name}' is a directory, skipping.")
                    continue

                if member_name.startswith('BOOT-INF/lib/') and member_name.lower().endswith('.jar'):
                    logger.info(f"    >>> Found potential library in Spring Boot JAR: {member_name}")
                    try:
                        library_bytes = main_jar_file.read(member_name)
                        gav = extract_gav_from_jar_bytes(library_bytes, member_name.split('/')[-1])

                        if any(val for key, val in gav.items() if key in ['groupId', 'artifactId', 'version']):
                            gav['filename_in_archive'] = member_name
                            identified_libraries_gav.append(gav)
                            logger.debug(f"      Successfully extracted GAV: {gav}")
                        else:
                            logger.warning(f"      Could not extract significant GAV for {member_name} in {file_path}")
                    except Exception as e_inner:
                        logger.error(f"      Failed to process library {member_name} in {file_path}: {e_inner}", exc_info=True)
    except zipfile.BadZipFile:
        logger.error(f"Bad ZIP file (Spring Boot JAR): {file_path}")
    except Exception as e:
        logger.error(f"Error processing Spring Boot JAR file {file_path}: {e}", exc_info=True)

    logger.info(f"Finished analyzing {file_path}. Found {len(identified_libraries_gav)} libraries with GAV.")
    return identified_libraries_gav

# Placeholder for EAR analysis - more complex
def analyze_ear_file(file_path: str) -> list[dict]:
    logger.warning("EAR file analysis is not fully implemented yet.")
    # Needs to:
    # 1. Open EAR as zip.
    # 2. Look for JARs at root.
    # 3. Look for WARs at root, then call analyze_war_file on them.
    # 4. Potentially parse META-INF/application.xml for <library-directory>.
    # 5. Collect all GAVs.
    return []