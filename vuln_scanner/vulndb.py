# vuln_scanner/vulndb.py
import sqlite3
import json
from pathlib import Path
import os  # <-- Added OS import
from platformdirs import user_data_path  # <-- Added platformdirs import
from collections import defaultdict
from datetime import datetime, timezone, timedelta
# Make sure models are imported if needed for type hints (Vulnerability needed here)
from .models import Vulnerability, Package

# --- Define App Name and Author for platformdirs ---
APP_NAME = "SimpleVulnScanner"
APP_AUTHOR = "ScannerAuthor" # You can change ScannerAuthor if you like

# --- Get the cross-platform user data directory path ---
# Ensures the directory structure exists
try:
    data_dir = user_data_path(appname=APP_NAME, appauthor=APP_AUTHOR, ensure_exists=True)
    DB_FILE = data_dir / "vuln_db.sqlite"
    print(f"DEBUG DB: Database path set to: {DB_FILE}") # Log the path
except Exception as e:
    print(f"FATAL: Could not determine or create user data directory: {e}")
    print("       Please check permissions or manually create the directory.")
     # Use a fallback local path? Or exit? Let's fallback for now.
    print("       Falling back to using local 'vuln_db_local.sqlite'")
    DB_FILE = Path("./vuln_db_local.sqlite").resolve()


_connection = None # Module-level cache for connection

def initialize_database():
    """Creates the database tables if they don't exist. Called by get_db_connection."""
    # Connection should already be established when this is called
    if _connection is None:
         print("Error: initialize_database called without an active connection.")
         return # Should not happen if called correctly from get_db_connection

    cursor = _connection.cursor()
    try:
        print("Initializing database tables if not exist...")
        # --- Vulnerabilities Table (NVD) ---
        print("Checking/Creating table 'vulnerabilities'...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY, description TEXT, cvss_v3_score REAL,
                cvss_v3_vector TEXT, configurations TEXT, last_modified TEXT
            )
        """)
        # --- OS Vulnerabilities Table ---
        print("Checking/Creating table 'os_vulnerabilities'...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS os_vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT, vuln_id TEXT NOT NULL,
                os_distro TEXT NOT NULL, os_release_codename TEXT NOT NULL,
                package_name TEXT NOT NULL, fixed_version TEXT NOT NULL,
                status TEXT, severity TEXT,
                UNIQUE(vuln_id, os_distro, os_release_codename, package_name)
            )
        """)
        # --- Indexes for OS Vulns ---
        print("Checking/Creating indexes for 'os_vulnerabilities'...")
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_os_vuln_lookup
            ON os_vulnerabilities (os_distro, os_release_codename, package_name);
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_os_vuln_id
            ON os_vulnerabilities (vuln_id);
        """)

        # --- NEW Table for Data Source Timestamps ---
        print("Checking/Creating table 'data_source_status'...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS data_source_status (
                source_name TEXT PRIMARY KEY,     -- e.g., 'nvd', 'debian_bullseye'
                last_updated_utc TEXT NOT NULL  -- ISO 8601 timestamp string
            )
        """)
        # --- END NEW Table ---

        # --- Commit all schema changes ---
        _connection.commit()
        print("Database tables initialized successfully.")
    except sqlite3.Error as e:
        print(f"Error initializing database table in {DB_FILE}: {e}")
        # Decide if we should rollback or raise
        # _connection.rollback() # Rollback might be needed if one CREATE fails
        raise # Re-raise to signal initialization failure

def get_db_connection():
    """Establishes and returns a SQLite connection. Ensures tables are initialized."""
    global _connection
    if _connection is None:
        try:
            # DB_FILE is now defined using platformdirs path above
            # Directory creation handled by platformdirs or fallback above
            print(f"Attempting to connect to database: {DB_FILE}")
            _connection = sqlite3.connect(DB_FILE, check_same_thread=False)
            _connection.row_factory = sqlite3.Row
            print(f"Database connection established to {DB_FILE}")
            # Ensure tables are created *after* connection is successful
            initialize_database()
        except sqlite3.Error as e:
            print(f"Error connecting to database {DB_FILE}: {e}")
            _connection = None # Ensure connection is None if connect fails
            raise # Re-raise the exception
        except Exception as e_init: # Catch potential init errors too
             print(f"Error during database initialization: {e_init}")
             if _connection: _connection.close(); _connection = None
             raise # Re-raise
    return _connection

def close_db_connection():
    """Closes the database connection if open."""
    global _connection
    if _connection is not None:
        _connection.close()
        _connection = None
        print("Database connection closed.")

def insert_vulnerability(cursor, cve_detail: dict):
    # ... (Keep exact implementation from before) ...
    sql = """INSERT OR REPLACE INTO vulnerabilities (cve_id, description, cvss_v3_score, cvss_v3_vector, configurations, last_modified) VALUES (?, ?, ?, ?, ?, ?)"""
    try: cursor.execute(sql, ( cve_detail.get("cve_id"), cve_detail.get("description"), cve_detail.get("cvss_v3_score"), cve_detail.get("cvss_v3_vector"), cve_detail.get("configurations"), cve_detail.get("last_modified") ))
    except sqlite3.Error as e: print(f"DB error inserting {cve_detail.get('cve_id')}: {e}"); raise
    except KeyError as e: print(f"Missing key inserting {cve_detail.get('cve_id')}: {e}"); raise

def insert_os_vulnerability(cursor, vuln_detail: dict):
    # ... (Keep exact implementation from before) ...
    sql = """INSERT OR IGNORE INTO os_vulnerabilities (vuln_id, os_distro, os_release_codename, package_name, fixed_version, status, severity) VALUES (?, ?, ?, ?, ?, ?, ?)"""
    try: cursor.execute(sql, ( vuln_detail.get("vuln_id"), vuln_detail.get("os_distro", "").lower(), vuln_detail.get("os_release_codename", "").lower(), vuln_detail.get("package_name"), vuln_detail.get("fixed_version"), vuln_detail.get("status"), vuln_detail.get("severity") ))
    except sqlite3.Error as e: print(f"DB error inserting OS vuln {vuln_detail.get('vuln_id')}/{vuln_detail.get('package_name')}: {e}")
    except KeyError as e: print(f"Missing key inserting OS vuln {vuln_detail.get('vuln_id')}/{vuln_detail.get('package_name')}: {e}")

def load_os_vulnerabilities(distro: str, release_codename: str) -> dict:
    # ... (Keep exact implementation from before) ...
    print(f"Loading OS vulnerability data for {distro} {release_codename}...")
    conn = get_db_connection(); cursor = conn.cursor(); vulns_by_package = defaultdict(list)
    try:
        cursor.execute("SELECT package_name, vuln_id, fixed_version, status, severity FROM os_vulnerabilities WHERE os_distro = ? AND os_release_codename = ?", (distro.lower(), release_codename.lower()))
        rows = cursor.fetchall(); print(f"Fetched {len(rows)} OS records for {distro} {release_codename}.")
        for row in rows: vulns_by_package[row["package_name"]].append(( row["vuln_id"], row["fixed_version"], row["status"], row["severity"] ))
        print(f"Structured OS vuln data for {len(vulns_by_package)} packages.")
        return dict(vulns_by_package)
    except sqlite3.Error as e: print(f"Error loading OS vulns: {e}"); return {}

def load_vulnerabilities() -> list[dict]:
    # ... (Keep exact implementation from before - loading minimal NVD data) ...
    print("Loading minimal NVD data (ID, configurations) for matching..."); conn = get_db_connection(); cursor = conn.cursor(); vuln_data_list = []
    try:
        cursor.execute("SELECT cve_id, configurations FROM vulnerabilities"); rows = cursor.fetchall()
        print(f"Fetched {len(rows)} minimal NVD entries from the database.")
        for row in rows: vuln_data_list.append({ "cve_id": row["cve_id"], "configurations": row["configurations"] })
        print(f"Prepared {len(vuln_data_list)} entries for scanner.")
    except sqlite3.Error as e: print(f"Error loading minimal NVD data: {e}")
    return vuln_data_list

def get_full_vulnerability_details(cve_id: str) -> Vulnerability | None:
    # ... (Keep exact implementation from before - loading full NVD details) ...
    conn = get_db_connection(); cursor = conn.cursor()
    try:
        cursor.execute("SELECT cve_id, description, cvss_v3_score, cvss_v3_vector, configurations FROM vulnerabilities WHERE cve_id = ?", (cve_id,))
        row = cursor.fetchone()
        if row: return Vulnerability( cve_id=row["cve_id"], description=row["description"], cvss_v3_score=row["cvss_v3_score"], cvss_v3_vector=row["cvss_v3_vector"], configurations=row["configurations"] )
        else: print(f"Warning: Could not find full details for {cve_id} in NVD table."); return None # Updated warning slightly
    except sqlite3.Error as e: print(f"Error fetching full NVD details for {cve_id}: {e}"); return None

def get_data_source_last_updated(source_name: str) -> datetime | None:
    """
    Retrieves the last update timestamp for a given data source.
    Returns a datetime object (UTC) or None if not found or error.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT last_updated_utc FROM data_source_status WHERE source_name = ?", (source_name,))
        row = cursor.fetchone()
        if row and row["last_updated_utc"]:
            return datetime.fromisoformat(row["last_updated_utc"])
    except sqlite3.Error as e:
        print(f"Error getting last_updated_utc for {source_name}: {e}")
    except ValueError as e: # fromisoformat can raise ValueError
        print(f"Error parsing stored timestamp for {source_name}: {e}")
    return None

def update_data_source_timestamp(source_name: str):
    """Updates the last_updated_utc timestamp for a data source to now."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now_utc_iso = datetime.now(timezone.utc).isoformat()
    try:
        cursor.execute("""
            INSERT OR REPLACE INTO data_source_status (source_name, last_updated_utc)
            VALUES (?, ?)
        """, (source_name, now_utc_iso))
        conn.commit()
        print(f"Timestamp updated for data source: {source_name} to {now_utc_iso}")
    except sqlite3.Error as e:
        print(f"Error updating timestamp for {source_name}: {e}")

# --- Removed get_cve_details (old debug function) ---

# --- Removed initialize_database() call from module level ---
# The get_db_connection function now handles calling initialize_database