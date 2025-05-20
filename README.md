CypherTrace 🛡️
CypherTrace is a versatile vulnerability scanner designed to identify security weaknesses in your software dependencies, Java archives, and container images.

Overview
CypherTrace scans various targets and cross-references multiple vulnerability databases, including OSV and NVD.

Supported Scan Targets
Python requirements.txt
NPM package-lock.json
Java archives (.jar, .war, .ear)
Container image tarballs (from docker save)
Images from remote registries (e.g., Docker Hub)
Output Formats
Human-readable text
JSON
HTML reports
✨ Features
Comprehensive scanning: Application dependencies (Python, NPM, Java), OS packages in container images, Java archives
Up-to-date vulnerability data: Leverages OSV & NVD
Persistent database: Local SQLite database, easily updatable
Flexible input: Scan files, Java archives, Docker image tarballs, remote registry images
Severity filtering: (CRITICAL, HIGH, MEDIUM, LOW, NONE, UNKNOWN)
Ignore list: Ignore specific vulnerability IDs via config or CLI
Dockerized: Consistent environment, easy deployment
User-friendly CLI: cyphertrace or python cyphertrace.py
Configurable: config.yaml for defaults
NVD API key support: For higher request rates
Prerequisites
Docker: Required. Download Docker
🚀 Installation & Setup
1. Using Docker Directly
bash
docker pull abhishek56/cyphertrace:latest
A persistent Docker volume is used for the vulnerability database and is created automatically on first use.

2. Using the Standalone CLI
Download the executable:
GitHub Releases
Docker must be running.
First-time use will pull the Docker image if needed.
🛠️ Usage
Use the CLI as either the standalone executable (cyphertrace) or via Python (python cyphertrace.py):

General Syntax
bash
cyphertrace <command> [options] [arguments]
# or
python cyphertrace.py <command> [options] [arguments]
Database Management
bash
cyphertrace update-db
cyphertrace update-db --max-pages 5
cyphertrace update-db --update-os debian=buster
cyphertrace update-db --update-os alpine=v3.18
cyphertrace update-db --fetch-cve CVE-2021-44228
Scanning
Scan a dependencies file:

bash
cyphertrace scan-file /path/to/requirements.txt --format html --output-file report.html --severity-threshold MEDIUM
Scan a Java archive:

bash
cyphertrace scan-java-archive /path/to/app.jar --format json --output-file app_vulns.json
Scan a Docker image tarball:

bash
cyphertrace scan-image-tar /path/to/image.tar --format text
Scan a remote registry image:

bash
cyphertrace scan-registry ubuntu:latest --format html --output-file ubuntu_latest_report.html
Common options:
--format (text/json/html), --output-file <path>, --severity-threshold <level>, --ignore <ID1,ID2,...>

NVD API Key (Recommended)
Request an API key from NVD and set it before updating the database:

Linux/macOS:

bash
export NVD_API_KEY="YOUR_NVD_API_KEY"
cyphertrace update-db
Windows (CMD):

bash
set NVD_API_KEY=YOUR_NVD_API_KEY
cyphertrace update-db
Windows (PowerShell):

PowerShell
$env:NVD_API_KEY="YOUR_NVD_API_KEY"
cyphertrace update-db
⚙️ Configuration
config.yaml allows customizing:

format: default output format
severity_threshold: minimum severity to report
ignore_vulnerabilities: list of IDs to ignore
auto_update_interval_days: auto-update frequency
nvd_max_pages_auto_update: max NVD pages during update
app_manifest_targets_in_image: manifests to search in container images
CLI arguments always override config.

🗃️ Database Persistence
The vulnerability database (vuln_db.sqlite) is stored in a Docker named volume (default: vuln_scanner_db_data) so data persists between runs.

🏗️ Building from Source (Optional)
Build Docker image:

bash
git clone https://github.com/Abhishek-Chidambaram/cyphertrace-scanner.git
cd cyphertrace-scanner
docker build -t yourusername/cyphertrace:customtag .
Build CLI executable:

bash
pip install click pyinstaller packaging
pyinstaller --onefile --name cyphertrace cyphertrace.py
# Result in dist/
📜 License
This project is licensed under the MIT License. See the LICENSE file for details.

🤝 Contributing
Contributions are welcome!
Submit a Pull Request or open an Issue.

📫 Contact
For questions or support, please open an Issue or contact the maintainer.

