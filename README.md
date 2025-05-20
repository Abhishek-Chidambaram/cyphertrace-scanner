# CypherTrace 🛡️

**CypherTrace is a versatile vulnerability scanner designed to help you identify security weaknesses in your software dependencies, Java archives, and container images.**

---

## Overview

CypherTrace scans various types of input to find known vulnerabilities by cross-referencing them with multiple vulnerability databases, including OSV (Open Source Vulnerability database) and NVD (National Vulnerability Database). It's designed to be run as a Docker container, with a user-friendly CLI wrapper to simplify its operation.

**Supported Scan Targets:**
* Python `requirements.txt` files
* NPM `package-lock.json` files
* Java Archives (`.jar`, `.war`, `.ear`) for bundled library vulnerabilities
* Container image tarballs (output of `docker save`) for OS package and application dependency vulnerabilities
* Container images directly from a remote registry (e.g., Docker Hub)

**Output Formats:**
* Human-readable text
* JSON
* HTML reports

## ✨ Features

* **Comprehensive Scanning:** Identifies vulnerabilities in application dependencies (Python, NPM, Java), OS packages within container images, and Java archives.
* **Multiple Data Sources:** Leverages OSV and NVD for up-to-date vulnerability information.
* **Persistent Database:** Maintains a local SQLite database for vulnerability data, which can be updated regularly.
* **Flexible Input:** Scans `requirements.txt`, `package-lock.json`, Java archives (`.jar`, `.war`, `.ear`), `*.tar` image files, and remote registry images.
* **Multiple Output Formats:** Generates reports in text, JSON, or user-friendly HTML.
* **Severity Filtering:** Allows users to filter reported vulnerabilities by severity (CRITICAL, HIGH, MEDIUM, LOW, NONE, UNKNOWN).
* **Ignore List:** Supports ignoring specific vulnerability IDs via configuration or CLI.
* **Dockerized:** Ensures consistent runtime environment and easy deployment.
* **User-Friendly CLI:** A simple command-line interface (`cyphertrace.exe` or `python cyphertrace.py`) to manage scans and database updates.
* **Configurable:** Uses a `config.yaml` for default settings.
* **NVD API Key Support:** Can utilize an NVD API key for higher request rates.

##  Prerequisites

* **Docker:** You must have Docker installed and running on your system. Download from [docker.com](https://www.docker.com/products/docker-desktop/).

## 🚀 Installation & Setup

There are two main ways to use CypherTrace: directly via its Docker image or using the provided CLI executable.

**1. Using the Docker Image Directly:**

   The core scanner runs as a Docker container.

   * **Pull the Image:**
        ```bash
        docker pull abhishek56/cyphertrace:latest
        ```

   * **Database Volume:** CypherTrace uses a persistent Docker volume to store its vulnerability database. Docker will create this volume automatically on first use if it doesn't exist. The recommended volume name is `vuln_scanner_db_data`.

**2. Using the Standalone CLI Executable (`cyphertrace.exe` or `cyphertrace`):**

   A standalone executable CLI wrapper is provided for convenience. This executable internally calls the Docker image.

   * **Download the Executable:**
        * Example: "Download the latest `cyphertrace.exe` (for Windows) or `cyphertrace` (for Linux/macOS) from the [GitHub Releases page](https://github.com/Abhishek-Chidambaram/cyphertrace-scanner/releases)." *(You'll need to create releases on your GitHub repo for this link to be valid)*
   * **Ensure Docker is Running:** The executable still requires Docker to be running in the background.
   * **Image Pull:** The first time you run a command with the executable, it will attempt to pull the `abhishek56/cyphertrace:latest` Docker image if it's not already present locally.

## 🛠️ Usage

The primary way to interact with CypherTrace is through its CLI (either the standalone executable or `python cyphertrace.py`).

**General Command Structure:**
```bash
cyphertrace <command> [options] [arguments]

(If not using the standalone executable, replace cyphertrace with python cyphertrace.py)

Database Management
Update Vulnerability Database:
It's recommended to update the database regularly. This fetches NVD data and OS-specific vulnerability data.

cyphertrace update-db

To limit the number of NVD pages fetched during an NVD update:

cyphertrace update-db --max-pages 5

To update specific OS vulnerability data (e.g., for Debian Buster or Alpine v3.18):

cyphertrace update-db --update-os debian=buster
cyphertrace update-db --update-os alpine=v3.18

To fetch details for a specific CVE ID from NVD:

cyphertrace update-db --fetch-cve CVE-2021-44228

Scanning
Scan a File (e.g., requirements.txt, package-lock.json):

cyphertrace scan-file /path/to/your/input_file.txt --format html --output-file /path/to/your/report.html --severity-threshold MEDIUM

<path_to_your/input_file.txt>: Full path to the dependency file on your computer.

--format: Can be text, json, or html. Default is text.

--output-file: Path on your computer where the report will be saved.

--severity-threshold: Filter results to show only vulnerabilities at this level or higher. Options: CRITICAL, HIGH, MEDIUM, LOW, NONE, UNKNOWN.

--ignore: Comma-separated vulnerability IDs to ignore (e.g., CVE-2020-123,GHSA-abc-xyz).

Example:

cyphertrace scan-file ./myproject/requirements.txt --format html --output-file ./myproject/scan_report.html

Scan a Java Archive (e.g., .war, .jar, .ear):
This command scans the specified Java archive for vulnerabilities in its bundled libraries.

cyphertrace scan-java-archive /path/to/your/java_archive.war --format text --output-file /path/to/java_report.txt

<path/to/your/java_archive.war>: Full path to the Java archive file on your computer.

Options for --format, --output-file, --severity-threshold, and --ignore are the same as scan-file.

Example:

cyphertrace scan-java-archive ./myapps/app.jar --format json --output-file ./myapps/app_vulns.json

Scan a Container Image Tarball (.tar file from docker save):
This scans for both OS package vulnerabilities and application dependencies (Python, NPM) within the image layers.

cyphertrace scan-image-tar /path/to/your/image.tar --format json --output-file /path/to/your/image_scan.json

<path_to_your/image.tar>: Full path to the image tarball on your computer.

Options for --format, --output-file, --severity-threshold, and --ignore are the same as scan-file.

Example:

cyphertrace scan-image-tar ./docker_images/my_app_image.tar --format text

Scan a Container Image from a Remote Registry:
This scans an image directly from a registry like Docker Hub.

cyphertrace scan-registry ubuntu:latest --format html --output-file ubuntu_latest_report.html

ubuntu:latest: The full name and tag of the image in the registry.

Options for --format, --output-file, --severity-threshold, and --ignore are the same as scan-file.

NVD API Key (Recommended for Database Updates)
To get higher request rates when updating the NVD database, it's highly recommended to use an NVD API Key.

Request an API key from the NVD website.

Set it as an environment variable before running CypherTrace:

Linux/macOS:

export NVD_API_KEY="YOUR_ACTUAL_NVD_API_KEY_HERE"
cyphertrace update-db

Windows (Command Prompt):

set NVD_API_KEY=YOUR_ACTUAL_NVD_API_KEY_HERE
cyphertrace update-db

Windows (PowerShell):

$env:NVD_API_KEY="YOUR_ACTUAL_NVD_API_KEY_HERE"
cyphertrace update-db

The CLI wrapper will automatically pass this environment variable to the Docker container.

⚙️ Configuration
CypherTrace uses a config.yaml file (located within the Docker image, but its defaults can be overridden by CLI arguments) for some default settings:

format: Default output format (e.g., text).

severity_threshold: Default minimum severity to report (e.g., UNKNOWN).

ignore_vulnerabilities: A list of CVE or GHSA IDs to always ignore in reports (e.g., ["CVE-2020-123", "GHSA-abc-xyz"]).

auto_update_interval_days: How often to automatically try to update vulnerability data sources before a scan (default is 7 days).

nvd_max_pages_auto_update: Max NVD pages to fetch during an automatic NVD update.

app_manifest_targets_in_image: List of application manifest filenames to search for within container images (e.g., ["requirements.txt", "package-lock.json"]).

You can see the default config.yaml in the project's source code. CLI arguments will always override these defaults.

🗃️ Database Persistence
The vulnerability database (vuln_db.sqlite) is stored in a Docker named volume, typically vuln_scanner_db_data. This ensures that your fetched vulnerability data persists even if the CypherTrace container is removed and re-created. The CLI and Docker commands are set up to use this volume automatically.

🏗️ Building from Source (Optional)
If you want to build the Docker image or the CLI executable yourself:

1. Build the Docker Image:
Clone this repository and navigate to its root directory. Then run:

docker build -t yourusername/cyphertrace:customtag .

(Replace yourusername with your Docker Hub username if you plan to push it, and customtag with your desired tag.)

2. Build the CLI Executable:
Ensure Python, pip, and pyinstaller are installed. Navigate to the directory containing cyphertrace.py (the CLI wrapper script) and run:

pip install click pyinstaller packaging # packaging is used by models.py
pyinstaller --onefile --name cyphertrace cyphertrace.py

The executable will be in the dist/ folder.

📜 License
(You need to choose a license and add it here. Example:)
This project is licensed under the MIT License. Please see the LICENSE file for details.

(Action for you: Choose a license (e.g., MIT, Apache 2.0, GPLv3). Create a LICENSE file in your project root containing the full text of that license. Then update the line above.)E

🤝 Contributing
Contributions are welcome! Please feel free
