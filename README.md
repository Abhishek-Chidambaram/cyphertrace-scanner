# CypherTrace 🛡️

**CypherTrace is a versatile vulnerability scanner designed to help you identify security weaknesses in your software dependencies and container images.**

</p>
-->

---

## Overview

CypherTrace scans various types of input to find known vulnerabilities by cross-referencing them with multiple vulnerability databases, including OSV (Open Source Vulnerability database) and NVD (National Vulnerability Database). It's designed to be run as a Docker container, with a user-friendly CLI wrapper to simplify its operation.

**Supported Scan Targets:**
* Python `requirements.txt` files
* NPM `package-lock.json` files
* Container image tarballs (output of `docker save`)

**Output Formats:**
* Human-readable text
* JSON
* HTML reports

## ✨ Features

* **Comprehensive Scanning:** Identifies vulnerabilities in application dependencies and OS packages within container images.
* **Multiple Data Sources:** Leverages OSV and NVD for up-to-date vulnerability information.
* **Persistent Database:** Maintains a local SQLite database for vulnerability data, which can be updated regularly.
* **Flexible Input:** Scans `requirements.txt`, `package-lock.json`, and `*.tar` image files.
* **Multiple Output Formats:** Generates reports in text, JSON, or user-friendly HTML.
* **Severity Filtering:** Allows users to filter reported vulnerabilities by severity (CRITICAL, HIGH, MEDIUM, LOW, NONE, UNKNOWN).
* **Ignore List:** Supports ignoring specific vulnerability IDs via configuration.
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
        docker pull yourdockerhubusername/cyphertrace:latest
        ```
        *(Replace `yourdockerhubusername` with your actual Docker Hub username where the image is hosted. For example: `abhishek56/cyphertrace:latest`)*

   * **Database Volume:** CypherTrace uses a persistent Docker volume to store its vulnerability database. Docker will create this volume automatically on first use if it doesn't exist. The recommended volume name is `vuln_scanner_db_data`.

**2. Using the Standalone CLI Executable (`cyphertrace.exe` or `cyphertrace`):**

   A standalone executable CLI wrapper is provided for convenience. This executable internally calls the Docker image.

   * **Download the Executable:**
        * *(You will need to specify where users can download this. For example, from the "Releases" page of your GitHub repository.)*
        * Example: "Download the latest `cyphertrace.exe` (for Windows) or `cyphertrace` (for Linux/macOS) from the [GitHub Releases page](https://github.com/Abhishek-Chidambaram/cyphertrace-scanner/releases)."
   * **Ensure Docker is Running:** The executable still requires Docker to be running in the background.
   * **Image Pull:** The first time you run a command with the executable, it will attempt to pull the `yourdockerhubusername/cyphertrace:latest` Docker image if it's not already present locally.

## 🛠️ Usage

The primary way to interact with CypherTrace is through its CLI (either the standalone executable or `python cyphertrace.py`).

**General Command Structure:**
```bash
cyphertrace <command> [options] [arguments]
```
*(If not using the standalone executable, replace `cyphertrace` with `python cyphertrace.py`)*

---
### Database Management

**Update Vulnerability Database:**
It's recommended to update the database regularly.
```bash
cyphertrace update-db
```
To limit the number of NVD pages fetched during an update (useful for quicker updates or when rate-limited):
```bash
cyphertrace update-db --max-pages 5
```

---
### Scanning

**Scan a File (e.g., `requirements.txt`, `package-lock.json`):**
```bash
cyphertrace scan-file /path/to/your/input_file.txt --format html --output-file /path/to/your/report.html --severity-threshold MEDIUM
```
* `<path_to_your/input_file.txt>`: Full path to the dependency file on your computer.
* `--format`: Can be `text`, `json`, or `html`. Default is `text`.
* `--output-file`: Path on your computer where the report will be saved (especially useful for `json` and `html`).
* `--severity-threshold`: Filter results to show only vulnerabilities at this level or higher. Options: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`, `UNKNOWN`.

**Example:**
```bash
cyphertrace scan-file ./myproject/requirements.txt --format html --output-file ./myproject/scan_report.html
```

**Scan a Container Image Tarball (`.tar` file from `docker save`):**
```bash
cyphertrace scan-image /path/to/your/image.tar --format json --output-file /path/to/your/image_scan.json
```
* `<path_to_your/image.tar>`: Full path to the image tarball on your computer.

**Example:**
```bash
cyphertrace scan-image ./docker_images/my_app_image.tar --format text
```

---
### NVD API Key (Recommended for Database Updates)

To get higher request rates when updating the NVD database, it's highly recommended to use an NVD API Key.
1.  Request an API key from the [NVD website](https://nvd.nist.gov/developers/request-an-api-key).
2.  Set it as an environment variable **before** running CypherTrace:

    * **Linux/macOS:**
        ```bash
        export NVD_API_KEY="YOUR_ACTUAL_NVD_API_KEY_HERE"
        cyphertrace update-db
        ```
    * **Windows (Command Prompt):**
        ```bash
        set NVD_API_KEY=YOUR_ACTUAL_NVD_API_KEY_HERE
        cyphertrace update-db
        ```
    * **Windows (PowerShell):**
        ```bash
        $env:NVD_API_KEY="YOUR_ACTUAL_NVD_API_KEY_HERE"
        cyphertrace update-db
        ```
The CLI wrapper will automatically pass this environment variable to the Docker container.

## ⚙️ Configuration

CypherTrace uses a `config.yaml` file (located within the Docker image, but its defaults can be overridden by CLI arguments) for some default settings:
* `format`: Default output format (e.g., `text`).
* `severity_threshold`: Default minimum severity to report (e.g., `UNKNOWN`).
* `ignore_vulnerabilities`: A list of CVE or GHSA IDs to always ignore in reports.
* `auto_update_interval_days`: How often to automatically try to update vulnerability data sources before a scan (default is 7 days).
* `nvd_max_pages_auto_update`: Max NVD pages to fetch during an automatic update.

You can see the default `config.yaml` in the project's source code. CLI arguments will always override these defaults.

## 🗃️ Database Persistence

The vulnerability database (`vuln_db.sqlite`) is stored in a Docker named volume, typically `vuln_scanner_db_data`. This ensures that your fetched vulnerability data persists even if the CypherTrace container is removed and re-created. The CLI and Docker commands are set up to use this volume automatically.

## 🏗️ Building from Source (Optional)

If you want to build the Docker image or the CLI executable yourself:

**1. Build the Docker Image:**
   Clone this repository and navigate to its root directory. Then run:
   ```bash
   docker build -t yourusername/cyphertrace:customtag .
   ```

**2. Build the CLI Executable:**
   Ensure Python, `pip`, and `pyinstaller` are installed. Navigate to the directory containing `cyphertrace.py` (the CLI wrapper script) and run:
   ```bash
   pip install click pyinstaller
   pyinstaller --onefile --name cyphertrace cyphertrace.py
   ```
   The executable will be in the `dist/` folder.

## 📜 License

This project is licensed under the **[YOUR CHOSEN LICENSE HERE]**. Please see the `LICENSE` file for details.

*(**Action for you:** Choose a license (e.g., MIT, Apache 2.0, GPLv3). Create a `LICENSE` file in your project root containing the full text of that license. Then update the line above.)*

**Example if you choose MIT:**
This project is licensed under the **MIT License**. Please see the `LICENSE` file for details.

## 🤝 Contributing (Optional)

*(If you are open to contributions, add guidelines here. For example:*
Contributions are welcome! Please feel free to submit a Pull Request or open an Issue.
*)*

## 🙏 Acknowledgements (Optional)

*(If you used other open-source libraries or tools that you'd like to acknowledge specifically, or if you had help, you can add that here.)*

---

*This README was generated for CypherTrace.*
