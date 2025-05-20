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
