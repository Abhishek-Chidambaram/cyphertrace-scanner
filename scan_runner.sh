#!/bin/sh
# scan_runner.sh - Script to be run by the Kubernetes CronJob

set -e # Exit immediately if a command exits with a non-zero status

echo "--- [$(date)] Starting CypherTrace Kubernetes Job ---"

# Step 1: Update the vulnerability database
# The entrypoint.sh in the Docker image handles permissions for the DB volume.
echo "[$(date)] Updating vulnerability database..."
python /app/main.py --update-db --max-pages 10 # Adjust max_pages as needed
echo "[$(date)] Database update complete."

# Step 2: Perform scans
# In a real scenario, you'd get targets from a ConfigMap mounted as a file,
# clone Git repos, or iterate through a list of image names.

# For this example, we'll scan a dummy requirements.txt created on the fly
# and save the report to a path that will be on a persistent volume.
DUMMY_REQ_FILE="/workspace/dummy_requirements.txt"
REPORT_OUTPUT_DIR="/reports" # This path will be mounted from a PVC
REPORT_FILE="${REPORT_OUTPUT_DIR}/scan_report_$(date +%Y-%m-%d_%H-%M-%S).html"

echo "[$(date)] Preparing dummy scan target..."
mkdir -p /workspace # Ensure workspace exists (though emptyDir usually handles this)
echo "requests==2.25.0" > "${DUMMY_REQ_FILE}"
echo "pyyaml==5.3" >> "${DUMMY_REQ_FILE}"

echo "[$(date)] Scanning dummy requirements file: ${DUMMY_REQ_FILE}"
python /app/main.py "${DUMMY_REQ_FILE}" \
  --format html \
  --output-file "${REPORT_FILE}" \
  --severity-threshold MEDIUM
echo "[$(date)] Dummy requirements scan complete. Report at ${REPORT_FILE}"

# TODO: Add logic here to process/upload reports from /reports if needed
# For example, copy to a shared location, upload to S3, etc.

# TODO: Add logic here to push metrics to Prometheus Pushgateway if desired

echo "--- [$(date)] CypherTrace Kubernetes Job Finished ---"