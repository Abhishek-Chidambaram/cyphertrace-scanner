#!/bin/sh
# entrypoint.sh (Updated to conditionally run main.py or scan_runner.sh)

set -e # Exit immediately if a command exits with a non-zero status.

# Directory for the database (from Dockerfile ENV)
APP_DATA_PATH_ON_VOLUME="${APP_FINAL_DATA_DIR}"
# Directory for temporary workspace (from Kubernetes CronJob volumeMount or local CLI mounts)
WORKSPACE_PATH="/workspace"
# Directory for reports (from Kubernetes CronJob volumeMount or local CLI mounts)
REPORTS_PATH="/reports" # This is the /outputs path from the CLI wrapper

echo "Entrypoint: Running as $(id)"
# echo "Entrypoint: Target data directory for database: ${APP_DATA_PATH_ON_VOLUME}"
# echo "Entrypoint: Workspace path: ${WORKSPACE_PATH}"
# echo "Entrypoint: Reports path: ${REPORTS_PATH}"

# Ensure the main data directory (which is the volume mount point for the DB)
# exists and is owned by appuser.
# echo "Entrypoint: Ensuring ownership of ${APP_DATA_PATH_ON_VOLUME} for appuser:appgroup..."
mkdir -p "${APP_DATA_PATH_ON_VOLUME}"
chown -R appuser:appgroup "${APP_DATA_PATH_ON_VOLUME}"
# echo "Entrypoint: DB directory ownership set."

# Ensure the workspace directory (used by scan_runner.sh or if main.py needs it)
# echo "Entrypoint: Ensuring ownership of ${WORKSPACE_PATH} for appuser:appgroup..."
mkdir -p "${WORKSPACE_PATH}"
chown -R appuser:appgroup "${WORKSPACE_PATH}"
# echo "Entrypoint: Workspace directory ownership set."

# Ensure the reports directory (used by scan_runner.sh and main.py via CLI output mapping)
# echo "Entrypoint: Ensuring ownership of ${REPORTS_PATH} for appuser:appgroup..."
mkdir -p "${REPORTS_PATH}" # This corresponds to /outputs in the CLI wrapper
chown -R appuser:appgroup "${REPORTS_PATH}"
# echo "Entrypoint: Reports directory ownership set."

# "$@" contains the arguments passed to 'docker run <image_name> args...'
# or the CMD from the Dockerfile if no args were passed to 'docker run'.

if [ "$#" -gt 0 ]; then
    # If arguments are provided to 'docker run' (e.g., by cyphertrace.py),
    # assume they are for main.py and execute main.py directly.
    echo "Entrypoint: Arguments provided. Switching to user 'appuser' to run: python /app/main.py $@"
    exec gosu appuser python /app/main.py "$@"
else
    # If no arguments are provided to 'docker run' (e.g., when K8s CronJob runs the container with default CMD,
    # or if user just runs 'docker run <image>'),
    # then execute the scan_runner.sh script.
    echo "Entrypoint: No arguments provided. Switching to user 'appuser' to run: /app/scan_runner.sh"
    exec gosu appuser /app/scan_runner.sh
fi