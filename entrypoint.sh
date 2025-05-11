#!/bin/sh

# entrypoint.sh

set -e # Exit immediately if a command exits with a non-zero status.

# The directory where platformdirs will try to create the database file.
# This should match the VOLUME instruction in Dockerfile and the -v mount path.
APP_DATA_PATH_ON_VOLUME="${APP_FINAL_DATA_DIR}" # APP_FINAL_DATA_DIR will be set by Dockerfile ENV

echo "Entrypoint: Running as $(id)"
echo "Entrypoint: Target data directory for database: ${APP_DATA_PATH_ON_VOLUME}"

# Ensure the directory (which is the volume mount point) exists and is owned by appuser.
# This step is crucial for named volumes on some Docker setups where volumes are initially root-owned.
echo "Entrypoint: Ensuring ownership of ${APP_DATA_PATH_ON_VOLUME} for appuser:appgroup..."
# The mkdir -p is good practice but platformdirs with ensure_exists=True should also do it.
# The chown is the critical part for the volume.
mkdir -p "${APP_DATA_PATH_ON_VOLUME}"
chown -R appuser:appgroup "${APP_DATA_PATH_ON_VOLUME}"
echo "Entrypoint: Ownership set."

# Execute the main command (passed as arguments to this script) as the 'appuser'
echo "Entrypoint: Switching to user 'appuser' to run: python main.py $@"
exec gosu appuser python main.py "$@"