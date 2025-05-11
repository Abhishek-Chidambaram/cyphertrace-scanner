# Dockerfile for VULN_SCANNER

# 1. Use an official Python runtime as a parent image
FROM python:3.10-slim-buster

# 2. Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV APP_USER_HOME=/home/appuser
ENV XDG_DATA_HOME=${APP_USER_HOME}/.local/share
# Where platformdirs will target
ENV APP_FINAL_DATA_DIR=${XDG_DATA_HOME}/SimpleVulnScanner 

# 3. Install gosu and create user/group & directories
RUN apt-get update && apt-get install -y --no-install-recommends gosu && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system appgroup && \
    useradd --system --no-log-init --gid appgroup --home-dir ${APP_USER_HOME} --create-home appuser && \
    mkdir -p ${APP_FINAL_DATA_DIR} && \
    # Ownership of APP_FINAL_DATA_DIR will be set by entrypoint.sh on the actual volume.
    # Chown APP_USER_HOME for general home directory sanity within the image layer.
    chown -R appuser:appgroup ${APP_USER_HOME} && \
    chmod -R 750 ${APP_USER_HOME}

# 4. Set the working directory in the container
WORKDIR /app

# 5. Copy requirements.txt and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 6. Copy your application code, configuration, and entrypoint script
# Application files will be run as appuser, so their ownership in the image isn't
# as critical as the entrypoint script itself if it needs to perform root actions.
# However, good practice to set ownership.
COPY --chown=appuser:appgroup main.py .
COPY --chown=appuser:appgroup config.yaml .
COPY --chown=appuser:appgroup vuln_scanner ./vuln_scanner

# Copy entrypoint script and make it executable
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# 7. Define the entrypoint for the container.
# This script will run as root by default.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# 8. Default command for the entrypoint script (passed as "$@" to entrypoint.sh)
# These arguments will be passed to 'python main.py' by the entrypoint script.
CMD ["--help"]

# 9. Document the volume
# This directory is created and its ownership managed by the entrypoint script
# on the actual mounted volume.
VOLUME ${APP_FINAL_DATA_DIR}