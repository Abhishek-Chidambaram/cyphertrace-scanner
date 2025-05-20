# Dockerfile for VULN_SCANNER (Updated for Kubernetes CronJob)

# 1. Use an official Python runtime as a parent image
FROM python:3.10-slim-buster

# 2. Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV APP_USER_HOME=/home/appuser
ENV XDG_DATA_HOME=${APP_USER_HOME}/.local/share
ENV APP_FINAL_DATA_DIR=${XDG_DATA_HOME}/SimpleVulnScanner

# 3. Install gosu and create user/group & directories
RUN apt-get update && apt-get install -y --no-install-recommends gosu && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system appgroup && \
    useradd --system --no-log-init --gid appgroup --home-dir ${APP_USER_HOME} --create-home appuser && \
    mkdir -p ${APP_FINAL_DATA_DIR} && \
    chown -R appuser:appgroup ${APP_USER_HOME} && \
    chmod -R 750 ${APP_USER_HOME}

# 4. Set the working directory in the container
WORKDIR /app

# 5. Copy requirements.txt and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 6. Copy your application code, configuration, and scripts
COPY --chown=appuser:appgroup main.py .
COPY --chown=appuser:appgroup config.yaml .
COPY --chown=appuser:appgroup vuln_scanner ./vuln_scanner
# New: Copy the runner script
COPY --chown=appuser:appgroup scan_runner.sh . 
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
# New: Make runner script executable
RUN chmod +x /app/scan_runner.sh 

# 7. Define the entrypoint for the container.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# 8. Default command for the entrypoint script.
# The entrypoint.sh now calls scan_runner.sh, so CMD here is less critical
# unless entrypoint.sh was designed to pass these to scan_runner.sh.
# For simplicity, scan_runner.sh is self-contained for now.
# CMD ["--help"] # This would be passed to scan_runner.sh if it accepted args

# 9. Document the volume
VOLUME ${APP_FINAL_DATA_DIR}