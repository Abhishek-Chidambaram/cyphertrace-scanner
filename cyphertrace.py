#!/usr/bin/env python3
import click
import subprocess
import os
import pathlib
from vuln_scanner import java_analyser

# --- Configuration ---
# Ensure this points to your Docker Hub image (or the image name you use)
CYPHERTRACE_IMAGE_NAME = "abhishek56/cyphertrace:latest"
DB_VOLUME_NAME = "vuln_scanner_db_data"
DB_INTERNAL_MOUNT_PATH = "/home/appuser/.local/share/SimpleVulnScanner"
INPUT_INTERNAL_MOUNT_PATH = "/inputs"  # For scan-file and scan-image (tar)
OUTPUT_INTERNAL_MOUNT_PATH = "/outputs" # For reports
NVD_API_KEY_ENV_VAR = "NVD_API_KEY"

# --- Helper Functions ---
def _build_docker_run_command(
    image_name: str,
    db_volume_name: str,
    db_internal_path: str,
    additional_volume_mounts: list = None,
    scanner_main_py_args: list = None
):
    """Builds the docker run command."""
    command = [
        "docker", "run", "--rm",
        "-v", f"{db_volume_name}:{db_internal_path}"
    ]
    nvd_api_key = os.environ.get(NVD_API_KEY_ENV_VAR)
    if nvd_api_key:
        command.extend(["-e", f"{NVD_API_KEY_ENV_VAR}={nvd_api_key}"])
    if additional_volume_mounts:
        command.extend(additional_volume_mounts)
    command.append(image_name)
    if scanner_main_py_args:
        command.extend(scanner_main_py_args)
    return command

def _run_docker_command(command: list, command_description: str):
    """Runs a Docker command and streams its output."""
    click.echo(f"Running: {command_description}")
    click.echo(f"Executing Docker command: {' '.join(command)}")
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
        if process.stdout:
            for line in process.stdout:
                click.echo(line, nl=False)
        process.wait()
        if process.returncode != 0:
            click.secho(f"\nError: Docker command for '{command_description}' failed with exit code {process.returncode}", fg="red")
        else:
            click.secho(f"\n'{command_description}' completed successfully.", fg="green")
    except FileNotFoundError:
        click.secho("Error: Docker command not found. Is Docker installed and in your PATH?", fg="red")
    except Exception as e:
        click.secho(f"An unexpected error occurred while running Docker command for '{command_description}': {e}", fg="red")

# --- CLI Definition ---
@click.group(context_settings=dict(help_option_names=['-h', '--help']))
def cli():
    """
    CypherTrace: A CLI wrapper for the Dockerized Vulnerability Scanner.
    Ensure Docker is running and the image (e.g., 'abhishek56/cyphertrace:latest') is built or pullable.
    The database volume 'vuln_scanner_db_data' will be used.
    """
    pass

@cli.command("update-db")
@click.option("--max-pages", type=int, help="Limit NVD pages during NVD database update.")
@click.option("--fetch-cve", type=str, metavar='CVE_ID', help="Fetch specific CVE ID (NVD).")
@click.option("--update-os", type=str, metavar='DISTRO=RELEASE', help="Update OS vulnerability data (e.g., debian=buster, alpine=v3.18).")
def update_db(max_pages, fetch_cve, update_os):
    """Fetches/Updates the vulnerability databases (NVD, OS-specific)."""
    scanner_args_for_main_py = []
    if fetch_cve:
        scanner_args_for_main_py.extend(["--fetch-cve", fetch_cve])
    elif update_os:
        scanner_args_for_main_py.extend(["--update-os", update_os])
    elif max_pages is not None: # Only add --update-db if other specific updates aren't chosen
        scanner_args_for_main_py.extend(["--update-db", "--max-pages", str(max_pages)])
    else:
        scanner_args_for_main_py.append("--update-db")


    command = _build_docker_run_command(
        image_name=CYPHERTRACE_IMAGE_NAME,
        db_volume_name=DB_VOLUME_NAME,
        db_internal_path=DB_INTERNAL_MOUNT_PATH,
        scanner_main_py_args=scanner_args_for_main_py
    )
    _run_docker_command(command, "Database update operations")

@cli.command("scan-file")
@click.argument("input_file_host_path", type=click.Path(exists=True, dir_okay=False, resolve_path=True))
@click.option("--format", "output_format", type=click.Choice(['text', 'json', 'html'], case_sensitive=False), default='text', show_default=True, help="Output format.")
@click.option("--output-file", "output_file_host_path", type=click.Path(resolve_path=True, dir_okay=False), help="Path on your computer to save the report output.")
@click.option("--severity-threshold", type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'], case_sensitive=False), help="Minimum severity to report.")
@click.option("--ignore", type=str, help="Comma-separated vulnerability IDs to ignore.")
def scan_file(input_file_host_path, output_format, output_file_host_path, severity_threshold, ignore):
    """Scans a specified local file (e.g., requirements.txt, package-lock.json)."""
    input_file_on_host = pathlib.Path(input_file_host_path)
    host_input_dir_for_mount = str(input_file_on_host.parent)
    container_input_file_arg_for_main_py = f"{INPUT_INTERNAL_MOUNT_PATH}/{input_file_on_host.name}"

    scanner_args_for_main_py = [container_input_file_arg_for_main_py]
    additional_volume_mounts_for_docker = ["-v", f"{host_input_dir_for_mount}:{INPUT_INTERNAL_MOUNT_PATH}"]

    if output_format: scanner_args_for_main_py.extend(["--format", output_format])
    if output_file_host_path:
        output_file_on_host = pathlib.Path(output_file_host_path)
        host_output_dir_for_mount = str(output_file_on_host.parent)
        container_output_file_arg_for_main_py = f"{OUTPUT_INTERNAL_MOUNT_PATH}/{output_file_on_host.name}"
        scanner_args_for_main_py.extend(["--output-file", container_output_file_arg_for_main_py])
        additional_volume_mounts_for_docker.extend(["-v", f"{host_output_dir_for_mount}:{OUTPUT_INTERNAL_MOUNT_PATH}"])
        output_file_on_host.parent.mkdir(parents=True, exist_ok=True)
    if severity_threshold: scanner_args_for_main_py.extend(["--severity-threshold", severity_threshold.upper()])
    if ignore: scanner_args_for_main_py.extend(["--ignore", ignore])

    command = _build_docker_run_command(
        image_name=CYPHERTRACE_IMAGE_NAME,
        db_volume_name=DB_VOLUME_NAME,
        db_internal_path=DB_INTERNAL_MOUNT_PATH,
        additional_volume_mounts=additional_volume_mounts_for_docker,
        scanner_main_py_args=scanner_args_for_main_py
    )
    _run_docker_command(command, f"File scan for {input_file_on_host.name}")

@cli.command("scan-image-tar") # Renamed for clarity from scan-image
@click.argument("image_tar_host_path", type=click.Path(exists=True, dir_okay=False, resolve_path=True))
@click.option("--format", "output_format", type=click.Choice(['text', 'json', 'html'], case_sensitive=False), default='text', show_default=True, help="Output format.")
@click.option("--output-file", "output_file_host_path", type=click.Path(resolve_path=True, dir_okay=False), help="Path on your computer to save the report output.")
@click.option("--severity-threshold", type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'], case_sensitive=False), help="Minimum severity to report.")
@click.option("--ignore", type=str, help="Comma-separated vulnerability IDs to ignore.")
def scan_image_tar(image_tar_host_path, output_format, output_file_host_path, severity_threshold, ignore):
    """Scans a local container image tarball ('docker save' output)."""
    image_tar_on_host = pathlib.Path(image_tar_host_path)
    host_input_dir_for_mount = str(image_tar_on_host.parent)
    container_image_tar_arg_for_main_py = f"{INPUT_INTERNAL_MOUNT_PATH}/{image_tar_on_host.name}"

    scanner_args_for_main_py = ["--image-tar", container_image_tar_arg_for_main_py]
    additional_volume_mounts_for_docker = ["-v", f"{host_input_dir_for_mount}:{INPUT_INTERNAL_MOUNT_PATH}"]

    if output_format: scanner_args_for_main_py.extend(["--format", output_format])
    if output_file_host_path:
        output_file_on_host = pathlib.Path(output_file_host_path)
        host_output_dir_for_mount = str(output_file_on_host.parent)
        container_output_file_arg_for_main_py = f"{OUTPUT_INTERNAL_MOUNT_PATH}/{output_file_on_host.name}"
        scanner_args_for_main_py.extend(["--output-file", container_output_file_arg_for_main_py])
        additional_volume_mounts_for_docker.extend(["-v", f"{host_output_dir_for_mount}:{OUTPUT_INTERNAL_MOUNT_PATH}"])
        output_file_on_host.parent.mkdir(parents=True, exist_ok=True)
    if severity_threshold: scanner_args_for_main_py.extend(["--severity-threshold", severity_threshold.upper()])
    if ignore: scanner_args_for_main_py.extend(["--ignore", ignore])

    command = _build_docker_run_command(
        image_name=CYPHERTRACE_IMAGE_NAME,
        db_volume_name=DB_VOLUME_NAME,
        db_internal_path=DB_INTERNAL_MOUNT_PATH,
        additional_volume_mounts=additional_volume_mounts_for_docker,
        scanner_main_py_args=scanner_args_for_main_py
    )
    _run_docker_command(command, f"Image tar scan for {image_tar_on_host.name}")

# --- NEW CLI COMMAND FOR REGISTRY SCAN ---
@cli.command("scan-registry")
@click.argument("image_name_tag", type=str) # e.g., "ubuntu:latest" or "python:3.10-slim"
@click.option("--format", "output_format", type=click.Choice(['text', 'json', 'html'], case_sensitive=False), default='text', show_default=True, help="Output format.")
@click.option("--output-file", "output_file_host_path", type=click.Path(resolve_path=True, dir_okay=False), help="Path on your computer to save the report output.")
@click.option("--severity-threshold", type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'], case_sensitive=False), help="Minimum severity to report.")
@click.option("--ignore", type=str, help="Comma-separated vulnerability IDs to ignore.")
def scan_registry(image_name_tag, output_format, output_file_host_path, severity_threshold, ignore):
    """Scans a container image directly from a remote registry (e.g., Docker Hub)."""
    
    scanner_args_for_main_py = ["--registry-image", image_name_tag]
    additional_volume_mounts_for_docker = [] # No input file mount needed for registry scan

    if output_format: scanner_args_for_main_py.extend(["--format", output_format])
    if output_file_host_path:
        output_file_on_host = pathlib.Path(output_file_host_path)
        host_output_dir_for_mount = str(output_file_on_host.parent)
        container_output_file_arg_for_main_py = f"{OUTPUT_INTERNAL_MOUNT_PATH}/{output_file_on_host.name}"
        
        scanner_args_for_main_py.extend(["--output-file", container_output_file_arg_for_main_py])
        # Still need to mount the output directory if saving a report file
        additional_volume_mounts_for_docker.extend(["-v", f"{host_output_dir_for_mount}:{OUTPUT_INTERNAL_MOUNT_PATH}"])
        
        output_file_on_host.parent.mkdir(parents=True, exist_ok=True)
    if severity_threshold: scanner_args_for_main_py.extend(["--severity-threshold", severity_threshold.upper()])
    if ignore: scanner_args_for_main_py.extend(["--ignore", ignore])

    command = _build_docker_run_command(
        image_name=CYPHERTRACE_IMAGE_NAME,
        db_volume_name=DB_VOLUME_NAME,
        db_internal_path=DB_INTERNAL_MOUNT_PATH,
        additional_volume_mounts=additional_volume_mounts_for_docker, # Might be empty or just output mount
        scanner_main_py_args=scanner_args_for_main_py
    )
    _run_docker_command(command, f"Registry scan for {image_name_tag}")

@cli.command("scan-java-archive")
@click.argument("input_archive_host_path", type=click.Path(exists=True, dir_okay=False, resolve_path=True))
@click.option("--format", "output_format", type=click.Choice(['text', 'json', 'html'], case_sensitive=False), default='text', show_default=True, help="Output format.")
@click.option("--output-file", "output_file_host_path", type=click.Path(resolve_path=True, dir_okay=False), help="Path on your computer to save the report output.")
@click.option("--severity-threshold", type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'], case_sensitive=False), help="Minimum severity to report.")
@click.option("--ignore", type=str, help="Comma-separated vulnerability IDs to ignore.")
def scan_java_archive_command(input_archive_host_path, output_format, output_file_host_path, severity_threshold, ignore):
    """
    Scans a Java archive (WAR, JAR, EAR) using the Dockerized scanner.
    """
    click.echo(f"Preparing to scan Java archive via Docker: {input_archive_host_path}")

    archive_on_host = pathlib.Path(input_archive_host_path)
    host_input_dir_for_mount = str(archive_on_host.parent)
    container_input_archive_arg_for_main_py = f"{INPUT_INTERNAL_MOUNT_PATH}/{archive_on_host.name}" # e.g., /inputs/myapp.war

    # This is the new argument your Docker's main script will need to handle
    scanner_args_for_main_py = ["--java-archive", container_input_archive_arg_for_main_py]
    
    additional_volume_mounts_for_docker = [
        "-v", f"{host_input_dir_for_mount}:{INPUT_INTERNAL_MOUNT_PATH}:ro" 
    ]

    if output_format:
        scanner_args_for_main_py.extend(["--format", output_format])
    
    if output_file_host_path:
        output_file_on_host = pathlib.Path(output_file_host_path)
        host_output_dir_for_mount = str(output_file_on_host.parent)
        # This will be the path *inside* the container for the output file
        container_output_file_arg_for_main_py = f"{OUTPUT_INTERNAL_MOUNT_PATH}/{output_file_on_host.name}"
        
        scanner_args_for_main_py.extend(["--output-file", container_output_file_arg_for_main_py])
        additional_volume_mounts_for_docker.extend(["-v", f"{host_output_dir_for_mount}:{OUTPUT_INTERNAL_MOUNT_PATH}"])
        output_file_on_host.parent.mkdir(parents=True, exist_ok=True)
        
    if severity_threshold:
        scanner_args_for_main_py.extend(["--severity-threshold", severity_threshold.upper()])
    if ignore:
        scanner_args_for_main_py.extend(["--ignore", ignore])

    command = _build_docker_run_command(
        image_name=CYPHERTRACE_IMAGE_NAME,
        db_volume_name=DB_VOLUME_NAME,
        db_internal_path=DB_INTERNAL_MOUNT_PATH,
        additional_volume_mounts=additional_volume_mounts_for_docker,
        scanner_main_py_args=scanner_args_for_main_py
    )
    _run_docker_command(command, f"Java archive scan for {archive_on_host.name}")

if __name__ == "__main__":
    cli()
