#!/usr/bin/env python3
import click
import subprocess
import os
import pathlib

# --- Configuration ---
CYPHERTRACE_IMAGE_NAME = "abhishek56/cyphertrace:latest"
DB_VOLUME_NAME = "vuln_scanner_db_data"
DB_INTERNAL_MOUNT_PATH = "/home/appuser/.local/share/SimpleVulnScanner"
INPUT_INTERNAL_MOUNT_PATH = "/inputs"
OUTPUT_INTERNAL_MOUNT_PATH = "/outputs"
NVD_API_KEY_ENV_VAR = "NVD_API_KEY"

# --- Helper Functions ---
def _build_docker_run_command(
    image_name: str,
    db_volume_name: str,
    db_internal_path: str,
    additional_volume_mounts: list = None, # For input/output paths
    scanner_main_py_args: list = None      # Arguments for your main.py
):
    """
    Builds the docker run command.
    Volume mounts for input/output are passed via additional_volume_mounts.
    Arguments for main.py are passed via scanner_main_py_args.
    """
    command = [
        "docker", "run", "--rm",
        "-v", f"{db_volume_name}:{db_internal_path}" # DB volume
    ]

    # Add NVD API Key if set
    nvd_api_key = os.environ.get(NVD_API_KEY_ENV_VAR)
    if nvd_api_key:
        command.extend(["-e", f"{NVD_API_KEY_ENV_VAR}={nvd_api_key}"])

    # Add any additional volume mounts (for input/output files)
    if additional_volume_mounts:
        command.extend(additional_volume_mounts)

    command.append(image_name) # Docker image name

    # Add arguments for the scanner's main.py script
    if scanner_main_py_args:
        command.extend(scanner_main_py_args)
        
    return command

def _run_docker_command(command: list, command_description: str):
    """Runs a Docker command using subprocess and prints output."""
    click.echo(f"Running: {command_description}")
    click.echo(f"Executing Docker command: {' '.join(command)}") # For debugging
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
    Ensure Docker is running and the 'cyphertrace:latest' image is built.
    The database volume 'vuln_scanner_db_data' will be used.
    """
    pass

@cli.command("update-db")
@click.option("--max-pages", type=int, help="Limit NVD pages during database update.")
def update_db(max_pages):
    """Fetches/Updates the NVD and other vulnerability databases."""
    scanner_args_for_main_py = ["--update-db"]
    if max_pages is not None:
        scanner_args_for_main_py.extend(["--max-pages", str(max_pages)])

    command = _build_docker_run_command(
        image_name=CYPHERTRACE_IMAGE_NAME,
        db_volume_name=DB_VOLUME_NAME,
        db_internal_path=DB_INTERNAL_MOUNT_PATH,
        scanner_main_py_args=scanner_args_for_main_py
        # No additional_volume_mounts needed for update-db
    )
    _run_docker_command(command, "Database update")

@cli.command("scan-file")
@click.argument("input_file_host_path", type=click.Path(exists=True, dir_okay=False, resolve_path=True))
@click.option("--format", "output_format", type=click.Choice(['text', 'json', 'html'], case_sensitive=False), default='text', show_default=True, help="Output format.")
@click.option("--output-file", "output_file_host_path", type=click.Path(resolve_path=True, dir_okay=False), help="Path on your computer to save the report output.")
@click.option("--severity-threshold", type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'], case_sensitive=False), help="Minimum severity to report.")
def scan_file(input_file_host_path, output_format, output_file_host_path, severity_threshold):
    """Scans a specified input file (e.g., requirements.txt, package-lock.json)."""
    
    input_file_on_host = pathlib.Path(input_file_host_path)
    host_input_dir_for_mount = str(input_file_on_host.parent)
    container_input_file_arg_for_main_py = f"{INPUT_INTERNAL_MOUNT_PATH}/{input_file_on_host.name}"

    scanner_args_for_main_py = [container_input_file_arg_for_main_py]
    
    additional_volume_mounts_for_docker = [
        "-v", f"{host_input_dir_for_mount}:{INPUT_INTERNAL_MOUNT_PATH}"
    ]

    if output_format:
        scanner_args_for_main_py.extend(["--format", output_format])

    if output_file_host_path:
        output_file_on_host = pathlib.Path(output_file_host_path)
        host_output_dir_for_mount = str(output_file_on_host.parent)
        container_output_file_arg_for_main_py = f"{OUTPUT_INTERNAL_MOUNT_PATH}/{output_file_on_host.name}"
        
        scanner_args_for_main_py.extend(["--output-file", container_output_file_arg_for_main_py])
        additional_volume_mounts_for_docker.extend(["-v", f"{host_output_dir_for_mount}:{OUTPUT_INTERNAL_MOUNT_PATH}"])
        
        output_file_on_host.parent.mkdir(parents=True, exist_ok=True)

    if severity_threshold:
        scanner_args_for_main_py.extend(["--severity-threshold", severity_threshold.upper()])

    command = _build_docker_run_command(
        image_name=CYPHERTRACE_IMAGE_NAME,
        db_volume_name=DB_VOLUME_NAME,
        db_internal_path=DB_INTERNAL_MOUNT_PATH,
        additional_volume_mounts=additional_volume_mounts_for_docker,
        scanner_main_py_args=scanner_args_for_main_py
    )
    _run_docker_command(command, f"File scan for {input_file_on_host.name}")

@cli.command("scan-image")
@click.argument("image_tar_host_path", type=click.Path(exists=True, dir_okay=False, resolve_path=True))
@click.option("--format", "output_format", type=click.Choice(['text', 'json', 'html'], case_sensitive=False), default='text', show_default=True, help="Output format.")
@click.option("--output-file", "output_file_host_path", type=click.Path(resolve_path=True, dir_okay=False), help="Path on your computer to save the report output.")
@click.option("--severity-threshold", type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'], case_sensitive=False), help="Minimum severity to report.")
def scan_image(image_tar_host_path, output_format, output_file_host_path, severity_threshold):
    """Scans a container image tarball ('docker save' output)."""

    image_tar_on_host = pathlib.Path(image_tar_host_path)
    host_input_dir_for_mount = str(image_tar_on_host.parent)
    container_image_tar_arg_for_main_py = f"{INPUT_INTERNAL_MOUNT_PATH}/{image_tar_on_host.name}"

    scanner_args_for_main_py = ["--image-tar", container_image_tar_arg_for_main_py]
    
    additional_volume_mounts_for_docker = [
        "-v", f"{host_input_dir_for_mount}:{INPUT_INTERNAL_MOUNT_PATH}"
    ]

    if output_format:
        scanner_args_for_main_py.extend(["--format", output_format])

    if output_file_host_path:
        output_file_on_host = pathlib.Path(output_file_host_path)
        host_output_dir_for_mount = str(output_file_on_host.parent)
        container_output_file_arg_for_main_py = f"{OUTPUT_INTERNAL_MOUNT_PATH}/{output_file_on_host.name}"
        
        scanner_args_for_main_py.extend(["--output-file", container_output_file_arg_for_main_py])
        additional_volume_mounts_for_docker.extend(["-v", f"{host_output_dir_for_mount}:{OUTPUT_INTERNAL_MOUNT_PATH}"])
        
        output_file_on_host.parent.mkdir(parents=True, exist_ok=True)

    if severity_threshold:
        scanner_args_for_main_py.extend(["--severity-threshold", severity_threshold.upper()])

    command = _build_docker_run_command(
        image_name=CYPHERTRACE_IMAGE_NAME,
        db_volume_name=DB_VOLUME_NAME,
        db_internal_path=DB_INTERNAL_MOUNT_PATH,
        additional_volume_mounts=additional_volume_mounts_for_docker,
        scanner_main_py_args=scanner_args_for_main_py
    )
    _run_docker_command(command, f"Image tar scan for {image_tar_on_host.name}")

if __name__ == "__main__":
    cli()
