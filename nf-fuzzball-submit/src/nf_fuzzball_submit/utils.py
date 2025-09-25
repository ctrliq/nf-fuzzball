"""Utility functions for nf-fuzzball-submit."""

import logging
import pathlib
import sys

import urllib3
import yaml

from .models import LocalFile

logger = logging.getLogger(__name__)


def str_presenter(dumper: yaml.Dumper, data: str) -> yaml.Node:
    """Represent strings with newlines as block literals in YAML.

    Args:
        dumper: The YAML dumper instance.
        data: The string data to represent.

    Returns:
        A YAML node representing the string.
    """
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


# Configure YAML to use block literals for multiline strings
yaml.add_representer(str, str_presenter)


def die(error: str) -> None:
    """Log an error message and exit the program.

    Args:
        error: The error message to log before exiting.
    """
    logger.fatal(error)
    sys.exit(1)


def get_canonical_api_url(url: str, http_client: urllib3.PoolManager) -> str:
    """Returns full API url including base path.

    Args:
        url: Base URL to test for API versioning.
        http_client: HTTP client for making requests.

    Returns:
        The full API URL with the correct base path.

    Raises:
        ValueError: If unable to determine the API base path.
    """
    base_url = url.rstrip("/")
    if not url.startswith("http"):
        base_url = f"https://{url.rstrip('/')}"
    candidates = ["/v2", "/v3", "/v4", "/v5", "/v6"]
    if base_url[-3:] in candidates:
        return base_url

    for path in candidates:
        test_url = f"{base_url}{path}"

        try:
            response = http_client.request(
                "GET",
                f"{test_url}/version",
                timeout=30,
            )
            if response.status < 400:
                return test_url
        except Exception:  # noqa: S112
            continue
    raise ValueError("Unable to sniff API base path")


def find_and_import_local_files(
    nextflow_cmd: list[str],
    remote_prefix: str = "",
) -> tuple[list[str], list[LocalFile]]:
    """Find local files in the Nextflow command and prepare them for upload to Fuzzball.

    Args:
        nextflow_cmd: The Nextflow command as a list of arguments.
        remote_prefix: Optional prefix for the remote file names.

    Returns:
        A tuple containing:
        - A modified command list with local file paths replaced by their remote equivalents.
        - A list of LocalFile objects representing the local files found.

    Raises:
        IOError: If a local file cannot be read.
        Exception: If there is an error processing a local file.
    """
    mangled_command = []
    local_files = []
    for arg in nextflow_cmd:
        if "," in arg:
            # Handle comma-separated lists of files
            cs_str = []
            for sub_arg in arg.split(","):
                p = pathlib.Path(sub_arg.strip())
                if p.is_file() and p.exists():
                    local_file = LocalFile(p, remote_prefix)
                    local_files.append(local_file)
                    cs_str.append(str(local_file.remote_path))
                    logger.debug(
                        f"Found local file to include in workflow: {local_file.local_path} -> {local_file.remote_path}",
                    )
                else:
                    cs_str.append(sub_arg.strip())
            mangled_command.append(",".join(cs_str))
            continue
        p = pathlib.Path(arg.strip())
        if p.is_file() and p.exists():
            local_file = LocalFile(p, remote_prefix)
            local_files.append(local_file)
            mangled_command.append(str(local_file.remote_path))
            logger.debug(
                f"Found local file to include in workflow: {local_file.local_path} -> {local_file.remote_path}",
            )
        else:
            mangled_command.append(arg)
    return mangled_command, local_files
