#! /usr/bin/env python3
"""
Submit a nextflow pipeline to Fuzzball.

Notes:
  - Requires a persistent data volume (mounted at /data) and an ephemeral volume (mounted
    at /scratch).
  - Paths for input, workdir, and output in your nextflow command should be absolute. For
    paths in persistent storate they should include the persistent storage mount point.
  - Any explicitly specified config and/or parameter files will be included in the
    fuzzball job but implicit files (i.e. $HOME/.nextflow/config and ./nextflow.config)
    will not.
  - Config and parameter files should be specified on the commandline directly rather than
    indirectly in a config file.
  - The nextflow command is specified after a `--` separator which follows the options
    for this submission script.
  - Include the fuzzball profile as one of your nextflow profiles.
  - If using a cluster with a self signed certificate the ca cert for the cluster
    needs to be specified to allow TLS certificate verification.
"""

import argparse
import base64
import json
import logging
import os
import pathlib
import shlex
import ssl
import sys
import textwrap
from typing import Dict, Any
import uuid
from urllib.parse import urlparse

import yaml
import urllib3
from urllib3.util import Retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

NAMESPACE_CONTENT = uuid.UUID("71c91ef2-0f9b-47f3-988b-5725d2f67599")
DATA_MOUNT = "/data"
SCRATCH_MOUNT = "/scratch"


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


yaml.add_representer(str, str_presenter)


def die(error: str) -> None:
    """Log an error message and exit the program.

    Args:
        error: The error message to log before exiting.
    """
    logger.fatal(error)
    sys.exit(1)


class LocalFile:
    """
    Represents a local file that should be included in the Nextflow job. The remote name
    is derived from the file content using a UUID based on a hash of the content.
    """

    def __init__(self, local_path: pathlib.Path, remote_prefix: str = "") -> None:
        """
        Initialize a LocalFile instance.
        Args:
            local_path: Path to the local file to be included in the Nextflow job.
            remote_prefix: Optional prefix for the remote file name.
        Raises:
            IOError: If the file cannot be read.
            Exception: If there is an error processing the file.
        """
        self.local_path = local_path
        try:
            with local_path.open("rb") as f:
                file_content = f.read()
                self.content: str = base64.b64encode(file_content).decode("utf-8")
            self.remote_name: str = (
                str(uuid.uuid5(NAMESPACE_CONTENT, self.content)) + f"-{local_path.name}"
            )
            self.remote_path: str = f"{remote_prefix.rstrip('/')}/{self.remote_name}"
        except IOError:
            logger.error(f"Failed to read file {local_path}")
            raise
        except Exception:
            logger.error(f"Error processing file {local_path}")
            raise


def find_and_import_local_files(
    nextflow_cmd: list[str], remote_prefix: str = ""
) -> tuple[list[str], list[LocalFile]]:
    """
    Find local files in the Nextflow command and prepare them for upload to Fuzzball.
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
                        f"Found local file to include in workflow: {local_file.local_path} -> {local_file.remote_path}"
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
                f"Found local file to include in workflow: {local_file.local_path} -> {local_file.remote_path}"
            )
        else:
            mangled_command.append(arg)
    return mangled_command, local_files


class MinimalFuzzballClient:
    """
    A minimal client for interacting with the Fuzzball API.

    Handles authentication, configuration management, and job submission
    for Nextflow pipelines to the Fuzzball cluster.
    """

    def __init__(self, config_path: pathlib.Path, context: str | None = None, ca_cert_file: str | None = None):
        """
        Initialize the Fuzzball client with configuration from a YAML file.

        Args:
            config_path: Path to the fuzzball configuration file
            context: Optional context name to use, defaults to activeContext in config
            ca_cert_file: Path to CA certificate file for SSL verification

        Raises:
            ValueError: If the context is missing or the config is invalid
            IOError: If the config file cannot be read
        """
        self._ca_cert_file = ca_cert_file
        try:
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
        except IOError as e:
            raise IOError(f"Failed to read configuration file {config_path}: {e}")
        except yaml.YAMLError as e:
            raise ValueError(f"Failed to parse configuration file {config_path}: {e}")

        if not isinstance(config, dict):
            raise ValueError("Configuration file has invalid format (not a dictionary)")

        # Get active context
        if context is None:
            context = config.get("activeContext")
        if context is None:
            raise ValueError(
                "No active context specified in config or provided as argument"
            )

        # Initialize minimal config
        self._config = {"activeContext": context, "contexts": []}
        logger.debug(f"Using context: {context}")

        # Find matching context in config
        context_found = False
        for c in config.get("contexts", []):
            if c["name"] == context:
                try:
                    self._host, self._port = c["address"].split(":")
                    self._token = c["auth"]["credentials"]["token"]
                    self._schema = "https"
                    self._base_path = "/v2"  # API version path
                    self._base_url = (
                        f"{self._schema}://{self._host}:{self._port}{self._base_path}"
                    )
                    self._config["contexts"].append(c)
                    context_found = True
                    break
                except (KeyError, ValueError) as e:
                    raise ValueError(
                        f"Invalid context configuration for '{context}': {e}"
                    )

        if not context_found:
            raise ValueError(f"Context '{context}' not found in configuration file")

        # Setup HTTP client with certificate verification
        self._setup_http_client(self._ca_cert_file)

        # Determine version of the Fuzzball API server
        try:
            response = self._request("GET", "/version")
            version_data = json.loads(response.data.decode('utf-8'))
            self._fb_version = ".".join(version_data["version"].split(".")[0:2])
            logger.info(f"Connected to Fuzzball version {self._fb_version} API server")
        except urllib3.exceptions.HTTPError as e:
            raise ValueError(f"Failed to connect to Fuzzball API: {e}")
        except Exception as e:
            raise ValueError(f"Unexpected error occurred: {e}")

    def _setup_http_client(self, ca_cert_file: str | None = None) -> None:
        """Setup urllib3 HTTP client with appropriate SSL configuration.

        Args:
            ca_cert_file: Path to CA certificate file for verification.
        """
        # Create SSL context
        if ca_cert_file:
            # Use custom CA certificate
            ssl_context = ssl.create_default_context()
            ssl_context.load_verify_locations(ca_cert_file)
            self._http = urllib3.PoolManager(
                ssl_context=ssl_context,
                retries=Retry(
                    total=3,
                    backoff_factor=0.1,
                    status_forcelist=[500, 502, 503, 504]
                )
            )
        else:
            # Use default SSL verification
            self._http = urllib3.PoolManager(
                retries=Retry(
                    total=3,
                    backoff_factor=0.1,
                    status_forcelist=[500, 502, 503, 504]
                )
            )

    @property
    def _headers(self) -> Dict[str, str]:
        """Return the headers required for API requests, including the authorization token.

        Returns:
            Dictionary containing the required HTTP headers.
        """
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def _request(
        self, method: str, endpoint: str, data: Dict[str, Any] | None = None
    ) -> urllib3.HTTPResponse:
        """
        Make an API request to the Fuzzball server with retry logic.

        Args:
            method: HTTP method to use (GET, POST, etc.)
            endpoint: API endpoint path
            data: Optional JSON data to send with the request

        Returns:
            HTTPResponse object from urllib3

        Raises:
            urllib3.exceptions.HTTPError: If the request fails
        """
        url = f"{self._base_url}/{endpoint.lstrip('/')}"

        body = None
        if data is not None:
            body = json.dumps(data).encode('utf-8')

        response = self._http.request(
            method.upper(),
            url,
            body=body,
            headers=self._headers,
            timeout=30
        )

        # Check for HTTP errors
        if response.status >= 400:
            raise urllib3.exceptions.HTTPError(f"HTTP {response.status}: {response.reason}")

        return response

    def _encode_config(self) -> str:
        """Return a base64 encoded version of the minimal Fuzzball configuration file
        containing only the active context.

        Returns:
            Base64 encoded config string safe for transport

        Raises:
            ValueError: If encoding fails
        """
        try:
            yaml_str = yaml.dump(self._config)
            return base64.b64encode(yaml_str.encode("utf-8")).decode("utf-8")
        except Exception as e:
            logger.error(f"Failed to encode Fuzzball configuration for transport: {e}")
            raise ValueError("Failed to encode Fuzzball configuration for transport")

    def _encode_ca_cert(self) -> str | None:
        """Return a base64 encoded version of the CA certificate if one was provided.

        Returns:
            Base64 encoded config string safe for transport (or None if no cert was provided)

        Raises:
            IOError: If the certificate file cannot be read.
        """
        if not self._ca_cert_file:
            return None

        try:
            with open(self._ca_cert_file, "rb") as f:
                cert_content = base64.b64encode(f.read()).decode("utf-8")
        except IOError:
            logger.error(f"Failed to read CA certificate file {self._ca_cert_file}")
            raise
        return cert_content

    def create_value_secret(self, secret_name: str, secret_value: str) -> str | None:
        """Create or update a value secret in Fuzzball.

        Args:
            secret_name: The name to give the secret.
            secret_value: The value to store in the secret (base64 encoded config).

        Returns:
            ID of created or existing secret or None

        Raises:
            urllib3.exceptions.HTTPError: If the request to create or update the secret fails.
        """
        # Check if the secret already exists
        try:
            response = self._request("GET", "/secrets")
        except urllib3.exceptions.HTTPError:
            logger.error("Failed to retrieve existing secrets")
            raise
        id = None
        secrets_data = json.loads(response.data.decode('utf-8'))
        for secret in secrets_data["secrets"]:
            if secret["name"] == secret_name:
                id = secret["id"]
                break

        if id is None:
            secret_data = {
                "name": secret_name,
                "scope": "SECRET_SCOPE_USER",
                "value": {"value": secret_value},
            }
            try:
                resp = self._request("PUT", "/secrets", data=secret_data)
            except urllib3.exceptions.HTTPError:
                logger.error("Failed to create secret")
                raise
            resp_data = json.loads(resp.data.decode('utf-8'))
            secret_id = resp_data["id"]
        else:
            secret_id = id
            secret_data = {"value": {"value": secret_value}}
            try:
                self._request("PATCH", f"/secrets/{id}", data=secret_data)
            except urllib3.exceptions.HTTPError:
                logger.error("Failed to update secret")
                raise
        return secret_id

    def submit_nextflow_job(self, args: argparse.Namespace) -> None:
        """Submit a Nextflow job to the Fuzzball cluster.

        Args:
            args: Parsed command line arguments.

        Raises:
            urllib3.exceptions.HTTPError: If any API request fails.
            IOError: If any local files cannot be read or processed.
            Exception: If there is any other (unspecific) error.
        """
        nextflow_cmd_str = shlex.join(args.nextflow_cmd)
        job_name = (
            args.job_name
            if len(args.job_name) > 0
            else str(uuid.uuid5(NAMESPACE_CONTENT, nextflow_cmd_str))
        )
        mounts = {"data": {"location": DATA_MOUNT}, "scratch": {"location": SCRATCH_MOUNT}}
        wd = f"{args.nextflow_work_base}/{job_name}"
        home_base = "home"
        home = f"{wd}/{home_base}"
        files_base = "files"
        files = f"{wd}/{files_base}"
        secret_name = str(uuid.uuid4())
        # we use a v prfix for tag but gradle idiomatically does not use a prefix
        plugin_version = args.nf_fuzzball_version
        plugin_tag = f"v{plugin_version}"

        mangled_nextflow_cmd, config_files = find_and_import_local_files(
            args.nextflow_cmd, files
        )
        mangled_nextflow_cmd_str = shlex.join(mangled_nextflow_cmd)

        # download url for the plugin (until it's in the nextflow plugin registry)
        plugin_uri = f"{args.plugin_base_uri}/{plugin_tag}/nf-fuzzball-{plugin_tag}-stable-{self._fb_version}.zip"
        # check that the URL exists
        if plugin_uri.startswith("http://") or plugin_uri.startswith("https://"):
            try:
                response = self._http.request('HEAD', plugin_uri, timeout=10)
                if response.status >= 400:
                    raise urllib3.exceptions.HTTPError(f"HTTP {response.status}: {response.reason}")
            except urllib3.exceptions.HTTPError:
                raise Exception(f"Failed to access nf-fuzzball plugin for this version of Fuzzball at {plugin_uri}")

        env = [
            f"HOME={home}",
            f"NXF_HOME={home}/.nextflow",
            "NXF_ANSI_CONSOLE=false",
            "NXF_ANSI_SUMMARY=false",
        ]
        volumes = {
            "data": {
                "reference": args.data_volume,
            },
            "scratch": {
                "reference": args.scratch_volume,
                "ingress": [
                    {
                        "source": {
                            "uri": plugin_uri,
                        },
                        "destination": {"uri": "file://nf-fuzzball.zip"},
                    },
                ],
            },
        }
        if args.plugin_base_uri.startswith("s3://"):
            volumes["scratch"]["ingress"][0]["source"]["secret"] = args.s3_secret

        config_secret_name = f"{secret_name}-conf"
        cert_secret_name = f"{secret_name}-cert"

        config_secret_id = self.create_value_secret(config_secret_name, self._encode_config())
        cert_secret_id = None
        if self._ca_cert_file is not None:
            cert_secret_id = self.create_value_secret(cert_secret_name, self._encode_ca_cert())

        nxf_fuzzball_config = base64.b64encode(
            textwrap.dedent(f"""\
        plugins {{ id 'nf-fuzzball@{plugin_version}' }}
        profiles {{
            fuzzball {{
                executor {{
                    '$fuzzball' {{
                        queueSize = {args.queue_size}
                        retry {{ maxAttempt = 3 }}
                    }}
                }}
                process {{
                    executor = 'fuzzball'
                }}
                {"docker { registry = 'quay.io' }" if args.nf_core else ""}
                fuzzball {{
                    cfgFile = '{home}/.config/fuzzball/config.yaml'
                }}
            }}
        }}
        """).encode("utf-8")
        ).decode("utf-8")
        nxf_fuzzball_config_name = str(
            uuid.uuid5(NAMESPACE_CONTENT, nxf_fuzzball_config)
        )

        setup_script = textwrap.dedent(f"""\
        #! /bin/sh
        rm -rf $HOME/.nextflow/plugins/nf-fuzzball-{plugin_version} \\
          && mkdir -p $HOME/.nextflow/plugins/nf-fuzzball-{plugin_version} $HOME/.config/fuzzball \\
          && unzip {SCRATCH_MOUNT}/nf-fuzzball.zip -d $HOME/.nextflow/plugins/nf-fuzzball-{plugin_version} > /dev/null \\
          && echo "$FB_CONFIG" | base64 -d > $HOME/.config/fuzzball/config.yaml \\
          || exit 1

        # Setup CA certificate if provided
        if [ ! -z "$FB_CA_CERT" ]; then
            echo "$FB_CA_CERT" | base64 -d > $HOME/.config/fuzzball/ca.crt || exit 1
        fi

        # there is only a single context in the config file so it's easy to extract the token
        TOKEN="$(awk '/token:/ {{print $2}}' $HOME/.config/fuzzball/config.yaml)"
        # clean up the secrets but don't fail if there is an error
        curl -s -X DELETE "{self._base_url}/secrets/{config_secret_id}" \\
            -H "Authorization: Bearer $TOKEN" \\
            -H "Accept: application/json" &> /dev/null && echo "temp config secret deleted" || echo "temp config secret not deleted"
        """)

        # Add certificate secret cleanup if one was created
        if cert_secret_id is not None:
            setup_script += textwrap.dedent(f"""\
        curl -s -X DELETE "{self._base_url}/secrets/{cert_secret_id}" \\
            -H "Authorization: Bearer $TOKEN" \\
            -H "Accept: application/json" &> /dev/null && echo "temp cert secret deleted" || echo "temp cert secret not deleted"
        """)

        setup_script += textwrap.dedent(f"""\
        mkdir -p {files}
        # copy the config files to the working directory
        cat /tmp/{nxf_fuzzball_config_name} | base64 -d > {files}/{nxf_fuzzball_config_name}.config || exit 1
        """)

        for f in config_files:
            setup_script += (
                f"cat /tmp/{f.remote_name} | base64 -d > {f.remote_path} || exit 1\n"
            )

        nextflow_script = textwrap.dedent(f"""\
        #! /bin/bash
        {mangled_nextflow_cmd_str} -c {files}/{nxf_fuzzball_config_name}.config
        ec=$?
        echo "-- LOG START ---------------------------------------------------------------------------------"
        cat .nextflow.log
        echo "-- LOG END -----------------------------------------------------------------------------------"
        exit $ec
        """)

        workflow = {
            "name": job_name,
            "definition": {
                "version": "v1",
                "files": {
                    nxf_fuzzball_config_name: nxf_fuzzball_config,
                },
                "volumes": volumes,
                "jobs": {
                    "setup": {
                        "image": {"uri": "docker://curlimages/curl"},
                        "files": {
                            f"/tmp/{nxf_fuzzball_config_name}": f"file://{nxf_fuzzball_config_name}"
                        },
                        "mounts": mounts,
                        "cwd": wd,
                        "script": setup_script,
                        "env": env + [f"FB_CONFIG=secret://user/{config_secret_name}"] +
                               ([f"FB_CA_CERT=secret://user/{cert_secret_name}"] if self._ca_cert_file is not None else []),
                        "policy": {"timeout": {"execute": "5m"}},
                        "resource": {"cpu": {"cores": 1}, "memory": {"size": "1GB"}},
                    },
                    "nextflow": {
                        "image": {
                            "uri": f"docker://nextflow/nextflow:{args.nextflow_version}"
                        },
                        "mounts": mounts,
                        "cwd": wd,
                        "script": nextflow_script,
                        "env": env + ([f"FUZZBALL_CA_CERT={home}/.config/fuzzball/ca.crt"] if self._ca_cert_file is not None else []),
                        "policy": {"timeout": {"execute": args.timelimit}},
                        "resource": {"cpu": {"cores": 1}, "memory": {"size": "4GB"}},
                        "requires": ["setup"],
                    },
                },
            },
        }

        # add in the local files
        for f in config_files:
            workflow["definition"]["files"][f.remote_name] = f.content
            if "files" not in workflow["definition"]["jobs"]["setup"]:
                workflow["definition"]["jobs"]["setup"]["files"] = {}
            workflow["definition"]["jobs"]["setup"]["files"][
                f"/tmp/{f.remote_name}"
            ] = f"file://{f.remote_name}"

        if args.verbose or args.dry_run:
            yaml.dump(workflow, sys.stdout, default_flow_style=False)
        if args.dry_run:
            logger.info("Dry run mode: not submitting the workflow.")
            self._request("DELETE", f"/secrets/{config_secret_id}")
            if cert_secret_id:
               self._request("DELETE", f"/secrets/{cert_secret_id}")
            return
        response = self._request("POST", "/workflows", data=workflow)
        response_data = json.loads(response.data.decode("utf-8"))
        logger.info(f"Submitted nextflow workflow {response_data['id']}")


def parse_cli() -> argparse.Namespace:
    """Parse command line arguments for the Nextflow submission script.

    Returns:
        Parsed command line arguments as an argparse.Namespace object.

    Raises:
        SystemExit: If required arguments are missing or invalid.
    """

    parser = argparse.ArgumentParser(
        description=__doc__,
        usage="%(prog)s [options] -- <nextflow_cmd>",
        epilog=textwrap.dedent(
            """\
            Example:
              %(prog)s -- nextflow run \\
                  -with-report report.html \\
                  -with-trace \\
                  -with-timeline timeline.html \\
                  hello
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-c",
        "--context",
        type=str,
        help="Name of the secret context to use from config.yaml. Defaults to the active context in the config file.",
        default=None,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Dump the workflow before submitting and add debug logging",
    )
    parser.add_argument(
        "--fuzzball-config",
        type=pathlib.Path,
        default=(
            pathlib.Path("~/.config/fuzzball/config.yaml").expanduser() if os.environ.get("XDG_CONFIG_HOME", None) is None
            else pathlib.Path(f"{os.environ['XDG_CONFIG_HOME']}/fuzzball/config.yaml")
        ),
        help="Path to the fuzzball configuration file. [%(default)s]",
    )
    parser.add_argument(
        "--ca-cert",
        type=str,
        help="Path to CA certificate file for SSL verification of self-signed certificates",
    )
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Don't submit the workflow, just print it",
    )
    parser.add_argument(
        "--job-name",
        type=str,
        default="",
        help=(
            "Name of the Fuzzball workflow running the nextflow controller job. Defaults to a "
            "UUID seeded by the full commandline of the nextflow command."
        ),
    )
    parser.add_argument(
        "--nextflow-work-base",
        type=str,
        default=f"{DATA_MOUNT}/nextflow/executions",
        help=(
            "Name of basedirectory for nextflow execution paths. The nextflow execution path will be "
            "<nextflow-work-base>/<job-name> which would include logs and the default workdir. "
            "[%(default)s]"
        ),
    )
    parser.add_argument(
        "--nf-fuzzball-version",
        type=str,
        default="0.1.0",
        help="nf-fuzzball plugin version. Note that the plugin tag includes a 'v' prefix [%(default)s]",
    )
    parser.add_argument(
        "--s3-secret",
        type=str,
        default="",
        help=(
            "Reference for fuzzball S3 secret used to pull the nf-fuzzball plugin if the base URI for the plugin download is a S3 URI"
            " Defaults to [%(default)s]"
        ),
    )
    parser.add_argument(
        "--plugin-base-uri",
        type=str,
        default="https://github.com/ctrliq/nf-fuzzball/releases/download",
        help=(
            "Base URI for the nf-fuzzball plugin. The submission script expects to find a zip file at "
            "<plugin-base-uri>/v<version>/nf-fuzzball-v<version>-stable-v<fuzzball-version>.zip. "
            "All version strings are expected to start with a v. The Fuzzball version is vMAJOR.MINOR, "
            "the nf-fuzzball version is vMAJOR.MINOR.PATCH"
            "Defaults to [%(default)s]"
        ),
    )
    parser.add_argument(
        "--nextflow-version",
        type=str,
        default="25.05.0-edge",
        help="Nextflow version [%(default)s]",
    )
    parser.add_argument(
        "--timelimit",
        type=str,
        default="8h",
        help="Timelimit for pipeline job [%(default)s]",
    )
    parser.add_argument(
        "--scratch-volume",
        type=str,
        default="volume://user/ephemeral",
        help="Ephemeral scratch volume [%(default)s]",
    )
    parser.add_argument(
        "--data-volume",
        type=str,
        default="volume://user/persistent",
        help="Persistent data volume [%(default)s]",
    )
    parser.add_argument(
        "--nf-core",
        action="store_true",
        help="Use nf-core conventions",
    )
    parser.add_argument(
        "--queue-size",
        type=int,
        default=20,
        help=(
            "Queue size for the Fuzzball executor. This is the number of jobs that can be queued at once. "
            "[%(default)s]"
        ),
    )
    parser.add_argument(
        "nextflow_cmd", nargs=argparse.REMAINDER, help="Nextflow command"
    )
    args = parser.parse_args()
    if not args.nextflow_cmd:
        parser.error(
            "Nextflow command is required. Please provide it after the options."
        )
    if args.nextflow_cmd[0] == "--":
        args.nextflow_cmd.pop(0)
    if args.nextflow_cmd[0] != "nextflow":
        parser.error(
            "Your nextflow command does not start with 'nextflow'"
        )
    if args.verbose or args.dry_run:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.plugin_base_uri.startswith("s3://") and not args.s3_secret:
        parser.error(
            "When using --plugin-base-uri with an S3 URI, you must also specify --s3-secret to access the S3 bucket."
        )
    return args


def main() -> None:
    """Main function that parses arguments and submits the Nextflow job.

    Raises:
        SystemExit: On any error or user interruption.
    """
    try:
        args = parse_cli()

        # Validate config path
        config_path = args.fuzzball_config.expanduser()
        if not config_path.exists():
            die(
                f"Fuzzball configuration file not found at {config_path}. Please create it first."
            )
        if not config_path.is_file():
            die(f"Path {config_path} exists but is not a file.")

        # Initialize client
        try:
            fb_client = MinimalFuzzballClient(config_path, args.context, args.ca_cert)
        except (ValueError, IOError) as e:
            die(f"Failed to load config: {e}")

        # Submit job
        try:
            fb_client.submit_nextflow_job(args)
        except Exception as e:
            die(f"Failed to submit Nextflow job: {e}")

    except KeyboardInterrupt:
        logger.info("Operation interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
