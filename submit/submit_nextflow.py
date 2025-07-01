#! /usr/bin/env python3
"""
Submit a nextflow pipeline to Fuzzball.

Notes:
  - Paths for input, workdir, and output in your nextflow command are relative to the
    data volume mounted at /data.
  - Any explicitly specified config and/or parameter files will be included in the
    fuzzball job but implicit files (i.e. $HOME/.nextflow/config and ./nextflow.config)
    will not.
  - config an parameter files should be specified on the commandline directly rather than
    indirectly in a config file.
  - The nextflow command should be specified after the -- separator.
  - Include the fuzzball profile as one of your nextflow profiles

"""

import argparse
import base64
import logging
import pathlib
import shlex
import sys
import textwrap
from typing import Dict, Any
import uuid

import yaml
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

NAMESPACE_CONTENT = uuid.UUID("71c91ef2-0f9b-47f3-988b-5725d2f67599")


def str_presenter(dumper: yaml.Dumper, data: str) -> yaml.Node:
    """
    Represent strings with newlines as block litererals in YAML
    """
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


yaml.add_representer(str, str_presenter)


def die(error: str) -> None:
    """
    Log an error message and exit the program.
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

    def __init__(self, config_path: pathlib.Path, context: str | None = None):
        """
        Initialize the Fuzzball client with configuration from a YAML file.

        Args:
            config_path: Path to the fuzzball configuration file
            context: Optional context name to use, defaults to activeContext in config

        Raises:
            ValueError: If the context is missing or the config is invalid
            IOError: If the config file cannot be read
        """
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

        # Determine version of the Fuzzball API server
        try:
            response = self._request("GET", "/version")
            self._fb_version = response.json()["version"]
            logger.info(f"Connected to Fuzzball version {self._fb_version} API server")
        except requests.HTTPError as e:
            raise ValueError(f"Failed to connect to Fuzzball API: {e}")
        except Exception as e:
            raise ValueError(f"Unexpected error occurred: {e}")

    @property
    def _headers(self) -> Dict[str, str]:
        """
        Return the headers required for API requests, including the authorization token.
        """
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def _request(
        self, method: str, endpoint: str, data: Dict[str, Any] | None = None
    ) -> requests.Response:
        """
        Make an API request to the Fuzzball server with retry logic.

        Args:
            method: HTTP method to use (GET, POST, etc.)
            endpoint: API endpoint path
            data: Optional JSON data to send with the request

        Returns:
            Response object from the request

        Raises:
            requests.HTTPError: If the request fails
        """
        session = requests.Session()
        retries = Retry(
            total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504]
        )
        session.mount("https://", HTTPAdapter(max_retries=retries))

        url = f"{self._base_url}/{endpoint.lstrip('/')}"
        response = session.request(
            method, url, json=data, headers=self._headers, timeout=30
        )
        response.raise_for_status()
        return response

    def _encode_config(self) -> str:
        """
        Return a base64 encoded version of the minimal Fuzzball configuration file
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

    def create_value_secret(self, secret_name: str, secret_value: str) -> None:
        """
        Create or update a value secret in Fuzzball.

        Args:
            secret_name: The name to give the secret
            secret_value: The value to store in the secret (base64 encoded config)
        Raises:
            requests.HTTPError: If the request to create or update the secret fails
        """
        # Check if the secret already exists
        try:
            response = self._request("GET", "/secrets")
        except requests.HTTPError:
            logger.error("Failed to retrieve existing secrets")
            raise
        id = None
        for secret in response.json()["secrets"]:
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
            except requests.HTTPError:
                logger.error("Failed to create secret")
                raise
            self._secret_id = resp.json()["id"]
        else:
            self._secret_id = id
            secret_data = {"value": {"value": secret_value}}
            try:
                self._request("PATCH", f"/secrets/{id}", data=secret_data)
            except requests.HTTPError:
                logger.error("Failed to update secret")
                raise

    def submit_nextflow_job(self, args: argparse.Namespace) -> None:
        """
        Submit a Nextflow job to the Fuzzball cluster.
        Args:
            args: Parsed command line arguments.
        Raises:
            requests.HTTPError: If any API request fails.
            IOError: If any local files cannot be read or processed
            Exception: If there is any other (unspecific) errors
        """
        nextflow_cmd_str = shlex.join(args.nextflow_cmd)
        job_name = (
            args.job_name
            if len(args.job_name) > 0
            else str(uuid.uuid5(NAMESPACE_CONTENT, nextflow_cmd_str))
        )
        mounts = {"data": {"location": "/data"}, "scratch": {"location": "/scratch"}}
        wd_base = f"{args.nextflow_work_base}/{job_name}"
        wd = f"{mounts['data']['location']}/{wd_base}"
        home_base = "home"
        home = f"{wd}/{home_base}"
        files_base = "files"
        files = f"{wd}/{files_base}"
        secret_name = str(uuid.uuid4())
        plugin_version = args.nf_fuzzball_version

        mangled_nextflow_cmd, config_files = find_and_import_local_files(
            args.nextflow_cmd, files
        )
        mangled_nextflow_cmd_str = shlex.join(mangled_nextflow_cmd)

        # download url for the plugin (until it's in the nextflow plugin registry)
        plugin_uri = f"{args.plugin_base_uri}/v{args.nf_fuzzball_version}/nf-fuzzball-{args.nf_fuzzball_version}-stable-{self._fb_version}.zip"
        # check that the URL exists
        if plugin_uri.startswith("http://") or plugin_uri.startswith("https://"):
            try:
                response = requests.head(plugin_uri, timeout=10)
                response.raise_for_status()
            except requests.HTTPError as e:
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

        self.create_value_secret(secret_name, self._encode_config())
        nxf_fuzzball_config = base64.b64encode(
            textwrap.dedent(f"""\
        plugins {{ id 'nf-fuzzball@{plugin_version}' }}
        profiles {{
            fuzzball {{
                executor {{
                    '$fuzzball' {{
                        queueSize = {args.queue_size}
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
          && unzip /scratch/nf-fuzzball.zip -d $HOME/.nextflow/plugins/nf-fuzzball-{plugin_version} > /dev/null \\
          && echo "$FB_CONFIG" | base64 -d > $HOME/.config/fuzzball/config.yaml \\
          || exit 1

        # there is only a single context in the config file so it's easy to extract the token
        TOKEN="$(awk '/token:/ {{print $2}}' $HOME/.config/fuzzball/config.yaml)"
        # clean up the secret but don't fail if there is an error
        curl -s -X DELETE "{self._base_url}/secrets/{self._secret_id}" \\
            -H "Authorization: Bearer $TOKEN" \\
            -H "Accept: application/json" &> /dev/null && echo "temp secret deleted" || echo "temp secret not deleted"

        mkdir {files}
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
                        "env": env + [f"FB_CONFIG=secret://user/{secret_name}"],
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
                        "env": env,
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
            self._request("DELETE", f"/secrets/{self._secret_id}")
            return
        response = self._request("POST", "/workflows", data=workflow)
        logger.info(f"Submitted nextflow workflow {response.json()['id']}")


def parse_cli() -> argparse.Namespace:
    """
    Parsing the commandline
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
        default=pathlib.Path("~/.config/fuzzball/config.yaml").expanduser(),
        help="Path to the fuzzball configuration file. [%(default)s]",
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
        default="nextflow/executions",
        help=(
            "Name of basedirectory for nextflow execution paths. The nextflow execution path will be "
            "/data/<nextflow-work-base>/<job-name> which would include logs and the default workdir. "
            "[%(default)s]"
        ),
    )
    parser.add_argument(
        "--nf-fuzzball-version",
        type=str,
        default="0.0.1",
        help="nf-fuzzball plugin version [%(default)s]",
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
            "<plugin-base-uri>/v<version>/nf-fuzzball-<version>-stable-v<fuzzball-version>.zip. "
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
    if args.verbose or args.dry_run:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.plugin_base_uri.startswith("s3://") and not args.s3_secret:
        parser.error(
            "When using --plugin-base-uri with an S3 URI, you must also specify --s3-secret to access the S3 bucket."
        )
    return args


def main() -> None:
    """
    Main function that parses arguments and submits the Nextflow job.
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
            fb_client = MinimalFuzzballClient(config_path, args.context)
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
