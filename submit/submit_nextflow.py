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
import getpass
import json
import logging
import os
import pathlib
import shlex
import ssl
import sys
import textwrap
from typing import Any
import uuid
from urllib.parse import urlencode, urlparse

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

    def __init__(
        self,
        config_path: pathlib.Path | None = None,
        context: str | None = None,
        ca_cert_file: str | None = None,
        api_url: str | None = None,
        auth_url: str | None = None,
        user: str | None = None,
        passwd: str | None = None,
        account_id: str | None = None,
    ):
        """
        Initialize the Fuzzball client.

        Args:
            config_path: Path to the fuzzball configuration file.
            context: Optional context name to use from the config file.
            ca_cert_file: Path to CA certificate file for SSL verification.
            api_url: URL of the Fuzzball API.
            auth_url: URL of the Keycloak authentication server.
            user: Username for direct login.
            passwd: Password for direct login.
            account_id: Fuzzball account ID for direct login.

        Raises:
            ValueError: If configuration is invalid or missing.
            IOError: If the config file cannot be read.
        """
        self._ca_cert_file = ca_cert_file
        self._config = None
        self._token: str | None = None
        self._user = user
        self._passwd = passwd
        self._account_id = account_id
        self._auth_url = auth_url
        self._api_url = api_url
        self._refresh_token: str | None = None

        self._setup_http_client(self._ca_cert_file)

        if self._user:
            # Direct login flow
            if not all(
                [
                    self._api_url,
                    self._auth_url,
                    self._user,
                    self._passwd,
                    self._account_id,
                ]
            ):
                raise ValueError(
                    "For direct login, api-url, auth-url, user, password, and account-id are required."
                )
            self._host = urlparse(self._api_url).hostname
            self._port = urlparse(self._api_url).port or 443
            self._schema = urlparse(self._api_url).scheme
            self._base_url = self._api_url
            self._detect_base_path()
            self.login()

            self._config = {"activeContext": "nextflow",
                            "contexts": [
                                {
                                    "name": "nextflow",
                                    "address": f"{self._host}:{self._port}",
                                    "oidcServerURL": self._auth_url,
                                    "oidcClientID": "fuzzball-cli",
                                    "auth": {
                                        "oidc_client_id": "fuzzball-cli",
                                        "oidc_well_known_endpoint": "n/a",
                                        "overrides": None,
                                        "credentials": {"token": self._token}
                                    },
                                    "realm": "n/a",
                                    "currentaccountid": self._account_id,
                                    "accounts": [
                                        {
                                            "accountid": self._account_id,
                                            "accountalias": "n/a"
                                        }
                                    ]

                                }
                            ]}


        else:
            # Config file flow
            if not config_path:
                raise ValueError(
                    "A config file path must be provided when not using direct login."
                )
            try:
                with open(config_path, "r") as f:
                    config = yaml.safe_load(f)
            except IOError as e:
                raise IOError(f"Failed to read configuration file {config_path}: {e}")
            except yaml.YAMLError as e:
                raise ValueError(
                    f"Failed to parse configuration file {config_path}: {e}"
                )

            if not isinstance(config, dict):
                raise ValueError(
                    "Configuration file has invalid format (not a dictionary)"
                )

            if context is None:
                context = config.get("activeContext")
            if context is None:
                raise ValueError(
                    "No active context specified in config or provided as argument"
                )

            self._config = {"activeContext": context, "contexts": []}
            logger.debug(f"Using context: {context}")

            context_found = False
            for c in config.get("contexts", []):
                if c["name"] == context:
                    try:
                        self._host, self._port = c["address"].split(":")
                        self._token = c["auth"]["credentials"]["token"]
                        self._schema = "https"
                        self._config["contexts"].append(c)
                        context_found = True
                        break
                    except (KeyError, ValueError) as e:
                        raise ValueError(
                            f"Invalid context configuration for '{context}': {e}"
                        )

            if not context_found:
                raise ValueError(f"Context '{context}' not found in configuration file")

            self._base_url = f"{self._schema}://{self._host}:{self._port}"
            self._detect_base_path()

        logger.debug(f"Using API base path: {self._base_path}")

        try:
            response = self._request("GET", "/version")
            version_data = json.loads(response.data.decode("utf-8"))
            self._fb_version = ".".join(version_data["version"].split(".")[0:2])
            logger.info(f"Connected to Fuzzball version {self._fb_version} API server")
        except urllib3.exceptions.HTTPError as e:
            raise ValueError(f"Failed to connect to Fuzzball API: {e}")
        except Exception as e:
            raise ValueError(f"Unexpected error occurred: {e}")

    def _detect_base_path(self):
        """Guess the base path based on the base url"""
        if self._base_url[-3:] in ["/v2", "/v3", "/v4"]:
            self._base_path = self._base_url[-3:]
            return

        detected_base_path = None
        for version in ["v2", "v3", "v4"]:
            test_base_path = f"/{version}"
            test_base_url = f"{self._base_url}{test_base_path}"

            try:
                response = self._http.request(
                    "GET",
                    f"{test_base_url}/version",
                    headers=self._headers,
                    timeout=30,
                )
                if response.status < 400:
                    detected_base_path = test_base_path
                    break
            except Exception:
                continue

        if detected_base_path is None:
            logger.warning("Failed to detect API base path, falling back to /v2")
            detected_base_path = "/v2"

        self._base_path = detected_base_path
        self._base_url = f"{self._base_url}{self._base_path}"

    def _setup_http_client(self, ca_cert_file: str | None = None) -> None:
        """Setup urllib3 HTTP client with appropriate SSL configuration."""
        if ca_cert_file:
            ssl_context = ssl.create_default_context()
            ssl_context.load_verify_locations(ca_cert_file)
            self._http = urllib3.PoolManager(
                ssl_context=ssl_context,
                retries=Retry(
                    total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504]
                ),
            )
        else:
            self._http = urllib3.PoolManager(
                retries=Retry(
                    total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504]
                )
            )

    def _auth_request(self, use_refresh_token: bool = True) -> urllib3.HTTPResponse:
        """Request auth token from Fuzzball Keycloak server."""
        data = {"client_id": "fuzzball-cli"}
        if use_refresh_token and self._refresh_token:
            logger.debug("Using refresh token to obtain new access token")
            data.update(
                {"grant_type": "refresh_token", "refresh_token": self._refresh_token}
            )
        else:
            logger.debug("Using password to obtain new access token")
            data.update(
                {
                    "grant_type": "password",
                    "username": self._user or "",
                    "password": self._passwd or "",
                }
            )

        return self._request(
            "POST",
            "/protocol/openid-connect/token",
            data=data,
            base_url=self._auth_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def login(self) -> None:
        """Login to Fuzzball and obtain an access token."""
        logger.debug("------------ Starting Auth Request ------------")
        try:
            response = self._auth_request(use_refresh_token=False)
        except urllib3.exceptions.HTTPError as e:
            raise ValueError(f"Failed to obtain auth token: {e}")

        response_data = json.loads(response.data.decode("utf-8"))
        if "access_token" not in response_data or "refresh_token" not in response_data:
            raise ValueError("No access or refresh token in response")

        auth_token = response_data["access_token"]
        self._refresh_token = response_data["refresh_token"]

        logger.debug("------------ Starting API Token Request ------------")
        try:
            api_response = self._request(
                "GET",
                f"/accounts/{self._account_id}/token",
                headers={
                    "Authorization": f"Bearer {auth_token}",
                    "Accept": "application/json",
                },
            )
        except urllib3.exceptions.HTTPError as e:
            raise ValueError(f"Failed to obtain API token: {e}")

        api_response_data = json.loads(api_response.data.decode("utf-8"))
        if "token" not in api_response_data:
            raise ValueError("No API token in response")
        self._token = api_response_data["token"]

    @property
    def _headers(self) -> dict[str, str]:
        """Return the headers required for API requests."""
        if not self._token:
            raise ValueError("Authentication token is not available.")
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def _request(
        self,
        method: str,
        endpoint: str,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        base_url: str | None = None,
    ) -> urllib3.HTTPResponse:
        """Make an API request to the Fuzzball server."""
        url = f"{base_url or self._base_url}/{endpoint.lstrip('/')}"
        body = None
        request_headers = headers if headers is not None else self._headers

        if data is not None:
            if request_headers.get("Content-Type") == "application/json":
                body = json.dumps(data).encode("utf-8")
            elif (
                request_headers.get("Content-Type")
                == "application/x-www-form-urlencoded"
            ):
                body = urlencode(data).encode("utf-8")
            else:
                body = json.dumps(data).encode("utf-8")

        response = self._http.request(
            method.upper(), url, body=body, headers=request_headers, timeout=30
        )

        if response.status >= 400:
            raise urllib3.exceptions.HTTPError(
                f"HTTP {response.status}: {response.reason} {response.data.decode('utf-8')}"
            )

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
            raise ValueError(f"Failed to encode Fuzzball configuration: {e}")

    def _encode_ca_cert(self) -> str:
        """Return a base64 encoded version of the CA certificate if one was provided.

        Returns:
            Base64 encoded config string safe for transport. Empty string if no cert was passed

        Raises:
            IOError: If the certificate file cannot be read.
        """
        if not self._ca_cert_file:
            return ""

        try:
            with open(self._ca_cert_file, "rb") as f:
                return base64.b64encode(f.read()).decode("utf-8")
        except IOError:
            logger.error(f"Failed to read CA certificate file {self._ca_cert_file}")
            raise

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
            secrets_data = json.loads(response.data.decode("utf-8"))
            for secret in secrets_data.get("secrets", []):
                if secret["name"] == secret_name:
                    secret_id = secret["id"]
                    secret_data = {"value": {"value": secret_value}}
                    self._request("PATCH", f"/secrets/{secret_id}", data=secret_data)
                    return secret_id
        except urllib3.exceptions.HTTPError as e:
            logger.warning(
                f"Could not list secrets, assuming secret does not exist: {e}"
            )

        secret_data = {
            "name": secret_name,
            "scope": "SECRET_SCOPE_USER",
            "value": {"value": secret_value},
        }
        resp = self._request("PUT", "/secrets", data=secret_data)
        resp_data = json.loads(resp.data.decode("utf-8"))
        return resp_data["id"]

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
        mounts = {
            "data": {"location": DATA_MOUNT},
            "scratch": {"location": SCRATCH_MOUNT},
        }
        wd = f"{args.nextflow_work_base}/{job_name}"
        home_base = "home"
        home = f"{wd}/{home_base}"
        files_base = "files"
        files = f"{wd}/{files_base}"
        ca_cert_path = f"{home}/.config/fuzzball/ca.crt"
        config_path = f"{home}/.config/fuzzball/config.yaml"

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
                response = self._http.request("HEAD", plugin_uri, timeout=10)
                if response.status >= 400:
                    raise urllib3.exceptions.HTTPError(
                        f"HTTP {response.status}: {response.reason}"
                    )
            except urllib3.exceptions.HTTPError:
                raise Exception(
                    f"Failed to access nf-fuzzball plugin for this version of Fuzzball at {plugin_uri}"
                )

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

        config_secret_id = None
        cert_secret_id = None
        user_secret_id = None
        pass_secret_id = None

        setup_env = env.copy()

        if self._user:  # Direct login
            user_secret_name = f"{secret_name}-user"
            pass_secret_name = f"{secret_name}-pass"
            user_secret_id = self.create_value_secret(
                user_secret_name, base64.b64encode(self._user.encode()).decode()
            )
            pass_secret_id = self.create_value_secret(
                pass_secret_name, base64.b64encode(self._passwd.encode()).decode()
            )
            setup_env.extend(
                [
                    f"FB_USER_SECRET=secret://user/{user_secret_name}",
                    f"FB_PASS_SECRET=secret://user/{pass_secret_name}",
                    f"FUZZBALL_API_URL={self._api_url}",
                    f"FUZZBALL_AUTH_URL={self._auth_url}",
                    f"FUZZBALL_ACCOUNT={self._account_id}",
                ]
            )
        # Config file login
        config_secret_name = f"{secret_name}-conf"
        config_secret_id = self.create_value_secret(
            config_secret_name, self._encode_config()
        )
        setup_env.append(f"FB_CONFIG_SECRET=secret://user/{config_secret_name}")

        if self._ca_cert_file:
            cert_secret_name = f"{secret_name}-cert"
            cert_secret_id = self.create_value_secret(
                cert_secret_name, self._encode_ca_cert()
            )
            setup_env.append(f"FB_CA_CERT_SECRET=secret://user/{cert_secret_name}")

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
                    cfgFile = '{config_path}'
                }}
            }}
        }}
        """).encode("utf-8")
        ).decode("utf-8")
        nxf_fuzzball_config_name = str(
            uuid.uuid5(NAMESPACE_CONTENT, nxf_fuzzball_config)
        )

        # Note: the setup job uses /tmp as the cwd in order to manually create the working dir
        #       for nextflow as part of the job. This makes sure ownership and permissions are as expected
        setup_script = textwrap.dedent(f"""\
        #! /bin/sh
        mkdir -p {wd} || exit 1
        rm -rf {home}/.nextflow/plugins/nf-fuzzball-{plugin_version} \\
          && mkdir -p {home}/.nextflow/plugins/nf-fuzzball-{plugin_version} {home}/.config/fuzzball \\
          && unzip {SCRATCH_MOUNT}/nf-fuzzball.zip -d {home}/.nextflow/plugins/nf-fuzzball-{plugin_version} > /dev/null \\
          && echo "$FB_CONFIG_SECRET" | base64 -d > {config_path} \\
          || exit 1

        # Setup CA certificate if provided
        if [ ! -z "$FB_CA_CERT_SECRET" ]; then
            echo "$FB_CA_CERT_SECRET" | base64 -d > {ca_cert_path} || exit 1
        fi

        TOKEN="$(awk '/token:/ {{print $2}}' {config_path})"
        CURL_CA_OPT=""
        if [ -n "$FB_CA_CERT_SECRET" ]; then
            CURL_CA_OPT="--cacert {ca_cert_path}"
        fi

        cleanup() {{
            echo "Cleaning up secrets..."
            {f'curl -s $CURL_CA_OPT -X DELETE "{self._base_url}/secrets/{config_secret_id}" -H "Authorization: Bearer $TOKEN" &' if config_secret_id else ""}
            {f'curl -s $CURL_CA_OPT -X DELETE "{self._base_url}/secrets/{cert_secret_id}" -H "Authorization: Bearer $TOKEN" &' if cert_secret_id else ""}
            {f'curl -s $CURL_CA_OPT -X DELETE "{self._base_url}/secrets/{user_secret_id}" -H "Authorization: Bearer $TOKEN" &' if user_secret_id else ""}
            {f'curl -s $CURL_CA_OPT -X DELETE "{self._base_url}/secrets/{pass_secret_id}" -H "Authorization: Bearer $TOKEN" &' if pass_secret_id else ""}
            wait
            echo "Cleanup finished."
        }}
        trap cleanup EXIT

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
                        "cwd": "/tmp",
                        "script": setup_script,
                        "env": setup_env,
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
                        "env": env
                        + (
                            [f"FB_CA_CERT={ca_cert_path}"]
                            if self._ca_cert_file is not None
                            else []
                        ),
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
            # Clean up secrets created during dry run
            if config_secret_id:
                self._request("DELETE", f"/secrets/{config_secret_id}")
            if cert_secret_id:
                self._request("DELETE", f"/secrets/{cert_secret_id}")
            if user_secret_id:
                self._request("DELETE", f"/secrets/{user_secret_id}")
            if pass_secret_id:
                self._request("DELETE", f"/secrets/{pass_secret_id}")
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
    auth_group = parser.add_argument_group("Fuzzball config based authentication")
    auth_group.add_argument(
        "-c",
        "--context",
        type=str,
        help="Name of the context to use from config.yaml.",
        default=None,
    )
    auth_group.add_argument(
        "--fuzzball-config",
        type=pathlib.Path,
        default=(
            pathlib.Path("~/.config/fuzzball/config.yaml").expanduser()
            if os.environ.get("XDG_CONFIG_HOME") is None
            else pathlib.Path(f"{os.environ['XDG_CONFIG_HOME']}/fuzzball/config.yaml")
        ),
        help="Path to the fuzzball configuration file. [%(default)s]",
    )
    direct_login_group = parser.add_argument_group("Direct Login based authentication")
    direct_login_group.add_argument(
        "--api-url",
        type=str,
        help=(
            "API URL of Fuzzball cluster [$FUZZBALL_API_URL]."
            " e.g. https://api.example.com"
        ),
        default=os.environ.get("FUZZBALL_API_URL", ""),
    )
    direct_login_group.add_argument(
        "--auth-url",
        type=str,
        help=(
            "AUTH URL of Fuzzball cluster [$FUZZBALL_AUTH_URL] "
            "e.g. https://auth.example.com/auth/realms/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        ),
        default=os.environ.get("FUZZBALL_AUTH_URL", ""),
    )
    direct_login_group.add_argument(
        "--user",
        type=str,
        help="Username/email for direct login [$FUZZBALL_USER]",
        default=os.environ.get("FUZZBALL_USER", ""),
    )
    direct_login_group.add_argument(
        "--password", action="store_true",
        help=(
            "Prompt for password for direct login. Otherwise defaults to [$FUZZBALL_PASSWORD]"
        )
    )
    direct_login_group.add_argument(
        "--account-id",
        type=str,
        help="Fuzzball account ID for direct login [$FUZZBALL_ACCOUNT]",
        default=os.environ.get("FUZZBALL_ACCOUNT", ""),
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging."
    )
    parser.add_argument(
        "--ca-cert", type=str, help="Path to CA certificate file for SSL verification."
    )
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Print the workflow without submitting.",
    )
    parser.add_argument(
        "--job-name", type=str, default="", help="Name of the Fuzzball workflow."
    )
    parser.add_argument(
        "--nextflow-work-base",
        type=str,
        default=f"{DATA_MOUNT}/nextflow/executions",
        help="Base directory for Nextflow execution.",
    )
    parser.add_argument(
        "--nf-fuzzball-version",
        type=str,
        default="0.2.0",
        help="nf-fuzzball plugin version.",
    )
    parser.add_argument(
        "--s3-secret",
        type=str,
        default="",
        help="Fuzzball S3 secret for plugin download.",
    )
    parser.add_argument(
        "--plugin-base-uri",
        type=str,
        default="https://github.com/ctrliq/nf-fuzzball/releases/download",
        help="Base URI for the nf-fuzzball plugin.",
    )
    parser.add_argument(
        "--nextflow-version", type=str, default="25.05.0-edge", help="Nextflow version."
    )
    parser.add_argument(
        "--timelimit", type=str, default="8h", help="Timelimit for the pipeline job."
    )
    parser.add_argument(
        "--scratch-volume",
        type=str,
        default="volume://user/ephemeral",
        help="Ephemeral scratch volume.",
    )
    parser.add_argument(
        "--data-volume",
        type=str,
        default="volume://user/persistent",
        help="Persistent data volume.",
    )
    parser.add_argument(
        "--nf-core", action="store_true", help="Use nf-core conventions."
    )
    parser.add_argument(
        "--queue-size",
        type=int,
        default=20,
        help="Queue size for the Fuzzball executor.",
    )
    parser.add_argument(
        "nextflow_cmd", nargs=argparse.REMAINDER, help="Nextflow command."
    )

    args = parser.parse_args()
    if not args.nextflow_cmd:
        parser.error("Nextflow command is required.")
    if args.nextflow_cmd[0] == "--":
        args.nextflow_cmd.pop(0)
    if args.nextflow_cmd[0] != "nextflow":
        parser.error("Nextflow command must start with 'nextflow'.")
    if args.verbose or args.dry_run:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.plugin_base_uri.startswith("s3://") and not args.s3_secret:
        parser.error("--s3-secret is required when --plugin-base-uri is an S3 URI.")

    return args


def main() -> None:
    """Main function that parses arguments and submits the Nextflow job.

    Raises:
        SystemExit: On any error or user interruption.
    """
    try:
        args = parse_cli()
        passwd = None
        if args.user:
            if args.password:
                passwd = getpass.getpass("Enter Fuzzball password: ")
            else:
                passwd = os.environ.get("FUZZBALL_PASSWORD")
            if not passwd:
                die(
                    "Password is required for direct login. Use --password or set FUZZBALL_PASSWORD."
                )

        fb_client = None
        if args.user:
            try:
                fb_client = MinimalFuzzballClient(
                    ca_cert_file=args.ca_cert,
                    api_url=args.api_url,
                    auth_url=args.auth_url,
                    user=args.user,
                    passwd=passwd,
                    account_id=args.account_id,
                )
            except (ValueError, IOError) as e:
                die(f"Failed to initialize Fuzzball client for direct login: {e}")
        else:
            config_path = args.fuzzball_config.expanduser()
            if not config_path.is_file():
                die(f"Fuzzball configuration file not found at {config_path}.")
            try:
                fb_client = MinimalFuzzballClient(
                    config_path=config_path,
                    context=args.context,
                    ca_cert_file=args.ca_cert,
                )
            except (ValueError, IOError) as e:
                die(f"Failed to load config: {e}")

        if fb_client:
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
