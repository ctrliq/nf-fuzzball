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

from abc import ABC, abstractmethod
import argparse
import base64
from dataclasses import dataclass
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
from urllib.parse import urlencode, urlparse
import uuid

import urllib3
from urllib3.util import Retry
import yaml


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)
logging.getLogger("urllib3").setLevel(logging.WARNING)

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
    """Represents a local file that should be included in the Nextflow job.

    The remote name is derived from the file content using a UUID based on a hash
    of the content.

    Attributes:
        local_path: Path to the local file.
        content: Base64 encoded file content.
        remote_name: Generated remote filename.
        remote_path: Full remote path including prefix.
    """

    def __init__(self, local_path: pathlib.Path, remote_prefix: str = "") -> None:
        """Initialize a LocalFile instance.

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

###
### Fuzzball
###

def make_url_canonical(url: str, http_client: urllib3.PoolManager) -> str:
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
        except Exception:
            continue
    raise ValueError("Unable to sniff API base path")


@dataclass
class ApiConfig:
    api_url: str     # full url with schema and basepath for the API
    auth_url: str    # full url with schema and path
    token: str
    account_id: str
    user: str | None = None
    password: str | None = None

    @property
    def api_host(self) -> str:
        """
        Hostname of the API Server.

        If the URL does not specify a port, returns 443 as the default port.

        Returns:
            str: Host name of the api.
        """
        return urlparse(self.api_url).hostname or "unknown"

    @property
    def api_port(self) -> int:
        """
        Port number of the API.

        If the URL does not specify a port, returns 443 as the default port.

        Returns:
            int: The port number extracted from the API URL, or 443 if not specified.
        """
        return urlparse(self.api_url).port or 443

    @property
    def cli_config(self) -> dict[str, Any]:
        """Return a Fuzzball compatible config dict with a single active context"""
        return {
            "activeContext": "nextflow",
            "contexts": [
                {
                    "name": "nextflow",
                    "address": f"{self.api_host}:{self.api_port}",
                    "oidcServerURL": self.auth_url,
                    "oidcClientID": "fuzzball-cli",
                    "auth": {
                        "oidc_client_id": "fuzzball-cli",
                        "oidc_well_known_endpoint": f"{self.auth_url}/.well-known/openid-configuration",
                        "overrides": None,
                        "credentials": {"token": self.token}
                    },
                    "realm": "",
                    "currentaccountid": self.account_id,
                    "accounts": [
                        {
                            "accountid": self.account_id,
                            "accountalias": "n/a"
                        }
                    ]
                }
            ]
        }


class FuzzballAuthenticator(ABC):
    """Abstract base class for Fuzzball authentication methods.

    This class defines the interface that all authentication methods must implement.
    """

    @abstractmethod
    def authenticate(self, http_client: urllib3.PoolManager) -> ApiConfig:
        """Authenticate and return connection configuration.

        Args:
            http_client: HTTP client for making requests.

        Returns:
            ApiConfig with authentication details.
        """
        pass


class DirectLoginAuthenticator(FuzzballAuthenticator):
    """Authenticator for direct login using username/password.

    This authenticator uses OAuth2 password flow to authenticate with Keycloak
    and obtain API tokens for Fuzzball.
    """

    def __init__(
        self,
        api_url: str,
        auth_url: str,
        user: str,
        password: str,
        account_id: str,
    ):
        self._raw_api_url = api_url # can leave off the API base path
        self._api_url: str | None = None # canonical URL
        self._auth_url = auth_url
        self._user = user
        self._password = password
        self._account_id = account_id

        self._validate_params()

    def _validate_params(self) -> None:
        """Validate that all required parameters are provided.

        Raises:
            ValueError: If validation fails.
        """
        required_params = [self._raw_api_url, self._auth_url, self._user, self._password, self._account_id]
        if not all(required_params):
            raise ValueError(
                "For direct login, api-url, auth-url, user, password, and account-id are required."
            )

    def _get_auth_token(self, http_client: urllib3.PoolManager) -> str:
        """Get authentication token from Keycloak.

        Args:
            http_client: HTTP client for making requests.

        Returns:
            The authentication token from Keycloak.

        Raises:
            ValueError: If authentication fails or token is not in response.
        """
        data = {
            "client_id": "fuzzball-cli",
            "grant_type": "password",
            "username": self._user,
            "password": self._password,
        }

        response = http_client.request(
            "POST",
            f"{self._auth_url.rstrip('/')}/protocol/openid-connect/token",
            body = urlencode(data).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )

        if response.status >= 400:
            raise ValueError(f"Failed to obtain auth token: HTTP {response.status}")

        response_data = json.loads(response.data.decode("utf-8"))
        if "access_token" not in response_data:
            raise ValueError("No access token in response from auth server")

        return response_data["access_token"]

    def _get_api_token(self, http_client: urllib3.PoolManager, auth_token: str) -> str:
        """Get API token using auth token from Keycloak.

        Args:
            http_client: HTTP client for making requests.
            auth_token: Authentication token from Keycloak.

        Returns:
            The API token for Fuzzball.

        Raises:
            ValueError: If API token request fails or token is not in response.
        """
        response = http_client.request(
            "GET",
            f"{self._api_url}/accounts/{self._account_id}/token",
            headers={
                "Authorization": f"Bearer {auth_token}",
                "Accept": "application/json",
            },
            timeout=30,
        )

        if response.status >= 400:
            raise ValueError(f"Failed to obtain API token: HTTP {response.status}")

        response_data = json.loads(response.data.decode("utf-8"))
        if "token" not in response_data:
            raise ValueError("No API token in response from API server")
        return response_data["token"]

    def authenticate(self, http_client: urllib3.PoolManager) -> ApiConfig:
        """Perform direct login authentication.

        Args:
            http_client: HTTP client for making requests.

        Returns:
            ApiConfig with authentication details.
        """

        if not self._api_url:
            self._api_url = make_url_canonical(self._raw_api_url, http_client)
        auth_token = self._get_auth_token(http_client)
        token = self._get_api_token(http_client, auth_token)
        return ApiConfig(
            api_url=self._api_url,
            auth_url=self._auth_url,
            token=token,
            account_id=self._account_id,
            user=self._user,
            password=self._password
        )


class ConfigFileAuthenticator(FuzzballAuthenticator):
    """Authenticator using configuration file.

    This authenticator reads authentication details from a YAML configuration
    file compatible with the Fuzzball CLI.
    """

    def __init__(self, config_path: pathlib.Path, context: str | None = None):
        self._config_path = config_path
        self._context = context
        self._config = self._load_config_file()

    def _load_config_file(self) -> dict[str, Any]:
        """Load and parse the configuration file.

        Returns:
            The parsed configuration as a dictionary.

        Raises:
            IOError: If the file cannot be read.
            ValueError: If the file cannot be parsed or has invalid format.
        """
        try:
            with open(self._config_path, "r") as f:
                config = yaml.safe_load(f)
        except IOError as e:
            raise IOError(f"Failed to read configuration file {self._config_path}: {e}")
        except yaml.YAMLError as e:
            raise ValueError(f"Failed to parse configuration file {self._config_path}: {e}")

        if not isinstance(config, dict):
            raise ValueError("Configuration file has invalid format (not a dictionary)")

        return config

    def _determine_context(self) -> str:
        """Determine which context to use.

        Returns:
            The name of the context to use.

        Raises:
            ValueError: If no context is specified.
        """
        context = self._context or self._config.get("activeContext")
        if context is None:
            raise ValueError(
                "No active context specified in config or provided as argument"
            )
        return context

    def _extract_context_info(self, context_name: str) -> dict[str, Any]:
        """Extract connection information from the specified context.

        Args:
            context_name: Name of the context to extract.

        Returns:
            The context configuration dictionary.

        Raises:
            ValueError: If the context is not found.
        """
        for context in self._config.get("contexts", []):
            if context["name"] == context_name:
                return context
        raise ValueError(f"Context '{context_name}' not found in configuration file")


    def authenticate(self, http_client: urllib3.PoolManager) -> ApiConfig:
        """Perform config file authentication.

        Args:
            http_client: HTTP client for making requests.

        Returns:
            ApiConfig with authentication details.
        """

        context_name = self._determine_context()
        context = self._extract_context_info(context_name)
        api_url = make_url_canonical(context["address"], http_client)
        return ApiConfig(
            api_url=api_url,
            auth_url=context["oidcServerURL"],
            token=context["auth"]["credentials"]["token"],
            account_id=context["currentaccountid"]
        )


class FuzzballClient:
    """
    A minimal client for interacting with the Fuzzball API.

    Handles authentication, configuration management, and job submission
    for Nextflow pipelines to the Fuzzball cluster.
    """

    def __init__(self, authenticator: FuzzballAuthenticator, ca_cert_file: str | None = None):
        """Initialize client with an authenticator.

        Args:
            authenticator: Authentication strategy to use.
            ca_cert_file: Optional CA certificate file path.
        """
        self._authenticator = authenticator
        self._ca_cert_file = ca_cert_file

        # These will be set during initialization
        self._api_config: ApiConfig
        self._fb_version: str
        self._http: urllib3.PoolManager

        self._initialize()

    def _initialize(self) -> None:
        """Initialize the client using the provided authenticator."""
        self._setup_http_client()
        self._api_config = self._authenticator.authenticate(self._http)
        self._validate_connection()

    def _setup_http_client(self) -> None:
        """Setup urllib3 HTTP client with appropriate SSL configuration."""
        if self._ca_cert_file:
            ssl_context = ssl.create_default_context()
            ssl_context.load_verify_locations(self._ca_cert_file)
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

    def _validate_connection(self) -> None:
        """Validate connection to Fuzzball API and get version.

        Raises:
            ValueError: If connection fails or version cannot be retrieved.
        """

        try:
            response = self._request("GET", "/version")
            version_data = json.loads(response.data.decode("utf-8"))
            self._fb_version = ".".join(version_data["version"].split(".")[0:2])
            logger.info(f"Connected to Fuzzball version {self._fb_version} API server")
        except urllib3.exceptions.HTTPError as e:
            raise ValueError(f"Failed to connect to Fuzzball API: {e}")
        except Exception as e:
            raise ValueError(f"Unexpected error occurred: {e}")

    @property
    def _headers(self) -> dict[str, str]:
        """Return the headers required for API requests.

        Returns:
            Dictionary of HTTP headers for API requests.

        Raises:
            ValueError: If authentication token is not available.
        """
        if not self._api_config:
            raise ValueError("Authentication token is not available.")
        return {
            "Authorization": f"Bearer {self._api_config.token}",
            "Content-Type": "application/json",
        }

    def _request(
        self,
        method: str,
        endpoint: str,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> urllib3.HTTPResponse:
        """Make an API request to the Fuzzball server.

        Args:
            method: HTTP method (GET, POST, etc.).
            endpoint: API endpoint path.
            data: Optional data to send in request body.
            headers: Optional custom headers.

        Returns:
            HTTP response from the server.

        Raises:
            urllib3.exceptions.HTTPError: If the request fails.
        """
        url = f"{self._api_config.api_url.rstrip('/')}/{endpoint.lstrip('/')}"
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
            yaml_str = yaml.dump(self._api_config.cli_config)
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

        if self._api_config.user:  # Direct login
            user_secret_name = f"{secret_name}-user"
            pass_secret_name = f"{secret_name}-pass"
            user_secret_id = self.create_value_secret(
                user_secret_name, base64.b64encode(self._api_config.user.encode()).decode()
            )
            pass_secret_id = self.create_value_secret(
                pass_secret_name, base64.b64encode(self._api_config.password.encode()).decode()
            )
            setup_env.extend(
                [
                    f"FB_USER_SECRET=secret://user/{user_secret_name}",
                    f"FB_PASS_SECRET=secret://user/{pass_secret_name}",
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
            {f'curl -s $CURL_CA_OPT -X DELETE "{self._api_config.api_url}/secrets/{config_secret_id}" -H "Authorization: Bearer $TOKEN" &' if config_secret_id else ""}
            {f'curl -s $CURL_CA_OPT -X DELETE "{self._api_config.api_url}/secrets/{cert_secret_id}" -H "Authorization: Bearer $TOKEN" &' if cert_secret_id else ""}
            {f'curl -s $CURL_CA_OPT -X DELETE "{self._api_config.api_url}/secrets/{user_secret_id}" -H "Authorization: Bearer $TOKEN" &' if user_secret_id else ""}
            {f'curl -s $CURL_CA_OPT -X DELETE "{self._api_config.api_url}/secrets/{pass_secret_id}" -H "Authorization: Bearer $TOKEN" &' if pass_secret_id else ""}
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

# Factory functions for easy client creation
def create_direct_login_client(
    api_url: str,
    auth_url: str,
    user: str,
    password: str,
    account_id: str,
    ca_cert_file: str | None = None,
) -> FuzzballClient:
    """Create a client using direct login authentication.

    Args:
        api_url: API URL of the Fuzzball cluster.
        auth_url: Authentication URL of the Fuzzball cluster.
        user: Username for authentication.
        password: Password for authentication.
        account_id: Fuzzball account ID.
        ca_cert_file: Optional CA certificate file path.

    Returns:
        Configured FuzzballClient instance.
    """
    authenticator = DirectLoginAuthenticator(
        api_url=api_url,
        auth_url=auth_url,
        user=user,
        password=password,
        account_id=account_id,
    )
    return FuzzballClient(authenticator, ca_cert_file)


def create_config_file_client(
    config_path: pathlib.Path,
    context: str | None = None,
    ca_cert_file: str | None = None,
) -> FuzzballClient:
    """Create a client using config file authentication.

    Args:
        config_path: Path to the Fuzzball configuration file.
        context: Optional context name to use from config.
        ca_cert_file: Optional CA certificate file path.

    Returns:
        Configured FuzzballClient instance.
    """
    authenticator = ConfigFileAuthenticator(config_path, context)
    return FuzzballClient(authenticator, ca_cert_file)


def create_fuzzball_client(
    config_path: pathlib.Path | None = None,
    context: str | None = None,
    ca_cert_file: str | None = None,
    api_url: str | None = None,
    auth_url: str | None = None,
    user: str | None = None,
    password: str | None = None,
    account_id: str | None = None,
) -> FuzzballClient:
    """Factory function to create appropriate client type based on parameters.

    Args:
        config_path: Path to the Fuzzball configuration file.
        context: Optional context name to use from config.
        ca_cert_file: Optional CA certificate file path.
        api_url: API URL for direct login.
        auth_url: Authentication URL for direct login.
        user: Username for direct login.
        password: Password for direct login.
        account_id: Account ID for direct login.

    Returns:
        Configured FuzzballClient instance.

    Raises:
        ValueError: If required parameters are missing.
    """
    if user:
        if not all([api_url, auth_url, password, account_id]):
            raise ValueError("For direct login, all credentials must be provided")
        return create_direct_login_client(
            api_url=api_url,
            auth_url=auth_url,
            user=user,
            password=password,
            account_id=account_id,
            ca_cert_file=ca_cert_file,
        )
    else:
        if not config_path:
            raise ValueError("Config path must be provided for config file authentication")
        return create_config_file_client(
            config_path=config_path,
            context=context,
            ca_cert_file=ca_cert_file,
        )

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
              %(prog)s -- nextflow run -profile fuzzball \\
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
            else pathlib.Path(f"{os.environ['XDG_CONFIG_HOME']}/fuzzball/config.yaml").expanduser()
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
        help="Fuzzball account ID for direct login [$FUZZBALL_ACCOUNT_ID]",
        default=os.environ.get("FUZZBALL_ACCOUNT_ID", ""),
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
        password = None
        if args.user:
            if args.password:
                password = getpass.getpass("Enter Fuzzball password: ")
            else:
                password = os.environ.get("FUZZBALL_PASSWORD")
            if not password:
                die(
                    "Password is required for direct login. Use --password or set FUZZBALL_PASSWORD."
                )

        fb_client = None
        fb_client =  create_fuzzball_client(
            args.fuzzball_config.expanduser(),
            args.context,
            args.ca_cert,
            args.api_url,
            args.auth_url,
            args.user,
            password,
            args.account_id
        )

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
