"""Fuzzball client and factory functions."""

import argparse
import base64
import json
import logging
import pathlib
import shlex
import ssl
import sys
import textwrap
import uuid
from typing import Any

import urllib3
import yaml
from jinja2 import Environment, PackageLoader
from urllib3.util import Retry

from .auth import ConfigFileAuthenticator, DirectLoginAuthenticator, FuzzballAuthenticator
from .models import NAMESPACE_CONTENT, ApiConfig
from .utils import find_and_import_local_files

logger = logging.getLogger(__name__)

# Constants
DATA_MOUNT = "/data"
SCRATCH_MOUNT = "/scratch"


class FuzzballClient:
    """A minimal client for interacting with the Fuzzball API.

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
        self._jinja_env = Environment(
            loader=PackageLoader('nf_fuzzball_submit', 'templates'),
            autoescape=False,  # Shell scripts should not be HTML-escaped  # noqa: S701
        )

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
                retries=Retry(total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504]),
            )
        else:
            self._http = urllib3.PoolManager(
                retries=Retry(total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504]),
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
            raise ValueError("Failed to connect to Fuzzball API") from e
        except Exception as e:
            raise ValueError("Unexpected error occurred") from e

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
    ) -> urllib3.BaseHTTPResponse:
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
            elif request_headers.get("Content-Type") == "application/x-www-form-urlencoded":
                from urllib.parse import urlencode

                body = urlencode(data).encode("utf-8")
            else:
                body = json.dumps(data).encode("utf-8")

        response = self._http.request(
            method.upper(),
            url,
            body=body,
            headers=request_headers,
            timeout=30,
        )

        if response.status >= 400:
            raise urllib3.exceptions.HTTPError(
                f"HTTP {response.status}: {response.reason} {response.data.decode('utf-8')}",
            )

        return response

    def _encode_config(self) -> str:
        """Return a base64 encoded version of the minimal Fuzzball configuration file.

        Contains only the active context.

        Returns:
            Base64 encoded config string safe for transport

        Raises:
            ValueError: If encoding fails
        """
        try:
            yaml_str = yaml.dump(self._api_config.cli_config)
            return base64.b64encode(yaml_str.encode("utf-8")).decode("utf-8")
        except Exception as e:
            raise ValueError("Failed to encode Fuzzball configuration") from e

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
            with pathlib.Path(self._ca_cert_file).open("rb") as f:
                return base64.b64encode(f.read()).decode("utf-8")
        except OSError:
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
                    secret_update = {"value": {"value": secret_value}}
                    self._request("PATCH", f"/secrets/{secret_id}", data=secret_update)
                    return secret_id
        except urllib3.exceptions.HTTPError as e:
            logger.warning(f"Could not list secrets, assuming secret does not exist: {e}")

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
        job_name = args.job_name if len(args.job_name) > 0 else str(uuid.uuid5(NAMESPACE_CONTENT, nextflow_cmd_str))
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

        mangled_nextflow_cmd, config_files = find_and_import_local_files(args.nextflow_cmd, files)
        mangled_nextflow_cmd_str = shlex.join(mangled_nextflow_cmd)

        # download url for the plugin (until it's in the nextflow plugin registry)
        plugin_uri = f"{args.plugin_base_uri}/{plugin_tag}/nf-fuzzball-{plugin_tag}-stable-{self._fb_version}.zip"
        # check that the URL exists
        if plugin_uri.startswith("http://") or plugin_uri.startswith("https://"):
            try:
                response = self._http.request("HEAD", plugin_uri, timeout=10)
                if response.status >= 400:
                    raise urllib3.exceptions.HTTPError(f"HTTP {response.status}: {response.reason}")
            except urllib3.exceptions.HTTPError as e:
                raise Exception(
                    f"Failed to access nf-fuzzball plugin for this version of Fuzzball at {plugin_uri}",
                ) from e

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
                user_secret_name,
                base64.b64encode(self._api_config.user.encode()).decode(),
            )
            pass_secret_id = self.create_value_secret(
                pass_secret_name,
                base64.b64encode(self._api_config.password.encode()).decode(),
            )
            setup_env.extend(
                [
                    f"FB_USER_SECRET=secret://user/{user_secret_name}",
                    f"FB_PASS_SECRET=secret://user/{pass_secret_name}",
                ],
            )
        # Config file login
        config_secret_name = f"{secret_name}-conf"
        config_secret_id = self.create_value_secret(config_secret_name, self._encode_config())
        setup_env.append(f"FB_CONFIG_SECRET=secret://user/{config_secret_name}")

        if self._ca_cert_file:
            cert_secret_name = f"{secret_name}-cert"
            cert_secret_id = self.create_value_secret(cert_secret_name, self._encode_ca_cert())
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
        """).encode("utf-8"),
        ).decode("utf-8")
        nxf_fuzzball_config_name = str(uuid.uuid5(NAMESPACE_CONTENT, nxf_fuzzball_config))

        # Note: the setup job uses /tmp as the cwd in order to manually create the working dir
        #       for nextflow as part of the job. This makes sure ownership and permissions are as expected
        # Prepare cleanup secrets list for template
        cleanup_secrets = [
            config_secret_id,
            cert_secret_id,
            user_secret_id,
            pass_secret_id,
        ]

        setup_script = self._jinja_env.get_template("setup.sh.j2").render(
            wd=wd,
            home=home,
            plugin_version=plugin_version,
            scratch_mount=SCRATCH_MOUNT,
            config_path=config_path,
            ca_cert_secret=self._ca_cert_file is not None,
            ca_cert_path=ca_cert_path,
            api_url=self._api_config.api_url,
            cleanup_secrets=cleanup_secrets,
            files=files,
            nxf_fuzzball_config_name=nxf_fuzzball_config_name,
            config_files=config_files,
        )

        nextflow_script = self._jinja_env.get_template("nextflow.sh.j2").render(
            mangled_nextflow_cmd_str=mangled_nextflow_cmd_str,
            files=files,
            nxf_fuzzball_config_name=nxf_fuzzball_config_name,
        )

        workflow: dict[str, Any] = {
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
                            f"/tmp/{nxf_fuzzball_config_name}": f"file://{nxf_fuzzball_config_name}",  # noqa: S108
                        },
                        "mounts": mounts,
                        "cwd": "/tmp",  # noqa: S108
                        "script": setup_script,
                        "env": setup_env,
                        "policy": {"timeout": {"execute": "5m"}},
                        "resource": {"cpu": {"cores": 1}, "memory": {"size": "1GB"}},
                    },
                    "nextflow": {
                        "image": {"uri": f"docker://nextflow/nextflow:{args.nextflow_version}"},
                        "mounts": mounts,
                        "cwd": wd,
                        "script": nextflow_script,
                        "env": env + ([f"FB_CA_CERT={ca_cert_path}"] if self._ca_cert_file is not None else []),
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
            workflow["definition"]["jobs"]["setup"]["files"][f"/tmp/{f.remote_name}"] = (  # noqa: S108
                f"file://{f.remote_name}"
            )

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
    if not config_path:
        raise ValueError("Config path must be provided for config file authentication")
    return create_config_file_client(
        config_path=config_path,
        context=context,
        ca_cert_file=ca_cert_file,
    )
