"""Data models for nf-fuzzball-submit."""

import base64
import pathlib
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

# Namespace for content-based UUIDs
NAMESPACE_CONTENT = uuid.UUID("71c91ef2-0f9b-47f3-988b-5725d2f67599")


@dataclass
class ApiConfig:
    """Configuration for Fuzzball API connection."""

    api_url: str  # full url with schema and basepath for the API
    auth_url: str  # full url with schema and path
    token: str
    account_id: str
    user: str | None = None
    password: str | None = None

    @property
    def api_host(self) -> str:
        """Hostname of the API Server.

        Returns:
            str: Host name of the api.
        """
        return urlparse(self.api_url).hostname or "unknown"

    @property
    def api_port(self) -> int:
        """Port number of the API.

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
                        "credentials": {"token": self.token},
                    },
                    "realm": "",
                    "currentaccountid": self.account_id,
                    "accounts": [{"accountid": self.account_id, "accountalias": "n/a"}],
                }
            ],
        }


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
            raise IOError(f"Failed to read file {local_path}")
        except Exception:
            raise Exception(f"Error processing file {local_path}")
