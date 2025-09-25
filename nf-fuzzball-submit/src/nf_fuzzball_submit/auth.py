"""Authentication classes for Fuzzball API."""

import json
import pathlib
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import urlencode

import urllib3
import yaml

from .models import ApiConfig
from .utils import get_canonical_api_url


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
        """Initialize direct login authenticator and validate parameters."""
        self._raw_api_url = api_url  # can leave off the API base path
        self._api_url: str | None = None  # canonical URL
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
        required_params = [
            self._raw_api_url,
            self._auth_url,
            self._user,
            self._password,
            self._account_id,
        ]
        if not all(required_params):
            raise ValueError(
                "For direct login, api-url, auth-url, user, password, and account-id are required.",
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
            body=urlencode(data).encode("utf-8"),
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
            self._api_url = get_canonical_api_url(self._raw_api_url, http_client)
        auth_token = self._get_auth_token(http_client)
        token = self._get_api_token(http_client, auth_token)
        return ApiConfig(
            api_url=self._api_url,
            auth_url=self._auth_url,
            token=token,
            account_id=self._account_id,
            user=self._user,
            password=self._password,
        )


class ConfigFileAuthenticator(FuzzballAuthenticator):
    """Authenticator using configuration file.

    This authenticator reads authentication details from a YAML configuration
    file compatible with the Fuzzball CLI.
    """

    def __init__(self, config_path: pathlib.Path, context: str | None = None):
        """Initialize ConfigFileAuthenticator and read/validate config file."""
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
            with pathlib.Path(self._config_path).open("r") as f:
                config = yaml.safe_load(f)
        except OSError as e:
            raise OSError(f"Failed to read configuration file {self._config_path}") from e
        except yaml.YAMLError as e:
            raise ValueError(f"Failed to parse configuration file {self._config_path}") from e

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
            raise ValueError("No active context specified in config or provided as argument")
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
        api_url = get_canonical_api_url(context["address"], http_client)
        return ApiConfig(
            api_url=api_url,
            auth_url=context["oidcServerURL"],
            token=context["auth"]["credentials"]["token"],
            account_id=context["currentaccountid"],
        )
