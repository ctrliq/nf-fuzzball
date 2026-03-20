"""Authentication classes for Fuzzball API."""

import json
import pathlib
import time
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


class KeycloakAuthenticator(FuzzballAuthenticator):
    """Base class for Keycloak-based authenticators.

    Subclasses implement _get_auth_token() for their specific grant type.
    This class provides the shared _get_api_token() and authenticate() logic.
    """

    def __init__(self, api_url: str, auth_url: str, account_id: str):
        """Initialize KeycloakAuthenticator-based classes."""
        self._raw_api_url = api_url  # can leave off the API base path
        self._api_url: str | None = None  # canonical URL resolved on first authenticate()
        self._auth_url = auth_url
        self._account_id = account_id

    @abstractmethod
    def _get_auth_token(self, http_client: urllib3.PoolManager) -> tuple[str, str]:
        """Obtain a Keycloak access token and offline refresh token.

        Returns:
            Tuple of (access_token, refresh_token).
        """

    def _get_api_token(self, http_client: urllib3.PoolManager, auth_token: str) -> str:
        """Exchange a Keycloak access token for a Fuzzball API token.

        Args:
            http_client: HTTP client for making requests.
            auth_token: Keycloak access token.

        Returns:
            The Fuzzball API token.

        Raises:
            ValueError: If the request fails or the token is absent from the response.
        """
        response = http_client.request(
            "GET",
            f"{self._api_url}/accounts/{self._account_id}/token",
            headers={"Authorization": f"Bearer {auth_token}", "Accept": "application/json"},
            timeout=30,
        )
        if response.status >= 400:
            raise ValueError(f"Failed to obtain API token: HTTP {response.status}")
        response_data = json.loads(response.data.decode("utf-8"))
        if "token" not in response_data:
            raise ValueError("No API token in response from API server")
        return response_data["token"]

    def authenticate(self, http_client: urllib3.PoolManager) -> ApiConfig:
        """Authenticate and return an ApiConfig.

        Args:
            http_client: HTTP client for making requests.

        Returns:
            ApiConfig with authentication details.
        """
        if not self._api_url:
            self._api_url = get_canonical_api_url(self._raw_api_url, http_client)
        access_token, refresh_token = self._get_auth_token(http_client)
        token = self._get_api_token(http_client, access_token)
        return ApiConfig(
            api_url=self._api_url,
            auth_url=self._auth_url,
            token=token,
            account_id=self._account_id,
            refresh_token=refresh_token,
        )


class DirectLoginAuthenticator(KeycloakAuthenticator):
    """Authenticator using OAuth2 password grant (username + password)."""

    def __init__(
        self,
        api_url: str,
        auth_url: str,
        user: str,
        password: str,
        account_id: str,
    ):
        """Initialize direct login authenticator and validate parameters."""
        super().__init__(api_url, auth_url, account_id)
        self._user = user
        self._password = password

        if not all([self._raw_api_url, self._auth_url, self._user, self._password, self._account_id]):
            raise ValueError(
                "For direct login, api-url, auth-url, user, password, and account-id are required.",
            )

    def _get_auth_token(self, http_client: urllib3.PoolManager) -> tuple[str, str]:
        """Password grant with offline_access scope.  Returns (access_token, refresh_token)."""
        data = {
            "client_id": "fuzzball-cli",
            "grant_type": "password",
            "username": self._user,
            "password": self._password,
            "scope": "offline_access",
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
        if "refresh_token" not in response_data:
            raise ValueError("No refresh token in response from auth server")
        return response_data["access_token"], response_data["refresh_token"]


class DeviceLoginAuthenticator(KeycloakAuthenticator):
    """Authenticator using OAuth2 device authorization grant.

    The user authenticates in a browser; no password is passed to this process.
    Requires 'OAuth 2.0 Device Authorization Grant' to be enabled on the
    fuzzball-cli Keycloak client.
    """

    def __init__(self, api_url: str, auth_url: str, account_id: str):
        """Initialize device login authenticator and validate parameters."""
        super().__init__(api_url, auth_url, account_id)
        if not all([self._raw_api_url, self._auth_url, self._account_id]):
            raise ValueError(
                "For device login, api-url, auth-url, and account-id are required.",
            )

    def _get_auth_token(self, http_client: urllib3.PoolManager) -> tuple[str, str]:
        """Device authorization grant flow.  Returns (access_token, refresh_token).

        Raises:
            ValueError: If the request fails, the user does not authorize in time,
                or the server returns an unexpected error code.
        """
        response = http_client.request(
            "POST",
            f"{self._auth_url.rstrip('/')}/protocol/openid-connect/auth/device",
            body=urlencode({"client_id": "fuzzball-cli", "scope": "offline_access"}).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        if response.status >= 400:
            raise ValueError(f"Device authorization request failed: HTTP {response.status}")
        body = json.loads(response.data.decode("utf-8"))

        device_code: str = body["device_code"]
        expires_in = body.get("expires_in", 300)
        interval = body.get("interval", 5)
        # verification_uri_complete already embeds the user_code as a query param
        verification_uri = body.get("verification_uri_complete") or body["verification_uri"]
        print(f"Open this URL to authenticate (expires in {expires_in}s):\n  {verification_uri}")
        if "verification_uri_complete" not in body:
            print(f"Enter code: {body['user_code']}")

        poll_data: dict[str, str] = {
            "client_id": "fuzzball-cli",
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
        }
        deadline = time.time() + expires_in
        while time.time() < deadline:
            time.sleep(interval)
            response = http_client.request(
                "POST",
                f"{self._auth_url.rstrip('/')}/protocol/openid-connect/token",
                body=urlencode(poll_data).encode("utf-8"),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            )
            body = json.loads(response.data.decode("utf-8"))
            if response.status == 200:
                if "access_token" not in body:
                    raise ValueError("No access token in device auth response")
                if "refresh_token" not in body:
                    raise ValueError("No refresh token in device auth response")
                return body["access_token"], body["refresh_token"]
            error = body.get("error", "")
            if error == "authorization_pending":
                continue
            elif error == "slow_down":
                interval += 5
            else:
                raise ValueError(f"Device authorization failed: {error}: {body.get('error_description', '')}")
        raise ValueError("Device authorization timed out")


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
            OSError: If the file cannot be read.
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

    @classmethod
    def connection_defaults(cls, config_path: pathlib.Path, context: str | None = None) -> dict[str, str | None]:
        """Return api_url, auth_url, and account_id from the config file.

        Intended as a low-precedence fallback for direct/device login flows that
        need these values but would otherwise require explicit flags.  Returns an
        empty dict if the file is absent, unparseable, or the context is not found.

        Args:
            config_path: Path to the fuzzball config file.
            context: Context name to read; falls back to activeContext if None.

        Returns:
            Dict with keys ``api_url``, ``auth_url``, ``account_id`` (values may
            be None if the field is absent in the config).
        """
        try:
            auth = cls(config_path, context)
            context_name = auth._determine_context()
            ctx = auth._extract_context_info(context_name)
            address = ctx.get("address", "")
            if address and not address.startswith("http"):
                address = f"https://{address}"
            return {
                "api_url": address or None,
                "auth_url": ctx.get("oidcServerURL"),
                "account_id": ctx.get("currentaccountid"),
            }
        except Exception:
            return {}

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
