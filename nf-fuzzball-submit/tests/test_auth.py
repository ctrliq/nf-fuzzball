"""Tests for nf_fuzzball_submit.auth module."""

import json
import pathlib
import tempfile
from unittest.mock import Mock, call, patch

import pytest

from nf_fuzzball_submit.auth import ConfigFileAuthenticator, DeviceLoginAuthenticator, DirectLoginAuthenticator
from nf_fuzzball_submit.models import ApiConfig


class TestDirectLoginAuthenticator:
    """Tests for DirectLoginAuthenticator class."""

    def test_authenticator_creation_with_valid_params(self):
        """Test DirectLoginAuthenticator creation with valid parameters."""
        auth = DirectLoginAuthenticator(
            api_url="https://api.example.com",
            auth_url="https://auth.example.com/auth/realms/test",
            user="test@example.com",
            password="password123",
            account_id="account-123",
        )

        assert auth._raw_api_url == "https://api.example.com"
        assert auth._auth_url == "https://auth.example.com/auth/realms/test"
        assert auth._user == "test@example.com"
        assert auth._password == "password123"
        assert auth._account_id == "account-123"

    def test_authenticator_creation_missing_params_raises_error(self):
        """Test DirectLoginAuthenticator raises error with missing parameters."""
        with pytest.raises(ValueError, match="api-url, auth-url, user, password, and account-id are required"):
            DirectLoginAuthenticator(
                api_url="",
                auth_url="https://auth.example.com",
                user="test@example.com",
                password="password123",
                account_id="account-123",
            )

    @patch("nf_fuzzball_submit.auth.get_canonical_api_url")
    def test_authenticate_success(self, mock_get_canonical_url, mock_http_client):
        """Test successful authentication flow — refresh token is extracted and stored."""
        mock_get_canonical_url.return_value = "https://api.example.com/v4"

        auth_response = Mock()
        auth_response.status = 200
        auth_response.data = json.dumps({
            "access_token": "auth-token-123",
            "refresh_token": "refresh-token-789",
        }).encode()

        api_response = Mock()
        api_response.status = 200
        api_response.data = json.dumps({"token": "api-token-456"}).encode()

        mock_http_client.request.side_effect = [auth_response, api_response]

        auth = DirectLoginAuthenticator(
            api_url="https://api.example.com",
            auth_url="https://auth.example.com/auth/realms/test",
            user="test@example.com",
            password="password123",
            account_id="account-123",
        )

        config = auth.authenticate(mock_http_client)

        assert isinstance(config, ApiConfig)
        assert config.api_url == "https://api.example.com/v4"
        assert config.auth_url == "https://auth.example.com/auth/realms/test"
        assert config.token == "api-token-456"
        assert config.account_id == "account-123"
        assert config.refresh_token == "refresh-token-789"
        # Credentials must not be stored on the config
        assert not hasattr(config, "user")
        assert not hasattr(config, "password")

        assert mock_http_client.request.call_count == 2

    def test_get_auth_token_missing_refresh_token(self, mock_http_client):
        """Test that missing refresh token in Keycloak response raises an error."""
        mock_response = Mock()
        mock_response.status = 200
        # Keycloak response with access_token but no refresh_token
        mock_response.data = json.dumps({"access_token": "auth-token-123"}).encode()
        mock_http_client.request.return_value = mock_response

        auth = DirectLoginAuthenticator(
            api_url="https://api.example.com/v4",
            auth_url="https://auth.example.com/auth/realms/test",
            user="test@example.com",
            password="password123",
            account_id="account-123",
        )

        with pytest.raises(ValueError, match="No refresh token in response from auth server"):
            auth.authenticate(mock_http_client)

    def test_get_auth_token_failure(self, mock_http_client):
        """Test authentication failure when getting auth token."""
        mock_response = Mock()
        mock_response.status = 401
        mock_http_client.request.return_value = mock_response

        auth = DirectLoginAuthenticator(
            api_url="https://api.example.com/v4",
            auth_url="https://auth.example.com/auth/realms/test",
            user="test@example.com",
            password="wrong-password",
            account_id="account-123",
        )

        with pytest.raises(ValueError, match="Failed to obtain auth token: HTTP 401"):
            auth.authenticate(mock_http_client)

    def test_get_auth_token_missing_in_response(self, mock_http_client):
        """Test handling when access token is missing from auth response."""
        mock_response = Mock()
        mock_response.status = 200
        mock_response.data = json.dumps({"some_other_field": "value"}).encode()
        mock_http_client.request.return_value = mock_response

        auth = DirectLoginAuthenticator(
            api_url="https://api.example.com/v4",
            auth_url="https://auth.example.com/auth/realms/test",
            user="test@example.com",
            password="password123",
            account_id="account-123",
        )

        with pytest.raises(ValueError, match="No access token in response"):
            auth.authenticate(mock_http_client)

    @patch("nf_fuzzball_submit.auth.get_canonical_api_url")
    def test_get_api_token_failure(self, mock_get_canonical_url, mock_http_client):
        """Test failure when getting API token."""
        mock_get_canonical_url.return_value = "https://api.example.com/v4"

        # Mock successful auth token response, failed API token response
        auth_response = Mock()
        auth_response.status = 200
        auth_response.data = json.dumps({
            "access_token": "auth-token-123",
            "refresh_token": "refresh-token-789",
        }).encode()

        api_response = Mock()
        api_response.status = 403

        mock_http_client.request.side_effect = [auth_response, api_response]

        auth = DirectLoginAuthenticator(
            api_url="https://api.example.com",
            auth_url="https://auth.example.com/auth/realms/test",
            user="test@example.com",
            password="password123",
            account_id="account-123",
        )

        with pytest.raises(ValueError, match="Failed to obtain API token: HTTP 403"):
            auth.authenticate(mock_http_client)


class TestDeviceLoginAuthenticator:
    """Tests for DeviceLoginAuthenticator class."""

    # Reusable device authorization response body
    DEVICE_AUTH_BODY = {
        "device_code": "dev-code-abc",
        "verification_uri_complete": "https://auth.example.com/activate?code=XXXX",
        "expires_in": 300,
        "interval": 5,
    }

    def _device_auth_response(self):
        r = Mock()
        r.status = 200
        r.data = json.dumps(self.DEVICE_AUTH_BODY).encode()
        return r

    def _poll_response(self, body, status=200):
        r = Mock()
        r.status = status
        r.data = json.dumps(body).encode()
        return r

    def test_creation_with_valid_params(self):
        """Test DeviceLoginAuthenticator creation with valid parameters."""
        auth = DeviceLoginAuthenticator(
            api_url="https://api.example.com",
            auth_url="https://auth.example.com/auth/realms/test",
            account_id="account-123",
        )
        assert auth._raw_api_url == "https://api.example.com"
        assert auth._auth_url == "https://auth.example.com/auth/realms/test"
        assert auth._account_id == "account-123"

    def test_creation_missing_params_raises_error(self):
        """Test DeviceLoginAuthenticator raises error with missing parameters."""
        with pytest.raises(ValueError, match="api-url, auth-url, and account-id are required"):
            DeviceLoginAuthenticator(
                api_url="",
                auth_url="https://auth.example.com",
                account_id="account-123",
            )

    @patch("nf_fuzzball_submit.auth.time.sleep")
    @patch("nf_fuzzball_submit.auth.time.time")
    @patch("nf_fuzzball_submit.auth.get_canonical_api_url")
    def test_authenticate_success(self, mock_get_canonical_url, mock_time, mock_sleep, mock_http_client):
        """Test successful full authentication flow — returns ApiConfig with refresh token."""
        mock_get_canonical_url.return_value = "https://api.example.com/v4"
        mock_time.side_effect = [0, 1]  # deadline=300, loop check passes

        api_token_response = Mock()
        api_token_response.status = 200
        api_token_response.data = json.dumps({"token": "api-token-456"}).encode()

        mock_http_client.request.side_effect = [
            self._device_auth_response(),
            self._poll_response({"access_token": "kc-token", "refresh_token": "refresh-xyz"}),
            api_token_response,
        ]

        auth = DeviceLoginAuthenticator(
            api_url="https://api.example.com",
            auth_url="https://auth.example.com/auth/realms/test",
            account_id="account-123",
        )
        config = auth.authenticate(mock_http_client)

        assert isinstance(config, ApiConfig)
        assert config.token == "api-token-456"
        assert config.refresh_token == "refresh-xyz"
        assert config.account_id == "account-123"

    @patch("nf_fuzzball_submit.auth.time.sleep")
    @patch("nf_fuzzball_submit.auth.time.time")
    def test_authorization_pending_then_success(self, mock_time, mock_sleep, mock_http_client):
        """Test that authorization_pending is retried and succeeds on the next poll."""
        mock_time.side_effect = [0, 1, 2]  # deadline=300, two loop checks

        mock_http_client.request.side_effect = [
            self._device_auth_response(),
            self._poll_response({"error": "authorization_pending"}, status=400),
            self._poll_response({"access_token": "kc-token", "refresh_token": "refresh-xyz"}),
        ]

        auth = DeviceLoginAuthenticator(
            api_url="https://api.example.com",
            auth_url="https://auth.example.com/auth/realms/test",
            account_id="account-123",
        )
        access_token, refresh_token = auth._get_auth_token(mock_http_client)

        assert access_token == "kc-token"
        assert refresh_token == "refresh-xyz"
        assert mock_sleep.call_count == 2

    @patch("nf_fuzzball_submit.auth.time.sleep")
    @patch("nf_fuzzball_submit.auth.time.time")
    def test_slow_down_increases_interval(self, mock_time, mock_sleep, mock_http_client):
        """Test that slow_down response increases the polling interval by 5s."""
        mock_time.side_effect = [0, 1, 2]

        mock_http_client.request.side_effect = [
            self._device_auth_response(),
            self._poll_response({"error": "slow_down"}, status=400),
            self._poll_response({"access_token": "kc-token", "refresh_token": "refresh-xyz"}),
        ]

        auth = DeviceLoginAuthenticator(
            api_url="https://api.example.com",
            auth_url="https://auth.example.com/auth/realms/test",
            account_id="account-123",
        )
        auth._get_auth_token(mock_http_client)

        # First sleep uses original interval (5), second uses increased interval (10)
        assert mock_sleep.call_args_list == [call(5), call(10)]

    @patch("nf_fuzzball_submit.auth.time.sleep")
    @patch("nf_fuzzball_submit.auth.time.time")
    def test_unknown_error_raises(self, mock_time, mock_sleep, mock_http_client):
        """Test that an unexpected error code from the poll endpoint raises ValueError."""
        mock_time.side_effect = [0, 1]

        mock_http_client.request.side_effect = [
            self._device_auth_response(),
            self._poll_response(
                {"error": "access_denied", "error_description": "User denied access"},
                status=400,
            ),
        ]

        auth = DeviceLoginAuthenticator(
            api_url="https://api.example.com",
            auth_url="https://auth.example.com/auth/realms/test",
            account_id="account-123",
        )
        with pytest.raises(ValueError, match="access_denied"):
            auth._get_auth_token(mock_http_client)

    @patch("nf_fuzzball_submit.auth.time.sleep")
    @patch("nf_fuzzball_submit.auth.time.time")
    def test_timeout_raises(self, mock_time, mock_sleep, mock_http_client):
        """Test that expiry of the device code raises ValueError."""
        # deadline = 0 + 300 = 300; loop check returns 301 → loop never runs
        mock_time.side_effect = [0, 301]

        mock_http_client.request.return_value = self._device_auth_response()

        auth = DeviceLoginAuthenticator(
            api_url="https://api.example.com",
            auth_url="https://auth.example.com/auth/realms/test",
            account_id="account-123",
        )
        with pytest.raises(ValueError, match="timed out"):
            auth._get_auth_token(mock_http_client)

        mock_sleep.assert_not_called()

    def test_device_auth_request_failure_raises(self, mock_http_client):
        """Test that a failed device authorization request raises ValueError."""
        mock_http_client.request.return_value = Mock(status=400)

        auth = DeviceLoginAuthenticator(
            api_url="https://api.example.com",
            auth_url="https://auth.example.com/auth/realms/test",
            account_id="account-123",
        )
        with pytest.raises(ValueError, match="Device authorization request failed: HTTP 400"):
            auth._get_auth_token(mock_http_client)

    @patch("nf_fuzzball_submit.auth.time.sleep")
    @patch("nf_fuzzball_submit.auth.time.time")
    def test_missing_access_token_in_poll_response_raises(self, mock_time, mock_sleep, mock_http_client):
        """Test that a successful poll response missing access_token raises ValueError."""
        mock_time.side_effect = [0, 1]

        mock_http_client.request.side_effect = [
            self._device_auth_response(),
            self._poll_response({"refresh_token": "refresh-xyz"}),
        ]

        auth = DeviceLoginAuthenticator(
            api_url="https://api.example.com",
            auth_url="https://auth.example.com/auth/realms/test",
            account_id="account-123",
        )
        with pytest.raises(ValueError, match="No access token in device auth response"):
            auth._get_auth_token(mock_http_client)

    @patch("nf_fuzzball_submit.auth.time.sleep")
    @patch("nf_fuzzball_submit.auth.time.time")
    def test_missing_refresh_token_in_poll_response_raises(self, mock_time, mock_sleep, mock_http_client):
        """Test that a successful poll response missing refresh_token raises ValueError."""
        mock_time.side_effect = [0, 1]

        mock_http_client.request.side_effect = [
            self._device_auth_response(),
            self._poll_response({"access_token": "kc-token"}),
        ]

        auth = DeviceLoginAuthenticator(
            api_url="https://api.example.com",
            auth_url="https://auth.example.com/auth/realms/test",
            account_id="account-123",
        )
        with pytest.raises(ValueError, match="No refresh token in device auth response"):
            auth._get_auth_token(mock_http_client)


class TestConfigFileAuthenticator:
    """Tests for ConfigFileAuthenticator class."""

    def test_authenticator_creation_with_valid_config(self, temp_config_file):
        """Test ConfigFileAuthenticator creation with valid config file."""
        auth = ConfigFileAuthenticator(temp_config_file)

        assert auth._config_path == temp_config_file
        assert auth._context is None
        assert isinstance(auth._config, dict)
        assert "activeContext" in auth._config
        assert "contexts" in auth._config

    def test_authenticator_creation_with_context(self, temp_config_file):
        """Test ConfigFileAuthenticator creation with specific context."""
        auth = ConfigFileAuthenticator(temp_config_file, context="test")

        assert auth._context == "test"

    def test_authenticator_nonexistent_file_raises_error(self):
        """Test ConfigFileAuthenticator raises error for nonexistent file."""
        nonexistent_path = pathlib.Path("/nonexistent/config.yaml")

        with pytest.raises(OSError, match="Failed to read configuration file"):
            ConfigFileAuthenticator(nonexistent_path)

    def test_authenticator_invalid_yaml_raises_error(self):
        """Test ConfigFileAuthenticator raises error for invalid YAML."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: content: [")
            temp_path = pathlib.Path(f.name)

        try:
            with pytest.raises(ValueError, match="Failed to parse configuration file"):
                ConfigFileAuthenticator(temp_path)
        finally:
            temp_path.unlink(missing_ok=True)

    def test_authenticator_non_dict_config_raises_error(self):
        """Test ConfigFileAuthenticator raises error for non-dict config."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("- this is a list, not a dict")
            temp_path = pathlib.Path(f.name)

        try:
            with pytest.raises(ValueError, match="Configuration file has invalid format"):
                ConfigFileAuthenticator(temp_path)
        finally:
            temp_path.unlink(missing_ok=True)

    @patch("nf_fuzzball_submit.auth.get_canonical_api_url")
    def test_authenticate_success(self, mock_get_canonical_url, temp_config_file, mock_http_client):
        """Test successful authentication with config file."""
        mock_get_canonical_url.return_value = "https://api.example.com/v4"

        auth = ConfigFileAuthenticator(temp_config_file)
        config = auth.authenticate(mock_http_client)

        assert isinstance(config, ApiConfig)
        assert config.api_url == "https://api.example.com/v4"
        assert config.auth_url == "https://auth.example.com/auth/realms/test-realm"
        assert config.token == "test-token-12345"
        assert config.account_id == "test-account-id"

    def test_determine_context_from_config(self, temp_config_file):
        """Test context determination from config file."""
        auth = ConfigFileAuthenticator(temp_config_file)
        context = auth._determine_context()

        assert context == "test"

    def test_determine_context_from_parameter(self, temp_config_file):
        """Test context determination from parameter."""
        auth = ConfigFileAuthenticator(temp_config_file, context="custom")
        context = auth._determine_context()

        assert context == "custom"

    def test_determine_context_no_active_context_raises_error(self):
        """Test error when no active context is available."""
        config_content = """
contexts:
  - name: test
    address: api.example.com:443
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(config_content.strip())
            temp_path = pathlib.Path(f.name)

        try:
            auth = ConfigFileAuthenticator(temp_path)
            with pytest.raises(ValueError, match="No active context specified"):
                auth._determine_context()
        finally:
            temp_path.unlink(missing_ok=True)

    def test_extract_context_info_nonexistent_context_raises_error(self, temp_config_file):
        """Test error when specified context doesn't exist."""
        auth = ConfigFileAuthenticator(temp_config_file)

        with pytest.raises(ValueError, match="Context 'nonexistent' not found"):
            auth._extract_context_info("nonexistent")
