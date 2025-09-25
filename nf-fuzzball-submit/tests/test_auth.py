"""Tests for nf_fuzzball_submit.auth module."""

import json
import pathlib
import tempfile
from unittest.mock import Mock, patch

import pytest

from nf_fuzzball_submit.auth import ConfigFileAuthenticator, DirectLoginAuthenticator
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
        """Test successful authentication flow."""
        # Mock the canonical URL function
        mock_get_canonical_url.return_value = "https://api.example.com/v4"

        # Mock auth token response
        auth_response = Mock()
        auth_response.status = 200
        auth_response.data = json.dumps({"access_token": "auth-token-123"}).encode()

        # Mock API token response
        api_response = Mock()
        api_response.status = 200
        api_response.data = json.dumps({"token": "api-token-456"}).encode()

        # Configure mock client to return different responses for different calls
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
        assert config.user == "test@example.com"
        assert config.password == "password123"

        # Verify correct API calls were made
        assert mock_http_client.request.call_count == 2

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
        auth_response.data = json.dumps({"access_token": "auth-token-123"}).encode()

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
