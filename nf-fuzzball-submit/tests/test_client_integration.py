"""Integration tests for FuzzballClient that don't require real API calls."""

import json
import pathlib
from unittest.mock import Mock, patch

import pytest

from nf_fuzzball_submit.auth import ConfigFileAuthenticator, DirectLoginAuthenticator
from nf_fuzzball_submit.client import FuzzballClient, create_fuzzball_client


class TestFuzzballClientInitialization:
    """Tests for FuzzballClient initialization."""

    @patch("nf_fuzzball_submit.auth.get_canonical_api_url")
    @patch("urllib3.PoolManager")
    def test_client_initialization_with_config_auth(self, mock_pool_manager, mock_canonical_url, temp_config_file, mock_http_client):
        """Test client initialization with config file authentication."""
        mock_canonical_url.return_value = "https://api.example.com/v4"
        mock_pool_manager.return_value = mock_http_client

        # Mock version response
        version_response = Mock()
        version_response.status = 200
        version_response.data = json.dumps({"version": "4.1.2"}).encode()
        mock_http_client.request.return_value = version_response

        auth = ConfigFileAuthenticator(temp_config_file)
        client = FuzzballClient(auth)

        assert client._fb_version == "4.1"
        assert client._api_config.api_url == "https://api.example.com/v4"

    @patch("nf_fuzzball_submit.auth.get_canonical_api_url")
    @patch("urllib3.PoolManager")
    def test_client_initialization_with_direct_login_auth(self, mock_pool_manager, mock_canonical_url, mock_http_client):
        """Test client initialization with direct login authentication."""
        mock_canonical_url.return_value = "https://api.example.com/v4"
        mock_pool_manager.return_value = mock_http_client

        # Mock auth flow responses
        auth_response = Mock()
        auth_response.status = 200
        auth_response.data = json.dumps({"access_token": "auth-token"}).encode()

        api_response = Mock()
        api_response.status = 200
        api_response.data = json.dumps({"token": "api-token"}).encode()

        version_response = Mock()
        version_response.status = 200
        version_response.data = json.dumps({"version": "4.2.0"}).encode()

        mock_http_client.request.side_effect = [auth_response, api_response, version_response]

        auth = DirectLoginAuthenticator(
            api_url="https://api.example.com",
            auth_url="https://auth.example.com/auth/realms/test",
            user="test@example.com",
            password="password",
            account_id="account-123",
        )

        client = FuzzballClient(auth)

        assert client._fb_version == "4.2"
        assert client._api_config.token == "api-token"

    def test_client_initialization_with_ca_cert(self, sample_api_config):
        """Test client initialization with CA certificate."""
        with (
            patch("ssl.create_default_context") as mock_ssl_context,
            patch("urllib3.PoolManager") as mock_pool_manager,
            patch.object(FuzzballClient, "_validate_connection"),
        ):
            mock_context = Mock()
            mock_ssl_context.return_value = mock_context

            auth = Mock()
            auth.authenticate.return_value = sample_api_config

            client = FuzzballClient(auth, ca_cert_file="/path/to/ca.crt")

            # Verify SSL context was configured
            mock_ssl_context.assert_called_once()
            mock_context.load_verify_locations.assert_called_once_with("/path/to/ca.crt")
            # Verify PoolManager was called with SSL context and retries
            mock_pool_manager.assert_called_once()
            call_args = mock_pool_manager.call_args
            assert call_args.kwargs["ssl_context"] == mock_context
            assert "retries" in call_args.kwargs

    def test_client_headers_property(self, sample_api_config, mock_http_client):
        """Test client headers property."""
        with (
            patch.object(FuzzballClient, "_validate_connection"),
            patch("urllib3.PoolManager", return_value=mock_http_client),
        ):
            auth = Mock()
            auth.authenticate.return_value = sample_api_config

            client = FuzzballClient(auth)
            headers = client._headers

            assert headers["Authorization"] == f"Bearer {sample_api_config.token}"
            assert headers["Content-Type"] == "application/json"

    def test_client_headers_without_token_raises_error(self, mock_http_client):
        """Test client headers raises error without token."""
        with (
            patch.object(FuzzballClient, "_validate_connection"),
            patch("urllib3.PoolManager", return_value=mock_http_client),
        ):
            auth = Mock()
            auth.authenticate.return_value = None

            client = FuzzballClient(auth)
            client._api_config = None

            with pytest.raises(ValueError, match="Authentication token is not available"):
                _ = client._headers

    def test_client_request_method(self, sample_api_config, mock_http_client):
        """Test client request method."""
        with (
            patch.object(FuzzballClient, "_validate_connection"),
            patch("urllib3.PoolManager", return_value=mock_http_client),
        ):
            auth = Mock()
            auth.authenticate.return_value = sample_api_config

            client = FuzzballClient(auth)

            # Mock successful response
            mock_response = Mock()
            mock_response.status = 200
            mock_http_client.request.return_value = mock_response

            response = client._request("GET", "/test-endpoint")

            assert response == mock_response
            mock_http_client.request.assert_called_with(
                "GET",
                f"{sample_api_config.api_url}/test-endpoint",
                body=None,
                headers={"Authorization": f"Bearer {sample_api_config.token}", "Content-Type": "application/json"},
                timeout=30,
            )

    def test_client_request_with_json_data(self, sample_api_config, mock_http_client):
        """Test client request with JSON data."""
        with (
            patch.object(FuzzballClient, "_validate_connection"),
            patch("urllib3.PoolManager", return_value=mock_http_client),
        ):
            auth = Mock()
            auth.authenticate.return_value = sample_api_config

            client = FuzzballClient(auth)

            mock_response = Mock()
            mock_response.status = 200
            mock_http_client.request.return_value = mock_response

            test_data = {"key": "value"}
            response = client._request("POST", "/test-endpoint", data=test_data)

            # Verify JSON encoding
            call_args = mock_http_client.request.call_args
            assert json.loads(call_args.kwargs["body"]) == test_data


class TestFactoryFunctions:
    """Tests for client factory functions."""

    def test_create_fuzzball_client_with_user_calls_direct_login(self):
        """Test factory function creates direct login client when user is provided."""
        with patch("nf_fuzzball_submit.client.create_direct_login_client") as mock_create_direct:
            mock_client = Mock()
            mock_create_direct.return_value = mock_client

            result = create_fuzzball_client(
                api_url="https://api.example.com",
                auth_url="https://auth.example.com",
                user="test@example.com",
                password="password",
                account_id="account-123",
            )

            assert result == mock_client
            mock_create_direct.assert_called_once_with(
                api_url="https://api.example.com",
                auth_url="https://auth.example.com",
                user="test@example.com",
                password="password",
                account_id="account-123",
                ca_cert_file=None,
            )

    def test_create_fuzzball_client_without_user_calls_config_file(self):
        """Test factory function creates config file client when no user is provided."""
        config_path = pathlib.Path("/path/to/config.yaml")

        with patch("nf_fuzzball_submit.client.create_config_file_client") as mock_create_config:
            mock_client = Mock()
            mock_create_config.return_value = mock_client

            result = create_fuzzball_client(config_path=config_path, context="test")

            assert result == mock_client
            mock_create_config.assert_called_once_with(
                config_path=config_path,
                context="test",
                ca_cert_file=None,
            )

    def test_create_fuzzball_client_user_missing_credentials_raises_error(self):
        """Test factory function raises error when user is provided but credentials are incomplete."""
        with pytest.raises(ValueError, match="For direct login, all credentials must be provided"):
            create_fuzzball_client(
                api_url="https://api.example.com",
                user="test@example.com",
                # Missing auth_url, password, account_id
            )

    def test_create_fuzzball_client_no_config_path_raises_error(self):
        """Test factory function raises error when no config path is provided for config file auth."""
        with pytest.raises(ValueError, match="Config path must be provided"):
            create_fuzzball_client()  # No user, no config_path
