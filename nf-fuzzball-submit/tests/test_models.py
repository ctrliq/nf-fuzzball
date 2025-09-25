"""Tests for nf_fuzzball_submit.models module."""

import base64
import pathlib
import uuid
from unittest.mock import patch

import pytest

from nf_fuzzball_submit.models import NAMESPACE_CONTENT, ApiConfig, LocalFile


class TestApiConfig:
    """Tests for ApiConfig class."""

    def test_api_config_creation(self, sample_api_config):
        """Test basic ApiConfig creation."""
        config = sample_api_config
        assert config.api_url == "https://api.example.com/v4"
        assert config.auth_url == "https://auth.example.com/auth/realms/test-realm"
        assert config.token == "test-token-12345"
        assert config.account_id == "test-account-id"
        assert config.user is None
        assert config.password is None

    def test_api_host_property(self, sample_api_config):
        """Test api_host property extraction."""
        assert sample_api_config.api_host == "api.example.com"

    def test_api_host_unknown_for_invalid_url(self):
        """Test api_host returns 'unknown' for invalid URLs."""
        config = ApiConfig(
            api_url="invalid-url",
            auth_url="https://auth.example.com",
            token="token",
            account_id="account",
        )
        assert config.api_host == "unknown"

    def test_api_port_property(self, sample_api_config):
        """Test api_port property extraction."""
        assert sample_api_config.api_port == 443

    def test_api_port_custom(self):
        """Test api_port with custom port."""
        config = ApiConfig(
            api_url="https://api.example.com:8080/v4",
            auth_url="https://auth.example.com",
            token="token",
            account_id="account",
        )
        assert config.api_port == 8080

    def test_api_port_default_443(self):
        """Test api_port defaults to 443 when not specified."""
        config = ApiConfig(
            api_url="https://api.example.com/v4",
            auth_url="https://auth.example.com",
            token="token",
            account_id="account",
        )
        assert config.api_port == 443

    def test_cli_config_generation(self, sample_api_config):
        """Test CLI config generation."""
        cli_config = sample_api_config.cli_config

        assert cli_config["activeContext"] == "nextflow"
        assert len(cli_config["contexts"]) == 1

        context = cli_config["contexts"][0]
        assert context["name"] == "nextflow"
        assert context["address"] == "api.example.com:443"
        assert context["oidcServerURL"] == sample_api_config.auth_url
        assert context["auth"]["credentials"]["token"] == sample_api_config.token
        assert context["currentaccountid"] == sample_api_config.account_id

    def test_cli_config_with_custom_port(self):
        """Test CLI config generation with custom port."""
        config = ApiConfig(
            api_url="https://api.example.com:8080/v4",
            auth_url="https://auth.example.com",
            token="token",
            account_id="account",
        )
        cli_config = config.cli_config
        context = cli_config["contexts"][0]
        assert context["address"] == "api.example.com:8080"


class TestLocalFile:
    """Tests for LocalFile class."""

    def test_local_file_creation(self, temp_file_content):
        """Test basic LocalFile creation."""
        temp_path, content = temp_file_content
        local_file = LocalFile(temp_path)

        # Check that content is base64 encoded
        decoded_content = base64.b64decode(local_file.content.encode())
        assert decoded_content == content

        # Check remote name generation
        expected_uuid = str(uuid.uuid5(NAMESPACE_CONTENT, local_file.content))
        expected_name = f"{expected_uuid}-{temp_path.name}"
        assert local_file.remote_name == expected_name

        # Check remote path
        assert local_file.remote_path == f"/{expected_name}"

    def test_local_file_with_prefix(self, temp_file_content):
        """Test LocalFile creation with remote prefix."""
        temp_path, _ = temp_file_content
        prefix = "config/files"
        local_file = LocalFile(temp_path, prefix)

        expected_uuid = str(uuid.uuid5(NAMESPACE_CONTENT, local_file.content))
        expected_name = f"{expected_uuid}-{temp_path.name}"
        assert local_file.remote_name == expected_name
        assert local_file.remote_path == f"{prefix}/{expected_name}"

    def test_local_file_with_trailing_slash_prefix(self, temp_file_content):
        """Test LocalFile creation with trailing slash in prefix."""
        temp_path, _ = temp_file_content
        prefix = "config/files/"
        local_file = LocalFile(temp_path, prefix)

        expected_uuid = str(uuid.uuid5(NAMESPACE_CONTENT, local_file.content))
        expected_name = f"{expected_uuid}-{temp_path.name}"
        assert local_file.remote_path == f"config/files/{expected_name}"

    def test_local_file_nonexistent_raises_error(self):
        """Test LocalFile creation with nonexistent file raises OSError."""
        nonexistent_path = pathlib.Path("/nonexistent/file.txt")
        with pytest.raises(OSError, match="Failed to read file"):
            LocalFile(nonexistent_path)

    def test_local_file_consistent_uuid_generation(self, temp_file_content):
        """Test that same content generates same UUID."""
        temp_path, _ = temp_file_content

        # Create two LocalFile instances from the same file
        local_file1 = LocalFile(temp_path)
        local_file2 = LocalFile(temp_path)

        # Should have identical remote names (same content = same UUID)
        assert local_file1.remote_name == local_file2.remote_name
        assert local_file1.content == local_file2.content

    @patch("pathlib.Path.open")
    def test_local_file_read_error_handling(self, mock_open_func):
        """Test LocalFile handles read errors gracefully."""
        mock_open_func.side_effect = OSError("Permission denied")

        with pytest.raises(OSError, match="Failed to read file"):
            LocalFile(pathlib.Path("/test/file.txt"))

    def test_namespace_content_uuid_is_consistent(self):
        """Test that NAMESPACE_CONTENT is a consistent UUID."""
        expected_uuid = uuid.UUID("71c91ef2-0f9b-47f3-988b-5725d2f67599")
        assert expected_uuid == NAMESPACE_CONTENT
