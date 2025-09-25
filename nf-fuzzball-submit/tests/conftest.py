"""Pytest configuration and shared fixtures."""

import pathlib
import tempfile
from unittest.mock import Mock

import pytest
import urllib3

from nf_fuzzball_submit.models import ApiConfig


@pytest.fixture
def sample_api_config():
    """Sample API configuration for testing."""
    return ApiConfig(
        api_url="https://api.example.com/v4",
        auth_url="https://auth.example.com/auth/realms/test-realm",
        token="test-token-12345",
        account_id="test-account-id",
        user=None,
        password=None,
    )


@pytest.fixture
def direct_login_api_config():
    """Sample API configuration for direct login testing."""
    return ApiConfig(
        api_url="https://api.example.com/v4",
        auth_url="https://auth.example.com/auth/realms/test-realm",
        token="test-token-12345",
        account_id="test-account-id",
        user="test@example.com",
        password="test-password",
    )


@pytest.fixture
def mock_http_client():
    """Mock HTTP client for testing."""
    mock_client = Mock(spec=urllib3.PoolManager)

    # Default successful responses
    mock_response = Mock()
    mock_response.status = 200
    mock_response.data = b'{"version": "4.1.0"}'
    mock_client.request.return_value = mock_response

    return mock_client


@pytest.fixture
def temp_config_file():
    """Create a temporary config file for testing."""
    config_content = """
activeContext: test
contexts:
  - name: test
    address: api.example.com:443
    oidcServerURL: https://auth.example.com/auth/realms/test-realm
    auth:
      credentials:
        token: test-token-12345
    currentaccountid: test-account-id
    accounts:
      - accountid: test-account-id
        accountalias: test-account
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(config_content.strip())
        temp_path = pathlib.Path(f.name)

    yield temp_path

    # Cleanup
    temp_path.unlink(missing_ok=True)


@pytest.fixture
def temp_file_content():
    """Create a temporary file with known content for LocalFile testing."""
    content = b"Hello, World!\nThis is test content."

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(content)
        temp_path = pathlib.Path(f.name)

    yield temp_path, content

    # Cleanup
    temp_path.unlink(missing_ok=True)


@pytest.fixture
def mock_nextflow_args():
    """Mock command line arguments for testing."""
    from argparse import Namespace

    return Namespace(
        nextflow_cmd=["nextflow", "run", "hello", "-profile", "fuzzball"],
        verbose=False,
        dry_run=False,
        job_name="test-job",
        nextflow_work_base="/data/nextflow/executions",
        nf_fuzzball_version="0.2.0",
        plugin_base_uri="https://github.com/ctrliq/nf-fuzzball/releases/download",
        nextflow_version="25.05.0-edge",
        timelimit="8h",
        scratch_volume="volume://user/ephemeral",
        data_volume="volume://user/persistent",
        nf_core=False,
        queue_size=20,
        s3_secret="",
        fuzzball_config=pathlib.Path("~/.config/fuzzball/config.yaml"),
        context=None,
        api_url="",
        auth_url="",
        user="",
        password=False,
        account_id="",
        ca_cert=None,
    )
