"""Tests for nf_fuzzball_submit.cli module."""

import os
import pathlib
from unittest.mock import patch

import pytest

from nf_fuzzball_submit.cli import parse_cli


class TestCliParsing:
    """Tests for CLI argument parsing."""

    def test_basic_nextflow_command(self):
        """Test parsing basic nextflow command."""
        test_args = ["--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()

        assert args.nextflow_cmd == ["nextflow", "run", "hello"]
        assert args.verbose is False
        assert args.dry_run is False

    def test_nextflow_command_with_double_dash(self):
        """Test nextflow command parsing strips leading double dash."""
        test_args = ["--", "nextflow", "run", "hello", "-profile", "fuzzball"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()

        assert args.nextflow_cmd == ["nextflow", "run", "hello", "-profile", "fuzzball"]

    def test_verbose_flag(self):
        """Test verbose flag parsing."""
        test_args = ["-v", "--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()

        assert args.verbose is True

    def test_dry_run_flag(self):
        """Test dry run flag parsing."""
        test_args = ["--dry-run", "--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()

        assert args.dry_run is True

    def test_job_name_option(self):
        """Test job name option parsing."""
        test_args = ["--job-name", "my-test-job", "--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()

        assert args.job_name == "my-test-job"

    def test_default_values(self):
        """Test default values are set correctly."""
        test_args = ["--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()

        assert args.nextflow_work_base == "/data/nextflow/executions"
        assert args.nf_fuzzball_version == "0.2.0"
        assert args.nextflow_version == "25.05.0-edge"
        assert args.timelimit == "8h"
        assert args.scratch_volume == "volume://user/ephemeral"
        assert args.data_volume == "volume://user/persistent"
        assert args.queue_size == 20
        assert args.nf_core is False

    def test_config_file_authentication_options(self):
        """Test config file authentication options."""
        test_args = ["--context", "prod", "--fuzzball-config", "/custom/config.yaml", "--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()

        assert args.context == "prod"
        assert args.fuzzball_config == pathlib.Path("/custom/config.yaml")

    def test_direct_login_authentication_options(self):
        """Test direct login authentication options."""
        test_args = [
            "--api-url",
            "https://api.example.com",
            "--auth-url",
            "https://auth.example.com/auth/realms/test",
            "--user",
            "test@example.com",
            "--password",
            "--account-id",
            "account-123",
            "--",
            "nextflow",
            "run",
            "hello",
        ]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()

        assert args.api_url == "https://api.example.com"
        assert args.auth_url == "https://auth.example.com/auth/realms/test"
        assert args.user == "test@example.com"
        assert args.password is True
        assert args.account_id == "account-123"

    def test_environment_variable_defaults(self):
        """Test environment variables are used as defaults."""
        env_vars = {
            "FUZZBALL_API_URL": "https://env-api.example.com",
            "FUZZBALL_AUTH_URL": "https://env-auth.example.com",
            "FUZZBALL_USER": "env-user@example.com",
            "FUZZBALL_ACCOUNT_ID": "env-account-123",
        }

        test_args = ["--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args), patch.dict(os.environ, env_vars):
            args = parse_cli()

        assert args.api_url == "https://env-api.example.com"
        assert args.auth_url == "https://env-auth.example.com"
        assert args.user == "env-user@example.com"
        assert args.account_id == "env-account-123"

    def test_command_line_overrides_environment(self):
        """Test command line arguments override environment variables."""
        env_vars = {
            "FUZZBALL_API_URL": "https://env-api.example.com",
        }

        test_args = ["--api-url", "https://cli-api.example.com", "--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args), patch.dict(os.environ, env_vars):
            args = parse_cli()

        assert args.api_url == "https://cli-api.example.com"

    def test_fuzzball_config_default_path(self):
        """Test default fuzzball config path."""
        test_args = ["--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()

        # Should default to ~/.config/fuzzball/config.yaml
        expected_path = pathlib.Path("~/.config/fuzzball/config.yaml").expanduser()
        assert args.fuzzball_config == expected_path

    def test_fuzzball_config_xdg_config_home(self):
        """Test fuzzball config path with XDG_CONFIG_HOME."""
        env_vars = {"XDG_CONFIG_HOME": "/custom/config"}
        test_args = ["--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args), patch.dict(os.environ, env_vars):
            args = parse_cli()

        expected_path = pathlib.Path("/custom/config/fuzzball/config.yaml").expanduser()
        assert args.fuzzball_config == expected_path

    def test_s3_plugin_uri_requires_secret(self):
        """Test S3 plugin URI requires S3 secret."""
        test_args = ["--plugin-base-uri", "s3://my-bucket/plugins", "--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            with pytest.raises(SystemExit):  # argparse calls sys.exit on error
                parse_cli()

    def test_s3_plugin_uri_with_secret_succeeds(self):
        """Test S3 plugin URI with secret succeeds."""
        test_args = [
            "--plugin-base-uri",
            "s3://my-bucket/plugins",
            "--s3-secret",
            "my-s3-secret",
            "--",
            "nextflow",
            "run",
            "hello",
        ]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()

        assert args.plugin_base_uri == "s3://my-bucket/plugins"
        assert args.s3_secret == "my-s3-secret"

    def test_missing_nextflow_command_raises_error(self):
        """Test missing nextflow command raises error."""
        test_args = ["--verbose"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            with pytest.raises(SystemExit):  # argparse calls sys.exit on error
                parse_cli()

    def test_nextflow_command_must_start_with_nextflow(self):
        """Test nextflow command must start with 'nextflow'."""
        test_args = ["--", "python", "script.py"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            with pytest.raises(SystemExit):  # argparse calls sys.exit on error
                parse_cli()

    def test_ca_cert_option(self):
        """Test CA certificate option parsing."""
        test_args = ["--ca-cert", "/path/to/ca.crt", "--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()

        assert args.ca_cert == "/path/to/ca.crt"

    def test_nf_core_flag(self):
        """Test nf-core flag parsing."""
        test_args = ["--nf-core", "--", "nextflow", "run", "nf-core/rnaseq"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()

        assert args.nf_core is True

    def test_queue_size_option(self):
        """Test queue size option parsing."""
        test_args = ["--queue-size", "50", "--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()

        assert args.queue_size == 50

    def test_custom_volumes(self):
        """Test custom volume specifications."""
        test_args = [
            "--scratch-volume",
            "volume://custom/scratch",
            "--data-volume",
            "volume://custom/data",
            "--",
            "nextflow",
            "run",
            "hello",
        ]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()

        assert args.scratch_volume == "volume://custom/scratch"
        assert args.data_volume == "volume://custom/data"
