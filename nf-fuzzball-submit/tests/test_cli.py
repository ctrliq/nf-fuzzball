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

    def test_fuzzball_config_default_path_no_xdg(self):
        """Test default fuzzball config path when XDG_CONFIG_HOME is not set"""
        test_args = ["--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            os.environ.pop("XDG_CONFIG_HOME", None)
            args = parse_cli()

        # Should default to ~/.config/fuzzball/config.yaml
        expected_path = pathlib.Path("~/.config/fuzzball/config.yaml").expanduser()
        assert args.fuzzball_config == expected_path

    def test_fuzzball_config_default_path_with_xdg(self):
        """Test default fuzzball config path when XDG_CONFIG_HOME is set"""
        test_args = ["--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            os.environ["XDG_CONFIG_HOME"] = "~/ops/cluster1/config"
            args = parse_cli()

        # Should default to ~/.config/fuzzball/config.yaml
        expected_path = pathlib.Path("~/ops/cluster1/config/fuzzball/config.yaml").expanduser()
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
            "secret://user/my-s3-secret",
            "--",
            "nextflow",
            "run",
            "hello",
        ]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()

        assert args.plugin_base_uri == "s3://my-bucket/plugins"
        assert args.s3_secret == "secret://user/my-s3-secret"

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

    @pytest.mark.parametrize("url", ["foo", "foo/bar", "https:/foo/bar"])
    def test_invalid_url(self, url):
        """Test that invalid url raises exception."""
        test_args = ["--plugin-base-uri", url, "--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            with pytest.raises(SystemExit):
                parse_cli()

    @pytest.mark.parametrize("qs", ["2", "10", "100"])
    def test_valid_queue_size_option(self, qs):
        """Test valid queue size option parsing."""
        test_args = ["--queue-size", qs, "--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()

        assert args.queue_size == int(qs)

    @pytest.mark.parametrize("qs", ["-1", "0", "bad"])
    def test_invalid_queue_size_option(self, qs):
        """Test invalid queue size raises exception."""
        test_args = ["--queue-size", qs, "--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            with pytest.raises(SystemExit):
                parse_cli()

    @pytest.mark.parametrize("c", ["1", "5", "10"])
    def test_valid_cores(self, c):
        """Test valid core option parsing."""
        test_args = ["--cores", c, "--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()

        assert args.cores == int(c)

    @pytest.mark.parametrize("c", ["-1", "0", "11", "bad"])
    def test_invalid_cores(self, c):
        """Test invalid core raises exception."""
        test_args = ["--cores", c, "--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            with pytest.raises(SystemExit):
                parse_cli()

    @pytest.mark.parametrize("mem", ["4GB", "10GiB", "500MB", "0.5GiB"])
    def test_valid_memory_option(self, mem):
        """Test valid memory option parsing."""
        test_args = ["--memory", mem, "--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()

        assert args.memory == mem


    @pytest.mark.parametrize("mem", ["bad", "0GB", "1.xGiB"])
    def test_valid_memory_option(self, mem):
        """Test invalid memory option parsing."""
        test_args = ["--memory", mem, "--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            with pytest.raises(SystemExit):
                parse_cli()

    @pytest.mark.parametrize("timelimit", [
        "2h",
        "8h",
        "120m",
        "1d8h30m",
        "30s",
        "1d",
        "2d3h",
        "1d2h3m4s",
    ])
    def test_valid_timelimit(self, timelimit):
        """Test valid time limits."""
        test_args = ["--timelimit", timelimit, "--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            args = parse_cli()
        assert args.timelimit == timelimit

    @pytest.mark.parametrize("timelimit", [
        "0h",
        "bad",
        "0d0h0m",
    ])
    def test_invalid_timelimit(self, timelimit):
        """Test valid time limits."""
        test_args = ["--timelimit", timelimit, "--", "nextflow", "run", "hello"]

        with patch("sys.argv", ["nf-fuzzball-submit"] + test_args):
            with pytest.raises(SystemExit):
                parse_cli()

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
