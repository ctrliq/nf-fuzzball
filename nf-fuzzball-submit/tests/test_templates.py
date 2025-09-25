"""Tests for Jinja2 template rendering."""

import pathlib
import tempfile

import pytest
from jinja2 import Environment, PackageLoader

from nf_fuzzball_submit.models import LocalFile


class TestTemplateRendering:
    """Tests for Jinja2 template rendering functionality."""

    @pytest.fixture
    def jinja_env(self):
        """Create Jinja2 environment for testing."""
        return Environment(
            loader=PackageLoader("nf_fuzzball_submit", "templates"),
            autoescape=False,
        )

    def test_setup_template_exists(self, jinja_env):
        """Test that setup.sh.j2 template exists and can be loaded."""
        template = jinja_env.get_template("setup.sh.j2")
        assert template is not None

    def test_nextflow_template_exists(self, jinja_env):
        """Test that nextflow.sh.j2 template exists and can be loaded."""
        template = jinja_env.get_template("nextflow.sh.j2")
        assert template is not None

    def test_setup_template_basic_rendering(self, jinja_env):
        """Test basic rendering of setup template."""
        template = jinja_env.get_template("setup.sh.j2")

        context = {
            "wd": "/data/nextflow/executions/test-job",
            "home": "/data/nextflow/executions/test-job/home",
            "plugin_version": "0.2.0",
            "scratch_mount": "/scratch",
            "config_path": "/data/nextflow/executions/test-job/home/.config/fuzzball/config.yaml",
            "ca_cert_secret": False,
            "ca_cert_path": "",
            "api_url": "https://api.example.com/v4",
            "cleanup_secrets": [],
            "files": "/data/nextflow/executions/test-job/files",
            "nxf_fuzzball_config_name": "test-config-123",
            "config_files": [],
        }

        result = template.render(**context)

        # Check that key elements are present
        assert "#!/bin/sh" in result
        assert "mkdir -p /data/nextflow/executions/test-job" in result
        assert "nf-fuzzball-0.2.0" in result
        assert "unzip /scratch/nf-fuzzball.zip" in result
        assert "base64 -d > /data/nextflow/executions/test-job/home/.config/fuzzball/config.yaml" in result

    def test_setup_template_with_ca_cert(self, jinja_env):
        """Test setup template rendering with CA certificate."""
        template = jinja_env.get_template("setup.sh.j2")

        context = {
            "wd": "/data/nextflow/executions/test-job",
            "home": "/data/nextflow/executions/test-job/home",
            "plugin_version": "0.2.0",
            "scratch_mount": "/scratch",
            "config_path": "/data/nextflow/executions/test-job/home/.config/fuzzball/config.yaml",
            "ca_cert_secret": True,
            "ca_cert_path": "/data/nextflow/executions/test-job/home/.config/fuzzball/ca.crt",
            "api_url": "https://api.example.com/v4",
            "cleanup_secrets": [],
            "files": "/data/nextflow/executions/test-job/files",
            "nxf_fuzzball_config_name": "test-config-123",
            "config_files": [],
        }

        result = template.render(**context)

        # Check CA certificate setup block is included
        assert "Setup CA certificate if provided" in result


    def test_setup_template_without_ca_cert(self, jinja_env):
        """Test setup template rendering without CA certificate."""
        template = jinja_env.get_template("setup.sh.j2")

        context = {
            "wd": "/data/nextflow/executions/test-job",
            "home": "/data/nextflow/executions/test-job/home",
            "plugin_version": "0.2.0",
            "scratch_mount": "/scratch",
            "config_path": "/data/nextflow/executions/test-job/home/.config/fuzzball/config.yaml",
            "ca_cert_secret": False,
            "ca_cert_path": "",
            "api_url": "https://api.example.com/v4",
            "cleanup_secrets": [],
            "files": "/data/nextflow/executions/test-job/files",
            "nxf_fuzzball_config_name": "test-config-123",
            "config_files": [],
        }

        result = template.render(**context)

        # Check CA certificate setup block is not included
        assert "Setup CA certificate if provided" not in result

    def test_setup_template_with_cleanup_secrets(self, jinja_env):
        """Test setup template rendering with cleanup secrets."""
        template = jinja_env.get_template("setup.sh.j2")

        context = {
            "wd": "/data/nextflow/executions/test-job",
            "home": "/data/nextflow/executions/test-job/home",
            "plugin_version": "0.2.0",
            "scratch_mount": "/scratch",
            "config_path": "/data/nextflow/executions/test-job/home/.config/fuzzball/config.yaml",
            "ca_cert_secret": False,
            "ca_cert_path": "",
            "api_url": "https://api.example.com/v4",
            "cleanup_secrets": ["secret-1", "secret-2", None, "secret-4"],
            "files": "/data/nextflow/executions/test-job/files",
            "nxf_fuzzball_config_name": "test-config-123",
            "config_files": [],
        }

        result = template.render(**context)

        # Check that cleanup commands are generated for non-None secrets
        assert 'curl -s $CURL_CA_OPT -X DELETE "https://api.example.com/v4/secrets/secret-1"' in result
        assert 'curl -s $CURL_CA_OPT -X DELETE "https://api.example.com/v4/secrets/secret-2"' in result
        assert 'curl -s $CURL_CA_OPT -X DELETE "https://api.example.com/v4/secrets/secret-4"' in result
        # None values should be skipped
        secret_deletes = result.count("curl -s $CURL_CA_OPT -X DELETE")
        assert secret_deletes == 3

    def test_setup_template_with_config_files(self, jinja_env):
        """Test setup template rendering with config files."""
        # Create temporary files to use as LocalFile instances
        with tempfile.NamedTemporaryFile(delete=False) as f1, tempfile.NamedTemporaryFile(delete=False) as f2:
            f1.write(b"config content 1")
            f2.write(b"config content 2")
            f1.flush()
            f2.flush()

            try:
                local_file1 = LocalFile(pathlib.Path(f1.name), "files")
                local_file2 = LocalFile(pathlib.Path(f2.name), "files")

                template = jinja_env.get_template("setup.sh.j2")

                context = {
                    "wd": "/data/nextflow/executions/test-job",
                    "home": "/data/nextflow/executions/test-job/home",
                    "plugin_version": "0.2.0",
                    "scratch_mount": "/scratch",
                    "config_path": "/data/nextflow/executions/test-job/home/.config/fuzzball/config.yaml",
                    "ca_cert_secret": False,
                    "ca_cert_path": "",
                    "api_url": "https://api.example.com/v4",
                    "cleanup_secrets": [],
                    "files": "/data/nextflow/executions/test-job/files",
                    "nxf_fuzzball_config_name": "test-config-123",
                    "config_files": [local_file1, local_file2],
                }

                result = template.render(**context)

                # Check that both config files are processed
                assert f"cat /tmp/{local_file1.remote_name} | base64 -d > {local_file1.remote_path}" in result
                assert f"cat /tmp/{local_file2.remote_name} | base64 -d > {local_file2.remote_path}" in result

            finally:
                pathlib.Path(f1.name).unlink(missing_ok=True)
                pathlib.Path(f2.name).unlink(missing_ok=True)

    def test_nextflow_template_basic_rendering(self, jinja_env):
        """Test basic rendering of nextflow template."""
        template = jinja_env.get_template("nextflow.sh.j2")

        context = {
            "mangled_nextflow_cmd_str": "nextflow run hello -profile fuzzball",
            "files": "/data/nextflow/executions/test-job/files",
            "nxf_fuzzball_config_name": "test-config-123",
        }

        result = template.render(**context)

        # Check that key elements are present
        assert "#!/bin/bash" in result
        assert (
            "nextflow run hello -profile fuzzball -c /data/nextflow/executions/test-job/files/test-config-123.config"
            in result
        )
        assert "ec=$?" in result
        assert "cat .nextflow.log" in result
        assert "exit $ec" in result
        assert "-- LOG START --" in result
        assert "-- LOG END --" in result

    def test_template_file_structure(self):
        """Test that template files exist in the expected location."""
        package_dir = pathlib.Path(__file__).parent.parent / "src" / "nf_fuzzball_submit"
        templates_dir = package_dir / "templates"

        assert templates_dir.exists(), f"Templates directory not found: {templates_dir}"
        assert (templates_dir / "setup.sh.j2").exists(), "setup.sh.j2 template not found"
        assert (templates_dir / "nextflow.sh.j2").exists(), "nextflow.sh.j2 template not found"

    def test_template_syntax_validity(self, jinja_env):
        """Test that templates have valid Jinja2 syntax."""
        # This test ensures templates can be parsed without errors
        setup_template = jinja_env.get_template("setup.sh.j2")
        nextflow_template = jinja_env.get_template("nextflow.sh.j2")

        # Templates should be loadable without errors
        assert setup_template is not None
        assert nextflow_template is not None

        # Templates should have valid syntax (if get_template() succeeded, syntax is valid)
        # We can also verify they have the expected attributes
        assert hasattr(setup_template, 'render')
        assert hasattr(nextflow_template, 'render')
