"""Tests for nf_fuzzball_submit.utils module."""

import pathlib
import tempfile
from unittest.mock import Mock, patch

import pytest
import urllib3

from nf_fuzzball_submit.utils import die, find_and_import_local_files, get_canonical_api_url


class TestGetCanonicalApiUrl:
    """Tests for get_canonical_api_url function."""

    def test_url_already_has_version_path(self, mock_http_client):
        """Test URL that already has version path."""
        url = "https://api.example.com/v4"
        result = get_canonical_api_url(url, mock_http_client)
        assert result == "https://api.example.com/v4"
        # Should not make any HTTP requests
        mock_http_client.request.assert_not_called()

    def test_url_without_schema_gets_https(self, mock_http_client):
        """Test URL without schema gets https prefix."""
        mock_http_client.request.return_value.status = 200

        url = "api.example.com"
        result = get_canonical_api_url(url, mock_http_client)

        # Should have made a request to the HTTPS version
        mock_http_client.request.assert_called()
        call_args = mock_http_client.request.call_args[0]
        assert call_args[1].startswith("https://api.example.com/v")

    def test_discovers_v4_endpoint(self, mock_http_client):
        """Test discovers v4 endpoint."""
        mock_response = Mock()
        mock_response.status = 404
        mock_http_client.request.side_effect = [
            mock_response,  # /v2 fails
            mock_response,  # /v3 fails
            Mock(status=200),  # /v4 succeeds
        ]

        url = "https://api.example.com"
        result = get_canonical_api_url(url, mock_http_client)

        assert result == "https://api.example.com/v4"

    def test_discovers_v2_endpoint_first(self, mock_http_client):
        """Test discovers v2 endpoint when it's the first to respond."""
        mock_http_client.request.return_value.status = 200

        url = "https://api.example.com"
        result = get_canonical_api_url(url, mock_http_client)

        assert result == "https://api.example.com/v2"
        # Should stop at first successful response
        assert mock_http_client.request.call_count == 1

    def test_no_version_endpoint_found_raises_error(self, mock_http_client):
        """Test raises error when no version endpoint is found."""
        mock_response = Mock()
        mock_response.status = 404
        mock_http_client.request.return_value = mock_response

        url = "https://api.example.com"

        with pytest.raises(ValueError, match="Unable to sniff API base path"):
            get_canonical_api_url(url, mock_http_client)

    def test_http_exception_continues_search(self, mock_http_client):
        """Test that HTTP exceptions during search are handled."""
        mock_http_client.request.side_effect = [
            urllib3.exceptions.HTTPError("Connection failed"),  # /v2 fails
            Mock(status=200),  # /v3 succeeds
        ]

        url = "https://api.example.com"
        result = get_canonical_api_url(url, mock_http_client)

        assert result == "https://api.example.com/v3"

    def test_strips_trailing_slash(self, mock_http_client):
        """Test strips trailing slash from URL."""
        mock_http_client.request.return_value.status = 200

        url = "https://api.example.com/"
        result = get_canonical_api_url(url, mock_http_client)

        # Should make request without double slash
        call_args = mock_http_client.request.call_args[0]
        assert "//" not in call_args[1].replace("https://", "")


class TestFindAndImportLocalFiles:
    """Tests for find_and_import_local_files function."""

    def test_no_local_files(self):
        """Test command with no local files."""
        cmd = ["nextflow", "run", "hello", "-profile", "fuzzball"]
        mangled_cmd, local_files = find_and_import_local_files(cmd)

        assert mangled_cmd == cmd
        assert local_files == []

    def test_single_local_file(self, temp_file_content):
        """Test command with single local file."""
        temp_path, _ = temp_file_content
        cmd = ["nextflow", "run", "-c", str(temp_path), "-profile", "fuzzball"]

        mangled_cmd, local_files = find_and_import_local_files(cmd)

        assert len(local_files) == 1
        assert local_files[0].local_path == temp_path
        assert mangled_cmd[3] == local_files[0].remote_path

    def test_multiple_local_files(self):
        """Test command with multiple local files."""
        with tempfile.NamedTemporaryFile(delete=False) as f1, tempfile.NamedTemporaryFile(delete=False) as f2:
            f1.write(b"content1")
            f2.write(b"content2")
            f1.flush()
            f2.flush()

            cmd = ["nextflow", "run", f1.name, "-params-file", f2.name]

            try:
                mangled_cmd, local_files = find_and_import_local_files(cmd)

                assert len(local_files) == 2
                assert mangled_cmd[2] == local_files[0].remote_path
                assert mangled_cmd[4] == local_files[1].remote_path

            finally:
                pathlib.Path(f1.name).unlink(missing_ok=True)
                pathlib.Path(f2.name).unlink(missing_ok=True)

    def test_comma_separated_files(self):
        """Test command with comma-separated files."""
        with tempfile.NamedTemporaryFile(delete=False) as f1, tempfile.NamedTemporaryFile(delete=False) as f2:
            f1.write(b"content1")
            f2.write(b"content2")
            f1.flush()
            f2.flush()

            cmd = ["nextflow", "run", "-c", f"{f1.name},{f2.name}"]

            try:
                mangled_cmd, local_files = find_and_import_local_files(cmd)

                assert len(local_files) == 2
                expected_remote_paths = f"{local_files[0].remote_path},{local_files[1].remote_path}"
                assert mangled_cmd[3] == expected_remote_paths

            finally:
                pathlib.Path(f1.name).unlink(missing_ok=True)
                pathlib.Path(f2.name).unlink(missing_ok=True)

    def test_comma_separated_mixed_files_and_non_files(self, temp_file_content):
        """Test comma-separated args with mix of files and non-files."""
        temp_path, _ = temp_file_content
        cmd = ["nextflow", "run", f"hello,{temp_path},world"]

        mangled_cmd, local_files = find_and_import_local_files(cmd)

        assert len(local_files) == 1
        expected_arg = f"hello,{local_files[0].remote_path},world"
        assert mangled_cmd[2] == expected_arg

    def test_with_remote_prefix(self, temp_file_content):
        """Test file discovery with remote prefix."""
        temp_path, _ = temp_file_content
        cmd = ["nextflow", "run", str(temp_path)]
        prefix = "config/files"

        mangled_cmd, local_files = find_and_import_local_files(cmd, prefix)

        assert len(local_files) == 1
        assert local_files[0].remote_path.startswith(f"{prefix}/")
        assert mangled_cmd[2] == local_files[0].remote_path

    def test_nonexistent_file_ignored(self):
        """Test that nonexistent files are ignored."""
        cmd = ["nextflow", "run", "/nonexistent/file.txt"]
        mangled_cmd, local_files = find_and_import_local_files(cmd)

        assert mangled_cmd == cmd  # unchanged
        assert local_files == []

    def test_directory_ignored(self):
        """Test that directories are ignored."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cmd = ["nextflow", "run", temp_dir]
            mangled_cmd, local_files = find_and_import_local_files(cmd)

            assert mangled_cmd == cmd  # unchanged
            assert local_files == []


class TestDie:
    """Tests for die function."""

    @patch("nf_fuzzball_submit.utils.sys.exit")
    @patch("nf_fuzzball_submit.utils.logger")
    def test_die_logs_and_exits(self, mock_logger, mock_exit):
        """Test die function logs error and exits."""
        error_message = "Something went wrong"

        die(error_message)

        mock_logger.fatal.assert_called_once_with(error_message)
        mock_exit.assert_called_once_with(1)
