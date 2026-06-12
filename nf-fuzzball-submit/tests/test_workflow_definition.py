"""Tests for the workflow definition built by submit_nextflow_job."""

import json
from argparse import Namespace
from typing import Any
from unittest.mock import Mock

import pytest
from jinja2 import Environment, PackageLoader

from nf_fuzzball_submit.client import DATA_MOUNT, SCRATCH_MOUNT, FuzzballClient, volume_from_reference
from nf_fuzzball_submit.models import ApiConfig

V4_MOUNTS = {
    DATA_MOUNT: {"volume": "data"},
    SCRATCH_MOUNT: {"volume": "scratch"},
}


def make_client() -> FuzzballClient:
    """Build a FuzzballClient without running network initialization."""
    client = FuzzballClient.__new__(FuzzballClient)
    client._authenticator = Mock()
    client._ca_cert_file = None
    client._fb_version = "v4.0"
    client._api_config = ApiConfig(
        api_url="https://api.example.com/v4",
        auth_url="https://auth.example.com/auth/realms/test-realm",
        token="test-token",
        account_id="test-account-id",
    )
    client._jinja_env = Environment(
        loader=PackageLoader("nf_fuzzball_submit", "templates"),
        autoescape=False,  # noqa: S701
    )
    client._http = Mock()
    client._http.request.return_value = Mock(status=200)  # plugin HEAD check
    return client


def make_args(**overrides: Any) -> Namespace:
    args = Namespace(
        nextflow_cmd=["nextflow", "run", "hello"],
        verbose=False,
        dry_run=True,
        job_name="test-job",
        nextflow_work_base="/data/nextflow/executions",
        nf_fuzzball_version="0.4.0",
        plugin_base_uri="https://github.com/ctrliq/nf-fuzzball/releases/download",
        nextflow_version="25.10.4",
        timelimit="8h",
        scratch_volume="volume://user/ephemeral",
        data_volume="volume://user/persistent/mydata",
        nf_core=False,
        queue_size=20,
        s3_secret="",
        ansi=False,
        cores=1,
        memory="4GB",
        egress_source=None,
        egress_s3_dest=None,
        egress_s3_aki=None,
        egress_s3_sak=None,
        egress_s3_region=None,
        egress_timelimit="2h",
    )
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def install_fake_request(client: FuzzballClient, captured: dict[str, Any]) -> None:
    """Stub client._request, capturing workflow-related request bodies."""

    def fake_request(method: str, endpoint: str, data: Any = None, headers: Any = None) -> Mock:
        captured.setdefault("calls", []).append((method, endpoint))
        response = Mock(status=200)
        if endpoint == "/secrets" and method == "GET":
            response.data = json.dumps({"secrets": []}).encode()
        elif endpoint == "/secrets" and method == "PUT":
            response.data = json.dumps({"id": "secret-1"}).encode()
        elif endpoint.startswith("/secrets/") and method == "DELETE":
            response.data = b"{}"
        elif endpoint == "/workflows" and method == "POST":
            captured["workflow_request"] = data
            response.data = json.dumps({"id": "wf-123"}).encode()
        else:
            raise AssertionError(f"unexpected request: {method} {endpoint}")
        return response

    client._request = fake_request  # type: ignore[method-assign]


class TestWorkflowDefinitionMounts:
    def test_jobs_use_path_keyed_v4_mounts(self) -> None:
        client = make_client()
        captured: dict[str, Any] = {}
        install_fake_request(client, captured)

        client.submit_nextflow_job(make_args(dry_run=False))

        definition = captured["workflow_request"]["definition"]
        assert definition["jobs"]["setup"]["mounts"] == V4_MOUNTS
        assert definition["jobs"]["nextflow"]["mounts"] == V4_MOUNTS

    def test_egress_job_mounts_only_data_volume(self) -> None:
        client = make_client()
        captured: dict[str, Any] = {}
        install_fake_request(client, captured)

        client.submit_nextflow_job(
            make_args(
                dry_run=False,
                egress_source=f"{DATA_MOUNT}/results",
                egress_s3_dest="s3://bucket/results",
                egress_s3_aki="AKIA...",
                egress_s3_sak="secret",
                egress_s3_region="us-east-1",
            )
        )

        definition = captured["workflow_request"]["definition"]
        assert definition["jobs"]["egress"]["mounts"] == {DATA_MOUNT: {"volume": "data"}}


class TestVolumeFromReference:
    def test_ephemeral_classes_become_empty_blocks(self) -> None:
        assert volume_from_reference("volume://user/ephemeral") == {}
        assert volume_from_reference("volume://user/scratch") == {}
        assert volume_from_reference("volume://user/ephemeral/named") == {}

    def test_named_persistent_volume(self) -> None:
        assert volume_from_reference("volume://group/persistent/data") == {"name": "data"}
        assert volume_from_reference("volume://user/persistent/mydata") == {"name": "mydata"}

    def test_unnamed_persistent_volume_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="explicit name"):
            volume_from_reference("volume://user/persistent")

    def test_provisioner_class_maps_to_use(self) -> None:
        assert volume_from_reference("volume://user/nfs-prod") == {"use": "nfs-prod"}
        assert volume_from_reference("volume://user/nfs-prod/data") == {"use": "nfs-prod", "name": "data"}

    def test_class_less_reference_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="volume://SCOPE/CLASS"):
            volume_from_reference("volume://user")


class TestWorkflowDefinitionVolumes:
    def test_submits_native_v4_definition(self) -> None:
        client = make_client()
        captured: dict[str, Any] = {}
        install_fake_request(client, captured)

        client.submit_nextflow_job(make_args(dry_run=False))

        definition = captured["workflow_request"]["definition"]
        assert definition["version"] == "v4"
        assert definition["volumes"]["data"] == {"name": "mydata"}
        scratch = definition["volumes"]["scratch"]
        assert "reference" not in scratch
        assert scratch["ingress"][0]["destination"] == {"uri": "file://nf-fuzzball.zip"}

    def test_dry_run_does_not_submit(self) -> None:
        client = make_client()
        captured: dict[str, Any] = {}
        install_fake_request(client, captured)

        client.submit_nextflow_job(make_args(dry_run=True))

        assert "workflow_request" not in captured
