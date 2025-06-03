"""
Submit a nextflow pipleine to run on fuzzball. This script will
collect the required config information, inject it into the  from your fuzzbal configuration
file and submit the pipeline controller job to the fuzzball clutster.
"""

import base64
import pathlib
import sys
import yaml
import requests
import secrets
import string
import argparse
from typing import Any, Dict

CONFIG_PATH = pathlib.Path("~/.config/fuzzball/config.yaml")


def generate_random_string(length: int = 6) -> str:
    """
    Generate a random string of fixed length using letters and digits.
    """
    characters = string.ascii_letters + string.digits
    return "".join(secrets.choice(characters) for _ in range(length))


class MinimalFuzzballClient:
    def __init__(self, config_path: pathlib.Path, context: str | None = None):
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
        if context is None:
            context = config.get("activeContext", None)
        if context is None:
            raise ValueError(
                "No active context specified in config or provided as argument."
            )
        self.__config = {"activeContext": context, "contexts": []}
        for c in config.get("contexts", []):
            if c["name"] == context:
                self.__host, self.__port = c["address"].split(":")
                self.__token = c["auth"]["credentials"]["token"]
                self.__schema = "https"
                self.__base_path = "/v2"
                self.__base_url = (
                    f"{self.__schema}://{self.__host}:{self.__port}{self.__base_path}"
                )
                self.__config = {
                    "host": self.__host,
                    "port": self.__port,
                    "token": self.__token,
                    "schema": self.__schema,
                    "base_path": self.__base_path,
                }
                break

    @property
    def headers(self) -> Dict[str, str]:
        """
        Return the headers required for API requests, including the authorization token.
        """
        return {
            "Authorization": f"Bearer {self.__token}",
            "Content-Type": "application/json",
        }

    def __request(
        self, method: str, endpoint: str, data: Dict[str, Any] | None = None
    ) -> requests.Response:
        """
        Make an API request to the Fuzzball server.
        """
        url = f"{self.__base_url}/{endpoint.lstrip('/')}"
        response = requests.request(method, url, json=data, headers=self.headers)
        response.raise_for_status()
        return response

    def encode_config(self) -> str:
        """
        Return a base64 encoded version of the minimal configuration file
        containing only the active context.
        """
        return base64.b64encode(yaml.dump(self.__config).encode("utf-8")).decode(
            "utf-8"
        )

    def create_value_secret(self, secret_name: str, secret_value: str) -> None:
        """
        Create or update a value secret in Fuzzball.
        """

        # Check if the secret already exists
        response = self.__request("GET", "/secrets")
        id = None
        for secret in response.json()["secrets"]:
            if secret["name"] == secret_name:
                id = secret["id"]
                break

        if id is None:
            secret_data = {
                "name": secret_name,
                "scope": "SECRET_SCOPE_USER",
                "value": {"value": secret_value},
            }
            self.__request("PUT", "/secrets", data=secret_data)
        else:
            secret_data = {"value": {"value": secret_value}}
            self.__request("PATCH", f"/secrets/{id}", data=secret_data)

    def submit_nextflow_job(self, job_name: str, nextflow_config: str | None = None):
        """
        Submit a Nextflow job to the Fuzzball cluster.
        """

        plugin_version = "0.0.1"
        nxf_version = "25.05.0-edge"
        runtime = "24h"
        home = "/scratch/home"
        wd = "/data/nextflow"
        mounts = {"data": {"location": "/data"}, "scratch": {"location": "/scratch"}}

        # Create or update the Fuzzball configuration secret. This will allow the nextflow to submit
        # workflows to the Fuzzball cluster. The nextflow plugin will remove the secret.
        secret_name = f"fb-{generate_random_string()}"
        self.create_value_secret(secret_name, self.encode_config())
        nxf_fuzzball_config = f"""
        plugins {{id 'nf-fuzzball@{plugin_version}' }}
        fuzzball {{
            configSecret = "{secret_name}"
        }}
        process.executor = 'fuzzball'
        """

        workflow = {
            "name": job_name,
            "definition": {
                "version": "v1",
                "files": {
                    "fuzzball.config": nxf_fuzzball_config,
                },
                "volumes": {
                    "data": {
                        "reference": "volume://user/persistent",
                    },
                    "scratch": {
                        "reference": "volume://user/ephemeral",
                        "ingress": [
                            {
                                "source": {
                                    "uri": f"s3://co-ciq-misc-support/nf-fuzzball/nf-fuzzball-{plugin_version}.zip",
                                    "secret": "secret://user/s3",
                                },
                                "destination": {"uri": "file://nf-fuzzball.zip"},
                            }
                        ],
                    },
                },
                "jobs": {
                    "setup": {
                        "image": {"uri": "docker://alpine:latest"},
                        "mounts": mounts,
                        "cwd": wd,
                        "command": [
                            "/bin/sh",
                            "-c",
                            f"mkdir -p $HOME/.nextflow/plugins/nf-fuzzball-{plugin_version}"
                            f"  && unzip /scratch/nf-fuzzball.zip -d $HOME/.nextflow/plugins/nf-fuzzball-{plugin_version}",
                        ],
                        "env": [f"HOME={home}"],
                        "policy": {"timeout": {"execute": "5m"}},
                        "resource": {"cpu": {"cores": 1}, "memory": {"size": "1GB"}},
                    },
                    "nextflow": {
                        "image": {"uri": f"docker://nextflow/nextflow:{nxf_version}"},
                        "mounts": mounts,
                        "files": {
                            "/tmp/fuzzball.config": "file://fuzzball.config",
                        },
                        "cwd": wd,
                        "command": [
                            "/bin/bash",
                            "-c",
                            "nextflow info -d && nextflow run -c /tmp/fuzzball.config hello",
                        ],
                        "env": [f"HOME={home}", f"NXF_HOME={home}/.nextflow"],
                        "policy": {"timeout": {"execute": runtime}},
                        "resource": {"cpu": {"cores": 1}, "memory": {"size": "4GB"}},
                        "requires": ["setup"],
                    },
                },
            },
        }
        if nextflow_config:
            workflow["definition"]["files"]["nextflow.config"] = nextflow_config
            workflow["definition"]["jobs"]["nextflow"]["files"][
                "/tmp/nextflow.config"
            ] = "file://nextflow.config"

        print("Running Nextflow job with the following configuration:")
        print(yaml.safe_dump(workflow, sort_keys=False, default_flow_style=False))
        response = self.__request("POST", "/workflows", data=workflow)
        print(f"Submitted workflow {response.json()['id']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a Fuzzball secret via REST API."
    )
    parser.add_argument(
        "-c",
        "--context",
        type=str,
        help="Name of the secret context to use from config.yaml. Defaults to the active context in the config file",
        default=None,
    )
    args = parser.parse_args()

    config_path = CONFIG_PATH.expanduser()
    if not config_path.exists():
        print(
            f"Configuration file not found at {config_path}. Please create it first.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        fb_client = MinimalFuzzballClient(config_path, args.context)
    except ValueError as e:
        print(f"Failed to load config: {e}", file=sys.stderr)
        sys.exit(1)

    fb_client.submit_nextflow_job("nextflow-job", nextflow_config=None)


if __name__ == "__main__":
    main()
