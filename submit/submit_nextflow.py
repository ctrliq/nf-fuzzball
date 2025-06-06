#! /usr/bin/env python3
"""
Submit a nextflow pipeline to Fuzzball.

Notes:
  - Paths for input, workdir, and output in your nextflow command are relative to the
    data volume mounted at /data.
  - Any explicitly specified config and/or parameter files will be included in the
    fuzzball job but implicit files (i.e. $HOME/.nextflow/config and ./nextflow.config)
    will not.

"""

import argparse
import base64
import pathlib
import secrets
import string
import sys
import textwrap
from typing import Any, Dict

import yaml
import requests

CONFIG_PATH = pathlib.Path("~/.config/fuzzball/config.yaml")


def generate_random_string(length: int = 6) -> str:
    """
    Generate a random string of fixed length using letters and digits.
    """
    characters = string.ascii_letters + string.digits
    return "".join(secrets.choice(characters) for _ in range(length))


def str_presenter(dumper: yaml.Dumper, data: str) -> yaml.Node:
    """
    Represent strings with newlines as block litererals in YAML
    """
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)

yaml.add_representer(str, str_presenter)

def fail(error: str) -> None:
    """
    Print an error message and exit the program.
    """
    print(f"Error: {error}; exiting", file=sys.stderr)
    sys.exit(1)

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
        self._config = {"activeContext": context, "contexts": []}
        for c in config.get("contexts", []):
            if c["name"] == context:
                self._host, self._port = c["address"].split(":")
                self._token = c["auth"]["credentials"]["token"]
                self._schema = "https"
                self._base_path = "/v2"
                self._base_url = (
                    f"{self._schema}://{self._host}:{self._port}{self._base_path}"
                )
                self._config["contexts"].append(c)
                break

    @property
    def _headers(self) -> Dict[str, str]:
        """
        Return the headers required for API requests, including the authorization token.
        """
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def _request(
        self, method: str, endpoint: str, data: Dict[str, Any] | None = None
    ) -> requests.Response:
        """
        Make an API request to the Fuzzball server.
        """
        url = f"{self._base_url}/{endpoint.lstrip('/')}"
        response = requests.request(method, url, json=data, headers=self._headers)
        response.raise_for_status()
        return response

    def _encode_config(self) -> str:
        """
        Return a base64 encoded version of the minimal configuration file
        containing only the active context.
        """
        return base64.b64encode(yaml.dump(self._config).encode("utf-8")).decode("utf-8")

    def create_value_secret(self, secret_name: str, secret_value: str) -> None:
        """
        Create or update a value secret in Fuzzball.
        """

        # Check if the secret already exists
        response = self._request("GET", "/secrets")
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
            try:
                resp = self._request("PUT", "/secrets", data=secret_data)
            except requests.HTTPError as e:
                fail(f"Failed to create secret: {e}")
            self._secret_id = resp.json()["id"]
        else:
            self._secret_id = id
            secret_data = {"value": {"value": secret_value}}
            self._request("PATCH", f"/secrets/{id}", data=secret_data)

    def submit_nextflow_job(self, args: argparse.Namespace) -> None:
        """
        Submit a Nextflow job to the Fuzzball cluster.
        """

        secret_name = f"{generate_random_string()}"
        plugin_version = "0.0.1"
        nxf_version = "25.05.0-edge"
        runtime = "24h"
        home = "/scratch/home"
        wd = f"/data/nextflow/{secret_name}"
        s3_secret = "secret://user/s3"
        env = [f"HOME={home}", f"NXF_HOME={home}/.nextflow"]
        volumes = {
            "data": {
                "reference": "volume://user/persistent",
            },
            "scratch": {
                "reference": "volume://user/ephemeral",
                "ingress": [
                    {
                        "source": {
                            "uri": f"s3://co-ciq-misc-support/nf-fuzzball/nf-fuzzball-{plugin_version}.zip",
                            "secret": s3_secret,
                        },
                        "destination": {"uri": "file://nf-fuzzball.zip"},
                    }
                ],
                "egress": [
                    {
                        "source": {"uri": "file:///nextflow_report.html"},
                        "destination": {
                            "uri": f"s3://co-ciq-misc-support/nf-fuzzball/nextflow_report-{secret_name}.html",
                            "secret": s3_secret,
                        },
                    },
                    {
                        "source": {"uri": "file:///nextflow_timeline.html"},
                        "destination": {
                            "uri": f"s3://co-ciq-misc-support/nf-fuzzball/nextflow_timeline-{secret_name}.html",
                            "secret": s3_secret,
                        },
                    },
                ],
            },
        }
        mounts = {"data": {"location": "/data"}, "scratch": {"location": "/scratch"}}

        self.create_value_secret(secret_name, self._encode_config())
        nxf_fuzzball_config = f"""\
        plugins {{id 'nf-fuzzball@{plugin_version}' }}
        fuzzball {{
            cfgFile = '/scratch/home/.config/fuzzball/config.yaml'
        }}
        process.executor = 'fuzzball'
        """

        setup_script = f"""\
        #! /bin/sh
        mkdir -p $HOME/.nextflow/plugins/nf-fuzzball-{plugin_version} $HOME/.config/fuzzball \\
          && unzip /scratch/nf-fuzzball.zip -d $HOME/.nextflow/plugins/nf-fuzzball-{plugin_version} \\
          && echo "$FB_CONFIG" | base64 -d > $HOME/.config/fuzzball/config.yaml \\
          || exit 1

        # there is only a single context in the config file so it's easy to extract the token
        TOKEN="$(awk '/token:/ {{print $2}}' $HOME/.config/fuzzball/config.yaml)"
        # clean up the secret but don't fail if there is an error
        curl -s -X DELETE "{self._base_url}/secrets/{self._secret_id}" \\
            -H "Authorization: Bearer $TOKEN" \\
            -H "Accept: application/json" && echo "secret deleted" || echo "secret not deleted"
        """

        nextflow_script = """\
        #! /bin/bash
        nextflow run -ansi-log false \\
            -with-report /scratch/nextflow_report.html \\
            -with-trace \\
            -with-timeline /scratch/nextflow_timeline.html \\
            -c /tmp/fuzzball.config hello
        """

        workflow = {
            "name": args.job_name,
            "definition": {
                "version": "v1",
                "files": {
                    "fuzzball.config": textwrap.dedent(nxf_fuzzball_config),
                },
                "volumes": volumes,
                "jobs": {
                    "setup": {
                        "image": {"uri": "docker://curlimages/curl"},
                        "mounts": mounts,
                        "cwd": wd,
                        "script": textwrap.dedent(setup_script),
                        "env": env + [f"FB_CONFIG=secret://user/{secret_name}"],
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
                        "script": textwrap.dedent(nextflow_script),
                        "env": env,
                        "policy": {"timeout": {"execute": runtime}},
                        "resource": {"cpu": {"cores": 1}, "memory": {"size": "4GB"}},
                        "requires": ["setup"],
                    },
                },
            },
        }
        if args.verbose or args.dry_run:
            yaml.dump(workflow, sys.stdout, default_flow_style=False)
        if args.dry_run:
            print("Dry run mode: not submitting the workflow.")
            self._request("DELETE", f"/secrets/{self._secret_id}")
            return
        response = self._request("POST", "/workflows", data=workflow)
        print(f"Submitted nextflow workflow {response.json()['id']}")

def parse_cli() -> argparse.Namespace:
    """
    Parsing the commandline
    """

    parser = argparse.ArgumentParser(
        description=__doc__,
        usage="%(prog)s [options] -- <nextflow_cmd>",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-c",
        "--context",
        type=str,
        help="Name of the secret context to use from config.yaml. Defaults to the active context in the config file",
        default=None,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Dump the workflow before submitting",
    )
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Don't submit the workflow, just print it",
    )
    parser.add_argument(
        "--job-name",
        type=str,
        default="nextflow-job",
        help="Name of the Fuzzball workflow running the nextflow controller job",
    )
    parser.add_argument(
        "nextflow_cmd",
        nargs=argparse.REMAINDER,
        help="Nextflow command"
    )
    return parser.parse_args()

def main() -> None:
    args = parse_cli()
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

    fb_client.submit_nextflow_job(args)

if __name__ == "__main__":
    main()
