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
import hashlib
import pathlib
import shlex
import sys
import textwrap
from typing import Any, Dict
import uuid

import yaml
import requests

CONFIG_PATH = pathlib.Path("~/.config/fuzzball/config.yaml")

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

class LocalFile:
    """
    Represents a local file that should be included in the Nextflow job. The remote name
    is derived from the file content using a UUID based on the MD5 hash of the content.
    The file will be uploaded to the fuzzball working directory.
    """

    def __init__(self, local_path: pathlib.Path):
        self.local_path = local_path
        with local_path.open("rb") as f:
            self.content: str = base64.b64encode(f.read()).decode("utf-8")
        self.remote_path: str = str(uuid.UUID(hashlib.md5(self.content.encode()).hexdigest()))


def find_and_import_local_files(nextflow_cmd: list[str]) -> tuple[list[str], list[LocalFile]]:
    mangled_command = []
    local_files = []
    for arg in nextflow_cmd:
        p = pathlib.Path(arg)
        if p.is_file() and p.exists():
            local_file = LocalFile(p)
            local_files.append(local_file)
            mangled_command.append(str(local_file.remote_path))
        else:
            mangled_command.append(arg)
    return mangled_command, local_files


class MinimalFuzzballClient:
    """
    A minimal client for interacting with the Fuzzball API.
    """
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

        mangled_nextflow_cmd, config_files = find_and_import_local_files(args.nextflow_cmd)

        nextflow_cmd_str = shlex.join(args.nextflow_cmd)
        mangled_nextflow_cmd_str = shlex.join(mangled_nextflow_cmd)

        job_name = args.job_name if len(args.job_name) > 0 else str(uuid.UUID(hashlib.md5(nextflow_cmd_str.encode()).hexdigest()))

        mounts = {"data": {"location": "/data"}, "scratch": {"location": "/scratch"}}
        wd_base = f"{args.nextflow_work_base}/{job_name}"
        wd = f"{mounts['data']['location']}/{wd_base}"
        home_base = "home"
        home = f"{wd}/{home_base}"

        secret_name = str(uuid.uuid4())

        plugin_version = args.nf_fuzzball_version

        env = [
            f"HOME={home}",
            f"NXF_HOME={home}/.nextflow",
            "NXF_ANSI_CONSOLE=false",
            "NXF_ANSI_SUMMARY=false",
        ]
        volumes = {
            "data": {
                "reference": args.data_volume,
            },
            "scratch": {
                "reference": args.scratch_volume,
                "ingress": [
                    {
                        "source": {
                            "uri": f"s3://co-ciq-misc-support/nf-fuzzball/nf-fuzzball-{plugin_version}-{self._config['activeContext']}.zip",
                            "secret": args.s3_secret,
                        },
                        "destination": {"uri": "file://nf-fuzzball.zip"},
                    },
                ],
            },
        }

        self.create_value_secret(secret_name, self._encode_config())
        nxf_fuzzball_config = f"""\
        plugins {{ id 'nf-fuzzball@{plugin_version}' }}
        profiles {{
            fuzzball {{
                process {{
                    executor = 'fuzzball'
                }}
                {"docker { registry = 'quay.io' }" if args.nf_core else ""}
                fuzzball {{
                    cfgFile = '{home}/.config/fuzzball/config.yaml'
                }}
            }}
        }}
        """

        setup_script = textwrap.dedent(f"""\
        #! /bin/sh
        rm -rf $HOME/.nextflow/plugins/nf-fuzzball-{plugin_version} \\
          && mkdir -p $HOME/.nextflow/plugins/nf-fuzzball-{plugin_version} $HOME/.config/fuzzball \\
          && unzip /scratch/nf-fuzzball.zip -d $HOME/.nextflow/plugins/nf-fuzzball-{plugin_version} > /dev/null \\
          && echo "$FB_CONFIG" | base64 -d > $HOME/.config/fuzzball/config.yaml \\
          || exit 1

        # there is only a single context in the config file so it's easy to extract the token
        TOKEN="$(awk '/token:/ {{print $2}}' $HOME/.config/fuzzball/config.yaml)"
        # clean up the secret but don't fail if there is an error
        curl -s -X DELETE "{self._base_url}/secrets/{self._secret_id}" \\
            -H "Authorization: Bearer $TOKEN" \\
            -H "Accept: application/json" &> /dev/null && echo "temp secret deleted" || echo "temp secret not deleted"

        """)

        for f in config_files:
            setup_script += f"cat /tmp/{f.remote_path} | base64 -d > {f.remote_path} || exit 1\n"

        nextflow_script = textwrap.dedent(f"""\
        #! /bin/bash
        {mangled_nextflow_cmd_str} -c /tmp/fuzzball.config
        ec=$?
        echo "-- LOG START ---------------------------------------------------------------------------------"
        cat .nextflow.log
        echo "-- LOG END -----------------------------------------------------------------------------------"
        exit $ec
        """)

        workflow = {
            "name": job_name,
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
                        "script": setup_script,
                        "env": env + [f"FB_CONFIG=secret://user/{secret_name}"],
                        "policy": {"timeout": {"execute": "5m"}},
                        "resource": {"cpu": {"cores": 1}, "memory": {"size": "1GB"}},
                    },
                    "nextflow": {
                        "image": {
                            "uri": f"docker://nextflow/nextflow:{args.nextflow_version}"
                        },
                        "files": {"/tmp/fuzzball.config": "file://fuzzball.config"},
                        "mounts": mounts,
                        "cwd": wd,
                        "script": nextflow_script,
                        "env": env,
                        "policy": {"timeout": {"execute": args.timelimit}},
                        "resource": {"cpu": {"cores": 1}, "memory": {"size": "4GB"}},
                        "requires": ["setup"],
                    },
                },
            },
        }

        # add in the local files
        for f in config_files:
            workflow["definition"]["files"][f.remote_path] = f.content
            if "files" not in workflow["definition"]["jobs"]["setup"]:
                workflow["definition"]["jobs"]["setup"]["files"] = {}
            workflow["definition"]["jobs"]["setup"]["files"][f"/tmp/{f.remote_path}"] = f"file://{f.remote_path}"

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
        epilog=textwrap.dedent(
            """\
            Example:
              %(prog)s -- nextflow run \\
                  -with-report report.html \\
                  -with-trace \\
                  -with-timeline timeline.html \\
                  hello
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-c",
        "--context",
        type=str,
        help="Name of the secret context to use from config.yaml. Defaults to the active context in the config file.",
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
        default="",
        help=(
            "Name of the Fuzzball workflow running the nextflow controller job. Defaults to a "
            "UUID seeded by the full commandline of the nextflow command."
        )
    )
    parser.add_argument(
        "--nextflow-work-base",
        type=str,
        default="nextflow/executions",
        help=(
            "Name of basedirectory for nextflow execution paths. The nextflow execution path will be "
            "/data/<nextflow-work-base>/<job-name> which would include logs and the default workdir. "
            "[%(default)s]"
        )
    )
    parser.add_argument(
        "--nf-fuzzball-version",
        type=str,
        default="0.0.1",
        help="nf-fuzzball plugin version [%(default)s]",
    )
    parser.add_argument(
        "--nextflow-version",
        type=str,
        default="25.05.0-edge",
        help="Nextflow version [%(default)s]",
    )
    parser.add_argument(
        "--timelimit",
        type=str,
        default="8h",
        help="Timelimit for pipeline job [%(default)s]",
    )
    parser.add_argument(
        "--scratch-volume",
        type=str,
        default="volume://user/ephemeral",
        help="Ephemeral scratch volume [%(default)s]",
    )
    parser.add_argument(
        "--data-volume",
        type=str,
        default="volume://user/persistent",
        help="Persistent data volume [%(default)s]",
    )
    parser.add_argument(
        "--nf-core",
        action="store_true",
        help="Use nf-core conventions",
    )
    parser.add_argument(
        "--s3-secret",
        type=str,
        default="secret://user/s3",
        help=(
            "Reference for fuzzball S3 secret to use for ingress/egress. This is not the same as the environment"
            " credentials needed to transfer to/from S3 in the pipeline [%(default)s]"
        ),
    )
    parser.add_argument(
        "nextflow_cmd", nargs=argparse.REMAINDER, help="Nextflow command"
    )
    args = parser.parse_args()
    if not args.nextflow_cmd:
        parser.error(
            "Nextflow command is required. Please provide it after the options."
        )
    if args.nextflow_cmd[0] == "--":
        args.nextflow_cmd.pop(0)
    return args


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
