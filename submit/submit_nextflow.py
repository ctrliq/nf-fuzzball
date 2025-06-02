"""
Submit a nextflow pipleine to run on fuzzball. This script will
collect the required config information, inject it into the  from your fuzzbal configuration
file and submit the pipeline controller job to the fuzzball clutster.
"""

## TODO: maybe try https://ctrliq.slack.com/archives/C05UM8YAX2S/p1747675251154369 and create a secret with encrypted username and password
##       and have the job set up a background process to get a new token every hour. Then the executor could re-read a config file. Or the task
##       handler could just try to submit the job and if it fails could try to get a new token. This could be done in the ApiConfig class via
##       a closure provided at the time of creation.
## TODO: do i need to find and include the various nextflow config files?

import base64
import pathlib
import sys
import yaml
import requests
import argparse
from typing import Any, Dict

CONFIG_PATH = pathlib.Path("~/.config/fuzzball/config.yaml")

def load_config(path: pathlib.Path, context: str | None) -> tuple[Dict[str, Any], str]:
    """
    Load the Fuzzball configuration file and return the requested context (or active context if
    no context was requested explicitly) and a base64 encoded version of
    the minimal configuration file containing only the active context.
    """
    with open(path, "r") as f:
        config = yaml.safe_load(f)

    if context is None:
        context = config["activeContext"]

    minimal_config = {"activeContext": context, "contexts": []}        
    for c in config["contexts"]:
        if c["name"] == context:
            minimal_config["contexts"].append(c)
            break

    if not minimal_config["contexts"]:
        raise ValueError(f"Context '{context}' not found in config.")
    encoded = base64.b64encode(yaml.dump(minimal_config).encode("utf-8")).decode("utf-8")
    return minimal_config["contexts"][0], encoded

def create_value_secret(base_url: str, api_key: str, secret_name: str, secret_value: str):
    """
    create or update a value secret
    """
    url = f"{base_url.rstrip('/')}/secrets"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    # check if secret already exists
    response = get_secrets(base_url, api_key)
    id = None
    for secret in response.json()["secrets"]:
        if secret["name"] == secret_name:
            id = secret["id"]
            break
    if id is not None:
        print("Updating existing secret")
        secret_data = {"value": {"value": secret_value}}
        response = requests.patch(f"{url}/{id}", json=secret_data, headers=headers)
    else:
        print("Creating new secret")
        secret_data = {"name": secret_name, 
                    "scope": "SECRET_SCOPE_USER", 
                    "value": {"value": secret_value}}

        response = requests.put(url, json=secret_data, headers=headers)
    response.raise_for_status()


def create_secret(base_url: str, api_key: str, secret_data: Dict[str, Any]) -> requests.Response:
    url = f"{base_url.rstrip('/')}/secrets"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    response = requests.put(url, json=secret_data, headers=headers)
    response.raise_for_status()
    return response

def get_secrets(base_url: str, api_key: str) -> requests.Response:
    url = f"{base_url.rstrip('/')}/secrets"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response

def main() -> None:
    parser = argparse.ArgumentParser(description="Create a Fuzzball secret via REST API.")
    parser.add_argument("-c", "--context",  type=str, help="Name of the secret context to use from config.yaml. Defaults to the active context in the config file", default=None)
    args = parser.parse_args()

    try:
        context, config_b64 = load_config(CONFIG_PATH.expanduser(), args.context)
        base_url = f"https://{context['address']}/v2"
        token = context["auth"]["credentials"]["token"]
    except Exception as e:
        print(f"Failed to load config: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        response = create_value_secret(base_url, token, "fb", config_b64)
        print("Secret created successfully:")
    except Exception as e:
        print(f"Failed to create secret: {e}", file=sys.stderr)
        sys.exit(1)


    # try:
    #     secrets = get_secrets(base_url, token).json()
    #     print(yaml.safe_dump(secrets, sort_keys=False, default_flow_style=False))
    # except Exception as e:
    #     print(f"Failed to get secrets: {e}", file=sys.stderr)
    #     sys.exit(1)


if __name__ == "__main__":
    main()
