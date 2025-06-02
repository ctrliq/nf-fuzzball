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

class MinimalFuzzballClient:
    def __init__(self, config_path: pathlib.Path, context: str | None = None):
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
        if context is None:
            context = config.get("activeContext", None)
        if context is None:
            raise ValueError("No active context specified in config or provided as argument.")
        self.__config = {"activeContext": context, "contexts": []}
        for c in config.get("contexts", []):
            if c["name"] == context:
                self.__config["contexts"].append(c)
                self.__base_url = f"https://{c['address']}/v2"
                self.__token = c["auth"]["credentials"]["token"]
                break
        if not self.__config["contexts"]:
            raise ValueError(f"Context not found in config.")

    
    @property
    def headers(self) -> Dict[str, str]:
        """
        Return the headers required for API requests, including the authorization token.
        """
        return {
            "Authorization": f"Bearer {self.__token}",
            "Content-Type": "application/json"
        }
    
    def __request(self, method: str, endpoint: str, data: Dict[str, Any] | None = None) -> requests.Response:
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
        return base64.b64encode(yaml.dump(self.__config).encode("utf-8")).decode("utf-8") 

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
                "value": {"value": secret_value}
            }
            self.__request("PUT", "/secrets", data=secret_data)
        else:
            secret_data = {"value": {"value": secret_value}}
            self.__request("PATCH", f"/secrets/{id}", data=secret_data)

    
def main() -> None:
    parser = argparse.ArgumentParser(description="Create a Fuzzball secret via REST API.")
    parser.add_argument("-c", "--context",  type=str, help="Name of the secret context to use from config.yaml. Defaults to the active context in the config file", default=None)
    args = parser.parse_args()

    config_path = CONFIG_PATH.expanduser()
    if not config_path.exists():
        print(f"Configuration file not found at {config_path}. Please create it first.", file=sys.stderr)
        sys.exit(1)

    try:
        fb_client = MinimalFuzzballClient(config_path, args.context)
    except ValueError as e:
        print(f"Failed to load config: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        fb_client.create_value_secret("fb", fb_client.encode_config())
    except Exception as e:
        print(f"Failed to create secret: {e}", file=sys.stderr)
        sys.exit(1)




if __name__ == "__main__":
    main()
