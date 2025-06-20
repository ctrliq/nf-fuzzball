

How to run with uv

```sh
uv venv
uv pip install requests pyyaml
pushd .. && make push && popd
uv run python submit_nextflow.py --help
```

You can use direnv as well
```sh
echo "source .venv/bin/activate" >> .envrc
direnv allow
./submit_nextflow.py --help
```


This assumes that
  - you have aws installed and authenticated to access `s3://co-ciq-misc-support`
  - you have a fuzzball S3 secret `secret://user/s3` with access to the same bucket
  - have a `~/.config/fuzzball/config.yaml` file with a valid token to submit jobs.
    The active context/account will be used.
  - you have `uv` installed for python dependencies

This needs to either become a real python project or (more likely) be turned into
an application template (once there is a mechanism to credential fuzzball jobs automatically).
