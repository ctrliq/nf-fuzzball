

How to run with uv

```sh
uv venv
uv pip install requests pyyaml
pushd .. && make push && popd
uv run python submit_nextflow.py
```